# Connect-IP Tunnel 架构设计

## 概述

Connect-IP Tunnel 是一个统一的 CONNECT-IP 代理内核，支持客户端和服务端两种运行模式。通过配置文件中的 `mode` 字段切换运行模式。

## 架构特点

### 1. 统一内核设计

- **单一二进制**：一个可执行文件同时支持客户端和服务端
- **配置驱动**：通过 JSON 配置文件控制运行模式
- **代码复用**：共享 TUN、TLS、HTTP/3、鉴权等核心模块

### 2. 模块化架构

```
connect-ip-tunnel/
├── cmd/app/              # 主程序入口
├── engine/               # 客户端引擎
│   └── client_engine.go
├── server/               # 服务端引擎
│   ├── server.go         # 服务端核心
│   ├── handler.go        # HTTP/3 请求处理
│   └── session.go        # 客户端会话管理
├── platform/             # 平台层（共享）
│   ├── tun/              # TUN 设备管理
│   └── bypass/           # Bypass 路由
├── security/             # 安全层（共享）
│   └── tls/              # TLS 1.3 + ECH + PQC + mTLS
├── transport/            # 传输层（共享）
│   └── http3/            # HTTP/3 over QUIC
├── tunnel/               # 隧道层（共享）
│   └── connectip/        # CONNECT-IP 协议
├── runner/               # 数据面（共享）
│   └── packet_pump.go    # 双向包转发
└── option/               # 配置管理（共享）
    ├── config.go
    ├── validate.go
    └── load.go
```

## 运行模式

### 客户端模式 (mode: "client")

**功能**：连接到远端 CONNECT-IP 代理服务器，建立 IP 隧道。

**数据流**：
```
本地应用 → TUN设备 → PacketPump → CONNECT-IP Client → HTTP/3 → QUIC → TLS+ECH → UDP(bypass) → 远端服务器
```

**关键组件**：
- `engine.Engine` - 客户端引擎
- `tunnel/connectip.Client` - CONNECT-IP 客户端
- `transport/http3.Factory` - HTTP/3 连接工厂
- `platform/bypass.Dialer` - Bypass 拨号器（绕过 TUN）

**配置示例**：
```json
{
  "mode": "client",
  "client": {
    "tun": { "name": "tun0", "mtu": 1400 },
    "tls": {
      "server_name": "proxy.example.com",
      "client_cert_file": "/path/to/client.crt",
      "client_key_file": "/path/to/client.key"
    },
    "connect_ip": {
      "addr": "proxy.example.com:443",
      "uri": "/.well-known/masque/ip"
    }
  }
}
```

### 服务端模式 (mode: "server")

**功能**：监听 QUIC 端口，接受客户端的 CONNECT-IP 请求，转发 IP 包。

**数据流**：
```
客户端 → UDP → QUIC → TLS → HTTP/3 → CONNECT-IP Handler → PacketPump → TUN设备 → 互联网
```

**关键组件**：
- `server.Server` - 服务端引擎
- `server.ServeHTTP` - HTTP/3 请求处理器
- `server.Session` - 客户端会话管理
- `security/tls` - mTLS 客户端证书验证

**配置示例**：
```json
{
  "mode": "server",
  "server": {
    "listen": ":443",
    "uri_template": "/.well-known/masque/ip",
    "tls": {
      "cert_file": "/path/to/cert.pem",
      "key_file": "/path/to/key.pem",
      "enable_mtls": true,
      "client_ca_file": "/path/to/ca.pem"
    }
  }
}
```

## 共享模块详解

### 1. TUN 设备层 (`platform/tun/`)

**功能**：
- 创建和配置 TUN 虚拟网卡
- 批量读写 IP 包（性能优化）
- 跨平台支持（Linux/Windows/macOS/Android/FreeBSD）

**关键接口**：
```go
type Device interface {
    ReadPacket(buf []byte) (int, error)
    WritePacket(pkt []byte) error
    BatchSize() int
    Read(bufs [][]byte, sizes []int, offset int) (int, error)
    Write(bufs [][]byte, offset int) (int, error)
    Close() error
}
```

### 2. TLS 安全层 (`security/tls/`)

**功能**：
- TLS 1.3 强制执行
- ECH (Encrypted Client Hello) 支持
  - 静态配置
  - 动态 DoH 刷新
- PQC (Post-Quantum Cryptography) 曲线
- Mozilla CA 嵌入
- Session 缓存优化

**客户端**：
```go
tlsClient, _ := securitytls.NewClient(securitytls.ClientOptions{
    ServerName: "proxy.example.com",
    EnableECH: true,
    ECHManager: echManager,
    EnablePQC: true,
})
```

**服务端**：
```go
tlsServer, _ := securitytls.NewServer(securitytls.ServerOptions{
    CertFile: "/path/to/cert.pem",
    KeyFile: "/path/to/key.pem",
    EnablePQC: true,
})
```

### 3. HTTP/3 传输层 (`transport/http3/`)

**功能**：
- QUIC 连接管理
- HTTP/3 ClientConn 创建
- Datagram 模式支持（CONNECT-IP 必需）
- Bypass dialer 集成

**客户端**：
```go
factory := http3.NewFactory(opts, tlsProvider, tlsOptions, bypassDialer)
clientConn, _ := factory.Dial(ctx, target)
```

### 4. 数据转发层 (`runner/`)

**功能**：
- 双向 IP 包转发（TUN ↔ Tunnel）
- 批量读写优化
- Buffer 池化（减少 GC）
- 统计信息收集

**使用**：
```go
pump := &runner.PacketPump{
    Dev: tunDevice,
    Tunnel: connectipSession,
    BufferSize: mtu + 4,
}
pump.Run(ctx)
```

## 性能优化

### 1. 批量 I/O

- TUN 设备使用 WireGuard 的批量 API
- 单次系统调用处理多个包
- 减少上下文切换开销

### 2. Buffer 池化

- `sync.Pool` 管理 65536 字节缓冲区
- 避免频繁内存分配
- 降低 GC 压力

### 3. Zero-Copy

- ICMP 回包直接写回 TUN
- 避免不必要的数据拷贝

## 安全特性

### 1. TLS 1.3 强制

- 禁用 TLS 1.2 及以下版本
- 前向保密 (Forward Secrecy)

### 2. ECH 支持

- 隐藏 SNI 和鉴权信息
- 防止中间人嗅探
- 动态 DoH 刷新配置

### 3. PQC 曲线

- X25519MLKEM768 后量子密码学
- 抵御量子计算机攻击

### 4. mTLS 双向认证

- 服务端验证客户端证书
- 客户端验证服务端证书
- 替代 HTTP 层鉴权，更安全
- 支持自定义 CA 或系统 CA

## 部署场景

### 场景 1：个人 VPN

```
[笔记本] --client--> [VPS服务器] --server--> [互联网]
```

### 场景 2：企业内网访问

```
[远程员工] --client--> [企业网关] --server--> [内网资源]
```

### 场景 3：多级代理

```
[客户端A] ---> [中继服务器B] ---> [出口服务器C] ---> [互联网]
           client模式      server+client模式    server模式
```

## 编译和运行

### 编译

```bash
cd connect-ip-tunnel
go build -o connect-ip-tunnel ./cmd/app
```

### 运行客户端

```bash
sudo ./connect-ip-tunnel -c config.client.json
```

### 运行服务端

```bash
sudo ./connect-ip-tunnel -c config.server.json
```

## 配置文件结构

### 顶层字段

- `mode`: "client" 或 "server"
- `client`: 客户端配置（mode=client 时必需）
- `server`: 服务端配置（mode=server 时必需）

### 客户端配置

- `tun`: TUN 设备配置
- `bypass`: Bypass 路由配置
- `tls`: TLS 客户端配置
- `http3`: HTTP/3 配置
- `connect_ip`: CONNECT-IP 连接配置

### 服务端配置

- `listen`: 监听地址
- `uri_template`: URI 模板
- `tun`: TUN 设备配置
- `tls`: TLS 服务端配置（证书 + mTLS）
- `http3`: HTTP/3 配置
- `ipv4_pool`: IPv4 地址池
- `ipv6_pool`: IPv6 地址池

## 未来扩展

### 1. IP 地址分配

- 服务端动态分配 IP 给客户端
- ADDRESS_ASSIGN capsule 支持

### 2. 路由广告

- ROUTE_ADVERTISEMENT capsule
- 动态路由更新

### 3. 多用户管理

- 用户配额限制
- 流量统计和计费

### 4. 监控和管理

- Prometheus metrics
- REST API 管理接口
- Web 控制面板

## 参考资料

- [IETF CONNECT-IP Draft](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ip-04.html)
- [RFC 9000 - QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [WireGuard TUN API](https://git.zx2c4.com/wireguard-go/)
