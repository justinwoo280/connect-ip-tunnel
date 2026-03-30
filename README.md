# connect-ip-tunnel

`connect-ip-tunnel` 是一个独立实验工程，用来实现：

- TUN 拦截原始 IP 包
- 通过 HTTP/3 + CONNECT-IP (RFC 9484) 转发
- 避免传统代理模式里“IP 包重组为 TCP/UDP payload + handler 维护”的复杂度

## 当前状态

数据传输链路已打通，具备以下能力：

**核心数据路径**：
- `platform/tun`：跨平台 TUN 设备创建与网络配置
- `transport/http3`：QUIC 建连 + HTTP/3 ClientConn 创建（含 bypass dialer 集成）
- `tunnel/connectip`：CONNECT-IP 会话建立与 IP 包封装/解封装
- `runner`：双向包泵（支持批量读写 + buffer 池化）
- `engine`：客户端全链路装配（TUN → TLS → H3 → CONNECT-IP → PacketPump）
- `server`：服务端全链路（QUIC 监听 → HTTP/3 Handler → IP 分配 → 数据转发）

**平台支持**：
- TUN：Windows / Linux / macOS / FreeBSD / Android
- Bypass：全平台绕行（SO_BINDTODEVICE / IP_UNICAST_IF / IP_BOUND_IF 等）

**安全层**：
- TLS 1.3 强制 + ECH（静态/动态 DoH 模式）+ PQC
- mTLS 双向证书认证（客户端/服务端互相验证）

**服务端**：
- IP 地址池管理（ADDRESS_ASSIGN capsule）
- 路由管理 + NAT (MASQUERADE)
- 会话管理与统计

## 目录

```text
cmd/app/                 # 可执行入口（支持 client/server 双模式）
engine/                  # 客户端引擎
server/                  # 服务端引擎
option/                  # 配置结构与校验
platform/tun/            # TUN 设备抽象（跨平台）
platform/bypass/         # bypass 路由（跨平台）
security/tls/            # TLS 1.3 + ECH + PQC + mTLS
transport/http3/         # HTTP/3 over QUIC 连接工厂
tunnel/                  # PacketTunnel 接口
tunnel/connectip/        # CONNECT-IP 会话适配
runner/                  # 双向包泵
```

## 下一步

1. ~~客户端支持 ADDRESS_ASSIGN~~（已完成）
2. ~~客户端自动重连（指数退避）~~（已完成）
3. ~~服务端多会话 TUN 包按目的 IP 分发~~（已完成）
4. ~~mTLS 双向证书认证~~（已完成，替代 HTTP 鉴权方案）
5. 集成测试

## 快速运行

```bash
cd connect-ip-tunnel
go run ./cmd/app -c ./config.client.example.json
```

服务端：

```bash
sudo go run ./cmd/app -c ./config.server.example.json
```

## 配置示例

### 客户端配置示例

```json
{
  "mode": "client",
  "client": {
    "tun": {
      "name": "citun0",
      "mtu": 1400
    },
    "bypass": {
      "enable": true,
      "server_addr": "example.com:443"
    },
    "tls": {
      "server_name": "example.com",
      "client_cert_file": "/path/to/client.crt",
      "client_key_file": "/path/to/client.key",
      "use_system_cas": true,
      "enable_session_cache": true
    },
    "http3": {
      "enable_datagrams": true,
      "max_idle_timeout": 30000000000,
      "keep_alive_period": 10000000000
    },
    "connect_ip": {
      "addr": "example.com:443",
      "uri": "/.well-known/masque/ip",
      "authority": "example.com",
      "wait_for_address_assign": true
    }
  }
}
```

### 服务端配置示例

```json
{
  "mode": "server",
  "server": {
    "listen": ":443",
    "uri_template": "/.well-known/masque/ip/{target}/{ip-protocol}/",
    "tun": {
      "name": "citun0",
      "mtu": 1400,
      "ipv4_cidr": "10.233.0.1/24"
    },
    "tls": {
      "cert_file": "/path/to/server.crt",
      "key_file": "/path/to/server.key",
      "enable_mtls": true,
      "client_ca_file": "/path/to/ca.crt"
    },
    "http3": {
      "enable_datagrams": true,
      "max_idle_timeout": 30000000000
    },
    "ipv4_pool": "10.233.0.0/24",
    "enable_nat": true
  }
}
```

> Android 端需要通过 VPNService 建立 TUN，并把 fd 填入 `tun.file_descriptor`。
