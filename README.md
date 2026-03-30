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
- 多种鉴权（Bearer / Basic / Custom Header）

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
security/tls/            # TLS 1.3 + ECH + PQC
security/auth/           # 鉴权框架
transport/http3/         # HTTP/3 over QUIC 连接工厂
tunnel/                  # PacketTunnel 接口
tunnel/connectip/        # CONNECT-IP 会话适配
runner/                  # 双向包泵
```

## 下一步

1. 客户端支持 ADDRESS_ASSIGN（等待服务端分配 IP 后再配置 TUN）
2. 客户端自动重连（指数退避）
3. 服务端多会话 TUN 包按目的 IP 分发
4. 客户端鉴权注入（待 connect-ip-go 上游支持或 fork）
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

`config.example.json`：

```json
{
  "tun": {
    "name": "citun0",
    "mtu": 1400,
    "file_descriptor": 0,
    "ipv4_cidr": "10.233.0.2/24",
    "ipv6_cidr": "fd00:233::2/64",
    "dns_v4": "1.1.1.1",
    "dns_v6": "2606:4700:4700::1111"
  },
  "bypass": {
    "enable": true,
    "server_addr": "example.com:443"
  },
  "tls": {
    "server_name": "example.com",
    "insecure_skip_verify": false,
    "enable_ech": false,
    "enable_pqc": false,
    "use_system_cas": true,
    "use_mozilla_ca": false,
    "enable_session_cache": true,
    "session_cache_size": 128,
    "key_log_path": ""
  },
  "http3": {
    "enable_datagrams": true,
    "max_idle_timeout": 30000000000,
    "keep_alive_period": 10000000000,
    "allow_0rtt": true,
    "disable_path_mtu_probe": false,
    "initial_stream_window": 6291456,
    "max_stream_window": 16777216,
    "initial_conn_window": 15728640,
    "max_conn_window": 26214400,
    "disable_compression": false,
    "tls_handshake_timeout": 10000000000,
    "max_response_header_sec": 10
  },
  "connect_ip": {
    "uri": "/.well-known/masque/ip",
    "authority": "example.com"
  }
}
```

> Android 端需要通过 VPNService 建立 TUN，并把 fd 填入 `tun.file_descriptor`。
