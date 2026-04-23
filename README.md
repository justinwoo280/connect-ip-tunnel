# connect-ip-tunnel

> **高性能 L3 透明隧道，基于 HTTP/3 + CONNECT-IP (RFC 9484) + mTLS**

将原始 IP 包封装在标准 HTTP/3 流量中转发，对防火墙和 DPI 呈现为普通 HTTPS 流量，同时保持 L3 完全透明——ICMP、任意 IP 协议、IP 分片均可正确处理。

---

## 特性

### 核心能力
- **L3 透明转发**：直接操作 IP 包，无需重组 TCP/UDP，延迟极低
- **HTTP/3 + QUIC**：流量特征与标准 HTTPS 完全一致，穿透能力强
- **mTLS 双向认证**：企业级证书认证，无需密码/token
- **跨平台 TUN**：Linux / macOS / Windows / FreeBSD / Android

### 安全层
- TLS 1.3 强制 + ECH（静态/动态 DoH 模式）+ PQC
- mTLS 双向证书认证
- ECH 配置自动刷新（后台 goroutine，Engine 关闭时正确停止）

### 性能设计
- **零分配热路径**：Dispatcher 包路由、Flow Hash 均为 0 allocs/op
- **Buffer 池化**：全链路复用 `bufferpool`，避免 GC 压力
- **批量 I/O**：TUN 批量读写（Linux/Windows 支持 BatchSize）
- **多 Session 并行**：按五元组哈希分发到 N 条并行 CONNECT-IP session
- **O(1) Session 查找**：Dispatcher 使用地址直索引，不随 session 数增长
- **O(1) IP 池操作**：反向索引，释放/查询不扫全表

### IP 分片正确性
多 session 模式下，Flow Hash 正确处理 IPv4/IPv6 分片：
- **非分片包**：`hash(Src_IP, Dst_IP, Protocol, Ports)` 五元组
- **IPv4 分片包**：`hash(Src_IP, Dst_IP, Protocol, Identification16)`
- **IPv6 分片包**：`hash(Src_IP, Dst_IP, Protocol, Identification32)`，通过 Extension Header 链解析
- 恶意超长 Extension Header 链限制最大跳数（`maxExtHdrHops=8`）

### 可观测性（v0.2）
- 结构化日志（`log/slog`，text/json 格式可选）
- Prometheus metrics 端点（`/metrics`）
- 管理 REST API（`/api/v1/sessions`、`/api/v1/stats` 等）

---

## 快速开始

### 一键部署（推荐，VPS 服务端）

```bash
# 交互式部署（自动生成 mTLS 证书 + 配置 + 启动服务）
sudo bash deploy.sh

# 或直接指定模式
sudo bash deploy.sh docker    # Docker 模式
sudo bash deploy.sh systemd   # systemd 裸机模式
sudo bash deploy.sh uninstall # 卸载
```

部署完成后，脚本会输出：
- 服务端监听地址和端口
- 生成的客户端证书路径（`client.crt` / `client.key` / `ca.crt`）
- 完整的客户端配置示例

### 使用 Docker Compose（开发/测试）

```bash
# 1. 生成开发用证书
make gen-certs

# 2. 启动服务端 + 客户端
make up

# 3. 同时启动 Prometheus + Grafana（可选）
make up-monitoring
# Grafana: http://localhost:3000 (无需登录)
# Prometheus: http://localhost:9091

# 4. 查看日志
make logs

# 5. 停止
make down
```

### 手动运行

```bash
# 构建
make build

# 服务端（需要 root 权限创建 TUN）
sudo ./bin/connect-ip-tunnel -c deploy/server/config.json

# 客户端（需要 root 权限创建 TUN）
sudo ./bin/connect-ip-tunnel -c deploy/client/config.json
```

---

## 配置

### 服务端配置

```json
{
  "mode": "server",
  "server": {
    "listen": ":443",
    "uri_template": "/.well-known/masque/ip",
    "admin_listen": ":9090",
    "unauthenticated_metrics": true,
    "enable_pprof": false,
    "tun": {
      "name": "tun0",
      "mtu": 1420
    },
    "tls": {
      "cert_file":        "/etc/connect-ip-tunnel/certs/server.crt",
      "key_file":         "/etc/connect-ip-tunnel/certs/server.key",
      "enable_mtls":      true,
      "client_ca_file":   "/etc/connect-ip-tunnel/certs/ca.crt",
      "enable_pqc":       true,
      "enable_session_cache": true,
      "session_cache_size":   256
    },
    "http3": {
      "udp_recv_buffer":   16777216,
      "udp_send_buffer":   16777216,
      "enable_gso":        true,
      "enable_datagrams":  true,
      "max_idle_timeout":  "60s",
      "keep_alive_period": "20s"
    },
    "ipv4_pool":    "10.233.0.0/16",
    "ipv6_pool":    "fd00::/64",
    "enable_nat":   true,
    "nat_interface": ""
  }
}
```

完整示例见 [`config.server.example.json`](config.server.example.json)。

#### 性能优化配置项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `http3.udp_recv_buffer` | 16777216 (16MB) | UDP 接收缓冲区大小（字节），高吞吐场景建议 16-32MB |
| `http3.udp_send_buffer` | 16777216 (16MB) | UDP 发送缓冲区大小（字节），高吞吐场景建议 16-32MB |
| `http3.enable_gso` | true | 启用 GSO/GRO（Linux），减少系统调用次数，提升吞吐 |
| `enable_pprof` | false | 启用 pprof 性能分析端点（`/debug/pprof/*`），需配合 `admin_listen` 使用 |

**高带宽场景调优建议**：
- 10 Gbps 链路：`udp_recv_buffer` 和 `udp_send_buffer` 设为 32MB，`enable_gso: true`
- 多核服务器：客户端配置 `num_sessions: 4` 或更高，充分利用多核和多连接带宽
- 详细调优指南见 [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md)

### 客户端配置

```json
{
  "mode": "client",
  "client": {
    "admin_listen": ":9091",
    "enable_pprof": false,
    "tun": {
      "name": "tun0",
      "mtu": 1420
    },
    "tls": {
      "server_name":        "your-server.example.com",
      "insecure_skip_verify": false,
      "client_cert_file":   "/etc/connect-ip-tunnel/certs/client.crt",
      "client_key_file":    "/etc/connect-ip-tunnel/certs/client.key",
      "enable_pqc":         true,
      "enable_session_cache": true,
      "session_cache_size":   128
    },
    "http3": {
      "udp_recv_buffer":   16777216,
      "udp_send_buffer":   16777216,
      "enable_gso":        true,
      "enable_datagrams":  true,
      "max_idle_timeout":  "30s",
      "keep_alive_period": "10s"
    },
    "connect_ip": {
      "addr":              "your-server.example.com:443",
      "uri":               "/.well-known/masque/ip",
      "authority":         "your-server.example.com",
      "enable_reconnect":  true,
      "max_reconnect_delay": "30s"
    }
  }
}
```

完整示例见 [`config.client.example.json`](config.client.example.json)。

---

## 管理 API

服务端启动时配置 `admin_listen`，即可访问以下端点：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查 |
| GET | `/metrics` | Prometheus 指标 |
| GET | `/api/v1/version` | 版本信息 |
| GET | `/api/v1/sessions` | 列出所有活跃 session |
| GET | `/api/v1/sessions/{id}` | 查看单个 session 详情 |
| DELETE | `/api/v1/sessions/{id}` | 强制断开 session |
| GET | `/api/v1/stats` | 全局统计（session 数、内存、GC） |
| GET | `/api/v1/ippool/stats` | IP 池使用情况 |
| GET | `/debug/pprof/*` | pprof 性能分析端点（需配置 `enable_pprof: true`） |

**pprof 端点**（需配置 `enable_pprof: true`）：

| 端点 | 说明 |
|------|------|
| `/debug/pprof/` | pprof 索引页 |
| `/debug/pprof/profile?seconds=30` | CPU profile（采样 30 秒） |
| `/debug/pprof/heap` | 内存 profile |
| `/debug/pprof/goroutine` | goroutine 堆栈 |
| `/debug/pprof/allocs` | 内存分配 profile |
| `/debug/pprof/block` | 阻塞 profile |
| `/debug/pprof/mutex` | 互斥锁 profile |

示例：

```bash
# 查看所有会话
curl http://localhost:9090/api/v1/sessions

# 强制断开某个会话
curl -X DELETE http://localhost:9090/api/v1/sessions/abc123def456

# 查看全局统计
curl http://localhost:9090/api/v1/stats

# Prometheus 指标
curl http://localhost:9090/metrics

# pprof CPU profile（需配置 enable_pprof: true）
go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30

# pprof 内存 profile
go tool pprof http://localhost:9090/debug/pprof/heap
```

---

## CertSrv — CA 证书管理面板

`certsrv` 是内置的 CA 证书管理 Web 面板，与服务端集成在同一个二进制中，负责：

- **签发** mTLS 客户端证书（`client.crt` + `client.key`）
- **吊销** 证书并实时更新 CRL
- **分发** CRL 给服务端定时拉取（服务端在握手时验证）

### 启用方式

在服务端配置中加入 `certsrv` 块：

```json
{
  "mode": "server",
  "server": {
    "tls": {
      "crl_url":      "https://127.0.0.1:8443/crl.pem",
      "crl_interval": "10m"
    },
    "certsrv": {
      "listen":       ":8443",
      "db_path":      "/etc/connect-ip-tunnel/certsrv.db",
      "ca_cert_file": "/etc/connect-ip-tunnel/certs/ca.crt",
      "ca_key_file":  "/etc/connect-ip-tunnel/certs/ca.key"
    }
  }
}
```

或使用 `deploy.sh` 一键部署时选择启用，脚本会自动填入所有配置。

### 首次登录

1. 浏览器访问 `https://your-server:8443`
2. 使用默认账号 `admin / admin` 登录
3. 系统强制引导：**修改密码** → **扫描 QR 码绑定 Google Authenticator**
4. 后续登录需要：用户名 + 密码 + 6位 TOTP 验证码

### 签发客户端证书

1. 进入面板 → **签发证书**
2. 填写 CN（设备标识）、备注、有效期
3. 签发完成后跳转下载页，**私钥仅显示一次**（一次性 Token 机制，刷新即失效）
4. 下载 `client.crt` + `client.key` + `ca.crt`，安全传输到客户端设备

### 吊销证书

在证书列表页点击**吊销**，填写原因确认后：
- 证书状态立即更新为"已吊销"
- CRL 立即重新生成
- 服务端在下次 CRL 拉取后（最长 `crl_interval`，默认 10 分钟）生效

### CRL 公开端点

| 端点 | 说明 |
|------|------|
| `GET /crl.pem` | 最新 CRL（PEM 格式），服务端定时拉取 |
| `GET /ca.crt` | CA 根证书，分发给客户端 |

### certsrv API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/certs` | 列出所有证书（需登录）|
| `POST` | `/api/v1/certs/issue` | 签发证书（需登录）|
| `POST` | `/api/v1/certs/revoke` | 吊销证书（需登录）|

```bash
# 通过 API 签发证书
curl -b "certsrv_session=<token>" \
     -H "Content-Type: application/json" \
     -d '{"cn":"alice-macbook","note":"Alice laptop","days":365}' \
     https://your-server:8443/api/v1/certs/issue

# 通过 API 吊销证书
curl -b "certsrv_session=<token>" \
     -H "Content-Type: application/json" \
     -d '{"serial":"<hex-serial>","reason":"device lost"}' \
     https://your-server:8443/api/v1/certs/revoke
```

### 安全说明

| 特性 | 说明 |
|------|------|
| 私钥不入库 | 私钥仅在签发时出现在内存，不持久化存储 |
| 一次性下载 | 私钥通过内存 Token（10分钟TTL）传递，取出即删除 |
| 密码保护 | bcrypt（cost=12）哈希存储 |
| 2FA | TOTP（RFC 6238），兼容 Google Authenticator / Authy |
| Session | httponly cookie，24小时有效 |

---

## Prometheus 指标

| 指标 | 类型 | 说明 |
|---|---|---|
| `connect_ip_tunnel_sessions_active` | Gauge | 当前活跃 session 数 |
| `connect_ip_tunnel_sessions_total` | Counter | 累计建立 session 数 |
| `connect_ip_tunnel_session_errors_total` | Counter | session 错误数（按原因） |
| `connect_ip_tunnel_session_duration_seconds` | Histogram | session 时长分布 |
| `connect_ip_tunnel_bytes_rx_total` | Counter | 上行字节数 |
| `connect_ip_tunnel_bytes_tx_total` | Counter | 下行字节数 |
| `connect_ip_tunnel_packet_drops_total` | Counter | 丢包数（按原因） |
| `connect_ip_tunnel_ippool_allocated` | Gauge | IP 池已分配地址数 |
| `connect_ip_tunnel_mtls_handshakes_total` | Counter | mTLS 握手次数（按结果） |
| `connect_ip_tunnel_dispatcher_lookup_duration_microseconds` | Histogram | Session 查找耗时分布 |
| `connect_ip_tunnel_udp_socket_buffer_bytes` | Gauge | UDP socket 缓冲区大小（按 family 和 direction） |

---

## 性能数据

> 测试环境：linux/arm64，2 vCPU，11 GiB RAM，Go 1.25.6  
> 所有 dispatch 路径均为 **0 allocs/op**，无 GC 压力

### Flow Distributor 热路径

| 测试项 | 延迟 | 单核 pps 上限 | 分配 |
|---|---|---|---|
| `hash4` murmur 纯计算 | 0.7 ns | — | 0 |
| `ipv4FlowHash`（包头解析 + hash） | 7.2 ns | — | 0 |
| `ipv6FlowHash`（含扩展头遍历） | 8.4 ns | — | 0 |
| `FlowDistributor.Select`（N=8，位掩码） | **11.4 ns** | **87.7M pps** | 0 |
| `FlowDistributor.Select`（N=8，2核并行） | **6.3 ns** | **158M pps/核** | 0 |
| Flow Hash IPv4 MTU 包（1400B） | 8.7 ns | — | 0 |

**10 Gbps 线速只需 ~89 万 pps，dispatch 层单核有 97 倍余量，CPU 占用 < 1%。**

### WritePacket 并发路径（优化前 vs 优化后）

| 场景 | 优化前（RWMutex） | 优化后（atomic.Bool） | 提升 |
|---|---|---|---|
| 单线程 | ~12 ns | < 1 ns | **>12x** |
| 多核并发（2核） | ~58 ns | < 1 ns | **>58x** |

### Dispatcher Session 查找（O(1) 地址索引）

| Session 数 | 延迟 | 随 N 增长 |
|---|---|---|
| 1 session | 88.6 ns | — |
| 10 sessions | **35.6 ns** | 不增长 ✅ |
| 100 sessions | 35.0 ns | 不增长 ✅ |
| 1000 sessions | 36.3 ns | 不增长 ✅ |
| 100 sessions（/24 前缀回退） | 997 ns | O(N) ⚠️ |

### IP 池操作（O(1) 反向索引）

| 测试项 | 延迟 | 分配 |
|---|---|---|
| AllocateIP | 409.7 ns | 1 alloc |
| Allocate + Release 轮转 | 589.9 ns | 1 alloc |
| ReleaseIP @ 10 sessions | 383.8 ns | 1 alloc |
| ReleaseIP @ 100 sessions | 419.6 ns | 1 alloc |
| ReleaseIP @ 1000 sessions | **417.5 ns** | 1 alloc ✅ |

**关键结论**：ReleaseIP 从 10 → 1000 session 延迟几乎不变，O(1) 反向索引有效。

### 10 Gbps 场景实际吞吐估算

| 配置 | 预估吞吐 | 说明 |
|---|---|---|
| 单 session | 2–4 Gbps | 受单条 QUIC 连接拥塞控制上限 |
| `num_sessions: 4` | **8–16 Gbps** | 4 条连接并行，绕过单连接瓶颈 ✅ |
| dispatch 层上限 | > 930 Gbps | 单核 87.7M pps × 1400B MTU |

> **真正决定吞吐的是 QUIC 连接数和窗口大小，不是 dispatch 层。**  
> 默认配置已针对高带宽优化：`initial_conn_window = 32 MB`，`max_conn_window = 128 MB`，满足 10G × 50ms RTT 的 BDP 需求。

### 与 WireGuard 对比定位

| 维度 | WireGuard (kernel) | connect-ip-tunnel |
|---|---|---|
| 协议特征 | UDP 私有协议，特征明显 | HTTP/3，与 HTTPS 无区分 ✅ |
| Session 查找 | kernel netfilter | 35 ns，O(1) map 查找 ✅ |
| 零分配热路径 | kernel bypass | userspace 零分配 ✅ |
| 多核扩展 | 受单队列限制 | 多 session 并行 × N 核 ✅ |
| 10 Gbps 支持 | ✅（kernel 态） | ✅（`num_sessions=4` + 大窗口） |
| 企业级认证 | 不支持 | mTLS 双向证书 ✅ |
| 协议透明性 | L3 | L3，ICMP/任意协议均支持 ✅ |

---

## 目录结构

```
cmd/app/                 # 可执行入口（client/server 双模式）
engine/                  # 客户端引擎
  flow_distributor.go    # 五元组哈希分发器（IPv4/IPv6 分片感知）
  multi_session.go       # 多 session 并行池
  client_engine.go       # 全链路装配
server/                  # 服务端引擎
  dispatcher.go          # TUN 包分发器（O(1) 地址索引）
  ippool.go              # IP 地址池（O(1) 反向索引）
  handler.go             # CONNECT-IP 请求处理
  api_handler.go         # 管理 REST API
  session.go             # Session 生命周期管理
observability/           # 可观测性基础设施
  logger.go              # 结构化日志（slog）
  metrics.go             # Prometheus metrics
option/                  # 配置结构与校验
platform/tun/            # TUN 设备抽象（跨平台）
platform/bypass/         # Bypass 路由（跨平台）
security/tls/            # TLS 1.3 + ECH + PQC + mTLS
  crl.go                 # CRL 定时拉取器（mTLS 吊销验证）
transport/http3/         # HTTP/3 over QUIC 连接工厂
tunnel/connectip/        # CONNECT-IP 会话适配
runner/                  # 双向包泵
common/bufferpool/       # 全局 buffer 池
certsrv/                 # CA 证书管理面板（内置，与服务端同进程）
  db.go                  # SQLite 存储（admin + certificates 表）
  auth.go                # 登录 / bcrypt / TOTP / Session
  ca.go                  # CA 签发 / 吊销 / CRL 生成
  keystore.go            # 一次性私钥 Token store
  server.go              # HTTP 路由 + JSON API
  static.go              # embed.FS 静态文件挂载
  static/                # 前端页面（Tailwind CSS，深色主题）
deploy/                  # 部署配置模板
  server/config.json     # 服务端配置
  client/config.json     # 客户端配置
  prometheus/            # Prometheus 配置
  grafana/               # Grafana 自动 provisioning
deploy.sh                # 一键部署脚本（Docker / systemd 双模式）
```

---

## 开发

```bash
# 运行测试
make test

# 运行 benchmark
make bench

# 竞态检测
make test-race

# 生成开发证书
make gen-certs

# 跨平台构建
make build-all
```

---

## 开源版 vs 企业版

| 特性 | 开源版 | 企业版 |
|---|---|---|
| 核心隧道 | ✅ | ✅ |
| 结构化日志 | ✅ | ✅ |
| Prometheus metrics | ✅ 基础指标 | ✅ 全指标 |
| 管理 REST API | ✅ 无认证 | ✅ Bearer Token |
| 多 Session 并行 | ✅ `num_sessions` 可配 | ✅ 自动调优 |
| 配置热重载 | ❌ | ✅ |
| 证书热重载 | ❌ | ✅ |
| 审计日志 | ❌ | ✅ |
| 限速 / QoS | ❌ | ✅ |
| 高可用（HA） | ❌ | ✅ |
| 商业支持 | ❌ | ✅ |

---

## 参考资料

- [性能调优指南](PERFORMANCE_TUNING.md) — UDP buffer、GSO/GRO、多 session 并行、benchmark 测试
- [性能分析报告](PERF_ANALYSIS.md) — Flow Distributor 性能分析与 10 Gbps 验证
- [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484)
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification](https://www.rfc-editor.org/rfc/rfc8200)
- [draft-ietf-tls-esni — TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
