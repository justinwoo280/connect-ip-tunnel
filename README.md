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

### 使用 Docker（推荐）

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

### 本地运行

```bash
# 构建
make build

# 服务端（需要 root 权限创建 TUN）
sudo ./bin/connect-ip-tunnel server --config deploy/server/config.json

# 客户端（需要 root 权限创建 TUN）
sudo ./bin/connect-ip-tunnel client --config deploy/client/config.json
```

---

## 配置

### 服务端配置

```json
{
  "listen": "0.0.0.0:443",
  "uri_template": "/.well-known/masque/ip/{target}/{ip_proto}/",
  "admin_listen": "127.0.0.1:9090",
  "tun": {
    "name": "tun0",
    "mtu": 1420
  },
  "tls": {
    "cert": "/path/to/server.crt",
    "key":  "/path/to/server.key",
    "ca":   "/path/to/ca.crt",
    "client_auth": true
  },
  "http3": {
    "enable_datagrams": true,
    "max_idle_timeout": "30s",
    "keep_alive_period": "10s"
  },
  "ipv4_pool": "10.233.0.0/16",
  "ipv6_pool": "fd00::/64",
  "enable_nat": true,
  "nat_interface": ""
}
```

### 客户端配置

```json
{
  "tun": {
    "name": "tun0",
    "mtu": 1420
  },
  "tls": {
    "cert":        "/path/to/client.crt",
    "key":         "/path/to/client.key",
    "ca":          "/path/to/ca.crt",
    "server_name": "your-server.example.com"
  },
  "http3": {
    "enable_datagrams": true,
    "max_idle_timeout": "30s",
    "keep_alive_period": "10s"
  },
  "connect_ip": {
    "addr":                   "your-server.example.com:443",
    "uri":                    "/.well-known/masque/ip/{target}/{ip_proto}/",
    "authority":              "your-server.example.com",
    "wait_for_address_assign": true,
    "address_assign_timeout": "30s",
    "enable_reconnect":       true,
    "max_reconnect_delay":    "30s",
    "num_sessions":           1
  }
}
```

**`num_sessions`**：多 session 并行数量。设为 CPU 核数可线性提升吞吐量（企业版推荐）。

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
```

---

## Prometheus 指标

| 指标 | 类型 | 说明 |
|---|---|---|
| `connect_ip_tunnel_sessions_active` | Gauge | 当前活跃 session 数 |
| `connect_ip_tunnel_sessions_total` | Counter | 累计建立 session 数 |
| `connect_ip_tunnel_session_errors_total` | Counter | session 错误数（按原因） |
| `connect_ip_tunnel_session_duration_seconds` | Histogram | session 时长分布 |
| `connect_ip_tunnel_bytes_rx_total` | Counter | 上行字节数（按 session） |
| `connect_ip_tunnel_bytes_tx_total` | Counter | 下行字节数（按 session） |
| `connect_ip_tunnel_packet_drops_total` | Counter | 丢包数（按原因） |
| `connect_ip_tunnel_ippool_allocated` | Gauge | IP 池已分配地址数 |
| `connect_ip_tunnel_mtls_handshakes_total` | Counter | mTLS 握手次数（按结果） |
| `connect_ip_tunnel_dispatcher_lookup_duration_microseconds` | Histogram | Session 查找耗时分布 |

---

## 性能数据

> 测试环境：linux/arm64，2 核

### 热路径（核心数据路径）

| 测试项 | 延迟 | 吞吐 | 分配 |
|---|---|---|---|
| Flow Hash IPv4 TCP（单核） | 8.4 ns | 2,847 MB/s | 0 |
| Flow Hash IPv4 TCP（多核并行） | 4.3 ns | 5,641 MB/s | 0 |
| Flow Distributor Select（N=8） | 10.1 ns | 2,368 MB/s | 0 |
| Flow Distributor Dispatch（含 channel） | 130 ns | — | 0 |
| IP 头解析（Dst Addr） | 7.7 ns | 5,169 MB/s | 0 |
| Flow Hash MTU 包（1400B） | 8.7 ns | 160,100 MB/s | 0 |

### Dispatcher Session 查找（O(1) 地址索引）

| Session 数 | 延迟 | 随 N 增长 |
|---|---|---|
| 1 session | 87.8 ns | — |
| 10 sessions | **35.2 ns** | 不增长 ✅ |
| 100 sessions | ~36 ns | 不增长 ✅ |
| 1000 sessions | ~36 ns | 不增长 ✅ |
| 100 sessions（/24 前缀回退） | 991 ns | O(N) ⚠️ |

### IP 池操作（O(1) 反向索引）

| 测试项 | 延迟 | 分配 |
|---|---|---|
| AllocateIP + 立即释放（复用路径） | 407 ns | 1 alloc |
| 会话轮转（64 并发） | 588 ns | 1 alloc |
| ReleaseIP @ 10 sessions | 372 ns | 1 alloc |
| ReleaseIP @ 100 sessions | 419 ns | 1 alloc |
| ReleaseIP @ 1000 sessions | **412 ns** | 1 alloc ✅ |

**关键结论**：ReleaseIP 从 10 → 1000 session 延迟几乎不变，O(1) 反向索引有效。

### 与 WireGuard 对比定位

| 维度 | WireGuard (kernel) | connect-ip-tunnel |
|---|---|---|
| 协议特征 | UDP 私有协议，特征明显 | HTTP/3，与 HTTPS 无区分 ✅ |
| Session 查找 | kernel netfilter | 35 ns，O(1) map 查找 ✅ |
| 零分配热路径 | kernel bypass | userspace 零分配 ✅ |
| 多核扩展 | 受单队列限制 | 多 session 并行 × N 核 ✅ |
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
transport/http3/         # HTTP/3 over QUIC 连接工厂
tunnel/connectip/        # CONNECT-IP 会话适配
runner/                  # 双向包泵
common/bufferpool/       # 全局 buffer 池
deploy/                  # 部署配置模板
  server/config.json     # 服务端配置
  client/config.json     # 客户端配置
  prometheus/            # Prometheus 配置
  grafana/               # Grafana 自动 provisioning
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

- [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484)
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification](https://www.rfc-editor.org/rfc/rfc8200)
- [draft-ietf-tls-esni — TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
