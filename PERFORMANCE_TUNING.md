# 性能调优指南

> 本文档介绍 connect-ip-tunnel 在高吞吐场景（1-10 Gbps）下的性能调优方法。

---

## 一、核心配置参数

### 1.1 UDP Socket Buffer（最重要）

UDP socket 缓冲区大小直接影响高吞吐场景下的丢包率和吞吐上限。

**配置项**：

```json
"http3": {
  "udp_recv_buffer": 16777216,
  "udp_send_buffer": 16777216
}
```

**推荐值**：

| 场景 | udp_recv_buffer | udp_send_buffer | 说明 |
|------|-----------------|-----------------|------|
| < 1 Gbps | 8388608 (8MB) | 8388608 (8MB) | 默认值足够 |
| 1-5 Gbps | 16777216 (16MB) | 16777216 (16MB) | 推荐值 |
| 5-10 Gbps | 33554432 (32MB) | 33554432 (32MB) | 高带宽场景 |
| > 10 Gbps | 67108864 (64MB) | 67108864 (64MB) | 极限场景 |

**验证方法**：

启动服务端/客户端后，查看日志中的实际缓冲区大小：

```
INFO UDP socket buffers set recv=16777216 send=16777216
```

如果实际值小于配置值，需要调整系统内核参数（见 1.4 节）。

---

### 1.2 GSO/GRO（Linux 专属）

GSO（Generic Segmentation Offload）和 GRO（Generic Receive Offload）可以将多个小包合并为一个大包发送/接收，大幅减少系统调用次数。

**配置项**：

```json
"http3": {
  "enable_gso": true
}
```

**适用场景**：
- ✅ Linux 内核 4.18+（QUIC over UDP 支持 GSO）
- ✅ 高吞吐场景（> 1 Gbps）
- ❌ Windows / macOS（不支持，配置无效）
- ❌ 虚拟化环境（部分虚拟网卡不支持 GSO）

**验证方法**：

使用 `strace` 观察 `sendmsg` 系统调用次数：

```bash
# 启用 GSO 前
strace -c -p $(pidof connect-ip-tunnel) 2>&1 | grep sendmsg
# sendmsg: ~100,000 calls/sec

# 启用 GSO 后
# sendmsg: ~10,000 calls/sec（减少 10 倍）
```

---

### 1.3 多 Session 并行（突破单连接瓶颈）

单条 QUIC 连接受拥塞控制算法限制，实测吞吐上限约 2-4 Gbps。多 session 模式可以并行建立 N 条连接，按五元组哈希分发上行包，线性叠加带宽。

**配置项**（客户端）：

```json
"connect_ip": {
  "num_sessions": 4
}
```

**推荐值**：

| 目标带宽 | num_sessions | 说明 |
|----------|--------------|------|
| < 2 Gbps | 1 | 单连接足够 |
| 2-5 Gbps | 2-4 | 推荐值 |
| 5-10 Gbps | 4-8 | 高带宽场景 |
| > 10 Gbps | 8-16 | 极限场景，建议 = CPU 核数 |

**注意事项**：
- 多 session 会增加服务端连接数和内存占用
- 每个 session 独立进行拥塞控制，可能导致总带宽略低于 N 倍单连接
- IP 分片包会被正确分发到同一 session（基于 Identification 字段）

---

### 1.4 系统内核参数

**Linux**：

```bash
# UDP 缓冲区上限（必须 >= 配置文件中的 udp_recv_buffer/udp_send_buffer）
sysctl -w net.core.rmem_max=67108864
sysctl -w net.core.wmem_max=67108864
sysctl -w net.core.rmem_default=16777216
sysctl -w net.core.wmem_default=16777216

# 网卡多队列（物理机）
ethtool -L eth0 combined $(nproc)

# 持久化配置
cat >> /etc/sysctl.conf <<EOF
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=16777216
net.core.wmem_default=16777216
EOF
sysctl -p
```

**macOS**：

```bash
# macOS 默认 UDP 缓冲区较小，需要调整
sudo sysctl -w kern.ipc.maxsockbuf=67108864
sudo sysctl -w net.inet.udp.recvspace=16777216
sudo sysctl -w net.inet.udp.maxdgram=16384
```

**Windows**：

Windows 会自动调整 UDP 缓冲区，通常无需手动配置。

---

## 二、QUIC 连接窗口调优

### 2.1 BDP（Bandwidth-Delay Product）计算

高带宽长距离链路需要足够大的 QUIC 连接窗口才能跑满带宽：

```
BDP = 带宽 × RTT
例如：10 Gbps × 50ms = 62.5 MB
```

**配置项**：

```json
"http3": {
  "initial_conn_window": 33554432,
  "max_conn_window": 134217728,
  "initial_stream_window": 16777216,
  "max_stream_window": 67108864
}
```

**推荐值**：

| 场景 | initial_conn_window | max_conn_window | 说明 |
|------|---------------------|-----------------|------|
| 低延迟（< 10ms RTT） | 16777216 (16MB) | 67108864 (64MB) | 默认值 |
| 中等延迟（10-50ms） | 33554432 (32MB) | 134217728 (128MB) | 推荐值 |
| 高延迟（> 50ms） | 67108864 (64MB) | 268435456 (256MB) | 跨国链路 |

---

### 2.2 拥塞控制算法

**BBRv2 vs CUBIC**：

| 算法 | 适用场景 | 优点 | 缺点 |
|------|----------|------|------|
| CUBIC | 低丢包率（< 0.1%） | 稳定，公平性好 | 高丢包时吞吐下降明显 |
| BBRv2 | 高丢包率（1-3%） | 抗丢包能力强 | 可能对其他流量不公平 |

**配置项**：

```json
"http3": {
  "congestion": {
    "algorithm": "bbr2",
    "bbr2": {
      "loss_threshold": 0.015,
      "beta": 0.3
    }
  }
}
```

**推荐场景**：
- 运营商 QoS 限速（随机丢包 1-3%）：使用 BBRv2
- 企业专线（丢包 < 0.1%）：使用 CUBIC（默认）

---

## 三、性能分析工具

### 3.1 pprof 性能分析

**启用方法**：

```json
{
  "server": {
    "admin_listen": ":9090",
    "enable_pprof": true
  }
}
```

**使用方法**：

```bash
# CPU profile（采样 30 秒）
go tool pprof http://localhost:9090/debug/pprof/profile?seconds=30

# 内存 profile
go tool pprof http://localhost:9090/debug/pprof/heap

# goroutine 泄漏检测
curl http://localhost:9090/debug/pprof/goroutine?debug=1

# 火焰图（需要安装 graphviz）
go tool pprof -http=:8080 http://localhost:9090/debug/pprof/profile?seconds=30
```

**安全提示**：
- pprof 端点受 `admin_token` 保护（如果配置了）
- 生产环境建议仅在需要时临时启用，分析完毕后关闭

---

### 3.2 Prometheus Metrics

**关键指标**：

| 指标 | 说明 | 调优建议 |
|------|------|----------|
| `connect_ip_tunnel_packet_drops_total` | 丢包数（按原因） | 如果 `dispatcher_inbound_full` 持续增长，增大 `num_sessions` |
| `connect_ip_tunnel_bytes_rx_total` | 上行字节数 | 监控实际吞吐是否达到预期 |
| `connect_ip_tunnel_bytes_tx_total` | 下行字节数 | 监控实际吞吐是否达到预期 |
| `connect_ip_tunnel_sessions_active` | 活跃 session 数 | 多 session 模式下应为 `num_sessions` |
| `connect_ip_tunnel_udp_socket_buffer_bytes` | UDP 缓冲区大小 | 验证是否与配置一致 |

**查询示例**：

```promql
# 实时吞吐（Mbps）
rate(connect_ip_tunnel_bytes_rx_total[1m]) * 8 / 1000000

# 丢包率
rate(connect_ip_tunnel_packet_drops_total[1m]) / rate(connect_ip_tunnel_packets_rx_total[1m])
```

---

## 四、Benchmark 基准测试

### 4.1 Dispatcher 查找性能

**测试命令**：

```bash
cd server
go test -bench=BenchmarkDispatcherLookupHostRoute -benchmem
```

**预期结果**：

```
BenchmarkDispatcherLookupHostRoute/sessions_1-2      13421772    88.6 ns/op    0 B/op    0 allocs/op
BenchmarkDispatcherLookupHostRoute/sessions_10-2     33750806    35.6 ns/op    0 B/op    0 allocs/op
BenchmarkDispatcherLookupHostRoute/sessions_100-2    34285714    35.0 ns/op    0 B/op    0 allocs/op
BenchmarkDispatcherLookupHostRoute/sessions_1000-2   33003300    36.3 ns/op    0 B/op    0 allocs/op
```

**关键指标**：
- 延迟应在 35-40 ns 范围内，且不随 session 数增长（O(1) 查找）
- 0 allocs/op（零内存分配，无 GC 压力）

---

### 4.2 Flow Distributor 性能

**测试命令**：

```bash
cd engine
go test -bench=BenchmarkFlowDistributor -benchmem
```

**预期结果**：

```
BenchmarkFlowDistributorSelect-2         104712219    11.4 ns/op    0 B/op    0 allocs/op
BenchmarkSelectParallel-2                189189189     6.3 ns/op    0 B/op    0 allocs/op
BenchmarkHash4-2                        1000000000     0.7 ns/op    0 B/op    0 allocs/op
BenchmarkIPv4FlowHash-2                  166666666     7.2 ns/op    0 B/op    0 allocs/op
BenchmarkIPv6FlowHash-2                  142857142     8.4 ns/op    0 B/op    0 allocs/op
```

**关键指标**：
- Select 延迟 < 15 ns（单核可处理 87M pps，远超 10G 线速所需的 0.9M pps）
- 多核并行延迟 < 10 ns（线性扩展）

---

### 4.3 iperf3 端到端吞吐测试

**测试环境**：
- 服务端：VPS（公网 IP）
- 客户端：本地机器
- 目标：测试隧道实际吞吐

**步骤 1：服务端启动 iperf3**

```bash
# 在服务端 TUN 地址上监听
iperf3 -s -B 10.233.0.1
```

**步骤 2：客户端启动隧道**

```bash
sudo ./connect-ip-tunnel -c config.client.json
```

**步骤 3：客户端运行 iperf3**

```bash
# 单流测试
iperf3 -c 10.233.0.1 -t 30

# 多流测试（模拟多连接）
iperf3 -c 10.233.0.1 -t 30 -P 4
```

**预期结果**：

| 配置 | 单流吞吐 | 多流吞吐（4 并发） |
|------|----------|-------------------|
| num_sessions=1 | 2-4 Gbps | 2-4 Gbps |
| num_sessions=4 | 2-4 Gbps | 8-16 Gbps |

**注意事项**：
- 实际吞吐受网络 RTT、丢包率、服务端带宽上限影响
- 如果吞吐远低于预期，检查 UDP 缓冲区、QUIC 窗口、系统内核参数

---

## 五、常见性能问题排查

### 5.1 吞吐无法达到预期

**可能原因**：

1. **UDP 缓冲区不足**
   - 检查日志中的实际缓冲区大小
   - 调整系统内核参数（见 1.4 节）

2. **QUIC 窗口过小**
   - 计算 BDP（带宽 × RTT）
   - 调整 `max_conn_window` 至少为 BDP 的 2 倍

3. **单连接瓶颈**
   - 增大 `num_sessions` 至 4 或更高

4. **服务端带宽限制**
   - 检查服务端出口带宽上限
   - 检查运营商 QoS 限速

---

### 5.2 高丢包率

**可能原因**：

1. **UDP 缓冲区溢出**
   - 增大 `udp_recv_buffer` 和 `udp_send_buffer`
   - 检查 `packet_drops_total{reason="dispatcher_inbound_full"}` 指标

2. **网络链路丢包**
   - 使用 `mtr` 或 `ping` 检查链路质量
   - 考虑切换拥塞控制算法为 BBRv2

3. **CPU 瓶颈**
   - 使用 pprof 分析 CPU 热点
   - 增大 `num_sessions` 利用多核

---

### 5.3 延迟抖动

**可能原因**：

1. **GC 压力**
   - 使用 pprof 分析内存分配热点
   - 检查 `go_gc_duration_seconds` 指标

2. **系统调度**
   - 检查 CPU 使用率是否接近 100%
   - 考虑使用 `taskset` 绑定 CPU 核心

3. **网络拥塞**
   - 检查 QUIC 拥塞控制状态
   - 调整 `congestion.algorithm` 和参数

---

## 六、生产环境推荐配置

### 6.1 高吞吐场景（5-10 Gbps）

**服务端**：

```json
{
  "server": {
    "admin_listen": ":9090",
    "enable_pprof": false,
    "http3": {
      "udp_recv_buffer": 33554432,
      "udp_send_buffer": 33554432,
      "enable_gso": true,
      "initial_conn_window": 67108864,
      "max_conn_window": 268435456,
      "congestion": {
        "algorithm": "bbr2"
      }
    }
  }
}
```

**客户端**：

```json
{
  "client": {
    "admin_listen": ":9091",
    "enable_pprof": false,
    "http3": {
      "udp_recv_buffer": 33554432,
      "udp_send_buffer": 33554432,
      "enable_gso": true,
      "initial_conn_window": 67108864,
      "max_conn_window": 268435456,
      "congestion": {
        "algorithm": "bbr2"
      }
    },
    "connect_ip": {
      "num_sessions": 8
    }
  }
}
```

---

### 6.2 低延迟场景（< 10ms RTT）

**服务端**：

```json
{
  "server": {
    "http3": {
      "udp_recv_buffer": 16777216,
      "udp_send_buffer": 16777216,
      "enable_gso": true,
      "initial_conn_window": 16777216,
      "max_conn_window": 67108864,
      "congestion": {
        "algorithm": "cubic"
      }
    }
  }
}
```

**客户端**：

```json
{
  "client": {
    "http3": {
      "udp_recv_buffer": 16777216,
      "udp_send_buffer": 16777216,
      "enable_gso": true,
      "initial_conn_window": 16777216,
      "max_conn_window": 67108864,
      "congestion": {
        "algorithm": "cubic"
      }
    },
    "connect_ip": {
      "num_sessions": 2
    }
  }
}
```

---

## 七、参考资料

- [PERF_ANALYSIS.md](PERF_ANALYSIS.md) — Flow Distributor 性能分析报告
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [BBRv2: Congestion Control for the Internet](https://datatracker.ietf.org/doc/draft-cardwell-iccrg-bbr-congestion-control/)
- [Linux UDP Socket Buffer Tuning](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
