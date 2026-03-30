# 服务端 IP 地址分配功能

## 概述

本功能实现了类似 WireGuard 的内网组网能力，但使用 CONNECT-IP 协议的 **ADDRESS_ASSIGN capsule** 机制。服务端动态分配内网 IP 给客户端，客户端使用分配的 IP 进行通信，数据传输依然通过 CONNECT-IP over HTTP/3 over QUIC。

## 设计原理

### 与 WireGuard 的对比

**WireGuard 方式**：
```
[客户端] 10.0.0.2 ←→ WireGuard隧道 ←→ 10.0.0.1 [服务端]
         ↑配置文件静态指定                    ↑配置文件静态指定
```

**本项目方式（CONNECT-IP）**：
```
[客户端] 10.0.0.2 ←→ CONNECT-IP/HTTP/3/QUIC ←→ 10.0.0.1 [服务端]
         ↑服务端动态分配                          ↑地址池管理
         ↑通过 ADDRESS_ASSIGN capsule 通知
```

### 核心差异

| 特性 | WireGuard | 本项目 (CONNECT-IP) |
|------|-----------|---------------------|
| IP 分配方式 | 静态配置 | 动态分配 |
| 通知机制 | 配置文件 | ADDRESS_ASSIGN capsule |
| 传输协议 | WireGuard 协议 | HTTP/3 over QUIC |
| 加密方式 | ChaCha20 | TLS 1.3 + ECH |
| 地址池管理 | 手动 | 自动 |

## 工作流程

### 1. 服务端启动

```go
// 创建 IP 地址池
ipPool := NewIPPool("10.0.0.0/24", "fd00::/64")

// 服务端 TUN 使用第一个 IP
// 10.0.0.1/24 (IPv4)
// fd00::1/64 (IPv6)
```

### 2. 客户端连接

```
[客户端] → CONNECT-IP 请求 → [服务端]
```

### 3. IP 地址分配

```go
// 服务端从地址池分配 IP
ipv4, ipv6, _ := ipPool.AllocateIP(sessionID)
// 例如：10.0.0.2/32, fd00::2/128
```

### 4. 通知客户端

```go
// 通过 ADDRESS_ASSIGN capsule 发送
conn.AssignAddresses(ctx, []netip.Prefix{
    netip.MustParsePrefix("10.0.0.2/32"),
    netip.MustParsePrefix("fd00::2/128"),
})
```

### 5. 客户端配置 TUN

```bash
# 客户端收到 ADDRESS_ASSIGN 后自动配置
ip addr add 10.0.0.2/32 dev tun0
ip addr add fd00::2/128 dev tun0
```

### 6. 数据传输

```
[客户端应用] 
    ↓ 发送到 10.0.0.x
[TUN 设备] 10.0.0.2
    ↓ IP 包
[CONNECT-IP Session]
    ↓ HTTP/3 Datagram
[QUIC 连接]
    ↓ 加密传输
[服务端 QUIC]
    ↓ 解密
[CONNECT-IP Handler]
    ↓ IP 包
[TUN 设备] 10.0.0.1
    ↓ 路由转发
[目标主机] 10.0.0.x
```

## 实现细节

### IP 地址池管理

```go
type IPPool struct {
    ipv4Pool      netip.Prefix          // 例如 10.0.0.0/24
    ipv6Pool      netip.Prefix          // 例如 fd00::/64
    allocatedIPv4 map[netip.Addr]string // IP -> SessionID
    allocatedIPv6 map[netip.Addr]string
    nextIPv4      netip.Addr            // 下一个可分配的 IP
    nextIPv6      netip.Addr
}
```

**分配策略**：
1. 从 `nextIPv4/nextIPv6` 开始查找
2. 跳过已分配的 IP
3. 分配 /32 (IPv4) 或 /128 (IPv6) 前缀
4. 更新 `nextIPv4/nextIPv6` 指针

**回收策略**：
- 会话关闭时自动释放 IP
- IP 可被后续会话重用

### ADDRESS_ASSIGN Capsule

根据 CONNECT-IP RFC 草案：

```
ADDRESS_ASSIGN Capsule {
  Capsule Type (i) = 0x01,
  Capsule Length (i),
  Assigned Address (..) ...,
}

Assigned Address {
  Request ID (i),
  IP Version (8),
  IP Address (32..128),
  IP Prefix Length (8),
}
```

**示例**：
```
分配 10.0.0.2/32:
  Request ID: 0
  IP Version: 4
  IP Address: 10.0.0.2
  Prefix Length: 32
```

### 会话管理

```go
type Session struct {
    id           string
    conn         *connectipgo.Conn
    assignedIPv4 netip.Prefix  // 分配的 IPv4
    assignedIPv6 netip.Prefix  // 分配的 IPv6
    // ...
}
```

**生命周期**：
1. 连接建立 → 分配 IP
2. 发送 ADDRESS_ASSIGN capsule
3. 数据转发
4. 连接关闭 → 释放 IP

## 配置示例

### 服务端配置

```json
{
  "mode": "server",
  "server": {
    "listen": ":443",
    "tun": {
      "ipv4_cidr": "10.0.0.1/24",  // 服务端 TUN IP
      "ipv6_cidr": "fd00::1/64"
    },
    "ipv4_pool": "10.0.0.0/24",    // 客户端地址池
    "ipv6_pool": "fd00::/64",
    "enable_nat": true               // 启用 NAT
  }
}
```

**地址分配规则**：
- 服务端 TUN: `10.0.0.1/24`
- 客户端地址池: `10.0.0.0/24`
- 可分配范围: `10.0.0.2` ~ `10.0.0.254` (253 个 IP)
- 第一个客户端: `10.0.0.2/32`
- 第二个客户端: `10.0.0.3/32`
- ...

### 客户端配置

```json
{
  "mode": "client",
  "client": {
    "tun": {
      "name": "tun0",
      "mtu": 1400
      // 不需要配置 ipv4_cidr，由服务端动态分配
    },
    "connect_ip": {
      "addr": "server.example.com:443",
      "uri": "/.well-known/masque/ip"
    }
  }
}
```

**客户端行为**：
1. 连接到服务端
2. 接收 ADDRESS_ASSIGN capsule
3. 自动配置 TUN 设备 IP
4. 开始数据传输

## 使用场景

### 场景 1：点对点 VPN

```
[客户端A] 10.0.0.2 ←→ [服务端] 10.0.0.1 ←→ 10.0.0.3 [客户端B]
                         ↑
                    CONNECT-IP 中继
```

**特点**：
- 客户端之间可以直接通信（通过服务端中继）
- 使用内网 IP 地址
- 数据加密传输（TLS 1.3）

### 场景 2：企业内网访问

```
[远程员工] 10.0.0.2 → [VPN服务器] 10.0.0.1 → [内网资源] 192.168.1.x
```

**特点**：
- 远程员工获得内网 IP
- 可访问企业内网资源
- 服务端配置 NAT 和路由

### 场景 3：多客户端组网

```
[客户端A] 10.0.0.2 ─┐
[客户端B] 10.0.0.3 ─┼→ [服务端] 10.0.0.1 → [互联网]
[客户端C] 10.0.0.4 ─┘
```

**特点**：
- 所有客户端在同一个虚拟网络
- 可以互相通信（通过服务端）
- 共享互联网出口

## 路由配置

### 服务端路由表

```bash
$ ip route show
default via 192.168.1.1 dev eth0          # 服务端默认路由
10.0.0.0/24 dev tun0 scope link           # 客户端地址池路由
192.168.1.0/24 dev eth0 scope link        # 本地网络
```

### 客户端路由表

```bash
$ ip route show
default dev tun0                          # 全局流量走 VPN
10.0.0.0/24 dev tun0 scope link          # VPN 内网
192.168.1.0/24 dev wlan0 scope link      # 本地网络（不走 VPN）
```

## 性能考虑

### IP 地址池大小

| 前缀长度 | 可用 IP 数 | 适用场景 |
|---------|-----------|---------|
| /24 | 254 | 小型部署 |
| /20 | 4094 | 中型部署 |
| /16 | 65534 | 大型部署 |

### 内存占用

```
每个会话: ~200 bytes (IP 映射)
1000 个会话: ~200 KB
10000 个会话: ~2 MB
```

### 分配性能

```
分配速度: O(n) 最坏情况（n = 已分配 IP 数）
优化: 使用空闲列表可优化到 O(1)
```

## 与 WireGuard 的互操作性

**不兼容**：
- ❌ 不能与 WireGuard 服务器互操作
- ❌ 不能与 WireGuard 客户端互操作
- ❌ 协议完全不同

**相似性**：
- ✅ 都使用内网 IP 地址
- ✅ 都支持点对点通信
- ✅ 都支持 NAT 穿透（通过服务端）

## 未来扩展

### 1. IP 地址租约

```go
type IPLease struct {
    IP         netip.Addr
    SessionID  string
    ExpiresAt  time.Time
    RenewCount int
}
```

### 2. 地址池分段

```go
// 为不同用户组分配不同的地址段
type IPPoolSegment struct {
    Name   string
    Prefix netip.Prefix
    Users  []string
}
```

### 3. IPv6 前缀委派

```go
// 为客户端分配整个 /64 前缀
conn.AssignAddresses(ctx, []netip.Prefix{
    netip.MustParsePrefix("fd00:1234::/64"),
})
```

### 4. 动态路由广告

```go
// 通过 ROUTE_ADVERTISEMENT capsule 通知客户端路由
conn.AdvertiseRoute(ctx, []IPRoute{
    {Start: "192.168.1.0", End: "192.168.1.255", Protocol: 0},
})
```

## 调试和监控

### 查看地址池状态

```go
stats := ipPool.Stats()
log.Printf("IPv4: %d/%d allocated", stats.IPv4Allocated, stats.IPv4PoolSize)
log.Printf("IPv6: %d/%d allocated", stats.IPv6Allocated, stats.IPv6PoolSize)
log.Printf("Total sessions: %d", stats.TotalSessions)
```

### 查看会话 IP

```go
ipv4, ipv6 := ipPool.GetAllocatedIPs(sessionID)
log.Printf("Session %s: ipv4=%s ipv6=%s", sessionID, ipv4, ipv6)
```

### 日志示例

```
[server] ip pool ready: ipv4=10.0.0.0/24 ipv6=fd00::/64
[server] assigned ipv4: 10.0.0.2/32 to session a1b2c3d4
[server] assigned ipv6: fd00::2/128 to session a1b2c3d4
[server] session a1b2c3d4 started from 203.0.113.1:54321 (ipv4=10.0.0.2/32 ipv6=fd00::2/128)
[server] session a1b2c3d4 closed
```

## 参考资料

- [IETF CONNECT-IP Draft - Section 5: Capsules](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ip-04.html#section-5)
- [RFC 9297 - HTTP Datagrams and Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297.html)
- [WireGuard AllowedIPs](https://www.wireguard.com/quickstart/#nat-and-firewall-traversal-persistence)
