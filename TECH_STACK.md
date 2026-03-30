# 技术栈说明

## 核心技术栈

```
┌─────────────────────────────────────────────────────────────┐
│                    Connect-IP Tunnel                         │
│                  (统一客户端/服务端内核)                      │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    ┌───▼────┐         ┌────▼────┐        ┌────▼────┐
    │ 应用层  │         │ 隧道层   │        │ 传输层   │
    └────────┘         └─────────┘        └─────────┘
        │                   │                   │
    ┌───▼────────────┐  ┌──▼──────────┐   ┌───▼──────────┐
    │ CONNECT-IP     │  │ HTTP/3      │   │ QUIC         │
    │ (RFC Draft)    │  │ (RFC 9114)  │   │ (RFC 9000)   │
    └────────────────┘  └─────────────┘   └──────────────┘
                                                │
                                           ┌────▼────────┐
                                           │ TLS 1.3     │
                                           │ + ECH + PQC │
                                           └─────────────┘
                                                │
        ┌───────────────────────────────────────┼───────────────┐
        │                                       │               │
    ┌───▼────────┐                         ┌───▼────┐     ┌────▼────┐
    │ TUN 设备    │                         │ UDP    │     │ mTLS    │
    │ (WireGuard) │                         │ Socket │     │ 双向认证 │
    └────────────┘                         └────────┘     └─────────┘
```

## 各层技术选型

### 1. TUN 设备层

**使用**：`golang.zx2c4.com/wireguard/tun`

**作用**：
- 创建和管理虚拟网卡
- 读写原始 IP 包
- 批量 I/O 优化

**注意**：
- ⚠️ 只使用 WireGuard 的 TUN 库
- ⚠️ 不使用 WireGuard 协议
- ⚠️ 不使用 WireGuard 加密

### 2. 传输层

**使用**：`github.com/quic-go/quic-go`

**作用**：
- QUIC 连接管理
- HTTP/3 支持
- Datagram 模式（CONNECT-IP 必需）

**特点**：
- 基于 UDP
- 多路复用
- 0-RTT 支持

### 3. 安全层

**使用**：`crypto/tls` + 自定义 ECH 实现

**作用**：
- TLS 1.3 加密
- ECH (Encrypted Client Hello)
- PQC (Post-Quantum Cryptography)

**特点**：
- 强制 TLS 1.3
- 隐藏 SNI
- 抗量子攻击

### 4. 隧道层

**使用**：`github.com/quic-go/connect-ip-go`

**作用**：
- CONNECT-IP 协议实现
- IP 包封装/解封装
- ICMP 回包处理

**特点**：
- 基于 HTTP/3
- 支持 IPv4/IPv6
- Capsule 协议

### 5. 认证层

**使用**：mTLS（双向 TLS 证书认证）

**作用**：
- 客户端向服务端证明身份
- 服务端验证客户端证书
- 替代 HTTP 层鉴权方案

**特点**：
- 在 TLS 握手阶段完成认证
- 比 HTTP 鉴权更安全（无法被中间人截获）
- 支持自定义 CA 或系统 CA

## 协议栈对比

### WireGuard VPN

```
应用 → TUN → WireGuard协议 → UDP → 网络
              ↑
              ChaCha20加密
              Curve25519密钥交换
```

### 本项目 (CONNECT-IP)

```
应用 → TUN → CONNECT-IP → HTTP/3 → QUIC → TLS1.3 → UDP → 网络
       ↑                                      ↑
       WireGuard库                            TLS加密
       (只用TUN管理)                          ECH + PQC
```

### 传统 VPN (OpenVPN)

```
应用 → TUN → OpenVPN协议 → TCP/UDP → 网络
              ↑
              OpenSSL加密
              证书认证
```

## 性能优化技术

### 1. 批量 I/O

```go
// 单包模式（慢）
for {
    n, _ := dev.Read(buf)
    process(buf[:n])
}

// 批量模式（快）
bufs := make([][]byte, 128)
n, _ := dev.Read(bufs, sizes, 0)  // 一次读 128 个包
for i := 0; i < n; i++ {
    process(bufs[i][:sizes[i]])
}
```

**性能提升**：
- 吞吐量：+30-50%
- CPU 使用率：-40-60%

### 2. Buffer 池化

```go
var PacketPool = &sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 65536)
        return &buf
    },
}
```

**优势**：
- 减少内存分配
- 降低 GC 压力

### 3. Zero-Copy

```go
// ICMP 回包直接写回 TUN
icmp, _ := conn.WritePacket(pkt)
if len(icmp) > 0 {
    _ = dev.WritePacket(icmp)  // 无拷贝
}
```

## 依赖树

```
connect-ip-tunnel
├── golang.zx2c4.com/wireguard/tun (TUN 设备)
│   └── golang.zx2c4.com/wintun (Windows 驱动)
├── github.com/quic-go/quic-go (QUIC + HTTP/3)
│   └── github.com/quic-go/qpack (QPACK 压缩)
├── github.com/quic-go/connect-ip-go (CONNECT-IP)
│   └── github.com/yosida95/uritemplate/v3 (URI 模板)
└── golang.org/x/crypto (密码学)
    └── golang.org/x/sys (系统调用)
```

## 与其他项目的关系

### ewp-core

**相同点**：
- 都是 IP 隧道
- 都使用 TLS + ECH
- 都支持 PQC

**不同点**：
- ewp-core: 使用 gVisor TUN + 自定义协议
- 本项目: 使用 WireGuard TUN + CONNECT-IP 标准协议

### WireGuard

**相同点**：
- 都使用 `wireguard/tun` 库

**不同点**：
- WireGuard: 使用 WireGuard 协议 + ChaCha20 加密
- 本项目: 使用 CONNECT-IP + TLS 1.3 加密

### Cloudflare WARP

**相同点**：
- 都支持 CONNECT-IP 协议
- 都使用 HTTP/3 传输

**不同点**：
- WARP: 闭源，集成 Cloudflare 服务
- 本项目: 开源，可自建服务器

## 技术选型理由

### 为什么用 WireGuard TUN？

1. ✅ 成熟稳定（生产环境验证）
2. ✅ 高性能（批量 I/O）
3. ✅ 跨平台（Linux/Windows/macOS/Android）
4. ✅ 简单易用（API 简洁）

### 为什么用 CONNECT-IP？

1. ✅ IETF 标准协议
2. ✅ 基于 HTTP/3（复用现有基础设施）
3. ✅ 支持 Datagram（低延迟）
4. ✅ 与 Web 生态兼容

### 为什么用 QUIC？

1. ✅ 多路复用（无队头阻塞）
2. ✅ 0-RTT（快速重连）
3. ✅ 连接迁移（网络切换无感）
4. ✅ 内置拥塞控制

### 为什么用 TLS 1.3 + ECH？

1. ✅ 强加密（前向保密）
2. ✅ 隐藏 SNI（防审查）
3. ✅ PQC 支持（抗量子攻击）
4. ✅ 标准协议（互操作性）

## 总结

**本项目 = WireGuard TUN + CONNECT-IP + HTTP/3 + TLS 1.3 + ECH + PQC**

**核心特点**：
- 🚀 高性能（批量 I/O + Buffer 池化）
- 🔒 强安全（TLS 1.3 + ECH + PQC）
- 🌐 标准协议（IETF CONNECT-IP）
- 🔧 易部署（统一内核 + JSON 配置）
- 🎯 跨平台（Linux/Windows/macOS/Android）

**适用场景**：
- 个人 VPN
- 企业内网访问
- 绕过网络审查
- 安全远程办公
