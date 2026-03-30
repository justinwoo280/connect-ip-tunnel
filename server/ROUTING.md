# 服务端路由配置说明

## 设计原则

服务端的路由配置遵循以下核心原则，避免路由回环和确保正确的数据包转发：

### 1. TUN 设备角色

- **只接收**：从客户端隧道接收加密的 IP 包
- **只发送**：将解密后的 IP 包通过系统路由表转发到互联网
- **不设置默认路由**：避免路由回环（服务端自身的流量不走 TUN）

### 2. 路由表配置

```
客户端 IP 池 → TUN 设备 → 系统路由表 → 互联网
```

- 仅为客户端 IP 地址池添加路由指向 TUN 设备
- 服务端自身的流量使用系统默认路由
- 客户端流量通过 NAT 转换后访问互联网

### 3. 防止路由回环

**错误配置（会导致回环）**：
```bash
# 错误：在 TUN 上设置默认路由
ip route add default dev tun0
```

**正确配置（本项目自动完成）**：
```bash
# 只为客户端地址池添加路由
ip route add 10.0.0.0/24 dev tun0
ip route add fd00::/64 dev tun0
```

## 自动配置流程

`RoutingManager` 会自动完成以下配置：

### 1. TUN 设备 IP 配置

```bash
# Linux
ip addr add 10.0.0.1/24 dev tun0
ip link set tun0 up

# macOS
ifconfig tun0 10.0.0.1 netmask 255.255.255.0 up

# Windows
netsh interface ip set address tun0 static 10.0.0.1 255.255.255.0
```

**注意**：不设置网关（gateway），避免默认路由被修改。

### 2. 客户端地址池路由

```bash
# Linux
ip route add 10.0.0.0/24 dev tun0
ip route add fd00::/64 dev tun0

# macOS
route add -net 10.0.0.0/24 -interface tun0
route add -net fd00::/64 -interface tun0

# Windows
route add 10.0.0.0 mask 255.255.255.0 if tun0
```

### 3. IP 转发启用

```bash
# Linux
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# macOS
sysctl -w net.inet.ip.forwarding=1
sysctl -w net.inet6.ip6.forwarding=1

# Windows
# 默认启用，无需配置
```

### 4. NAT 配置（可选）

```bash
# Linux - iptables MASQUERADE
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s fd00::/64 -o eth0 -j MASQUERADE

# macOS - pfctl
# 需要手动配置 /etc/pf.conf

# Windows - ICS
# 需要通过网络共享配置
```

## 配置选项

### enable_nat

启用 NAT（MASQUERADE），允许客户端通过服务端访问互联网。

```json
{
  "server": {
    "enable_nat": true,
    "nat_interface": "eth0"  // 留空自动检测
  }
}
```

**自动检测逻辑**：
- Linux: 解析 `ip route show default` 输出
- macOS: 解析 `route -n get default` 输出
- Windows: 需要手动指定

### nat_interface

指定 NAT 出口接口（物理网卡）。

- 留空：自动检测默认网关接口
- 指定：使用指定接口（例如 `eth0`, `ens33`, `en0`）

## 数据流向

### 客户端 → 互联网

```
[客户端] 
  ↓ QUIC/HTTP/3 (加密)
[服务端 QUIC 监听器]
  ↓ 解密
[CONNECT-IP Handler]
  ↓ IP 包
[TUN 设备 tun0]
  ↓ 路由查找（系统路由表）
[NAT (MASQUERADE)]
  ↓ 源地址转换 10.0.0.x → 服务端公网 IP
[物理网卡 eth0]
  ↓
[互联网]
```

### 互联网 → 客户端

```
[互联网]
  ↓
[物理网卡 eth0]
  ↓ NAT 反向转换（conntrack）
[TUN 设备 tun0]
  ↓ 路由查找（10.0.0.x → tun0）
[CONNECT-IP Handler]
  ↓ 加密
[服务端 QUIC 连接]
  ↓ QUIC/HTTP/3 (加密)
[客户端]
```

## 路由表示例

### 服务端路由表（配置后）

```bash
$ ip route show
default via 192.168.1.1 dev eth0          # 服务端默认路由（不变）
10.0.0.0/24 dev tun0 scope link           # 客户端地址池路由
192.168.1.0/24 dev eth0 scope link        # 本地网络
```

### NAT 规则（iptables）

```bash
$ iptables -t nat -L POSTROUTING -v
Chain POSTROUTING (policy ACCEPT)
target     prot opt in     out     source               destination
MASQUERADE all  --  any    eth0    10.0.0.0/24          anywhere
```

## 故障排查

### 1. 客户端无法访问互联网

**检查 IP 转发**：
```bash
# Linux
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding

# 应该输出 1
```

**检查 NAT 规则**：
```bash
iptables -t nat -L POSTROUTING -n
# 应该看到 MASQUERADE 规则
```

**检查路由**：
```bash
ip route show
# 应该看到客户端地址池路由指向 tun0
```

### 2. 服务端自身无法访问互联网

**原因**：可能错误地在 TUN 上设置了默认路由。

**检查**：
```bash
ip route show default
# 应该指向物理网卡，而不是 tun0
```

**修复**：
```bash
# 删除错误的默认路由
ip route del default dev tun0

# 恢复正确的默认路由
ip route add default via <gateway_ip> dev eth0
```

### 3. 路由回环

**症状**：服务端 CPU 占用高，网络不通。

**原因**：TUN 设备上配置了默认路由，导致服务端自身流量也走 TUN。

**检查**：
```bash
ip route show | grep default
# 不应该看到 "default ... dev tun0"
```

**修复**：重启服务端，确保配置正确。

### 4. NAT 不工作

**检查 conntrack 模块**：
```bash
# Linux
lsmod | grep nf_conntrack
# 应该看到 nf_conntrack 模块
```

**检查 NAT 表**：
```bash
iptables -t nat -L -n -v
# 应该看到 MASQUERADE 规则和计数器增长
```

## 安全建议

### 1. 防火墙规则

```bash
# 只允许客户端访问互联网，不允许访问服务端本地服务
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -j DROP

# 禁止客户端访问服务端本地网络
iptables -A FORWARD -i tun0 -d 192.168.1.0/24 -j DROP
```

### 2. 速率限制

```bash
# 限制每个客户端的带宽
tc qdisc add dev tun0 root tbf rate 10mbit burst 32kbit latency 400ms
```

### 3. 日志记录

```bash
# 记录转发的包（调试用）
iptables -A FORWARD -i tun0 -j LOG --log-prefix "TUN-FORWARD: "
```

## 平台差异

### Linux

- 完全支持自动配置
- 使用 `ip` 命令和 `iptables`
- 推荐用于生产环境

### macOS

- 支持基本路由配置
- NAT 需要手动配置 `pfctl`
- 适合开发测试

### Windows

- 支持基本路由配置
- NAT 需要手动配置 ICS（Internet Connection Sharing）
- 需要管理员权限

## 参考资料

- [Linux Advanced Routing & Traffic Control](https://lartc.org/)
- [iptables NAT HOWTO](https://www.netfilter.org/documentation/HOWTO/NAT-HOWTO.html)
- [RFC 1918 - Private Address Space](https://www.rfc-editor.org/rfc/rfc1918.html)
