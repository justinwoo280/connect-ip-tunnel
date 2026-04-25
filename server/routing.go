package server

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// RoutingManager 管理服务端路由配置
// 核心原则：
// 1. TUN 设备只接收来自客户端的加密流量（从隧道读取）
// 2. TUN 设备发送的包直接通过系统路由表转发到互联网
// 3. 不在 TUN 上配置默认路由，避免路由回环
type RoutingManager struct {
	tunIfName  string
	tunIPv4    netip.Prefix // TUN 设备的 IP 地址
	tunIPv6    netip.Prefix
	clientPool []netip.Prefix // 客户端 IP 地址池
}

func NewRoutingManager(tunIfName string, tunIPv4, tunIPv6 string, clientPools []string) (*RoutingManager, error) {
	rm := &RoutingManager{
		tunIfName: tunIfName,
	}

	// 解析 TUN 设备 IP
	if tunIPv4 != "" {
		prefix, err := netip.ParsePrefix(tunIPv4)
		if err != nil {
			return nil, fmt.Errorf("parse tun ipv4: %w", err)
		}
		rm.tunIPv4 = prefix
	}

	if tunIPv6 != "" {
		prefix, err := netip.ParsePrefix(tunIPv6)
		if err != nil {
			return nil, fmt.Errorf("parse tun ipv6: %w", err)
		}
		rm.tunIPv6 = prefix
	}

	// 解析客户端地址池
	for _, pool := range clientPools {
		if pool == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(pool)
		if err != nil {
			return nil, fmt.Errorf("parse client pool %q: %w", pool, err)
		}
		rm.clientPool = append(rm.clientPool, prefix)
	}

	return rm, nil
}

// Setup 配置服务端路由
// 策略：
// 1. 给 TUN 设备分配 IP 地址（不配置网关）
// 2. 添加客户端地址池的路由指向 TUN 设备
// 3. 启用 IP 转发
// 4. 配置 NAT（可选，用于客户端访问互联网）
func (rm *RoutingManager) Setup(enableNAT bool, natInterface string) error {
	log.Printf("[routing] setting up server routing for %s", rm.tunIfName)

	// 1. 配置 TUN 设备 IP（不设置网关，避免路由回环）
	if rm.tunIPv4.IsValid() {
		if err := rm.setTunIP(rm.tunIPv4, false); err != nil {
			return fmt.Errorf("set tun ipv4: %w", err)
		}
		log.Printf("[routing] tun ipv4: %s", rm.tunIPv4)
	}

	if rm.tunIPv6.IsValid() {
		if err := rm.setTunIP(rm.tunIPv6, true); err != nil {
			return fmt.Errorf("set tun ipv6: %w", err)
		}
		log.Printf("[routing] tun ipv6: %s", rm.tunIPv6)
	}

	// 没有配置 TUN IP 时，也需要确保设备处于 UP 状态，否则后续 ip route add 会失败
	if !rm.tunIPv4.IsValid() && !rm.tunIPv6.IsValid() {
		if runtime.GOOS == "linux" {
			cmd := exec.Command("ip", "link", "set", rm.tunIfName, "up")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[routing] warning: ip link set %s up: %v (output: %s)", rm.tunIfName, err, string(out))
			}
			if err := rm.waitLinkUp(rm.tunIfName, 2*time.Second); err != nil {
				log.Printf("[routing] warning: %v, proceeding anyway", err)
			}
		}
	}

	// 2. 添加客户端地址池路由（指向 TUN 设备）
	for _, pool := range rm.clientPool {
		if err := rm.addClientPoolRoute(pool); err != nil {
			return fmt.Errorf("add client pool route %s: %w", pool, err)
		}
		log.Printf("[routing] client pool route: %s -> %s", pool, rm.tunIfName)
	}

	// 3. 启用 IP 转发
	if err := rm.enableIPForwarding(); err != nil {
		return fmt.Errorf("enable ip forwarding: %w", err)
	}
	log.Printf("[routing] ip forwarding enabled")

	// 4. 配置 NAT（可选）
	if enableNAT {
		if natInterface == "" {
			natInterface = rm.detectDefaultInterface()
		}
		if natInterface != "" {
			if err := rm.setupNAT(natInterface); err != nil {
				log.Printf("[routing] warning: setup nat failed: %v", err)
			} else {
				log.Printf("[routing] nat enabled: %s -> %s", rm.tunIfName, natInterface)
			}
		}
	}

	return nil
}

// Teardown 清理路由配置
func (rm *RoutingManager) Teardown(enableNAT bool, natInterface string) error {
	log.Printf("[routing] tearing down server routing for %s", rm.tunIfName)

	// 清理 NAT 规则
	if enableNAT && natInterface != "" {
		_ = rm.cleanupNAT(natInterface)
	}

	// 删除客户端地址池路由
	for _, pool := range rm.clientPool {
		_ = rm.deleteClientPoolRoute(pool)
	}

	return nil
}

// setTunIP 设置 TUN 设备 IP 地址（不配置网关）
func (rm *RoutingManager) setTunIP(prefix netip.Prefix, isIPv6 bool) error {
	switch runtime.GOOS {
	case "linux":
		return rm.setTunIPLinux(prefix, isIPv6)
	case "darwin":
		return rm.setTunIPDarwin(prefix, isIPv6)
	case "windows":
		return rm.setTunIPWindows(prefix, isIPv6)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func (rm *RoutingManager) setTunIPLinux(prefix netip.Prefix, isIPv6 bool) error {
	// 只设置 IP 地址，不设置网关
	family := "inet"
	if isIPv6 {
		family = "inet6"
	}

	// ip addr add <prefix> dev <ifname>
	cmd := exec.Command("ip", "addr", "add", prefix.String(), "dev", rm.tunIfName)
	if out, err := cmd.CombinedOutput(); err != nil {
		// 忽略地址已存在的错误
		if !strings.Contains(string(out), "File exists") && !strings.Contains(string(out), "RTNETLINK answers: File exists") {
			return fmt.Errorf("ip addr add: %w (output: %s)", err, string(out))
		}
	}

	// ip link set <ifname> up
	cmd = exec.Command("ip", "link", "set", rm.tunIfName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up: %w (output: %s)", err, string(out))
	}

	// 等待设备进入 UP 状态（最多 2 秒），避免后续 ip route add 报 "Device not up"
	if err := rm.waitLinkUp(rm.tunIfName, 2*time.Second); err != nil {
		log.Printf("[routing] warning: %v, proceeding anyway", err)
	}

	_ = family // 避免未使用警告
	return nil
}

// waitLinkUp 轮询等待网络设备进入 UP 状态
func (rm *RoutingManager) waitLinkUp(ifname string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ip", "link", "show", ifname).Output()
		if err == nil && (strings.Contains(string(out), "state UP") || strings.Contains(string(out), "state UNKNOWN")) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s to come up", ifname)
}

func (rm *RoutingManager) setTunIPDarwin(prefix netip.Prefix, isIPv6 bool) error {
	// macOS: ifconfig <ifname> <ip> <netmask> up
	addr := prefix.Addr().String()
	bits := prefix.Bits()

	args := []string{rm.tunIfName}
	if isIPv6 {
		args = append(args, "inet6", addr, "prefixlen", fmt.Sprint(bits), "up")
	} else {
		// 计算 netmask
		netmask := prefixToNetmask(bits)
		args = append(args, addr, netmask, "up")
	}

	cmd := exec.Command("ifconfig", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig: %w (output: %s)", err, string(out))
	}

	return nil
}

func (rm *RoutingManager) setTunIPWindows(prefix netip.Prefix, isIPv6 bool) error {
	// Windows: netsh interface ip set address
	addr := prefix.Addr().String()
	bits := prefix.Bits()

	if isIPv6 {
		cmd := exec.Command("netsh", "interface", "ipv6", "set", "address",
			rm.tunIfName, addr+"/"+fmt.Sprint(bits))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh ipv6: %w (output: %s)", err, string(out))
		}
	} else {
		netmask := prefixToNetmask(bits)
		cmd := exec.Command("netsh", "interface", "ip", "set", "address",
			rm.tunIfName, "static", addr, netmask)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh ip: %w (output: %s)", err, string(out))
		}
	}

	return nil
}

// addClientPoolRoute 添加客户端地址池路由
func (rm *RoutingManager) addClientPoolRoute(pool netip.Prefix) error {
	switch runtime.GOOS {
	case "linux":
		// ip route add <pool> dev <ifname>
		cmd := exec.Command("ip", "route", "add", pool.String(), "dev", rm.tunIfName)
		if out, err := cmd.CombinedOutput(); err != nil {
			// 忽略已存在的路由
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip route add: %w (output: %s)", err, string(out))
			}
		}
		return nil

	case "darwin":
		// route add -net <pool> -interface <ifname>
		cmd := exec.Command("route", "add", "-net", pool.String(), "-interface", rm.tunIfName)
		if out, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("route add: %w (output: %s)", err, string(out))
			}
		}
		return nil

	case "windows":
		// route add <pool> mask <netmask> <gateway> if <ifindex>
		// 简化：使用 netsh
		cmd := exec.Command("route", "add", pool.String(), "if", rm.tunIfName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("route add: %w (output: %s)", err, string(out))
		}
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// deleteClientPoolRoute 删除客户端地址池路由
func (rm *RoutingManager) deleteClientPoolRoute(pool netip.Prefix) error {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ip", "route", "del", pool.String(), "dev", rm.tunIfName)
		_ = cmd.Run()
		return nil

	case "darwin":
		cmd := exec.Command("route", "delete", "-net", pool.String(), "-interface", rm.tunIfName)
		_ = cmd.Run()
		return nil

	case "windows":
		cmd := exec.Command("route", "delete", pool.String())
		_ = cmd.Run()
		return nil

	default:
		return nil
	}
}

// enableIPForwarding 启用 IP 转发
func (rm *RoutingManager) enableIPForwarding() error {
	switch runtime.GOOS {
	case "linux":
		// sysctl -w net.ipv4.ip_forward=1
		cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
		_ = cmd.Run()

		// sysctl -w net.ipv6.conf.all.forwarding=1
		cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
		_ = cmd.Run()

		return nil

	case "darwin":
		// sysctl -w net.inet.ip.forwarding=1
		cmd := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1")
		_ = cmd.Run()

		// sysctl -w net.inet6.ip6.forwarding=1
		cmd = exec.Command("sysctl", "-w", "net.inet6.ip6.forwarding=1")
		_ = cmd.Run()

		return nil

	case "windows":
		// Windows 默认启用转发
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// setupNAT 配置 NAT（SNAT/MASQUERADE）和 FORWARD 规则
func (rm *RoutingManager) setupNAT(outInterface string) error {
	switch runtime.GOOS {
	case "linux":
		// 0. 先 best-effort 清理一次旧规则，再追加新规则。
		//
		// 背景：服务端非优雅退出（kill -9 / OOM / panic / 容器重启等）时，
		// 上一轮 setupNAT 注入的 iptables 规则会**残留**在内核 netfilter 表中。
		// 旧版本 setupNAT 直接 -A / -I 追加，结果每次重启都把同一条规则又添一次：
		// 实测看到 ip6tables -t nat -nvL POSTROUTING 中堆了 5 条完全相同的
		// MASQUERADE，这种重复虽然不影响功能，但 cleanup 时只删一条，越积越多，
		// 也让 -nvL 的 pkts/bytes 计数失真，给排障增加噪音。
		//
		// 这里调一次 cleanupNAT 把可能存在的旧规则全删掉（参数完全对齐），
		// 错误全部忽略——目标只是去重，不是要清理失败时阻断启动。
		_ = rm.cleanupNAT(outInterface)

		// 1. 添加 FORWARD 规则：允许 TUN → 出口 和 出口 → TUN（ESTABLISHED,RELATED）的双向转发。
		// 许多 VPS 默认 iptables -P FORWARD DROP，不加这些规则流量会被静默丢弃。
		// 使用 -I（Insert 到链首）确保优先于可能存在的 DROP 规则。

		// TUN → outbound：允许来自客户端池的出站流量
		cmd := exec.Command("iptables", "-I", "FORWARD",
			"-i", rm.tunIfName, "-o", outInterface, "-j", "ACCEPT")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[routing] warning: iptables forward out: %v (output: %s)", err, string(out))
		}

		// outbound → TUN：允许已建立连接的回程流量
		cmd = exec.Command("iptables", "-I", "FORWARD",
			"-i", outInterface, "-o", rm.tunIfName,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[routing] warning: iptables forward in: %v (output: %s)", err, string(out))
		}

		// IPv6 FORWARD 规则
		cmd = exec.Command("ip6tables", "-I", "FORWARD",
			"-i", rm.tunIfName, "-o", outInterface, "-j", "ACCEPT")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[routing] warning: ip6tables forward out: %v (output: %s)", err, string(out))
		}
		cmd = exec.Command("ip6tables", "-I", "FORWARD",
			"-i", outInterface, "-o", rm.tunIfName,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[routing] warning: ip6tables forward in: %v (output: %s)", err, string(out))
		}

		// 3. TCP MSS Clamping：防止隧道内 MTU 黑洞
		//
		// 外层开销：QUIC short header(~20B) + HTTP/3 Datagram(~5B) + Salamander(8B)
		// + UDP(8B) + 外层 IP(20/40B) ≈ 60-80B。
		//
		// IPv4：MSS=mssV4ClampBytes(1200) → TCP+IP=1240B → 加 60B 外层 ≈ 1300B UDP，
		//       适配任何合理的公网 path MTU（PPPoE 1492、4G 1300+）。
		// IPv6：IPv6 头比 IPv4 多 20B，因此 IPv6 MSS 必须再 -20。
		//       MSS=mssV6ClampBytes(1180) → TCP+IPv6=1240B（与 IPv4 持平），
		//       否则 1200 时 TCP+IPv6=1260B 会落入实测的 IPv6 path MTU 黑洞
		//       （详见会话日志 2026-04-25：IPv6 ping 1200 字节通、1260 字节超时）。
		//
		// 表现：HTTP/小响应正常；HTTPS 大握手 / DNSv6 解析超时 → 改 1180 后通。
		for _, args := range buildMSSClampRules(rm.tunIfName) {
			cmd = exec.Command(args[0], args[1:]...)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[routing] warning: %s mss clamp: %v (output: %s)", args[0], err, string(out))
			}
		}

		// 2. NAT MASQUERADE
		// iptables -t nat -A POSTROUTING -s <client_pool> -o <out_if> -j MASQUERADE
		for _, pool := range rm.clientPool {
			if pool.Addr().Is4() {
				cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
					"-s", pool.String(), "-o", outInterface, "-j", "MASQUERADE")
				if out, err := cmd.CombinedOutput(); err != nil {
					return fmt.Errorf("iptables masquerade: %w (output: %s)", err, string(out))
				}
			} else {
				cmd := exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING",
					"-s", pool.String(), "-o", outInterface, "-j", "MASQUERADE")
				if out, err := cmd.CombinedOutput(); err != nil {
					return fmt.Errorf("ip6tables masquerade: %w (output: %s)", err, string(out))
				}
			}
		}
		return nil

	case "darwin":
		// macOS 使用 pfctl
		log.Printf("[routing] warning: NAT on macOS requires manual pfctl configuration")
		return nil

	case "windows":
		// Windows 使用 netsh
		log.Printf("[routing] warning: NAT on Windows requires manual ICS configuration")
		return nil

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// cleanupNAT 清理 NAT 和 FORWARD 规则
func (rm *RoutingManager) cleanupNAT(outInterface string) error {
	switch runtime.GOOS {
	case "linux":
		// 清理 FORWARD 规则
		cmd := exec.Command("iptables", "-D", "FORWARD",
			"-i", rm.tunIfName, "-o", outInterface, "-j", "ACCEPT")
		_ = cmd.Run()
		cmd = exec.Command("iptables", "-D", "FORWARD",
			"-i", outInterface, "-o", rm.tunIfName,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		_ = cmd.Run()
		cmd = exec.Command("ip6tables", "-D", "FORWARD",
			"-i", rm.tunIfName, "-o", outInterface, "-j", "ACCEPT")
		_ = cmd.Run()
		cmd = exec.Command("ip6tables", "-D", "FORWARD",
			"-i", outInterface, "-o", rm.tunIfName,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		_ = cmd.Run()

		// 清理 MSS Clamping 规则（mangle 表）：用 buildMSSClampRules 反推 -D 命令，
		// 保证 add / del 规则参数永远一致。同时清理历史 IPv6=1200 规则，
		// 避免升级到当前版本（IPv6=1180）时旧规则成"幽灵"。
		for _, args := range buildMSSClampRules(rm.tunIfName) {
			delArgs := append([]string{}, args...)
			for i, a := range delArgs {
				if a == "-A" {
					delArgs[i] = "-D"
				}
			}
			_ = exec.Command(delArgs[0], delArgs[1:]...).Run()
		}
		for _, dir := range []string{"-o", "-i"} {
			_ = exec.Command("ip6tables", "-t", "mangle", "-D", "FORWARD",
				dir, rm.tunIfName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
				"-j", "TCPMSS", "--set-mss", "1200").Run()
		}
		for _, pool := range rm.clientPool {
			if pool.Addr().Is4() {
				cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
					"-s", pool.String(), "-o", outInterface, "-j", "MASQUERADE")
				_ = cmd.Run()
			} else {
				cmd := exec.Command("ip6tables", "-t", "nat", "-D", "POSTROUTING",
					"-s", pool.String(), "-o", outInterface, "-j", "MASQUERADE")
				_ = cmd.Run()
			}
		}
		return nil

	default:
		return nil
	}
}

// detectDefaultInterface 检测默认网络接口
func (rm *RoutingManager) detectDefaultInterface() string {
	switch runtime.GOOS {
	case "linux":
		// ip route show default
		cmd := exec.Command("ip", "route", "show", "default")
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		// 解析输出：default via <gateway> dev <interface>
		fields := strings.Fields(string(out))
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
		return ""

	case "darwin":
		// route -n get default
		cmd := exec.Command("route", "-n", "get", "default")
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		// 解析输出：interface: <interface>
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "interface:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					return fields[1]
				}
			}
		}
		return ""

	default:
		return ""
	}
}

// prefixToNetmask 将前缀长度转换为 netmask
// MSS clamp 数值定义（变更说明见 setupNAT 注释）
const (
	mssV4ClampBytes = 1200 // IPv4: TCP+IP=1240B
	mssV6ClampBytes = 1180 // IPv6: TCP+IPv6=1240B（与 IPv4 持平，避开实测 IPv6 黑洞）
)

// buildMSSClampRules 返回需要 -A 到 mangle FORWARD 链的全部 MSS clamp 规则。
//
// 抽出来的目的：
//  1. add (setupNAT) 与 del (cleanupNAT) 共用同一组规则定义，避免参数偏差导致
//     "明明 add 了却 del 不掉、积累出多份重复规则"的问题（之前 IPv6 NAT 表里堆了
//     5 条相同 MASQUERADE 就是这个 pattern 的另一种症状）；
//  2. 升级 MSS 数值（如 IPv6: 1200→1180）时只需改常量，不需改两处分散的命令字符串。
//
// 每个返回值是一个 exec.Command 的 args 序列（首元素是命令名）。
func buildMSSClampRules(tunIfName string) [][]string {
	mkRule := func(prog, dir, mss string) []string {
		return []string{
			prog, "-t", "mangle", "-A", "FORWARD",
			dir, tunIfName, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", mss,
		}
	}
	v4 := strconv.Itoa(mssV4ClampBytes)
	v6 := strconv.Itoa(mssV6ClampBytes)
	return [][]string{
		mkRule("iptables", "-o", v4),
		mkRule("iptables", "-i", v4),
		mkRule("ip6tables", "-o", v6),
		mkRule("ip6tables", "-i", v6),
	}
}

func prefixToNetmask(bits int) string {
	if bits < 0 || bits > 32 {
		return "255.255.255.255"
	}

	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
