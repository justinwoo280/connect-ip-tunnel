package server

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
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

		// 清理 MASQUERADE 规则
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
func prefixToNetmask(bits int) string {
	if bits < 0 || bits > 32 {
		return "255.255.255.255"
	}

	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
