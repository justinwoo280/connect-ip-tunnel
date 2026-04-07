//go:build windows

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type windowsFactory struct{}

func NewFactory() Factory {
	return &windowsFactory{}
}

func (f *windowsFactory) Create(cfg CreateConfig) (Device, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = "citun0"
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1400
	}

	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun device: %w", err)
	}
	return &windowsDevice{dev: dev, mtu: mtu}, nil
}

type windowsDevice struct {
	dev       wgtun.Device
	mtu       int
	closeOnce sync.Once

	// 单包模式缓存，避免热路径分配
	singleBufs  [][]byte
	singleSizes []int
}

func (d *windowsDevice) Name() (string, error) {
	return d.dev.Name()
}

func (d *windowsDevice) MTU() int {
	if mtu, err := d.dev.MTU(); err == nil && mtu > 0 {
		return mtu
	}
	return d.mtu
}

func (d *windowsDevice) ReadPacket(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if d.singleBufs == nil {
		d.singleBufs = make([][]byte, 1)
		d.singleSizes = make([]int, 1)
	}
	d.singleBufs[0] = buf
	n, err := d.dev.Read(d.singleBufs, d.singleSizes, 0)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, nil
	}
	return d.singleSizes[0], nil
}

func (d *windowsDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if d.singleBufs == nil {
		d.singleBufs = make([][]byte, 1)
	}
	d.singleBufs[0] = pkt
	n, err := d.dev.Write(d.singleBufs, 0)
	if err != nil {
		return err
	}
	if n <= 0 {
		return fmt.Errorf("tun write returned 0 packets")
	}
	return nil
}

func (d *windowsDevice) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.dev.Close()
	})
	return closeErr
}

// 批量读写接口
func (d *windowsDevice) BatchSize() int {
	return d.dev.BatchSize()
}

func (d *windowsDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.dev.Read(bufs, sizes, offset)
}

func (d *windowsDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.dev.Write(bufs, offset)
}

type windowsConfigurator struct{}

func NewConfigurator() Configurator {
	return &windowsConfigurator{}
}

func (c *windowsConfigurator) Setup(cfg NetworkConfig) error {
	ifName := strings.TrimSpace(cfg.IfName)
	if ifName == "" {
		return fmt.Errorf("setup tun: interface name is empty")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1400
	}

	if cfg.IPv4CIDR != "" {
		ipCIDR := cfg.IPv4CIDR
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/24"
		}
		prefix, err := netip.ParsePrefix(ipCIDR)
		if err != nil {
			return fmt.Errorf("parse ipv4 cidr: %w", err)
		}
		ip := prefix.Addr().Unmap().String()
		mask := prefixToMask(prefix)
		gw := deriveGatewayV4(prefix)

		if err := run("netsh", "interface", "ip", "set", "address", "name="+ifName, "static", ip, mask); err != nil {
			return fmt.Errorf("set ipv4 address: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "set", "subinterface", ifName, fmt.Sprintf("mtu=%d", mtu), "store=active"); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "set", "interface", ifName, "metric=1"); err != nil {
			return fmt.Errorf("set ipv4 metric: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv4 route 0.0.0.0/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv4 route 128.0.0.0/1: %w", err)
		}
	}

	if cfg.DNSv4 != "" {
		if err := run("netsh", "interface", "ip", "set", "dns", "name="+ifName, "static", cfg.DNSv4, "primary"); err != nil {
			return fmt.Errorf("set ipv4 dns: %w", err)
		}
	}

	if cfg.IPv6CIDR != "" {
		ipCIDR := cfg.IPv6CIDR
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/64"
		}
		prefix, err := netip.ParsePrefix(ipCIDR)
		if err != nil {
			return fmt.Errorf("parse ipv6 cidr: %w", err)
		}
		gw6 := deriveGatewayV6(prefix)

		if err := run("netsh", "interface", "ipv6", "set", "address", ifName, prefix.Addr().String()); err != nil {
			return fmt.Errorf("set ipv6 address: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "set", "interface", ifName, "metric=1"); err != nil {
			return fmt.Errorf("set ipv6 metric: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route", "::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv6 route ::/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route", "8000::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv6 route 8000::/1: %w", err)
		}
	}

	if cfg.DNSv6 != "" {
		if err := run("netsh", "interface", "ipv6", "add", "dnsserver", ifName, cfg.DNSv6, "index=1"); err != nil {
			return fmt.Errorf("set ipv6 dns: %w", err)
		}
	}

	// 清理上次可能残留的状态（应对进程被强制 kill 的情况）
	restoreOtherDNS(ifName)
	_ = removeNRPTRule()
	suppressOtherDNS(ifName)
	// 重新应用 NRPT 规则
	if cfg.DNSv4 != "" {
		if err := applyNRPTRule(cfg.DNSv4); err != nil {
			log.Printf("[tun] NRPT rule apply failed (non-fatal): %v", err)
		}
	}
	_ = run("ipconfig", "/flushdns")

	return nil
}

func (c *windowsConfigurator) Teardown(ifName string) error {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil
	}
	_ = run("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", ifName)
	_ = run("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", ifName)
	_ = run("netsh", "interface", "ipv6", "delete", "route", "::/1", ifName)
	_ = run("netsh", "interface", "ipv6", "delete", "route", "8000::/1", ifName)
	_ = removeNRPTRule()
	restoreOtherDNS(ifName)
	_ = run("ipconfig", "/flushdns")
	return nil
}

func suppressOtherDNS(tunIfName string) {
	psCmd := fmt.Sprintf(
		`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne '%s' } | ForEach-Object { `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -InterfaceMetric 9999 -ErrorAction SilentlyContinue; `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -InterfaceMetric 9999 -ErrorAction SilentlyContinue `+
			`}`,
		tunIfName,
	)
	_, _ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
}

func restoreOtherDNS(tunIfName string) {
	psCmd := fmt.Sprintf(
		`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne '%s' } | ForEach-Object { `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction SilentlyContinue; `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -AutomaticMetric Enabled -ErrorAction SilentlyContinue `+
			`}`,
		tunIfName,
	)
	_, _ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
}

func applyNRPTRule(dns string) error {
	cmd := fmt.Sprintf(
		`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'connect-ip-tunnel' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; `+
			`Add-DnsClientNrptRule -Namespace '.' -NameServers '%s' -Comment 'connect-ip-tunnel'`,
		dns,
	)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply nrpt rule: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeNRPTRule() error {
	_, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'connect-ip-tunnel' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue`,
	).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

// deriveGatewayV4 派生 IPv4 路由的 nexthop 地址。
//
// Windows netsh route add 必须指定一个 nexthop，但 Connect-IP 分配的是 /32 单主机地址，
// 不存在"同网段网关"的概念。
// 处理策略：
//   - /32：用接口自身 IP 作为 nexthop（on-link 语义，Windows 支持）
//   - 其他前缀长度：用网段的第一个可用地址（.1）作为 nexthop，
//     若该地址恰好是接口自身 IP，则顺延到下一个地址
func deriveGatewayV4(prefix netip.Prefix) string {
	addr := prefix.Addr().Unmap()
	// /32 单主机路由：nexthop 用自身 IP（on-link）
	if prefix.Bits() == 32 {
		return addr.String()
	}
	// 其他前缀：取网段第一个可用地址（网络地址 .Next() = .1）
	gw := prefix.Masked().Addr().Next()
	if gw == addr {
		gw = gw.Next()
	}
	// 确保 nexthop 仍在前缀内
	if !prefix.Contains(gw) {
		return addr.String() // 退回 on-link
	}
	return gw.String()
}

// deriveGatewayV6 派生 IPv6 路由的 nexthop 地址，逻辑同 deriveGatewayV4。
func deriveGatewayV6(prefix netip.Prefix) string {
	addr := prefix.Addr()
	// /128 单主机路由：nexthop 用自身 IP（on-link）
	if prefix.Bits() == 128 {
		return addr.String()
	}
	gw := prefix.Masked().Addr().Next()
	if gw == addr {
		gw = gw.Next()
	}
	if !prefix.Contains(gw) {
		return addr.String()
	}
	return gw.String()
}

func prefixToMask(prefix netip.Prefix) string {
	mask := net.CIDRMask(prefix.Bits(), 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
