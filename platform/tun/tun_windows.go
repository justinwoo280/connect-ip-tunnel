//go:build windows

package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"connect-ip-tunnel/observability"

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
		if err := run("netsh", "interface", "ip", "set", "address", "name="+ifName, "static", ip, mask); err != nil {
			return fmt.Errorf("set ipv4 address: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "set", "subinterface", ifName, fmt.Sprintf("mtu=%d", mtu), "store=active"); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "set", "interface", ifName, "metric=1"); err != nil {
			return fmt.Errorf("set ipv4 metric: %w", err)
		}

		// 添加 split-default 路由（0.0.0.0/1 + 128.0.0.0/1 = 全部 IPv4，优先级高于 0.0.0.0/0）
		// WinTUN 是 L3 点对点设备，无 ARP 解析。
		// /32 时 nexthop=自身 IP 在部分 Windows 版本上不可达，
		// 省略 nexthop 让 netsh 创建 on-link 路由（直接绑定到接口），TUN 设备天然支持。
		if prefix.Bits() == 32 {
			// on-link 路由：不指定 nexthop，流量直接发往 TUN 接口
			if err := run("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", ifName, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv4 route 0.0.0.0/1: %w", err)
			}
			if err := run("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", ifName, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv4 route 128.0.0.0/1: %w", err)
			}
		} else {
			gw := deriveGatewayV4(prefix)
			if err := run("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv4 route 0.0.0.0/1: %w", err)
			}
			if err := run("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv4 route 128.0.0.0/1: %w", err)
			}
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
		if err := run("netsh", "interface", "ipv6", "set", "address", ifName, prefix.Addr().String()); err != nil {
			return fmt.Errorf("set ipv6 address: %w", err)
		}

		// TUN 是 L3 点对点设备，不需要 NDP（Neighbor Discovery Protocol）。
		// dadtransmits=0：跳过 DAD（减少 :: 源地址包）
		// routerdiscovery=disabled：禁用 Router Solicitation
		if err := run("netsh", "interface", "ipv6", "set", "interface", ifName,
			"dadtransmits=0", "routerdiscovery=disabled"); err != nil {
			log.Printf("[tun] warning: suppress ipv6 ndp: %v", err)
		}

		// 加固 IPv6 配置：阻止 Windows 在 TUN 上误用 SLAAC / DHCPv6 派生出的地址。
		//   - ManagedAddressConfiguration Disabled：禁用有状态自动配置（DHCPv6 地址）
		//   - OtherStatefulConfiguration Disabled：禁用 DHCPv6 其它选项（DNS / NTP）
		//   - WeakHostSend / WeakHostReceive Enabled：允许跨接口源地址（避免严格主机模型阻断 ULA）
		// 命令失败被视为非致命（旧版 PowerShell 可能不识别某些参数），仅打 warning。
		hardenCmd := fmt.Sprintf(
			`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv6 `+
				`-ManagedAddressConfiguration Disabled `+
				`-OtherStatefulConfiguration Disabled `+
				`-RouterDiscovery Disabled `+
				`-Dhcp Disabled `+
				`-ErrorAction SilentlyContinue`,
			ifName,
		)
		if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", hardenCmd).CombinedOutput(); err != nil {
			log.Printf("[tun] warning: harden ipv6 interface: %v (output: %s)",
				err, strings.TrimSpace(string(out)))
		}

		// 关闭 TUN 上的 RFC 4941 临时地址（隐私扩展）。
		// 临时地址会被 RFC 6724 选源算法优先选中，导致服务端看到非 ADDRESS_ASSIGN 范围的源 IP。
		// PowerShell 接口级 cmdlet 名称随版本不同（Set-NetIPv6Protocol 是全局），
		// 优先尝试 Get-NetIPInterface 上的属性，失败则忽略（仅记录 warning）。
		tempAddrCmd := fmt.Sprintf(
			`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv6 `+
				`-AdvertiseDefaultRoute Disabled `+
				`-ErrorAction SilentlyContinue; `+
				`Set-NetIPv6Protocol -UseTemporaryAddresses Disabled -ErrorAction SilentlyContinue`,
			ifName,
		)
		if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", tempAddrCmd).CombinedOutput(); err != nil {
			log.Printf("[tun] warning: disable RFC 4941 temporary addresses: %v (output: %s)",
				err, strings.TrimSpace(string(out)))
		}

		// 关键修复：将 TUN 上所有 link-local (fe80::) 地址标记为 SkipAsSource=true。
		// Windows 会自动为所有 IPv6 接口生成 fe80:: 地址且 SkipAsSource=false，
		// 导致 RFC 6724 源地址选择可能选中 fe80:: 而非分配的 ULA (fd00::2)。
		// 服务端 connect-ip-go 检查源地址必须在 ADDRESS_ASSIGN 范围内，
		// fe80:: 不在范围 → 数据包被拒绝 → IPv6 完全不通。
		//
		// 设置 SkipAsSource=true 后，Windows 将只使用 fd00::2 作为源地址。
		psCmd := fmt.Sprintf(
			`Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 | `+
				`Where-Object { $_.PrefixOrigin -eq 'WellKnown' } | `+
				`Set-NetIPAddress -SkipAsSource $true -ErrorAction SilentlyContinue`,
			ifName,
		)
		if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput(); err != nil {
			log.Printf("[tun] warning: set link-local skipassource: %v (output: %s)", err, strings.TrimSpace(string(out)))
		}

		if err := run("netsh", "interface", "ipv6", "set", "interface", ifName, "metric=1"); err != nil {
			return fmt.Errorf("set ipv6 metric: %w", err)
		}

		// 同 IPv4：/128 时使用 on-link 路由
		if prefix.Bits() == 128 {
			if err := run("netsh", "interface", "ipv6", "add", "route", "::/1", ifName, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv6 route ::/1: %w", err)
			}
			if err := run("netsh", "interface", "ipv6", "add", "route", "8000::/1", ifName, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv6 route 8000::/1: %w", err)
			}
		} else {
			gw6 := deriveGatewayV6(prefix)
			if err := run("netsh", "interface", "ipv6", "add", "route", "::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv6 route ::/1: %w", err)
			}
			if err := run("netsh", "interface", "ipv6", "add", "route", "8000::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
				return fmt.Errorf("add ipv6 route 8000::/1: %w", err)
			}
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

	// IPv6 自检：仅当配置了 IPv6 时执行；失败仅记录日志 + metric，不阻塞 setup。
	if cfg.IPv6CIDR != "" {
		runIPv6SelfCheck(ifName, cfg.IPv6CIDR)
	}

	return nil
}

// runIPv6SelfCheck 在 TUN setup / 差量更新完成后做一组 IPv6 健康检查。
//
// 当前覆盖的阶段（任一失败仅记 warning + metric，不返回错误）：
//   - link_local：检查 TUN 上至少存在一个 link-local 地址；
//   - addr_present：检查分配到的 ULA 地址实际生效；
//   - gateway_ping：尝试 ping 一次自己的 IPv6 网关（如 fd00::1，超时 1s）。
//
// 任何一项失败都会输出 "IPv6 self-check: failed reason=..." 形式的 ERROR 日志，
// 与 spec §4.7 验收标准一致。
func runIPv6SelfCheck(ifName, ipv6CIDR string) {
	if !strings.Contains(ipv6CIDR, "/") {
		ipv6CIDR += "/64"
	}
	prefix, err := netip.ParsePrefix(ipv6CIDR)
	if err != nil {
		log.Printf("[tun] IPv6 self-check: skipped (bad cidr %q): %v", ipv6CIDR, err)
		return
	}
	addr := prefix.Addr().String()

	// stage: link_local
	llCmd := fmt.Sprintf(
		`(Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.IPAddress -like 'fe80*' } | Measure-Object).Count`,
		ifName,
	)
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", llCmd).CombinedOutput(); err != nil {
		log.Printf("[tun] IPv6 self-check: failed reason=link_local query err=%v", err)
		observability.Global.RecordIPv6SelfCheckFailure("link_local")
	} else if cnt := strings.TrimSpace(string(out)); cnt == "0" {
		log.Printf("[tun] IPv6 self-check: failed reason=link_local count=0")
		observability.Global.RecordIPv6SelfCheckFailure("link_local")
	}

	// stage: addr_present
	addrCmd := fmt.Sprintf(
		`(Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 -IPAddress '%s' -ErrorAction SilentlyContinue | Measure-Object).Count`,
		ifName, addr,
	)
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", addrCmd).CombinedOutput(); err != nil {
		log.Printf("[tun] IPv6 self-check: failed reason=addr_present query err=%v addr=%s", err, addr)
		observability.Global.RecordIPv6SelfCheckFailure("addr_present")
	} else if cnt := strings.TrimSpace(string(out)); cnt == "0" {
		log.Printf("[tun] IPv6 self-check: failed reason=addr_present addr=%s not found on %s", addr, ifName)
		observability.Global.RecordIPv6SelfCheckFailure("addr_present")
	}

	// stage: gateway_ping —— 尝试 ping IPv6 网关，超时 1s，失败仅记录。
	// /128 host route 的网关无意义；其它子网用 deriveGatewayV6。
	if prefix.Bits() < 128 {
		gw := deriveGatewayV6(prefix)
		// ping -6 -n 1 -w 1000 <gw>
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "ping", "-6", "-n", "1", "-w", "1000", gw).Run(); err != nil {
			log.Printf("[tun] IPv6 self-check: failed reason=gateway_ping gw=%s err=%v", gw, err)
			observability.Global.RecordIPv6SelfCheckFailure("gateway_ping")
		} else {
			log.Printf("[tun] IPv6 self-check: ok (gateway=%s, addr=%s)", gw, addr)
			return
		}
	}
	log.Printf("[tun] IPv6 self-check: completed (addr=%s)", addr)
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

// UpdateAddress 在 Windows 上做地址族级别的差量更新：
//   - 接口名变化 → 退化为完整 Teardown(prev) + Setup(next)；
//   - 仅 IPv4 / IPv6 / DNS 单族变化 → 仅 teardown + 重建变化的那一族，
//     避免误触另一族（例如 IPv4 变化时不动已工作的 IPv6 路由）；
//   - MTU 变化 → 通过 netsh subinterface 单独应用；
//   - prev 与 next 完全相同 → 直接返回 nil。
//
// 设计动机：netsh 命令在 Windows 上较慢（数百 ms），且
// 反复 add/delete IPv6 路由会触发 RA 重协商，导致短暂 IPv6 中断。
// 真实差量可以把单族变更收敛在 < 200ms 内，另一族完全不受影响。
func (c *windowsConfigurator) UpdateAddress(prev, next NetworkConfig) error {
	if prev.Equal(next) {
		return nil
	}
	// 接口名变化属于罕见场景（重新创建 TUN），走完整路径最安全。
	if prev.IfName != next.IfName || prev.IfName == "" {
		return updateAddressByReSetup(c, prev, next)
	}
	ifName := next.IfName

	// IPv4 差量
	if prev.IPv4CIDR != next.IPv4CIDR {
		if err := c.tearDownIPv4Locked(ifName); err != nil {
			log.Printf("[tun] update v4 teardown: %v", err)
		}
		if next.IPv4CIDR != "" {
			if err := c.setupIPv4Locked(ifName, next.IPv4CIDR, next.MTU); err != nil {
				return fmt.Errorf("update ipv4: %w", err)
			}
		}
	}

	// IPv6 差量
	if prev.IPv6CIDR != next.IPv6CIDR {
		if err := c.tearDownIPv6Locked(ifName); err != nil {
			log.Printf("[tun] update v6 teardown: %v", err)
		}
		if next.IPv6CIDR != "" {
			if err := c.setupIPv6Locked(ifName, next.IPv6CIDR); err != nil {
				return fmt.Errorf("update ipv6: %w", err)
			}
		}
	}

	// DNS 差量（v4）
	if prev.DNSv4 != next.DNSv4 {
		if next.DNSv4 == "" {
			_ = run("netsh", "interface", "ip", "set", "dns", "name="+ifName, "dhcp")
		} else if err := run("netsh", "interface", "ip", "set", "dns", "name="+ifName, "static", next.DNSv4, "primary"); err != nil {
			log.Printf("[tun] update dnsv4: %v", err)
		}
		_ = removeNRPTRule()
		if next.DNSv4 != "" {
			if err := applyNRPTRule(next.DNSv4); err != nil {
				log.Printf("[tun] NRPT reapply: %v", err)
			}
		}
		_ = run("ipconfig", "/flushdns")
	}

	// DNS 差量（v6）
	if prev.DNSv6 != next.DNSv6 {
		_ = run("netsh", "interface", "ipv6", "delete", "dnsserver", ifName, "all")
		if next.DNSv6 != "" {
			if err := run("netsh", "interface", "ipv6", "add", "dnsserver", ifName, next.DNSv6, "index=1"); err != nil {
				log.Printf("[tun] update dnsv6: %v", err)
			}
		}
	}

	// MTU 同步（独立于地址变化）
	if prev.MTU != next.MTU && next.MTU > 0 {
		_ = run("netsh", "interface", "ipv4", "set", "subinterface", ifName, fmt.Sprintf("mtu=%d", next.MTU), "store=active")
		_ = run("netsh", "interface", "ipv6", "set", "subinterface", ifName, fmt.Sprintf("mtu=%d", next.MTU), "store=active")
	}

	return nil
}

// tearDownIPv4Locked 删除 IPv4 split-default 路由，地址会随新 set address 命令被替换。
func (c *windowsConfigurator) tearDownIPv4Locked(ifName string) error {
	_ = run("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", ifName)
	_ = run("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", ifName)
	return nil
}

// tearDownIPv6Locked 删除 IPv6 split-default 路由 + 旧 unicast 地址。
func (c *windowsConfigurator) tearDownIPv6Locked(ifName string) error {
	_ = run("netsh", "interface", "ipv6", "delete", "route", "::/1", ifName)
	_ = run("netsh", "interface", "ipv6", "delete", "route", "8000::/1", ifName)
	// 与 IPv4 不同，IPv6 set address 不会替换旧地址，需要主动清掉非 link-local 的 manual 地址
	psCmd := fmt.Sprintf(
		`Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.PrefixOrigin -eq 'Manual' } | `+
			`Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue`,
		ifName,
	)
	_, _ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	return nil
}

// setupIPv4Locked 仅做 IPv4 地址 + 路由配置，不动 DNS / IPv6 / NRPT。
// 抽出此 helper 是为了让 UpdateAddress 与 Setup 共享同一套顺序与策略。
func (c *windowsConfigurator) setupIPv4Locked(ifName, cidr string, mtu int) error {
	if !strings.Contains(cidr, "/") {
		cidr += "/24"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("parse ipv4 cidr: %w", err)
	}
	ip := prefix.Addr().Unmap().String()
	mask := prefixToMask(prefix)
	if err := run("netsh", "interface", "ip", "set", "address", "name="+ifName, "static", ip, mask); err != nil {
		return fmt.Errorf("set ipv4 address: %w", err)
	}
	if mtu > 0 {
		_ = run("netsh", "interface", "ipv4", "set", "subinterface", ifName, fmt.Sprintf("mtu=%d", mtu), "store=active")
	}
	_ = run("netsh", "interface", "ipv4", "set", "interface", ifName, "metric=1")
	if prefix.Bits() == 32 {
		if err := run("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", ifName, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv4 route 0.0.0.0/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", ifName, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv4 route 128.0.0.0/1: %w", err)
		}
	} else {
		gw := deriveGatewayV4(prefix)
		if err := run("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv4 route 0.0.0.0/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv4 route 128.0.0.0/1: %w", err)
		}
	}
	return nil
}

// setupIPv6Locked 仅做 IPv6 地址 + NDP 抑制 + 路由 + link-local SkipAsSource。
// 与 Setup 主路径共享同一套加固 + self-check 逻辑。
func (c *windowsConfigurator) setupIPv6Locked(ifName, cidr string) error {
	if !strings.Contains(cidr, "/") {
		cidr += "/64"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("parse ipv6 cidr: %w", err)
	}
	if err := run("netsh", "interface", "ipv6", "set", "address", ifName, prefix.Addr().String()); err != nil {
		return fmt.Errorf("set ipv6 address: %w", err)
	}
	if err := run("netsh", "interface", "ipv6", "set", "interface", ifName,
		"dadtransmits=0", "routerdiscovery=disabled"); err != nil {
		log.Printf("[tun] warning: suppress ipv6 ndp: %v", err)
	}
	hardenIPv6Interface(ifName)
	psCmd := fmt.Sprintf(
		`Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 | `+
			`Where-Object { $_.PrefixOrigin -eq 'WellKnown' } | `+
			`Set-NetIPAddress -SkipAsSource $true -ErrorAction SilentlyContinue`,
		ifName,
	)
	_, _ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	_ = run("netsh", "interface", "ipv6", "set", "interface", ifName, "metric=1")
	if prefix.Bits() == 128 {
		if err := run("netsh", "interface", "ipv6", "add", "route", "::/1", ifName, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv6 route ::/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route", "8000::/1", ifName, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv6 route 8000::/1: %w", err)
		}
	} else {
		gw6 := deriveGatewayV6(prefix)
		if err := run("netsh", "interface", "ipv6", "add", "route", "::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv6 route ::/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route", "8000::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("add ipv6 route 8000::/1: %w", err)
		}
	}
	// 差量路径上同样跑一遍 self-check，确保 prefix 切换后真的可达。
	runIPv6SelfCheck(ifName, cidr)
	return nil
}

// hardenIPv6Interface 抽出 Setup 中重复的 IPv6 加固命令（DHCPv6 / RA / RFC 4941 关闭），
// 让差量更新路径也能复用。
func hardenIPv6Interface(ifName string) {
	hardenCmd := fmt.Sprintf(
		`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv6 `+
			`-ManagedAddressConfiguration Disabled `+
			`-OtherStatefulConfiguration Disabled `+
			`-RouterDiscovery Disabled `+
			`-Dhcp Disabled `+
			`-ErrorAction SilentlyContinue`,
		ifName,
	)
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", hardenCmd).CombinedOutput(); err != nil {
		log.Printf("[tun] warning: harden ipv6 interface: %v (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	tempAddrCmd := fmt.Sprintf(
		`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv6 `+
			`-AdvertiseDefaultRoute Disabled `+
			`-ErrorAction SilentlyContinue; `+
			`Set-NetIPv6Protocol -UseTemporaryAddresses Disabled -ErrorAction SilentlyContinue`,
		ifName,
	)
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", tempAddrCmd).CombinedOutput(); err != nil {
		log.Printf("[tun] warning: disable RFC 4941 temporary addresses: %v (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
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
