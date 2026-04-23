//go:build darwin

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type darwinFactory struct{}

func NewFactory() Factory {
	return &darwinFactory{}
}

func (f *darwinFactory) Create(cfg CreateConfig) (Device, error) {
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = "utun"
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1400
	}

	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun device: %w", err)
	}
	return &darwinDevice{dev: dev, mtu: mtu}, nil
}

type darwinDevice struct {
	dev       wgtun.Device
	mtu       int
	closeOnce sync.Once

	// 单包模式缓存，避免热路径分配
	singleBufs  [][]byte
	singleSizes []int
}

func (d *darwinDevice) Name() (string, error) {
	return d.dev.Name()
}

func (d *darwinDevice) MTU() int {
	if mtu, err := d.dev.MTU(); err == nil && mtu > 0 {
		return mtu
	}
	return d.mtu
}

func (d *darwinDevice) ReadPacket(buf []byte) (int, error) {
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

func (d *darwinDevice) WritePacket(pkt []byte) error {
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

func (d *darwinDevice) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.dev.Close()
	})
	return closeErr
}

// 批量读写接口
func (d *darwinDevice) BatchSize() int {
	return d.dev.BatchSize()
}

func (d *darwinDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.dev.Read(bufs, sizes, offset)
}

func (d *darwinDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.dev.Write(bufs, offset)
}

type darwinConfigurator struct{}

func NewConfigurator() Configurator {
	return &darwinConfigurator{}
}

func (c *darwinConfigurator) Setup(cfg NetworkConfig) error {
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
		local := prefix.Addr().Unmap()
		peer := peerAddr(local)

		if err := run("ifconfig", ifName, local.String(), peer.String(), "mtu", fmt.Sprint(mtu), "up"); err != nil {
			return fmt.Errorf("ifconfig ipv4: %w", err)
		}
		if err := run("route", "add", "-net", "0.0.0.0/0", peer.String()); err != nil {
			return fmt.Errorf("add ipv4 default route: %w", err)
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
		if err := run("ifconfig", ifName, "inet6", prefix.Addr().String(), "prefixlen", fmt.Sprint(prefix.Bits()), "up"); err != nil {
			return fmt.Errorf("ifconfig ipv6: %w", err)
		}
		if err := run("route", "add", "-inet6", "default", "-interface", ifName); err != nil {
			return fmt.Errorf("add ipv6 default route: %w", err)
		}
	}

	if cfg.DNSv4 != "" || cfg.DNSv6 != "" {
		_ = setMacOSDNS(cfg.DNSv4, cfg.DNSv6)
	}

	return nil
}

func (c *darwinConfigurator) Teardown(ifName string) error {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil
	}
	_ = run("route", "delete", "-net", "default", "-interface", ifName)
	_ = run("route", "delete", "-inet6", "default", "-interface", ifName)
	_ = run("ifconfig", ifName, "down")
	_ = clearMacOSDNS()
	return nil
}

// UpdateAddress 在 macOS 上走通用 "重新 setup" 兜底路径。
func (c *darwinConfigurator) UpdateAddress(prev, next NetworkConfig) error {
	return updateAddressByReSetup(c, prev, next)
}

func setMacOSDNS(dns, ipv6DNS string) error {
	line := "d.add ServerAddresses *"
	if dns != "" {
		line += " " + dns
	}
	if ipv6DNS != "" {
		line += " " + ipv6DNS
	}
	script := "d.init\n" + line + "\nset State:/Network/Global/DNS\n"
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil set dns: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func clearMacOSDNS() error {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("remove State:/Network/Global/DNS\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil remove dns: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func peerAddr(local netip.Addr) netip.Addr {
	if local.Is4() {
		a := local.As4()
		if a[3] < 255 {
			a[3]++
		} else {
			a[3]--
		}
		return netip.AddrFrom4(a)
	}
	a := local.As16()
	if a[15] < 255 {
		a[15]++
	} else {
		a[15]--
	}
	return netip.AddrFrom16(a)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
