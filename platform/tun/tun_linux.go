//go:build linux && !android

package tun

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type linuxFactory struct{}

func NewFactory() Factory {
	return &linuxFactory{}
}

func (f *linuxFactory) Create(cfg CreateConfig) (Device, error) {
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
	return &linuxDevice{dev: dev, mtu: mtu}, nil
}

type linuxDevice struct {
	dev       wgtun.Device
	mtu       int
	closeOnce sync.Once

	// 单包模式缓存，避免热路径分配
	singleBufs [][]byte
	singleSizes []int
}

func (d *linuxDevice) Name() (string, error) {
	return d.dev.Name()
}

func (d *linuxDevice) MTU() int {
	if mtu, err := d.dev.MTU(); err == nil && mtu > 0 {
		return mtu
	}
	return d.mtu
}

func (d *linuxDevice) ReadPacket(buf []byte) (int, error) {
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

func (d *linuxDevice) WritePacket(pkt []byte) error {
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

func (d *linuxDevice) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.dev.Close()
	})
	return closeErr
}

// 批量读写接口（直接暴露 WireGuard TUN 的批量能力）
func (d *linuxDevice) BatchSize() int {
	return d.dev.BatchSize()
}

func (d *linuxDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.dev.Read(bufs, sizes, offset)
}

func (d *linuxDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.dev.Write(bufs, offset)
}

type linuxConfigurator struct{}

func NewConfigurator() Configurator {
	return &linuxConfigurator{}
}

func (c *linuxConfigurator) Setup(cfg NetworkConfig) error {
	ifName := strings.TrimSpace(cfg.IfName)
	if ifName == "" {
		return fmt.Errorf("setup tun: interface name is empty")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1400
	}

	if err := run("ip", "link", "set", ifName, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return fmt.Errorf("bring up interface: %w", err)
	}

	if cfg.IPv4CIDR != "" {
		ipCIDR := cfg.IPv4CIDR
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/24"
		}
		if err := run("ip", "addr", "add", ipCIDR, "dev", ifName); err != nil {
			return fmt.Errorf("assign ipv4: %w", err)
		}
		if err := run("ip", "route", "add", "0.0.0.0/0", "dev", ifName, "metric", "1"); err != nil {
			return fmt.Errorf("add ipv4 default route: %w", err)
		}
	}

	if cfg.IPv6CIDR != "" {
		ipCIDR := cfg.IPv6CIDR
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/64"
		}
		if err := run("ip", "-6", "addr", "add", ipCIDR, "dev", ifName); err != nil {
			return fmt.Errorf("assign ipv6: %w", err)
		}
		if err := run("ip", "-6", "route", "add", "::/0", "dev", ifName, "metric", "1"); err != nil {
			return fmt.Errorf("add ipv6 default route: %w", err)
		}
	}

	if cfg.DNSv4 != "" || cfg.DNSv6 != "" {
		args := []string{"dns", ifName}
		if cfg.DNSv4 != "" {
			args = append(args, cfg.DNSv4)
		}
		if cfg.DNSv6 != "" {
			args = append(args, cfg.DNSv6)
		}
		if err := run("resolvectl", args...); err == nil {
			_ = run("resolvectl", "domain", ifName, "~.")
		}
	}

	return nil
}

func (c *linuxConfigurator) Teardown(ifName string) error {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil
	}
	_ = run("ip", "link", "set", ifName, "down")
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
