//go:build freebsd

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type freebsdFactory struct{}

func NewFactory() Factory {
	return &freebsdFactory{}
}

func (f *freebsdFactory) Create(cfg CreateConfig) (Device, error) {
	name := strings.TrimSpace(cfg.Name)
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1400
	}

	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun device: %w", err)
	}
	return &freebsdDevice{dev: dev, mtu: mtu}, nil
}

type freebsdDevice struct {
	dev       wgtun.Device
	mtu       int
	closeOnce sync.Once
}

func (d *freebsdDevice) Name() (string, error) {
	return d.dev.Name()
}

func (d *freebsdDevice) MTU() int {
	if mtu, err := d.dev.MTU(); err == nil && mtu > 0 {
		return mtu
	}
	return d.mtu
}

func (d *freebsdDevice) ReadPacket(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	buffs := [][]byte{buf}
	sizes := make([]int, 1)
	n, err := d.dev.Read(buffs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (d *freebsdDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	buffs := [][]byte{pkt}
	n, err := d.dev.Write(buffs, 0)
	if err != nil {
		return err
	}
	if n <= 0 {
		return fmt.Errorf("tun write returned 0 packets")
	}
	return nil
}

func (d *freebsdDevice) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.dev.Close()
	})
	return closeErr
}

func (d *freebsdDevice) BatchSize() int {
	return d.dev.BatchSize()
}

func (d *freebsdDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.dev.Read(bufs, sizes, offset)
}

func (d *freebsdDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.dev.Write(bufs, offset)
}

type freebsdConfigurator struct{}

func NewConfigurator() Configurator {
	return &freebsdConfigurator{}
}

func (c *freebsdConfigurator) Setup(cfg NetworkConfig) error {
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
		_ = configureFreeBSDDNS(ifName, cfg.DNSv4, cfg.DNSv6)
	}

	return nil
}

func (c *freebsdConfigurator) Teardown(ifName string) error {
	ifName = strings.TrimSpace(ifName)
	if ifName == "" {
		return nil
	}
	_ = run("route", "delete", "-net", "default", "-interface", ifName)
	_ = run("route", "delete", "-inet6", "default", "-interface", ifName)
	_ = run("ifconfig", ifName, "down")
	_ = run("resolvconf", "-d", ifName)
	return nil
}

func configureFreeBSDDNS(ifName, dns, ipv6DNS string) error {
	var lines []string
	if dns != "" {
		lines = append(lines, "nameserver "+dns)
	}
	if ipv6DNS != "" {
		lines = append(lines, "nameserver "+ipv6DNS)
	}
	if len(lines) == 0 {
		return nil
	}
	content := strings.Join(lines, "\n") + "\n"
	cmd := exec.Command("resolvconf", "-a", ifName, "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(content)
	_, err := cmd.CombinedOutput()
	return err
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
