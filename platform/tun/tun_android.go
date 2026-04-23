//go:build android

package tun

import (
	"fmt"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type androidFactory struct{}

func NewFactory() Factory {
	return &androidFactory{}
}

func (f *androidFactory) Create(cfg CreateConfig) (Device, error) {
	if cfg.FileDescriptor <= 0 {
		return nil, fmt.Errorf("android tun requires valid file descriptor from VPNService")
	}
	dev, ifName, err := wgtun.CreateUnmonitoredTUNFromFD(cfg.FileDescriptor)
	if err != nil {
		return nil, fmt.Errorf("create tun from fd: %w", err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		if v, e := dev.MTU(); e == nil {
			mtu = v
		}
	}
	return &androidDevice{dev: dev, ifName: ifName, mtu: mtu}, nil
}

type androidDevice struct {
	dev       wgtun.Device
	ifName    string
	mtu       int
	closeOnce sync.Once
}

func (d *androidDevice) Name() (string, error) {
	if d.ifName != "" {
		return d.ifName, nil
	}
	return d.dev.Name()
}

func (d *androidDevice) MTU() int {
	if mtu, err := d.dev.MTU(); err == nil && mtu > 0 {
		return mtu
	}
	return d.mtu
}

func (d *androidDevice) ReadPacket(buf []byte) (int, error) {
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

func (d *androidDevice) WritePacket(pkt []byte) error {
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

func (d *androidDevice) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.dev.Close()
	})
	return closeErr
}

// 批量读写接口
func (d *androidDevice) BatchSize() int {
	return d.dev.BatchSize()
}

func (d *androidDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.dev.Read(bufs, sizes, offset)
}

func (d *androidDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.dev.Write(bufs, offset)
}

type androidConfigurator struct{}

func NewConfigurator() Configurator {
	return &androidConfigurator{}
}

func (c *androidConfigurator) Setup(cfg NetworkConfig) error {
	// Android 的地址/路由/DNS 由 VPNService.Builder 预先完成。
	// 这里保持 no-op，仅做基本参数规范化。
	_ = strings.TrimSpace(cfg.IfName)
	return nil
}

func (c *androidConfigurator) Teardown(ifName string) error {
	_ = ifName
	return nil
}

// UpdateAddress 在 Android 上是 no-op：地址 / 路由 / DNS 由
// VPNService.Builder 在 fd 创建期固化，进程内无法热更新；上层
// 应在监测到地址变化时主动重建 VPN 接口。
func (c *androidConfigurator) UpdateAddress(prev, next NetworkConfig) error {
	_ = prev
	_ = next
	return nil
}
