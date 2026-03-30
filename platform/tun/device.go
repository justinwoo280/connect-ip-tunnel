package tun

import "errors"

var ErrNotImplemented = errors.New("platform/tun: not implemented")

// Device 是平台无关的 TUN 设备抽象，只暴露原始 IP 包读写能力。
type Device interface {
	Name() (string, error)
	MTU() int
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Close() error

	// 批量读写接口（可选，性能优化）
	// 若底层 TUN 实现支持批量操作，直接暴露即可。
	// WireGuard TUN 已实现这些方法。
	BatchSize() int
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
}

// Factory 负责创建 TUN 设备。
type Factory interface {
	Create(cfg CreateConfig) (Device, error)
}

// Configurator 负责系统网络配置（地址 / 路由 / DNS）和回滚。
type Configurator interface {
	Setup(cfg NetworkConfig) error
	Teardown(ifName string) error
}
