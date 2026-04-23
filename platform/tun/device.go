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
//
// UpdateAddress 用于热更新 TUN 上的地址（典型场景：服务端二次下发
// ADDRESS_ASSIGN，IPv4 / IPv6 prefix 发生变化）。实现需保证：
//   - 仅修改实际发生变化的地址族，不影响另一族；
//   - 若 prev 与 next 完全一致，应直接返回 nil；
//   - 失败时不应留下半配置态（prev 仍可用）。
//
// 各平台默认实现可走 "先 Teardown 再 Setup" 兜底；性能 / 功能敏感平台
// （如 Windows）可改为真正的差量更新。
type Configurator interface {
	Setup(cfg NetworkConfig) error
	Teardown(ifName string) error
	UpdateAddress(prev, next NetworkConfig) error
}
