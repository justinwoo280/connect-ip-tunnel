package tun

import "errors"

var ErrNotImplemented = errors.New("platform/tun: not implemented")

// VirtioNetHdrLen 是 Linux virtio_net_hdr 结构体大小（10 字节）。
//
// Linux 上 wireguard-go 当内核支持 vnetHdr（绝大多数现代 5.x+ 内核都支持）时，
// Write/Read 会要求调用方在 buf 头部预留 VirtioNetHdrLen 字节作为 offset 区域，
// 否则返回 "invalid offset" 错误，导致整个批次写入失败。
//
// 调用约定：
//   - 缓冲区分配长度至少为 VirtioNetHdrLen + MTU
//   - 实际 IP 包数据放在 buf[VirtioNetHdrLen:]
//   - 调用 dev.Write(bufs, VirtioNetHdrLen)（offset 参数）
//
// 其它平台（Windows wintun、macOS utun、Android）vnetHdr=false，
// 多传 offset=VirtioNetHdrLen 也是安全的（wireguard-go 会跳过头部），
// 因此跨平台代码统一使用此常量即可。
const VirtioNetHdrLen = 10

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

// CleanupStaleClientState 是平台相关的"启动期清理"钩子。
//
// 调用方应在客户端进程**主入口最早**位置调用一次，用于擦除上一轮进程异常退出
// （kill -9 / panic / 系统断电）残留在操作系统中的客户端状态——例如 Windows 上
// 的 NRPT 规则、被压低优先级的物理网卡 InterfaceMetric 等。
//
// 默认实现是 no-op，各平台通过 init() 覆盖（目前仅 Windows 提供真实实现）。
//
// 该函数永远不应当 panic 或返回错误：清理失败不能阻止程序启动；调用方也不需要
// 关心其内部行为，安全起见可在任何客户端启动路径都调用一次（重复调用幂等）。
var CleanupStaleClientState = func() {}

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
