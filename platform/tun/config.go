package tun

// CreateConfig 描述 TUN 设备创建参数。
type CreateConfig struct {
	Name           string
	MTU            int
	FileDescriptor int // Android/VPNService 场景可传入现有 TUN fd
}

// NetworkConfig 描述 TUN 设备在系统侧的网络配置。
type NetworkConfig struct {
	IfName   string
	IPv4CIDR string
	IPv6CIDR string
	DNSv4    string
	DNSv6    string
	MTU      int
}

// Equal 报告两个 NetworkConfig 是否完全等价（含接口名 / 地址 / DNS / MTU）。
func (c NetworkConfig) Equal(other NetworkConfig) bool {
	return c.IfName == other.IfName &&
		c.IPv4CIDR == other.IPv4CIDR &&
		c.IPv6CIDR == other.IPv6CIDR &&
		c.DNSv4 == other.DNSv4 &&
		c.DNSv6 == other.DNSv6 &&
		c.MTU == other.MTU
}

// updateAddressByReSetup 提供 UpdateAddress 的通用兜底实现：
// 先 Teardown(prev.IfName)，再 Setup(next)。
//
// 适用平台：linux / darwin / freebsd —— 这些平台上 ip / ifconfig
// 命令本身较快（毫秒级），且业务对短暂中断容忍度较高；不需要做精细的
// 单地址族差量。Windows 上由于 netsh / PowerShell 较慢，且 IPv6
// 路由抖动会触发 RA 重协商，单独实现差量版本。
func updateAddressByReSetup(c Configurator, prev, next NetworkConfig) error {
	if prev.Equal(next) {
		return nil
	}
	if prev.IfName != "" {
		// 忽略 teardown 错误：可能是 prev 已被外部清理；后续 setup 是事实标准。
		_ = c.Teardown(prev.IfName)
	}
	return c.Setup(next)
}
