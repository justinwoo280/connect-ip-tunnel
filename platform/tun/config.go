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
