package http3

import (
	"time"

	"connect-ip-tunnel/option"
)

type Options struct {
	EnableDatagrams bool
	// Obfs UDP 包级别混淆配置
	Obfs option.ObfsConfig

	// UDP socket buffer 配置（性能优化）
	UDPRecvBuffer int  // UDP 接收缓冲区大小（字节），默认 16MB
	UDPSendBuffer int  // UDP 发送缓冲区大小（字节），默认 16MB
	EnableGSO     bool // 启用 GSO/GRO（Linux），默认 true

	// PreferAddressFamily 解析服务端域名时的地址族偏好：
	//   "auto" - Happy Eyeballs（默认；空值视为 auto）
	//   "v4"   - 仅 IPv4
	//   "v6"   - 仅 IPv6
	PreferAddressFamily string
	// HappyEyeballsDelay 双栈尝试之间的交错延迟（默认 50ms，<=0 视为默认）。
	HappyEyeballsDelay time.Duration

	MaxIdleTimeout          time.Duration
	KeepAlivePeriod         time.Duration
	Allow0RTT               bool
	DisablePathMTUDiscovery bool

	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64

	// Congestion 拥塞控制配置（留空使用默认 CUBIC）
	Congestion option.CongestionConfig
}

type Target struct {
	Addr       string // host:port 或 ip:port
	ServerName string
	Authority  string
}
