package http3

import (
	"time"

	"connect-ip-tunnel/option"
)

type Options struct {
	EnableDatagrams bool

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
