package http3

import "time"

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
}

type Target struct {
	Addr       string // host:port 或 ip:port
	ServerName string
	Authority  string
}
