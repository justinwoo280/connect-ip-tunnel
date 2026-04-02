package http3

import (
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC 配置兜底值（当 Options 中对应字段为 0 时使用）
// 与 option.defaultInitialStreamWindow 等常量保持一致，
// 此处独立定义是为了让 transport 层无需 import option 包（避免循环依赖）。
const (
	fallbackInitialStreamWindow = 16 * 1024 * 1024  // 16 MB
	fallbackMaxStreamWindow     = 64 * 1024 * 1024  // 64 MB
	fallbackInitialConnWindow   = 32 * 1024 * 1024  // 32 MB
	fallbackMaxConnWindow       = 128 * 1024 * 1024 // 128 MB
	fallbackMaxIdleTimeout      = 30 * time.Second
	fallbackKeepAlivePeriod     = 10 * time.Second
)

func buildQUICConfig(opts Options) *quic.Config {
	initialStream := opts.InitialStreamReceiveWindow
	if initialStream == 0 {
		initialStream = fallbackInitialStreamWindow
	}
	maxStream := opts.MaxStreamReceiveWindow
	if maxStream == 0 {
		maxStream = fallbackMaxStreamWindow
	}
	// MaxStreamWindow 不能小于 InitialStreamWindow
	if maxStream < initialStream {
		maxStream = initialStream
	}

	initialConn := opts.InitialConnectionReceiveWindow
	if initialConn == 0 {
		initialConn = fallbackInitialConnWindow
	}
	maxConn := opts.MaxConnectionReceiveWindow
	if maxConn == 0 {
		maxConn = fallbackMaxConnWindow
	}
	// MaxConnWindow 不能小于 InitialConnWindow，也不能小于 MaxStreamWindow
	if maxConn < initialConn {
		maxConn = initialConn
	}
	if maxConn < maxStream {
		maxConn = maxStream
	}

	idleTimeout := opts.MaxIdleTimeout
	if idleTimeout == 0 {
		idleTimeout = fallbackMaxIdleTimeout
	}
	keepAlive := opts.KeepAlivePeriod
	if keepAlive == 0 {
		keepAlive = fallbackKeepAlivePeriod
	}

	return &quic.Config{
		EnableDatagrams:                opts.EnableDatagrams,
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                keepAlive,
		Allow0RTT:                      opts.Allow0RTT,
		DisablePathMTUDiscovery:        opts.DisablePathMTUDiscovery,
		InitialStreamReceiveWindow:     initialStream,
		MaxStreamReceiveWindow:         maxStream,
		InitialConnectionReceiveWindow: initialConn,
		MaxConnectionReceiveWindow:     maxConn,
	}
}
