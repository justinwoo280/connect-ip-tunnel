package http3

import "github.com/quic-go/quic-go"

func buildQUICConfig(opts Options) *quic.Config {
	return &quic.Config{
		EnableDatagrams:                opts.EnableDatagrams,
		MaxIdleTimeout:                 opts.MaxIdleTimeout,
		KeepAlivePeriod:                opts.KeepAlivePeriod,
		Allow0RTT:                      opts.Allow0RTT,
		DisablePathMTUDiscovery:        opts.DisablePathMTUDiscovery,
		InitialStreamReceiveWindow:     opts.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         opts.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: opts.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     opts.MaxConnectionReceiveWindow,
	}
}
