package http3

import (
	"context"
	"fmt"
	"net"
	"sync"

	bypass "connect-ip-tunnel/platform/bypass"
	securitytls "connect-ip-tunnel/security/tls"

	"github.com/quic-go/quic-go"
	qhttp3 "github.com/quic-go/quic-go/http3"
)

type ClientFactory interface {
	Dial(ctx context.Context, target Target) (*qhttp3.ClientConn, error)
	Close() error
}

type Factory struct {
	opts      Options
	tlsClient securitytls.ClientConfig
	bypass    bypass.Dialer

	mu        sync.Mutex
	transport *qhttp3.Transport
}

func NewFactory(opts Options, tlsClient securitytls.ClientConfig, bp bypass.Dialer) *Factory {
	return &Factory{
		opts:      opts,
		tlsClient: tlsClient,
		bypass:    bp,
	}
}

// Dial 建立到 target 的 QUIC 连接并返回 HTTP/3 ClientConn。
// 若配置了 bypass dialer，使用它建 UDP socket 以绕过 TUN；否则直接 DialAddr。
//
// ECH HRR 处理：若服务端拒绝 ECH 并返回 RetryConfigList，Dial 会在同一次调用内
// 使用新配置重试（最多由 ClientConfig.HandleHandshakeError 控制次数）。
// 超过重试上限或无法获取重试配置时，返回错误，不降级为明文 ClientHello。
func (f *Factory) Dial(ctx context.Context, target Target) (*qhttp3.ClientConn, error) {
	quicCfg := buildQUICConfig(f.opts)

	for {
		// 每次尝试都从 tlsClient 取最新配置（HandleHandshakeError 会原地更新）
		tlsCfg := f.tlsClient.TLSConfig().Clone()
		if target.ServerName != "" {
			tlsCfg.ServerName = target.ServerName
		}

		var quicConn *quic.Conn
		var dialErr error

		if f.bypass != nil {
			pc, err := f.bypass.ListenPacket(ctx, "udp", "")
			if err != nil {
				return nil, fmt.Errorf("http3: bypass listen packet: %w", err)
			}
			udpAddr, err := net.ResolveUDPAddr("udp", target.Addr)
			if err != nil {
				_ = pc.Close()
				return nil, fmt.Errorf("http3: resolve target addr %q: %w", target.Addr, err)
			}
			quicConn, dialErr = quic.Dial(ctx, pc, udpAddr, tlsCfg, quicCfg)
			if dialErr != nil {
				_ = pc.Close()
			}
		} else {
			quicConn, dialErr = quic.DialAddr(ctx, target.Addr, tlsCfg, quicCfg)
		}

		if dialErr != nil {
			retry, outErr := f.tlsClient.HandleHandshakeError(dialErr)
			if retry {
				// 服务端返回了新的 ECH RetryConfigList，使用新配置重试
				continue
			}
			// 非可重试错误（含超过重试上限的 ErrECHRejected）
			return nil, outErr
		}

		// 握手成功
		f.mu.Lock()
		if f.transport == nil {
			f.transport = &qhttp3.Transport{
				EnableDatagrams: f.opts.EnableDatagrams,
			}
		}
		t := f.transport
		f.mu.Unlock()

		return t.NewClientConn(quicConn), nil
	}
}

func (f *Factory) Close() error {
	f.mu.Lock()
	t := f.transport
	f.transport = nil
	f.mu.Unlock()
	if t != nil {
		return t.Close()
	}
	return nil
}

