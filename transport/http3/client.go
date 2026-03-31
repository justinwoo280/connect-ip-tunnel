package http3

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
	roundTrip http.RoundTripper // 可选的自定义 RoundTripper（用于注入鉴权等）
}

func NewFactory(opts Options, tlsClient securitytls.ClientConfig, bp bypass.Dialer) *Factory {
	return &Factory{
		opts:      opts,
		tlsClient: tlsClient,
		bypass:    bp,
	}
}

// SetRoundTripper 设置自定义 RoundTripper（用于鉴权等场景）
func (f *Factory) SetRoundTripper(rt http.RoundTripper) {
	f.roundTrip = rt
}

// Dial 建立到 target 的 QUIC 连接并返回 HTTP/3 ClientConn。
// 若配置了 bypass dialer，使用它建 UDP socket 以绕过 TUN；否则直接 DialAddr。
func (f *Factory) Dial(ctx context.Context, target Target) (*qhttp3.ClientConn, error) {
	tlsCfg := f.tlsClient.TLSConfig().Clone()
	if target.ServerName != "" {
		tlsCfg.ServerName = target.ServerName
	}

	quicCfg := buildQUICConfig(f.opts)

	var quicConn *quic.Conn
	var err error
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
		quicConn, err = quic.Dial(ctx, pc, udpAddr, tlsCfg, quicCfg)
		if err != nil {
			_ = pc.Close()
			_, _ = f.tlsClient.HandleHandshakeError(err)
			return nil, fmt.Errorf("http3: quic dial (bypass): %w", err)
		}
	} else {
		quicConn, err = quic.DialAddr(ctx, target.Addr, tlsCfg, quicCfg)
		if err != nil {
			_, _ = f.tlsClient.HandleHandshakeError(err)
			return nil, fmt.Errorf("http3: quic dial: %w", err)
		}
	}

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

// authRoundTripper 包装 RoundTripper 以注入鉴权信息
type authRoundTripper struct {
	base     http.RoundTripper
	authFunc func(*http.Request) error
}

func (a *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if a.authFunc != nil {
		if err := a.authFunc(req); err != nil {
			return nil, fmt.Errorf("auth: apply to request: %w", err)
		}
	}
	return a.base.RoundTrip(req)
}

// NewAuthRoundTripper 创建带鉴权的 RoundTripper
func NewAuthRoundTripper(base http.RoundTripper, authFunc func(*http.Request) error) http.RoundTripper {
	if authFunc == nil {
		return base
	}
	return &authRoundTripper{
		base:     base,
		authFunc: authFunc,
	}
}
