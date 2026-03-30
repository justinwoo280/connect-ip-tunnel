//go:build !windows && !linux && !android && !darwin && !freebsd

package bypass

import (
	"context"
	"net"
)

type stubProvider struct{}

func NewProvider() Provider {
	return &stubProvider{}
}

func (p *stubProvider) Build(cfg Config) (Dialer, error) {
	_ = cfg
	return &stubDialer{}, nil
}

type stubDialer struct{}

func (d *stubDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_ = ctx
	_ = network
	_ = addr
	return nil, ErrNotImplemented
}

func (d *stubDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	_ = ctx
	_ = network
	_ = addr
	return nil, ErrNotImplemented
}
