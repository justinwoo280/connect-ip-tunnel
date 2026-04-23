package connectip

import (
	"context"
	"net/netip"
	"sync"

	"connect-ip-tunnel/platform/tun"

	connectipgo "github.com/quic-go/connect-ip-go"
)

var _ interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
} = (*Session)(nil)

// SessionInfo 暴露前缀分配 / 路由广告状态。
type SessionInfo struct {
	LocalPrefixes  []netip.Prefix
	RemotePrefixes []netip.Prefix
}

// Session 包装 connectip.Conn，适配 tunnel.PacketTunnel 接口。
// WritePacket 处理库返回的 ICMP 回包：若非空则写回 TUN 设备。
type Session struct {
	conn      *connectipgo.Conn
	dev       tun.Device // 用于将 ICMP 回包写回 TUN，可为 nil（测试场景）
	doneCh    chan struct{}
	closeOnce sync.Once
}

func newSession(conn *connectipgo.Conn, dev tun.Device) *Session {
	return &Session{
		conn:   conn,
		dev:    dev,
		doneCh: make(chan struct{}),
	}
}

// ReadPacket 从隧道读取一个 IP 包，写入 buf，返回字节数。
func (s *Session) ReadPacket(buf []byte) (int, error) {
	return s.conn.ReadPacket(buf)
}

// WritePacket 将 IP 包发送到隧道。
// connect-ip-go 的 WritePacket 可能返回一个 ICMP 回包（例如 Packet Too Big），
// 需要写回 TUN 设备，否则上层协议无法感知 MTU 限制。
func (s *Session) WritePacket(pkt []byte) error {
	icmp, err := s.conn.WritePacket(pkt)
	if err != nil {
		return err
	}
	if len(icmp) > 0 && s.dev != nil {
		// 忽略写回错误：ICMP 是尽力而为，不影响主路径。
		_ = s.dev.WritePacket(icmp)
	}
	return nil
}

// Close 关闭底层 CONNECT-IP 连接。
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.conn.Close()
		close(s.doneCh)
	})
	return err
}

// Done 返回一个 channel，当 session 关闭时会被关闭
func (s *Session) Done() <-chan struct{} {
	return s.doneCh
}

// LocalPrefixes 阻塞直到收到服务端的 ADDRESS_ASSIGN capsule，返回分配的 IP 前缀。
// 每次调用都会等待下一次 ADDRESS_ASSIGN 更新。
// 建议在循环中调用以持续跟踪服务端的 IP 重分配。
func (s *Session) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return s.conn.LocalPrefixes(ctx)
}

// Routes 阻塞直到收到服务端的 ROUTE_ADVERTISEMENT capsule，返回可用路由。
func (s *Session) Routes(ctx context.Context) ([]connectipgo.IPRoute, error) {
	return s.conn.Routes(ctx)
}
