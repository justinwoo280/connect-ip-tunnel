package server

import (
	"net/netip"
	"sync/atomic"
	"time"

	"connect-ip-tunnel/platform/tun"

	connectipgo "github.com/quic-go/connect-ip-go"
)

// Session 表示一个客户端的 CONNECT-IP 会话
type Session struct {
	id         string
	conn       *connectipgo.Conn
	dev        tun.Device
	remoteAddr string
	createdAt  time.Time

	// 分配给客户端的 IP 地址
	assignedIPv4 netip.Prefix
	assignedIPv6 netip.Prefix

	// 由 PacketDispatcher 推送的下行包（TUN -> session）
	inbound chan []byte

	txPackets atomic.Uint64
	rxPackets atomic.Uint64
	txBytes   atomic.Uint64
	rxBytes   atomic.Uint64
	
	// 应用层活跃度跟踪
	lastActiveAt atomic.Int64 // unix nano
}

func newSession(conn *connectipgo.Conn, dev tun.Device, remoteAddr string) *Session {
	id := generateSessionID()
	return &Session{
		id:         id,
		conn:       conn,
		dev:        dev,
		remoteAddr: remoteAddr,
	}
}

func newSessionWithIP(conn *connectipgo.Conn, dev tun.Device, remoteAddr, id string, ipv4, ipv6 netip.Prefix) *Session {
	s := &Session{
		id:           id,
		conn:         conn,
		dev:          dev,
		remoteAddr:   remoteAddr,
		createdAt:    time.Now(),
		assignedIPv4: ipv4,
		assignedIPv6: ipv6,
	}
	s.lastActiveAt.Store(time.Now().UnixNano())
	return s
}

// SetInbound 设置由 PacketDispatcher 推送的下行包 channel。
func (s *Session) SetInbound(ch chan []byte) {
	s.inbound = ch
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) RemoteAddr() string {
	return s.remoteAddr
}

// ReadPacket 从客户端读取 IP 包
func (s *Session) ReadPacket(buf []byte) (int, error) {
	n, err := s.conn.ReadPacket(buf)
	if err == nil && n > 0 {
		s.rxPackets.Add(1)
		s.rxBytes.Add(uint64(n))
		s.UpdateLastActive()
	}
	return n, err
}

// WritePacket 向客户端发送 IP 包
func (s *Session) WritePacket(pkt []byte) error {
	icmp, err := s.conn.WritePacket(pkt)
	if err != nil {
		return err
	}
	s.txPackets.Add(1)
	s.txBytes.Add(uint64(len(pkt)))

	// 处理 ICMP 回包
	if len(icmp) > 0 && s.dev != nil {
		_ = s.dev.WritePacket(icmp)
	}
	return nil
}

// UpdateLastActive 更新最后活跃时间
func (s *Session) UpdateLastActive() {
	s.lastActiveAt.Store(time.Now().UnixNano())
}

// GetLastActive 获取最后活跃时间
func (s *Session) GetLastActive() time.Time {
	nano := s.lastActiveAt.Load()
	if nano == 0 {
		return s.createdAt
	}
	return time.Unix(0, nano)
}

func (s *Session) Close() error {
	return s.conn.Close()
}

// Stats 返回会话流量统计（rx bytes, tx bytes, rx packets, tx packets）。
func (s *Session) Stats() (rxBytes, txBytes, rxPackets, txPackets uint64) {
	return s.rxBytes.Load(), s.txBytes.Load(), s.rxPackets.Load(), s.txPackets.Load()
}

// IsAssignedIP 检查给定的 IP 地址是否为分配给该 session 的 IP
func (s *Session) IsAssignedIP(addr netip.Addr) bool {
	// 检查 IPv4
	if addr.Is4() && s.assignedIPv4.IsValid() {
		return s.assignedIPv4.Contains(addr)
	}
	// 检查 IPv6
	if addr.Is6() && s.assignedIPv6.IsValid() {
		return s.assignedIPv6.Contains(addr)
	}
	return false
}

type SessionStats struct {
	TxPackets    uint64
	RxPackets    uint64
	TxBytes      uint64
	RxBytes      uint64
	AssignedIPv4 netip.Prefix
	AssignedIPv6 netip.Prefix
}
