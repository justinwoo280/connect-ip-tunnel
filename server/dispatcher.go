package server

import (
	"context"
	"log"
	"net/netip"
	"sync"

	"connect-ip-tunnel/common/bufferpool"
	"connect-ip-tunnel/platform/tun"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PacketDispatcher 从 TUN 设备读取 IP 包，根据目的地址分发到正确的 session。
// 解决多会话共享 TUN 时的包路由问题。
type PacketDispatcher struct {
	dev tun.Device

	mu       sync.RWMutex
	sessions map[string]*dispatchEntry // sessionID -> entry
}

type dispatchEntry struct {
	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
	inbound    chan []byte // TUN -> session 方向的包
}

// NewPacketDispatcher 创建包分发器。
func NewPacketDispatcher(dev tun.Device) *PacketDispatcher {
	return &PacketDispatcher{
		dev:      dev,
		sessions: make(map[string]*dispatchEntry),
	}
}

// RegisterSession 注册一个 session，指定其分配的 IP 前缀。
func (d *PacketDispatcher) RegisterSession(sessionID string, ipv4Prefix, ipv6Prefix netip.Prefix) chan []byte {
	inbound := make(chan []byte, 256)
	d.mu.Lock()
	d.sessions[sessionID] = &dispatchEntry{
		ipv4Prefix: ipv4Prefix,
		ipv6Prefix: ipv6Prefix,
		inbound:    inbound,
	}
	d.mu.Unlock()
	log.Printf("[dispatcher] registered session %s (ipv4=%s ipv6=%s)", sessionID, ipv4Prefix, ipv6Prefix)
	return inbound
}

// UnregisterSession 取消注册一个 session，关闭其 inbound channel。
func (d *PacketDispatcher) UnregisterSession(sessionID string) {
	d.mu.Lock()
	if entry, ok := d.sessions[sessionID]; ok {
		close(entry.inbound)
		delete(d.sessions, sessionID)
	}
	d.mu.Unlock()
	log.Printf("[dispatcher] unregistered session %s", sessionID)
}

// Run 启动 TUN 读取循环，根据目的 IP 将包分发到匹配的 session。
// 阻塞直到 context 取消或读取错误。
func (d *PacketDispatcher) Run(ctx context.Context) error {
	buf := bufferpool.GetPacket()
	defer bufferpool.PutPacket(buf)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := d.dev.ReadPacket(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n <= 0 {
			continue
		}

		pkt := buf[:n]
		dstAddr, ok := parseDstAddr(pkt)
		if !ok {
			continue
		}

		// 查找匹配的 session
		d.mu.RLock()
		var target *dispatchEntry
		for _, entry := range d.sessions {
			if entry.ipv4Prefix.IsValid() && entry.ipv4Prefix.Contains(dstAddr) {
				target = entry
				break
			}
			if entry.ipv6Prefix.IsValid() && entry.ipv6Prefix.Contains(dstAddr) {
				target = entry
				break
			}
		}
		d.mu.RUnlock()

		if target == nil {
			// 无匹配 session，丢弃
			continue
		}

		// 复制包数据（buf 会被复用）
		pktCopy := make([]byte, n)
		copy(pktCopy, pkt)

		// 尝试发送，满了就丢弃（避免阻塞 TUN 读取）
		select {
		case target.inbound <- pktCopy:
		default:
			// channel 满，丢弃包
		}
	}
}

// parseDstAddr 从 IP 包头解析目的地址。
func parseDstAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) == 0 {
		return netip.Addr{}, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		if len(pkt) < ipv4.HeaderLen {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < ipv6.HeaderLen {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return netip.Addr{}, false
	}
}
