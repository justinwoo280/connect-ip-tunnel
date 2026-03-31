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

	mu        sync.RWMutex
	sessions  map[string]*dispatchEntry // sessionID -> entry
	ipv4Index map[netip.Addr]*dispatchEntry
	ipv6Index map[netip.Addr]*dispatchEntry
}

type dispatchEntry struct {
	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
	inbound    chan []byte // TUN -> session 方向的包
}

// NewPacketDispatcher 创建包分发器。
func NewPacketDispatcher(dev tun.Device) *PacketDispatcher {
	return &PacketDispatcher{
		dev:       dev,
		sessions:  make(map[string]*dispatchEntry),
		ipv4Index: make(map[netip.Addr]*dispatchEntry),
		ipv6Index: make(map[netip.Addr]*dispatchEntry),
	}
}

// RegisterSession 注册一个 session，指定其分配的 IP 前缀。
func (d *PacketDispatcher) RegisterSession(sessionID string, ipv4Prefix, ipv6Prefix netip.Prefix) chan []byte {
	inbound := make(chan []byte, 256)
	entry := &dispatchEntry{
		ipv4Prefix: ipv4Prefix,
		ipv6Prefix: ipv6Prefix,
		inbound:    inbound,
	}

	d.mu.Lock()
	if old, ok := d.sessions[sessionID]; ok {
		d.unindexEntry(old)
		close(old.inbound)
	}
	d.sessions[sessionID] = entry
	d.indexEntry(entry)
	d.mu.Unlock()

	log.Printf("[dispatcher] registered session %s (ipv4=%s ipv6=%s)", sessionID, ipv4Prefix, ipv6Prefix)
	return inbound
}

// UnregisterSession 取消注册一个 session，关闭其 inbound channel。
func (d *PacketDispatcher) UnregisterSession(sessionID string) {
	d.mu.Lock()
	if entry, ok := d.sessions[sessionID]; ok {
		d.unindexEntry(entry)
		delete(d.sessions, sessionID)
		close(entry.inbound)
	}
	d.mu.Unlock()
	log.Printf("[dispatcher] unregistered session %s", sessionID)
}

func (d *PacketDispatcher) indexEntry(entry *dispatchEntry) {
	if addr, ok := hostRouteAddr(entry.ipv4Prefix); ok {
		d.ipv4Index[addr] = entry
	}
	if addr, ok := hostRouteAddr(entry.ipv6Prefix); ok {
		d.ipv6Index[addr] = entry
	}
}

func (d *PacketDispatcher) unindexEntry(entry *dispatchEntry) {
	if addr, ok := hostRouteAddr(entry.ipv4Prefix); ok {
		delete(d.ipv4Index, addr)
	}
	if addr, ok := hostRouteAddr(entry.ipv6Prefix); ok {
		delete(d.ipv6Index, addr)
	}
}

func hostRouteAddr(prefix netip.Prefix) (netip.Addr, bool) {
	if !prefix.IsValid() {
		return netip.Addr{}, false
	}
	addr := prefix.Addr()
	if addr.Is4() && prefix.Bits() == 32 {
		return addr, true
	}
	if addr.Is6() && prefix.Bits() == 128 {
		return addr, true
	}
	return netip.Addr{}, false
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

		target := d.lookupSession(dstAddr)
		if target == nil {
			// 无匹配 session，丢弃
			continue
		}

		// 复制包数据（buf 会被复用）
		pktCopy := bufferpool.GetPacket()[:n]
		copy(pktCopy, pkt)

		// 尝试发送，满了就丢弃（避免阻塞 TUN 读取）
		select {
		case target.inbound <- pktCopy:
		default:
			bufferpool.PutPacket(pktCopy)
		}
	}
}

func (d *PacketDispatcher) lookupSession(dstAddr netip.Addr) *dispatchEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if dstAddr.Is4() {
		if entry := d.ipv4Index[dstAddr]; entry != nil {
			return entry
		}
	} else if dstAddr.Is6() {
		if entry := d.ipv6Index[dstAddr]; entry != nil {
			return entry
		}
	}

	// 回退到前缀匹配，兼容未来非 /32 /128 的分配策略。
	for _, entry := range d.sessions {
		if entry.ipv4Prefix.IsValid() && entry.ipv4Prefix.Contains(dstAddr) {
			return entry
		}
		if entry.ipv6Prefix.IsValid() && entry.ipv6Prefix.Contains(dstAddr) {
			return entry
		}
	}
	return nil
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
