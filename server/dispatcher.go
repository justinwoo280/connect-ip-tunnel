package server

import (
	"context"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"

	"connect-ip-tunnel/common/bufferpool"
	"connect-ip-tunnel/observability"
	"connect-ip-tunnel/platform/tun"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// indexes 是不可变的索引快照，用于无锁查找。
type indexes struct {
	ipv4 map[netip.Addr]*dispatchEntry
	ipv6 map[netip.Addr]*dispatchEntry
}

// PacketDispatcher 从 TUN 设备读取 IP 包，根据目的地址分发到正确的 session。
// 解决多会话共享 TUN 时的包路由问题。
type PacketDispatcher struct {
	dev tun.Device

	mu       sync.Mutex                 // 仅保护写操作（注册/注销）
	sessions map[string]*dispatchEntry  // sessionID -> entry
	idx      atomic.Pointer[indexes]    // 无锁读取的索引快照
}

type dispatchEntry struct {
	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
	inbound    chan []byte // TUN -> session 方向的包
}

// NewPacketDispatcher 创建包分发器。
func NewPacketDispatcher(dev tun.Device) *PacketDispatcher {
	d := &PacketDispatcher{
		dev:      dev,
		sessions: make(map[string]*dispatchEntry),
	}
	// 初始化空索引
	d.idx.Store(&indexes{
		ipv4: make(map[netip.Addr]*dispatchEntry),
		ipv6: make(map[netip.Addr]*dispatchEntry),
	})
	return d
}

// cloneAndAdd 克隆当前索引并添加新 entry。
func (d *PacketDispatcher) cloneAndAdd(entry *dispatchEntry) *indexes {
	old := d.idx.Load()
	newIdx := &indexes{
		ipv4: make(map[netip.Addr]*dispatchEntry, len(old.ipv4)+1),
		ipv6: make(map[netip.Addr]*dispatchEntry, len(old.ipv6)+1),
	}
	
	// 复制旧索引
	for k, v := range old.ipv4 {
		newIdx.ipv4[k] = v
	}
	for k, v := range old.ipv6 {
		newIdx.ipv6[k] = v
	}
	
	// 添加新 entry
	if addr, ok := hostRouteAddr(entry.ipv4Prefix); ok {
		newIdx.ipv4[addr] = entry
	}
	if addr, ok := hostRouteAddr(entry.ipv6Prefix); ok {
		newIdx.ipv6[addr] = entry
	}
	
	return newIdx
}

// cloneAndRemove 克隆当前索引并移除指定 entry。
func (d *PacketDispatcher) cloneAndRemove(entry *dispatchEntry) *indexes {
	old := d.idx.Load()
	newIdx := &indexes{
		ipv4: make(map[netip.Addr]*dispatchEntry, len(old.ipv4)),
		ipv6: make(map[netip.Addr]*dispatchEntry, len(old.ipv6)),
	}
	
	// 复制旧索引，跳过要删除的 entry
	ipv4Addr, hasIPv4 := hostRouteAddr(entry.ipv4Prefix)
	ipv6Addr, hasIPv6 := hostRouteAddr(entry.ipv6Prefix)
	
	for k, v := range old.ipv4 {
		if !(hasIPv4 && k == ipv4Addr && v == entry) {
			newIdx.ipv4[k] = v
		}
	}
	for k, v := range old.ipv6 {
		if !(hasIPv6 && k == ipv6Addr && v == entry) {
			newIdx.ipv6[k] = v
		}
	}
	
	return newIdx
}

// inboundChanBufLen 是每条 session 的下行 channel 缓冲长度。
//
// 必须与 quic-go 的 maxDatagramSendQueueLen 量级匹配。如果太小（如默认 256），
// 当 BBRv2 cwnd 涨到允许 4096 个 datagram in-flight 时，dispatcher 在 1ms 内
// 就能把 channel 灌满，多余包走 select default 静默丢弃 → TCP 反复重传 →
// 用户观感就是"小响应通、大响应挂死"。
//
// 4096 与 quic-go 的 datagram send queue 对齐，吸收能力一致。
const inboundChanBufLen = 4096

// RegisterSession 注册一个 session，指定其分配的 IP 前缀。
func (d *PacketDispatcher) RegisterSession(sessionID string, ipv4Prefix, ipv6Prefix netip.Prefix) chan []byte {
	inbound := make(chan []byte, inboundChanBufLen)
	entry := &dispatchEntry{
		ipv4Prefix: ipv4Prefix,
		ipv6Prefix: ipv6Prefix,
		inbound:    inbound,
	}

	d.mu.Lock()
	if old, ok := d.sessions[sessionID]; ok {
		// 移除旧 entry 的索引
		d.idx.Store(d.cloneAndRemove(old))
		close(old.inbound)
	}
	d.sessions[sessionID] = entry
	// 添加新 entry 的索引（copy-on-write）
	d.idx.Store(d.cloneAndAdd(entry))
	d.mu.Unlock()

	log.Printf("[dispatcher] registered session %s (ipv4=%s ipv6=%s)", sessionID, ipv4Prefix, ipv6Prefix)
	return inbound
}

// UnregisterSession 取消注册一个 session，关闭其 inbound channel。
func (d *PacketDispatcher) UnregisterSession(sessionID string) {
	d.mu.Lock()
	if entry, ok := d.sessions[sessionID]; ok {
		// 移除索引（copy-on-write）
		d.idx.Store(d.cloneAndRemove(entry))
		delete(d.sessions, sessionID)
		close(entry.inbound)
	}
	d.mu.Unlock()
	log.Printf("[dispatcher] unregistered session %s", sessionID)
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
// 使用批量读取接口（wireguard-go GRO 模式下 BatchSize > 1），避免单 buf 溢出。
// 阻塞直到 context 取消或读取错误。
func (d *PacketDispatcher) Run(ctx context.Context) error {
	batchSize := d.dev.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}

	// 按 batchSize 分配足够的 buf 槽，每槽 65536 字节
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = bufferpool.GetPacket()
	}
	defer func() {
		for _, b := range bufs {
			bufferpool.PutPacket(b)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Linux wireguard-go 在 vnetHdr=true（绝大多数现代内核）时，要求 Read 调用方
		// 在 buf 头部预留 VirtioNetHdrLen 字节作为 virtio_net_hdr 区域，
		// 否则会返回 "invalid offset" 整批失败、整个下行链路停摆。
		// 其它平台 vnetHdr=false 时，多传 offset 也会被 wireguard-go 自动跳过，是安全的。
		const offset = tun.VirtioNetHdrLen

		n, err := d.dev.Read(bufs, sizes, offset)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("[dispatcher] error: %v", err)
			return err
		}

		for i := 0; i < n; i++ {
			pktLen := sizes[i]
			if pktLen <= 0 {
				continue
			}

			// 实际 IP 包数据从 buf[offset:] 起，长度为 sizes[i]
			pkt := bufs[i][offset : offset+pktLen]
			dstAddr, ok := parseDstAddr(pkt)
			if !ok {
				continue
			}

			target := d.lookupSession(dstAddr)
			if target == nil {
				// 无匹配 session，丢弃
				continue
			}

			// 复制包数据（bufs[i] 会被复用）
			pktCopy := bufferpool.GetPacket()[:pktLen]
			copy(pktCopy, pkt)

			// 尝试发送，满了就丢弃（避免阻塞 TUN 读取）
			select {
			case target.inbound <- pktCopy:
			default:
				if observability.Global != nil {
					observability.Global.RecordDrop("dispatcher_inbound_full")
				}
				bufferpool.PutPacket(pktCopy)
			}
		}
	}
}

func (d *PacketDispatcher) lookupSession(dstAddr netip.Addr) *dispatchEntry {
	// 无锁读取：原子加载索引快照
	idx := d.idx.Load()
	
	if dstAddr.Is4() {
		if entry := idx.ipv4[dstAddr]; entry != nil {
			return entry
		}
	} else if dstAddr.Is6() {
		if entry := idx.ipv6[dstAddr]; entry != nil {
			return entry
		}
	}
	
	// 不再回退到线性扫描，假设所有分配都是 /32 或 /128
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
