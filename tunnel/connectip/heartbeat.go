package connectip

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"connect-ip-tunnel/observability"
)

// 心跳使用 IP 协议号 253 (IANA "Use for experimentation and testing")
const (
	HeartbeatProtocol = 253
	HeartbeatTypePing = 0x01
	HeartbeatTypePong = 0x02
)

// HeartbeatPayload 心跳负载格式：[type:1][seq:8][ts_ns:8] 共 17 字节
const heartbeatPayloadSize = 17

// PendingPing 记录待确认的 ping
type PendingPing struct {
	Seq      uint64
	SentAt   time.Time
	Deadline time.Time
}

// BuildHeartbeatPacket 构造心跳 IP 包
// 使用 IP 协议号 253，负载为 [type:1][seq:8][ts_ns:8]
func BuildHeartbeatPacket(typ byte, seq uint64, ts time.Time, src, dst netip.Addr) ([]byte, error) {
	if !src.IsValid() || !dst.IsValid() {
		return nil, fmt.Errorf("invalid src or dst address")
	}
	
	// 构造心跳负载
	payload := make([]byte, heartbeatPayloadSize)
	payload[0] = typ
	binary.BigEndian.PutUint64(payload[1:9], seq)
	binary.BigEndian.PutUint64(payload[9:17], uint64(ts.UnixNano()))
	
	// 构造 IP 包
	if src.Is4() && dst.Is4() {
		return buildIPv4Heartbeat(src, dst, payload), nil
	} else if src.Is6() && dst.Is6() {
		return buildIPv6Heartbeat(src, dst, payload), nil
	}
	
	return nil, fmt.Errorf("src and dst must be same IP version")
}

// buildIPv4Heartbeat 构造 IPv4 心跳包
func buildIPv4Heartbeat(src, dst netip.Addr, payload []byte) []byte {
	totalLen := 20 + len(payload) // IPv4 header (20) + payload
	pkt := make([]byte, totalLen)
	
	// IPv4 header
	pkt[0] = 0x45                                      // Version=4, IHL=5 (20 bytes)
	pkt[1] = 0x00                                      // DSCP=0, ECN=0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // Total Length
	binary.BigEndian.PutUint16(pkt[4:6], 0)           // Identification
	binary.BigEndian.PutUint16(pkt[6:8], 0)           // Flags=0, Fragment Offset=0
	pkt[8] = 64                                        // TTL=64
	pkt[9] = HeartbeatProtocol                         // Protocol=253
	// Checksum 先填 0，后面计算
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	
	// Source IP
	srcBytes := src.As4()
	copy(pkt[12:16], srcBytes[:])
	
	// Destination IP
	dstBytes := dst.As4()
	copy(pkt[16:20], dstBytes[:])
	
	// 计算 checksum
	checksum := ipv4Checksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], checksum)
	
	// Payload
	copy(pkt[20:], payload)
	
	return pkt
}

// buildIPv6Heartbeat 构造 IPv6 心跳包
func buildIPv6Heartbeat(src, dst netip.Addr, payload []byte) []byte {
	totalLen := 40 + len(payload) // IPv6 header (40) + payload
	pkt := make([]byte, totalLen)
	
	// IPv6 header
	pkt[0] = 0x60                                           // Version=6, Traffic Class=0
	pkt[1] = 0x00                                           // Traffic Class (cont), Flow Label
	binary.BigEndian.PutUint16(pkt[2:4], 0)                // Flow Label (cont)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload))) // Payload Length
	pkt[6] = HeartbeatProtocol                              // Next Header=253
	pkt[7] = 64                                             // Hop Limit=64
	
	// Source IP
	srcBytes := src.As16()
	copy(pkt[8:24], srcBytes[:])
	
	// Destination IP
	dstBytes := dst.As16()
	copy(pkt[24:40], dstBytes[:])
	
	// Payload
	copy(pkt[40:], payload)
	
	return pkt
}

// ipv4Checksum 计算 IPv4 header checksum
func ipv4Checksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// IsHeartbeatPacket 检查是否为心跳包
// 严格校验：协议号=253, src/dst 匹配, payload 长度=17, type ∈ {0x01, 0x02}
func IsHeartbeatPacket(pkt []byte, assignedPrefixes []netip.Prefix, serverGateway netip.Addr, isServer bool) bool {
	if len(pkt) < 20 {
		return false
	}
	
	version := pkt[0] >> 4
	
	if version == 4 {
		return isIPv4Heartbeat(pkt, assignedPrefixes, serverGateway, isServer)
	} else if version == 6 {
		return isIPv6Heartbeat(pkt, assignedPrefixes, serverGateway, isServer)
	}
	
	return false
}

func isIPv4Heartbeat(pkt []byte, assignedPrefixes []netip.Prefix, serverGateway netip.Addr, isServer bool) bool {
	if len(pkt) < 20+heartbeatPayloadSize {
		return false
	}
	
	// 检查协议号
	if pkt[9] != HeartbeatProtocol {
		return false
	}
	
	// 解析 src/dst
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	
	// 检查地址匹配
	if isServer {
		// 服务端：src 必须是 assigned IP, dst 必须是 server gateway
		if !containsAddr(assignedPrefixes, src) || dst != serverGateway {
			return false
		}
	} else {
		// 客户端：src 必须是 server gateway, dst 必须是 assigned IP
		if src != serverGateway || !containsAddr(assignedPrefixes, dst) {
			return false
		}
	}
	
	// 检查 payload
	payload := pkt[20:]
	if len(payload) != heartbeatPayloadSize {
		return false
	}
	
	typ := payload[0]
	return typ == HeartbeatTypePing || typ == HeartbeatTypePong
}

func isIPv6Heartbeat(pkt []byte, assignedPrefixes []netip.Prefix, serverGateway netip.Addr, isServer bool) bool {
	if len(pkt) < 40+heartbeatPayloadSize {
		return false
	}
	
	// 检查协议号
	if pkt[6] != HeartbeatProtocol {
		return false
	}
	
	// 解析 src/dst
	var srcBytes, dstBytes [16]byte
	copy(srcBytes[:], pkt[8:24])
	copy(dstBytes[:], pkt[24:40])
	src := netip.AddrFrom16(srcBytes)
	dst := netip.AddrFrom16(dstBytes)
	
	// 检查地址匹配
	if isServer {
		if !containsAddr(assignedPrefixes, src) || dst != serverGateway {
			return false
		}
	} else {
		if src != serverGateway || !containsAddr(assignedPrefixes, dst) {
			return false
		}
	}
	
	// 检查 payload
	payload := pkt[40:]
	if len(payload) != heartbeatPayloadSize {
		return false
	}
	
	typ := payload[0]
	return typ == HeartbeatTypePing || typ == HeartbeatTypePong
}

// ParseHeartbeatPayload 解析心跳负载
func ParseHeartbeatPayload(pkt []byte) (typ byte, seq uint64, ts time.Time, err error) {
	version := pkt[0] >> 4
	var payload []byte
	
	if version == 4 {
		if len(pkt) < 20+heartbeatPayloadSize {
			return 0, 0, time.Time{}, fmt.Errorf("packet too short")
		}
		payload = pkt[20:]
	} else if version == 6 {
		if len(pkt) < 40+heartbeatPayloadSize {
			return 0, 0, time.Time{}, fmt.Errorf("packet too short")
		}
		payload = pkt[40:]
	} else {
		return 0, 0, time.Time{}, fmt.Errorf("invalid IP version")
	}
	
	typ = payload[0]
	seq = binary.BigEndian.Uint64(payload[1:9])
	tsNano := binary.BigEndian.Uint64(payload[9:17])
	ts = time.Unix(0, int64(tsNano))
	
	return typ, seq, ts, nil
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// HeartbeatManager 管理心跳发送和超时检测
type HeartbeatManager struct {
	assignedPrefixes []netip.Prefix
	serverGateway    netip.Addr
	sendPacket       func([]byte) error
	period           time.Duration
	timeout          time.Duration
	threshold        int
	
	mu            sync.Mutex
	seq           uint64
	pending       map[uint64]*PendingPing
	timeoutCount  int
	stopCh        chan struct{}
	stoppedCh     chan struct{}
}

// NewHeartbeatManager 创建心跳管理器
func NewHeartbeatManager(
	assignedPrefixes []netip.Prefix,
	serverGateway netip.Addr,
	sendPacket func([]byte) error,
	period, timeout time.Duration,
	threshold int,
) *HeartbeatManager {
	return &HeartbeatManager{
		assignedPrefixes: assignedPrefixes,
		serverGateway:    serverGateway,
		sendPacket:       sendPacket,
		period:           period,
		timeout:          timeout,
		threshold:        threshold,
		pending:          make(map[uint64]*PendingPing),
		stopCh:           make(chan struct{}),
		stoppedCh:        make(chan struct{}),
	}
}

// Start 启动心跳循环
func (hm *HeartbeatManager) Start(ctx context.Context) error {
	defer close(hm.stoppedCh)
	
	ticker := time.NewTicker(hm.period)
	defer ticker.Stop()
	
	checkTicker := time.NewTicker(hm.timeout / 2)
	defer checkTicker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-hm.stopCh:
			return nil
		case <-ticker.C:
			if err := hm.sendPing(); err != nil {
				return err
			}
		case <-checkTicker.C:
			if hm.checkTimeouts() {
				return fmt.Errorf("heartbeat: %d consecutive timeouts", hm.threshold)
			}
		}
	}
}

// Stop 停止心跳循环
func (hm *HeartbeatManager) Stop() {
	close(hm.stopCh)
	<-hm.stoppedCh
}

// OnPong 处理 pong 响应
func (hm *HeartbeatManager) OnPong(seq uint64) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if pending, ok := hm.pending[seq]; ok {
		delete(hm.pending, seq)
		hm.timeoutCount = 0 // 重置超时计数

		// 上报 RTT 到 observability，便于 Grafana 看 P50/P95 / 网络抖动告警。
		observability.Global.ObserveAppKeepaliveRTT(time.Since(pending.SentAt))
	}
}

func (hm *HeartbeatManager) sendPing() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.seq++
	seq := hm.seq
	now := time.Now()
	
	hm.pending[seq] = &PendingPing{
		Seq:      seq,
		SentAt:   now,
		Deadline: now.Add(hm.timeout),
	}
	
	// 使用第一个 assigned prefix 的地址作为源地址
	if len(hm.assignedPrefixes) == 0 {
		return fmt.Errorf("no assigned prefixes")
	}
	
	src := hm.assignedPrefixes[0].Addr()
	pkt, err := BuildHeartbeatPacket(HeartbeatTypePing, seq, now, src, hm.serverGateway)
	if err != nil {
		return err
	}
	
	return hm.sendPacket(pkt)
}

func (hm *HeartbeatManager) checkTimeouts() bool {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	now := time.Now()
	hasTimeout := false

	for seq, pending := range hm.pending {
		if now.After(pending.Deadline) {
			delete(hm.pending, seq)
			hasTimeout = true
			// 每条超过 deadline 的 ping 计 1 次 timeout，
			// 这与 spec 4.5 中"心跳 timeout 计数"语义一致。
			observability.Global.IncAppKeepaliveTimeout()
		}
	}

	if hasTimeout {
		hm.timeoutCount++
		if hm.timeoutCount >= hm.threshold {
			return true // 达到不健康阈值
		}
	}

	return false
}
