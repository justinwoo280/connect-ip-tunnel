package connectip

import (
	"net/netip"
	"testing"
	"time"
)

// TestHeartbeatPacketRoundTrip 验证 BuildHeartbeatPacket → ParseHeartbeatPayload 端到端可往返。
// 旧测试调用的 MarshalHeartbeat/UnmarshalHeartbeat/HeartbeatFrame.Type 已经被
// BuildHeartbeatPacket / ParseHeartbeatPayload 取代（前者构造完整 IP 包而非 17 字节裸 payload）。
func TestHeartbeatPacketRoundTrip(t *testing.T) {
	src := netip.MustParseAddr("10.233.0.2")
	dst := netip.MustParseAddr("10.233.0.1")
	seq := uint64(12345)
	// 截断到秒以避免与解码后单调时钟相关的细微差异；payload 用纳秒序列化，逐字节对比。
	ts := time.Unix(1714000000, 123456000)

	// PING
	pingPkt, err := BuildHeartbeatPacket(HeartbeatTypePing, seq, ts, src, dst)
	if err != nil {
		t.Fatalf("build ping: %v", err)
	}
	// IPv4 header (20) + payload (17)
	if want := 20 + 17; len(pingPkt) != want {
		t.Errorf("expected ping packet size %d, got %d", want, len(pingPkt))
	}
	gotTyp, gotSeq, gotTs, err := ParseHeartbeatPayload(pingPkt)
	if err != nil {
		t.Fatalf("parse ping: %v", err)
	}
	if gotTyp != HeartbeatTypePing {
		t.Errorf("expected type PING (0x01), got 0x%02x", gotTyp)
	}
	if gotSeq != seq {
		t.Errorf("expected seq %d, got %d", seq, gotSeq)
	}
	if !gotTs.Equal(ts) {
		t.Errorf("expected ts %v, got %v", ts, gotTs)
	}

	// PONG
	pongPkt, err := BuildHeartbeatPacket(HeartbeatTypePong, seq, ts, src, dst)
	if err != nil {
		t.Fatalf("build pong: %v", err)
	}
	gotTyp, _, _, err = ParseHeartbeatPayload(pongPkt)
	if err != nil {
		t.Fatalf("parse pong: %v", err)
	}
	if gotTyp != HeartbeatTypePong {
		t.Errorf("expected type PONG (0x02), got 0x%02x", gotTyp)
	}
}

// TestIsHeartbeatPacketBasic 验证 IsHeartbeatPacket 对真实心跳包返回 true，
// 对随机字节流返回 false。
//
// 心跳方向（来自实现 isIPv4Heartbeat）：
//   - 客户端 → 服务端 PING: src=assignedIP, dst=serverGateway
//                          服务端 (isServer=true) 收到此包应返回 true
//   - 服务端 → 客户端 PONG: src=serverGateway, dst=assignedIP
//                          客户端 (isServer=false) 收到此包应返回 true
func TestIsHeartbeatPacketBasic(t *testing.T) {
	clientAssigned := netip.MustParseAddr("10.233.0.2")
	serverGateway := netip.MustParseAddr("10.233.0.1")
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.233.0.0/16")}
	now := time.Now()

	// 客户端发出的 PING（src=clientAssigned, dst=serverGateway），服务端视角应识别
	pingPkt, err := BuildHeartbeatPacket(HeartbeatTypePing, 1, now, clientAssigned, serverGateway)
	if err != nil {
		t.Fatalf("build ping: %v", err)
	}
	if !IsHeartbeatPacket(pingPkt, prefixes, serverGateway, true) {
		t.Errorf("server-side: expected IsHeartbeatPacket=true for client→server ping")
	}
	// 但同样的包从客户端视角看不应被识别（src/dst 与方向不符）
	if IsHeartbeatPacket(pingPkt, prefixes, serverGateway, false) {
		t.Errorf("client-side: expected IsHeartbeatPacket=false for client→server ping (wrong direction)")
	}

	// 服务端回复的 PONG（src=serverGateway, dst=clientAssigned），客户端视角应识别
	pongPkt, err := BuildHeartbeatPacket(HeartbeatTypePong, 1, now, serverGateway, clientAssigned)
	if err != nil {
		t.Fatalf("build pong: %v", err)
	}
	if !IsHeartbeatPacket(pongPkt, prefixes, serverGateway, false) {
		t.Errorf("client-side: expected IsHeartbeatPacket=true for server→client pong")
	}

	// 太短 / 非心跳的输入应返回 false
	negatives := [][]byte{
		nil,
		{},
		{0x00}, // 长度不足 + 非 IPv4/IPv6
		{0x45}, // 仅 IPv4 magic 一字节
		{0x60}, // 仅 IPv6 magic 一字节
	}
	for i, n := range negatives {
		if IsHeartbeatPacket(n, prefixes, serverGateway, false) {
			t.Errorf("case[%d] expected false for malformed input %v", i, n)
		}
	}
}
