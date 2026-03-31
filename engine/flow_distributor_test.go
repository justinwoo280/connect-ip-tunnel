package engine

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func buildIPv4Packet(srcIP, dstIP net.IP, proto uint8) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[9] = proto
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	return pkt
}

func buildIPv4TCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 24)
	pkt[0] = 0x45
	pkt[9] = 6 // TCP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

// TestFlowDistributorSameFlowSameSession 验证同一五元组始终映射到同一 session。
func TestFlowDistributorSameFlowSameSession(t *testing.T) {
	dist := newFlowDistributor(8)
	pkt := buildIPv4TCPPacket(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"), 54321, 443,
	)

	first := dist.Select(pkt)
	for i := 0; i < 100; i++ {
		if got := dist.Select(pkt); got != first {
			t.Fatalf("same flow mapped to different sessions: %d vs %d", first, got)
		}
	}
}

// TestFlowDistributorDifferentFlowsDifferentSessions 验证不同 flow 能分散到不同 session。
func TestFlowDistributorDifferentFlowsDifferentSessions(t *testing.T) {
	dist := newFlowDistributor(8)
	seen := make(map[int]bool)
	for i := 0; i < 100; i++ {
		pkt := buildIPv4TCPPacket(
			net.ParseIP("10.0.0.1"),
			net.ParseIP("1.2.3.4"),
			uint16(1000+i), 443,
		)
		seen[dist.Select(pkt)] = true
	}
	// 100 个不同 srcPort 的 flow，至少应分散到 2 个以上 session
	if len(seen) < 2 {
		t.Fatalf("expected flows to spread across sessions, only used %d", len(seen))
	}
}

// TestFlowDistributorSingleSession 验证 n=1 时所有包都路由到 session 0。
func TestFlowDistributorSingleSession(t *testing.T) {
	dist := newFlowDistributor(1)
	for i := 0; i < 10; i++ {
		pkt := buildIPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 17)
		if got := dist.Select(pkt); got != 0 {
			t.Fatalf("single session mode: expected 0, got %d", got)
		}
	}
}

// TestFlowDistributorShortPacket 验证不完整包不会 panic。
func TestFlowDistributorShortPacket(t *testing.T) {
	dist := newFlowDistributor(4)
	for _, pkt := range [][]byte{
		nil,
		{},
		{0x45},
		{0x60, 0x00, 0x00},
	} {
		_ = dist.Select(pkt) // 不应 panic
	}
}

// buildIPv4Fragment 构造一个 IPv4 分片包。
// identification 是原始包的 ID，fragOffset 单位为 8 字节，mf 表示还有后续分片。
func buildIPv4Fragment(srcIP, dstIP net.IP, proto uint8, identification uint16, fragOffset uint16, mf bool) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[9] = proto
	binary.BigEndian.PutUint16(pkt[4:6], identification)

	flags := uint16(0)
	if mf {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flags|fragOffset)
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	return pkt
}

// TestFlowDistributorFragmentConsistency 验证同一原始 IP 包的所有分片
// 被哈希到同一个 session。
func TestFlowDistributorFragmentConsistency(t *testing.T) {
	dist := newFlowDistributor(8)
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("1.2.3.4")
	const identification = 0xABCD

	// 第一个分片：MF=1, offset=0
	frag1 := buildIPv4Fragment(src, dst, 17, identification, 0, true)
	// 第二个分片：MF=1, offset=185（185*8=1480 字节偏移）
	frag2 := buildIPv4Fragment(src, dst, 17, identification, 185, true)
	// 最后一个分片：MF=0, offset=370
	frag3 := buildIPv4Fragment(src, dst, 17, identification, 370, false)

	s1 := dist.Select(frag1)
	s2 := dist.Select(frag2)
	s3 := dist.Select(frag3)

	if s1 != s2 || s2 != s3 {
		t.Fatalf("fragments of same IP packet routed to different sessions: frag1=%d frag2=%d frag3=%d", s1, s2, s3)
	}
	t.Logf("all fragments routed to session %d ✅", s1)
}

// TestFlowDistributorDifferentIdentificationSpread 验证不同 identification
// 的分片包可以分散到不同 session（均匀性）。
func TestFlowDistributorDifferentIdentificationSpread(t *testing.T) {
	dist := newFlowDistributor(8)
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("1.2.3.4")

	seen := make(map[int]bool)
	for i := 0; i < 256; i++ {
		// 每个不同 identification 的分片包
		frag := buildIPv4Fragment(src, dst, 17, uint16(i*257), 185, true)
		seen[dist.Select(frag)] = true
	}
	if len(seen) < 4 {
		t.Fatalf("expected fragments with different identification to spread across sessions, only used %d", len(seen))
	}
	t.Logf("different identification packets spread across %d sessions ✅", len(seen))
}

// buildIPv6FragmentPacket 构造一个带 Fragment Extension Header 的 IPv6 包。
func buildIPv6FragmentPacket(srcIP, dstIP net.IP, transportProto uint8, identification uint32, fragOffset uint16, mFlag bool) []byte {
	// IPv6 基础头（40B）+ Fragment Header（8B）
	pkt := make([]byte, 48)

	// IPv6 基础头
	pkt[0] = 0x60 // version=6
	pkt[6] = 44   // Next Header = Fragment Header
	pkt[7] = 64   // Hop Limit

	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	// Fragment Header（offset 40）
	pkt[40] = transportProto // Next Header（真正的传输层协议）
	pkt[41] = 0              // Reserved

	// Fragment Offset (13bit) << 3 | Res(2bit) | M flag(1bit)
	offsetAndFlags := fragOffset << 3
	if mFlag {
		offsetAndFlags |= 0x0001
	}
	binary.BigEndian.PutUint16(pkt[42:44], offsetAndFlags)

	// Identification（32bit）
	binary.BigEndian.PutUint32(pkt[44:48], identification)
	return pkt
}

// TestFlowDistributorIPv6FragmentConsistency 验证 IPv6 同一原始包的所有分片
// 落在同一 session。
func TestFlowDistributorIPv6FragmentConsistency(t *testing.T) {
	dist := newFlowDistributor(8)
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	const identification = uint32(0xDEADBEEF)

	// 三个分片：第一片 MF=1 offset=0，中间片 MF=1 offset=185，最后片 MF=0 offset=370
	frag1 := buildIPv6FragmentPacket(src, dst, 17, identification, 0, true)
	frag2 := buildIPv6FragmentPacket(src, dst, 17, identification, 185, true)
	frag3 := buildIPv6FragmentPacket(src, dst, 17, identification, 370, false)

	s1 := dist.Select(frag1)
	s2 := dist.Select(frag2)
	s3 := dist.Select(frag3)

	if s1 != s2 || s2 != s3 {
		t.Fatalf("IPv6 fragments of same packet routed to different sessions: %d %d %d", s1, s2, s3)
	}
	t.Logf("IPv6 all fragments routed to session %d ✅", s1)
}

// TestFlowDistributorIPv6FragmentSpread 验证不同 identification 的 IPv6 分片
// 能均匀分散到多个 session（32bit identification 的优势）。
func TestFlowDistributorIPv6FragmentSpread(t *testing.T) {
	dist := newFlowDistributor(8)
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")

	seen := make(map[int]bool)
	for i := 0; i < 64; i++ {
		frag := buildIPv6FragmentPacket(src, dst, 17, uint32(i*0x1000001), 185, true)
		seen[dist.Select(frag)] = true
	}
	if len(seen) < 4 {
		t.Fatalf("IPv6 fragments expected to spread, only used %d sessions", len(seen))
	}
	t.Logf("IPv6 different identification spread across %d sessions ✅", len(seen))
}

// TestFlowDistributorIPv6MaliciousExtHdrChain 验证超长 Extension Header 链不会让 CPU 跑飞。
func TestFlowDistributorIPv6MaliciousExtHdrChain(t *testing.T) {
	dist := newFlowDistributor(8)

	// 构造一个有 20 个 Hop-by-Hop Extension Header 的恶意包（超过 maxExtHdrHops=8）
	// 每个 Hop-by-Hop Header：Next Header(1) + Len(1) + Padding(6) = 8 字节，Len=0 表示 8 字节
	const numExtHdrs = 20
	pkt := make([]byte, 40+numExtHdrs*8+4)
	pkt[0] = 0x60 // IPv6
	pkt[6] = 0    // Next Header = Hop-by-Hop Options
	pkt[7] = 64   // Hop Limit
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())

	// 构造 Extension Header 链
	offset := 40
	for i := 0; i < numExtHdrs; i++ {
		if i < numExtHdrs-1 {
			pkt[offset] = 0 // Next = Hop-by-Hop
		} else {
			pkt[offset] = 17 // Next = UDP（最后一个）
		}
		pkt[offset+1] = 0 // Len=0 表示 8 字节
		offset += 8
	}

	// 关键：不应该 panic，也不应该死循环
	done := make(chan struct{})
	go func() {
		_ = dist.Select(pkt)
		close(done)
	}()

	select {
	case <-done:
		t.Log("malicious ext header chain handled safely ✅")
	case <-func() chan struct{} {
		ch := make(chan struct{})
		go func() {
			// 5ms 超时，正常应该在 ns 级完成
			time.Sleep(5 * time.Millisecond)
			close(ch)
		}()
		return ch
	}():
		t.Fatal("ext header traversal took too long, possible infinite loop")
	}
}

// TestFlowDistributorIPv6NonFragment 验证 IPv6 非分片包（无 Fragment Header）正常走五元组。
func TestFlowDistributorIPv6NonFragment(t *testing.T) {
	dist := newFlowDistributor(8)

	// 构造普通 IPv6 UDP 包（无 Extension Header）
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	pkt[6] = 17 // Next Header = UDP（直接，无 Extension Header）
	pkt[7] = 64
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(pkt[40:42], 12345) // src port
	binary.BigEndian.PutUint16(pkt[42:44], 443)   // dst port

	// 相同包两次哈希结果一致
	if dist.Select(pkt) != dist.Select(pkt) {
		t.Fatal("IPv6 non-fragment hash not stable")
	}
	t.Logf("IPv6 non-fragment routed to session %d ✅", dist.Select(pkt))
}

// TestFlowDistributorNonFragmentVsFragment 验证同一 flow 的非分片包
// 和分片包可能落在不同 session（这是预期行为，因为分片包无法提取端口）。
func TestFlowDistributorNonFragmentVsFragment(t *testing.T) {
	dist := newFlowDistributor(8)
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("1.2.3.4")

	// 正常非分片 TCP 包
	normal := buildIPv4TCPPacket(src, dst, 54321, 443)

	// 同一 src/dst/proto 的分片包
	frag := buildIPv4Fragment(src, dst, 6, 0x1234, 185, false)

	// 两者不要求落在同一 session（分片包只能三元组+id，无法精确到 flow）
	// 但两者都不应该 panic，且分片包的所有片段要一致
	_ = dist.Select(normal)
	s1 := dist.Select(frag)

	// 再构建同一 identification 的后续分片，验证一致性
	frag2 := buildIPv4Fragment(src, dst, 6, 0x1234, 370, false)
	s2 := dist.Select(frag2)
	if s1 != s2 {
		t.Fatalf("same identification fragments routed differently: %d vs %d", s1, s2)
	}
	t.Logf("non-fragment and fragment handling verified ✅")
}
