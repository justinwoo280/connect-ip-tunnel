package engine

import (
	"encoding/binary"
	"net"
	"testing"
)

// ── Flow Hash Benchmark ───────────────────────────────────────────────────────

// BenchmarkFlowHashIPv4 测量 IPv4 TCP 包的五元组哈希计算吞吐。
func BenchmarkFlowHashIPv4(b *testing.B) {
	pkt := buildIPv4TCPPacket(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"), 54321, 443,
	)
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = flowHash(pkt)
	}
}

// BenchmarkFlowHashIPv4Parallel 并行版，模拟多核场景。
func BenchmarkFlowHashIPv4Parallel(b *testing.B) {
	pkt := buildIPv4TCPPacket(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"), 54321, 443,
	)
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = flowHash(pkt)
		}
	})
}

// BenchmarkFlowDistributorSelect 测量 N=8 session 场景下的 select 吞吐。
func BenchmarkFlowDistributorSelect(b *testing.B) {
	dist := newFlowDistributor(8)
	pkts := make([][]byte, 256)
	for i := range pkts {
		pkts[i] = buildIPv4TCPPacket(
			net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"),
			uint16(1024+i), 443,
		)
	}
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = dist.Select(pkts[i%256])
	}
}

// ── Multi-Session Write Simulation ───────────────────────────────────────────

// BenchmarkFlowDistributorDispatch 模拟高速包分发到 N 个 session 的吞吐量。
// 这里用 channel 模拟 session 写，测量分发层的纯 CPU 开销。
func BenchmarkFlowDistributorDispatch(b *testing.B) {
	const nSessions = 8
	dist := newFlowDistributor(nSessions)

	// 模拟 session 的接收 channel
	channels := make([]chan []byte, nSessions)
	for i := range channels {
		channels[i] = make(chan []byte, 4096)
	}
	// 消费 goroutine，避免 channel 满导致测试阻塞
	for i := range channels {
		ch := channels[i]
		go func() {
			for range ch {
			}
		}()
	}

	// 预生成 256 个不同 flow 的包
	pkts := make([][]byte, 256)
	for i := range pkts {
		pkts[i] = buildIPv4TCPPacket(
			net.ParseIP("10.0.0.1"), net.ParseIP("1.2.3.4"),
			uint16(1024+i), 443,
		)
	}

	pktSize := int64(len(pkts[0]))
	b.SetBytes(pktSize)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := pkts[i%256]
		idx := dist.Select(pkt)
		channels[idx] <- pkt
	}

	for _, ch := range channels {
		close(ch)
	}
}

// ── IPv4 Header Parse Benchmark ───────────────────────────────────────────────

// BenchmarkParseDstAddr 测量从 IP 包头解析目的地址的性能（dispatcher 热路径）。
func BenchmarkParseDstAddr(b *testing.B) {
	// 复用 server 包里的 parseDstAddr 逻辑，这里直接内联 IPv4 解析
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5
	// dst IP at offset 16
	copy(pkt[16:20], net.ParseIP("10.0.0.2").To4())

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = flowHash(pkt)
	}
}

// ── Dispatch Path Micro Benchmarks ───────────────────────────────────────────

// BenchmarkSelectN8 精准测量 n=8（2的幂，走位掩码路径）的 Select 开销。
func BenchmarkSelectN8(b *testing.B) {
	dist := newFlowDistributor(8)
	pkts := make([][]byte, 256)
	for i := range pkts {
		pkts[i] = buildIPv4TCPPacket(
			net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
			uint16(10000+i), 443,
		)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = dist.Select(pkts[i%256])
	}
}

// BenchmarkSelectN6 精准测量 n=6（非2的幂，走取模路径）的 Select 开销。
func BenchmarkSelectN6(b *testing.B) {
	dist := newFlowDistributor(6)
	pkts := make([][]byte, 256)
	for i := range pkts {
		pkts[i] = buildIPv4TCPPacket(
			net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
			uint16(10000+i), 443,
		)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = dist.Select(pkts[i%256])
	}
}

// BenchmarkSelectParallel 多核并发 Select（模拟多 goroutine 同时分发）。
func BenchmarkSelectParallel(b *testing.B) {
	dist := newFlowDistributor(8)
	pkts := make([][]byte, 256)
	for i := range pkts {
		pkts[i] = buildIPv4TCPPacket(
			net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
			uint16(10000+i), 443,
		)
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		idx := 0
		for pb.Next() {
			_ = dist.Select(pkts[idx%256])
			idx++
		}
	})
}

// BenchmarkHash4 单独测量 hash4（murmur）的开销（dispatch 里的核心计算）。
func BenchmarkHash4(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = hash4(0x0a000001, 0x08080808, 6, 0xd4310000|443)
	}
}

// BenchmarkIPv4FlowHash 单独测量 ipv4FlowHash（解析+hash）开销。
func BenchmarkIPv4FlowHash(b *testing.B) {
	pkt := buildIPv4TCPPacket(
		net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 54321, 443,
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ipv4FlowHash(pkt)
	}
}

// BenchmarkIPv6FlowHash 单独测量 ipv6FlowHash（含扩展头遍历）开销。
func BenchmarkIPv6FlowHash(b *testing.B) {
	// 最小 IPv6 + TCP 包（40B header + 4B TCP ports）
	pkt := make([]byte, 44)
	pkt[0] = 0x60 // IPv6
	pkt[6] = 6    // Next Header = TCP
	// src [8:24], dst [24:40] 全零即可
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ipv6FlowHash(pkt)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payloadSize int) []byte {
	pkt := make([]byte, 20+8+payloadSize)
	pkt[0] = 0x45
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

// BenchmarkFlowHashMTUPacket 测量 MTU 大小包（1400 字节）的哈希性能。
func BenchmarkFlowHashMTUPacket(b *testing.B) {
	pkt := buildIPv4UDPPacket(
		net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
		12345, 53, 1372, // 20 IP + 8 UDP + 1372 payload = 1400
	)
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = flowHash(pkt)
	}
}
