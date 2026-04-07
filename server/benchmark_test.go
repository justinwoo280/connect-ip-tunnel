package server

import (
	"fmt"
	"net/netip"
	"testing"
)

// ── Dispatcher Benchmark ─────────────────────────────────────────────────────

// BenchmarkDispatcherLookupHostRoute 测量有 N 个 session 时 /32 地址直索引的查找性能。
func BenchmarkDispatcherLookupHostRoute(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("sessions_%d", n), func(b *testing.B) {
			d := NewPacketDispatcher(nil)
			for i := 0; i < n; i++ {
				id := fmt.Sprintf("session-%d", i)
				ip := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.%d/32", i/65536, (i/256)%256, i%256))
				d.RegisterSession(id, ip, netip.Prefix{})
			}
			target := netip.MustParseAddr("10.0.0.1")

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = d.lookupSession(target)
			}
		})
	}
}

// BenchmarkDispatcherLookupPrefixFallback 测量前缀回退路径（非 /32）的查找性能。
func BenchmarkDispatcherLookupPrefixFallback(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("sessions_%d", n), func(b *testing.B) {
			d := NewPacketDispatcher(nil)
			for i := 0; i < n; i++ {
				id := fmt.Sprintf("session-%d", i)
				// /24 前缀，触发 fallback 扫描
				ip := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
				d.RegisterSession(id, ip, netip.Prefix{})
			}
			target := netip.MustParseAddr("10.0.0.55")

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = d.lookupSession(target)
			}
		})
	}
}

// ── IPPool Benchmark ──────────────────────────────────────────────────────────

// BenchmarkIPPoolAllocate 测量 IP 池分配性能（含空闲地址复用路径）。
func BenchmarkIPPoolAllocate(b *testing.B) {
	pool, err := NewIPPool("10.0.0.0/16", "")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("s-%d", i)
		_, _, err := pool.AllocateIP(id, id+"-s")
		if err != nil {
			// 池满后释放所有 session，重新开始
			for j := 0; j < i; j++ {
				pool.ReleaseIP(fmt.Sprintf("s-%d", j))
			}
			i = 0
			continue
		}
		pool.ReleaseIP(id) // 立即释放，测试复用路径
	}
}

// BenchmarkIPPoolAllocateReleaseCycle 测量分配/释放循环（模拟会话轮转）。
func BenchmarkIPPoolAllocateReleaseCycle(b *testing.B) {
	pool, err := NewIPPool("10.0.0.0/24", "fd00::/120")
	if err != nil {
		b.Fatal(err)
	}

	// 预分配 64 个 session，模拟在线会话
	for i := 0; i < 64; i++ {
		pool.AllocateIP(fmt.Sprintf("pre-%d", i), fmt.Sprintf("pre-%d-s", i))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("bench-%d", i%64)
		pool.ReleaseIP(id)
		pool.AllocateIP(id, id+"-s")
	}
}

// BenchmarkIPPoolReleaseO1 对比旧的 O(N) 全表释放和新的 O(1) 反向索引释放。
func BenchmarkIPPoolReleaseO1(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("sessions_%d", n), func(b *testing.B) {
			pool, err := NewIPPool("10.0.0.0/8", "")
			if err != nil {
				b.Fatal(err)
			}
			// 预分配 n 个
			for i := 0; i < n; i++ {
				pool.AllocateIP(fmt.Sprintf("s-%d", i), fmt.Sprintf("s-%d-s", i))
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				id := fmt.Sprintf("s-%d", i%n)
				pool.ReleaseIP(id)
				pool.AllocateIP(id, id+"-s")
			}
		})
	}
}
