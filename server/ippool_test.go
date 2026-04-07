package server

import "testing"

func TestIPPoolReleaseReusesAddress(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/30", "")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	// clientKey="client-1", sessionID="sess-1"
	first, _, err := pool.AllocateIP("client-1", "sess-1")
	if err != nil {
		t.Fatalf("AllocateIP client-1: %v", err)
	}
	second, _, err := pool.AllocateIP("client-2", "sess-2")
	if err != nil {
		t.Fatalf("AllocateIP client-2: %v", err)
	}
	if first.Addr() == second.Addr() {
		t.Fatalf("expected distinct IPs, got %s and %s", first, second)
	}

	// 释放 client-1 的 sess-1（唯一 session，IP 应归还）
	pool.ReleaseIP("sess-1")

	reused, _, err := pool.AllocateIP("client-3", "sess-3")
	if err != nil {
		t.Fatalf("AllocateIP client-3: %v", err)
	}
	if reused.Addr() != first.Addr() {
		t.Fatalf("expected released IP %s to be reused, got %s", first, reused)
	}
}

func TestIPPoolMultiSessionSharesIP(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/29", "")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	// 同一 clientKey 建立 3 个并行 session，应复用同一 IP
	ip1, _, err := pool.AllocateIP("client-a", "sess-a1")
	if err != nil {
		t.Fatalf("AllocateIP sess-a1: %v", err)
	}
	ip2, _, err := pool.AllocateIP("client-a", "sess-a2")
	if err != nil {
		t.Fatalf("AllocateIP sess-a2: %v", err)
	}
	ip3, _, err := pool.AllocateIP("client-a", "sess-a3")
	if err != nil {
		t.Fatalf("AllocateIP sess-a3: %v", err)
	}
	if ip1.Addr() != ip2.Addr() || ip2.Addr() != ip3.Addr() {
		t.Fatalf("expected same IP for same clientKey, got %s %s %s", ip1, ip2, ip3)
	}

	// 释放前两个 session，IP 不应归还
	pool.ReleaseIP("sess-a1")
	pool.ReleaseIP("sess-a2")
	got4, _ := pool.GetAllocatedIPs("sess-a3")
	if !got4.IsValid() {
		t.Fatal("IP should still be allocated after partial release")
	}

	// 释放最后一个 session，IP 归还
	pool.ReleaseIP("sess-a3")
	got4, _ = pool.GetAllocatedIPs("sess-a3")
	if got4.IsValid() {
		t.Fatal("IP should be released after all sessions closed")
	}
}

func TestIPPoolGetAllocatedIPsUsesReverseIndex(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/29", "fd00::/126")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	ipv4, ipv6, err := pool.AllocateIP("client-1", "sess-1")
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}

	// GetAllocatedIPs 接受 sessionID
	got4, got6 := pool.GetAllocatedIPs("sess-1")
	if got4 != ipv4.Addr() {
		t.Fatalf("unexpected ipv4: got %s want %s", got4, ipv4.Addr())
	}
	if got6 != ipv6.Addr() {
		t.Fatalf("unexpected ipv6: got %s want %s", got6, ipv6.Addr())
	}
}
