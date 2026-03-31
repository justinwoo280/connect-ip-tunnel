package server

import "testing"

func TestIPPoolReleaseReusesAddress(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/30", "")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	first, _, err := pool.AllocateIP("s1")
	if err != nil {
		t.Fatalf("AllocateIP s1: %v", err)
	}
	second, _, err := pool.AllocateIP("s2")
	if err != nil {
		t.Fatalf("AllocateIP s2: %v", err)
	}
	if first.Addr() == second.Addr() {
		t.Fatalf("expected distinct IPs, got %s and %s", first, second)
	}

	pool.ReleaseIP("s1")

	reused, _, err := pool.AllocateIP("s3")
	if err != nil {
		t.Fatalf("AllocateIP s3: %v", err)
	}
	if reused.Addr() != first.Addr() {
		t.Fatalf("expected released IP %s to be reused, got %s", first, reused)
	}
}

func TestIPPoolGetAllocatedIPsUsesReverseIndex(t *testing.T) {
	pool, err := NewIPPool("10.0.0.0/29", "fd00::/126")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	ipv4, ipv6, err := pool.AllocateIP("session-1")
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}

	got4, got6 := pool.GetAllocatedIPs("session-1")
	if got4 != ipv4.Addr() {
		t.Fatalf("unexpected ipv4: got %s want %s", got4, ipv4.Addr())
	}
	if got6 != ipv6.Addr() {
		t.Fatalf("unexpected ipv6: got %s want %s", got6, ipv6.Addr())
	}
}
