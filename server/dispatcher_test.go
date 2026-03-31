package server

import (
	"net/netip"
	"testing"
)

func TestPacketDispatcherLookupUsesExactHostIndex(t *testing.T) {
	d := NewPacketDispatcher(nil)
	ch := d.RegisterSession("s1", netip.MustParsePrefix("10.0.0.2/32"), netip.Prefix{})
	defer d.UnregisterSession("s1")

	entry := d.lookupSession(netip.MustParseAddr("10.0.0.2"))
	if entry == nil {
		t.Fatal("expected indexed session lookup to succeed")
	}
	if entry.inbound != ch {
		t.Fatal("lookup returned wrong session entry")
	}
}

func TestPacketDispatcherLookupFallsBackToPrefixScan(t *testing.T) {
	d := NewPacketDispatcher(nil)
	ch := d.RegisterSession("s1", netip.MustParsePrefix("10.0.0.0/24"), netip.Prefix{})
	defer d.UnregisterSession("s1")

	entry := d.lookupSession(netip.MustParseAddr("10.0.0.55"))
	if entry == nil {
		t.Fatal("expected prefix fallback lookup to succeed")
	}
	if entry.inbound != ch {
		t.Fatal("lookup returned wrong prefix-matched session entry")
	}
}
