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

func TestPacketDispatcherLookupRequiresHostRoute(t *testing.T) {
	// 新行为：不再支持前缀扫描回退，只支持 /32 和 /128 的精确查找
	d := NewPacketDispatcher(nil)
	d.RegisterSession("s1", netip.MustParsePrefix("10.0.0.0/24"), netip.Prefix{})
	defer d.UnregisterSession("s1")

	// /24 前缀不会被索引，因此查找应该失败
	entry := d.lookupSession(netip.MustParseAddr("10.0.0.55"))
	if entry != nil {
		t.Fatal("expected lookup to fail for non-host-route prefix")
	}
}
