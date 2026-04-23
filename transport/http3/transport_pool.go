package http3

import (
	"context"
	"fmt"
	"net"
	"sync"

	"connect-ip-tunnel/common/udpsocket"
	"connect-ip-tunnel/transport/obfs"

	"github.com/quic-go/quic-go"
)

// poolKey uniquely identifies a transport in the pool.
// Transports are keyed by network type (udp4/udp6) and interface name
// (for bypass scenarios where different interfaces require separate sockets).
type poolKey struct {
	network string // "udp4" or "udp6"
	ifName  string // interface name (empty for non-bypass)
}

// poolItem holds a quic.Transport and its underlying PacketConn.
// Both must be closed together when the pool is cleaned up.
type poolItem struct {
	transport *quic.Transport
	conn      net.PacketConn
}

// transportPool manages a pool of quic.Transport instances for reuse
// across multiple dial operations. This is a key performance optimization
// that allows UDP socket and transport reuse, reducing syscall overhead
// and enabling GSO/GRO batching.
//
// Thread-safety: All methods are protected by a mutex.
type transportPool struct {
	mu    sync.Mutex
	items map[poolKey]*poolItem
	opts  Options
}

// newTransportPool creates a new transport pool with the given options.
func newTransportPool(opts Options) *transportPool {
	return &transportPool{
		items: make(map[poolKey]*poolItem),
		opts:  opts,
	}
}

// Get retrieves or creates a quic.Transport for the given network and interface.
//
// Parameters:
//   - ctx: Context for cancellation (used when creating new connections)
//   - network: "udp4" or "udp6"
//   - ifName: Interface name for bypass scenarios (empty for non-bypass)
//   - bypass: Bypass dialer (nil for non-bypass scenarios)
//
// Returns the transport on success, or an error if creation fails.
// The returned transport is shared and must not be closed by the caller.
func (p *transportPool) Get(ctx context.Context, network, ifName string, bypass interface{}) (*quic.Transport, error) {
	key := poolKey{network: network, ifName: ifName}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if we already have a transport for this key
	if item, ok := p.items[key]; ok {
		return item.transport, nil
	}

	// Create a new transport
	var pc net.PacketConn
	var err error

	// Create the base UDP connection
	if bypass != nil {
		// Bypass scenario: use the bypass dialer's ListenPacket
		// The bypass dialer will bind to the specific interface
		type bypassDialer interface {
			ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
		}
		if bp, ok := bypass.(bypassDialer); ok {
			pc, err = bp.ListenPacket(ctx, network, "")
			if err != nil {
				return nil, fmt.Errorf("transport pool: bypass listen packet: %w", err)
			}
		} else {
			return nil, fmt.Errorf("transport pool: invalid bypass dialer type")
		}
	} else {
		// Non-bypass scenario: standard ListenPacket
		pc, err = net.ListenPacket(network, "")
		if err != nil {
			return nil, fmt.Errorf("transport pool: listen packet: %w", err)
		}
	}

	// Configure UDP socket buffers
	if p.opts.UDPRecvBuffer > 0 || p.opts.UDPSendBuffer > 0 {
		bufSize := p.opts.UDPRecvBuffer
		if bufSize == 0 {
			bufSize = p.opts.UDPSendBuffer
		}
		udpsocket.SetBuffers(pc, bufSize)
	}

	// Wrap with Salamander obfuscation if configured
	var transportConn net.PacketConn = pc
	if p.opts.Obfs.Type == obfs.ObfsTypeSalamander && p.opts.Obfs.Password != "" {
		transportConn = obfs.NewSalamanderConn(pc, p.opts.Obfs.Password)
	}

	// Create the quic.Transport
	transport := &quic.Transport{
		Conn: transportConn,
	}

	// Store in pool
	item := &poolItem{
		transport: transport,
		conn:      pc, // Store the base connection for cleanup
	}
	p.items[key] = item

	return transport, nil
}

// Close closes all transports and connections in the pool.
// This should be called when the Factory is closed.
func (p *transportPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var firstErr error
	for key, item := range p.items {
		// Close the transport first
		if err := item.transport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		// Then close the underlying connection
		if err := item.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(p.items, key)
	}

	return firstErr
}
