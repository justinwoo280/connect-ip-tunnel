// +build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"connect-ip-tunnel/transport/http3"
)

// This example demonstrates how to use the Happy Eyeballs implementation
// to dial a server with automatic IPv4/IPv6 fallback.
//
// This file is marked with +build ignore so it won't be compiled with the package.
// It serves as documentation for how to integrate Happy Eyeballs into the client.

func exampleHappyEyeballsUsage() {
	ctx := context.Background()

	// Step 1: Resolve targets with preference
	// "auto" = IPv6 first (RFC 6724), then IPv4
	// "v4" = IPv4 only
	// "v6" = IPv6 only
	targets, err := http3.ResolveTargets(ctx, "vpn.example.com:443", "auto")
	if err != nil {
		log.Fatalf("Failed to resolve targets: %v", err)
	}

	fmt.Printf("Resolved %d targets:\n", len(targets))
	for i, t := range targets {
		fmt.Printf("  %d. %s -> %s\n", i+1, t.Network, t.Addr)
	}

	// Step 2: Define a dialOne function that attempts to connect to a single target
	dialOne := func(ctx context.Context, t http3.Target) (interface{}, error) {
		// This would be replaced with actual QUIC dial logic
		// For example: transport.Dial(ctx, t.Addr, tlsConfig, quicConfig)
		fmt.Printf("Attempting to dial %s %s\n", t.Network, t.Addr)
		
		// Simulate dial attempt
		time.Sleep(10 * time.Millisecond)
		
		// Return success for demonstration
		return fmt.Sprintf("connection to %s", t.Addr), nil
	}

	// Step 3: Use Happy Eyeballs to dial with automatic fallback
	// RFC 8305 recommends 250-300ms delay between attempts
	delay := 50 * time.Millisecond
	
	conn, err := http3.HappyEyeballsDial(ctx, targets, delay, dialOne)
	if err != nil {
		log.Fatalf("All dial attempts failed: %v", err)
	}

	fmt.Printf("Successfully connected: %v\n", conn)
}

// Example integration into Factory.Dial method:
//
// func (f *Factory) Dial(ctx context.Context, target Target) (*qhttp3.ClientConn, error) {
//     // Get preference from config (e.g., f.opts.PreferAddressFamily)
//     prefer := "auto" // or "v4" or "v6"
//     
//     // Resolve targets with Happy Eyeballs
//     targets, err := resolveTargets(ctx, target.Addr, prefer)
//     if err != nil {
//         return nil, fmt.Errorf("resolve targets: %w", err)
//     }
//     
//     // Define dialOne function
//     dialOne := func(ctx context.Context, t target) (interface{}, error) {
//         // Get transport from pool for this network type
//         transport, err := f.pool.Get(ctx, t.network, "", f.bypass)
//         if err != nil {
//             return nil, err
//         }
//         
//         // Dial using the transport
//         tlsCfg := f.tlsClient.TLSConfig().Clone()
//         if target.ServerName != "" {
//             tlsCfg.ServerName = target.ServerName
//         }
//         
//         quicCfg := buildQUICConfig(f.opts)
//         return transport.Dial(ctx, t.addr, tlsCfg, quicCfg)
//     }
//     
//     // Use Happy Eyeballs with 50ms delay (configurable via f.opts.HappyEyeballsDelay)
//     delay := 50 * time.Millisecond
//     conn, err := happyEyeballsDial(ctx, targets, delay, dialOne)
//     if err != nil {
//         return nil, err
//     }
//     
//     quicConn := conn.(*quic.Conn)
//     // ... rest of the dial logic (ECH retry, congestion control, etc.)
// }

func main() {
	exampleHappyEyeballsUsage()
}
