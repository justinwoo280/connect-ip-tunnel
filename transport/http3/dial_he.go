package http3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// target represents a resolved address that can be dialed.
// It contains both the network type (udp4/udp6) and the resolved UDP address.
type target struct {
	network string       // "udp4" or "udp6"
	addr    *net.UDPAddr // resolved UDP address
}

// resolveTargets resolves a host:port string into a list of dialable targets.
// It performs DNS resolution and returns addresses ordered according to the preference.
//
// Parameters:
//   - ctx: Context for cancellation
//   - hostport: Address in "host:port" format
//   - prefer: Address family preference - "auto" (IPv6 first per RFC 6724), "v4" (IPv4 only), "v6" (IPv6 only)
//
// Returns a list of targets ordered by preference, or an error if resolution fails.
func resolveTargets(ctx context.Context, hostport, prefer string) ([]target, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("invalid hostport %q: %w", hostport, err)
	}

	// If host is already an IP address, return it directly
	if ip := net.ParseIP(host); ip != nil {
		network := "udp4"
		if ip.To4() == nil {
			network = "udp6"
		}

		// Check if the IP family matches the preference
		if prefer == "v4" && network == "udp6" {
			return nil, fmt.Errorf("prefer v4 but got IPv6 address %s", host)
		}
		if prefer == "v6" && network == "udp4" {
			return nil, fmt.Errorf("prefer v6 but got IPv4 address %s", host)
		}

		addr := &net.UDPAddr{
			IP:   ip,
			Port: mustParsePort(port),
		}
		return []target{{network: network, addr: addr}}, nil
	}

	// Perform DNS resolution
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed for %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %q", host)
	}

	portNum := mustParsePort(port)
	var targets []target
	var ipv4Targets, ipv6Targets []target

	// Separate IPv4 and IPv6 addresses
	for _, ip := range ips {
		if ip.To4() != nil {
			// IPv4 address
			if prefer != "v6" {
				ipv4Targets = append(ipv4Targets, target{
					network: "udp4",
					addr: &net.UDPAddr{
						IP:   ip,
						Port: portNum,
					},
				})
			}
		} else {
			// IPv6 address
			if prefer != "v4" {
				ipv6Targets = append(ipv6Targets, target{
					network: "udp6",
					addr: &net.UDPAddr{
						IP:   ip,
						Port: portNum,
					},
				})
			}
		}
	}

	// Order targets according to preference
	switch prefer {
	case "v4":
		targets = ipv4Targets
	case "v6":
		targets = ipv6Targets
	case "auto", "":
		// RFC 6724: prefer IPv6 over IPv4
		targets = append(ipv6Targets, ipv4Targets...)
	default:
		return nil, fmt.Errorf("invalid prefer value %q, must be auto/v4/v6", prefer)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no suitable addresses found for %q with preference %q", host, prefer)
	}

	return targets, nil
}

// mustParsePort parses a port string and panics on error.
// This is safe because net.SplitHostPort already validated the port format.
func mustParsePort(port string) int {
	portNum := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			panic(fmt.Sprintf("invalid port %q", port))
		}
		portNum = portNum*10 + int(c-'0')
	}
	if portNum < 0 || portNum > 65535 {
		panic(fmt.Sprintf("port out of range: %d", portNum))
	}
	return portNum
}

// dialResult holds the result of a single dial attempt.
type dialResult struct {
	conn   interface{} // Connection (generic to support different connection types)
	target target      // The target that was dialed
	err    error       // Error if dial failed
}

// happyEyeballsDial implements RFC 8305 Happy Eyeballs algorithm.
// It attempts to dial multiple targets in parallel with staggered delays,
// returning the first successful connection and canceling remaining attempts.
//
// Parameters:
//   - ctx: Context for cancellation
//   - targets: List of targets to dial (should be ordered by preference)
//   - delay: Stagger delay between attempts (typically 250-300ms per RFC 8305)
//   - dialOne: Function to dial a single target
//
// Returns the first successful connection, or an error if all attempts fail.
func happyEyeballsDial(
	ctx context.Context,
	targets []target,
	delay time.Duration,
	dialOne func(ctx context.Context, t target) (interface{}, error),
) (interface{}, error) {
	if len(targets) == 0 {
		return nil, errors.New("no targets to dial")
	}

	// Create a child context that we can cancel to stop all in-flight dials
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Buffered channel to collect results from all dial attempts
	results := make(chan dialResult, len(targets))

	// Launch dial attempts with staggered delays
	for i, t := range targets {
		go func(index int, tgt target) {
			// Apply stagger delay for all attempts except the first
			if index > 0 {
				timer := time.NewTimer(delay * time.Duration(index))
				select {
				case <-timer.C:
					// Delay elapsed, proceed with dial
				case <-childCtx.Done():
					timer.Stop()
					return
				}
			}

			// Perform the dial
			conn, err := dialOne(childCtx, tgt)
			
			// Send result (non-blocking in case context was canceled)
			select {
			case results <- dialResult{conn: conn, target: tgt, err: err}:
			case <-childCtx.Done():
			}
		}(i, t)
	}

	// Collect results and return the first success
	var lastErr error
	for i := 0; i < len(targets); i++ {
		select {
		case result := <-results:
			if result.err == nil {
				// Success! Cancel remaining attempts and return
				cancel()
				return result.conn, nil
			}
			// Record the error and continue waiting for other attempts
			lastErr = result.err
		case <-ctx.Done():
			// Parent context canceled
			return nil, ctx.Err()
		}
	}

	// All attempts failed
	if lastErr != nil {
		return nil, fmt.Errorf("all dial attempts failed: %w", lastErr)
	}
	return nil, errors.New("all dial attempts failed")
}
