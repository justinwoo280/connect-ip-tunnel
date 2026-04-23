package http3

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestResolveTargets_IPAddress tests resolving IP addresses directly
func TestResolveTargets_IPAddress(t *testing.T) {
	tests := []struct {
		name      string
		hostport  string
		prefer    string
		wantCount int
		wantNet   string
		wantErr   bool
	}{
		{
			name:      "IPv4 address with auto",
			hostport:  "1.2.3.4:443",
			prefer:    "auto",
			wantCount: 1,
			wantNet:   "udp4",
			wantErr:   false,
		},
		{
			name:      "IPv6 address with auto",
			hostport:  "[2001:db8::1]:443",
			prefer:    "auto",
			wantCount: 1,
			wantNet:   "udp6",
			wantErr:   false,
		},
		{
			name:      "IPv4 address with v4 preference",
			hostport:  "1.2.3.4:443",
			prefer:    "v4",
			wantCount: 1,
			wantNet:   "udp4",
			wantErr:   false,
		},
		{
			name:     "IPv4 address with v6 preference should fail",
			hostport: "1.2.3.4:443",
			prefer:   "v6",
			wantErr:  true,
		},
		{
			name:      "IPv6 address with v6 preference",
			hostport:  "[2001:db8::1]:443",
			prefer:    "v6",
			wantCount: 1,
			wantNet:   "udp6",
			wantErr:   false,
		},
		{
			name:     "IPv6 address with v4 preference should fail",
			hostport: "[2001:db8::1]:443",
			prefer:   "v4",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			targets, err := resolveTargets(ctx, tt.hostport, tt.prefer)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(targets) != tt.wantCount {
				t.Errorf("got %d targets, want %d", len(targets), tt.wantCount)
			}

			if len(targets) > 0 && targets[0].network != tt.wantNet {
				t.Errorf("got network %s, want %s", targets[0].network, tt.wantNet)
			}
		})
	}
}

// TestResolveTargets_Hostname tests DNS resolution for hostnames
func TestResolveTargets_Hostname(t *testing.T) {
	tests := []struct {
		name       string
		hostport   string
		prefer     string
		wantMinLen int
		firstNet   string // expected network type of first target
	}{
		{
			name:       "localhost with auto prefers IPv6",
			hostport:   "localhost:443",
			prefer:     "auto",
			wantMinLen: 1,
			// Note: localhost resolution is system-dependent
		},
		{
			name:       "localhost with v4 preference",
			hostport:   "localhost:443",
			prefer:     "v4",
			wantMinLen: 1,
			firstNet:   "udp4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			targets, err := resolveTargets(ctx, tt.hostport, tt.prefer)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(targets) < tt.wantMinLen {
				t.Errorf("got %d targets, want at least %d", len(targets), tt.wantMinLen)
			}

			if tt.firstNet != "" && len(targets) > 0 {
				if targets[0].network != tt.firstNet {
					t.Errorf("first target network = %s, want %s", targets[0].network, tt.firstNet)
				}
			}

			// Verify all targets have valid addresses
			for i, tgt := range targets {
				if tgt.addr == nil {
					t.Errorf("target[%d] has nil address", i)
				}
				if tgt.network != "udp4" && tgt.network != "udp6" {
					t.Errorf("target[%d] has invalid network %s", i, tgt.network)
				}
			}
		})
	}
}

// TestResolveTargets_InvalidInput tests error handling
func TestResolveTargets_InvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		hostport string
		prefer   string
	}{
		{
			name:     "missing port",
			hostport: "example.com",
			prefer:   "auto",
		},
		{
			name:     "invalid prefer value",
			hostport: "example.com:443",
			prefer:   "invalid",
		},
		{
			name:     "empty hostport",
			hostport: "",
			prefer:   "auto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := resolveTargets(ctx, tt.hostport, tt.prefer)
			if err == nil {
				t.Errorf("expected error but got none")
			}
		})
	}
}

// TestResolveTargets_ContextCancellation tests context cancellation during DNS resolution
func TestResolveTargets_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := resolveTargets(ctx, "example.com:443", "auto")
	if err == nil {
		t.Errorf("expected error due to canceled context")
	}
}

// TestHappyEyeballsDial_SingleTarget tests dialing with a single target
func TestHappyEyeballsDial_SingleTarget(t *testing.T) {
	ctx := context.Background()
	
	targets := []target{
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}},
	}

	called := false
	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		called = true
		return "success", nil
	}

	result, err := happyEyeballsDial(ctx, targets, 50*time.Millisecond, dialOne)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !called {
		t.Errorf("dialOne was not called")
	}

	if result != "success" {
		t.Errorf("got result %v, want 'success'", result)
	}
}

// TestHappyEyeballsDial_MultipleTargets_FirstSucceeds tests when first target succeeds
func TestHappyEyeballsDial_MultipleTargets_FirstSucceeds(t *testing.T) {
	ctx := context.Background()
	
	targets := []target{
		{network: "udp6", addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}},
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}},
	}

	callCount := 0
	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		callCount++
		// First target succeeds immediately
		if t.network == "udp6" {
			return "ipv6-success", nil
		}
		// Second target would succeed but should be canceled
		time.Sleep(100 * time.Millisecond)
		return "ipv4-success", nil
	}

	result, err := happyEyeballsDial(ctx, targets, 50*time.Millisecond, dialOne)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "ipv6-success" {
		t.Errorf("got result %v, want 'ipv6-success'", result)
	}

	// Give some time for the second goroutine to potentially start
	time.Sleep(150 * time.Millisecond)
	
	// Both should have been called (second one started but canceled)
	if callCount < 1 {
		t.Errorf("expected at least 1 call to dialOne, got %d", callCount)
	}
}

// TestHappyEyeballsDial_FirstFails_SecondSucceeds tests fallback behavior
func TestHappyEyeballsDial_FirstFails_SecondSucceeds(t *testing.T) {
	ctx := context.Background()
	
	targets := []target{
		{network: "udp6", addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}},
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}},
	}

	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		if t.network == "udp6" {
			// First target fails immediately
			return nil, errors.New("ipv6 connection failed")
		}
		// Second target succeeds
		return "ipv4-success", nil
	}

	result, err := happyEyeballsDial(ctx, targets, 50*time.Millisecond, dialOne)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != "ipv4-success" {
		t.Errorf("got result %v, want 'ipv4-success'", result)
	}
}

// TestHappyEyeballsDial_AllFail tests when all targets fail
func TestHappyEyeballsDial_AllFail(t *testing.T) {
	ctx := context.Background()
	
	targets := []target{
		{network: "udp6", addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}},
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}},
	}

	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		return nil, errors.New("connection failed")
	}

	_, err := happyEyeballsDial(ctx, targets, 50*time.Millisecond, dialOne)
	if err == nil {
		t.Errorf("expected error when all targets fail")
	}
}

// TestHappyEyeballsDial_ContextCancellation tests context cancellation during dial
func TestHappyEyeballsDial_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	
	targets := []target{
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}},
	}

	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		// Simulate slow dial
		time.Sleep(100 * time.Millisecond)
		return "success", nil
	}

	_, err := happyEyeballsDial(ctx, targets, 50*time.Millisecond, dialOne)
	if err == nil {
		t.Errorf("expected error due to context timeout")
	}
}

// TestHappyEyeballsDial_StaggerDelay tests that delays are properly applied
func TestHappyEyeballsDial_StaggerDelay(t *testing.T) {
	ctx := context.Background()
	
	targets := []target{
		{network: "udp6", addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}},
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}},
		{network: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 443}},
	}

	callTimes := make([]time.Time, 0, len(targets))
	var startTime time.Time

	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		if startTime.IsZero() {
			startTime = time.Now()
		}
		callTimes = append(callTimes, time.Now())
		
		// All fail so we can observe all attempts
		return nil, errors.New("failed")
	}

	delay := 50 * time.Millisecond
	_, _ = happyEyeballsDial(ctx, targets, delay, dialOne)

	// Verify we got all attempts
	if len(callTimes) != len(targets) {
		t.Fatalf("expected %d dial attempts, got %d", len(targets), len(callTimes))
	}

	// First call should be immediate (within 10ms tolerance)
	if callTimes[0].Sub(startTime) > 10*time.Millisecond {
		t.Errorf("first call delayed by %v, expected immediate", callTimes[0].Sub(startTime))
	}

	// Subsequent calls should be staggered by approximately 'delay'
	for i := 1; i < len(callTimes); i++ {
		actualDelay := callTimes[i].Sub(startTime)
		expectedDelay := delay * time.Duration(i)
		tolerance := 30 * time.Millisecond // Allow some scheduling variance
		
		if actualDelay < expectedDelay-tolerance || actualDelay > expectedDelay+tolerance {
			t.Errorf("call %d: delay = %v, expected ~%v (±%v)", 
				i, actualDelay, expectedDelay, tolerance)
		}
	}
}

// TestHappyEyeballsDial_EmptyTargets tests error handling for empty target list
func TestHappyEyeballsDial_EmptyTargets(t *testing.T) {
	ctx := context.Background()
	
	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		return "success", nil
	}

	_, err := happyEyeballsDial(ctx, []target{}, 50*time.Millisecond, dialOne)
	if err == nil {
		t.Errorf("expected error for empty targets list")
	}
}

// TestHappyEyeballsDial_RaceCondition tests concurrent access safety
func TestHappyEyeballsDial_RaceCondition(t *testing.T) {
	ctx := context.Background()
	
	// Create many targets to increase chance of race conditions
	targets := make([]target, 10)
	for i := range targets {
		targets[i] = target{
			network: "udp4",
			addr:    &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443 + i},
		}
	}

	dialOne := func(ctx context.Context, t target) (interface{}, error) {
		// Simulate variable dial times
		time.Sleep(time.Duration(t.addr.Port%5) * time.Millisecond)
		
		// First few succeed
		if t.addr.Port < 445 {
			return t.addr.Port, nil
		}
		return nil, errors.New("failed")
	}

	result, err := happyEyeballsDial(ctx, targets, 5*time.Millisecond, dialOne)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get one of the successful results
	portResult, ok := result.(int)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}
	
	if portResult < 443 || portResult >= 445 {
		t.Errorf("unexpected result port: %d", portResult)
	}
}

// TestMustParsePort tests the port parsing helper
func TestMustParsePort(t *testing.T) {
	tests := []struct {
		name string
		port string
		want int
	}{
		{"standard http", "80", 80},
		{"standard https", "443", 443},
		{"high port", "8080", 8080},
		{"max port", "65535", 65535},
		{"min port", "0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParsePort(tt.port)
			if got != tt.want {
				t.Errorf("mustParsePort(%q) = %d, want %d", tt.port, got, tt.want)
			}
		})
	}
}
