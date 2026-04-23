package connectip

import (
	"testing"
	"time"
)

func TestHeartbeatFrameMarshalUnmarshal(t *testing.T) {
	seq := uint64(12345)
	ts := time.Now()
	
	// Test PING
	pingData := MarshalHeartbeat(HeartbeatTypePing, seq, ts)
	if len(pingData) != 17 {
		t.Errorf("expected ping frame size 17, got %d", len(pingData))
	}
	
	pingFrame, err := UnmarshalHeartbeat(pingData)
	if err != nil {
		t.Fatalf("unmarshal ping failed: %v", err)
	}
	
	if pingFrame.Type != HeartbeatTypePing {
		t.Errorf("expected type PING (0x01), got 0x%02x", pingFrame.Type)
	}
	if pingFrame.Seq != seq {
		t.Errorf("expected seq %d, got %d", seq, pingFrame.Seq)
	}
	
	// Test PONG
	pongData := MarshalHeartbeat(HeartbeatTypePong, seq, ts)
	pongFrame, err := UnmarshalHeartbeat(pongData)
	if err != nil {
		t.Fatalf("unmarshal pong failed: %v", err)
	}
	
	if pongFrame.Type != HeartbeatTypePong {
		t.Errorf("expected type PONG (0x02), got 0x%02x", pongFrame.Type)
	}
}

func TestIsHeartbeatFrame(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"ping", []byte{0x01}, true},
		{"pong", []byte{0x02}, true},
		{"ipv4", []byte{0x45}, false},
		{"ipv6", []byte{0x60}, false},
		{"invalid", []byte{0x03}, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHeartbeatFrame(tt.data)
			if result != tt.expected {
				t.Errorf("IsHeartbeatFrame(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}
