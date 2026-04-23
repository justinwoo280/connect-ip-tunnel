package bufferpool

import (
	"testing"
)

func TestSetPacketBufferSize(t *testing.T) {
	// Save original value
	originalSize := PacketBufferSize
	defer func() {
		SetPacketBufferSize(originalSize)
	}()

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			name:     "set to 8192",
			input:    8192,
			expected: 8192,
		},
		{
			name:     "set to 1500",
			input:    1500,
			expected: 1500,
		},
		{
			name:     "set to zero defaults to 4096",
			input:    0,
			expected: 4096,
		},
		{
			name:     "set to negative defaults to 4096",
			input:    -100,
			expected: 4096,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetPacketBufferSize(tt.input)
			if PacketBufferSize != tt.expected {
				t.Errorf("SetPacketBufferSize(%d): got %d, want %d", tt.input, PacketBufferSize, tt.expected)
			}

			// Verify pool creates buffers of correct size
			buf := GetPacket()
			if len(buf) != tt.expected {
				t.Errorf("GetPacket() returned buffer of size %d, want %d", len(buf), tt.expected)
			}
			PutPacket(buf)
		})
	}
}

func TestGetPutPacket(t *testing.T) {
	// Set a known size
	SetPacketBufferSize(2048)
	defer SetPacketBufferSize(4096)

	// Get a packet
	buf := GetPacket()
	if len(buf) != 2048 {
		t.Errorf("GetPacket() returned buffer of size %d, want 2048", len(buf))
	}

	// Modify it
	buf[0] = 0xFF

	// Put it back
	PutPacket(buf)

	// Get another packet (might be the same one from pool)
	buf2 := GetPacket()
	if len(buf2) != 2048 {
		t.Errorf("GetPacket() returned buffer of size %d, want 2048", len(buf2))
	}
	PutPacket(buf2)
}

func TestPutPacketWithWrongSize(t *testing.T) {
	SetPacketBufferSize(4096)
	defer SetPacketBufferSize(4096)

	// Create a buffer that's too small
	smallBuf := make([]byte, 100)
	
	// This should not panic, just not put it back in the pool
	PutPacket(smallBuf)
}
