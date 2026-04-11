package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// mockPacketConn 模拟 UDP socket，用于测试
type mockPacketConn struct {
	buf  []byte
	addr net.Addr
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n = copy(p, m.buf)
	return n, m.addr, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	m.buf = make([]byte, len(p))
	copy(m.buf, p)
	m.addr = addr
	return len(p), nil
}

func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// TestSalamanderEncryptDecrypt 验证加密后解密能还原原始数据
func TestSalamanderEncryptDecrypt(t *testing.T) {
	password := "test-password-123"
	original := []byte("Hello, Salamander! This is a QUIC packet payload for testing.")

	// 加密端（客户端）
	sender := &mockPacketConn{}
	senderConn := NewSalamanderConn(sender, password)

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	_, err := senderConn.WriteTo(original, addr)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	// 确认加密后内容不同于原始数据
	if bytes.Equal(sender.buf[salamanderSaltLen:], original) {
		t.Error("encrypted data should differ from original")
	}

	// 解密端（服务端）：把加密后的数据放入 mockConn
	receiver := &mockPacketConn{buf: sender.buf, addr: addr}
	receiverConn := NewSalamanderConn(receiver, password)

	decrypted := make([]byte, len(sender.buf))
	n, _, err := receiverConn.ReadFrom(decrypted)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if !bytes.Equal(decrypted[:n], original) {
		t.Errorf("decrypted mismatch:\n  got  %q\n  want %q", decrypted[:n], original)
	}
}

// TestSalamanderWrongPassword 验证错误密码无法解密
func TestSalamanderWrongPassword(t *testing.T) {
	original := []byte("secret QUIC packet")

	sender := &mockPacketConn{}
	senderConn := NewSalamanderConn(sender, "correct-password")
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	senderConn.WriteTo(original, addr)

	// 用错误密码解密
	receiver := &mockPacketConn{buf: sender.buf, addr: addr}
	receiverConn := NewSalamanderConn(receiver, "wrong-password")

	decrypted := make([]byte, len(sender.buf))
	n, _, err := receiverConn.ReadFrom(decrypted)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	if bytes.Equal(decrypted[:n], original) {
		t.Error("wrong password should NOT produce correct plaintext")
	}
	t.Logf("✅ wrong password produces garbage: %x", decrypted[:n])
}

// TestSalamanderShortPacket 验证短包（≤8字节）不会 panic
func TestSalamanderShortPacket(t *testing.T) {
	receiver := &mockPacketConn{
		buf:  []byte{1, 2, 3, 4}, // 只有 4 字节，< salamanderSaltLen(8)
		addr: &net.UDPAddr{},
	}
	conn := NewSalamanderConn(receiver, "password")

	p := make([]byte, 64)
	n, _, err := conn.ReadFrom(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("short packet should return n=0, got %d", n)
	}
	t.Log("✅ short packet handled gracefully")
}

// TestSalamanderDifferentSalts 验证每次发包 salt 不同（加密结果不同）
func TestSalamanderDifferentSalts(t *testing.T) {
	password := "test-password"
	payload := []byte("same payload every time")
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	sender1 := &mockPacketConn{}
	NewSalamanderConn(sender1, password).WriteTo(payload, addr)

	sender2 := &mockPacketConn{}
	NewSalamanderConn(sender2, password).WriteTo(payload, addr)

	if bytes.Equal(sender1.buf, sender2.buf) {
		t.Error("two encryptions of same payload should differ (random salt)")
	}
	t.Log("✅ different salts produce different ciphertext")
}

// TestSalamanderLargePacket 验证大包（接近 MTU）正确处理
func TestSalamanderLargePacket(t *testing.T) {
	password := "test-password"
	// 模拟 1200 字节 QUIC 包
	original := make([]byte, 1200)
	for i := range original {
		original[i] = byte(i % 256)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}

	sender := &mockPacketConn{}
	NewSalamanderConn(sender, password).WriteTo(original, addr)

	receiver := &mockPacketConn{buf: sender.buf, addr: addr}
	decrypted := make([]byte, len(sender.buf))
	n, _, err := NewSalamanderConn(receiver, password).ReadFrom(decrypted)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if !bytes.Equal(decrypted[:n], original) {
		t.Error("large packet decryption failed")
	}
	t.Logf("✅ 1200-byte packet: encrypted size=%d (+%d bytes salt overhead)",
		len(sender.buf), salamanderSaltLen)
}
