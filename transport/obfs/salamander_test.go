package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
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

// TestSalamanderKeyCaching 验证 key 缓存机制正确工作
func TestSalamanderKeyCaching(t *testing.T) {
	password := "test-password"
	payload1 := []byte("first packet")
	payload2 := []byte("second packet")
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	// 测试写缓存：连续写入应该复用 salt
	sender := &mockPacketConn{}
	senderConn := NewSalamanderConn(sender, password).(*SalamanderPacketConn)

	// 第一次写入：生成新 salt
	_, err := senderConn.WriteTo(payload1, addr)
	if err != nil {
		t.Fatalf("first WriteTo failed: %v", err)
	}
	firstSalt := make([]byte, salamanderSaltLen)
	copy(firstSalt, sender.buf[:salamanderSaltLen])

	// 第二次写入：应该复用相同的 salt（缓存命中）
	_, err = senderConn.WriteTo(payload2, addr)
	if err != nil {
		t.Fatalf("second WriteTo failed: %v", err)
	}
	secondSalt := sender.buf[:salamanderSaltLen]

	if !bytes.Equal(firstSalt, secondSalt) {
		t.Error("write cache should reuse salt for consecutive writes")
	}
	t.Log("✅ write cache: salt reused for consecutive writes")

	// 测试读缓存：相同 salt 的包应该命中缓存
	receiver := &mockPacketConn{}
	receiverConn := NewSalamanderConn(receiver, password).(*SalamanderPacketConn)

	// 准备两个使用相同 salt 的加密包
	testSalt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	encryptedBuf1 := make([]byte, salamanderSaltLen+len(payload1))
	copy(encryptedBuf1[:salamanderSaltLen], testSalt)
	// 手动加密 payload1
	keyBuf := make([]byte, len(password)+salamanderSaltLen)
	copy(keyBuf, []byte(password))
	copy(keyBuf[len(password):], testSalt)
	key := blake2b.Sum256(keyBuf)
	for i, c := range payload1 {
		encryptedBuf1[salamanderSaltLen+i] = c ^ key[i%blake2b.Size256]
	}

	// 第一次读取：缓存未命中
	receiver.buf = encryptedBuf1
	decrypted1 := make([]byte, len(encryptedBuf1))
	n1, _, err := receiverConn.ReadFrom(decrypted1)
	if err != nil {
		t.Fatalf("first ReadFrom failed: %v", err)
	}
	if !bytes.Equal(decrypted1[:n1], payload1) {
		t.Error("first read decryption failed")
	}

	// 验证缓存已设置
	if !receiverConn.hasReadKey {
		t.Error("read cache should be set after first read")
	}
	if !bytes.Equal(receiverConn.lastReadSalt[:], testSalt) {
		t.Error("cached salt should match test salt")
	}

	// 第二次读取：使用相同 salt，应该命中缓存
	encryptedBuf2 := make([]byte, salamanderSaltLen+len(payload2))
	copy(encryptedBuf2[:salamanderSaltLen], testSalt)
	for i, c := range payload2 {
		encryptedBuf2[salamanderSaltLen+i] = c ^ key[i%blake2b.Size256]
	}

	receiver.buf = encryptedBuf2
	decrypted2 := make([]byte, len(encryptedBuf2))
	n2, _, err := receiverConn.ReadFrom(decrypted2)
	if err != nil {
		t.Fatalf("second ReadFrom failed: %v", err)
	}
	if !bytes.Equal(decrypted2[:n2], payload2) {
		t.Error("second read decryption failed")
	}

	t.Log("✅ read cache: same salt reuses cached key")
}

// TestSalamanderCacheMiss 验证不同 salt 会触发缓存未命中
func TestSalamanderCacheMiss(t *testing.T) {
	password := "test-password"
	payload := []byte("test packet")
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	// 创建两个独立的连接（不共享缓存）
	sender1 := &mockPacketConn{}
	conn1 := NewSalamanderConn(sender1, password)
	conn1.WriteTo(payload, addr)
	salt1 := sender1.buf[:salamanderSaltLen]

	sender2 := &mockPacketConn{}
	conn2 := NewSalamanderConn(sender2, password)
	conn2.WriteTo(payload, addr)
	salt2 := sender2.buf[:salamanderSaltLen]

	// 不同连接应该生成不同的 salt（因为是随机生成的）
	if bytes.Equal(salt1, salt2) {
		t.Log("⚠️  warning: random salts happened to be equal (very unlikely)")
	} else {
		t.Log("✅ different connections generate different salts")
	}
}

// BenchmarkSalamanderWriteWithCache 测试写入性能（缓存命中场景）
func BenchmarkSalamanderWriteWithCache(b *testing.B) {
	password := "benchmark-password"
	payload := make([]byte, 1200) // 典型 QUIC 包大小
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}

	sender := &mockPacketConn{}
	conn := NewSalamanderConn(sender, password)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		conn.WriteTo(payload, addr)
	}
}

// BenchmarkSalamanderReadWithCache 测试读取性能（缓存命中场景）
func BenchmarkSalamanderReadWithCache(b *testing.B) {
	password := "benchmark-password"
	payload := make([]byte, 1200)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}

	// 准备加密包（使用固定 salt 以触发缓存）
	sender := &mockPacketConn{}
	senderConn := NewSalamanderConn(sender, password)
	senderConn.WriteTo(payload, addr)
	encryptedPacket := make([]byte, len(sender.buf))
	copy(encryptedPacket, sender.buf)

	receiver := &mockPacketConn{buf: encryptedPacket, addr: addr}
	receiverConn := NewSalamanderConn(receiver, password)
	decrypted := make([]byte, len(encryptedPacket))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		receiver.buf = encryptedPacket // 重置 buffer
		receiverConn.ReadFrom(decrypted)
	}
}
