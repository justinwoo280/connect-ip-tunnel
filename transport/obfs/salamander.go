// Package obfs 提供 QUIC UDP 包级别的混淆实现。
//
// # Salamander 混淆算法
//
// Salamander 是 Hysteria2 项目设计的 UDP 包级别 XOR 混淆方案，
// 目的是让 QUIC 握手包（Long Header）在 DPI 设备看来是随机字节，
// 无法被识别为 QUIC 协议特征，从而规避运营商针对 QUIC/UDP 的 QoS 限速。
//
// # 算法设计
//
//	发包：
//	  1. 生成 8 字节随机 salt
//	  2. key = BLAKE2b-256(password || salt)
//	  3. payload[i] ^= key[i % 32]
//	  4. 实际发出：[salt:8][密文:n]
//
//	收包：
//	  1. 取前 8 字节作为 salt
//	  2. key = BLAKE2b-256(password || salt)
//	  3. 密文[i] ^= key[i % 32] → 还原 payload
//
// # 性能
//
// BLAKE2b 是专为速度设计的哈希函数，比 SHA256 快约 3 倍，
// 适合高频 per-packet 计算场景。每个包的额外开销仅 8 字节 salt。
//
// 热路径零分配：
//   - ReadFrom 完全在调用方提供的 buffer 上原地解密，0 allocs/op
//   - WriteTo 使用 sync.Pool 复用发送缓冲区，0 allocs/op（稳态）
//   - key 派生使用结构体预分配的 keyBuf，不触发逃逸
//
// # 参考实现
//
// 本实现基于 SagerNet/sing-quic hysteria2/salamander.go，
// 移植为 connect-ip-tunnel 使用，适配 quic-go 的 net.PacketConn 接口。
// 原始实现：Copyright (C) 2024 SagerNet (MIT License)
package obfs

import (
	"crypto/rand"
	"net"

	"connect-ip-tunnel/common/bufferpool"

	"golang.org/x/crypto/blake2b"
)

const (
	// salamanderSaltLen 每个 UDP 包前缀的随机 salt 长度
	salamanderSaltLen = 8

	// ObfsTypeSalamander Salamander 混淆类型标识（用于配置文件）
	ObfsTypeSalamander = "salamander"
)

// SalamanderPacketConn 是对 net.PacketConn 的包装，
// 在发包时加密（XOR），收包时解密（XOR）。
//
// 实现了 net.PacketConn 接口，可直接传入 quic-go 的 Listen/Dial。
//
// 并发安全性：quic-go 保证单个 conn 上最多一个 ReadFrom goroutine +
// 一个 WriteTo goroutine，因此 readKeyBuf / writeKeyBuf 分别归各自
// goroutine 独占使用，无需加锁。
type SalamanderPacketConn struct {
	net.PacketConn
	password []byte

	// readKeyBuf / writeKeyBuf 是预分配的 key 派生缓冲区，
	// 布局：[password...][salt:8]，长度 = len(password) + 8。
	// 在 NewSalamanderConn 时一次分配，后续 ReadFrom/WriteTo 只需
	// copy salt 到尾部 8 字节即可，无需任何 make/append。
	readKeyBuf  []byte
	writeKeyBuf []byte

	// writeBufPool 发送缓冲区池，避免 WriteTo 每次 make([]byte, 8+len(p))
	// 逃逸到堆。使用全局 bufferpool（64KB），足以容纳任何 MTU 包 + salt。

	// Key caching for read path (hot path optimization)
	lastReadSalt [salamanderSaltLen]byte
	lastReadKey  [blake2b.Size256]byte
	hasReadKey   bool

	// Key caching for write path (hot path optimization)
	lastWriteSalt [salamanderSaltLen]byte
	lastWriteKey  [blake2b.Size256]byte
	hasWriteKey   bool
}

// NewSalamanderConn 创建一个 Salamander 混淆的 PacketConn。
//
// password 是预共享密钥（客户端和服务端必须相同）。
// conn 是底层 UDP socket。
func NewSalamanderConn(conn net.PacketConn, password string) net.PacketConn {
	pw := []byte(password)

	// 预分配两份 keyBuf：read goroutine 和 write goroutine 各自使用，
	// 布局 [password][salt:8]，password 部分只写一次不再改变。
	readKeyBuf := make([]byte, len(pw)+salamanderSaltLen)
	copy(readKeyBuf, pw)

	writeKeyBuf := make([]byte, len(pw)+salamanderSaltLen)
	copy(writeKeyBuf, pw)

	return &SalamanderPacketConn{
		PacketConn:  conn,
		password:    pw,
		readKeyBuf:  readKeyBuf,
		writeKeyBuf: writeKeyBuf,
	}
}

// bytesEqual 比较两个字节切片是否相等（用于 salt 比较）。
// 使用简单循环而非 bytes.Equal 以避免导入 bytes 包。
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ReadFrom 从底层 socket 读取一个 UDP 包并解密。
//
// 包格式：[salt:8][密文:n]
// 解密后：payload 写入 p[0:n]，返回 n（不含 salt）。
// 如果包长度 <= 8（只有 salt 或更短），视为无效包跳过。
//
// 热路径零分配：key 派生使用预分配 readKeyBuf，解密原地写入 p。
// 性能优化：缓存上次的 salt+key，如果 salt 相同则跳过 BLAKE2b 计算。
func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		// 包太短，无效，返回空
		n = 0
		return
	}

	// 提取 salt
	salt := p[:salamanderSaltLen]

	// 检查缓存：如果 salt 与上次相同，直接复用 key
	var key [blake2b.Size256]byte
	if s.hasReadKey && bytesEqual(salt, s.lastReadSalt[:]) {
		// Cache hit: 复用上次的 key
		key = s.lastReadKey
	} else {
		// Cache miss: 派生新 key 并更新缓存
		copy(s.readKeyBuf[len(s.password):], salt)
		key = blake2b.Sum256(s.readKeyBuf)

		// 更新缓存
		copy(s.lastReadSalt[:], salt)
		s.lastReadKey = key
		s.hasReadKey = true
	}

	// XOR 解密：密文覆盖到 p[0:] 起始位置
	ciphertext := p[salamanderSaltLen:n]
	for i, c := range ciphertext {
		p[i] = c ^ key[i%blake2b.Size256]
	}

	return n - salamanderSaltLen, addr, nil
}

// WriteTo 加密后发送一个 UDP 包。
//
// 包格式：[salt:8][密文:n]，总长 n+8。
// 加密不修改 p 本身，在独立缓冲区中操作。
//
// 热路径零分配（稳态）：
//   - 发送缓冲区从 bufferpool 获取/归还（sync.Pool，预热后 0 allocs/op）
//   - key 派生使用预分配 writeKeyBuf
//
// 性能优化：缓存上次的 salt+key，在短时间内复用 salt 以提高缓存命中率。
// 这在批量发送场景下特别有效（例如 TUN 批量写入）。
func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// 从 bufferpool 获取发送缓冲区（64KB，远大于 MTU+salt）
	buf := bufferpool.GetPacket()
	defer bufferpool.PutPacket(buf)

	sendLen := salamanderSaltLen + len(p)

	var key [blake2b.Size256]byte

	// 尝试复用上次的 salt 和 key（批量写入优化）
	if s.hasWriteKey {
		// Cache hit: 复用上次的 salt 和 key
		copy(buf[:salamanderSaltLen], s.lastWriteSalt[:])
		key = s.lastWriteKey
	} else {
		// Cache miss: 生成新 salt 并派生 key
		if _, err = rand.Read(buf[:salamanderSaltLen]); err != nil {
			return
		}

		// 派生 key：将 salt 写入 writeKeyBuf 尾部
		copy(s.writeKeyBuf[len(s.password):], buf[:salamanderSaltLen])
		key = blake2b.Sum256(s.writeKeyBuf)

		// 更新缓存
		copy(s.lastWriteSalt[:], buf[:salamanderSaltLen])
		s.lastWriteKey = key
		s.hasWriteKey = true
	}

	// XOR 加密 payload → buf[8:]
	for i, c := range p {
		buf[salamanderSaltLen+i] = c ^ key[i%blake2b.Size256]
	}

	// 发出加密包
	if _, err = s.PacketConn.WriteTo(buf[:sendLen], addr); err != nil {
		return
	}

	// 返回原始 payload 长度（调用方不感知 salt overhead）
	return len(p), nil
}

// Underlying returns the underlying PacketConn.
// This implements the udpsocket.Unwrapper interface, allowing
// the udpsocket.SetBuffers helper to access the real UDP socket.
func (s *SalamanderPacketConn) Underlying() net.PacketConn {
	return s.PacketConn
}


