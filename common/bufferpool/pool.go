package bufferpool

import "sync"

const (
	// PacketBufferSize 是单个 IP 包的最大尺寸（MTU + 预留）
	PacketBufferSize = 65536
)

var (
	// PacketPool 用于 TUN 读写的包缓冲区
	PacketPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, PacketBufferSize)
			return &buf
		},
	}
)

// GetPacket 从池中获取一个包缓冲区
func GetPacket() []byte {
	return *PacketPool.Get().(*[]byte)
}

// PutPacket 将包缓冲区归还到池
func PutPacket(buf []byte) {
	if cap(buf) >= PacketBufferSize {
		buf = buf[:PacketBufferSize]
		PacketPool.Put(&buf)
	}
}
