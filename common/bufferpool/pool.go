package bufferpool

import "sync"

var (
	// PacketBufferSize 是单个 IP 包的最大尺寸（MTU + 预留）
	// 默认 4096 字节，可通过 SetPacketBufferSize 调整
	PacketBufferSize = 4096

	// PacketPool 用于 TUN 读写的包缓冲区
	PacketPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, PacketBufferSize)
			return &buf
		},
	}

	// mu 保护 PacketBufferSize 的并发修改
	mu sync.Mutex
)

// SetPacketBufferSize 设置包缓冲区大小
// 必须在任何 GetPacket/PutPacket 调用之前调用
// 通常在 Engine.Start 或 Server.Start 中根据 MTU 设置
func SetPacketBufferSize(n int) {
	mu.Lock()
	defer mu.Unlock()
	
	if n <= 0 {
		n = 4096
	}
	
	PacketBufferSize = n
	
	// 重新创建 pool 以使用新的缓冲区大小
	PacketPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, PacketBufferSize)
			return &buf
		},
	}
}

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
