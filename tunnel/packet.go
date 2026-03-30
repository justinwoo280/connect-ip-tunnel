package tunnel

// PacketTunnel 是 raw IP packet 隧道抽象。
// connect-ip、MASQUE 或其他 L3 隧道实现都应满足该接口。
type PacketTunnel interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Close() error
}
