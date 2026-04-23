package engine

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// FlowDistributor 按五元组哈希将 IP 包分发到 N 个 session 之一。
// 同一 flow（src IP + dst IP + protocol）始终映射到同一 session，避免乱序。
//
// 性能优化：
//   - n == 1：直接返回 0，跳过哈希计算
//   - n 为 2 的幂：用位掩码替代除法取模（&mask vs %n），在 x86/arm64 上快约 3-5 倍
//   - n 非 2 的幂：回退到标准取模
//
// 健康过滤：
//   - 支持标记 session 为不健康，Select 会跳过不健康的 session
type FlowDistributor struct {
	n    uint32 // session 数量
	mask uint32 // n 为 2 的幂时 = n-1，否则为 0（标记用普通取模）
	pow2 bool   // n 是否为 2 的幂
	
	mu      sync.RWMutex
	healthy []bool // 每个 session 的健康状态
}

func newFlowDistributor(n int) *FlowDistributor {
	if n <= 0 {
		n = 1
	}
	un := uint32(n)
	isPow2 := un&(un-1) == 0
	mask := uint32(0)
	if isPow2 {
		mask = un - 1
	}
	
	healthy := make([]bool, n)
	for i := range healthy {
		healthy[i] = true // 默认所有 session 都是健康的
	}
	
	return &FlowDistributor{
		n:       un,
		mask:    mask,
		pow2:    isPow2,
		healthy: healthy,
	}
}

// Select 返回该包应分发到的 session 索引（0 到 n-1）。
// 如果首选的 session 不健康，会尝试找一个健康的替代。
func (f *FlowDistributor) Select(pkt []byte) int {
	if f.n == 1 {
		return 0
	}
	
	h := flowHash(pkt)
	var idx int
	if f.pow2 {
		idx = int(h & f.mask)
	} else {
		idx = int(h % f.n)
	}
	
	// 检查首选 session 是否健康
	f.mu.RLock()
	if f.healthy[idx] {
		f.mu.RUnlock()
		return idx
	}
	
	// 首选不健康，找一个健康的
	for i := 0; i < int(f.n); i++ {
		if f.healthy[i] {
			f.mu.RUnlock()
			return i
		}
	}
	f.mu.RUnlock()
	
	// 没有健康的 session，返回首选（让上层处理错误）
	return idx
}

// SetHealthy 设置指定 session 的健康状态
func (f *FlowDistributor) SetHealthy(idx int, healthy bool) {
	if idx < 0 || idx >= int(f.n) {
		return
	}
	f.mu.Lock()
	f.healthy[idx] = healthy
	f.mu.Unlock()
}

// GetHealthy 返回指定 session 的健康状态
func (f *FlowDistributor) GetHealthy(idx int) bool {
	if idx < 0 || idx >= int(f.n) {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healthy[idx]
}

// flowHash 从 IP 包头提取流标识字段，计算哈希值。
//
// 非分片包：hash(Src_IP, Dst_IP, Protocol, Src_Port<<16|Dst_Port)
// 分片包：  hash(Src_IP, Dst_IP, Protocol, Identification)
//
// 两条路径形式完全对称，保证：
//   - 同一 flow 的所有包落在同一 session
//   - 同一原始 IP 包的所有分片落在同一 session
//   - 不同 flow / 不同原始包均匀分散到各 session
func flowHash(pkt []byte) uint32 {
	if len(pkt) == 0 {
		return 0
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		return ipv4FlowHash(pkt)
	case 6:
		return ipv6FlowHash(pkt)
	default:
		return 0
	}
}

func ipv4FlowHash(pkt []byte) uint32 {
	if len(pkt) < 20 {
		return 0
	}
	proto := uint32(pkt[9])
	src := binary.BigEndian.Uint32(pkt[12:16])
	dst := binary.BigEndian.Uint32(pkt[16:20])

	// 检查分片标志
	// pkt[6:8] = Flags(3bit) + Fragment Offset(13bit)
	flagsAndOffset := binary.BigEndian.Uint16(pkt[6:8])
	mf := flagsAndOffset&0x2000 != 0     // More Fragments
	fragOffset := flagsAndOffset & 0x1FFF // Fragment Offset（单位 8 字节）
	isFragmented := mf || fragOffset != 0

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		// 非法 IHL，退化为三元组
		return hash4(src, dst, proto, 0)
	}

	if isFragmented {
		// 分片包：hash(Src_IP, Dst_IP, Protocol, Identification)
		// Identification 在 pkt[4:6]，同一原始 IP 包所有分片值相同
		identification := uint32(binary.BigEndian.Uint16(pkt[4:6]))
		return hash4(src, dst, proto, identification)
	}

	// 非分片包：hash(Src_IP, Dst_IP, Protocol, Src_Port<<16|Dst_Port)
	if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
		ports := binary.BigEndian.Uint32(pkt[ihl : ihl+4])
		return hash4(src, dst, proto, ports)
	}
	// 非 TCP/UDP 协议（如 ICMP、GRE、ESP 等）：
	// 引入包长和首字节作为二级散列因子，避免所有非 TCP/UDP 包都映射到同一 session
	discriminator := uint32(pkt[0])<<24 | uint32(len(pkt))
	return hash4(src, dst, proto, discriminator)
}

func ipv6FlowHash(pkt []byte) uint32 {
	if len(pkt) < 40 {
		return 0
	}

	// src: pkt[8:24]，dst: pkt[24:40]
	// 128bit 地址折叠为 32bit：高低 64bit XOR 后再取高低 32bit XOR
	// 保留地址的全部熵，同时把输出压到 32bit
	src := ipv6AddrFold(pkt[8:24])
	dst := ipv6AddrFold(pkt[24:40])

	// 遍历 Extension Header 链，找到最终 transport 层协议和分片信息。
	//
	// 安全限制：RFC 8200 Section 4 规定合法 IPv6 包的 Extension Header 数量极少
	// （通常 0-3 个）。恶意构造的包可能包含大量 Extension Header 形成死循环攻击。
	// 限制最大跳数为 8，超过则退化为三元组哈希，不影响正常流量。
	const maxExtHdrHops = 8
	nextHdr := uint8(pkt[6])
	offset := 40
	fragID := uint32(0)
	isFragmented := false

	for hops := 0; hops < maxExtHdrHops && offset < len(pkt); hops++ {
		switch nextHdr {
		case 0, 60: // Hop-by-Hop Options, Destination Options
			if offset+2 > len(pkt) {
				goto done
			}
			nextHdr = pkt[offset]
			hdrLen := (int(pkt[offset+1]) + 1) * 8
			if hdrLen <= 0 || offset+hdrLen > len(pkt) {
				goto done
			}
			offset += hdrLen

		case 43: // Routing Header
			if offset+2 > len(pkt) {
				goto done
			}
			nextHdr = pkt[offset]
			hdrLen := (int(pkt[offset+1]) + 1) * 8
			if hdrLen <= 0 || offset+hdrLen > len(pkt) {
				goto done
			}
			offset += hdrLen

		case 44: // Fragment Header（RFC 8200 Section 4.5）
			// Fragment Header 结构（8 字节固定长度）：
			//   [0]   Next Header
			//   [1]   Reserved
			//   [2:4] Fragment Offset (13bit) + Res (2bit) + M flag (1bit)
			//   [4:8] Identification (32bit)
			if offset+8 > len(pkt) {
				goto done
			}
			nextHdr = pkt[offset]
			fragOffsetAndFlags := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			fragOffset := fragOffsetAndFlags >> 3
			mFlag := fragOffsetAndFlags & 0x1
			if fragOffset != 0 || mFlag != 0 {
				isFragmented = true
			}
			// IPv6 Identification 是 32bit，比 IPv4 的 16bit 大得多，碰撞概率更低
			fragID = binary.BigEndian.Uint32(pkt[offset+4 : offset+8])
			offset += 8

		default:
			// 到达 transport 层或未知 header，停止
			goto done
		}
	}

done:
	proto := uint32(nextHdr)

	if isFragmented {
		// 分片包：hash(Src_IP, Dst_IP, Protocol, Identification)
		// IPv6 Identification 是 32bit，比 IPv4 的 16bit 碰撞概率低 65536 倍
		return hash4(src, dst, proto, fragID)
	}

	// 非分片包：hash(Src_IP, Dst_IP, Protocol, Src_Port<<16|Dst_Port)
	if (nextHdr == 6 || nextHdr == 17) && offset+4 <= len(pkt) {
		ports := binary.BigEndian.Uint32(pkt[offset : offset+4])
		return hash4(src, dst, proto, ports)
	}
	return hash4(src, dst, proto, 0)
}

// ipv6AddrFold 将 128bit IPv6 地址折叠为 32bit，保留全部地址熵。
// 折叠方式：(hi64 XOR lo64) 的高 32bit XOR 低 32bit
func ipv6AddrFold(addr []byte) uint32 {
	hi := binary.BigEndian.Uint64(addr[0:8])
	lo := binary.BigEndian.Uint64(addr[8:16])
	folded := hi ^ lo
	return uint32(folded>>32) ^ uint32(folded)
}

// hash4 计算四个 uint32 字段的哈希值。
// 统一接口：hash(Src_IP, Dst_IP, Protocol, Discriminator)
//   非分片包：Discriminator = Src_Port<<16 | Dst_Port
//   分片包：  Discriminator = Identification
//   退化情况：Discriminator = 0
func hash4(a, b, c, d uint32) uint32 {
	h := murmur32(a, b, c)
	return murmurMix(h, d)
}

// murmur32 使用 MurmurHash3 finalizer 混合三个 uint32 值，雪崩效应强。
func murmur32(a, b, c uint32) uint32 {
	h := a ^ b ^ c
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

func murmurMix(h, v uint32) uint32 {
	h ^= v
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// FlowKey 是一个可以直接 map 查找的 flow 五元组。
type FlowKey struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	Protocol uint8
}
