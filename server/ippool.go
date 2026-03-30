package server

import (
	"fmt"
	"net/netip"
	"sync"
)

// IPPool 管理客户端 IP 地址分配
// 类似 WireGuard 的 AllowedIPs，但通过 CONNECT-IP 的 ADDRESS_ASSIGN capsule 实现
type IPPool struct {
	ipv4Pool netip.Prefix
	ipv6Pool netip.Prefix

	// 已分配的 IP 地址
	allocatedIPv4 map[netip.Addr]string // IP -> SessionID
	allocatedIPv6 map[netip.Addr]string

	// 下一个可分配的 IP
	nextIPv4 netip.Addr
	nextIPv6 netip.Addr

	mu sync.Mutex
}

func NewIPPool(ipv4Pool, ipv6Pool string) (*IPPool, error) {
	pool := &IPPool{
		allocatedIPv4: make(map[netip.Addr]string),
		allocatedIPv6: make(map[netip.Addr]string),
	}

	// 解析 IPv4 地址池
	if ipv4Pool != "" {
		prefix, err := netip.ParsePrefix(ipv4Pool)
		if err != nil {
			return nil, fmt.Errorf("parse ipv4 pool: %w", err)
		}
		pool.ipv4Pool = prefix
		// 从地址池的第二个 IP 开始分配（第一个通常是网关）
		pool.nextIPv4 = prefix.Addr().Next()
	}

	// 解析 IPv6 地址池
	if ipv6Pool != "" {
		prefix, err := netip.ParsePrefix(ipv6Pool)
		if err != nil {
			return nil, fmt.Errorf("parse ipv6 pool: %w", err)
		}
		pool.ipv6Pool = prefix
		pool.nextIPv6 = prefix.Addr().Next()
	}

	return pool, nil
}

// AllocateIP 为会话分配 IP 地址
// 返回分配的 IPv4 和 IPv6 前缀（用于 ADDRESS_ASSIGN capsule）
func (p *IPPool) AllocateIP(sessionID string) (ipv4Prefix, ipv6Prefix netip.Prefix, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 分配 IPv4
	if p.ipv4Pool.IsValid() {
		ipv4, err := p.allocateIPv4(sessionID)
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("allocate ipv4: %w", err)
		}
		// 分配 /32 前缀（单个 IP）
		ipv4Prefix = netip.PrefixFrom(ipv4, 32)
	}

	// 分配 IPv6
	if p.ipv6Pool.IsValid() {
		ipv6, err := p.allocateIPv6(sessionID)
		if err != nil {
			// 如果 IPv6 分配失败，回收 IPv4
			if ipv4Prefix.IsValid() {
				delete(p.allocatedIPv4, ipv4Prefix.Addr())
			}
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("allocate ipv6: %w", err)
		}
		// 分配 /128 前缀（单个 IP）
		ipv6Prefix = netip.PrefixFrom(ipv6, 128)
	}

	return ipv4Prefix, ipv6Prefix, nil
}

// allocateIPv4 分配一个 IPv4 地址
func (p *IPPool) allocateIPv4(sessionID string) (netip.Addr, error) {
	// 从 nextIPv4 开始查找可用 IP
	current := p.nextIPv4
	poolEnd := p.ipv4Pool.Masked().Addr()

	for {
		// 检查是否在地址池范围内
		if !p.ipv4Pool.Contains(current) {
			return netip.Addr{}, fmt.Errorf("ipv4 pool exhausted")
		}

		// 检查是否已分配
		if _, exists := p.allocatedIPv4[current]; !exists {
			// 分配这个 IP
			p.allocatedIPv4[current] = sessionID
			p.nextIPv4 = current.Next()
			return current, nil
		}

		// 尝试下一个 IP
		current = current.Next()

		// 防止无限循环
		if current == poolEnd {
			return netip.Addr{}, fmt.Errorf("ipv4 pool exhausted")
		}
	}
}

// allocateIPv6 分配一个 IPv6 地址
func (p *IPPool) allocateIPv6(sessionID string) (netip.Addr, error) {
	// 从 nextIPv6 开始查找可用 IP
	current := p.nextIPv6
	poolEnd := p.ipv6Pool.Masked().Addr()

	for {
		// 检查是否在地址池范围内
		if !p.ipv6Pool.Contains(current) {
			return netip.Addr{}, fmt.Errorf("ipv6 pool exhausted")
		}

		// 检查是否已分配
		if _, exists := p.allocatedIPv6[current]; !exists {
			// 分配这个 IP
			p.allocatedIPv6[current] = sessionID
			p.nextIPv6 = current.Next()
			return current, nil
		}

		// 尝试下一个 IP
		current = current.Next()

		// 防止无限循环（简化检查）
		if current == poolEnd {
			return netip.Addr{}, fmt.Errorf("ipv6 pool exhausted")
		}
	}
}

// ReleaseIP 释放会话的 IP 地址
func (p *IPPool) ReleaseIP(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 释放 IPv4
	for ip, sid := range p.allocatedIPv4 {
		if sid == sessionID {
			delete(p.allocatedIPv4, ip)
		}
	}

	// 释放 IPv6
	for ip, sid := range p.allocatedIPv6 {
		if sid == sessionID {
			delete(p.allocatedIPv6, ip)
		}
	}
}

// GetAllocatedIPs 获取会话已分配的 IP 地址
func (p *IPPool) GetAllocatedIPs(sessionID string) (ipv4, ipv6 netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 查找 IPv4
	for ip, sid := range p.allocatedIPv4 {
		if sid == sessionID {
			ipv4 = ip
			break
		}
	}

	// 查找 IPv6
	for ip, sid := range p.allocatedIPv6 {
		if sid == sessionID {
			ipv6 = ip
			break
		}
	}

	return ipv4, ipv6
}

// Stats 返回地址池统计信息
func (p *IPPool) Stats() IPPoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return IPPoolStats{
		IPv4PoolSize:      p.ipv4Pool.Bits(),
		IPv4Allocated:     len(p.allocatedIPv4),
		IPv6PoolSize:      p.ipv6Pool.Bits(),
		IPv6Allocated:     len(p.allocatedIPv6),
		TotalSessions:     p.countUniqueSessions(),
	}
}

func (p *IPPool) countUniqueSessions() int {
	sessions := make(map[string]struct{})
	for _, sid := range p.allocatedIPv4 {
		sessions[sid] = struct{}{}
	}
	for _, sid := range p.allocatedIPv6 {
		sessions[sid] = struct{}{}
	}
	return len(sessions)
}

type IPPoolStats struct {
	IPv4PoolSize  int
	IPv4Allocated int
	IPv6PoolSize  int
	IPv6Allocated int
	TotalSessions int
}
