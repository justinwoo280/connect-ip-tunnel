package server

import (
	"fmt"
	"net/netip"
	"sync"
)

// IPPool 管理客户端 IP 地址分配。
// 支持多 session 复用同一 IP：同一 clientKey（mTLS 证书 CN）的多个 session 共享同一 IP，
// 只有该 clientKey 的最后一个 session 释放时才真正归还 IP。
type IPPool struct {
	ipv4Pool netip.Prefix
	ipv6Pool netip.Prefix

	// clientKey -> IP（核心分配表）
	clientIPv4 map[string]netip.Addr
	clientIPv6 map[string]netip.Addr

	// IP -> clientKey（反向查找）
	allocatedIPv4 map[netip.Addr]string
	allocatedIPv6 map[netip.Addr]string

	// clientKey -> []sessionID（引用计数：记录哪些 session 属于同一客户端）
	clientSessions map[string][]string

	// sessionID -> clientKey（快速反查）
	sessionToClient map[string]string

	// 已释放可复用的 IP
	freeIPv4 []netip.Addr
	freeIPv6 []netip.Addr

	// 下一个未使用过的可分配 IP
	nextIPv4 netip.Addr
	nextIPv6 netip.Addr

	mu sync.Mutex
}

func NewIPPool(ipv4Pool, ipv6Pool string) (*IPPool, error) {
	pool := &IPPool{
		clientIPv4:      make(map[string]netip.Addr),
		clientIPv6:      make(map[string]netip.Addr),
		allocatedIPv4:   make(map[netip.Addr]string),
		allocatedIPv6:   make(map[netip.Addr]string),
		clientSessions:  make(map[string][]string),
		sessionToClient: make(map[string]string),
	}

	// 解析 IPv4 地址池
	if ipv4Pool != "" {
		prefix, err := netip.ParsePrefix(ipv4Pool)
		if err != nil {
			return nil, fmt.Errorf("parse ipv4 pool: %w", err)
		}
		pool.ipv4Pool = prefix
		// .0 网络地址，.1 作为 TUN 网关 IP，客户端从 .2 开始分配
		pool.nextIPv4 = prefix.Addr().Next().Next()
	}

	// 解析 IPv6 地址池
	if ipv6Pool != "" {
		prefix, err := netip.ParsePrefix(ipv6Pool)
		if err != nil {
			return nil, fmt.Errorf("parse ipv6 pool: %w", err)
		}
		pool.ipv6Pool = prefix
		// ::0 网络地址，::1 作为 TUN 网关 IP，客户端从 ::2 开始分配
		pool.nextIPv6 = prefix.Addr().Next().Next()
	}

	return pool, nil
}

// GatewayIPv4 返回 IPv4 池的 TUN 网关地址，格式为 CIDR（如 "10.233.0.1/16"）。
// 网关取池的第二个地址（.1），池的第一个地址（.0）是网络地址不可用。
// 客户端从第三个地址（.2）开始分配。
func (p *IPPool) GatewayIPv4() (string, error) {
	if !p.ipv4Pool.IsValid() {
		return "", fmt.Errorf("no ipv4 pool configured")
	}
	// .0 是网络地址，.1 是网关（TUN IP），客户端从 .2 开始
	gw := p.ipv4Pool.Addr().Next() // 10.233.0.0 → 10.233.0.1
	if !p.ipv4Pool.Contains(gw) {
		return "", fmt.Errorf("ipv4 pool too small for gateway")
	}
	return netip.PrefixFrom(gw, p.ipv4Pool.Bits()).String(), nil
}

// GatewayIPv6 返回 IPv6 池的 TUN 网关地址，格式为 CIDR（如 "fd00::1/64"）。
func (p *IPPool) GatewayIPv6() (string, error) {
	if !p.ipv6Pool.IsValid() {
		return "", fmt.Errorf("no ipv6 pool configured")
	}
	gw := p.ipv6Pool.Addr().Next() // fd00:: → fd00::1
	if !p.ipv6Pool.Contains(gw) {
		return "", fmt.Errorf("ipv6 pool too small for gateway")
	}
	return netip.PrefixFrom(gw, p.ipv6Pool.Bits()).String(), nil
}

// AllocateIP 为会话分配 IP 地址。
//
// clientKey 是客户端的唯一标识（mTLS 场景下用证书 CN/Subject），
// 同一 clientKey 的多个 session（多路并行）复用同一 IP，
// 避免多 session 模式下各 session 分配到不同 IP 导致源地址校验失败。
//
// sessionID 用于追踪哪些 session 属于同一客户端（用于 ReleaseIP 引用计数）。
func (p *IPPool) AllocateIP(clientKey, sessionID string) (ipv4Prefix, ipv6Prefix netip.Prefix, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 同一 clientKey 已有分配，直接复用并记录新 session。
	if ipv4, ok := p.clientIPv4[clientKey]; ok {
		p.sessionToClient[sessionID] = clientKey
		p.clientSessions[clientKey] = append(p.clientSessions[clientKey], sessionID)
		ipv4Prefix = netip.PrefixFrom(ipv4, 32)
		if ipv6, ok := p.clientIPv6[clientKey]; ok {
			ipv6Prefix = netip.PrefixFrom(ipv6, 128)
		}
		return ipv4Prefix, ipv6Prefix, nil
	}

	// 新客户端，分配新 IP
	if p.ipv4Pool.IsValid() {
		ipv4, err := p.allocateIPv4(clientKey)
		if err != nil {
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("allocate ipv4: %w", err)
		}
		ipv4Prefix = netip.PrefixFrom(ipv4, 32)
	}

	if p.ipv6Pool.IsValid() {
		ipv6, err := p.allocateIPv6(clientKey)
		if err != nil {
			if ipv4Prefix.IsValid() {
				p.releaseIPv4Locked(clientKey)
			}
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("allocate ipv6: %w", err)
		}
		ipv6Prefix = netip.PrefixFrom(ipv6, 128)
	}

	p.sessionToClient[sessionID] = clientKey
	p.clientSessions[clientKey] = append(p.clientSessions[clientKey], sessionID)
	return ipv4Prefix, ipv6Prefix, nil
}

// allocateIPv4 分配一个 IPv4 地址（按 clientKey）
func (p *IPPool) allocateIPv4(clientKey string) (netip.Addr, error) {
	if addr, ok := p.popFreeIPv4Locked(); ok {
		p.allocatedIPv4[addr] = clientKey
		p.clientIPv4[clientKey] = addr
		return addr, nil
	}

	current := p.nextIPv4
	if !current.IsValid() {
		return netip.Addr{}, fmt.Errorf("ipv4 pool exhausted")
	}
	for p.ipv4Pool.Contains(current) {
		if _, exists := p.allocatedIPv4[current]; !exists {
			p.allocatedIPv4[current] = clientKey
			p.clientIPv4[clientKey] = current
			p.nextIPv4 = current.Next()
			return current, nil
		}
		current = current.Next()
	}
	return netip.Addr{}, fmt.Errorf("ipv4 pool exhausted")
}

// allocateIPv6 分配一个 IPv6 地址（按 clientKey）
func (p *IPPool) allocateIPv6(clientKey string) (netip.Addr, error) {
	if addr, ok := p.popFreeIPv6Locked(); ok {
		p.allocatedIPv6[addr] = clientKey
		p.clientIPv6[clientKey] = addr
		return addr, nil
	}

	current := p.nextIPv6
	if !current.IsValid() {
		return netip.Addr{}, fmt.Errorf("ipv6 pool exhausted")
	}
	for p.ipv6Pool.Contains(current) {
		if _, exists := p.allocatedIPv6[current]; !exists {
			p.allocatedIPv6[current] = clientKey
			p.clientIPv6[clientKey] = current
			p.nextIPv6 = current.Next()
			return current, nil
		}
		current = current.Next()
	}
	return netip.Addr{}, fmt.Errorf("ipv6 pool exhausted")
}

func (p *IPPool) popFreeIPv4Locked() (netip.Addr, bool) {
	for len(p.freeIPv4) > 0 {
		idx := len(p.freeIPv4) - 1
		addr := p.freeIPv4[idx]
		p.freeIPv4 = p.freeIPv4[:idx]
		if !p.ipv4Pool.Contains(addr) {
			continue
		}
		if _, exists := p.allocatedIPv4[addr]; exists {
			continue
		}
		return addr, true
	}
	return netip.Addr{}, false
}

func (p *IPPool) popFreeIPv6Locked() (netip.Addr, bool) {
	for len(p.freeIPv6) > 0 {
		idx := len(p.freeIPv6) - 1
		addr := p.freeIPv6[idx]
		p.freeIPv6 = p.freeIPv6[:idx]
		if !p.ipv6Pool.Contains(addr) {
			continue
		}
		if _, exists := p.allocatedIPv6[addr]; exists {
			continue
		}
		return addr, true
	}
	return netip.Addr{}, false
}

// ReleaseIP 释放一个 session 的引用。
// 只有当 clientKey 的所有 session 都释放后，IP 才真正归还到池中。
func (p *IPPool) ReleaseIP(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	clientKey, ok := p.sessionToClient[sessionID]
	if !ok {
		return
	}
	delete(p.sessionToClient, sessionID)

	// 从 clientSessions 里移除此 session
	sessions := p.clientSessions[clientKey]
	newSessions := sessions[:0]
	for _, s := range sessions {
		if s != sessionID {
			newSessions = append(newSessions, s)
		}
	}
	if len(newSessions) > 0 {
		p.clientSessions[clientKey] = newSessions
		return // 还有其他 session 在用，不释放 IP
	}

	// 最后一个 session 释放，真正归还 IP
	delete(p.clientSessions, clientKey)
	p.releaseIPv4Locked(clientKey)
	p.releaseIPv6Locked(clientKey)
}

func (p *IPPool) releaseIPv4Locked(clientKey string) {
	if ip, ok := p.clientIPv4[clientKey]; ok {
		delete(p.clientIPv4, clientKey)
		delete(p.allocatedIPv4, ip)
		p.freeIPv4 = append(p.freeIPv4, ip)
	}
}

func (p *IPPool) releaseIPv6Locked(clientKey string) {
	if ip, ok := p.clientIPv6[clientKey]; ok {
		delete(p.clientIPv6, clientKey)
		delete(p.allocatedIPv6, ip)
		p.freeIPv6 = append(p.freeIPv6, ip)
	}
}

// GetAllocatedIPs 获取 session 对应客户端已分配的 IP 地址
func (p *IPPool) GetAllocatedIPs(sessionID string) (ipv4, ipv6 netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	clientKey, ok := p.sessionToClient[sessionID]
	if !ok {
		return netip.Addr{}, netip.Addr{}
	}
	return p.clientIPv4[clientKey], p.clientIPv6[clientKey]
}

// Stats 返回地址池统计信息
func (p *IPPool) Stats() IPPoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return IPPoolStats{
		IPv4PoolSize:  p.ipv4Pool.Bits(),
		IPv4Allocated: len(p.allocatedIPv4),
		IPv6PoolSize:  p.ipv6Pool.Bits(),
		IPv6Allocated: len(p.allocatedIPv6),
		TotalSessions: p.countUniqueSessions(),
	}
}

func (p *IPPool) countUniqueSessions() int {
	return len(p.sessionToClient)
}

type IPPoolStats struct {
	IPv4PoolSize  int
	IPv4Allocated int
	IPv6PoolSize  int
	IPv6Allocated int
	TotalSessions int
}
