package server

import (
	"fmt"
	"net/netip"
)

// RoutesPolicy 管理 per-client 路由策略
// 根据客户端证书 CN 返回允许的路由前缀列表
type RoutesPolicy struct {
	policies map[string][]netip.Prefix // CN -> 允许的路由前缀列表
	fallback []netip.Prefix             // 默认路由（未配置策略的客户端）
}

// NewRoutesPolicy 创建路由策略管理器
// policies: map[CN][]CIDR，例如 {"alice": ["10.0.0.0/8"], "bob": ["192.168.0.0/16"]}
// fallback: 默认路由（未配置策略的客户端使用），nil 表示使用全路由
func NewRoutesPolicy(policies map[string][]string, fallback []string) (*RoutesPolicy, error) {
	rp := &RoutesPolicy{
		policies: make(map[string][]netip.Prefix),
	}

	// 解析 per-client 策略
	for cn, cidrs := range policies {
		prefixes := make([]netip.Prefix, 0, len(cidrs))
		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q for client %q: %w", cidr, cn, err)
			}
			prefixes = append(prefixes, prefix)
		}
		rp.policies[cn] = prefixes
	}

	// 解析 fallback 路由
	if fallback != nil {
		prefixes := make([]netip.Prefix, 0, len(fallback))
		for _, cidr := range fallback {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid fallback CIDR %q: %w", cidr, err)
			}
			prefixes = append(prefixes, prefix)
		}
		rp.fallback = prefixes
	}

	return rp, nil
}

// For 返回指定客户端 CN 允许的路由前缀列表
// 如果该 CN 没有配置策略，返回 fallback 路由
// 如果 fallback 也为空，返回 nil（表示使用全路由）
func (rp *RoutesPolicy) For(cn string) []netip.Prefix {
	if prefixes, ok := rp.policies[cn]; ok {
		return prefixes
	}
	return rp.fallback
}
