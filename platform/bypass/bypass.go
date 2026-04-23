package bypass

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
)

// 探测目标：选择不同运营商的公共 anycast 地址，
// 与服务端真实地址族无关，仅用于触发内核选路并拿到出口接口。
var (
	probeTargetsV4 = []string{"8.8.8.8", "1.1.1.1"}
	probeTargetsV6 = []string{"2001:4860:4860::8888", "2606:4700:4700::1111"}
)

var ErrNotImplemented = errors.New("platform/bypass: not implemented")

// Dialer 提供绕过 TUN 的拨号能力。
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
}

// Detector 用于探测访问服务端时的物理出口接口。
type Detector interface {
	DetectOutboundInterface(serverAddr string) (string, error)
}

type Config struct {
	ServerAddr string
	Strict     bool // 严格模式：探测失败时返回错误而非降级
}

type Provider interface {
	Build(cfg Config) (Dialer, error)
}

type stdDialer struct {
	dialer *net.Dialer
	lc     *net.ListenConfig
}

func newFallbackDialer() Dialer {
	return &stdDialer{
		dialer: &net.Dialer{},
		lc:     &net.ListenConfig{},
	}
}

func newPlatformDialer(cfg Config, control func(*net.Interface) func(network, address string, c syscall.RawConn) error) (Dialer, error) {
	iface, err := detectOutboundInterface(cfg.ServerAddr)
	if err != nil {
		// 严格模式：探测失败时返回错误，不降级
		if cfg.Strict {
			return nil, fmt.Errorf("bypass: detect outbound interface failed (strict mode): %w", err)
		}
		// 宽松模式：无法识别物理出口时降级为标准拨号，避免主流程启动失败
		return newFallbackDialer(), nil
	}
	ctrl := control(iface)
	return &stdDialer{
		dialer: &net.Dialer{Control: ctrl},
		lc:     &net.ListenConfig{Control: ctrl},
	}, nil
}

// NetDialer 暴露内部的 *net.Dialer，供需要标准 Dialer 的组件使用（如 ECHManager DoH 客户端）。
func (d *stdDialer) NetDialer() *net.Dialer {
	return d.dialer
}

func (d *stdDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *stdDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	if strings.TrimSpace(addr) == "" {
		addr = ":0"
	}
	return d.lc.ListenPacket(ctx, network, addr)
}

// probeTarget 表示一次探测尝试：网络（udp4/udp6）+ 目标 IP 字面量。
type probeTarget struct {
	network string // "udp4" | "udp6"
	addr    string // 字面量 IP
}

// buildProbeTargets 根据 serverAddr 推断地址族偏好，构造一组候选探测目标。
//
// 排序规则：
//  1. 若 serverAddr 解析到 IP 字面量，优先尝试与服务端同族的目标，再尝试另一族。
//  2. 若 serverAddr 为空 / 无法解析，按 v4 → v6 顺序尝试（保持向后兼容）。
//  3. 服务端地址本身被作为首个探测目标，确保得到的接口与真实出站路径一致。
func buildProbeTargets(serverAddr string) []probeTarget {
	var (
		v4Targets []probeTarget
		v6Targets []probeTarget
		preferV6  bool
	)
	for _, addr := range probeTargetsV4 {
		v4Targets = append(v4Targets, probeTarget{network: "udp4", addr: addr})
	}
	for _, addr := range probeTargetsV6 {
		v6Targets = append(v6Targets, probeTarget{network: "udp6", addr: addr})
	}

	// 服务端 IP 作为最优探测目标（与真实路径一致）。
	var serverFirst []probeTarget
	if ip := parseIPFromAddr(serverAddr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			serverFirst = append(serverFirst, probeTarget{network: "udp4", addr: v4.String()})
		} else if ip.To16() != nil {
			serverFirst = append(serverFirst, probeTarget{network: "udp6", addr: ip.String()})
			preferV6 = true
		}
	}

	out := make([]probeTarget, 0, len(serverFirst)+len(v4Targets)+len(v6Targets))
	out = append(out, serverFirst...)
	if preferV6 {
		out = append(out, v6Targets...)
		out = append(out, v4Targets...)
	} else {
		out = append(out, v4Targets...)
		out = append(out, v6Targets...)
	}
	return out
}

func detectOutboundInterface(serverAddr string) (*net.Interface, error) {
	targets := buildProbeTargets(serverAddr)

	var lastErr error
	for _, p := range targets {
		conn, err := net.Dial(p.network, net.JoinHostPort(p.addr, "80"))
		if err != nil {
			lastErr = err
			log.Printf("[bypass] probe %s/%s failed: %v", p.network, p.addr, err)
			continue
		}
		localAddr := conn.LocalAddr()
		_ = conn.Close()
		udpAddr, ok := localAddr.(*net.UDPAddr)
		if !ok || udpAddr.IP == nil {
			continue
		}
		iface, err := findInterfaceByIP(udpAddr.IP)
		if err != nil {
			lastErr = err
			log.Printf("[bypass] probe %s/%s: no interface for %s: %v", p.network, p.addr, udpAddr.IP, err)
			continue
		}
		return iface, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no outbound interface detected")
	}
	log.Printf("[bypass] WARN: outbound interface detection failed for serverAddr=%q: %v", serverAddr, lastErr)
	return nil, lastErr
}

func parseIPFromAddr(addr string) net.IP {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func findInterfaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ifIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifIP = v.IP
			case *net.IPAddr:
				ifIP = v.IP
			}
			if ifIP != nil && ifIP.Equal(ip) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found for IP %s", ip.String())
}
