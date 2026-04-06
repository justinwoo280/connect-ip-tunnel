package bypass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
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
		// 无法识别物理出口时降级为标准拨号，避免主流程启动失败。
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

func detectOutboundInterface(serverAddr string) (*net.Interface, error) {
	probeTargets := []string{}
	if ip := parseIPFromAddr(serverAddr); ip != nil {
		probeTargets = append(probeTargets, ip.String())
	}
	probeTargets = append(probeTargets, "8.8.8.8", "1.1.1.1")

	var lastErr error
	for _, probe := range probeTargets {
		conn, err := net.Dial("udp", net.JoinHostPort(probe, "80"))
		if err != nil {
			lastErr = err
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
			continue
		}
		return iface, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no outbound interface detected")
	}
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
