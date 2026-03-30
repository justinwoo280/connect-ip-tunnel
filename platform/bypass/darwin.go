//go:build darwin

package bypass

import (
	"net"
	"syscall"
)

type darwinProvider struct{}

func NewProvider() Provider {
	return &darwinProvider{}
}

func (p *darwinProvider) Build(cfg Config) (Dialer, error) {
	return newPlatformDialer(cfg, makeBypassControl)
}

const (
	ipBoundIF   = 25  // IP_BOUND_IF
	ipv6BoundIF = 125 // IPV6_BOUND_IF
)

func makeBypassControl(iface *net.Interface) func(network, address string, c syscall.RawConn) error {
	ifIndex := iface.Index
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			isIPv6 := len(network) > 0 && network[len(network)-1] == '6'
			if isIPv6 {
				bindErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, ifIndex)
			} else {
				bindErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, ifIndex)
			}
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
