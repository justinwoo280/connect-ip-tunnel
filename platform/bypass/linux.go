//go:build linux && !android

package bypass

import (
	"net"
	"syscall"
)

type linuxProvider struct{}

func NewProvider() Provider {
	return &linuxProvider{}
}

func (p *linuxProvider) Build(cfg Config) (Dialer, error) {
	return newPlatformDialer(cfg, makeBypassControl)
}

func makeBypassControl(iface *net.Interface) func(network, address string, c syscall.RawConn) error {
	name := iface.Name
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
