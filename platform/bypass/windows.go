//go:build windows

package bypass

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProvider struct{}

func NewProvider() Provider {
	return &windowsProvider{}
}

func (p *windowsProvider) Build(cfg Config) (Dialer, error) {
	return newPlatformDialer(cfg, makeBypassControl)
}

const (
	ipProtoIP     = 0  // IPPROTO_IP
	ipProtoIPv6   = 41 // IPPROTO_IPV6
	ipUnicastIF   = 31 // IP_UNICAST_IF
	ipv6UnicastIF = 31 // IPV6_UNICAST_IF
)

func makeBypassControl(iface *net.Interface) func(network, address string, c syscall.RawConn) error {
	ifIndex := uint32(iface.Index)
	var ifIndexNetOrder [4]byte
	binary.BigEndian.PutUint32(ifIndexNetOrder[:], ifIndex)

	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			handle := windows.Handle(fd)
			isIPv6 := len(network) > 0 && network[len(network)-1] == '6'
			if isIPv6 {
				bindErr = windows.Setsockopt(
					handle,
					ipProtoIPv6,
					ipv6UnicastIF,
					(*byte)(unsafe.Pointer(&ifIndex)),
					int32(unsafe.Sizeof(ifIndex)),
				)
			} else {
				bindErr = windows.Setsockopt(
					handle,
					ipProtoIP,
					ipUnicastIF,
					&ifIndexNetOrder[0],
					int32(len(ifIndexNetOrder)),
				)
			}
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
