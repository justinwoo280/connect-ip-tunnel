//go:build unix

package udpsocket

import (
	"net"
	"syscall"
)

func getActualRecvBuffer(conn *net.UDPConn, want int) int {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return want // fallback to requested value
	}

	var size int
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		size, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	})

	if err != nil || sockErr != nil {
		return want
	}

	return size
}

func getActualSendBuffer(conn *net.UDPConn, want int) int {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return want
	}

	var size int
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		size, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	})

	if err != nil || sockErr != nil {
		return want
	}

	return size
}
