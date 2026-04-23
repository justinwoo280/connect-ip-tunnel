package udpsocket

import (
	"fmt"
	"log/slog"
	"net"
)

// Unwrapper is an interface for packet connections that wrap another connection.
// This allows us to access the underlying UDP connection for buffer configuration.
type Unwrapper interface {
	Underlying() net.PacketConn
}

// SetBuffers attempts to set UDP socket receive and send buffer sizes.
// Returns the actual buffer sizes achieved (which may differ from requested).
// Logs warnings on failure but does not return errors - degraded operation is acceptable.
//
// Parameters:
//   - pc: The packet connection to configure
//   - want: Desired buffer size in bytes (applied to both recv and send)
//
// Returns:
//   - gotRecv: Actual receive buffer size achieved
//   - gotSend: Actual send buffer size achieved
func SetBuffers(pc net.PacketConn, want int) (gotRecv, gotSend int) {
	if pc == nil {
		slog.Warn("udpsocket.SetBuffers: nil PacketConn")
		return 0, 0
	}

	// Unwrap if this is a wrapped connection (e.g., Salamander obfuscation)
	underlying := pc
	if unwrapper, ok := pc.(Unwrapper); ok {
		underlying = unwrapper.Underlying()
		slog.Debug("udpsocket.SetBuffers: unwrapped connection",
			"wrapper_type", fmt.Sprintf("%T", pc),
			"underlying_type", fmt.Sprintf("%T", underlying))
	}

	// Type assert to *net.UDPConn
	udpConn, ok := underlying.(*net.UDPConn)
	if !ok {
		slog.Warn("udpsocket.SetBuffers: not a UDP connection",
			"type", fmt.Sprintf("%T", underlying))
		return 0, 0
	}

	// Set receive buffer
	if err := udpConn.SetReadBuffer(want); err != nil {
		slog.Warn("udpsocket.SetBuffers: failed to set read buffer",
			"want", want,
			"error", err)
	}

	// Set send buffer
	if err := udpConn.SetWriteBuffer(want); err != nil {
		slog.Warn("udpsocket.SetBuffers: failed to set write buffer",
			"want", want,
			"error", err)
	}

	// Read back actual values using SyscallConn
	// This is platform-specific but works on Linux/Windows/macOS
	gotRecv = getActualRecvBuffer(udpConn, want)
	gotSend = getActualSendBuffer(udpConn, want)

	// 注意：Linux 上内核报告的值是请求值的 2x（含 sk_buff 元数据开销），
	// 因此即便完全成功，got 也会是 2*want。这里用 want 作为期望对比基线，
	// 但只把"未达期望一半"视为受系统 cap，避免 Linux 上误警告。
	const capWarnThreshold = 2 // got < want / capWarnThreshold 视为被 cap
	if gotRecv > 0 && gotRecv < want/capWarnThreshold {
		slog.Warn("udpsocket.SetBuffers: receive buffer capped by OS",
			"want", want,
			"got_recv", gotRecv,
			"hint", "Windows/macOS 默认上限较低；Linux 请调整 net.core.rmem_max")
	}
	if gotSend > 0 && gotSend < want/capWarnThreshold {
		slog.Warn("udpsocket.SetBuffers: send buffer capped by OS",
			"want", want,
			"got_send", gotSend,
			"hint", "Windows/macOS 默认上限较低；Linux 请调整 net.core.wmem_max")
	}

	slog.Info("udpsocket.SetBuffers: configured UDP socket buffers",
		"want", want,
		"got_recv", gotRecv,
		"got_send", gotSend)

	return gotRecv, gotSend
}
