package http3

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	bypass "connect-ip-tunnel/platform/bypass"
	securitytls "connect-ip-tunnel/security/tls"

	"github.com/quic-go/quic-go"
	qhttp3 "github.com/quic-go/quic-go/http3"
	"connect-ip-tunnel/congestion/bbr2"
	"connect-ip-tunnel/transport/obfs"
	congestion "github.com/quic-go/quic-go/congestion"
)

type ClientFactory interface {
	Dial(ctx context.Context, target Target) (*qhttp3.ClientConn, error)
	Close() error
}

type Factory struct {
	opts      Options
	tlsClient securitytls.ClientConfig
	bypass    bypass.Dialer

	mu        sync.Mutex
	transport *qhttp3.Transport
}

func NewFactory(opts Options, tlsClient securitytls.ClientConfig, bp bypass.Dialer) *Factory {
	return &Factory{
		opts:      opts,
		tlsClient: tlsClient,
		bypass:    bp,
	}
}

// Dial 建立到 target 的 QUIC 连接并返回 HTTP/3 ClientConn。
// 若配置了 bypass dialer，使用它建 UDP socket 以绕过 TUN；否则直接 DialAddr。
//
// ECH HRR 处理：若服务端拒绝 ECH 并返回 RetryConfigList，Dial 会在同一次调用内
// 使用新配置重试（最多由 ClientConfig.HandleHandshakeError 控制次数）。
// 超过重试上限或无法获取重试配置时，返回错误，不降级为明文 ClientHello。
func (f *Factory) Dial(ctx context.Context, target Target) (*qhttp3.ClientConn, error) {
	quicCfg := buildQUICConfig(f.opts)

	for {
		// 每次尝试都从 tlsClient 取最新配置（HandleHandshakeError 会原地更新）
		tlsCfg := f.tlsClient.TLSConfig().Clone()
		if target.ServerName != "" {
			tlsCfg.ServerName = target.ServerName
		}

		var quicConn *quic.Conn
		var dialErr error

		if f.bypass != nil {
			// 根据目标地址类型选择 udp4 或 udp6，确保创建的是单栈 socket。
			// Windows 上 "udp" 会产生双栈 IPv6 socket（本地地址为 [::]），
			// 此时 IP_UNICAST_IF（IPPROTO_IP）对该 socket 无效，bypass 绑定不生效；
			// 显式使用 udp4/udp6 可保证 setsockopt 作用于正确协议族的 socket。
			udpNetwork := udpNetworkForAddr(target.Addr)
			pc, err := f.bypass.ListenPacket(ctx, udpNetwork, "")
			if err != nil {
				return nil, fmt.Errorf("http3: bypass listen packet: %w", err)
			}
			udpAddr, err := net.ResolveUDPAddr(udpNetwork, target.Addr)
			if err != nil {
				_ = pc.Close()
				return nil, fmt.Errorf("http3: resolve target addr %q: %w", target.Addr, err)
			}
			// 如果配置了 Salamander 混淆，包装 PacketConn
			var dialConn net.PacketConn = pc
			if f.opts.Obfs.Type == obfs.ObfsTypeSalamander && f.opts.Obfs.Password != "" {
				dialConn = obfs.NewSalamanderConn(pc, f.opts.Obfs.Password)
			}
			quicConn, dialErr = quic.Dial(ctx, dialConn, udpAddr, tlsCfg, quicCfg)
			if dialErr != nil {
				_ = pc.Close()
			}
		} else if f.opts.Obfs.Type == obfs.ObfsTypeSalamander && f.opts.Obfs.Password != "" {
			// Salamander 混淆：需要自己创建 PacketConn
			udpNetwork := udpNetworkForAddr(target.Addr)
			udpAddr, resolveErr := net.ResolveUDPAddr(udpNetwork, target.Addr)
			if resolveErr != nil {
				return nil, fmt.Errorf("http3: resolve target addr %q: %w", target.Addr, resolveErr)
			}
			rawConn, listenErr := net.ListenPacket(udpNetwork, "")
			if listenErr != nil {
				return nil, fmt.Errorf("http3: listen packet for salamander: %w", listenErr)
			}
			salamanderConn := obfs.NewSalamanderConn(rawConn, f.opts.Obfs.Password)
			quicConn, dialErr = quic.Dial(ctx, salamanderConn, udpAddr, tlsCfg, quicCfg)
			if dialErr != nil {
				_ = rawConn.Close()
			}
		} else {
			quicConn, dialErr = quic.DialAddr(ctx, target.Addr, tlsCfg, quicCfg)
		}

		if dialErr != nil {
			retry, outErr := f.tlsClient.HandleHandshakeError(dialErr)
			if retry {
				// 服务端返回了新的 ECH RetryConfigList，使用新配置重试
				continue
			}
			// 非可重试错误（含超过重试上限的 ErrECHRejected）
			return nil, outErr
		}

		// 握手成功
		// 根据配置注入拥塞控制算法
		if f.opts.Congestion.Algorithm == "bbr2" {
			cfg := f.opts.Congestion.BBRv2
			params := bbr2.DefaultParams()
			if cfg.LossThreshold > 0 {
				params.LossThreshold = cfg.LossThreshold
			}
			if cfg.Beta > 0 {
				params.Beta = cfg.Beta
			}
			if cfg.StartupFullBwRounds > 0 {
				params.StartupFullBwRounds = cfg.StartupFullBwRounds
			}
			if cfg.ProbeRTTPeriod.Duration > 0 {
				params.ProbeRttPeriod = cfg.ProbeRTTPeriod.Duration
			}
			if cfg.ProbeRTTDuration.Duration > 0 {
				params.ProbeRttDuration = cfg.ProbeRTTDuration.Duration
			}
			sender := bbr2.NewBBR2SenderWithParams(
				bbr2.DefaultClock{},
				congestion.InitialPacketSize,
				0,
				cfg.Aggressive,
				params,
			)
			quicConn.SetCongestionControl(sender)
		}

		f.mu.Lock()
		if f.transport == nil {
			f.transport = &qhttp3.Transport{
				EnableDatagrams: f.opts.EnableDatagrams,
			}
		}
		t := f.transport
		f.mu.Unlock()

		return t.NewClientConn(quicConn), nil
	}
}

// udpNetworkForAddr 根据目标地址判断应使用 "udp4" 还是 "udp6"。
// 若解析失败或无法判断，保守返回 "udp4"（绝大多数服务端为 IPv4）。
func udpNetworkForAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 没有端口，直接当 host 解析
		host = addr
	}
	// 去掉 IPv6 括号 [::1] → ::1
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		// 纯 IPv6 地址
		return "udp6"
	}
	return "udp4"
}

func (f *Factory) Close() error {
	f.mu.Lock()
	t := f.transport
	f.transport = nil
	f.mu.Unlock()
	if t != nil {
		return t.Close()
	}
	return nil
}

