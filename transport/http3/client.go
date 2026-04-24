package http3

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	bypass "connect-ip-tunnel/platform/bypass"
	securitytls "connect-ip-tunnel/security/tls"

	"github.com/quic-go/quic-go"
	qhttp3 "github.com/quic-go/quic-go/http3"
	"connect-ip-tunnel/congestion/bbr2"
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
	pool      *transportPool

	mu        sync.Mutex
	transport *qhttp3.Transport
}

func NewFactory(opts Options, tlsClient securitytls.ClientConfig, bp bypass.Dialer) *Factory {
	return &Factory{
		opts:      opts,
		tlsClient: tlsClient,
		bypass:    bp,
		pool:      newTransportPool(opts),
	}
}

// Dial 建立到 target 的 QUIC 连接并返回 HTTP/3 ClientConn。
// 若配置了 bypass dialer，使用它建 UDP socket 以绕过 TUN；否则直接 DialAddr。
//
// 域名解析与连接策略（Happy Eyeballs / RFC 8305 简化版）：
//   - 当 target.Addr 是字面量 IP 时，直接用对应地址族 dial。
//   - 当 target.Addr 是域名时，根据 opts.PreferAddressFamily 解析：
//       * "v4" / "v6"：仅尝试对应地址族；
//       * "auto"（默认）：解析所有 A/AAAA，IPv6 优先发起 dial，
//         若 HappyEyeballsDelay 内未成功则并行尝试 IPv4，先成功者赢。
//   - 任一地址族成功后立即取消另一族的尝试。
//
// ECH HRR 处理：若服务端拒绝 ECH 并返回 RetryConfigList，Dial 会在同一次调用内
// 使用新配置重试（最多由 ClientConfig.HandleHandshakeError 控制次数）。
// 超过重试上限或无法获取重试配置时，返回错误，不降级为明文 ClientHello。
func (f *Factory) Dial(ctx context.Context, tgt Target) (*qhttp3.ClientConn, error) {
	quicCfg := buildQUICConfig(f.opts)

	// 1. 解析目标，得到候选 target 列表（按偏好排序）。
	prefer := f.opts.PreferAddressFamily
	if prefer == "" {
		prefer = "auto"
	}
	targets, err := resolveTargets(ctx, tgt.Addr, prefer)
	if err != nil {
		return nil, fmt.Errorf("http3: resolve %q: %w", tgt.Addr, err)
	}

	// 2. ECH retry loop（每次重试都使用最新 tlsClient 配置）。
	for {
		tlsCfg := f.tlsClient.TLSConfig().Clone()
		if tgt.ServerName != "" {
			tlsCfg.ServerName = tgt.ServerName
		}

		// dialOne 在指定 target 上发起 QUIC 握手。
		//
		// 0-RTT-first 策略（spec H6 / Phase 5）：
		//   - 当 opts.Allow0RTT == true 时，优先调 tr.DialEarly()。quic-go 内部会
		//     根据 tlsCfg.ClientSessionCache 中是否有可复用的 ticket 决定走 0-RTT 还是
		//     回退到 1-RTT 全握手。两条路径都返回 *quic.Conn，调用方无需做手工 fallback。
		//   - Used0RTT 真值表示 early data 被接受，可在握手未完成时就发出应用层数据；
		//     若服务端拒绝 0-RTT（重放保护 / ticket 过期），quic-go 自动降级到 1-RTT。
		//   - opts.Allow0RTT == false → 走传统 tr.Dial，行为与之前完全一致。
		dialOne := func(dctx context.Context, t target) (interface{}, error) {
			tr, gerr := f.pool.Get(dctx, t.network, "", f.bypass)
			if gerr != nil {
				return nil, fmt.Errorf("http3: get transport (%s): %w", t.network, gerr)
			}
			if f.opts.Allow0RTT {
				conn, derr := tr.DialEarly(dctx, t.addr, tlsCfg, quicCfg)
				if derr != nil {
					return nil, derr
				}
				if conn.ConnectionState().Used0RTT {
					log.Printf("[http3] 0-RTT accepted on %s/%s", t.network, t.addr)
				} else {
					log.Printf("[http3] 0-RTT not used (no ticket / rejected) on %s/%s, fallback 1-RTT ok", t.network, t.addr)
				}
				return conn, nil
			}
			conn, derr := tr.Dial(dctx, t.addr, tlsCfg, quicCfg)
			if derr != nil {
				return nil, derr
			}
			return conn, nil
		}

		var quicConn *quic.Conn
		var dialErr error
		if len(targets) == 1 {
			// 单 target 快路径：直接 dial，避免 happy eyeballs 调度开销。
			c, err := dialOne(ctx, targets[0])
			if err != nil {
				dialErr = err
			} else {
				quicConn = c.(*quic.Conn)
				log.Printf("[http3] connected via %s to %s", targets[0].network, targets[0].addr)
			}
		} else {
			delay := f.opts.HappyEyeballsDelay
			if delay <= 0 {
				delay = 50 * time.Millisecond
			}
			c, err := happyEyeballsDial(ctx, targets, delay, dialOne)
			if err != nil {
				dialErr = err
			} else {
				quicConn = c.(*quic.Conn)
				if ra := quicConn.RemoteAddr(); ra != nil {
					log.Printf("[http3] connected via happy-eyeballs to %s", ra.String())
				}
			}
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
		// 根据配置注入拥塞控制算法。
		// 注意：必须在握手完成后立刻调用，且每条 quic.Conn 只调一次；
		// 多次调用或在已发包之后调用会让 BBRv2 的 BandwidthSampler 看到
		// "属于旧算法发出"的 ACK，导致带宽估算异常。
		ApplyCongestionControl(quicConn, f.opts.Congestion)

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
// ApplyCongestionControl 在握手完成的 *quic.Conn 上注入应用层选定的拥塞算法。
//
// 客户端：在 client.go Dial() 拿到 quicConn 后立即调用。
// 服务端：在 qhttp3.Server.ConnContext 钩子里立即调用（每条新连接一次）。
//
// 设计取舍：
//   - 接受 option.CongestionConfig 而非把字段拆开传，避免新增字段时调用方都要改；
//   - bbr2 包不直接依赖 quic-go 的 *Conn 类型（避免循环 / 加重依赖图），
//     故注入 helper 放在 http3 包（已经依赖 quic-go + bbr2）。
//   - cfg.Algorithm == "" / "cubic" 走 quic-go 内置 cubic（不调用 SetCongestionControl）；
//     未来加新算法只需在此 switch 加分支。
func ApplyCongestionControl(conn *quic.Conn, cfg interface {
	GetAlgorithm() string
}) {
	// fast path：interface 适配在最下面提供，避免暴露 option 包到 http3 包外。
	algo := cfg.GetAlgorithm()
	switch algo {
	case "bbr2":
		applyBBR2(conn, cfg)
	default:
		// "" / "cubic" / 未识别值 → 走 quic-go 内置 cubic，不调用 SetCongestionControl。
	}
}

// applyBBR2 是 BBRv2 注入的实际实现。它通过 bbr2ConfigGetter 接口拿子参数，
// 这样 http3 包不需要 import option 包。
func applyBBR2(conn *quic.Conn, cfg interface{ GetAlgorithm() string }) {
	getter, ok := cfg.(bbr2ConfigGetter)
	if !ok {
		// 调用方传了不实现 BBRv2 子参数 getter 的对象，退化为默认参数。
		sender := bbr2.NewBBR2SenderWithParams(
			bbr2.DefaultClock{}, congestion.InitialPacketSize, 0, false, bbr2.DefaultParams(),
		)
		conn.SetCongestionControl(sender)
		return
	}
	params := bbr2.DefaultParams()
	if v := getter.GetBBR2LossThreshold(); v > 0 {
		params.LossThreshold = v
	}
	if v := getter.GetBBR2Beta(); v > 0 {
		params.Beta = v
	}
	if v := getter.GetBBR2StartupFullBwRounds(); v > 0 {
		params.StartupFullBwRounds = v
	}
	if v := getter.GetBBR2ProbeRTTPeriod(); v > 0 {
		params.ProbeRttPeriod = v
	}
	if v := getter.GetBBR2ProbeRTTDuration(); v > 0 {
		params.ProbeRttDuration = v
	}
	sender := bbr2.NewBBR2SenderWithParams(
		bbr2.DefaultClock{},
		congestion.InitialPacketSize,
		0,
		getter.GetBBR2Aggressive(),
		params,
	)
	conn.SetCongestionControl(sender)
}

// bbr2ConfigGetter 是 ApplyCongestionControl 期望 BBRv2 配置对象实现的接口。
// option.CongestionConfig 通过附带方法实现该接口（见 option/config.go）。
type bbr2ConfigGetter interface {
	GetAlgorithm() string
	GetBBR2LossThreshold() float64
	GetBBR2Beta() float64
	GetBBR2StartupFullBwRounds() int
	GetBBR2ProbeRTTPeriod() time.Duration
	GetBBR2ProbeRTTDuration() time.Duration
	GetBBR2Aggressive() bool
}

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
	
	var firstErr error
	if t != nil {
		if err := t.Close(); err != nil {
			firstErr = err
		}
	}
	
	// Close the transport pool
	if f.pool != nil {
		if err := f.pool.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	
	return firstErr
}

