package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connect-ip-tunnel/option"
	bypass "connect-ip-tunnel/platform/bypass"
	"connect-ip-tunnel/platform/tun"
	"connect-ip-tunnel/runner"
	securitytls "connect-ip-tunnel/security/tls"
	h3transport "connect-ip-tunnel/transport/http3"
	"connect-ip-tunnel/tunnel/connectip"
)

// 编译时验证 MultiSessionPool 相关类型已注册
var _ = (*MultiSessionPool)(nil)

var ErrNotImplemented = errors.New("engine: not implemented")

// Engine 负责组装平台层、传输层与数据面 runner（客户端模式）。
// 支持 ADDRESS_ASSIGN（等待服务端分配 IP 后配置 TUN）和自动重连。
type Engine struct {
	cfg option.ClientConfig

	tunDevice       tun.Device
	tunConfigurator tun.Configurator
	tunIfName       string

	h3Factory *h3transport.Factory
	tlsClient securitytls.ClientConfig
	bpDialer  bypass.Dialer
	echMgr    *securitytls.ECHManager

	cancelLoop context.CancelFunc
	loopDone   chan struct{}

	startOnce sync.Once
	closeOnce sync.Once
	started   bool

	// admin HTTP server（GUI 统计接口）
	adminServer *http.Server

	// 统计（原子操作，pump goroutine 写，admin handler 读）
	pump        atomic.Pointer[runner.PacketPump]
	status      atomic.Value // string: "disconnected" / "connecting" / "connected"
	assignedV4  atomic.Value // string: 分配的 IPv4 CIDR，例如 "10.0.0.2/24"
	assignedV6  atomic.Value // string: 分配的 IPv6 CIDR
	connectedAt atomic.Value // time.Time: 连接建立时间
}

func New(cfg option.ClientConfig) (*Engine, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg}, nil
}

func (e *Engine) Start() error {
	var startErr error
	e.startOnce.Do(func() {
		log.Printf("[engine] starting with tun=%s mtu=%d", e.cfg.TUN.Name, e.cfg.TUN.MTU)

		// 1. 创建 TUN 设备（仅创建，不配置 IP）
		tunFactory := tun.NewFactory()
		tunDevice, err := tunFactory.Create(tun.CreateConfig{
			Name:           e.cfg.TUN.Name,
			MTU:            e.cfg.TUN.MTU,
			FileDescriptor: e.cfg.TUN.FileDescriptor,
		})
		if err != nil {
			startErr = fmt.Errorf("engine: create tun device: %w", err)
			return
		}
		e.tunDevice = tunDevice

		ifName, err := tunDevice.Name()
		if err != nil {
			startErr = fmt.Errorf("engine: get tun interface name: %w", err)
			return
		}
		e.tunIfName = ifName
		e.tunConfigurator = tun.NewConfigurator()

		log.Printf("[engine] tun created: if=%s mtu=%d", ifName, tunDevice.MTU())

		// 2. 构建 ECH 管理器
		if e.cfg.TLS.EnableECH && e.cfg.TLS.ECHDomain != "" && e.cfg.TLS.ECHDOHServer != "" {
			e.echMgr = securitytls.NewECHManager(e.cfg.TLS.ECHDomain, e.cfg.TLS.ECHDOHServer)
		}

		// 3. 构建 TLS
		tlsProvider := securitytls.NewProvider()
		tlsClient, err := tlsProvider.NewClient(context.Background(), e.buildTLSOptions())
		if err != nil {
			startErr = fmt.Errorf("engine: init tls client: %w", err)
			return
		}
		e.tlsClient = tlsClient

		// 4. 构建 Bypass
		if e.cfg.Bypass.Enable {
			bpProvider := bypass.NewProvider()
			bp, err := bpProvider.Build(bypass.Config{ServerAddr: e.cfg.Bypass.ServerAddr})
			if err != nil {
				startErr = fmt.Errorf("engine: init bypass dialer: %w", err)
				return
			}
			e.bpDialer = bp
			if e.echMgr != nil {
				if stdDialer, ok := bp.(interface{ NetDialer() *net.Dialer }); ok {
					e.echMgr.SetBypassDialer(stdDialer.NetDialer())
				}
			}
		}

		// 5. 构建 HTTP/3 工厂（复用已构建的 tlsClient，避免重复加载证书）
		h3Opts := h3transport.Options{
			EnableDatagrams:                e.cfg.HTTP3.EnableDatagrams,
			Obfs:                           e.cfg.HTTP3.Obfs,
			Congestion:                     e.cfg.HTTP3.Congestion,
			MaxIdleTimeout:                 e.cfg.HTTP3.MaxIdleTimeout.Duration,
			KeepAlivePeriod:                e.cfg.HTTP3.KeepAlivePeriod.Duration,
			Allow0RTT:                      e.cfg.HTTP3.Allow0RTT,
			DisablePathMTUDiscovery:        e.cfg.HTTP3.DisablePathMTUProbe,
			InitialStreamReceiveWindow:     uint64(e.cfg.HTTP3.InitialStreamWindow),
			MaxStreamReceiveWindow:         uint64(e.cfg.HTTP3.MaxStreamWindow),
			InitialConnectionReceiveWindow: uint64(e.cfg.HTTP3.InitialConnWindow),
			MaxConnectionReceiveWindow:     uint64(e.cfg.HTTP3.MaxConnWindow),
		}
		e.h3Factory = h3transport.NewFactory(h3Opts, e.tlsClient, e.bpDialer)

		// 6. 启动连接循环
		ctx, cancel := context.WithCancel(context.Background())
		e.cancelLoop = cancel
		e.loopDone = make(chan struct{})
		e.status.Store("disconnected")
		go e.runLoop(ctx)

		// 7. 启动 admin HTTP server（若配置了监听地址）
		if e.cfg.AdminListen != "" {
			if err := e.startAdminServer(e.cfg.AdminListen); err != nil {
				startErr = fmt.Errorf("engine: start admin server: %w", err)
				return
			}
		}

		e.started = true
		log.Printf("[engine] started: tun=%s server=%s", ifName, e.cfg.ConnectIP.Addr)
	})

	if startErr != nil {
		_ = e.Close()
		return startErr
	}
	if !e.started {
		return ErrNotImplemented
	}
	return nil
}

// runLoop 管理连接生命周期：建连 → 等 ADDRESS_ASSIGN → 配置 TUN → 跑 pump → 断了重连。
func (e *Engine) runLoop(ctx context.Context) {
	defer close(e.loopDone)

	backoff := time.Second
	const (
		maxBackoff              = 30 * time.Second
		stableConnectionResetAt = 30 * time.Second
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		startedAt := time.Now()
		err := e.connectAndRun(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		if time.Since(startedAt) >= stableConnectionResetAt {
			backoff = time.Second
		}

		log.Printf("[engine] session ended: %v", err)

		if !e.cfg.ConnectIP.EnableReconnect {
			log.Printf("[engine] reconnect disabled, stopping")
			return
		}

		// 指数退避 + jitter
		jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
		wait := backoff + jitter
		if wait > e.cfg.ConnectIP.MaxReconnectDelay.Duration {
			wait = e.cfg.ConnectIP.MaxReconnectDelay.Duration
		}
		log.Printf("[engine] reconnecting in %v", wait)

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connectAndRun 执行一次完整的 连接 → ADDRESS_ASSIGN → TUN 配置 → 数据转发 流程。
// 当 cfg.ConnectIP.NumSessions > 1 时，并行建立多个 session 共享流量。
func (e *Engine) connectAndRun(ctx context.Context) error {
	n := e.cfg.ConnectIP.NumSessions
	if n <= 1 {
		return e.connectAndRunSingle(ctx)
	}
	return e.connectAndRunMulti(ctx, n)
}

// connectAndRunSingle 单 session 模式（开源版默认路径）。
func (e *Engine) connectAndRunSingle(ctx context.Context) error {
	cipClient := connectip.NewClient(e.h3Factory, e.tunDevice)
	target := h3transport.Target{
		Addr:       e.cfg.ConnectIP.Addr,
		ServerName: e.cfg.TLS.ServerName,
		Authority:  e.cfg.ConnectIP.Authority,
	}

	e.status.Store("connecting")
	session, err := cipClient.Open(ctx, target, connectip.Options{
		URI:       e.cfg.ConnectIP.URI,
		Authority: e.cfg.ConnectIP.Authority,
	})
	if err != nil {
		e.status.Store("disconnected")
		return fmt.Errorf("engine: open connectip session: %w", err)
	}
	defer func() {
		_ = session.Close()
		e.status.Store("disconnected")
		e.assignedV4.Store("")
		e.assignedV6.Store("")
	}()

	log.Printf("[engine] connect-ip session established to %s", e.cfg.ConnectIP.Addr)

	if e.cfg.ConnectIP.WaitForAddressAssign {
		if err := e.waitAndConfigureTUN(ctx, session); err != nil {
			return fmt.Errorf("engine: address assign: %w", err)
		}
	} else {
		if err := e.configureTUNStatic(); err != nil {
			return fmt.Errorf("engine: configure tun static: %w", err)
		}
	}

	e.status.Store("connected")
	now := time.Now()
	e.connectedAt.Store(now)

	pump := &runner.PacketPump{
		Dev:        e.tunDevice,
		Tunnel:     session,
		BufferSize: e.cfg.TUN.MTU + 4,
	}
	e.pump.Store(pump)
	defer e.pump.Store(nil)

	log.Printf("[engine] packet pump started (single session)")
	if err := pump.Run(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("engine: packet pump: %w", err)
	}
	return nil
}

// connectAndRunMulti 多 session 并行模式（企业版路径）。
func (e *Engine) connectAndRunMulti(ctx context.Context, n int) error {
	log.Printf("[engine] starting multi-session mode: n=%d target=%s", n, e.cfg.ConnectIP.Addr)

	dialFn := func(ctx context.Context) (*connectip.Session, error) {
		cipClient := connectip.NewClient(e.h3Factory, e.tunDevice)
		target := h3transport.Target{
			Addr:       e.cfg.ConnectIP.Addr,
			ServerName: e.cfg.TLS.ServerName,
			Authority:  e.cfg.ConnectIP.Authority,
		}
		return cipClient.Open(ctx, target, connectip.Options{
			URI:       e.cfg.ConnectIP.URI,
			Authority: e.cfg.ConnectIP.Authority,
		})
	}

	pool, err := buildSessionsParallel(ctx, n, dialFn)
	if err != nil {
		return fmt.Errorf("engine: build session pool: %w", err)
	}
	defer func() { _ = pool.Close() }()

	log.Printf("[engine] %d sessions established to %s", n, e.cfg.ConnectIP.Addr)

	// ADDRESS_ASSIGN 只需等第一个 session 分配即可（服务端对所有 session 分配同一客户端 IP）
	if e.cfg.ConnectIP.WaitForAddressAssign {
		if err := e.waitAndConfigureTUN(ctx, pool.sessions[0]); err != nil {
			return fmt.Errorf("engine: address assign: %w", err)
		}
	} else {
		if err := e.configureTUNStatic(); err != nil {
			return fmt.Errorf("engine: configure tun static: %w", err)
		}
	}

	// 启动多路 pump：上行按 flow hash 分发，下行各 session 独立 goroutine
	return e.runMultiSessionPump(ctx, pool)
}

// runMultiSessionPump 启动多 session 的双向数据转发。
func (e *Engine) runMultiSessionPump(ctx context.Context, pool *MultiSessionPool) error {
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	bufSize := e.cfg.TUN.MTU + 4
	if bufSize <= 4 {
		bufSize = 65535
	}

	// 上行：TUN → flow hash → 对应 session
	// 优先使用批量读接口（wireguard-go GRO 模式下 BatchSize > 1），避免 GRO 丢包。
	wg.Add(1)
	go func() {
		defer wg.Done()

		// 检测批量读能力
		type batchReader interface {
			BatchSize() int
			Read(bufs [][]byte, sizes []int, offset int) (int, error)
		}

		if br, ok := e.tunDevice.(batchReader); ok {
			batchSize := br.BatchSize()
			if batchSize <= 0 {
				batchSize = 1
			}
			bufs := make([][]byte, batchSize)
			for i := range bufs {
				bufs[i] = make([]byte, bufSize)
			}
			sizes := make([]int, batchSize)

			for {
				n, err := br.Read(bufs, sizes, 0)
				if err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					select {
					case errCh <- fmt.Errorf("multi pump tun read: %w", err):
					default:
					}
					cancel()
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] <= 0 {
						continue
					}
					if err := pool.WritePacket(bufs[i][:sizes[i]]); err != nil {
						if pumpCtx.Err() != nil {
							return
						}
						select {
						case errCh <- fmt.Errorf("multi pump session write: %w", err):
						default:
						}
						cancel()
						return
					}
				}
			}
		} else {
			// 降级：单包模式（非 Linux 平台）
			buf := make([]byte, bufSize)
			for {
				n, err := e.tunDevice.ReadPacket(buf)
				if err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					select {
					case errCh <- fmt.Errorf("multi pump tun read: %w", err):
					default:
					}
					cancel()
					return
				}
				if n <= 0 {
					continue
				}
				if err := pool.WritePacket(buf[:n]); err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					select {
					case errCh <- fmt.Errorf("multi pump session write: %w", err):
					default:
					}
					cancel()
					return
				}
			}
		}
	}()

	// 下行：各 session → TUN，每个 session 独立 goroutine
	// 热路径优化：同上行，去掉每次迭代的 select/ctx 轮询。
	for i := 0; i < pool.SessionCount(); i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, bufSize)
			for {
				n, err := pool.ReadFrom(idx, buf)
				if err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					select {
					case errCh <- fmt.Errorf("multi pump session[%d] read: %w", idx, err):
					default:
					}
					cancel()
					_ = pool.Close()
					return
				}
				if n <= 0 {
					continue
				}
				if err := e.tunDevice.WritePacket(buf[:n]); err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					select {
					case errCh <- fmt.Errorf("multi pump tun write: %w", err):
					default:
					}
					cancel()
					return
				}
			}
		}()
	}

	log.Printf("[engine] multi-session pump started (%d sessions)", pool.SessionCount())

	select {
	case <-ctx.Done():
		cancel()
		wg.Wait()
		return nil
	case err := <-errCh:
		wg.Wait()
		return err
	}
}

// waitAndConfigureTUN 等待服务端的 ADDRESS_ASSIGN capsule，用分配的 IP 配置 TUN。
func (e *Engine) waitAndConfigureTUN(ctx context.Context, session *connectip.Session) error {
	log.Printf("[engine] waiting for ADDRESS_ASSIGN from server (timeout=%v)", e.cfg.ConnectIP.AddressAssignTimeout.Duration)

	assignCtx, cancel := context.WithTimeout(ctx, e.cfg.ConnectIP.AddressAssignTimeout.Duration)
	defer cancel()

	prefixes, err := session.LocalPrefixes(assignCtx)
	if err != nil {
		return fmt.Errorf("wait for address assign: %w", err)
	}

	if len(prefixes) == 0 {
		return fmt.Errorf("server assigned no IP prefixes")
	}

	// 用分配到的 prefix 配置 TUN
	netCfg := tun.NetworkConfig{
		IfName: e.tunIfName,
		MTU:    e.cfg.TUN.MTU,
		DNSv4:  e.cfg.TUN.DNSv4,
		DNSv6:  e.cfg.TUN.DNSv6,
	}

	for _, p := range prefixes {
		if p.Addr().Is4() {
			netCfg.IPv4CIDR = p.String()
			e.assignedV4.Store(p.String())
			log.Printf("[engine] assigned ipv4: %s", p)
		} else {
			netCfg.IPv6CIDR = p.String()
			e.assignedV6.Store(p.String())
			log.Printf("[engine] assigned ipv6: %s", p)
		}
	}

	if err := e.tunConfigurator.Setup(netCfg); err != nil {
		return fmt.Errorf("configure tun with assigned ip: %w", err)
	}

	log.Printf("[engine] tun configured with server-assigned addresses")
	return nil
}

// configureTUNStatic 使用配置文件中的静态 IP 配置 TUN。
func (e *Engine) configureTUNStatic() error {
	if err := e.tunConfigurator.Setup(tun.NetworkConfig{
		IfName:   e.tunIfName,
		IPv4CIDR: e.cfg.TUN.IPv4CIDR,
		IPv6CIDR: e.cfg.TUN.IPv6CIDR,
		DNSv4:    e.cfg.TUN.DNSv4,
		DNSv6:    e.cfg.TUN.DNSv6,
		MTU:      e.cfg.TUN.MTU,
	}); err != nil {
		return fmt.Errorf("engine: setup tun network: %w", err)
	}
	log.Printf("[engine] tun configured with static addresses: ipv4=%s ipv6=%s", e.cfg.TUN.IPv4CIDR, e.cfg.TUN.IPv6CIDR)
	return nil
}

// buildTLSOptions 构建 TLS 选项（复用于多处）。
func (e *Engine) buildTLSOptions() securitytls.ClientOptions {
	return securitytls.ClientOptions{
		ServerName:         e.cfg.TLS.ServerName,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: e.cfg.TLS.InsecureSkipVerify,
		EnableECH:          e.cfg.TLS.EnableECH,
		ECHConfigList:      e.cfg.TLS.ECHConfigList,
		ECHManager:         e.echMgr,
		EnablePQC:          e.cfg.TLS.EnablePQC,
		UseSystemCAs:       e.cfg.TLS.UseSystemCAs,
		UseMozillaCA:       e.cfg.TLS.UseMozillaCA,
		// mTLS 客户端证书配置
		ClientCertFile:     e.cfg.TLS.ClientCertFile,
		ClientKeyFile:      e.cfg.TLS.ClientKeyFile,
		EnableSessionCache: e.cfg.TLS.EnableSessionCache,
		SessionCacheSize:   e.cfg.TLS.SessionCacheSize,
		KeyLogPath:         e.cfg.TLS.KeyLogPath,
	}
}

// startAdminServer 启动客户端管理 HTTP 接口，暴露统计信息给 GUI。
func (e *Engine) startAdminServer(addr string) error {
	mux := http.NewServeMux()

	// GET /api/v1/stats — 全局统计
	mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		status, _ := e.status.Load().(string)
		v4, _ := e.assignedV4.Load().(string)
		v6, _ := e.assignedV6.Load().(string)

		var uptimeSec float64
		if ct, ok := e.connectedAt.Load().(time.Time); ok && !ct.IsZero() && status == "connected" {
			uptimeSec = time.Since(ct).Seconds()
		}

		var txBytes, rxBytes, txPkts, rxPkts, drops uint64
		if p := e.pump.Load(); p != nil {
			s := p.Stats()
			txBytes = s.TxBytes.Load()
			rxBytes = s.RxBytes.Load()
			txPkts = s.TxPackets.Load()
			rxPkts = s.RxPackets.Load()
			drops = s.Drops.Load()
		}

		resp := map[string]any{
			"status":         status,
			"assigned_ipv4":  v4,
			"assigned_ipv6":  v6,
			"uptime_seconds": uptimeSec,
			"tx_bytes":       txBytes,
			"rx_bytes":       rxBytes,
			"tx_packets":     txPkts,
			"rx_packets":     rxPkts,
			"drops":          drops,
			"server":         e.cfg.ConnectIP.Addr,
			"tun":            e.tunIfName,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// GET /api/v1/version
	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"mode": "client"})
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listen %s: %w", addr, err)
	}

	e.adminServer = &http.Server{Handler: mux}
	go func() {
		log.Printf("[engine] admin server listening on %s", ln.Addr().String())
		if err := e.adminServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[engine] admin server error: %v", err)
		}
	}()
	return nil
}

func (e *Engine) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		if e.cancelLoop != nil {
			e.cancelLoop()
			// 等待连接循环退出
			if e.loopDone != nil {
				<-e.loopDone
			}
		}
		if e.adminServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = e.adminServer.Shutdown(ctx)
		}
		if e.h3Factory != nil {
			if err := e.h3Factory.Close(); err != nil {
				closeErr = err
			}
		}
		if e.tunConfigurator != nil && e.tunIfName != "" {
			if err := e.tunConfigurator.Teardown(e.tunIfName); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if e.tunDevice != nil {
			if err := e.tunDevice.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if e.echMgr != nil {
			e.echMgr.Stop()
		}
		if e.tlsClient != nil {
			if err := e.tlsClient.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if e.started {
			log.Printf("[engine] stopped")
		}
	})
	if closeErr != nil {
		return closeErr
	}
	return nil
}
