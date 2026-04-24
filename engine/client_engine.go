package engine

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connect-ip-tunnel/common/bufferpool"
	"connect-ip-tunnel/common/safe"
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

	// lastNetCfg 记录最近一次成功配置 TUN 时使用的 NetworkConfig。
	// trackAddressUpdates 用它作为差量更新的 prev 参数，并在每次更新成功后写入。
	lastNetCfg atomic.Pointer[tun.NetworkConfig]
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

		// 配置包缓冲区大小（MTU + 80 字节预留用于 IP/UDP/QUIC 头部）
		bufferSize := e.cfg.TUN.MTU + 80
		bufferpool.SetPacketBufferSize(bufferSize)
		log.Printf("[engine] packet buffer size set to %d (MTU=%d)", bufferSize, e.cfg.TUN.MTU)

		log.Printf("[engine] tun created: if=%s mtu=%d", ifName, tunDevice.MTU())

		// 2. 构建 ECH 管理器
		if e.cfg.TLS.EnableECH && e.cfg.TLS.ECHDomain != "" && e.cfg.TLS.ECHDOHServer != "" {
			e.echMgr = securitytls.NewECHManager(e.cfg.TLS.ECHDomain, e.cfg.TLS.ECHDOHServer)
		}

		// 3. 构建 TLS
		tlsProvider := securitytls.NewProvider()
		tlsOpts, err := e.buildTLSOptions()
		if err != nil {
			startErr = fmt.Errorf("engine: build tls options: %w", err)
			return
		}
		tlsClient, err := tlsProvider.NewClient(context.Background(), tlsOpts)
		if err != nil {
			startErr = fmt.Errorf("engine: init tls client: %w", err)
			return
		}
		e.tlsClient = tlsClient

		// 4. 构建 Bypass
		if e.cfg.Bypass.Enable {
			bpProvider := bypass.NewProvider()
			bp, err := bpProvider.Build(bypass.Config{
				ServerAddr: e.cfg.Bypass.ServerAddr,
				Strict:     e.cfg.Bypass.Strict,
			})
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
			// UDP socket buffer（性能调优，主要在 Linux 上有效；Windows/macOS 会被系统 cap）
			UDPRecvBuffer:       e.cfg.HTTP3.UDPRecvBuffer,
			UDPSendBuffer:       e.cfg.HTTP3.UDPSendBuffer,
			EnableGSO:           e.cfg.HTTP3.IsGSOEnabled(),
			PreferAddressFamily: e.cfg.TLS.PreferAddressFamily,
			HappyEyeballsDelay:  e.cfg.TLS.HappyEyeballsDelay.Duration,
		}
		e.h3Factory = h3transport.NewFactory(h3Opts, e.tlsClient, e.bpDialer)

		// 6. 启动连接循环
		ctx, cancel := context.WithCancel(context.Background())
		e.cancelLoop = cancel
		e.loopDone = make(chan struct{})
		e.status.Store("disconnected")
		safe.Go("engine.runLoop", func() {
			e.runLoop(ctx)
		})

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

		if !e.cfg.ConnectIP.IsReconnectEnabled() {
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
		// 启动后台 ADDRESS_ASSIGN 跟踪（只在动态分配模式启用，静态模式无意义）。
		// 该 goroutine 与 session 寿命绑定：session 关闭时 LocalPrefixes 返回 error 自然退出。
		safe.Go("engine.addr-track.single", func() {
			e.trackAddressUpdates(ctx, session)
		})
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

	// 检查是否启用独立重连
	if e.cfg.ConnectIP.IsPerSessionReconnectEnabled() {
		return e.connectAndRunMultiIndependent(ctx, n, dialFn)
	}
	
	// 旧的 all-or-nothing 模式（作为回退）
	return e.connectAndRunMultiLegacy(ctx, n, dialFn)
}

// connectAndRunMultiIndependent 使用新的独立重连架构
func (e *Engine) connectAndRunMultiIndependent(ctx context.Context, n int, dialFn func(ctx context.Context) (*connectip.Session, error)) error {
	supervisor := NewMultiSessionSupervisor(n, dialFn, e.cfg.ConnectIP)
	supervisor.Start(ctx)
	defer func() { _ = supervisor.Close() }()

	log.Printf("[engine] waiting for first healthy session...")
	
	// 等待至少一个 session 变为 healthy
	waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer waitCancel()
	
	if err := supervisor.WaitForFirstHealthy(waitCtx); err != nil {
		return fmt.Errorf("engine: no healthy session available: %w", err)
	}

	log.Printf("[engine] first session ready, configuring TUN...")

	// ADDRESS_ASSIGN 只需等第一个健康的 session 分配即可
	var assignedPrefixes []netip.Prefix
	var serverGateway netip.Addr
	
	if e.cfg.ConnectIP.WaitForAddressAssign {
		// 找到第一个健康的 worker
		var firstSession *connectip.Session
		for _, idx := range supervisor.GetHealthyWorkers() {
			if sess := supervisor.workers[idx].Get(); sess != nil {
				firstSession = sess
				break
			}
		}
		
		if firstSession == nil {
			return fmt.Errorf("engine: no healthy session for address assign")
		}
		
		if err := e.waitAndConfigureTUN(ctx, firstSession); err != nil {
			return fmt.Errorf("engine: address assign: %w", err)
		}

		// 用刚刚 Setup 时记录的 lastNetCfg 提取 prefixes 计算心跳目标网关，
		// 避免再次调用 LocalPrefixes（那会消费下一次 ADDRESS_ASSIGN 通知，
		// 与下面 trackAddressUpdates 抢同一条订阅流）。
		if cur := e.lastNetCfg.Load(); cur != nil {
			if cur.IPv4CIDR != "" {
				if pfx, perr := netip.ParsePrefix(cur.IPv4CIDR); perr == nil {
					assignedPrefixes = append(assignedPrefixes, pfx)
					if gw := pfx.Masked().Addr().Next(); gw.IsValid() {
						serverGateway = gw
					}
				}
			}
			if cur.IPv6CIDR != "" {
				if pfx, perr := netip.ParsePrefix(cur.IPv6CIDR); perr == nil {
					assignedPrefixes = append(assignedPrefixes, pfx)
				}
			}
		}

		// 启动后台 ADDRESS_ASSIGN 跟踪（多 session 模式下绑定到首个 healthy session：
		// 该 session 与服务端的 capsule 流是一对一的；其它 worker 的 LocalPrefixes
		// 会单独发出，这里只关心已用于 TUN 配置的那一条）。
		safe.Go("engine.addr-track.multi", func() {
			e.trackAddressUpdates(ctx, firstSession)
		})
	} else {
		if err := e.configureTUNStatic(); err != nil {
			return fmt.Errorf("engine: configure tun static: %w", err)
		}
	}

	e.status.Store("connected")
	now := time.Now()
	e.connectedAt.Store(now)

	// 启动心跳管理器（如果配置了且有分配的 IP）
	var heartbeatMgr *connectip.HeartbeatManager
	if e.cfg.ConnectIP.AppKeepalivePeriod.Duration > 0 && len(assignedPrefixes) > 0 && serverGateway.IsValid() {
		// 创建心跳管理器
		sendPacket := func(pkt []byte) error {
			return supervisor.WritePacket(pkt)
		}
		
		heartbeatMgr = connectip.NewHeartbeatManager(
			assignedPrefixes,
			serverGateway,
			sendPacket,
			e.cfg.ConnectIP.AppKeepalivePeriod.Duration,
			e.cfg.ConnectIP.AppKeepaliveTimeout.Duration,
			e.cfg.ConnectIP.UnhealthyThreshold,
		)
		
		// 启动心跳
		hbCtx, hbCancel := context.WithCancel(ctx)
		defer hbCancel()
		
		safe.Go("engine.heartbeat", func() {
			if err := heartbeatMgr.Start(hbCtx); err != nil {
				log.Printf("[engine] heartbeat manager stopped: %v", err)
			}
		})
		
		log.Printf("[engine] heartbeat enabled: period=%v, timeout=%v, threshold=%d",
			e.cfg.ConnectIP.AppKeepalivePeriod.Duration,
			e.cfg.ConnectIP.AppKeepaliveTimeout.Duration,
			e.cfg.ConnectIP.UnhealthyThreshold)
	}

	// 启动多路 pump（传递心跳管理器用于 pong 处理）
	return e.runMultiSessionPumpIndependent(ctx, supervisor, heartbeatMgr, assignedPrefixes, serverGateway)
}

// connectAndRunMultiLegacy 旧的 all-or-nothing 模式
func (e *Engine) connectAndRunMultiLegacy(ctx context.Context, n int, dialFn func(ctx context.Context) (*connectip.Session, error)) error {
	log.Printf("[engine] using legacy all-or-nothing mode")
	
	// 并发建立所有 session
	type dialResult struct {
		idx  int
		sess *connectip.Session
		err  error
	}
	
	results := make(chan dialResult, n)
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for i := 0; i < n; i++ {
		go func(idx int) {
			sess, err := dialFn(dialCtx)
			results <- dialResult{idx: idx, sess: sess, err: err}
		}(i)
	}

	sessions := make([]*connectip.Session, n)
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			// 有一个失败则取消其他，并关闭已建立的
			cancel()
			for j := 0; j < n; j++ {
				if j == i {
					continue
				}
				remaining := <-results
				if remaining.sess != nil {
					_ = remaining.sess.Close()
				}
			}
			return fmt.Errorf("session[%d] dial failed: %w", r.idx, r.err)
		}
		sessions[r.idx] = r.sess
		log.Printf("[engine] multi-session[%d/%d] established", r.idx+1, n)
	}

	// 创建一个简单的 pool wrapper
	supervisor := &MultiSessionSupervisor{
		workers:     make([]*SessionWorker, n),
		distributor: newFlowDistributor(n),
		n:           n,
		closeCh:     make(chan struct{}),
	}
	
	// 为每个 session 创建一个假的 worker（不会重连）
	for i, sess := range sessions {
		worker := &SessionWorker{
			idx: i,
			cfg: e.cfg.ConnectIP,
		}
		worker.sess.Store(sess)
		worker.state.Store(int32(stateHealthy))
		supervisor.workers[i] = worker
	}

	defer func() { _ = supervisor.Close() }()

	log.Printf("[engine] %d sessions established to %s", n, e.cfg.ConnectIP.Addr)

	// ADDRESS_ASSIGN
	if e.cfg.ConnectIP.WaitForAddressAssign {
		if err := e.waitAndConfigureTUN(ctx, sessions[0]); err != nil {
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

	// 启动多路 pump（旧模式：任一失败全部退出）
	return e.runMultiSessionPump(ctx, supervisor)
}

// runMultiSessionPumpIndependent 新的独立重连模式的 pump
func (e *Engine) runMultiSessionPumpIndependent(ctx context.Context, supervisor *MultiSessionSupervisor, heartbeatMgr *connectip.HeartbeatManager, assignedPrefixes []netip.Prefix, serverGateway netip.Addr) error {
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	bufSize := e.cfg.TUN.MTU + 4
	if bufSize <= 4 {
		bufSize = 65535
	}

	// 上行：TUN → supervisor（自动选择健康的 session）
	wg.Add(1)
	safe.Go("engine.pump.tun", func() {
		defer wg.Done()

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
				select {
				case <-pumpCtx.Done():
					return
				default:
				}
				
				n, err := br.Read(bufs, sizes, 0)
				if err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					log.Printf("[engine] tun read error: %v", err)
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] <= 0 {
						continue
					}
					if err := supervisor.WritePacket(bufs[i][:sizes[i]]); err != nil {
						// 写入失败不退出，继续尝试
						log.Printf("[engine] session write error: %v", err)
					}
				}
			}
		} else {
			// 降级：单包模式
			buf := make([]byte, bufSize)
			for {
				select {
				case <-pumpCtx.Done():
					return
				default:
				}
				
				n, err := e.tunDevice.ReadPacket(buf)
				if err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					log.Printf("[engine] tun read error: %v", err)
					return
				}
				if n <= 0 {
					continue
				}
				if err := supervisor.WritePacket(buf[:n]); err != nil {
					log.Printf("[engine] session write error: %v", err)
				}
			}
		}
	})

	// 下行：各 worker → TUN，每个 worker 独立 goroutine
	// worker 重连时会自动恢复，不需要退出整个 pump
	for i := 0; i < supervisor.WorkerCount(); i++ {
		idx := i
		wg.Add(1)
		safe.Go("engine.pump.sess", func() {
			defer wg.Done()
			buf := make([]byte, bufSize)
			for {
				select {
				case <-pumpCtx.Done():
					return
				default:
				}
				
				n, err := supervisor.ReadFrom(idx, buf)
				if err != nil {
					// 读取失败可能是 worker 正在重连，等待一下继续
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if n <= 0 {
					continue
				}
				
				// 检查是否为心跳 pong
				if heartbeatMgr != nil && len(assignedPrefixes) > 0 && serverGateway.IsValid() {
					if connectip.IsHeartbeatPacket(buf[:n], assignedPrefixes, serverGateway, false) {
						// 解析并处理 pong
						typ, seq, _, err := connectip.ParseHeartbeatPayload(buf[:n])
						if err == nil && typ == connectip.HeartbeatTypePong {
							heartbeatMgr.OnPong(seq)
						}
						continue // 不写入 TUN
					}
				}
				
				if err := e.tunDevice.WritePacket(buf[:n]); err != nil {
					if pumpCtx.Err() != nil {
						return
					}
					log.Printf("[engine] tun write error: %v", err)
				}
			}
		})
	}

	log.Printf("[engine] multi-session pump started (%d workers, independent reconnect)", supervisor.WorkerCount())

	// 等待上下文取消
	<-ctx.Done()
	cancel()
	wg.Wait()
	return nil
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
	safe.Go("engine.pump.tun", func() {
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
	})

	// 下行：各 session → TUN，每个 session 独立 goroutine
	// 热路径优化：同上行，去掉每次迭代的 select/ctx 轮询。
	for i := 0; i < pool.WorkerCount(); i++ {
		idx := i
		wg.Add(1)
		safe.Go("engine.pump.sess", func() {
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
		})
	}

	log.Printf("[engine] multi-session pump started (%d sessions)", pool.WorkerCount())

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
	// 记录基线配置，供后续 trackAddressUpdates 做 prev/next 差量更新。
	cfgCopy := netCfg
	e.lastNetCfg.Store(&cfgCopy)

	log.Printf("[engine] tun configured with server-assigned addresses")
	return nil
}

// trackAddressUpdates 是后台 goroutine：持续监听服务端二次（及更多次）
// ADDRESS_ASSIGN，收到新 prefix 时调用 tunConfigurator.UpdateAddress 做
// 差量更新（不删除已工作的地址族）。
//
// 触发条件 / 退出条件：
//   - ctx 取消（engine 关闭 / runLoop 重连）→ return；
//   - session.LocalPrefixes 返回 error（连接断开）→ return，由上层重连逻辑兜底；
//   - 收到的 prefixes 与当前已配置完全一致（IPv4 + IPv6 CIDR 都没变）→ 跳过、继续等。
//
// 由 connectAndRunSingle / connectAndRunMultiIndependent 在首次 ADDRESS_ASSIGN
// 完成后调用。spec §4.6 / §W-F6 要求此能力。
func (e *Engine) trackAddressUpdates(ctx context.Context, session *connectip.Session) {
	for {
		if ctx.Err() != nil {
			return
		}
		// LocalPrefixes 是阻塞调用，每次返回最新的 ADDRESS_ASSIGN 内容。
		prefixes, err := session.LocalPrefixes(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("[engine] address-update tracker stopped: %v", err)
			}
			return
		}
		if len(prefixes) == 0 {
			continue
		}

		prev := e.lastNetCfg.Load()
		next := tun.NetworkConfig{
			MTU:   e.cfg.TUN.MTU,
			DNSv4: e.cfg.TUN.DNSv4,
			DNSv6: e.cfg.TUN.DNSv6,
		}
		if prev != nil {
			next.IfName = prev.IfName
		} else {
			next.IfName = e.tunIfName
		}
		for _, p := range prefixes {
			if p.Addr().Is4() {
				next.IPv4CIDR = p.String()
			} else {
				next.IPv6CIDR = p.String()
			}
		}

		// 与当前完全一致 → 不动。这能避免 ADDRESS_ASSIGN 的 keepalive 重复触发系统命令。
		if prev != nil && prev.Equal(next) {
			continue
		}

		var prevCfg tun.NetworkConfig
		if prev != nil {
			prevCfg = *prev
		} else {
			prevCfg = tun.NetworkConfig{IfName: next.IfName}
		}

		log.Printf("[engine] ADDRESS_ASSIGN update: ipv4 %q→%q, ipv6 %q→%q",
			prevCfg.IPv4CIDR, next.IPv4CIDR, prevCfg.IPv6CIDR, next.IPv6CIDR)

		if err := e.tunConfigurator.UpdateAddress(prevCfg, next); err != nil {
			log.Printf("[engine] tun UpdateAddress failed: %v", err)
			// 失败不退出，等待下一次更新（也许下次配置可应用），并保留旧 lastNetCfg。
			continue
		}

		// 同步 admin handler 看到的 assignedV4/v6
		if next.IPv4CIDR != "" {
			e.assignedV4.Store(next.IPv4CIDR)
		}
		if next.IPv6CIDR != "" {
			e.assignedV6.Store(next.IPv6CIDR)
		}
		nextCopy := next
		e.lastNetCfg.Store(&nextCopy)
	}
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
func (e *Engine) buildTLSOptions() (securitytls.ClientOptions, error) {
	opts := securitytls.ClientOptions{
		ServerName:    e.cfg.TLS.ServerName,
		NextProtos:    []string{"h3"},
		EnableECH:     e.cfg.TLS.EnableECH,
		ECHConfigList: e.cfg.TLS.ECHConfigList,
		ECHManager:    e.echMgr,
		EnablePQC:     e.cfg.TLS.EnablePQC,
		UseSystemCAs:  e.cfg.TLS.UseSystemCAs,
		UseMozillaCA:  e.cfg.TLS.UseMozillaCA,
		// mTLS 客户端证书配置
		ClientCertFile:     e.cfg.TLS.ClientCertFile,
		ClientKeyFile:      e.cfg.TLS.ClientKeyFile,
		EnableSessionCache: e.cfg.TLS.EnableSessionCache,
		SessionCacheSize:   e.cfg.TLS.SessionCacheSize,
		KeyLogPath:         e.cfg.TLS.KeyLogPath,
	}

	// ServerCAFile：客户端用，指向信任的服务端根 CA PEM。
	// 优先级最高 —— 一旦设置，覆盖 use_system_cas / use_mozilla_ca。
	// 这是企业内网 mTLS + 自签 CA 部署的标准做法。
	if e.cfg.TLS.ServerCAFile != "" {
		pemData, err := os.ReadFile(e.cfg.TLS.ServerCAFile)
		if err != nil {
			return opts, fmt.Errorf("read server_ca_file %q: %w", e.cfg.TLS.ServerCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return opts, fmt.Errorf("server_ca_file %q contains no valid PEM-encoded certificates", e.cfg.TLS.ServerCAFile)
		}
		opts.RootCAs = pool
	}

	// 启用 KeyLog 时打印高亮警告（密钥日志会让 TLS 流量可被解密，仅供调试）
	if e.cfg.TLS.KeyLogPath != "" {
		slog.Warn("⚠️  TLS KeyLog ENABLED: master secrets will be written to file. "+
			"Anyone with access to this file can decrypt all TLS traffic. "+
			"USE ONLY FOR DEBUGGING; never enable in production.",
			"path", e.cfg.TLS.KeyLogPath)
	}

	return opts, nil
}

// startAdminServer 启动客户端管理 HTTP 接口，暴露统计信息给 GUI。
func (e *Engine) startAdminServer(addr string) error {
	mux := http.NewServeMux()

	// GET /healthz — 始终匿名访问
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 创建 API 路由处理函数
	apiHandler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/stats":
			e.handleStats(w, r)
		case "/api/v1/version":
			e.handleVersion(w, r)
		default:
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	}

	// 根据配置决定是否需要鉴权
	if e.cfg.AdminToken != "" {
		// 需要 token 鉴权
		mux.Handle("/api/", requireTokenClient(e.cfg.AdminToken)(http.HandlerFunc(apiHandler)))

		// 挂载 pprof 端点（如果启用）
		if e.cfg.EnablePprof {
			pprofMux := http.NewServeMux()
			pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
			pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			mux.Handle("/debug/pprof/", requireTokenClient(e.cfg.AdminToken)(pprofMux))
			log.Printf("[engine] pprof endpoints enabled at /debug/pprof/* (auth required)")
		}
	} else {
		// 不需要鉴权（loopback 地址）
		mux.Handle("/api/", http.HandlerFunc(apiHandler))

		// 挂载 pprof 端点（如果启用且无 token 配置）
		if e.cfg.EnablePprof {
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			log.Printf("[engine] pprof endpoints enabled at /debug/pprof/* (no auth)")
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listen %s: %w", addr, err)
	}

	e.adminServer = &http.Server{Handler: safe.HTTP("engine.admin", mux)}
	safe.Go("engine.admin", func() {
		log.Printf("[engine] admin server listening on %s", ln.Addr().String())
		if err := e.adminServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[engine] admin server error: %v", err)
		}
	})
	return nil
}

// handleStats 处理 GET /api/v1/stats
func (e *Engine) handleStats(w http.ResponseWriter, r *http.Request) {
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
}

// handleVersion 处理 GET /api/v1/version
func (e *Engine) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"mode": "client"})
}

// requireTokenClient 返回客户端 admin API 的 token 验证 middleware
func requireTokenClient(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			const prefix = "Bearer "
			if !strings.HasPrefix(auth, prefix) {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			providedToken := auth[len(prefix):]
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
