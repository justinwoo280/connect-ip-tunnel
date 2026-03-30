package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"connect-ip-tunnel/option"
	bypass "connect-ip-tunnel/platform/bypass"
	"connect-ip-tunnel/platform/tun"
	"connect-ip-tunnel/runner"
	securitytls "connect-ip-tunnel/security/tls"
	h3transport "connect-ip-tunnel/transport/http3"
	"connect-ip-tunnel/tunnel/connectip"
)

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

		// 5. 构建 HTTP/3 工厂
		h3Opts := h3transport.Options{
			EnableDatagrams:                e.cfg.HTTP3.EnableDatagrams,
			MaxIdleTimeout:                 e.cfg.HTTP3.MaxIdleTimeout,
			KeepAlivePeriod:                e.cfg.HTTP3.KeepAlivePeriod,
			Allow0RTT:                      e.cfg.HTTP3.Allow0RTT,
			DisablePathMTUDiscovery:        e.cfg.HTTP3.DisablePathMTUProbe,
			InitialStreamReceiveWindow:     uint64(e.cfg.HTTP3.InitialStreamWindow),
			MaxStreamReceiveWindow:         uint64(e.cfg.HTTP3.MaxStreamWindow),
			InitialConnectionReceiveWindow: uint64(e.cfg.HTTP3.InitialConnWindow),
			MaxConnectionReceiveWindow:     uint64(e.cfg.HTTP3.MaxConnWindow),
		}
		tlsProvider2 := securitytls.NewProvider()
		e.h3Factory = h3transport.NewFactory(h3Opts, tlsProvider2, e.buildTLSOptions(), e.bpDialer)

		// 6. 启动连接循环
		ctx, cancel := context.WithCancel(context.Background())
		e.cancelLoop = cancel
		e.loopDone = make(chan struct{})
		go e.runLoop(ctx)

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
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := e.connectAndRun(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}

		log.Printf("[engine] session ended: %v", err)

		if !e.cfg.ConnectIP.EnableReconnect {
			log.Printf("[engine] reconnect disabled, stopping")
			return
		}

		// 指数退避 + jitter
		jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
		wait := backoff + jitter
		if wait > e.cfg.ConnectIP.MaxReconnectDelay {
			wait = e.cfg.ConnectIP.MaxReconnectDelay
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
func (e *Engine) connectAndRun(ctx context.Context) error {
	// 1. 建立 CONNECT-IP 会话
	cipClient := connectip.NewClient(e.h3Factory, e.tunDevice)
	target := h3transport.Target{
		Addr:       e.cfg.ConnectIP.Addr,
		ServerName: e.cfg.TLS.ServerName,
		Authority:  e.cfg.ConnectIP.Authority,
	}

	// 注：鉴权已由 TLS 层的 mTLS 完成，无需在 HTTP 层注入凭证

	session, err := cipClient.Open(ctx, target, connectip.Options{
		URI:       e.cfg.ConnectIP.URI,
		Authority: e.cfg.ConnectIP.Authority,
	})
	if err != nil {
		return fmt.Errorf("engine: open connectip session: %w", err)
	}
	defer func() { _ = session.Close() }()

	log.Printf("[engine] connect-ip session established to %s", e.cfg.ConnectIP.Addr)

	// 2. 等待 ADDRESS_ASSIGN 或使用静态配置
	if e.cfg.ConnectIP.WaitForAddressAssign {
		if err := e.waitAndConfigureTUN(ctx, session); err != nil {
			return fmt.Errorf("engine: address assign: %w", err)
		}
	} else {
		// 使用配置文件中的静态 IP
		if err := e.configureTUNStatic(); err != nil {
			return fmt.Errorf("engine: configure tun static: %w", err)
		}
	}

	// 3. 启动数据面 pump
	pump := &runner.PacketPump{
		Dev:        e.tunDevice,
		Tunnel:     session,
		BufferSize: e.cfg.TUN.MTU + 4,
	}

	log.Printf("[engine] packet pump started")
	if err := pump.Run(ctx); err != nil {
		if ctx.Err() != nil {
			return nil // 正常关闭
		}
		return fmt.Errorf("engine: packet pump: %w", err)
	}
	return nil
}

// waitAndConfigureTUN 等待服务端的 ADDRESS_ASSIGN capsule，用分配的 IP 配置 TUN。
func (e *Engine) waitAndConfigureTUN(ctx context.Context, session *connectip.Session) error {
	log.Printf("[engine] waiting for ADDRESS_ASSIGN from server (timeout=%v)", e.cfg.ConnectIP.AddressAssignTimeout)

	assignCtx, cancel := context.WithTimeout(ctx, e.cfg.ConnectIP.AddressAssignTimeout)
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
			log.Printf("[engine] assigned ipv4: %s", p)
		} else {
			netCfg.IPv6CIDR = p.String()
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
