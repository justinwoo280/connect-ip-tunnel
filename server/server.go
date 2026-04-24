package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"sync"
	"time"

	"connect-ip-tunnel/common/bufferpool"
	"connect-ip-tunnel/common/safe"
	"connect-ip-tunnel/common/udpsocket"
	"connect-ip-tunnel/observability"
	"connect-ip-tunnel/option"
	"connect-ip-tunnel/platform/tun"
	securitytls "connect-ip-tunnel/security/tls"

	"github.com/quic-go/quic-go"
	"connect-ip-tunnel/transport/obfs"
	qhttp3 "github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

var ErrNotImplemented = errors.New("server: not implemented")

// Server 是 CONNECT-IP 代理服务器
type Server struct {
	cfg option.ServerConfig

	tunDevice       tun.Device
	tunConfigurator tun.Configurator
	tunIfName       string
	tunGatewayIPv4  netip.Addr // TUN 网关 IPv4 地址
	tunGatewayIPv6  netip.Addr // TUN 网关 IPv6 地址
	routingMgr      *RoutingManager
	ipPool          *IPPool               // IP 地址池管理
	dispatcher      *PacketDispatcher     // TUN 包分发器
	dispatchCancel  context.CancelFunc
	uriTemplate     *uritemplate.Template // 缓存的 URI template
	metrics         *observability.Metrics
	routesPolicy    *RoutesPolicy         // Per-client 路由策略

	listener    *quic.Listener
	httpServer  *qhttp3.Server
	adminServer *http.Server // 管理/metrics HTTP 服务

	sessions   map[string]*Session // sessionID -> Session
	sessionsMu sync.RWMutex

	transport *quic.Transport // Shared QUIC transport

	startOnce sync.Once
	closeOnce sync.Once
	started   bool
}

func New(cfg option.ServerConfig) (*Server, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// connect-ip-go 的 ParseRequest 要求完整 URI Template（含 scheme + host），
	// 且 host 必须与客户端请求的 :authority（即客户端配置的 connect_ip.authority）完全一致。
	// 配置示例：uri_template = "https://vpn.example.com/.well-known/masque/ip"
	tmpl, err := uritemplate.New(cfg.URITemplate)
	if err != nil {
		return nil, fmt.Errorf("server: invalid uri template %q: %w", cfg.URITemplate, err)
	}
	log.Printf("[server] uri template: %s", cfg.URITemplate)

	// 初始化路由策略
	var routesPolicy *RoutesPolicy
	if len(cfg.ClientRoutesPolicy) > 0 {
		routesPolicy, err = NewRoutesPolicy(cfg.ClientRoutesPolicy, nil)
		if err != nil {
			return nil, fmt.Errorf("server: invalid client routes policy: %w", err)
		}
		log.Printf("[server] per-client routes policy enabled for %d clients", len(cfg.ClientRoutesPolicy))
	}

	return &Server{
		cfg:          cfg,
		sessions:     make(map[string]*Session),
		uriTemplate:  tmpl,
		routesPolicy: routesPolicy,
	}, nil
}

// RegisterSession 注册会话到分发器，返回 inbound channel。
func (s *Server) RegisterSession(session *Session) chan []byte {
	return s.dispatcher.RegisterSession(session.id, session.assignedIPv4, session.assignedIPv6)
}

// UnregisterSession 从分发器取消注册会话。
func (s *Server) UnregisterSession(sessionID string) {
	s.dispatcher.UnregisterSession(sessionID)
}

func (s *Server) Start() error {
	var startErr error
	s.startOnce.Do(func() {
		log.Printf("[server] starting on %s", s.cfg.Listen)

		// 1. 创建 TUN 设备（服务端需要路由客户端流量）
		tunFactory := tun.NewFactory()
		tunDevice, err := tunFactory.Create(tun.CreateConfig{
			Name: s.cfg.TUN.Name,
			MTU:  s.cfg.TUN.MTU,
		})
		if err != nil {
			startErr = fmt.Errorf("server: create tun device: %w", err)
			return
		}
		s.tunDevice = tunDevice

		ifName, err := tunDevice.Name()
		if err != nil {
			startErr = fmt.Errorf("server: get tun interface name: %w", err)
			return
		}
		s.tunIfName = ifName

		// 配置包缓冲区大小（MTU + 80 字节预留用于 IP/UDP/QUIC 头部）
		bufferSize := s.cfg.TUN.MTU + 80
		bufferpool.SetPacketBufferSize(bufferSize)
		log.Printf("[server] packet buffer size set to %d (MTU=%d)", bufferSize, s.cfg.TUN.MTU)

		// 创建 IP 地址池
		ipPool, err := NewIPPool(s.cfg.IPv4Pool, s.cfg.IPv6Pool)
		if err != nil {
			startErr = fmt.Errorf("server: create ip pool: %w", err)
			return
		}
		s.ipPool = ipPool
		log.Printf("[server] ip pool ready: ipv4=%s ipv6=%s", s.cfg.IPv4Pool, s.cfg.IPv6Pool)

		// 派生 TUN 网关 IP：若配置未指定，自动从 IP 池取网关地址（池内第一个可用 IP）
		// 例如 pool=10.233.0.0/16 → tun IP=10.233.0.1/16
		tunIPv4 := s.cfg.TUN.IPv4CIDR
		tunIPv6 := s.cfg.TUN.IPv6CIDR
		if tunIPv4 == "" && s.cfg.IPv4Pool != "" {
			if gw, err := ipPool.GatewayIPv4(); err == nil {
				tunIPv4 = gw
				log.Printf("[server] tun ipv4 (auto): %s", tunIPv4)
			}
		}
		if tunIPv6 == "" && s.cfg.IPv6Pool != "" {
			if gw, err := ipPool.GatewayIPv6(); err == nil {
				tunIPv6 = gw
				log.Printf("[server] tun ipv6 (auto): %s", tunIPv6)
			}
		}

		// 配置路由管理器
		clientPools := []string{}
		if s.cfg.IPv4Pool != "" {
			clientPools = append(clientPools, s.cfg.IPv4Pool)
		}
		if s.cfg.IPv6Pool != "" {
			clientPools = append(clientPools, s.cfg.IPv6Pool)
		}

		routingMgr, err := NewRoutingManager(ifName, tunIPv4, tunIPv6, clientPools)
		if err != nil {
			startErr = fmt.Errorf("server: create routing manager: %w", err)
			return
		}
		s.routingMgr = routingMgr
		
		// 保存 TUN 网关地址用于心跳
		if tunIPv4 != "" {
			if prefix, err := netip.ParsePrefix(tunIPv4); err == nil {
				s.tunGatewayIPv4 = prefix.Addr()
			}
		}
		if tunIPv6 != "" {
			if prefix, err := netip.ParsePrefix(tunIPv6); err == nil {
				s.tunGatewayIPv6 = prefix.Addr()
			}
		}

		tunCfg := tun.NewConfigurator()
		s.tunConfigurator = tunCfg

		// 使用路由管理器配置网络（不使用 tunConfigurator 的默认路由配置）
		if err := routingMgr.Setup(s.cfg.EnableNAT, s.cfg.NATInterface); err != nil {
			startErr = fmt.Errorf("server: setup routing: %w", err)
			return
		}
		log.Printf("[server] tun ready: if=%s mtu=%d", ifName, tunDevice.MTU())

		// 启动 TUN 包分发器
		s.dispatcher = NewPacketDispatcher(tunDevice)
		dispatchCtx, dispatchCancel := context.WithCancel(context.Background())
		s.dispatchCancel = dispatchCancel
		safe.Go("server.dispatcher", func() {
			if err := s.dispatcher.Run(dispatchCtx); err != nil && dispatchCtx.Err() == nil {
				log.Printf("[server] dispatcher error: %v", err)
			}
		})

		// 2. 初始化 metrics（在 TLS 之前，以便 CRL fetcher 可以使用）
		if s.cfg.AdminListen != "" {
			m := observability.InitMetrics("connect_ip_tunnel")
			s.metrics = m
		}

		// 3. 构建 TLS 配置（含 mTLS + CRL）
		tlsServer, err := securitytls.NewServer(securitytls.ServerOptions{
			CertFile:           s.cfg.TLS.CertFile,
			KeyFile:            s.cfg.TLS.KeyFile,
			NextProtos:         []string{"h3"},
			EnablePQC:          s.cfg.TLS.EnablePQC,
			EnableMTLS:         s.cfg.TLS.EnableMTLS,
			ClientCAFile:       s.cfg.TLS.ClientCAFile,
			CRLUrl:             s.cfg.TLS.CRLUrl,
			CRLInterval:        s.cfg.TLS.CRLInterval.Duration,
			RequireCRL:         s.cfg.TLS.RequireCRL,
			EnableSessionCache: s.cfg.TLS.EnableSessionCache,
			SessionCacheSize:   s.cfg.TLS.SessionCacheSize,
			KeyLogPath:         s.cfg.TLS.KeyLogPath,
			Metrics:            s.metrics, // 传递 metrics 实例
		})
		if err != nil {
			startErr = fmt.Errorf("server: init tls server: %w", err)
			return
		}

		if s.cfg.TLS.EnableMTLS {
			log.Printf("[server] mTLS enabled, client certificates required")
		}

		// 4. 启动 QUIC 监听器
		udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
		if err != nil {
			startErr = fmt.Errorf("server: resolve listen addr: %w", err)
			return
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			startErr = fmt.Errorf("server: listen udp: %w", err)
			return
		}

		// 设置 UDP socket 缓冲区（性能优化）
		recvBuf := s.cfg.HTTP3.UDPRecvBuffer
		sendBuf := s.cfg.HTTP3.UDPSendBuffer
		if recvBuf == 0 {
			recvBuf = 16 * 1024 * 1024 // 默认 16MB
		}
		if sendBuf == 0 {
			sendBuf = 16 * 1024 * 1024 // 默认 16MB
		}
		
		// 注意：必须在 obfs 包装之前设置缓冲区，因为 SetBuffers 需要访问底层 UDP socket
		gotRecv, gotSend := udpsocket.SetBuffers(udpConn, recvBuf)
		log.Printf("[server] UDP socket buffers: recv=%d send=%d (requested: recv=%d send=%d)",
			gotRecv, gotSend, recvBuf, sendBuf)

		quicCfg := &quic.Config{
			EnableDatagrams: true,
			MaxIdleTimeout:  s.cfg.HTTP3.MaxIdleTimeout.Duration,
			KeepAlivePeriod: s.cfg.HTTP3.KeepAlivePeriod.Duration,
		}

		// 如果配置了 Salamander 混淆，包装 UDP socket
		// 注意：必须在创建 quic.Transport 之前包装
		var baseConn net.PacketConn = udpConn
		if s.cfg.HTTP3.Obfs.Type == obfs.ObfsTypeSalamander && s.cfg.HTTP3.Obfs.Password != "" {
			baseConn = obfs.NewSalamanderConn(udpConn, s.cfg.HTTP3.Obfs.Password)
			log.Printf("[server] Salamander obfs enabled")
		}

		// 创建 quic.Transport（共享 UDP socket，支持 GSO/GRO）
		transport := &quic.Transport{
			Conn: baseConn,
		}
		s.transport = transport
		defer func() {
			if startErr != nil {
				_ = transport.Close()
			}
		}()

		// 使用 transport.Listen 替代 quic.Listen
		listener, err := transport.Listen(tlsServer.TLSConfig(), quicCfg)
		if err != nil {
			startErr = fmt.Errorf("server: quic listen: %w", err)
			return
		}
		s.listener = listener

		// 5. 启动 HTTP/3 服务器
		// EnableDatagrams 必须与 QUIC 层的 EnableDatagrams 一致，
		// Connect-IP 使用 HTTP/3 Datagram（RFC 9297）转发 IP 包。
		s.httpServer = &qhttp3.Server{
			Handler:         s,
			EnableDatagrams: true,
		}

		safe.Go("server.http3", func() {
			if err := s.httpServer.ServeListener(listener); err != nil {
				log.Printf("[server] http3 serve error: %v", err)
			}
		})

		// 6. 启动 Prometheus metrics / 管理 HTTP 端点
		if s.cfg.AdminListen != "" {
			mux := http.NewServeMux()
			
			// /healthz 始终匿名访问
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})

			// /metrics 根据配置决定是否需要鉴权
			if s.cfg.UnauthenticatedMetrics {
				mux.Handle("/metrics", s.metrics.Handler())
			} else if s.cfg.AdminToken != "" {
				mux.Handle("/metrics", requireToken(s.cfg.AdminToken)(s.metrics.Handler()))
			} else {
				// 默认需要 token，但未配置 token（loopback 地址允许）
				mux.Handle("/metrics", s.metrics.Handler())
			}

			// /api/* 和 /debug/pprof/* 必须鉴权（如果配置了 token）
			if s.cfg.AdminToken != "" {
				// 创建受保护的子 mux
				apiMux := http.NewServeMux()
				s.RegisterAPIRoutes(apiMux)
				mux.Handle("/api/", requireToken(s.cfg.AdminToken)(apiMux))

				// 挂载 pprof 端点（如果启用）
				if s.cfg.EnablePprof {
					pprofMux := http.NewServeMux()
					pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
					pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
					pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
					pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
					pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
					mux.Handle("/debug/pprof/", requireToken(s.cfg.AdminToken)(pprofMux))
					log.Printf("[server] pprof endpoints enabled at /debug/pprof/* (auth required)")
				}
			} else {
				s.RegisterAPIRoutes(mux)
				
				// 挂载 pprof 端点（如果启用且无 token 配置）
				if s.cfg.EnablePprof {
					mux.HandleFunc("/debug/pprof/", pprof.Index)
					mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
					mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
					mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
					mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
					log.Printf("[server] pprof endpoints enabled at /debug/pprof/* (no auth)")
				}
			}

			s.adminServer = &http.Server{
				Addr:    s.cfg.AdminListen,
				Handler: safe.HTTP("server.admin", mux),
			}
			safe.Go("server.admin", func() {
				log.Printf("[server] admin/metrics listening on %s", s.cfg.AdminListen)
				if err := s.adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("[server] admin server error: %v", err)
				}
			})
		}

		s.started = true
		log.Printf("[server] started: listen=%s tun=%s", s.cfg.Listen, ifName)
		
		// 7. 启动 idle session reaper（如果配置了）
		if s.cfg.SessionIdleTimeout.Duration > 0 {
			safe.Go("server.idle-reaper", func() {
				s.runIdleReaper(context.Background())
			})
			log.Printf("[server] idle session reaper enabled: timeout=%v", s.cfg.SessionIdleTimeout.Duration)
		}
	})

	if startErr != nil {
		_ = s.Close()
		return startErr
	}
	if !s.started {
		return ErrNotImplemented
	}
	return nil
}

func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		// 关闭顺序说明：
		// 1. 先关闭 HTTP/3 server 和 QUIC listener，让新连接无法进入，
		//    并触发已有 handler goroutine 的 context 取消，
		//    由 handler 的 defer 自行完成 UnregisterSession / ReleaseIP / session.Close。
		// 2. 停止 dispatcher，确保 TUN 读循环退出。
		// 3. 关闭 quic.Transport（释放 UDP socket）。
		// 4. 最后清理系统资源（路由、TUN）。
		//
		// 不在 Close 中重复调用 UnregisterSession/session.Close，
		// 避免与 handler defer 并发双重清理。

		if s.adminServer != nil {
			if err := s.adminServer.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if s.httpServer != nil {
			if err := s.httpServer.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if s.listener != nil {
			if err := s.listener.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}

		// 关闭 quic.Transport（释放 UDP socket）
		if s.transport != nil {
			if err := s.transport.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}

		// 停止分发器
		if s.dispatchCancel != nil {
			s.dispatchCancel()
		}

		// 清理路由配置
		if s.routingMgr != nil {
			if err := s.routingMgr.Teardown(s.cfg.EnableNAT, s.cfg.NATInterface); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if s.tunDevice != nil {
			if err := s.tunDevice.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if s.started {
			log.Printf("[server] stopped")
		}
	})
	return closeErr
}


// runIdleReaper 定期扫描并清理 idle 的 session
func (s *Server) runIdleReaper(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reapIdleSessions()
		}
	}
}

// reapIdleSessions 清理超过 idle timeout 的 session
func (s *Server) reapIdleSessions() {
	if s.cfg.SessionIdleTimeout.Duration == 0 {
		return
	}
	
	now := time.Now()
	timeout := s.cfg.SessionIdleTimeout.Duration
	
	s.sessionsMu.RLock()
	var toReap []string
	for id, sess := range s.sessions {
		lastActive := sess.GetLastActive()
		if now.Sub(lastActive) > timeout {
			toReap = append(toReap, id)
		}
	}
	s.sessionsMu.RUnlock()
	
	if len(toReap) == 0 {
		return
	}

	log.Printf("[server] reaping %d idle sessions (timeout=%v)", len(toReap), timeout)
	observability.Global.AddIdleSessionsReaped(len(toReap))

	for _, id := range toReap {
		s.sessionsMu.RLock()
		sess, ok := s.sessions[id]
		s.sessionsMu.RUnlock()

		if ok {
			log.Printf("[server] reaping idle session %s (last active: %v ago)",
				id, now.Sub(sess.GetLastActive()))
			_ = sess.Close()
		}
	}
}


// tunGatewayV4 返回 TUN 网关 IPv4 地址
func (s *Server) tunGatewayV4() netip.Addr {
	return s.tunGatewayIPv4
}

// tunGatewayV6 返回 TUN 网关 IPv6 地址
func (s *Server) tunGatewayV6() netip.Addr {
	return s.tunGatewayIPv6
}
