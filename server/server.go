package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"connect-ip-tunnel/option"
	"connect-ip-tunnel/platform/tun"
	securityauth "connect-ip-tunnel/security/auth"
	securitytls "connect-ip-tunnel/security/tls"

	"github.com/quic-go/quic-go"
	qhttp3 "github.com/quic-go/quic-go/http3"
)

var ErrNotImplemented = errors.New("server: not implemented")

// Server 是 CONNECT-IP 代理服务器
type Server struct {
	cfg option.ServerConfig

	tunDevice       tun.Device
	tunConfigurator tun.Configurator
	tunIfName       string
	routingMgr      *RoutingManager
	ipPool          *IPPool // IP 地址池管理
	dispatcher      *PacketDispatcher // TUN 包分发器
	dispatchCancel  context.CancelFunc

	listener   *quic.Listener
	httpServer *qhttp3.Server
	authProv   *securityauth.Provider

	sessions   map[string]*Session // sessionID -> Session
	sessionsMu sync.RWMutex

	startOnce sync.Once
	closeOnce sync.Once
	started   bool
}

func New(cfg option.ServerConfig) (*Server, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		sessions: make(map[string]*Session),
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

		// 配置路由管理器
		clientPools := []string{}
		if s.cfg.IPv4Pool != "" {
			clientPools = append(clientPools, s.cfg.IPv4Pool)
		}
		if s.cfg.IPv6Pool != "" {
			clientPools = append(clientPools, s.cfg.IPv6Pool)
		}

		routingMgr, err := NewRoutingManager(ifName, s.cfg.TUN.IPv4CIDR, s.cfg.TUN.IPv6CIDR, clientPools)
		if err != nil {
			startErr = fmt.Errorf("server: create routing manager: %w", err)
			return
		}
		s.routingMgr = routingMgr

		// 创建 IP 地址池
		ipPool, err := NewIPPool(s.cfg.IPv4Pool, s.cfg.IPv6Pool)
		if err != nil {
			startErr = fmt.Errorf("server: create ip pool: %w", err)
			return
		}
		s.ipPool = ipPool
		log.Printf("[server] ip pool ready: ipv4=%s ipv6=%s", s.cfg.IPv4Pool, s.cfg.IPv6Pool)

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
		go func() {
			if err := s.dispatcher.Run(dispatchCtx); err != nil && dispatchCtx.Err() == nil {
				log.Printf("[server] dispatcher error: %v", err)
			}
		}()

		// 2. 构建 TLS 配置
		tlsServer, err := securitytls.NewServer(securitytls.ServerOptions{
			CertFile:           s.cfg.TLS.CertFile,
			KeyFile:            s.cfg.TLS.KeyFile,
			NextProtos:         []string{"h3"},
			EnablePQC:          s.cfg.TLS.EnablePQC,
			EnableSessionCache: s.cfg.TLS.EnableSessionCache,
			SessionCacheSize:   s.cfg.TLS.SessionCacheSize,
		})
		if err != nil {
			startErr = fmt.Errorf("server: init tls server: %w", err)
			return
		}

		// 3. 构建鉴权提供者
		if s.cfg.Auth.Method != "" && s.cfg.Auth.Method != "none" {
			authCfg := securityauth.Config{
				Method:      securityauth.AuthMethod(s.cfg.Auth.Method),
				BearerToken: s.cfg.Auth.BearerToken,
				Username:    s.cfg.Auth.Username,
				Password:    s.cfg.Auth.Password,
				HeaderName:  s.cfg.Auth.HeaderName,
				HeaderValue: s.cfg.Auth.HeaderValue,
			}
			if err := authCfg.Validate(); err != nil {
				startErr = fmt.Errorf("server: invalid auth config: %w", err)
				return
			}
			s.authProv = securityauth.NewProvider(authCfg)
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

		quicCfg := &quic.Config{
			EnableDatagrams: true,
			MaxIdleTimeout:  s.cfg.HTTP3.MaxIdleTimeout,
			KeepAlivePeriod: s.cfg.HTTP3.KeepAlivePeriod,
		}

		listener, err := quic.Listen(udpConn, tlsServer.TLSConfig(), quicCfg)
		if err != nil {
			startErr = fmt.Errorf("server: quic listen: %w", err)
			return
		}
		s.listener = listener

		// 5. 启动 HTTP/3 服务器
		s.httpServer = &qhttp3.Server{
			Handler: s,
		}

		go func() {
			if err := s.httpServer.ServeListener(listener); err != nil {
				log.Printf("[server] http3 serve error: %v", err)
			}
		}()

		s.started = true
		log.Printf("[server] started: listen=%s tun=%s", s.cfg.Listen, ifName)
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
		// 停止分发器
		if s.dispatchCancel != nil {
			s.dispatchCancel()
		}

		// 关闭所有会话
		s.sessionsMu.Lock()
		for id, sess := range s.sessions {
			if s.dispatcher != nil {
				s.dispatcher.UnregisterSession(id)
			}
			_ = sess.Close()
		}
		s.sessions = make(map[string]*Session)
		s.sessionsMu.Unlock()

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
