package option

import (
	"fmt"
	"time"
)

// ApplyDefaults 应用默认值
func (c *Config) ApplyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeClient
	}

	if c.Mode == ModeClient {
		c.Client.ApplyDefaults()
	} else {
		c.Server.ApplyDefaults()
	}
}

// Validate 验证配置有效性
func (c *Config) Validate() error {
	if c.Mode != ModeClient && c.Mode != ModeServer {
		return fmt.Errorf("invalid mode %q (must be client or server)", c.Mode)
	}

	if c.Mode == ModeClient {
		return c.Client.Validate()
	}
	return c.Server.Validate()
}

// QUIC 窗口参数默认值（面向 10 Gbps 场景设计）
//
// BDP（带宽时延积）= bandwidth × RTT，窗口必须 >= BDP 才能跑满链路：
//   10 Gbps × 10ms RTT → BDP = 12.5 MB → 初始窗口 16 MB，最大 128 MB
//   1  Gbps × 50ms RTT → BDP = 6.25 MB → 初始窗口 16 MB 同样足够
//
// Stream 窗口：CONNECT-IP 用单条 stream 传 capsule，窗口同样需要足够大。
// Connection 窗口 >= Stream 窗口，通常设为 Stream 的 4-8 倍。
const (
	defaultInitialStreamWindow = 16 * 1024 * 1024  // 16 MB
	defaultMaxStreamWindow     = 64 * 1024 * 1024  // 64 MB
	defaultInitialConnWindow   = 32 * 1024 * 1024  // 32 MB
	defaultMaxConnWindow       = 128 * 1024 * 1024 // 128 MB
)

// ClientConfig 方法
func (c *ClientConfig) ApplyDefaults() {
	if c.TUN.MTU <= 0 {
		c.TUN.MTU = 1400
	}
	if c.HTTP3.MaxIdleTimeout.Duration == 0 {
		c.HTTP3.MaxIdleTimeout = Duration{30 * time.Second}
	}
	if c.HTTP3.KeepAlivePeriod.Duration == 0 {
		c.HTTP3.KeepAlivePeriod = Duration{10 * time.Second}
	}
	if c.TLS.SessionCacheSize <= 0 {
		c.TLS.SessionCacheSize = 128
	}
	// ADDRESS_ASSIGN 默认启用
	if c.ConnectIP.AddressAssignTimeout.Duration == 0 {
		c.ConnectIP.AddressAssignTimeout = Duration{30 * time.Second}
	}
	// 重连默认启用
	if c.ConnectIP.MaxReconnectDelay.Duration == 0 {
		c.ConnectIP.MaxReconnectDelay = Duration{30 * time.Second}
	}
	// QUIC 流控窗口：未配置时使用面向高带宽的默认值
	if c.HTTP3.InitialStreamWindow <= 0 {
		c.HTTP3.InitialStreamWindow = defaultInitialStreamWindow
	}
	if c.HTTP3.MaxStreamWindow <= 0 {
		c.HTTP3.MaxStreamWindow = defaultMaxStreamWindow
	}
	if c.HTTP3.InitialConnWindow <= 0 {
		c.HTTP3.InitialConnWindow = defaultInitialConnWindow
	}
	if c.HTTP3.MaxConnWindow <= 0 {
		c.HTTP3.MaxConnWindow = defaultMaxConnWindow
	}
}

func (c *ClientConfig) Validate() error {
	if c.ConnectIP.Addr == "" {
		return fmt.Errorf("client: connect_ip.addr is required")
	}
	if c.ConnectIP.URI == "" {
		return fmt.Errorf("client: connect_ip.uri is required")
	}
	if c.TUN.MTU < 1280 || c.TUN.MTU > 65535 {
		return fmt.Errorf("client: tun.mtu must be between 1280 and 65535")
	}
	return nil
}

// ServerConfig 方法
func (s *ServerConfig) ApplyDefaults() {
	if s.Listen == "" {
		s.Listen = ":443"
	}
	if s.URITemplate == "" {
		s.URITemplate = "https://localhost/.well-known/masque/ip"
	}
	if s.TUN.MTU <= 0 {
		s.TUN.MTU = 1400
	}
	if s.HTTP3.MaxIdleTimeout.Duration == 0 {
		s.HTTP3.MaxIdleTimeout = Duration{60 * time.Second}
	}
	if s.HTTP3.KeepAlivePeriod.Duration == 0 {
		s.HTTP3.KeepAlivePeriod = Duration{20 * time.Second}
	}
	if s.TLS.SessionCacheSize <= 0 {
		s.TLS.SessionCacheSize = 256
	}
	if s.IPv4Pool == "" {
		s.IPv4Pool = "10.0.0.0/24"
	}
	if s.IPv6Pool == "" {
		s.IPv6Pool = "fd00::/64"
	}
	// QUIC 流控窗口：服务端面向多客户端并发，单连接窗口与客户端一致
	if s.HTTP3.InitialStreamWindow <= 0 {
		s.HTTP3.InitialStreamWindow = defaultInitialStreamWindow
	}
	if s.HTTP3.MaxStreamWindow <= 0 {
		s.HTTP3.MaxStreamWindow = defaultMaxStreamWindow
	}
	if s.HTTP3.InitialConnWindow <= 0 {
		s.HTTP3.InitialConnWindow = defaultInitialConnWindow
	}
	if s.HTTP3.MaxConnWindow <= 0 {
		s.HTTP3.MaxConnWindow = defaultMaxConnWindow
	}
}

func (s *ServerConfig) Validate() error {
	if s.Listen == "" {
		return fmt.Errorf("server: listen is required")
	}
	if s.TLS.CertFile == "" {
		return fmt.Errorf("server: tls.cert_file is required")
	}
	if s.TLS.KeyFile == "" {
		return fmt.Errorf("server: tls.key_file is required")
	}
	if s.TUN.MTU < 1280 || s.TUN.MTU > 65535 {
		return fmt.Errorf("server: tun.mtu must be between 1280 and 65535")
	}
	return nil
}
