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

// ClientConfig 方法
func (c *ClientConfig) ApplyDefaults() {
	if c.TUN.MTU <= 0 {
		c.TUN.MTU = 1400
	}
	if c.HTTP3.MaxIdleTimeout == 0 {
		c.HTTP3.MaxIdleTimeout = 30 * time.Second
	}
	if c.HTTP3.KeepAlivePeriod == 0 {
		c.HTTP3.KeepAlivePeriod = 10 * time.Second
	}
	if c.TLS.SessionCacheSize <= 0 {
		c.TLS.SessionCacheSize = 128
	}
	// ADDRESS_ASSIGN 默认启用
	if c.ConnectIP.AddressAssignTimeout == 0 {
		c.ConnectIP.AddressAssignTimeout = 30 * time.Second
	}
	// 重连默认启用
	if c.ConnectIP.MaxReconnectDelay == 0 {
		c.ConnectIP.MaxReconnectDelay = 30 * time.Second
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
		s.URITemplate = "/.well-known/masque/ip"
	}
	if s.TUN.MTU <= 0 {
		s.TUN.MTU = 1400
	}
	if s.HTTP3.MaxIdleTimeout == 0 {
		s.HTTP3.MaxIdleTimeout = 30 * time.Second
	}
	if s.HTTP3.KeepAlivePeriod == 0 {
		s.HTTP3.KeepAlivePeriod = 10 * time.Second
	}
	if s.TLS.SessionCacheSize <= 0 {
		s.TLS.SessionCacheSize = 128
	}
	if s.IPv4Pool == "" {
		s.IPv4Pool = "10.0.0.0/24"
	}
	if s.IPv6Pool == "" {
		s.IPv6Pool = "fd00::/64"
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
