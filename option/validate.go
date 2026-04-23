package option

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// 已知合法值集合（供 validate 校验，避免用户拼写错误时静默回退到默认）。
var (
	validCongestionAlgos = map[string]struct{}{
		"":      {}, // 留空 = 默认 cubic
		"cubic": {},
		"bbr2":  {},
	}
	validObfsTypes = map[string]struct{}{
		"":           {}, // 留空 = 不启用混淆
		"salamander": {},
	}
)

// validateHTTP3Common 抽出客户端 / 服务端共用的 HTTP3 字段校验逻辑。
// 不返回错误的字段（如 obfs 参数）使用 slog.Warn 提示，便于排障但不阻断启动。
func validateHTTP3Common(scope string, h HTTP3Config) error {
	algo := strings.ToLower(strings.TrimSpace(h.Congestion.Algorithm))
	if _, ok := validCongestionAlgos[algo]; !ok {
		return fmt.Errorf("%s: http3.congestion.algorithm must be one of cubic/bbr2, got %q", scope, h.Congestion.Algorithm)
	}

	obfsType := strings.ToLower(strings.TrimSpace(h.Obfs.Type))
	if _, ok := validObfsTypes[obfsType]; !ok {
		return fmt.Errorf("%s: http3.obfs.type must be salamander or empty, got %q", scope, h.Obfs.Type)
	}
	if obfsType != "" && h.Obfs.Password == "" {
		return fmt.Errorf("%s: http3.obfs.password is required when obfs.type=%q", scope, h.Obfs.Type)
	}

	// 窗口一致性提示
	if h.MaxStreamWindow > 0 && h.InitialStreamWindow > 0 &&
		h.MaxStreamWindow < h.InitialStreamWindow {
		slog.Warn("http3 window misconfigured: max_stream_window < initial_stream_window, will be auto-promoted",
			"scope", scope,
			"max", h.MaxStreamWindow,
			"initial", h.InitialStreamWindow)
	}
	if h.MaxConnWindow > 0 && h.InitialConnWindow > 0 &&
		h.MaxConnWindow < h.InitialConnWindow {
		slog.Warn("http3 window misconfigured: max_conn_window < initial_conn_window, will be auto-promoted",
			"scope", scope,
			"max", h.MaxConnWindow,
			"initial", h.InitialConnWindow)
	}

	return nil
}

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
		c.HTTP3.MaxIdleTimeout = Duration{45 * time.Second}
	}
	if c.HTTP3.KeepAlivePeriod.Duration == 0 {
		c.HTTP3.KeepAlivePeriod = Duration{15 * time.Second}
	}
	// UDP socket buffer 默认值（性能优化）
	if c.HTTP3.UDPRecvBuffer <= 0 {
		c.HTTP3.UDPRecvBuffer = 16 * 1024 * 1024 // 16 MB
	}
	if c.HTTP3.UDPSendBuffer <= 0 {
		c.HTTP3.UDPSendBuffer = 16 * 1024 * 1024 // 16 MB
	}
	// GSO/GRO 默认启用（Linux 上有效，其他平台 noop）。
	// 注意：此处只在用户未显式配置时填充默认，不再无条件覆盖。
	if c.HTTP3.EnableGSO == nil {
		c.HTTP3.EnableGSO = boolPtr(true)
	}

	if c.TLS.SessionCacheSize <= 0 {
		c.TLS.SessionCacheSize = 128
	}
	// 地址族偏好默认 "auto"（Happy Eyeballs）
	if c.TLS.PreferAddressFamily == "" {
		c.TLS.PreferAddressFamily = "auto"
	}
	// Happy Eyeballs 交错延迟默认 50ms（比 RFC 8305 250ms 更激进）
	if c.TLS.HappyEyeballsDelay.Duration <= 0 {
		c.TLS.HappyEyeballsDelay = Duration{50 * time.Millisecond}
	}
	// ADDRESS_ASSIGN 默认启用
	if c.ConnectIP.AddressAssignTimeout.Duration == 0 {
		c.ConnectIP.AddressAssignTimeout = Duration{30 * time.Second}
	}
	// 重连默认启用：仅当用户未显式配置时填默认 true，不再覆盖用户的 false。
	if c.ConnectIP.EnableReconnect == nil {
		c.ConnectIP.EnableReconnect = boolPtr(true)
	}
	if c.ConnectIP.MaxReconnectDelay.Duration == 0 {
		c.ConnectIP.MaxReconnectDelay = Duration{30 * time.Second}
	}
	// 应用层心跳默认配置
	if c.ConnectIP.AppKeepalivePeriod.Duration == 0 {
		c.ConnectIP.AppKeepalivePeriod = Duration{25 * time.Second}
	}
	if c.ConnectIP.AppKeepaliveTimeout.Duration == 0 {
		c.ConnectIP.AppKeepaliveTimeout = Duration{30 * time.Second}
	}
	if c.ConnectIP.UnhealthyThreshold <= 0 {
		c.ConnectIP.UnhealthyThreshold = 3
	}
	// 多 session 独立重连默认启用：同样只在 nil 时填默认。
	if c.ConnectIP.PerSessionReconnect == nil {
		c.ConnectIP.PerSessionReconnect = boolPtr(true)
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
	// 管理 API 鉴权检查：非 loopback 地址必须设置 token
	if c.AdminListen != "" && !isLoopback(c.AdminListen) && c.AdminToken == "" {
		return fmt.Errorf("client: admin_token is required when admin_listen is not a loopback address")
	}
	// 地址族偏好合法性校验
	switch c.TLS.PreferAddressFamily {
	case "auto", "v4", "v6":
		// ok
	default:
		return fmt.Errorf("client: tls.prefer_address_family must be one of auto/v4/v6, got %q", c.TLS.PreferAddressFamily)
	}

	// HTTP3 公共校验（congestion / obfs / window 一致性）
	if err := validateHTTP3Common("client", c.HTTP3); err != nil {
		return err
	}

	// EnablePprof 仅在 AdminListen 启用时有意义
	if c.EnablePprof && c.AdminListen == "" {
		slog.Warn("client.enable_pprof=true but admin_listen is empty; pprof endpoint will not be served")
	}

	// num_sessions 越界提示（不阻断启动）
	if c.ConnectIP.NumSessions < 0 {
		return fmt.Errorf("client: connect_ip.num_sessions must be >= 0 (0/1 = single session)")
	}
	if c.ConnectIP.NumSessions > 32 {
		slog.Warn("client.connect_ip.num_sessions > 32 is unusual and may exhaust file descriptors",
			"num_sessions", c.ConnectIP.NumSessions)
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
	// UDP socket buffer 默认值（性能优化）
	if s.HTTP3.UDPRecvBuffer <= 0 {
		s.HTTP3.UDPRecvBuffer = 16 * 1024 * 1024 // 16 MB
	}
	if s.HTTP3.UDPSendBuffer <= 0 {
		s.HTTP3.UDPSendBuffer = 16 * 1024 * 1024 // 16 MB
	}
	// GSO/GRO 默认启用：仅在用户未显式配置时填默认。
	if s.HTTP3.EnableGSO == nil {
		s.HTTP3.EnableGSO = boolPtr(true)
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
	// Session idle timeout 默认 5 分钟
	if s.SessionIdleTimeout.Duration == 0 {
		s.SessionIdleTimeout = Duration{5 * time.Minute}
	}
	// UnauthenticatedMetrics 默认为 true（向后兼容）
	// 注意：Go 的零值为 false，所以这里不能简单判断 == false
	// 实际上配置文件中不设置时，默认就是 false，需要在文档中说明默认行为
	// 为了向后兼容，我们在这里不修改默认值，保持 false（需要 token）
	// 如果用户想要匿名访问 metrics，需要显式设置 "unauthenticated_metrics": true
	
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
	// 管理 API 鉴权检查：非 loopback 地址必须设置 token
	if s.AdminListen != "" && !isLoopback(s.AdminListen) && s.AdminToken == "" {
		return fmt.Errorf("server: admin_token is required when admin_listen is not a loopback address")
	}

	// HTTP3 公共校验
	if err := validateHTTP3Common("server", s.HTTP3); err != nil {
		return err
	}

	// EnablePprof 仅在 AdminListen 启用时有意义
	if s.EnablePprof && s.AdminListen == "" {
		slog.Warn("server.enable_pprof=true but admin_listen is empty; pprof endpoint will not be served")
	}

	return nil
}

// isLoopback 检查地址是否为 loopback（127.0.0.1, ::1, localhost）
func isLoopback(addr string) bool {
	// 简单检查：包含 127.0.0.1, ::1, localhost 或 [::1]
	return addr == "" ||
		addr[0] == ':' || // :9090 等价于 localhost:9090
		len(addr) >= 9 && addr[:9] == "127.0.0.1" ||
		len(addr) >= 9 && addr[:9] == "localhost" ||
		len(addr) >= 4 && addr[:4] == "[::1" ||
		len(addr) >= 3 && addr[:3] == "::1"
}
