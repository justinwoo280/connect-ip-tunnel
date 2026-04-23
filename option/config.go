package option

import (
	"fmt"
	"time"
)

// Duration 是一个支持 JSON 字符串（如 "10m"、"30s"）和纳秒数字两种格式的时间类型。
// 标准 time.Duration 的 JSON 解析只支持数字（纳秒），不支持人类可读字符串。
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	// 数字格式（纳秒）：兼容旧配置
	if len(s) > 0 && s[0] != '"' {
		var ns int64
		if _, err := fmt.Sscanf(s, "%d", &ns); err != nil {
			return fmt.Errorf("invalid duration %s: %w", s, err)
		}
		d.Duration = time.Duration(ns)
		return nil
	}
	// 字符串格式："10m"、"30s"、"1h30m" 等
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Errorf("invalid duration format: %s", s)
	}
	dur, err := time.ParseDuration(s[1 : len(s)-1])
	if err != nil {
		return fmt.Errorf("invalid duration %s: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Mode 运行模式
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

type Config struct {
	Mode   Mode         `json:"mode"` // client 或 server
	Client ClientConfig `json:"client,omitempty"`
	Server ServerConfig `json:"server,omitempty"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	TUN       TUNConfig       `json:"tun"`
	Bypass    BypassConfig    `json:"bypass"`
	TLS       TLSConfig       `json:"tls"`
	HTTP3     HTTP3Config     `json:"http3"`
	ConnectIP ConnectIPConfig `json:"connect_ip"`

	// AdminListen 管理/统计 HTTP 接口监听地址（留空则不启动）
	// 例如 "127.0.0.1:9091" 或 "127.0.0.1:0"（随机端口，从日志读取实际端口）
	AdminListen string `json:"admin_listen,omitempty"`

	// AdminToken 管理 API 访问令牌（Bearer token）
	// 当 AdminListen 不是 loopback 地址时必须设置
	AdminToken string `json:"admin_token,omitempty"`

	// EnablePprof 启用 pprof 性能分析端点（/debug/pprof/*）
	// 仅在 AdminListen 启用时生效，受 AdminToken 保护
	EnablePprof bool `json:"enable_pprof,omitempty"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Listen      string      `json:"listen"`       // 监听地址，例如 :443 或 0.0.0.0:443
	URITemplate string      `json:"uri_template"` // URI 模板，例如 /.well-known/masque/ip
	AdminListen string      `json:"admin_listen"` // 管理/metrics 端点监听地址，例如 127.0.0.1:9090（留空则不启动）
	TUN         TUNConfig   `json:"tun"`
	TLS         TLSConfig   `json:"tls"`
	HTTP3       HTTP3Config `json:"http3"`

	// IP 地址池配置
	IPv4Pool string `json:"ipv4_pool"` // 例如 10.0.0.0/24
	IPv6Pool string `json:"ipv6_pool"` // 例如 fd00::/64

	// 路由配置
	EnableNAT    bool   `json:"enable_nat"`    // 启用 NAT（MASQUERADE）
	NATInterface string `json:"nat_interface"` // NAT 出口接口（留空自动检测）

	// 管理 API 鉴权配置
	AdminToken             string `json:"admin_token,omitempty"`              // 管理 API 访问令牌（Bearer token）
	UnauthenticatedMetrics bool   `json:"unauthenticated_metrics,omitempty"`  // 允许匿名访问 /metrics（默认 true）
	EnablePprof            bool   `json:"enable_pprof,omitempty"`             // 启用 pprof 性能分析端点（/debug/pprof/*）

	// Session 管理配置
	SessionIdleTimeout Duration `json:"session_idle_timeout"` // 应用层 idle 清理间隔，默认 5m，0 = 禁用

	// Per-client 路由策略（基于 mTLS 证书 CN）
	// 例如 {"alice": ["10.0.0.0/8"], "bob": ["192.168.0.0/16"]}
	// 未配置的客户端使用全路由（0.0.0.0/0 + ::/0）
	ClientRoutesPolicy map[string][]string `json:"client_routes_policy,omitempty"`

	// CertSrv：CA 证书管理 Web 面板（留空则不启动）
	CertSrv CertSrvConfig `json:"certsrv,omitempty"`
}

// CertSrvConfig CA 证书管理面板配置
type CertSrvConfig struct {
	Listen     string `json:"listen"`       // 监听地址，如 ":8443"（留空则不启动）
	DBPath     string `json:"db_path"`      // SQLite 路径，默认 /etc/connect-ip-tunnel/certsrv.db
	CACertFile string `json:"ca_cert_file"` // CA 证书路径（默认与 tls.client_ca_file 相同）
	CAKeyFile  string `json:"ca_key_file"`  // CA 私钥路径
	TLSCert    string `json:"tls_cert"`     // certsrv HTTPS 证书（留空复用 tls.cert_file）
	TLSKey     string `json:"tls_key"`      // certsrv HTTPS 私钥（留空复用 tls.key_file）

	// 审计日志轮转配置
	AuditLogDir     string `json:"audit_log_dir"`      // JSONL 导出目录，留空则只删不导出
	AuditRetainDays int    `json:"audit_retain_days"`  // DB 内保留天数，默认 30

	// TrustedProxy 为 true 时才信任 X-Forwarded-For / X-Real-IP 取客户端真实 IP。
	// 仅在 certsrv 前有可信反向代理（如 nginx）时开启，否则攻击者可伪造请求头绕过登录限速。
	TrustedProxy bool `json:"trusted_proxy"`
}

// TUNConfig 描述 TUN 设备的创建与寻址参数。
//
// 跨平台行为差异：
//   - Linux  : Name 直接作为接口名（如 "tun0"）；FileDescriptor 用于 NetworkManager
//              托管场景，可传入已 open 的 fd。
//   - macOS  : Name 必须形如 "utun*"，否则系统会拒绝创建。留空则由内核分配下一个可用号。
//   - Windows: 使用 wintun 驱动，Name 仅作为偏好的适配器别名（同名已存在时会被复用），
//              真实接口名最终以系统注册表里的 wintun 实例为准。
//   - FreeBSD: Name 同 Linux 语义。
//   - Android: 必须传入 FileDescriptor（来自 VPNService），Name/MTU 仅作日志记录。
type TUNConfig struct {
	Name           string `json:"name"`
	MTU            int    `json:"mtu"`
	FileDescriptor int    `json:"file_descriptor"`
	IPv4CIDR       string `json:"ipv4_cidr"`
	IPv6CIDR       string `json:"ipv6_cidr"`
	DNSv4          string `json:"dns_v4"`
	DNSv6          string `json:"dns_v6"`
}

type BypassConfig struct {
	Enable     bool   `json:"enable"`
	ServerAddr string `json:"server_addr"`
	Strict     bool   `json:"strict"` // 严格模式：探测失败时返回错误而非降级
}

type TLSConfig struct {
	ServerName         string `json:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`

	// PreferAddressFamily 解析服务端域名时的地址族偏好：
	//   "auto" (默认) - Happy Eyeballs（IPv6 优先，IPv4 兜底）
	//   "v4"          - 仅使用 IPv4
	//   "v6"          - 仅使用 IPv6
	PreferAddressFamily string `json:"prefer_address_family,omitempty"`

	// HappyEyeballsDelay Happy Eyeballs 算法中两个连接尝试之间的交错延迟。
	// RFC 8305 推荐 250ms；本项目默认更激进的 50ms，便于双栈环境下快速回退。
	HappyEyeballsDelay Duration `json:"happy_eyeballs_delay,omitempty"`

	EnablePQC    bool `json:"enable_pqc"`
	UseSystemCAs bool `json:"use_system_cas"`
	UseMozillaCA bool `json:"use_mozilla_ca"`

	// ECH（Encrypted Client Hello）- 客户端
	EnableECH     bool   `json:"enable_ech"`
	ECHConfigList []byte `json:"ech_config_list,omitempty"` // 静态 ECH 配置（base64 解码后的二进制）
	ECHDomain     string `json:"ech_domain,omitempty"`      // 动态 ECH：查询的域名
	ECHDOHServer  string `json:"ech_doh_server,omitempty"`  // 动态 ECH：DoH 服务器 URL

	// 服务端证书配置
	CertFile string `json:"cert_file,omitempty"` // 服务端证书文件路径
	KeyFile  string `json:"key_file,omitempty"`  // 服务端私钥文件路径

	// mTLS 配置
	ClientCertFile string `json:"client_cert_file,omitempty"` // 客户端证书文件路径（用于向服务端证明身份）
	ClientKeyFile  string `json:"client_key_file,omitempty"`  // 客户端私钥文件路径
	ClientCAFile   string `json:"client_ca_file,omitempty"`   // 服务端用：验证客户端证书的 CA（PEM 格式）
	EnableMTLS     bool   `json:"enable_mtls"`                // 服务端用：是否启用 mTLS 验证

	// CRL（证书吊销列表）— 服务端 mTLS 模式下使用
	CRLUrl      string   `json:"crl_url,omitempty"`      // CRL PEM 的 HTTP(S) URL
	CRLInterval Duration `json:"crl_interval,omitempty"` // 拉取间隔，默认 10m，支持 "10m"/"1h" 字符串

	EnableSessionCache bool   `json:"enable_session_cache"`
	SessionCacheSize   int    `json:"session_cache_size"`
	KeyLogPath         string `json:"key_log_path"`
}

type HTTP3Config struct {
	// Obfs UDP 包级别混淆配置（留空不启用）
	// Salamander 混淆可规避运营商对 QUIC Long Header 的 DPI 识别
	Obfs ObfsConfig `json:"obfs,omitempty"`
	// Congestion 拥塞控制配置（留空使用默认 CUBIC）
	Congestion CongestionConfig `json:"congestion,omitempty"`
	
	// UDP socket buffer 配置（性能优化）
	UDPRecvBuffer int  `json:"udp_recv_buffer"` // UDP 接收缓冲区大小（字节），默认 16MB
	UDPSendBuffer int  `json:"udp_send_buffer"` // UDP 发送缓冲区大小（字节），默认 16MB
	// EnableGSO 启用 GSO/GRO（仅 Linux 真正生效；其他平台 quic-go 自动降级）。
	// 默认 nil = true（启用）。显式写 false 通过 QUIC_GO_DISABLE_GSO 环境变量
	// 关闭 quic-go 内的发送方 GSO 路径（用于排障 / 兼容旧内核）。
	EnableGSO *bool `json:"enable_gso,omitempty"`
	
	EnableDatagrams bool     `json:"enable_datagrams"`
	MaxIdleTimeout  Duration `json:"max_idle_timeout"`
	KeepAlivePeriod Duration `json:"keep_alive_period"`
	Allow0RTT       bool     `json:"allow_0rtt"`
	// DisablePathMTUProbe 关闭 quic-go 的路径 MTU 探测。
	// 跨平台说明：探测依赖 ICMP "Frag Needed"/"Packet Too Big" 响应；
	// 在 Windows 上若防火墙过滤了入向 ICMPv6，会出现长时间停顿后回退到保守 MTU。
	// 遇到这种症状时可临时设为 true（保守 MTU=1252），但损失约 5-10% 吞吐。
	DisablePathMTUProbe bool  `json:"disable_path_mtu_probe"`
	InitialStreamWindow int64 `json:"initial_stream_window"`
	MaxStreamWindow     int64 `json:"max_stream_window"`
	InitialConnWindow   int64 `json:"initial_conn_window"`
	MaxConnWindow       int64 `json:"max_conn_window"`
	// 注意：以下 3 个字段（disable_compression / tls_handshake_timeout / max_response_header_sec）
	// 已于 2026-04 移除 —— CONNECT-IP 走 datagram + capsule 路径，没有独立 HTTP 响应头与
	// HTTP 压缩协商，quic-go 也不暴露相应钩子，留着只会误导用户。配置文件里残留这些 key
	// 由 Go 的 json 解码器静默忽略（无 json 标签命中），向后兼容。
}

type ConnectIPConfig struct {
	Addr      string `json:"addr"` // host:port，例如 proxy.example.com:443
	URI       string `json:"uri"`
	Authority string `json:"authority"`

	// ADDRESS_ASSIGN: 等待服务端分配 IP 后再配置 TUN
	WaitForAddressAssign bool     `json:"wait_for_address_assign"` // 默认 true
	AddressAssignTimeout Duration `json:"address_assign_timeout"`  // 默认 30s

	// 重连配置
	// EnableReconnect 默认 nil = true（启用断线自动重连）；显式写 false 可禁用。
	EnableReconnect   *bool    `json:"enable_reconnect,omitempty"`
	MaxReconnectDelay Duration `json:"max_reconnect_delay"` // 默认 30s

	// 应用层心跳配置
	AppKeepalivePeriod  Duration `json:"app_keepalive_period"`  // 默认 25s，0 = 禁用
	AppKeepaliveTimeout Duration `json:"app_keepalive_timeout"` // 默认 30s，单次 ping 等待 pong 的超时
	UnhealthyThreshold  int      `json:"unhealthy_threshold"`   // 默认 3，连续 N 次 timeout 视为不健康

	// 多 session 独立重连配置
	// 默认 nil = true（启用）；显式写 false 时退化到 all-or-nothing 重连模式。
	PerSessionReconnect *bool `json:"per_session_reconnect,omitempty"`

	// 多 session 并行（默认 1，建议设为 CPU 核数或带宽瓶颈数）。
	// 启用后客户端会并行建立 N 条 CONNECT-IP session，
	// 按五元组哈希分发上行包，充分利用多核与多连接带宽。
	// 实际生效的并发上限受 quic-go transport 池大小限制。
	NumSessions int `json:"num_sessions"`
}

// boolPtr 返回指向 b 的指针，便于在配置初始化时显式赋值。
func boolPtr(b bool) *bool { return &b }

// IsReconnectEnabled 报告 EnableReconnect 是否启用：
// nil（未配置） → true（默认启用）；非 nil → 取指针值。
func (c ConnectIPConfig) IsReconnectEnabled() bool {
	if c.EnableReconnect == nil {
		return true
	}
	return *c.EnableReconnect
}

// IsPerSessionReconnectEnabled 同 IsReconnectEnabled 语义。
func (c ConnectIPConfig) IsPerSessionReconnectEnabled() bool {
	if c.PerSessionReconnect == nil {
		return true
	}
	return *c.PerSessionReconnect
}

// IsGSOEnabled 报告 EnableGSO 是否启用：默认 true，显式 false 会通过
// QUIC_GO_DISABLE_GSO 环境变量传给 quic-go。
func (h HTTP3Config) IsGSOEnabled() bool {
	if h.EnableGSO == nil {
		return true
	}
	return *h.EnableGSO
}

// ObfsConfig UDP 包级别混淆配置
type ObfsConfig struct {
	// Type 混淆类型，目前支持 "salamander"
	// 留空表示不启用混淆
	Type string `json:"type,omitempty"`
	// Password 预共享密钥（客户端和服务端必须相同）
	Password string `json:"password,omitempty"`
}

// CongestionConfig 拥塞控制配置
type CongestionConfig struct {
	// Algorithm 选择拥塞控制算法：cubic（默认）或 bbr2
	Algorithm string `json:"algorithm,omitempty"`
	// BBRv2 BBRv2 算法参数（仅 algorithm=bbr2 时生效）
	BBRv2 BBRv2Config `json:"bbr2,omitempty"`
}

// BBRv2Config BBRv2 拥塞控制可调参数
// 默认值已针对运营商 QoS 场景优化（1.5% 丢包阈值，beta=0.3）
type BBRv2Config struct {
	// LossThreshold 触发带宽下调的最低丢包率（默认 0.015 即 1.5%）
	// 运营商随机丢包通常 < 1%，此阈值可避免因 QoS 丢包误判拥塞
	LossThreshold float64 `json:"loss_threshold,omitempty"`
	// Beta 丢包时带宽下调比例（默认 0.3，即保留 70% 带宽）
	Beta float64 `json:"beta,omitempty"`
	// StartupFullBwRounds 判定带宽已达瓶颈所需的连续轮数（默认 3）
	StartupFullBwRounds int `json:"startup_full_bw_rounds,omitempty"`
	// ProbeRTTPeriod 两次 ProbeRTT 之间的间隔（默认 10s）
	ProbeRTTPeriod Duration `json:"probe_rtt_period,omitempty"`
	// ProbeRTTDuration 每次 ProbeRTT 持续时间（默认 200ms）
	ProbeRTTDuration Duration `json:"probe_rtt_duration,omitempty"`
	// BwLoReduction 带宽下调策略：default / minrtt / inflight / cwnd
	BwLoReduction string `json:"bw_lo_reduction,omitempty"`
	// Aggressive 激进模式：初始窗口更大，适合高带宽低延迟线路（默认 false）
	Aggressive bool `json:"aggressive,omitempty"`
}
