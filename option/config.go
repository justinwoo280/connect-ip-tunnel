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
}

type TLSConfig struct {
	ServerName         string `json:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`

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
	EnableDatagrams      bool     `json:"enable_datagrams"`
	MaxIdleTimeout       Duration `json:"max_idle_timeout"`
	KeepAlivePeriod      Duration `json:"keep_alive_period"`
	Allow0RTT            bool     `json:"allow_0rtt"`
	DisablePathMTUProbe  bool     `json:"disable_path_mtu_probe"`
	InitialStreamWindow  int64    `json:"initial_stream_window"`
	MaxStreamWindow      int64    `json:"max_stream_window"`
	InitialConnWindow    int64    `json:"initial_conn_window"`
	MaxConnWindow        int64    `json:"max_conn_window"`
	DisableCompression   bool     `json:"disable_compression"`
	TLSHandshakeTimeout  Duration `json:"tls_handshake_timeout"`
	MaxResponseHeaderSec int      `json:"max_response_header_sec"`
}

type ConnectIPConfig struct {
	Addr      string `json:"addr"` // host:port，例如 proxy.example.com:443
	URI       string `json:"uri"`
	Authority string `json:"authority"`

	// ADDRESS_ASSIGN: 等待服务端分配 IP 后再配置 TUN
	WaitForAddressAssign bool     `json:"wait_for_address_assign"` // 默认 true
	AddressAssignTimeout Duration `json:"address_assign_timeout"`  // 默认 30s

	// 重连配置
	EnableReconnect   bool     `json:"enable_reconnect"`    // 默认 true
	MaxReconnectDelay Duration `json:"max_reconnect_delay"` // 默认 30s

	// 多 session 并行（企业版特性，开源版固定为 1）
	// 启用后客户端会并行建立 N 条 CONNECT-IP session，
	// 按五元组哈希分发上行包，充分利用多核与多连接带宽。
	NumSessions int `json:"num_sessions"` // 默认 1；建议设为 CPU 核数或带宽瓶颈数
}


