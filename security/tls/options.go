package tls

import (
	"crypto/x509"
	"time"
)

// ClientOptions 描述构建 TLS 客户端配置所需的全部参数。
type ClientOptions struct {
	ServerName         string
	NextProtos         []string
	InsecureSkipVerify bool

	// PQC：启用后在 CurvePreferences 首位插入 X25519MLKEM768
	EnablePQC bool

	// CA 证书来源（优先级：RootCAs > UseMozillaCA > UseSystemCAs > nil）
	UseSystemCAs bool
	UseMozillaCA bool
	RootCAs      *x509.CertPool

	// mTLS 客户端证书（用于向服务端证明身份）
	ClientCertFile string // 客户端证书文件路径
	ClientKeyFile  string // 客户端私钥文件路径

	// ECH（Encrypted Client Hello）
	EnableECH     bool
	ECHConfigList []byte      // 静态 ECH 配置列表（优先于 ECHManager）
	ECHManager    *ECHManager // 动态 ECH 管理器（DoH 自动刷新）
	// ECH HRR 重试次数上限（0 表示使用默认值 3）
	// 若服务端拒绝 ECH 并返回 RetryConfigList，将使用新配置重试，
	// 超过上限后直接返回错误，不降级为明文 ClientHello。
	ECHMaxRetries int

	// TLS Session Cache
	EnableSessionCache bool
	SessionCacheSize   int

	// 调试：将 TLS 密钥写入文件（SSLKEYLOGFILE 格式）
	KeyLogPath string
}

// ServerOptions TLS 服务端配置选项
type ServerOptions struct {
	CertFile string // 证书文件路径
	KeyFile  string // 私钥文件路径

	NextProtos []string // ALPN 协议列表，例如 []string{"h3"}

	EnablePQC bool // 启用后量子密码学曲线

	// mTLS 配置
	EnableMTLS   bool           // 启用 mTLS 客户端证书验证
	ClientCAs    *x509.CertPool // 自定义客户端 CA 池（nil 时使用系统 CA）
	ClientCAFile string         // 客户端 CA 证书文件路径（PEM 格式，可包含多个证书）

	// CRL（证书吊销列表）配置
	// 设置后服务端会定时从该 URL 拉取 CRL，并在 mTLS 握手时检查客户端证书是否被吊销
	CRLUrl      string        // CRL PEM 文件的 HTTP(S) URL，例如 http://certsrv:8443/crl.pem
	CRLInterval time.Duration // CRL 拉取间隔，默认 10 分钟

	EnableSessionCache bool // 启用 TLS session 缓存
	SessionCacheSize   int  // Session 缓存大小

	KeyLogPath string // 调试：TLS 密钥日志文件路径
}
