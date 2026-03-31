package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

type stdlibProvider struct{}

// NewProvider 返回基于标准库的 TLS Provider。
func NewProvider() Provider {
	return &stdlibProvider{}
}

const defaultECHMaxRetries = 3

func (p *stdlibProvider) NewClient(_ context.Context, opts ClientOptions) (ClientConfig, error) {
	roots, err := buildRootCAs(opts)
	if err != nil {
		return nil, fmt.Errorf("tls: build root CAs: %w", err)
	}

	base := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         opts.ServerName,
		NextProtos:         append([]string(nil), opts.NextProtos...),
		InsecureSkipVerify: opts.InsecureSkipVerify,
		RootCAs:            roots,
		CurvePreferences:   buildCurvePreferences(opts.EnablePQC),
	}

	// mTLS 客户端证书加载（如果配置了证书和私钥）
	if opts.ClientCertFile != "" && opts.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load client cert/key: %w", err)
		}
		base.Certificates = []tls.Certificate{cert}
	}

	if opts.EnableSessionCache {
		size := opts.SessionCacheSize
		if size <= 0 {
			size = 128
		}
		base.ClientSessionCache = tls.NewLRUClientSessionCache(size)
	}

	var keyLogFile *os.File
	if opts.KeyLogPath != "" {
		f, err := os.OpenFile(opts.KeyLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("tls: open key log file: %w", err)
		}
		base.KeyLogWriter = f
		keyLogFile = f
	}

	maxRetries := opts.ECHMaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultECHMaxRetries
	}

	// ECH 严格模式：EnableECH=true 时必须拿到配置，否则报错；绝不降级为明文 ClientHello。
	if opts.EnableECH {
		echList, echMgr, err := resolveECH(opts)
		if err != nil {
			if keyLogFile != nil {
				_ = keyLogFile.Close()
			}
			return nil, fmt.Errorf("tls: ECH enabled but cannot load config: %w", err)
		}
		if len(echList) == 0 {
			if keyLogFile != nil {
				_ = keyLogFile.Close()
			}
			return nil, fmt.Errorf("tls: ECH enabled but no ECH config available (set ech_config_list or ech_domain+ech_doh_server)")
		}
		echCfg := buildECHTLSConfig(base, echList)
		return &stdlibClientConfig{
			cfg:        echCfg,
			baseCfg:    base,
			keyLogFile: keyLogFile,
			echMgr:     echMgr,
			maxRetries: maxRetries,
		}, nil
	}

	return &stdlibClientConfig{cfg: base, baseCfg: base, keyLogFile: keyLogFile}, nil
}

// resolveECH 从 opts 中解析 ECH 配置列表。
// 返回 (echList, manager, error)；manager 非 nil 时表示使用动态刷新。
func resolveECH(opts ClientOptions) ([]byte, *ECHManager, error) {
	// 1. 静态配置优先
	if len(opts.ECHConfigList) > 0 {
		return opts.ECHConfigList, nil, nil
	}
	// 2. 动态管理器
	if opts.ECHManager != nil {
		list, err := opts.ECHManager.Get()
		if err != nil {
			return nil, nil, fmt.Errorf("tls: get ech config: %w", err)
		}
		return list, opts.ECHManager, nil
	}
	// 3. 无来源 → 降级
	return nil, nil, nil
}

// buildRootCAs 按优先级选择根证书池：
//  1. 调用方显式传入 RootCAs
//  2. Mozilla CA（内嵌 PEM）
//  3. 系统 CA
//  4. nil（Go 默认行为）
func buildRootCAs(opts ClientOptions) (*x509.CertPool, error) {
	if opts.RootCAs != nil {
		return opts.RootCAs, nil
	}
	if opts.UseMozillaCA {
		return GetMozillaCertPool(), nil
	}
	if opts.UseSystemCAs {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, nil // Android 等平台不支持，降级
		}
		return pool, nil
	}
	return nil, nil
}

// buildCurvePreferences 返回 ECDH/KEM 曲线偏好列表。
// enablePQC=true 时将 X25519MLKEM768 放在首位。
func buildCurvePreferences(enablePQC bool) []tls.CurveID {
	if enablePQC {
		return []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		}
	}
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
	}
}

// ErrECHRejected 在服务端拒绝 ECH 且超过最大重试次数后返回。
var ErrECHRejected = fmt.Errorf("tls: server rejected ECH after maximum retries, refusing to downgrade")

// stdlibClientConfig 实现 ClientConfig。
type stdlibClientConfig struct {
	cfg        *tls.Config  // 当前生效的 TLS 配置（含 ECH 配置）
	baseCfg    *tls.Config  // 不含 ECH 的基础配置（用于克隆）
	keyLogFile *os.File
	echMgr     *ECHManager // 非 nil 时支持 retry config 更新

	maxRetries  int // ECH HRR 最大重试次数（0 = 无 ECH 模式，不计数）
	retryCount  int // 已重试次数
}

func (c *stdlibClientConfig) TLSConfig() *tls.Config {
	return c.cfg
}

// HandleHandshakeError 处理握手错误。
//
// ECH 严格模式（maxRetries > 0）：
//   - 服务端拒绝 ECH 并携带 RetryConfigList → 用新配置重试，最多 maxRetries 次。
//   - 服务端拒绝 ECH 但无 RetryConfigList，或超过重试上限 → 返回 ErrECHRejected，不降级。
//
// 非 ECH 模式（maxRetries == 0）：原样返回错误。
func (c *stdlibClientConfig) HandleHandshakeError(err error) (retry bool, outErr error) {
	if err == nil {
		return false, nil
	}

	// 非 ECH 模式，直接透传错误
	if c.maxRetries == 0 {
		return false, err
	}

	var echErr *tls.ECHRejectionError
	if !isECHRejection(err, &echErr) {
		// 非 ECH 拒绝错误（如证书错误、网络错误），直接透传
		return false, err
	}

	// 服务端拒绝 ECH，但没有提供 RetryConfigList → 无法重试，断连
	if echErr == nil || len(echErr.RetryConfigList) == 0 {
		return false, fmt.Errorf("%w: server provided no retry config", ErrECHRejected)
	}

	// 超过重试上限 → 断连，不降级
	if c.retryCount >= c.maxRetries {
		return false, fmt.Errorf("%w: tried %d time(s)", ErrECHRejected, c.retryCount)
	}

	// 使用服务端返回的新 ECH 配置重试
	c.retryCount++
	newCfg := buildECHTLSConfig(c.baseCfg, echErr.RetryConfigList)
	c.cfg = newCfg

	if c.echMgr != nil {
		_ = c.echMgr.UpdateFromRetry(echErr.RetryConfigList)
	}

	return true, nil
}

// ResetRetryCount 在成功连接后重置重试计数器。
func (c *stdlibClientConfig) ResetRetryCount() {
	c.retryCount = 0
}

func (c *stdlibClientConfig) Close() error {
	if c.keyLogFile != nil {
		return c.keyLogFile.Close()
	}
	return nil
}
