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

	// ECH 路径
	if opts.EnableECH {
		echList, echMgr, err := resolveECH(opts)
		if err != nil {
			return nil, err
		}
		if len(echList) > 0 {
			echCfg := buildECHTLSConfig(base, echList)
			return &stdlibClientConfig{cfg: echCfg, keyLogFile: keyLogFile, echMgr: echMgr}, nil
		}
		// 无法获取 ECH 配置时降级（不阻断连接）
	}

	return &stdlibClientConfig{cfg: base, keyLogFile: keyLogFile}, nil
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

// stdlibClientConfig 实现 ClientConfig。
type stdlibClientConfig struct {
	cfg        *tls.Config
	keyLogFile *os.File
	echMgr     *ECHManager // 非 nil 时支持 retry config 更新
}

func (c *stdlibClientConfig) TLSConfig() *tls.Config {
	return c.cfg
}

// HandleHandshakeError 处理握手错误。
// 若服务端拒绝 ECH 并返回 RetryConfigList，则更新配置并建议重试。
func (c *stdlibClientConfig) HandleHandshakeError(err error) (retry bool, outErr error) {
	if err == nil {
		return false, nil
	}
	var echErr *tls.ECHRejectionError
	if isECHRejection(err, &echErr) && echErr != nil && len(echErr.RetryConfigList) > 0 {
		c.cfg.EncryptedClientHelloConfigList = echErr.RetryConfigList
		if c.echMgr != nil {
			_ = c.echMgr.UpdateFromRetry(echErr.RetryConfigList)
		}
		return true, nil
	}
	return false, err
}

func (c *stdlibClientConfig) Close() error {
	if c.keyLogFile != nil {
		return c.keyLogFile.Close()
	}
	return nil
}
