package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

// ServerConfig TLS 服务端配置接口
type ServerConfig interface {
	TLSConfig() *tls.Config
	Close() error
}

type serverConfig struct {
	tlsConfig  *tls.Config
	keyLog     *os.File
	crlFetcher *CRLFetcher
}

func (s *serverConfig) TLSConfig() *tls.Config {
	return s.tlsConfig
}

func (s *serverConfig) Close() error {
	if s.crlFetcher != nil {
		s.crlFetcher.Stop()
	}
	if s.keyLog != nil {
		return s.keyLog.Close()
	}
	return nil
}

// loadClientCAPool 从 PEM 文件加载客户端 CA 证书池
func loadClientCAPool(caFile string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid certificates found in %s", caFile)
	}

	return pool, nil
}

// NewServer 创建 TLS 服务端配置
func NewServer(opts ServerOptions) (ServerConfig, error) {
	// 1. 加载证书和私钥
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	// 2. 构建基础 TLS 配置
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // 强制 TLS 1.3
		NextProtos:   opts.NextProtos,
	}

	// mTLS 配置：根据配置决定是否启用客户端证书验证
	if opts.EnableMTLS {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

		// 优先使用传入的 ClientCAs，其次尝试从文件加载，最后使用系统 CA
		if opts.ClientCAs != nil {
			tlsCfg.ClientCAs = opts.ClientCAs
		} else if opts.ClientCAFile != "" {
			pool, err := loadClientCAPool(opts.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("load client CA file: %w", err)
			}
			tlsCfg.ClientCAs = pool
		} else {
			// 使用系统根证书作为客户端 CA
			if roots, err := x509.SystemCertPool(); err == nil && roots != nil {
				tlsCfg.ClientCAs = roots
			}
		}
	}

	// 3. PQC 支持
	if opts.EnablePQC {
		tlsCfg.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768, // 后量子密码学曲线
			tls.X25519,
			tls.CurveP256,
		}
	}

	// 4. Session 缓存
	if opts.EnableSessionCache {
		cacheSize := opts.SessionCacheSize
		if cacheSize <= 0 {
			cacheSize = 128
		}
		tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(cacheSize)
	}

	// 5. 密钥日志（调试用）
	var keyLog *os.File
	if opts.KeyLogPath != "" {
		f, err := os.OpenFile(opts.KeyLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("open key log file: %w", err)
		}
		tlsCfg.KeyLogWriter = f
		keyLog = f
	}

	// 6. CRL 定时拉取（仅 mTLS 模式下有意义）
	// 传入 ClientCA PEM，使 CRL fetcher 能验证 certsrv 的自签 TLS 证书
	var crlFetcher *CRLFetcher
	if opts.EnableMTLS && opts.CRLUrl != "" {
		interval := opts.CRLInterval
		if interval <= 0 {
			interval = 10 * time.Minute
		}
		// 读取 CA 证书 PEM（用于验证 certsrv 的 TLS 证书，避免 "unknown authority" 错误）
		var caCertPEM []byte
		if opts.ClientCAFile != "" {
			caCertPEM, _ = os.ReadFile(opts.ClientCAFile)
		}
		if opts.RequireCRL {
			crlFetcher, err = NewCRLFetcherStrict(opts.CRLUrl, interval, caCertPEM, opts.Metrics, nil)
		} else {
			crlFetcher, err = NewCRLFetcher(opts.CRLUrl, interval, caCertPEM, opts.Metrics, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("init CRL fetcher: %w", err)
		}
		injectCRLVerifier(tlsCfg, crlFetcher)
	}

	// KeyLog 启用警告（密钥日志会让所有 TLS 流量可被解密，仅供调试）
	if opts.KeyLogPath != "" {
		// 不依赖 slog（避免引入循环），直接写 stderr
		fmt.Fprintf(os.Stderr,
			"⚠️  TLS KeyLog ENABLED at %q. Anyone with read access to this file can decrypt ALL TLS traffic. USE FOR DEBUGGING ONLY.\n",
			opts.KeyLogPath)
	}

	return &serverConfig{
		tlsConfig:  tlsCfg,
		keyLog:     keyLog,
		crlFetcher: crlFetcher,
	}, nil
}
