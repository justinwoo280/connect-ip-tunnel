package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerConfig TLS 服务端配置接口
type ServerConfig interface {
	TLSConfig() *tls.Config
	Close() error
}

type serverConfig struct {
	tlsConfig *tls.Config
	keyLog    *os.File
}

func (s *serverConfig) TLSConfig() *tls.Config {
	return s.tlsConfig
}

func (s *serverConfig) Close() error {
	if s.keyLog != nil {
		return s.keyLog.Close()
	}
	return nil
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

	// 启用 mTLS：要求客户端提供有效证书并进行验证
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	// 使用系统根证书作为客户端 CA（如果需要自定义，可在未来扩展）
	if roots, err := x509.SystemCertPool(); err == nil && roots != nil {
		tlsCfg.ClientCAs = roots
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

	return &serverConfig{
		tlsConfig: tlsCfg,
		keyLog:    keyLog,
	}, nil
}
