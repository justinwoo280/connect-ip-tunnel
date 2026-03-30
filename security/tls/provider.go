package tls

import (
	"context"
	"crypto/tls"
	"fmt"
)

// Provider 负责构造客户端 TLS 配置。
type Provider interface {
	NewClient(ctx context.Context, opts ClientOptions) (ClientConfig, error)
}

// ClientConfig 是可供 QUIC / HTTP3 消费的 TLS 客户端配置句柄。
type ClientConfig interface {
	TLSConfig() *tls.Config
	HandleHandshakeError(err error) (retry bool, outErr error)
	Close() error
}

// NewClient 是便捷函数，直接从 ClientOptions 构建 ClientConfig。
// 处理顺序：
//  1. EnableECH=false → 标准 TLS（无 ECH）
//  2. EnableECH=true + ECHConfigList 非空 → 静态 ECH 配置
//  3. EnableECH=true + ECHManager 非空 → 动态 ECH（DoH 自动刷新）
//  4. EnableECH=true 但无配置来源 → 降级为标准 TLS
func NewClient(opts ClientOptions) (ClientConfig, error) {
	return NewProvider().NewClient(context.Background(), opts)
}

// buildECHTLSConfig 在基础 tls.Config 上叠加 ECH 配置。
func buildECHTLSConfig(base *tls.Config, echList []byte) *tls.Config {
	cfg := base.Clone()
	cfg.EncryptedClientHelloConfigList = echList
	cfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
		return fmt.Errorf("tls: server rejected ECH")
	}
	return cfg
}
