package tls

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

//go:embed mozilla_cas.pem
var mozillaCAPEM []byte

var (
	mozillaPool     *x509.CertPool
	mozillaPoolOnce sync.Once
)

// GetMozillaCertPool 返回内嵌 Mozilla NSS 根证书池（单例，懒加载）。
func GetMozillaCertPool() *x509.CertPool {
	mozillaPoolOnce.Do(func() {
		mozillaPool = x509.NewCertPool()
		if !mozillaPool.AppendCertsFromPEM(mozillaCAPEM) {
			panic("tls: failed to parse embedded mozilla_cas.pem")
		}
	})
	return mozillaPool
}
