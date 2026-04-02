package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// CRLFetcher 定时从 URL 拉取 CRL 并缓存，
// 通过 VerifyFunc 提供给 tls.Config.VerifyPeerCertificate 使用。
type CRLFetcher struct {
	mu       sync.RWMutex
	url      string
	interval time.Duration
	crl      *x509.RevocationList
	log      *slog.Logger
	stopCh   chan struct{}
}

// NewCRLFetcher 创建并启动 CRL 定时拉取器。
// url：CRL PEM 文件的 HTTP(S) 地址（如 http://certsrv:8443/crl.pem）
// interval：拉取间隔（建议 5~30 分钟）
//
// 初始拉取失败不阻塞启动：certsrv 可能比主服务晚启动，
// 此时 crl 为 nil，VerifyFunc 会放行所有连接（宽松模式），
// 后台 loop 会持续重试直到拉取成功。
func NewCRLFetcher(url string, interval time.Duration, log *slog.Logger) (*CRLFetcher, error) {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	f := &CRLFetcher{
		url:      url,
		interval: interval,
		log:      log,
		stopCh:   make(chan struct{}),
	}
	// 尝试初始拉取，失败时只打警告，不阻塞启动
	// certsrv 可能与主服务并行启动，稍后会在后台 loop 中重试
	if err := f.fetch(); err != nil {
		log.Warn("initial CRL fetch failed, will retry in background (connections allowed until CRL is available)",
			"url", url, "err", err)
	}
	go f.loop()
	return f, nil
}

// Stop 停止后台定时拉取
func (f *CRLFetcher) Stop() {
	close(f.stopCh)
}

// VerifyFunc 返回一个可以直接赋给 tls.Config.VerifyPeerCertificate 的函数。
// 该函数在 TLS 握手完成后被调用，检查客户端证书是否在 CRL 中被吊销。
func (f *CRLFetcher) VerifyFunc() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		f.mu.RLock()
		crl := f.crl
		f.mu.RUnlock()

		if crl == nil {
			// 没有 CRL 则放行（宽松模式）
			return nil
		}

		// 检查所有已验证链中的叶子证书
		for _, chain := range verifiedChains {
			if len(chain) == 0 {
				continue
			}
			leaf := chain[0]
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return fmt.Errorf("tls: client certificate revoked (serial=%s, CN=%s)",
						leaf.SerialNumber.Text(16), leaf.Subject.CommonName)
				}
			}
		}

		// 无 verifiedChains 时直接解析 rawCerts（mTLS RequireAndVerify 下通常有 verifiedChains）
		if len(verifiedChains) == 0 && len(rawCerts) > 0 {
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("tls: parse client cert: %w", err)
			}
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("tls: client certificate revoked (serial=%s, CN=%s)",
						cert.SerialNumber.Text(16), cert.Subject.CommonName)
				}
			}
		}

		return nil
	}
}

// loop 后台定时拉取
// 若 CRL 尚未成功拉取过（crl == nil），使用短间隔（30s）快速重试；
// 拉取成功后切换为正常间隔。
func (f *CRLFetcher) loop() {
	retryInterval := 30 * time.Second
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			if err := f.fetch(); err != nil {
				f.mu.RLock()
				hasCRL := f.crl != nil
				f.mu.RUnlock()
				if hasCRL {
					f.log.Warn("CRL refresh failed, using cached CRL", "err", err)
					timer.Reset(f.interval)
				} else {
					// 还没拿到过 CRL，快速重试
					f.log.Warn("CRL fetch failed, retrying soon", "err", err, "retry_in", retryInterval)
					timer.Reset(retryInterval)
				}
			} else {
				timer.Reset(f.interval)
			}
		case <-f.stopCh:
			return
		}
	}
}

// fetch 从 URL 下载并解析 CRL
func (f *CRLFetcher) fetch() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(f.url)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 最大 4MB
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	// 支持 PEM 和 DER 两种格式
	var derBytes []byte
	block, _ := pem.Decode(data)
	if block != nil {
		derBytes = block.Bytes
	} else {
		derBytes = data // 尝试直接当 DER 解析
	}

	crl, err := x509.ParseRevocationList(derBytes)
	if err != nil {
		return fmt.Errorf("parse CRL: %w", err)
	}

	// 检查 CRL 是否已过期
	if time.Now().After(crl.NextUpdate) {
		f.log.Warn("fetched CRL is expired", "next_update", crl.NextUpdate)
	}

	f.mu.Lock()
	f.crl = crl
	f.mu.Unlock()

	f.log.Info("CRL refreshed",
		"url", f.url,
		"revoked_count", len(crl.RevokedCertificateEntries),
		"next_update", crl.NextUpdate.Format(time.RFC3339),
	)
	return nil
}

// injectCRLVerifier 将 CRL 验证函数注入到 tls.Config
func injectCRLVerifier(cfg *tls.Config, fetcher *CRLFetcher) {
	existing := cfg.VerifyPeerCertificate
	crlVerify := fetcher.VerifyFunc()

	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// 先执行已有的验证逻辑
		if existing != nil {
			if err := existing(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		// 再执行 CRL 检查
		return crlVerify(rawCerts, verifiedChains)
	}
}
