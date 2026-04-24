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

	"connect-ip-tunnel/common/safe"
	"connect-ip-tunnel/observability"
)

// CRLFetcher 定时从 URL 拉取 CRL 并缓存，
// 通过 VerifyFunc 提供给 tls.Config.VerifyPeerCertificate 使用。
type CRLFetcher struct {
	mu         sync.RWMutex
	url        string
	interval   time.Duration
	crl        *x509.RevocationList
	log        *slog.Logger
	stopCh     chan struct{}
	httpClient *http.Client // 携带自定义 CA，用于访问自签证书的 certsrv
	metrics    *observability.Metrics

	// require 为 true 时进入严格模式：CRL 不可用 → 拒绝所有连接；
	// 为 false 时为宽松模式：CRL 未拉取成功时放行（向后兼容）。
	require bool

	// 可观测性字段
	startedAt          time.Time // 启动时间
	firstFetchSuccessAt time.Time // 首次成功拉取时间
	lastFetchSuccessAt  time.Time // 最近一次成功拉取时间
	lastErrLogTime      time.Time // 最近一次 ERROR 日志时间（用于去重）
}

// NewCRLFetcher 创建并启动 CRL 定时拉取器。
// url：CRL PEM 文件的 HTTP(S) 地址（如 https://127.0.0.1:8443/crl.pem）
// interval：拉取间隔（建议 5~30 分钟）
// caCertPEM：访问 certsrv 时使用的 CA 证书（PEM 格式），为 nil 时使用系统 CA 池
// metrics：Prometheus metrics 实例（可为 nil，此时不上报 metric）
//
// 初始拉取失败不阻塞启动：certsrv 可能比主服务晚启动，
// 此时 crl 为 nil，VerifyFunc 会放行所有连接（宽松模式），
// 后台 loop 会持续重试直到拉取成功。
// NewCRLFetcherStrict 与 NewCRLFetcher 相同，但启用严格模式。
// 严格模式下，CRL 未成功拉取时所有 TLS 握手都会被拒绝。
func NewCRLFetcherStrict(url string, interval time.Duration, caCertPEM []byte, metrics *observability.Metrics, log *slog.Logger) (*CRLFetcher, error) {
	f, err := NewCRLFetcher(url, interval, caCertPEM, metrics, log)
	if err != nil {
		return nil, err
	}
	f.require = true
	return f, nil
}

func NewCRLFetcher(url string, interval time.Duration, caCertPEM []byte, metrics *observability.Metrics, log *slog.Logger) (*CRLFetcher, error) {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 10 * time.Minute
	}

	// 构建 HTTP 客户端：若提供了 CA 证书则用自定义 CA 池，避免自签证书验证失败
	httpClient := &http.Client{Timeout: 15 * time.Second}
	if len(caCertPEM) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCertPEM) {
			log.Warn("CRLFetcher: failed to parse CA cert PEM, falling back to system CA pool")
		} else {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			}
		}
	}

	f := &CRLFetcher{
		url:        url,
		interval:   interval,
		log:        log,
		stopCh:     make(chan struct{}),
		httpClient: httpClient,
		metrics:    metrics,
		startedAt:  time.Now(),
	}
	// 尝试初始拉取，失败时只打警告，不阻塞启动
	if err := f.fetch(); err != nil {
		log.Warn("initial CRL fetch failed, will retry in background (connections allowed until CRL is available)",
			"url", url, "err", err)
	}
	safe.Go("crl.fetcher", func() {
		f.loop()
	})
	safe.Go("crl.metric", func() {
		f.metricLoop()
	})
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
			// 严格模式：拒绝所有连接，直到 CRL 可用
			if f.require {
				return fmt.Errorf("tls: CRL not yet available, refusing connection (strict mode)")
			}
			// 宽松模式（默认）：放行，避免 certsrv 启动慢阻塞主服务
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
				// 检查是否需要输出 ERROR 日志
				f.checkAndLogError()
			} else {
				timer.Reset(f.interval)
			}
		case <-f.stopCh:
			return
		}
	}
}

// checkAndLogError 检查 CRL 是否长时间未成功拉取，输出 ERROR 日志（带去重）
func (f *CRLFetcher) checkAndLogError() {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// 启动超过 5 分钟且从未成功拉取过
	if time.Since(f.startedAt) > 5*time.Minute && f.firstFetchSuccessAt.IsZero() {
		// 去重：每 5 分钟最多输出一次 ERROR
		if time.Since(f.lastErrLogTime) >= 5*time.Minute {
			f.log.Error("CRL has never been fetched successfully for >5min, certificate revocation enforcement is disabled",
				"url", f.url,
				"elapsed", time.Since(f.startedAt).Round(time.Second))
			f.lastErrLogTime = time.Now()
		}
	}
}

// metricLoop 定期上报 CRL 不可用时长 metric
func (f *CRLFetcher) metricLoop() {
	if f.metrics == nil {
		return // 没有 metrics 实例，不上报
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.mu.RLock()
			var unavailableSince time.Time
			if f.lastFetchSuccessAt.IsZero() {
				unavailableSince = f.startedAt
			} else {
				unavailableSince = f.lastFetchSuccessAt
			}
			f.mu.RUnlock()

			// 上报不可用时长（秒）
			unavailableSeconds := time.Since(unavailableSince).Seconds()
			f.metrics.CRLUnavailableSeconds.Set(unavailableSeconds)
		case <-f.stopCh:
			return
		}
	}
}

// fetch 从 URL 下载并解析 CRL
func (f *CRLFetcher) fetch() error {
	resp, err := f.httpClient.Get(f.url)
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
	// 更新成功时间戳
	now := time.Now()
	if f.firstFetchSuccessAt.IsZero() {
		f.firstFetchSuccessAt = now
	}
	f.lastFetchSuccessAt = now
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
