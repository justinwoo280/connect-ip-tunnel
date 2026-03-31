package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics 是全局 Prometheus 指标集合
type Metrics struct {
	// ── 会话 ──────────────────────────────────────────
	SessionsActive prometheus.Gauge
	SessionsTotal  prometheus.Counter
	SessionErrors  *prometheus.CounterVec  // label: reason
	SessionDuration *prometheus.HistogramVec // label: (无，按需扩展)

	// ── 流量 ──────────────────────────────────────────
	BytesRx   *prometheus.CounterVec // label: session_id
	BytesTx   *prometheus.CounterVec
	PacketsRx *prometheus.CounterVec
	PacketsTx *prometheus.CounterVec
	PacketDrops *prometheus.CounterVec // label: reason

	// ── IP 池 ─────────────────────────────────────────
	IPPoolAllocated *prometheus.GaugeVec // label: family (ipv4|ipv6)
	IPPoolAvailable *prometheus.GaugeVec

	// ── mTLS ──────────────────────────────────────────
	MTLSHandshakes *prometheus.CounterVec // label: status (success|failure)
	CertExpiryDays *prometheus.GaugeVec  // label: cn

	// ── 性能 ──────────────────────────────────────────
	DispatcherLookupDuration prometheus.Histogram
	PacketLatency            prometheus.Histogram

	// ── 系统 ──────────────────────────────────────────
	registry *prometheus.Registry
}

var Global *Metrics

// InitMetrics 初始化并注册所有 Prometheus 指标。
// 调用一次，通常在 main() 或 Server.Start() 早期调用。
func InitMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "connect_ip_tunnel"
	}

	reg := prometheus.NewRegistry()
	// 注册 Go runtime 和 process 默认指标
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	m := &Metrics{
		registry: reg,

		SessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "sessions_active",
			Help:      "Number of currently active sessions.",
		}),
		SessionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "sessions_total",
			Help:      "Total number of sessions established since start.",
		}),
		SessionErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "session_errors_total",
			Help:      "Total number of session errors.",
		}, []string{"reason"}),
		SessionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "session_duration_seconds",
			Help:      "Distribution of session durations in seconds.",
			Buckets:   []float64{1, 5, 30, 60, 300, 1800, 3600, 86400},
		}, []string{}),

		BytesRx: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "bytes_rx_total",
			Help:      "Total bytes received from clients (uplink).",
		}, []string{"session_id"}),
		BytesTx: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "bytes_tx_total",
			Help:      "Total bytes sent to clients (downlink).",
		}, []string{"session_id"}),
		PacketsRx: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_rx_total",
			Help:      "Total packets received from clients (uplink).",
		}, []string{"session_id"}),
		PacketsTx: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_tx_total",
			Help:      "Total packets sent to clients (downlink).",
		}, []string{"session_id"}),
		PacketDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packet_drops_total",
			Help:      "Total number of dropped packets.",
		}, []string{"reason"}),

		IPPoolAllocated: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "ippool_allocated",
			Help:      "Number of currently allocated IP addresses.",
		}, []string{"family"}),
		IPPoolAvailable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "ippool_available",
			Help:      "Number of currently available IP addresses.",
		}, []string{"family"}),

		MTLSHandshakes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "mtls_handshakes_total",
			Help:      "Total number of mTLS handshakes.",
		}, []string{"status"}),
		CertExpiryDays: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expiry_days",
			Help:      "Days until certificate expiry.",
		}, []string{"cn"}),

		DispatcherLookupDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "dispatcher_lookup_duration_microseconds",
			Help:      "Distribution of dispatcher session lookup durations.",
			Buckets:   []float64{0.5, 1, 2, 5, 10, 25, 50, 100},
		}),
		PacketLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "packet_latency_milliseconds",
			Help:      "Distribution of end-to-end packet latency.",
			Buckets:   []float64{0.5, 1, 2, 5, 10, 25, 50, 100, 250},
		}),
	}

	reg.MustRegister(
		m.SessionsActive,
		m.SessionsTotal,
		m.SessionErrors,
		m.SessionDuration,
		m.BytesRx,
		m.BytesTx,
		m.PacketsRx,
		m.PacketsTx,
		m.PacketDrops,
		m.IPPoolAllocated,
		m.IPPoolAvailable,
		m.MTLSHandshakes,
		m.CertExpiryDays,
		m.DispatcherLookupDuration,
		m.PacketLatency,
	)

	Global = m
	return m
}

// Handler 返回 Prometheus HTTP handler，挂载到 /metrics 路由。
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// ── 便捷方法 ─────────────────────────────────────────────────────────────────

// RecordSessionStart 记录一个新 session 建立。
func (m *Metrics) RecordSessionStart() {
	m.SessionsActive.Inc()
	m.SessionsTotal.Inc()
}

// RecordSessionEnd 记录一个 session 结束，dur 为本次 session 时长。
func (m *Metrics) RecordSessionEnd(sessionID string, dur time.Duration) {
	m.SessionsActive.Dec()
	m.SessionDuration.WithLabelValues().Observe(dur.Seconds())
	// 清理 per-session 向量（避免高基数标签无限增长）
	m.BytesRx.DeleteLabelValues(sessionID)
	m.BytesTx.DeleteLabelValues(sessionID)
	m.PacketsRx.DeleteLabelValues(sessionID)
	m.PacketsTx.DeleteLabelValues(sessionID)
}

// RecordSessionError 记录 session 级别错误。
func (m *Metrics) RecordSessionError(reason string) {
	m.SessionErrors.WithLabelValues(reason).Inc()
}

// AddRx 记录上行流量（client → server）。
func (m *Metrics) AddRx(sessionID string, bytes int) {
	m.BytesRx.WithLabelValues(sessionID).Add(float64(bytes))
	m.PacketsRx.WithLabelValues(sessionID).Inc()
}

// AddTx 记录下行流量（server → client）。
func (m *Metrics) AddTx(sessionID string, bytes int) {
	m.BytesTx.WithLabelValues(sessionID).Add(float64(bytes))
	m.PacketsTx.WithLabelValues(sessionID).Inc()
}

// RecordDrop 记录丢包。
func (m *Metrics) RecordDrop(reason string) {
	m.PacketDrops.WithLabelValues(reason).Inc()
}

// SetIPPoolStats 更新 IP 池使用情况。
func (m *Metrics) SetIPPoolStats(v4Allocated, v4Available, v6Allocated, v6Available int) {
	m.IPPoolAllocated.WithLabelValues("ipv4").Set(float64(v4Allocated))
	m.IPPoolAvailable.WithLabelValues("ipv4").Set(float64(v4Available))
	m.IPPoolAllocated.WithLabelValues("ipv6").Set(float64(v6Allocated))
	m.IPPoolAvailable.WithLabelValues("ipv6").Set(float64(v6Available))
}

// RecordMTLSHandshake 记录 mTLS 握手结果。
func (m *Metrics) RecordMTLSHandshake(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	m.MTLSHandshakes.WithLabelValues(status).Inc()
}

// SetCertExpiry 设置证书过期时间。
func (m *Metrics) SetCertExpiry(cn string, days float64) {
	m.CertExpiryDays.WithLabelValues(cn).Set(days)
}
