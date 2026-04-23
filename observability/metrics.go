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
	SessionDuration prometheus.Histogram // 移除 Vec，不需要标签

	// ── 流量 ──────────────────────────────────────────
	// 全局流量计数器（无 session_id 标签，降低基数）
	BytesRx   prometheus.Counter
	BytesTx   prometheus.Counter
	PacketsRx prometheus.Counter
	PacketsTx prometheus.Counter
	
	// 可选的按客户端 CN 分组的流量计数器（config-gated）
	BytesByCN   *prometheus.CounterVec // label: client_cn
	PacketsByCN *prometheus.CounterVec // label: client_cn
	
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
	
	// UDP socket buffer 实际生效值
	UDPSocketBufferBytes *prometheus.GaugeVec // label: family (ipv4|ipv6), direction (recv|send)
	
	// QUIC GSO segments 计数（可选）
	QUICGSOSegments prometheus.Counter
	
	// Dispatcher inbound channel 满时丢包计数
	DispatcherInboundFull prometheus.Counter

	// ── 系统 ──────────────────────────────────────────
	Panics                 *prometheus.CounterVec // label: component
	CRLUnavailableSeconds  prometheus.Gauge

	// IPv6 自检：在 TUN 配置完成后探测各阶段的连通性，失败时按
	// stage 分类计数。stage ∈ {gateway_ping, link_local, dad, ndp_suppress, ...}
	IPv6SelfCheckFailures *prometheus.CounterVec // label: stage

	// ── 心跳与多 session 健康 ─────────────────────────
	// SessionWorkers 是客户端各 session worker 当前所处状态的实时数。
	// label: state ∈ {connecting, healthy, reconnecting, closed}
	SessionWorkers *prometheus.GaugeVec
	// AppKeepaliveRTT 应用层心跳 ping/pong 往返时延（毫秒）。
	AppKeepaliveRTT prometheus.Histogram
	// AppKeepaliveTimeouts 应用层心跳超时累计次数（每次 ping 未收到 pong 计 1）。
	AppKeepaliveTimeouts prometheus.Counter
	// SessionReconnects 每个 session worker 重连次数，按触发原因区分。
	// label: cause ∈ {ping_timeout, read_err, write_err, stream_close, other}
	SessionReconnects *prometheus.CounterVec
	// IdleSessionsReaped 服务端清理 idle session 的累计次数。
	IdleSessionsReaped prometheus.Counter

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
		SessionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "session_duration_seconds",
			Help:      "Distribution of session durations in seconds.",
			Buckets:   []float64{1, 5, 30, 60, 300, 1800, 3600, 86400},
		}),

		BytesRx: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "bytes_rx_total",
			Help:      "Total bytes received from clients (uplink).",
		}),
		BytesTx: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "bytes_tx_total",
			Help:      "Total bytes sent to clients (downlink).",
		}),
		PacketsRx: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_rx_total",
			Help:      "Total packets received from clients (uplink).",
		}),
		PacketsTx: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_tx_total",
			Help:      "Total packets sent to clients (downlink).",
		}),
		
		// Optional per-client CN metrics (nil by default, created when enabled)
		BytesByCN: nil,
		PacketsByCN: nil,
		
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
		
		UDPSocketBufferBytes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "udp_socket_buffer_bytes",
			Help:      "Actual UDP socket buffer sizes achieved.",
		}, []string{"family", "direction"}),
		
		QUICGSOSegments: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "quic_gso_segments_total",
			Help:      "Total number of QUIC GSO segments sent (Linux UDP_SEGMENT).",
		}),
		
		DispatcherInboundFull: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "dispatcher_inbound_full_total",
			Help:      "Total number of packets dropped due to dispatcher inbound channel full.",
		}),

		Panics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "panics_total",
			Help:      "Total number of recovered panics.",
		}, []string{"component"}),
		CRLUnavailableSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "crl_unavailable_seconds",
			Help:      "Seconds since last successful CRL fetch (0 if never fetched).",
		}),
		IPv6SelfCheckFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "ipv6_self_check_failures_total",
			Help:      "Total number of IPv6 self-check failures after TUN setup, by stage.",
		}, []string{"stage"}),

		SessionWorkers: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "session_workers",
			Help:      "Current number of client session workers in each state.",
		}, []string{"state"}),
		AppKeepaliveRTT: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "app_keepalive_rtt_ms",
			Help:      "Application-layer keepalive ping/pong round-trip time in milliseconds.",
			Buckets:   []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		}),
		AppKeepaliveTimeouts: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "app_keepalive_timeouts_total",
			Help:      "Total number of application-layer keepalive ping timeouts.",
		}),
		SessionReconnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "session_reconnects_total",
			Help:      "Total number of client session worker reconnects, by cause.",
		}, []string{"cause"}),
		IdleSessionsReaped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "idle_sessions_reaped_total",
			Help:      "Total number of idle sessions reaped by the server.",
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
		m.UDPSocketBufferBytes,
		m.QUICGSOSegments,
		m.DispatcherInboundFull,
		m.Panics,
		m.CRLUnavailableSeconds,
		m.IPv6SelfCheckFailures,
		m.SessionWorkers,
		m.AppKeepaliveRTT,
		m.AppKeepaliveTimeouts,
		m.SessionReconnects,
		m.IdleSessionsReaped,
	)

	Global = m
	return m
}

// EnablePerCNMetrics 启用按客户端 CN 分组的流量统计。
// 必须在 InitMetrics 之后、开始记录指标之前调用。
func (m *Metrics) EnablePerCNMetrics(namespace string) {
	if namespace == "" {
		namespace = "connect_ip_tunnel"
	}
	
	m.BytesByCN = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "bytes_by_cn_total",
		Help:      "Total bytes by client CN (optional, config-gated).",
	}, []string{"client_cn"})
	
	m.PacketsByCN = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "packets_by_cn_total",
		Help:      "Total packets by client CN (optional, config-gated).",
	}, []string{"client_cn"})
	
	m.registry.MustRegister(m.BytesByCN, m.PacketsByCN)
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
func (m *Metrics) RecordSessionEnd(dur time.Duration) {
	m.SessionsActive.Dec()
	m.SessionDuration.Observe(dur.Seconds())
	// 注意：BytesRx/BytesTx/PacketsRx/PacketsTx 现在是全局 Counter，无需清理
	// BytesByCN/PacketsByCN 如果启用，也不需要在这里清理（由配置决定是否启用）
}

// RecordSessionError 记录 session 级别错误。
func (m *Metrics) RecordSessionError(reason string) {
	m.SessionErrors.WithLabelValues(reason).Inc()
}

// AddRx 记录上行流量（client → server）。
// cn 是客户端证书的 CN（Common Name），用于可选的 per-CN 统计。
func (m *Metrics) AddRx(cn string, bytes int) {
	m.BytesRx.Add(float64(bytes))
	m.PacketsRx.Inc()
	
	// 如果启用了 per-CN 统计，同时记录到 BytesByCN/PacketsByCN
	if m.BytesByCN != nil {
		m.BytesByCN.WithLabelValues(cn).Add(float64(bytes))
	}
	if m.PacketsByCN != nil {
		m.PacketsByCN.WithLabelValues(cn).Inc()
	}
}

// AddTx 记录下行流量（server → client）。
// cn 是客户端证书的 CN（Common Name），用于可选的 per-CN 统计。
func (m *Metrics) AddTx(cn string, bytes int) {
	m.BytesTx.Add(float64(bytes))
	m.PacketsTx.Inc()
	
	// 如果启用了 per-CN 统计，同时记录到 BytesByCN/PacketsByCN
	if m.BytesByCN != nil {
		m.BytesByCN.WithLabelValues(cn).Add(float64(bytes))
	}
	if m.PacketsByCN != nil {
		m.PacketsByCN.WithLabelValues(cn).Inc()
	}
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

// SetUDPSocketBuffer 设置 UDP socket buffer 实际生效值。
// family: "ipv4" 或 "ipv6"
// direction: "recv" 或 "send"
func (m *Metrics) SetUDPSocketBuffer(family, direction string, bytes int) {
	m.UDPSocketBufferBytes.WithLabelValues(family, direction).Set(float64(bytes))
}

// RecordGSOSegments 记录 GSO segments 发送数量。
func (m *Metrics) RecordGSOSegments(count int) {
	m.QUICGSOSegments.Add(float64(count))
}

// RecordDispatcherInboundFull 记录 dispatcher inbound channel 满时的丢包。
func (m *Metrics) RecordDispatcherInboundFull() {
	m.DispatcherInboundFull.Inc()
}

// RecordIPv6SelfCheckFailure 记录一次 IPv6 自检失败，按阶段分类。
// 推荐 stage 取值：gateway_ping / link_local / dad / ndp_suppress / route_present。
func (m *Metrics) RecordIPv6SelfCheckFailure(stage string) {
	if m == nil || m.IPv6SelfCheckFailures == nil {
		return
	}
	m.IPv6SelfCheckFailures.WithLabelValues(stage).Inc()
}

// SetSessionWorkerState 把单个 worker 在状态机里的迁移反映到 SessionWorkers gauge：
// 旧状态 -1，新状态 +1。允许 prev / next 同名（结果是 no-op）。
//
// 调用约束：每次状态切换调用一次；初始进入第一个状态时把 prev 传 ""。
func (m *Metrics) SetSessionWorkerState(prev, next string) {
	if m == nil || m.SessionWorkers == nil {
		return
	}
	if prev == next {
		return
	}
	if prev != "" {
		m.SessionWorkers.WithLabelValues(prev).Dec()
	}
	if next != "" {
		m.SessionWorkers.WithLabelValues(next).Inc()
	}
}

// ObserveAppKeepaliveRTT 记录一次心跳 RTT（毫秒）。
func (m *Metrics) ObserveAppKeepaliveRTT(rtt time.Duration) {
	if m == nil || m.AppKeepaliveRTT == nil {
		return
	}
	m.AppKeepaliveRTT.Observe(float64(rtt.Milliseconds()))
}

// IncAppKeepaliveTimeout 记录一次心跳超时（每次 checkTimeouts 检测到 ≥1 条 ping
// 超时即调用一次；连续 N 次后由上层触发重连）。
func (m *Metrics) IncAppKeepaliveTimeout() {
	if m == nil || m.AppKeepaliveTimeouts == nil {
		return
	}
	m.AppKeepaliveTimeouts.Inc()
}

// IncSessionReconnect 记录一次客户端 session worker 重连，按触发原因区分。
func (m *Metrics) IncSessionReconnect(cause string) {
	if m == nil || m.SessionReconnects == nil {
		return
	}
	m.SessionReconnects.WithLabelValues(cause).Inc()
}

// AddIdleSessionsReaped 记录服务端 idle reaper 本轮回收的 session 数量。
func (m *Metrics) AddIdleSessionsReaped(n int) {
	if m == nil || m.IdleSessionsReaped == nil || n <= 0 {
		return
	}
	m.IdleSessionsReaped.Add(float64(n))
}
