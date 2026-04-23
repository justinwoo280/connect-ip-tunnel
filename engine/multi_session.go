package engine

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"connect-ip-tunnel/observability"
	"connect-ip-tunnel/option"
	"connect-ip-tunnel/tunnel/connectip"
)

// workerState 表示 SessionWorker 的状态
type workerState int32

const (
	stateConnecting workerState = iota
	stateHealthy
	stateReconnecting
	stateClosed
)

func (s workerState) String() string {
	switch s {
	case stateConnecting:
		return "connecting"
	case stateHealthy:
		return "healthy"
	case stateReconnecting:
		return "reconnecting"
	case stateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// SessionWorker 管理单个 session 的生命周期（dial → health-check → retire）
type SessionWorker struct {
	idx        int
	dialFn     func(ctx context.Context) (*connectip.Session, error)
	cfg        option.ConnectIPConfig
	state      atomic.Int32 // workerState
	sess       atomic.Pointer[connectip.Session]
	lastActive atomic.Int64 // unix nano
	
	cancel     context.CancelFunc
	done       chan struct{}
	mu         sync.Mutex
}

// NewSessionWorker 创建一个新的 SessionWorker
func NewSessionWorker(idx int, dialFn func(ctx context.Context) (*connectip.Session, error), cfg option.ConnectIPConfig) *SessionWorker {
	return &SessionWorker{
		idx:    idx,
		dialFn: dialFn,
		cfg:    cfg,
		done:   make(chan struct{}),
	}
}

// Start 启动 worker 的主循环
func (w *SessionWorker) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	
	go w.runSupervisorLoop(workerCtx)
}

// runSupervisorLoop 是 worker 的主循环：dial → healthy → reconnecting → dial
func (w *SessionWorker) runSupervisorLoop(ctx context.Context) {
	defer close(w.done)
	
	backoff := time.Second
	const (
		maxBackoff              = 30 * time.Second
		stableConnectionResetAt = 30 * time.Second
	)
	
	for {
		select {
		case <-ctx.Done():
			w.transition(stateClosed)
			return
		default:
		}

		// 设置为 connecting 状态
		w.transition(stateConnecting)

		startedAt := time.Now()

		// 尝试建立连接
		dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
		sess, err := w.dialFn(dialCtx)
		dialCancel()

		if err != nil {
			log.Printf("[engine] session[%d] dial failed: %v, retrying in %v", w.idx, err, backoff)

			// 指数退避
			jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
			wait := backoff + jitter
			if wait > w.cfg.MaxReconnectDelay.Duration {
				wait = w.cfg.MaxReconnectDelay.Duration
			}

			select {
			case <-ctx.Done():
				w.transition(stateClosed)
				return
			case <-time.After(wait):
			}

			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("[engine] session[%d] established", w.idx)

		// 连接成功，设置为 healthy
		w.sess.Store(sess)
		w.transition(stateHealthy)
		w.lastActive.Store(time.Now().UnixNano())

		// 心跳功能暂时禁用，等待实现基于 IP 包的心跳
		// TODO: 实现基于 IP 协议号 253 的心跳机制

		// 等待连接失败或上下文取消
		<-sess.Done()

		// 连接断开 → 进入 reconnecting，并把"重连"事件计入 metric。
		// 当前没法精准区分原因（read_err vs write_err vs ping_timeout），统一标记为
		// "stream_close"；后续如果在 session 上暴露 close cause 可以细化。
		w.transition(stateReconnecting)
		w.sess.Store(nil)
		observability.Global.IncSessionReconnect("stream_close")

		log.Printf("[engine] session[%d] disconnected, reconnecting...", w.idx)

		// 如果连接稳定超过 30s，重置 backoff
		if time.Since(startedAt) >= stableConnectionResetAt {
			backoff = time.Second
		}
	}
}

// Stop 停止 worker
func (w *SessionWorker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	<-w.done
}

// Healthy 返回 worker 是否健康
func (w *SessionWorker) Healthy() bool {
	return workerState(w.state.Load()) == stateHealthy
}

// Get 返回当前的 session（可能为 nil）
func (w *SessionWorker) Get() *connectip.Session {
	return w.sess.Load()
}

// State 返回当前状态
func (w *SessionWorker) State() workerState {
	return workerState(w.state.Load())
}

// transition 把 worker 状态机转到 next，并把对应的 prev/next gauge 调整反映到
// observability.Global.SessionWorkers。同时把日志统一一行，便于运维排查。
//
// 调用约束：runSupervisorLoop 内部任何状态切换都必须经过这里，避免漏埋点。
func (w *SessionWorker) transition(next workerState) {
	prev := workerState(w.state.Swap(int32(next)))
	if prev == next {
		return
	}
	observability.Global.SetSessionWorkerState(prev.String(), next.String())
}

// MultiSessionSupervisor 维护 N 个 SessionWorker 的状态表
type MultiSessionSupervisor struct {
	workers     []*SessionWorker
	distributor *FlowDistributor
	n           int
	
	closed  atomic.Bool
	closeCh chan struct{}
	closeMu sync.Mutex
}

// NewMultiSessionSupervisor 创建一个新的 supervisor
func NewMultiSessionSupervisor(n int, dialFn func(ctx context.Context) (*connectip.Session, error), cfg option.ConnectIPConfig) *MultiSessionSupervisor {
	if n <= 0 {
		n = 1
	}
	
	workers := make([]*SessionWorker, n)
	for i := 0; i < n; i++ {
		workers[i] = NewSessionWorker(i, dialFn, cfg)
	}
	
	return &MultiSessionSupervisor{
		workers:     workers,
		distributor: newFlowDistributor(n),
		n:           n,
		closeCh:     make(chan struct{}),
	}
}

// Start 启动所有 workers
func (s *MultiSessionSupervisor) Start(ctx context.Context) {
	for _, w := range s.workers {
		w.Start(ctx)
	}
}

// WritePacket 将 IP 包按 flow hash 写入对应的健康 session
func (s *MultiSessionSupervisor) WritePacket(pkt []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("supervisor closed")
	}
	
	idx := s.distributor.Select(pkt)
	worker := s.workers[idx]
	
	// 如果选中的 worker 不健康，尝试找一个健康的
	if !worker.Healthy() {
		for i := 0; i < s.n; i++ {
			if s.workers[i].Healthy() {
				worker = s.workers[i]
				break
			}
		}
	}
	
	sess := worker.Get()
	if sess == nil {
		return fmt.Errorf("no healthy session available")
	}
	
	return sess.WritePacket(pkt)
}

// ReadFrom 从指定 worker 读取下行包
func (s *MultiSessionSupervisor) ReadFrom(idx int, buf []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("supervisor closed")
	}
	
	if idx < 0 || idx >= s.n {
		return 0, fmt.Errorf("invalid worker index: %d", idx)
	}
	
	worker := s.workers[idx]
	sess := worker.Get()
	if sess == nil {
		// Worker 正在重连，等待一小段时间
		time.Sleep(100 * time.Millisecond)
		sess = worker.Get()
		if sess == nil {
			return 0, fmt.Errorf("session[%d] not available", idx)
		}
	}
	
	return sess.ReadPacket(buf)
}

// Close 关闭所有 workers
func (s *MultiSessionSupervisor) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	
	if s.closed.Load() {
		return nil
	}
	
	s.closed.Store(true)
	close(s.closeCh)
	
	for _, w := range s.workers {
		w.Stop()
		if sess := w.Get(); sess != nil {
			_ = sess.Close()
		}
	}
	
	return nil
}

// Done 返回 supervisor 关闭的 channel
func (s *MultiSessionSupervisor) Done() <-chan struct{} {
	return s.closeCh
}

// WorkerCount 返回 worker 数量
func (s *MultiSessionSupervisor) WorkerCount() int {
	return s.n
}

// GetHealthyWorkers 返回健康的 worker 索引列表
func (s *MultiSessionSupervisor) GetHealthyWorkers() []int {
	var healthy []int
	for i, w := range s.workers {
		if w.Healthy() {
			healthy = append(healthy, i)
		}
	}
	return healthy
}

// WaitForFirstHealthy 等待至少一个 worker 变为 healthy
func (s *MultiSessionSupervisor) WaitForFirstHealthy(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for _, w := range s.workers {
				if w.Healthy() {
					return nil
				}
			}
		}
	}
}

// ── 兼容旧代码的类型别名 ──────────────────────────────────────────────────────

// MultiSessionPool 是 MultiSessionSupervisor 的别名，用于向后兼容
type MultiSessionPool = MultiSessionSupervisor

// newMultiSessionPool 创建一个新的 supervisor（兼容旧代码）
func newMultiSessionPool(sessions []*connectip.Session) *MultiSessionPool {
	// 这个函数在新架构中不再使用，但保留以避免编译错误
	// 实际使用时应该用 NewMultiSessionSupervisor
	panic("newMultiSessionPool is deprecated, use NewMultiSessionSupervisor instead")
}

// buildSessionsParallel 已废弃，使用 NewMultiSessionSupervisor 替代
func buildSessionsParallel(ctx context.Context, n int, dialFn func(ctx context.Context) (*connectip.Session, error)) (*MultiSessionPool, error) {
	// 这个函数在新架构中不再使用
	panic("buildSessionsParallel is deprecated, use NewMultiSessionSupervisor instead")
}
