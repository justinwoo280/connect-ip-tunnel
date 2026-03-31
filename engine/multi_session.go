package engine

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"connect-ip-tunnel/tunnel/connectip"
)

// MultiSessionPool 维护 N 个并行 CONNECT-IP session，
// 通过 FlowDistributor 将上行包按五元组哈希分发到各 session，
// 充分利用多核、多 QUIC 连接的并行能力。
type MultiSessionPool struct {
	sessions    []*connectip.Session
	distributor *FlowDistributor
	n           int

	mu      sync.RWMutex
	closed  bool
	closeCh chan struct{}
}

// newMultiSessionPool 创建并返回一个 N 个 session 的并行池。
// sessions 切片必须已经建立完毕。
func newMultiSessionPool(sessions []*connectip.Session) *MultiSessionPool {
	n := len(sessions)
	if n == 0 {
		panic("newMultiSessionPool: sessions must not be empty")
	}
	return &MultiSessionPool{
		sessions:    sessions,
		distributor: newFlowDistributor(n),
		n:           n,
		closeCh:     make(chan struct{}),
	}
}

// WritePacket 将 IP 包按 flow hash 写入对应 session（上行，client→server）。
func (p *MultiSessionPool) WritePacket(pkt []byte) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("multi session pool closed")
	}
	idx := p.distributor.Select(pkt)
	sess := p.sessions[idx]
	p.mu.RUnlock()
	return sess.WritePacket(pkt)
}

// ReadFrom 从指定 session 读取下行包（server→client）。
// 由 aggregator goroutine 调用，每个 session 一个独立 goroutine。
func (p *MultiSessionPool) ReadFrom(idx int, buf []byte) (int, error) {
	p.mu.RLock()
	if p.closed || idx >= p.n {
		p.mu.RUnlock()
		return 0, fmt.Errorf("multi session pool closed or invalid index")
	}
	sess := p.sessions[idx]
	p.mu.RUnlock()
	return sess.ReadPacket(buf)
}

// Close 关闭所有 session。
func (p *MultiSessionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.closeCh)
	var lastErr error
	for _, sess := range p.sessions {
		if err := sess.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Done 返回池关闭的 channel，外层可用于 select 感知关闭。
func (p *MultiSessionPool) Done() <-chan struct{} {
	return p.closeCh
}

// SessionCount 返回当前 session 数量。
func (p *MultiSessionPool) SessionCount() int {
	return p.n
}

// ── 连接建立辅助 ──────────────────────────────────────────────────────────────

// dialResult 单个 session 建立结果。
type dialResult struct {
	idx  int
	sess *connectip.Session
	err  error
}

// buildSessionsParallel 并发建立 n 个 session，全部成功才返回池。
// dialFn 由调用方提供，封装了 HTTP/3 拨号和 CONNECT-IP 握手逻辑。
func buildSessionsParallel(ctx context.Context, n int, dialFn func(ctx context.Context) (*connectip.Session, error)) (*MultiSessionPool, error) {
	if n <= 0 {
		n = 1
	}

	results := make(chan dialResult, n)
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for i := 0; i < n; i++ {
		go func(idx int) {
			sess, err := dialFn(dialCtx)
			results <- dialResult{idx: idx, sess: sess, err: err}
		}(i)
	}

	sessions := make([]*connectip.Session, n)
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			// 有一个失败则取消其他，并关闭已建立的
			cancel()
			for j := 0; j < n; j++ {
				if j == i {
					continue
				}
				// 等待剩余 goroutine，关闭已建立的 session
				remaining := <-results
				if remaining.sess != nil {
					_ = remaining.sess.Close()
				}
			}
			return nil, fmt.Errorf("session[%d] dial failed: %w", r.idx, r.err)
		}
		sessions[r.idx] = r.sess
		log.Printf("[engine] multi-session[%d/%d] established", r.idx+1, n)
	}

	return newMultiSessionPool(sessions), nil
}
