package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"connect-ip-tunnel/common/bufferpool"
	"connect-ip-tunnel/common/safe"
	"connect-ip-tunnel/platform/tun"
	"connect-ip-tunnel/tunnel"
)

var ErrInvalidPacketPump = errors.New("runner: invalid packet pump")

type Stats struct {
	TxPackets atomic.Uint64
	TxBytes   atomic.Uint64
	RxPackets atomic.Uint64
	RxBytes   atomic.Uint64
	Drops     atomic.Uint64
}

type PacketPump struct {
	Dev        tun.Device
	Tunnel     tunnel.PacketTunnel
	BufferSize int
	stats      Stats
}

func (p *PacketPump) Stats() *Stats {
	return &p.stats
}

// Run 启动双向包转发，优先使用批量读写接口。
func (p *PacketPump) Run(ctx context.Context) error {
	if p.Dev == nil || p.Tunnel == nil {
		return ErrInvalidPacketPump
	}

	// 检测 TUN 设备是否支持批量操作
	type batchDevice interface {
		BatchSize() int
		Read(bufs [][]byte, sizes []int, offset int) (int, error)
		Write(bufs [][]byte, offset int) (int, error)
	}

	if bd, ok := p.Dev.(batchDevice); ok {
		return p.runBatch(ctx, bd)
	}

	// 降级到单包模式
	return p.runSingle(ctx)
}

// runBatch 使用批量读写接口（高性能路径）
func (p *PacketPump) runBatch(ctx context.Context, dev interface {
	BatchSize() int
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
}) error {
	batchSize := dev.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}
	if batchSize > 128 {
		batchSize = 128 // 限制最大批量大小
	}

	bufSize := p.BufferSize
	if bufSize <= 0 {
		bufSize = 65535
	}

	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	var closeTunnelOnce sync.Once
	signalErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
		cancel()
		closeTunnelOnce.Do(func() {
			_ = p.Tunnel.Close()
		})
	}

	wg.Add(2)

	// TUN → Tunnel
	//
	// 性能说明：热路径的取消语义完全依赖 Read 在 ctx 取消时返回 error
	// （signalErr 会调用 Tunnel.Close()，TUN 侧关闭由 Engine.Close 兜底）。
	// 因此循环顶端不再做 `select { case <-pumpCtx.Done(): default: }`
	// 非阻塞探测 —— 每包省下一次 atomic load + scheduler 唤醒成本。
	safe.Go("runner.up", func() {
		defer wg.Done()
		bufs := make([][]byte, batchSize)
		for i := range bufs {
			bufs[i] = make([]byte, bufSize)
		}
		sizes := make([]int, batchSize)

		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				if pumpCtx.Err() != nil {
					return
				}
				signalErr(fmt.Errorf("packet pump tun->tunnel read: %w", err))
				return
			}

			for i := 0; i < n; i++ {
				if sizes[i] <= 0 {
					continue
				}
				if err := p.Tunnel.WritePacket(bufs[i][:sizes[i]]); err != nil {
					if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
						signalErr(fmt.Errorf("packet pump tun->tunnel write: %w", err))
						return
					}
					// 单包发送失败（如 MTU 超限被拒）视为可恢复，丢包继续。
					p.stats.Drops.Add(1)
					continue
				}
				p.stats.TxPackets.Add(1)
				p.stats.TxBytes.Add(uint64(sizes[i]))
			}
		}
	})

	// Tunnel → TUN
	// 同上：去掉每包 select ctx 探测，由 Tunnel.ReadPacket 在 ctx 取消 / Tunnel.Close() 时返回 error。
	safe.Go("runner.down", func() {
		defer wg.Done()
		buf := bufferpool.GetPacket()
		defer bufferpool.PutPacket(buf)

		for {
			n, err := p.Tunnel.ReadPacket(buf)
			if err != nil {
				if pumpCtx.Err() != nil {
					return
				}
				signalErr(fmt.Errorf("packet pump tunnel->tun read: %w", err))
				return
			}
			if n <= 0 {
				continue
			}

			// 单包写入（Tunnel 侧暂不支持批量）
			if err := p.Dev.WritePacket(buf[:n]); err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
					signalErr(fmt.Errorf("packet pump tunnel->tun write: %w", err))
					return
				}
				// 单包写 TUN 失败（如畸形包、invalid offset 边界情况）视为可恢复。
				p.stats.Drops.Add(1)
				continue
			}

			p.stats.RxPackets.Add(1)
			p.stats.RxBytes.Add(uint64(n))
		}
	})

	select {
		case <-ctx.Done():
		cancel()
		if !waitWithTimeout(&wg, 2*time.Second) {
			return ctx.Err()
		}
		return ctx.Err()
	case err := <-errCh:
		if !waitWithTimeout(&wg, 2*time.Second) {
			return fmt.Errorf("%w (peer goroutine did not exit before timeout)", err)
		}
		return err
	}
}

// runSingle 单包读写模式（兼容降级路径）
func (p *PacketPump) runSingle(ctx context.Context) error {
	bufSize := p.BufferSize
	if bufSize <= 0 {
		bufSize = 65535
	}

	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	var closeTunnelOnce sync.Once
	signalErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
		cancel()
		closeTunnelOnce.Do(func() {
			_ = p.Tunnel.Close()
		})
	}

	wg.Add(2)

	// TUN → Tunnel —— 与 runBatch 一致，去掉每包 select ctx 探测。
	safe.Go("runner.up", func() {
		defer wg.Done()
		buf := bufferpool.GetPacket()
		defer bufferpool.PutPacket(buf)

		for {
			n, err := p.Dev.ReadPacket(buf)
			if err != nil {
				if pumpCtx.Err() != nil {
					return
				}
				signalErr(fmt.Errorf("packet pump tun->tunnel read: %w", err))
				return
			}
			if n <= 0 {
				continue
			}

			if err := p.Tunnel.WritePacket(buf[:n]); err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
					signalErr(fmt.Errorf("packet pump tun->tunnel write: %w", err))
					return
				}
				p.stats.Drops.Add(1)
				continue
			}

			p.stats.TxPackets.Add(1)
			p.stats.TxBytes.Add(uint64(n))
		}
	})

	// Tunnel → TUN —— 与 runBatch 一致，去掉每包 select ctx 探测。
	safe.Go("runner.down", func() {
		defer wg.Done()
		buf := bufferpool.GetPacket()
		defer bufferpool.PutPacket(buf)

		for {
			n, err := p.Tunnel.ReadPacket(buf)
			if err != nil {
				if pumpCtx.Err() != nil {
					return
				}
				signalErr(fmt.Errorf("packet pump tunnel->tun read: %w", err))
				return
			}
			if n <= 0 {
				continue
			}

			if err := p.Dev.WritePacket(buf[:n]); err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
					signalErr(fmt.Errorf("packet pump tunnel->tun write: %w", err))
					return
				}
				p.stats.Drops.Add(1)
				continue
			}

			p.stats.RxPackets.Add(1)
			p.stats.RxBytes.Add(uint64(n))
		}
	})

	select {
		case <-ctx.Done():
		cancel()
		if !waitWithTimeout(&wg, 2*time.Second) {
			return ctx.Err()
		}
		return ctx.Err()
	case err := <-errCh:
		if !waitWithTimeout(&wg, 2*time.Second) {
			return fmt.Errorf("%w (peer goroutine did not exit before timeout)", err)
		}
		return err
	}
}

func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
