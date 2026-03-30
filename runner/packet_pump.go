package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"connect-ip-tunnel/common/bufferpool"
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

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// TUN → Tunnel
	go func() {
		defer wg.Done()
		bufs := make([][]byte, batchSize)
		for i := range bufs {
			bufs[i] = make([]byte, bufSize)
		}
		sizes := make([]int, batchSize)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				errCh <- fmt.Errorf("packet pump tun->tunnel read: %w", err)
				return
			}

			for i := 0; i < n; i++ {
				if sizes[i] <= 0 {
					continue
				}
				if err := p.Tunnel.WritePacket(bufs[i][:sizes[i]]); err != nil {
					p.stats.Drops.Add(1)
					// 单包失败不中断整个批次
					continue
				}
				p.stats.TxPackets.Add(1)
				p.stats.TxBytes.Add(uint64(sizes[i]))
			}
		}
	}()

	// Tunnel → TUN
	go func() {
		defer wg.Done()
		buf := bufferpool.GetPacket()
		defer bufferpool.PutPacket(buf)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := p.Tunnel.ReadPacket(buf)
			if err != nil {
				errCh <- fmt.Errorf("packet pump tunnel->tun read: %w", err)
				return
			}
			if n <= 0 {
				continue
			}

			// 单包写入（Tunnel 侧暂不支持批量）
			if err := p.Dev.WritePacket(buf[:n]); err != nil {
				p.stats.Drops.Add(1)
				errCh <- fmt.Errorf("packet pump tunnel->tun write: %w", err)
				return
			}

			p.stats.RxPackets.Add(1)
			p.stats.RxBytes.Add(uint64(n))
		}
	}()

	select {
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	case err := <-errCh:
		wg.Wait()
		return err
	}
}

// runSingle 单包读写模式（兼容降级路径）
func (p *PacketPump) runSingle(ctx context.Context) error {
	bufSize := p.BufferSize
	if bufSize <= 0 {
		bufSize = 65535
	}

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// TUN → Tunnel
	go func() {
		defer wg.Done()
		buf := bufferpool.GetPacket()
		defer bufferpool.PutPacket(buf)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := p.Dev.ReadPacket(buf)
			if err != nil {
				errCh <- fmt.Errorf("packet pump tun->tunnel read: %w", err)
				return
			}
			if n <= 0 {
				continue
			}

			if err := p.Tunnel.WritePacket(buf[:n]); err != nil {
				p.stats.Drops.Add(1)
				errCh <- fmt.Errorf("packet pump tun->tunnel write: %w", err)
				return
			}

			p.stats.TxPackets.Add(1)
			p.stats.TxBytes.Add(uint64(n))
		}
	}()

	// Tunnel → TUN
	go func() {
		defer wg.Done()
		buf := bufferpool.GetPacket()
		defer bufferpool.PutPacket(buf)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := p.Tunnel.ReadPacket(buf)
			if err != nil {
				errCh <- fmt.Errorf("packet pump tunnel->tun read: %w", err)
				return
			}
			if n <= 0 {
				continue
			}

			if err := p.Dev.WritePacket(buf[:n]); err != nil {
				p.stats.Drops.Add(1)
				errCh <- fmt.Errorf("packet pump tunnel->tun write: %w", err)
				return
			}

			p.stats.RxPackets.Add(1)
			p.stats.RxBytes.Add(uint64(n))
		}
	}()

	select {
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	case err := <-errCh:
		wg.Wait()
		return err
	}
}
