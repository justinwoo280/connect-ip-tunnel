package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"connect-ip-tunnel/common/bufferpool"
	"connect-ip-tunnel/common/safe"
	"connect-ip-tunnel/observability"
	"connect-ip-tunnel/platform/tun"
	"connect-ip-tunnel/tunnel/connectip"

	connectipgo "github.com/quic-go/connect-ip-go"
)

// 注：handler 中的数据转发路径完全通过 session.ReadPacket/WritePacket 完成，
// 统计计数由 Session 层统一管理，避免双重计数和职责分散。

// ServeHTTP 实现 http.Handler 接口，处理 CONNECT-IP 请求
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. 验证请求方法
	if r.Method != http.MethodConnect || r.Proto != "connect-ip" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 注：鉴权已由 TLS 层的 mTLS 完成，客户端证书在握手阶段已验证

	// 2. 解析 CONNECT-IP 请求
	req, err := connectipgo.ParseRequest(r, s.uriTemplate)
	if err != nil {
		log.Printf("[server] parse connect-ip request failed: %v", err)
		if parseErr, ok := err.(*connectipgo.RequestParseError); ok {
			http.Error(w, parseErr.Error(), parseErr.HTTPStatus)
		} else {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		return
	}

	// 4. 创建 CONNECT-IP 代理
	if m := observability.Global; m != nil {
		m.RecordMTLSHandshake(true)
	}
	proxy := &connectipgo.Proxy{}
	conn, err := proxy.Proxy(w, req)
	if err != nil {
		log.Printf("[server] proxy failed: %v", err)
		if m := observability.Global; m != nil {
			m.RecordSessionError("proxy_failed")
		}
		return
	}

	// 5. 分配 IP 地址给客户端
	// 用 mTLS 证书 Subject 作为 clientKey，同一客户端的多个并行 session 复用同一 IP。
	// 未启用 mTLS 时退化为 RemoteAddr，保证单 session 场景仍可正常工作。
	clientKey := r.RemoteAddr
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientKey = r.TLS.PeerCertificates[0].Subject.String()
	}

	sessionID := generateSessionID()
	ipv4Prefix, ipv6Prefix, err := s.ipPool.AllocateIP(clientKey, sessionID)
	if err != nil {
		log.Printf("[server] allocate ip failed: %v", err)
		_ = conn.Close()
		if m := observability.Global; m != nil {
			m.RecordSessionError("ip_pool_exhausted")
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 6. 通过 ADDRESS_ASSIGN capsule 通知客户端分配的 IP
	var prefixes []netip.Prefix
	if ipv4Prefix.IsValid() {
		prefixes = append(prefixes, ipv4Prefix)
		log.Printf("[server] assigned ipv4: %s to session %s", ipv4Prefix, sessionID)
	}
	if ipv6Prefix.IsValid() {
		prefixes = append(prefixes, ipv6Prefix)
		log.Printf("[server] assigned ipv6: %s to session %s", ipv6Prefix, sessionID)
	}

	if len(prefixes) > 0 {
		if err := conn.AssignAddresses(r.Context(), prefixes); err != nil {
			log.Printf("[server] assign addresses failed: %v", err)
			s.ipPool.ReleaseIP(sessionID)
			_ = conn.Close()
			return
		}
	}

	// 广播全路由，允许客户端通过此隧道转发任意目标地址的流量。
	// RFC 9484 要求服务端通过 ROUTE_ADVERTISEMENT capsule 明确告知客户端
	// 哪些路由可用；若不广播，connect-ip-go 库会拒绝所有非分配地址的数据包。
	// IPProtocol=0 表示允许所有协议。
	
	// 从 TLS 证书中提取 CN，用于 per-client 路由策略和指标记录
	var clientCN string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	// 如果无法提取 CN，使用空字符串作为 fallback
	if clientCN == "" {
		clientCN = "unknown"
	}

	// 根据路由策略生成允许的路由列表
	var routes []connectipgo.IPRoute
	if s.routesPolicy != nil {
		prefixes := s.routesPolicy.For(clientCN)
		if prefixes != nil {
			// 有明确策略，转换为 IPRoute
			routes = prefixesToIPRoutes(prefixes)
			log.Printf("[server] session %s (CN=%s) routes: %d prefixes", sessionID, clientCN, len(prefixes))
		} else {
			// 无策略，使用全路由
			routes = fullRoutes()
		}
	} else {
		// 未启用路由策略，使用全路由
		routes = fullRoutes()
	}

	if err := conn.AdvertiseRoute(r.Context(), routes); err != nil {
		log.Printf("[server] advertise routes failed: %v", err)
		s.ipPool.ReleaseIP(sessionID)
		_ = conn.Close()
		return
	}

	// 7. 创建会话并注册到分发器
	session := newSessionWithIP(conn, s.tunDevice, r.RemoteAddr, sessionID, ipv4Prefix, ipv6Prefix)

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	// 注册到分发器，获取下行包 channel
	inbound := s.RegisterSession(session)
	session.SetInbound(inbound)

	sessionStart := time.Now()
	if m := observability.Global; m != nil {
		m.RecordSessionStart()
	}

	defer func() {
		s.sessionsMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionsMu.Unlock()
		s.UnregisterSession(sessionID)
		// 释放分配的 IP 地址
		s.ipPool.ReleaseIP(sessionID)
		_ = session.Close()
		if m := observability.Global; m != nil {
			m.RecordSessionEnd(time.Since(sessionStart))
			// 更新 IP 池指标
			stats := s.ipPool.Stats()
			v4Cap, v6Cap := s.ipPool.Capacity()
			m.SetIPPoolStats(
				stats.IPv4Allocated,
				v4Cap-stats.IPv4Allocated,
				stats.IPv6Allocated,
				v6Cap-stats.IPv6Allocated,
			)
		}
	}()

	log.Printf("[server] session %s started from %s (ipv4=%s ipv6=%s)",
		sessionID, r.RemoteAddr, ipv4Prefix, ipv6Prefix)

	// 8. 启动双向数据转发（不再使用 PacketPump，而是分离上行和下行）
	ctx := r.Context()
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// 获取批量写入的 batch size
	batchSize := s.tunDevice.BatchSize()
	if batchSize <= 0 {
		batchSize = 16 // 默认值
	}

	// 上行：client → tunnel → TUN（批量写入）
	wg.Add(1)
	safe.Go("server.uplink", func() {
		defer wg.Done()
		
		// 创建批量缓冲区
		bufs := make([][]byte, 0, batchSize)
		flushTimer := time.NewTimer(time.Millisecond)
		defer flushTimer.Stop()
		
		// flush 辅助函数：批量写入 TUN 并释放缓冲区
		//
		// 重要：bufs 中每个缓冲区前 tun.VirtioNetHdrLen 字节是 wireguard-go 要求的
		// virtio_net_hdr 预留区，实际 IP 包数据从 buf[VirtioNetHdrLen:] 开始；
		// Write 调用必须传 offset=VirtioNetHdrLen，否则 Linux 内核 vnetHdr 路径会返回
		// "invalid offset" 整批失败（曾导致下行完全不通的回归 bug）。
		flush := func() {
			if len(bufs) == 0 {
				return
			}

			// 批量写入 TUN，offset = virtio_net_hdr 预留头长度
			n, err := s.tunDevice.Write(bufs, tun.VirtioNetHdrLen)
			if err != nil {
				log.Printf("[server] session %s batch tun write error: %v", sessionID, err)
			}

			// 统计已写入的包（实际 IP 包长度 = buf 长度 - 预留头）
			if m := observability.Global; m != nil {
				for i := 0; i < n && i < len(bufs); i++ {
					payloadLen := len(bufs[i]) - tun.VirtioNetHdrLen
					if payloadLen < 0 {
						payloadLen = 0
					}
					m.AddRx(clientCN, payloadLen)
				}
			}

			// 释放所有缓冲区到池
			for _, buf := range bufs {
				bufferpool.PutPacket(buf)
			}
			bufs = bufs[:0]
		}
		
		defer flush() // 确保退出时刷新剩余包
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-flushTimer.C:
				// 超时触发部分批次刷新
				flush()
				flushTimer.Reset(time.Millisecond)
			default:
			}
			
			// 从池中获取新缓冲区
			buf := bufferpool.GetPacket()
			
			n, err := session.ReadPacket(buf)
			if err != nil {
				bufferpool.PutPacket(buf)
				// connect-ip-go 对不合法源/目标地址、畸形包等返回普通错误（可恢复）；
				// 只有 CloseError（对应 net.ErrClosed）和 context 取消才是致命错误。
				if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
					errCh <- fmt.Errorf("uplink read: %w", err)
					return
				}
				// 可恢复错误（source/destination not allowed、malformed datagram 等）
				// 静默跳过，不终止 session。
				log.Printf("[server] session %s uplink drop: %v", sessionID, err)
				continue
			}
			if n <= 0 {
				bufferpool.PutPacket(buf)
				continue
			}
			
			// 检查是否为心跳帧
			if isHeartbeatPacket(buf[:n], session, s.tunGatewayV4(), s.tunGatewayV6()) {
				handleHeartbeatServer(conn, buf[:n], session, s.tunGatewayV4(), s.tunGatewayV6())
				bufferpool.PutPacket(buf)
				continue
			}

			// 源地址校验：检查包的源 IP 是否为分配给该 session 的 IP
			srcAddr, ok := parseSrcAddr(buf[:n])
			if !ok {
				// 无法解析源地址（畸形包），丢弃
				bufferpool.PutPacket(buf)
				if m := observability.Global; m != nil {
					m.RecordDrop("malformed_packet")
				}
				continue
			}

			// 检查源地址是否匹配分配的 IP
			if !session.IsAssignedIP(srcAddr) {
				// 源地址伪造，丢弃并记录
				bufferpool.PutPacket(buf)
				log.Printf("[server] session %s source IP spoofing detected: src=%s (assigned: v4=%s v6=%s)",
					sessionID, srcAddr, ipv4Prefix, ipv6Prefix)
				if m := observability.Global; m != nil {
					m.RecordDrop("src_ip_spoof")
				}
				continue
			}

			// 将包添加到批次：在 wireguard-go 要求的 virtio_net_hdr 预留区之后拷入实际 IP 包。
			// 缓冲区布局：[ 0 .. VirtioNetHdrLen ) = vnethdr 预留 ; [ VirtioNetHdrLen .. ) = IP 包数据
			pktCopy := make([]byte, tun.VirtioNetHdrLen+n)
			copy(pktCopy[tun.VirtioNetHdrLen:], buf[:n])
			bufferpool.PutPacket(buf)
			bufs = append(bufs, pktCopy)
			
			// 批次满时立即刷新
			if len(bufs) >= batchSize {
				flush()
				// 重置定时器
				if !flushTimer.Stop() {
					select {
					case <-flushTimer.C:
					default:
					}
				}
				flushTimer.Reset(time.Millisecond)
			}
		}
	})

	// 下行：TUN → dispatcher → session inbound channel → tunnel → client
	wg.Add(1)
	safe.Go("server.downlink", func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-inbound:
				if !ok {
					return // channel 关闭
				}
				pktLen := len(pkt)
				err := session.WritePacket(pkt)
				bufferpool.PutPacket(pkt)
				if err != nil {
					errCh <- fmt.Errorf("downlink write to tunnel: %w", err)
					return
				}
				if m := observability.Global; m != nil {
					m.AddTx(clientCN, pktLen)
				}
			}
		}
	})

	// 等待任一方向出错或 context 取消
	select {
	case <-ctx.Done():
	case err := <-errCh:
		log.Printf("[server] session %s error: %v", sessionID, err)
	}

	wg.Wait()
	log.Printf("[server] session %s closed", sessionID)
}

func generateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("server: generate session id: crypto/rand.Read failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// fullRoutes 返回全路由（0.0.0.0/0 + ::/0）
func fullRoutes() []connectipgo.IPRoute {
	return []connectipgo.IPRoute{
		{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255"), IPProtocol: 0},
		{StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPProtocol: 0},
	}
}

// prefixesToIPRoutes 将 netip.Prefix 列表转换为 connectipgo.IPRoute 列表
func prefixesToIPRoutes(prefixes []netip.Prefix) []connectipgo.IPRoute {
	routes := make([]connectipgo.IPRoute, 0, len(prefixes))
	for _, prefix := range prefixes {
		// 计算前缀的起始和结束 IP
		startIP := prefix.Addr()
		
		// 计算结束 IP：将主机位全部置 1
		bits := prefix.Bits()
		addr := prefix.Addr()
		
		var endIP netip.Addr
		if addr.Is4() {
			// IPv4
			a := addr.As4()
			mask := uint32(0xFFFFFFFF) >> bits
			start := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
			end := start | mask
			endIP = netip.AddrFrom4([4]byte{
				byte(end >> 24),
				byte(end >> 16),
				byte(end >> 8),
				byte(end),
			})
		} else {
			// IPv6
			a := addr.As16()
			hostBits := 128 - bits
			
			// 将 IPv6 地址转换为两个 uint64
			hi := uint64(a[0])<<56 | uint64(a[1])<<48 | uint64(a[2])<<40 | uint64(a[3])<<32 |
				uint64(a[4])<<24 | uint64(a[5])<<16 | uint64(a[6])<<8 | uint64(a[7])
			lo := uint64(a[8])<<56 | uint64(a[9])<<48 | uint64(a[10])<<40 | uint64(a[11])<<32 |
				uint64(a[12])<<24 | uint64(a[13])<<16 | uint64(a[14])<<8 | uint64(a[15])
			
			// 计算掩码并应用
			if hostBits >= 64 {
				// 低 64 位全部是主机位
				lo = 0xFFFFFFFFFFFFFFFF
				if hostBits > 64 {
					// 高 64 位也有部分主机位
					hi |= (uint64(1) << (hostBits - 64)) - 1
				}
			} else if hostBits > 0 {
				// 只有低 64 位有主机位
				lo |= (uint64(1) << hostBits) - 1
			}
			
			endIP = netip.AddrFrom16([16]byte{
				byte(hi >> 56), byte(hi >> 48), byte(hi >> 40), byte(hi >> 32),
				byte(hi >> 24), byte(hi >> 16), byte(hi >> 8), byte(hi),
				byte(lo >> 56), byte(lo >> 48), byte(lo >> 40), byte(lo >> 32),
				byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo),
			})
		}
		
		routes = append(routes, connectipgo.IPRoute{
			StartIP:    startIP,
			EndIP:      endIP,
			IPProtocol: 0, // 允许所有协议
		})
	}
	return routes
}

// parseSrcAddr 从 IP 包中解析源地址
// 返回 (源地址, 是否成功解析)
func parseSrcAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, false
	}

	// 检查 IP 版本
	version := pkt[0] >> 4
	switch version {
	case 4:
		// IPv4：源地址在偏移 12-15
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		addr := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
		return addr, true
	case 6:
		// IPv6：源地址在偏移 8-23
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], pkt[8:24])
		addr := netip.AddrFrom16(a)
		return addr, true
	default:
		return netip.Addr{}, false
	}
}


// isHeartbeatPacket 检查数据包是否为心跳包
func isHeartbeatPacket(pkt []byte, session *Session, gwV4, gwV6 netip.Addr) bool {
	assignedPrefixes := []netip.Prefix{}
	if session.assignedIPv4.IsValid() {
		assignedPrefixes = append(assignedPrefixes, session.assignedIPv4)
	}
	if session.assignedIPv6.IsValid() {
		assignedPrefixes = append(assignedPrefixes, session.assignedIPv6)
	}
	
	// 根据 IP 版本选择网关
	var gateway netip.Addr
	if len(pkt) > 0 {
		version := pkt[0] >> 4
		if version == 4 {
			gateway = gwV4
		} else if version == 6 {
			gateway = gwV6
		}
	}
	
	if !gateway.IsValid() {
		return false
	}
	
	// 使用 connectip 包的函数检查
	return connectip.IsHeartbeatPacket(pkt, assignedPrefixes, gateway, true)
}

// handleHeartbeatServer 处理心跳帧：收到 ping 后镜射 pong
func handleHeartbeatServer(conn *connectipgo.Conn, pkt []byte, session *Session, gwV4, gwV6 netip.Addr) {
	// 更新 session 活跃时间
	session.UpdateLastActive()
	
	// 解析心跳负载
	typ, seq, ts, err := connectip.ParseHeartbeatPayload(pkt)
	if err != nil {
		return
	}
	
	if typ == connectip.HeartbeatTypePing {
		// 构造 pong 包
		// 源地址：server gateway，目标地址：client assigned IP
		var src, dst netip.Addr
		version := pkt[0] >> 4
		if version == 4 {
			src = gwV4
			if session.assignedIPv4.IsValid() {
				dst = session.assignedIPv4.Addr()
			}
		} else if version == 6 {
			src = gwV6
			if session.assignedIPv6.IsValid() {
				dst = session.assignedIPv6.Addr()
			}
		}
		
		if !src.IsValid() || !dst.IsValid() {
			return
		}
		
		pong, err := connectip.BuildHeartbeatPacket(connectip.HeartbeatTypePong, seq, ts, src, dst)
		if err != nil {
			return
		}
		
		// 发送 pong
		_, _ = conn.WritePacket(pong)
	}
}
