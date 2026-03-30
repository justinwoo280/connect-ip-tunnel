package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"sync"

	"connect-ip-tunnel/common/bufferpool"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/yosida95/uritemplate/v3"
)

// ServeHTTP 实现 http.Handler 接口，处理 CONNECT-IP 请求
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. 验证请求方法
	if r.Method != http.MethodConnect || r.Proto != "connect-ip" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. 鉴权检查
	if s.authProv != nil {
		if err := s.authenticate(r); err != nil {
			log.Printf("[server] auth failed from %s: %v", r.RemoteAddr, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 3. 解析 CONNECT-IP 请求
	tmpl, err := uritemplate.New(s.cfg.URITemplate)
	if err != nil {
		log.Printf("[server] invalid uri template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	req, err := connectipgo.ParseRequest(r, tmpl)
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
	proxy := &connectipgo.Proxy{}
	conn, err := proxy.Proxy(w, req)
	if err != nil {
		log.Printf("[server] proxy failed: %v", err)
		return
	}

	// 5. 分配 IP 地址给客户端
	sessionID := generateSessionID()
	ipv4Prefix, ipv6Prefix, err := s.ipPool.AllocateIP(sessionID)
	if err != nil {
		log.Printf("[server] allocate ip failed: %v", err)
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
			log.Printf("[server] warning: assign addresses failed: %v", err)
			// 不中断连接，继续处理
		}
	}

	// 7. 创建会话并注册到分发器
	session := newSessionWithIP(conn, s.tunDevice, r.RemoteAddr, sessionID, ipv4Prefix, ipv6Prefix)

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	// 注册到分发器，获取下行包 channel
	inbound := s.RegisterSession(session)
	session.SetInbound(inbound)

	defer func() {
		s.sessionsMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionsMu.Unlock()
		s.UnregisterSession(sessionID)
		// 释放分配的 IP 地址
		s.ipPool.ReleaseIP(sessionID)
		_ = session.Close()
	}()

	log.Printf("[server] session %s started from %s (ipv4=%s ipv6=%s)",
		sessionID, r.RemoteAddr, ipv4Prefix, ipv6Prefix)

	// 8. 启动双向数据转发（不再使用 PacketPump，而是分离上行和下行）
	ctx := r.Context()
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// 上行：client → tunnel → TUN
	wg.Add(1)
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

			n, err := conn.ReadPacket(buf)
			if err != nil {
				errCh <- fmt.Errorf("uplink read: %w", err)
				return
			}
			if n <= 0 {
				continue
			}

			if err := s.tunDevice.WritePacket(buf[:n]); err != nil {
				errCh <- fmt.Errorf("uplink write to tun: %w", err)
				return
			}
			session.rxPackets.Add(1)
			session.rxBytes.Add(uint64(n))
		}
	}()

	// 下行：TUN → dispatcher → session inbound channel → tunnel → client
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-inbound:
				if !ok {
					return // channel 关闭
				}
				icmp, err := conn.WritePacket(pkt)
				if err != nil {
					errCh <- fmt.Errorf("downlink write to tunnel: %w", err)
					return
				}
				session.txPackets.Add(1)
				session.txBytes.Add(uint64(len(pkt)))

				// 处理 ICMP 回包
				if len(icmp) > 0 && s.tunDevice != nil {
					_ = s.tunDevice.WritePacket(icmp)
				}
			}
		}
	}()

	// 等待任一方向出错或 context 取消
	select {
	case <-ctx.Done():
	case err := <-errCh:
		log.Printf("[server] session %s error: %v", sessionID, err)
	}

	wg.Wait()
	log.Printf("[server] session %s closed", sessionID)
}

// authenticate 验证请求的鉴权信息
func (s *Server) authenticate(r *http.Request) error {
	// 创建一个临时请求用于验证
	testReq, _ := http.NewRequest("GET", "/", nil)
	if err := s.authProv.ApplyToRequest(testReq); err != nil {
		return fmt.Errorf("apply auth: %w", err)
	}

	// 比对 header
	for k, expectedVals := range testReq.Header {
		actualVals := r.Header[k]
		if len(actualVals) == 0 {
			return fmt.Errorf("missing header %s", k)
		}
		// 简单比对第一个值（实际应该更严格）
		if actualVals[0] != expectedVals[0] {
			return fmt.Errorf("invalid header %s", k)
		}
	}

	return nil
}

func generateSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
