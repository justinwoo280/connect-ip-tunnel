package tls

import (
"bytes"
"context"
"crypto/tls"
"encoding/base64"
"encoding/binary"
"errors"
"fmt"
"io"
"math"
"net"
"net/http"
"net/url"
"strings"
"sync"
"time"

"connect-ip-tunnel/common/safe"
)

func isECHRejection(err error, out **tls.ECHRejectionError) bool {
return errors.As(err, out)
}

type ECHManager struct {
domain    string
dohURL    string
echList   []byte
lastFetch time.Time
cacheTTL  time.Duration
mu        sync.RWMutex
dohClient *dohClient
stopCh    chan struct{}
cleanOnce sync.Once
}

func NewECHManager(domain, dohURL string) *ECHManager {
return NewECHManagerWithTTL(domain, dohURL, time.Hour)
}

func NewECHManagerWithTTL(domain, dohURL string, ttl time.Duration) *ECHManager {
m := &ECHManager{
domain:    domain,
dohURL:    dohURL,
cacheTTL:  ttl,
dohClient: newDOHClient(dohURL, nil),
stopCh:    make(chan struct{}),
}
m.startBackground()
return m
}

func (m *ECHManager) SetBypassDialer(d *net.Dialer) {
m.mu.Lock()
defer m.mu.Unlock()
m.dohClient = newDOHClient(m.dohURL, d)
}

func (m *ECHManager) Refresh() error {
m.mu.RLock()
client := m.dohClient
m.mu.RUnlock()
echList, err := client.queryECH(m.domain)
if err != nil {
return fmt.Errorf("ech: refresh %s: %w", m.domain, err)
}
m.mu.Lock()
m.echList = echList
m.lastFetch = time.Now()
m.mu.Unlock()
return nil
}

func (m *ECHManager) Get() ([]byte, error) {
m.mu.RLock()
expired := m.isExpiredLocked()
m.mu.RUnlock()
if expired {
if err := m.Refresh(); err != nil {
m.mu.RLock()
cached := m.echList
m.mu.RUnlock()
if len(cached) > 0 {
return cached, nil
}
return nil, fmt.Errorf("ech: no cache and refresh failed: %w", err)
}
}
m.mu.RLock()
defer m.mu.RUnlock()
if len(m.echList) == 0 {
return nil, errors.New("ech: configuration not loaded")
}
return m.echList, nil
}

func (m *ECHManager) UpdateFromRetry(retryConfigList []byte) error {
if len(retryConfigList) == 0 {
return errors.New("ech: empty retry config list")
}
m.mu.Lock()
m.echList = retryConfigList
m.lastFetch = time.Now()
m.mu.Unlock()
return nil
}

func (m *ECHManager) Stop() {
m.cleanOnce.Do(func() { close(m.stopCh) })
}

func (m *ECHManager) isExpiredLocked() bool {
return m.lastFetch.IsZero() || time.Since(m.lastFetch) > m.cacheTTL
}

func (m *ECHManager) startBackground() {
	safe.Go("ech.refresh", func() {
		// 动态 backoff：成功时 30 分钟，失败时 5 分钟
		const (
			successInterval = 30 * time.Minute
			failureInterval = 5 * time.Minute
		)
		
		interval := successInterval
		timer := time.NewTimer(interval)
		defer timer.Stop()
		
		for {
			select {
			case <-timer.C:
				m.mu.RLock()
				expired := m.isExpiredLocked()
				m.mu.RUnlock()
				
				if expired {
					err := m.Refresh()
					if err != nil {
						// Refresh 失败，使用短间隔快速重试
						interval = failureInterval
					} else {
						// Refresh 成功，恢复正常间隔
						interval = successInterval
					}
				} else {
					// 未过期，保持正常间隔
					interval = successInterval
				}
				
				timer.Reset(interval)
			case <-m.stopCh:
				return
			}
		}
	})
}

const maxDOHResponseSize = 64 * 1024

type dohClient struct {
serverURL  string
httpClient *http.Client
}

func newDOHClient(serverURL string, dialer *net.Dialer) *dohClient {
if !strings.HasPrefix(serverURL, "https://") && !strings.HasPrefix(serverURL, "http://") {
serverURL = "https://" + serverURL
}
if dialer == nil {
dialer = &net.Dialer{Timeout: 5 * time.Second}
}
u, _ := url.Parse(serverURL)
serverName := ""
if u != nil {
serverName = u.Hostname()
}
tlsCfg := &tls.Config{
MinVersion: tls.VersionTLS12,
NextProtos: []string{"h2"},
ServerName: serverName,
}
d := dialer
transport := &http.Transport{
DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
conn, err := d.DialContext(ctx, network, addr)
if err != nil {
return nil, err
}
tlsConn := tls.Client(conn, tlsCfg)
if err := tlsConn.HandshakeContext(ctx); err != nil {
_ = conn.Close()
return nil, err
}
return tlsConn, nil
},
ForceAttemptHTTP2: true,
}
return &dohClient{
serverURL: serverURL,
httpClient: &http.Client{
Transport: transport,
Timeout:   10 * time.Second,
},
}
}

func (c *dohClient) queryECH(domain string) ([]byte, error) {
query, err := buildDNSQuery(domain, 65)
if err != nil {
return nil, err
}
req, err := http.NewRequest(http.MethodPost, c.serverURL, bytes.NewReader(query))
if err != nil {
return nil, fmt.Errorf("doh: build request: %w", err)
}
req.Header.Set("Accept", "application/dns-message")
req.Header.Set("Content-Type", "application/dns-message")
resp, err := c.httpClient.Do(req)
if err != nil {
return nil, fmt.Errorf("doh: request: %w", err)
}
defer resp.Body.Close()
if resp.StatusCode != http.StatusOK {
return nil, fmt.Errorf("doh: server returned %d", resp.StatusCode)
}
body, err := io.ReadAll(io.LimitReader(resp.Body, maxDOHResponseSize+1))
if err != nil {
return nil, fmt.Errorf("doh: read response: %w", err)
}
if len(body) > maxDOHResponseSize {
return nil, fmt.Errorf("doh: response exceeds %d bytes", maxDOHResponseSize)
}
echB64, err := parseDNSResponseForECH(body)
if err != nil {
return nil, err
}
echList, err := base64.StdEncoding.DecodeString(echB64)
if err != nil {
return nil, fmt.Errorf("doh: decode ech base64: %w", err)
}
return echList, nil
}

func buildDNSQuery(domain string, qtype uint16) ([]byte, error) {
domain = strings.TrimSuffix(domain, ".")
if domain == "" {
return nil, errors.New("doh: empty domain")
}
if len(domain) > 253 {
return nil, errors.New("doh: domain name too long")
}

var q []byte
q = append(q, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
for _, label := range strings.Split(domain, ".") {
if label == "" {
return nil, errors.New("doh: domain contains empty label")
}
if len(label) > 63 {
return nil, fmt.Errorf("doh: domain label %q too long", label)
}
if len(label) > math.MaxUint8 {
return nil, fmt.Errorf("doh: domain label %q length overflows dns encoding", label)
}
q = append(q, byte(len(label)))
q = append(q, label...)
}
q = append(q, 0x00)
var qtb [2]byte
binary.BigEndian.PutUint16(qtb[:], qtype)
q = append(q, qtb[:]...)
q = append(q, 0x00, 0x01)
return q, nil
}

func parseDNSResponseForECH(resp []byte) (string, error) {
if len(resp) < 12 {
return "", errors.New("doh: response too short")
}
answerCount := int(binary.BigEndian.Uint16(resp[6:8]))
if answerCount == 0 {
return "", errors.New("doh: no answers")
}

offset, err := skipDNSName(resp, 12)
if err != nil {
return "", err
}
if offset+4 > len(resp) {
return "", errors.New("doh: truncated question")
}
offset += 4 // qtype + qclass

for i := 0; i < answerCount; i++ {
	offset, err = skipDNSName(resp, offset)
	if err != nil {
		return "", err
	}
	if offset+10 > len(resp) {
		return "", errors.New("doh: truncated resource record header")
	}
	rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
	rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
	offset += 10
	if offset+rdlen > len(resp) {
		return "", errors.New("doh: truncated resource record data")
	}
	if rtype == 65 {
		echB64, err := parseHTTPSRecordForECH(resp[offset : offset+rdlen])
		if err == nil {
			return echB64, nil
		}
	}
	offset += rdlen
}
return "", errors.New("doh: no ECH parameter in HTTPS record")
}

func skipDNSName(msg []byte, offset int) (int, error) {
	steps := 0
	for {
		if offset >= len(msg) {
			return 0, errors.New("doh: truncated dns name")
		}
		if steps > len(msg) {
			return 0, errors.New("doh: invalid dns name compression loop")
		}
		steps++

		length := msg[offset]
		switch {
		case length == 0:
			return offset + 1, nil
		case length&0xC0 == 0xC0:
			if offset+1 >= len(msg) {
				return 0, errors.New("doh: truncated dns compression pointer")
			}
			return offset + 2, nil
		case length&0xC0 != 0:
			return 0, errors.New("doh: invalid dns label encoding")
		default:
			if length > 63 {
				return 0, errors.New("doh: dns label too long")
			}
			offset++
			if offset+int(length) > len(msg) {
				return 0, errors.New("doh: truncated dns label")
			}
			offset += int(length)
		}
	}
}

func parseHTTPSRecordForECH(rdata []byte) (string, error) {
	if len(rdata) < 3 {
		return "", errors.New("doh: https record too short")
	}
	offset := 2 // priority
	next, err := skipDNSName(rdata, offset)
	if err != nil {
		return "", err
	}
	offset = next
	for {
		if offset == len(rdata) {
			return "", errors.New("doh: no ECH parameter in HTTPS record")
		}
		if offset+4 > len(rdata) {
			return "", errors.New("doh: truncated https svcparam header")
		}
		key := binary.BigEndian.Uint16(rdata[offset : offset+2])
		plen := int(binary.BigEndian.Uint16(rdata[offset+2 : offset+4]))
		offset += 4
		if offset+plen > len(rdata) {
			return "", errors.New("doh: truncated https svcparam value")
		}
		if key == 5 {
			return base64.StdEncoding.EncodeToString(rdata[offset : offset+plen]), nil
		}
		offset += plen
	}
}
