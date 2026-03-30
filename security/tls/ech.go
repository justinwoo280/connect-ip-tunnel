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
"net"
"net/http"
"net/url"
"strings"
"sync"
"time"
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
go func() {
ticker := time.NewTicker(30 * time.Minute)
defer ticker.Stop()
for {
select {
case <-ticker.C:
m.mu.RLock()
expired := m.isExpiredLocked()
m.mu.RUnlock()
if expired {
_ = m.Refresh()
}
case <-m.stopCh:
return
}
}
}()
}

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
query := buildDNSQuery(domain, 65)
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
body, err := io.ReadAll(resp.Body)
if err != nil {
return nil, fmt.Errorf("doh: read response: %w", err)
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

func buildDNSQuery(domain string, qtype uint16) []byte {
var q []byte
q = append(q, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
labels := []byte(domain)
start := 0
for i, b := range labels {
if b == '.' {
q = append(q, byte(i-start))
q = append(q, labels[start:i]...)
start = i + 1
}
}
if start < len(labels) {
q = append(q, byte(len(labels)-start))
q = append(q, labels[start:]...)
}
q = append(q, 0x00)
var qtb [2]byte
binary.BigEndian.PutUint16(qtb[:], qtype)
q = append(q, qtb[:]...)
q = append(q, 0x00, 0x01)
return q
}

func parseDNSResponseForECH(resp []byte) (string, error) {
if len(resp) < 12 {
return "", errors.New("doh: response too short")
}
answerCount := int(resp[6])<<8 | int(resp[7])
if answerCount == 0 {
return "", errors.New("doh: no answers")
}
offset := 12
for offset < len(resp) {
if resp[offset] == 0 {
offset += 5
break
}
if resp[offset]&0xC0 == 0xC0 {
offset += 6
break
}
offset += int(resp[offset]) + 1
}
for i := 0; i < answerCount && offset < len(resp); i++ {
if offset+2 > len(resp) {
break
}
if resp[offset]&0xC0 == 0xC0 {
offset += 2
} else {
for offset < len(resp) && resp[offset] != 0 {
offset += int(resp[offset]) + 1
}
offset++
}
if offset+10 > len(resp) {
break
}
rtype := uint16(resp[offset])<<8 | uint16(resp[offset+1])
rdlen := int(resp[offset+8])<<8 | int(resp[offset+9])
offset += 10
if offset+rdlen > len(resp) {
break
}
if rtype == 65 {
if rdlen < 3 {
offset += rdlen
continue
}
dp := offset + 2
for dp < offset+rdlen && resp[dp] != 0 {
if resp[dp]&0xC0 == 0xC0 {
dp += 2
break
}
dp += int(resp[dp]) + 1
}
if dp < offset+rdlen {
dp++
}
for dp+4 <= offset+rdlen {
key := uint16(resp[dp])<<8 | uint16(resp[dp+1])
plen := int(resp[dp+2])<<8 | int(resp[dp+3])
dp += 4
if dp+plen > offset+rdlen {
break
}
if key == 5 {
return base64.StdEncoding.EncodeToString(resp[dp : dp+plen]), nil
}
dp += plen
}
}
offset += rdlen
}
return "", errors.New("doh: no ECH parameter in HTTPS record")
}
