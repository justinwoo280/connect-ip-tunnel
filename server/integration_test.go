package server

// 集成测试：验证完整的服务端链路可以正确收发 IP 包。
//
// 使用 fakeTUN 模拟 TUN 设备，在进程内跑真实的：
//   - IPPool 分配
//   - PacketDispatcher 分发
//   - ServeHTTP handler（AssignAddresses + AdvertiseRoute + 双向转发）
//   - QUIC/HTTP3 传输层
//
// 客户端侧使用 connectipgo.Dial 直接建立 CONNECT-IP 会话。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	qhttp3 "github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	tunpkg "connect-ip-tunnel/platform/tun"
	"connect-ip-tunnel/runner"
)

// ── fakeTUN ──────────────────────────────────────────────────────────────────

type fakeTUN struct {
	tx     chan []byte // Inject → ReadPacket
	rx     chan []byte // WritePacket → Recv
	closed chan struct{}
	once   sync.Once
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		tx:     make(chan []byte, 128),
		rx:     make(chan []byte, 128),
		closed: make(chan struct{}),
	}
}

func (f *fakeTUN) Name() (string, error) { return "fake0", nil }
func (f *fakeTUN) MTU() int              { return 1420 }
func (f *fakeTUN) BatchSize() int        { return 1 }
func (f *fakeTUN) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeTUN) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-f.tx:
		return copy(buf, pkt), nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakeTUN) WritePacket(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case f.rx <- cp:
	case <-f.closed:
		return net.ErrClosed
	default: // 满了丢弃
	}
	return nil
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-f.tx:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	pkt := bufs[0][offset:]
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case f.rx <- cp:
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	return 1, nil
}

// Inject 模拟"内核把包交给 TUN 发出"（上行源头 / 下行回包注入）
func (f *fakeTUN) Inject(pkt []byte) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case f.tx <- cp:
	case <-f.closed:
	}
}

// Recv 模拟"从 TUN 收到包"（等待 WritePacket 写入）
func (f *fakeTUN) Recv(timeout time.Duration) ([]byte, bool) {
	select {
	case pkt := <-f.rx:
		return pkt, true
	case <-time.After(timeout):
		return nil, false
	}
}

// 确保 fakeTUN 实现了 tunpkg.Device 接口
var _ tunpkg.Device = (*fakeTUN)(nil)

// ── connTunnel：将 connectipgo.Conn 适配为 tunnel.PacketTunnel ───────────────

type connTunnel struct {
	conn *connectipgo.Conn
	dev  tunpkg.Device // 用于 ICMP 回包写回，可为 nil
}

func (t *connTunnel) ReadPacket(buf []byte) (int, error) {
	return t.conn.ReadPacket(buf)
}

func (t *connTunnel) WritePacket(pkt []byte) error {
	icmp, err := t.conn.WritePacket(pkt)
	if err != nil {
		return err
	}
	if len(icmp) > 0 && t.dev != nil {
		_ = t.dev.WritePacket(icmp)
	}
	return nil
}

func (t *connTunnel) Close() error {
	return t.conn.Close()
}

// ── TLS 证书生成 ──────────────────────────────────────────────────────────────

type testCerts struct {
	serverTLS *tls.Config
	clientTLS *tls.Config
}

func generateTestCerts(t *testing.T) testCerts {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// 服务端证书
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	srvTLSCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER}),
	)
	if err != nil {
		t.Fatalf("server X509KeyPair: %v", err)
	}

	// 客户端证书（mTLS）
	cliKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cliTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, _ := x509.CreateCertificate(rand.Reader, cliTemplate, caCert, &cliKey.PublicKey, caKey)
	cliKeyDER, _ := x509.MarshalECPrivateKey(cliKey)
	cliTLSCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cliKeyDER}),
	)
	if err != nil {
		t.Fatalf("client X509KeyPair: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{srvTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h3"},
	}
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{cliTLSCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		NextProtos:   []string{"h3"},
	}
	return testCerts{serverTLS: serverTLS, clientTLS: clientTLS}
}

// ── IP 包构造 ─────────────────────────────────────────────────────────────────

// makeIPv4UDPPacket 构造最小 IPv4/UDP 包（checksum=0，测试环境不校验）
func makeIPv4UDPPacket(src, dst netip.Addr, payload []byte) []byte {
	const ipHdrLen = 20
	udpLen := 8 + len(payload)
	total := ipHdrLen + udpLen
	pkt := make([]byte, total)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64  // TTL
	pkt[9] = 17  // UDP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 12345)
	binary.BigEndian.PutUint16(pkt[22:24], 53)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], payload)
	return pkt
}

// ── 集成测试 ──────────────────────────────────────────────────────────────────

// TestIntegrationPacketRoundTrip 验证完整链路收发：
//
//	客户端 fakeTUN → pump → QUIC/CONNECT-IP → server handler → 服务端 fakeTUN  (上行)
//	服务端 fakeTUN → dispatcher → session → QUIC → pump → 客户端 fakeTUN       (下行)
func TestIntegrationPacketRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	certs := generateTestCerts(t)

	// ── 服务端 TUN + 核心组件 ──────────────────────────────────────────────────
	srvTUN := newFakeTUN()
	t.Cleanup(func() { srvTUN.Close() })

	ipPool, err := NewIPPool("10.233.0.0/24", "")
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	disp := NewPacketDispatcher(srvTUN)
	dispCtx, dispCancel := context.WithCancel(ctx)
	t.Cleanup(dispCancel)
	go func() { _ = disp.Run(dispCtx) }()

	const uriTmpl = "https://localhost/.well-known/masque/ip"
	tmpl, _ := uritemplate.New(uriTmpl)

	// 构造仅含必要字段的 Server（cfg 零值，metrics 不启用）
	srv := &Server{
		ipPool:      ipPool,
		dispatcher:  disp,
		tunDevice:   srvTUN,
		uriTemplate: tmpl,
		sessions:    make(map[string]*Session),
	}

	// ── QUIC 监听 ──────────────────────────────────────────────────────────────
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srvAddr := udpConn.LocalAddr().String()

	ql, err := quic.Listen(udpConn.(*net.UDPConn), certs.serverTLS, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	t.Cleanup(func() { ql.Close() })

	h3Srv := &qhttp3.Server{Handler: srv, EnableDatagrams: true}
	go func() { _ = h3Srv.ServeListener(ql) }()
	t.Cleanup(func() { h3Srv.Close() })

	// ── 客户端建立 CONNECT-IP 会话 ────────────────────────────────────────────
	cliTUN := newFakeTUN()
	t.Cleanup(func() { cliTUN.Close() })

	quicConn, err := quic.DialAddr(ctx, srvAddr, certs.clientTLS, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}

	h3Transport := &qhttp3.Transport{EnableDatagrams: true}
	clientConn := h3Transport.NewClientConn(quicConn)

	tmplCli, _ := uritemplate.New(uriTmpl)
	conn, _, err := connectipgo.Dial(ctx, clientConn, tmplCli)
	if err != nil {
		t.Fatalf("connectip dial: %v", err)
	}

	// 等待 ADDRESS_ASSIGN
	prefixes, err := conn.LocalPrefixes(ctx)
	if err != nil {
		t.Fatalf("LocalPrefixes: %v", err)
	}
	if len(prefixes) == 0 {
		t.Fatal("no prefixes assigned")
	}
	assignedIP := prefixes[0].Addr()
	t.Logf("assigned IP: %s", assignedIP)

	// 包装成 PacketTunnel 适配器（供 PacketPump 使用）
	sess := &connTunnel{conn: conn, dev: cliTUN}

	pump := &runner.PacketPump{Dev: cliTUN, Tunnel: sess}
	pumpCtx, pumpCancel := context.WithCancel(ctx)
	t.Cleanup(pumpCancel)
	go func() { _ = pump.Run(pumpCtx) }()

	// 稍等会话稳定
	time.Sleep(200 * time.Millisecond)

	// ── 上行验证：客户端 TUN → 服务端 TUN ────────────────────────────────────
	dstIP := netip.MustParseAddr("8.8.8.8")
	upPkt := makeIPv4UDPPacket(assignedIP, dstIP, []byte("hello-server"))
	cliTUN.Inject(upPkt)

	got, ok := srvTUN.Recv(5 * time.Second)
	if !ok {
		t.Fatal("timeout: server TUN did not receive uplink packet")
	}
	if len(got) < 20 {
		t.Fatalf("uplink packet too short: %d bytes", len(got))
	}
	gotSrc := netip.AddrFrom4([4]byte(got[12:16]))
	gotDst := netip.AddrFrom4([4]byte(got[16:20]))
	t.Logf("✅ uplink OK: src=%s dst=%s len=%d", gotSrc, gotDst, len(got))
	if gotSrc != assignedIP {
		t.Errorf("uplink src: got %s want %s", gotSrc, assignedIP)
	}
	if gotDst != dstIP {
		t.Errorf("uplink dst: got %s want %s", gotDst, dstIP)
	}

	// ── 下行验证：服务端 TUN → 客户端 TUN ────────────────────────────────────
	downPkt := makeIPv4UDPPacket(dstIP, assignedIP, []byte("hello-client"))
	srvTUN.Inject(downPkt)

	gotDown, ok := cliTUN.Recv(5 * time.Second)
	if !ok {
		t.Fatal("timeout: client TUN did not receive downlink packet")
	}
	if len(gotDown) < 20 {
		t.Fatalf("downlink packet too short: %d bytes", len(gotDown))
	}
	downSrc := netip.AddrFrom4([4]byte(gotDown[12:16]))
	downDst := netip.AddrFrom4([4]byte(gotDown[16:20]))
	t.Logf("✅ downlink OK: src=%s dst=%s len=%d", downSrc, downDst, len(gotDown))
	if downSrc != dstIP {
		t.Errorf("downlink src: got %s want %s", downSrc, dstIP)
	}
	if downDst != assignedIP {
		t.Errorf("downlink dst: got %s want %s", downDst, assignedIP)
	}

	t.Log("✅ full round-trip integration test passed")
}
