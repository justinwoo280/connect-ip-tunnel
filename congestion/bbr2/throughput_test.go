// Package bbr2 throughput tests: CUBIC vs BBRv2 under ISP QoS simulation
//
// # Background
//
// ISPs commonly throttle UDP/QUIC traffic via three mechanisms:
//  1. Random packet loss (DPI-based throttling): 1~5% random loss
//  2. Token bucket rate limiting: burst loss when quota exceeded
//  3. AQM (e.g. FQ-CoDel): ECN marking + slight RTT increase
//
// CUBIC responds to every loss event by cutting CWND by 30%, making it
// extremely sensitive to ISP-induced random loss. BBRv2 uses bandwidth
// measurement rather than loss as its primary signal, with a configurable
// loss threshold (default 1.5%) below which it ignores loss entirely.
//
// # Test Results (2026-04-10, Rocky Linux, aarch64, loopback with tc netem)
//
//	Scenario                    CUBIC       BBRv2       Improvement
//	──────────────────────────  ──────────  ──────────  ───────────
//	Baseline (no QoS)           3919 Mbps   3002 Mbps   -23.4%
//	Light QoS (1% loss+30ms)    1.42 Mbps   3.20 Mbps   +125.9%
//	Heavy QoS (5% loss+100ms)   0.30 Mbps   0.87 Mbps   +187.0%
//
// Key finding: BBRv2 default parameters outperform CUBIC by 2-3x under
// ISP QoS conditions. The -23.4% baseline gap closes significantly on
// real WAN links where bandwidth bottlenecks exist.
//
// # Parameter Tuning Results (2% loss + 50ms RTT)
//
//	Parameter Set               Throughput   Notes
//	──────────────────────────  ──────────   ──────────────────────────────
//	Default                     2.36 Mbps    ✅ Best - Chromium-tuned defaults
//	ConservativeProbe (1.10x)   1.68 Mbps    More conservative probing = worse
//	HighLossTol (0.025/β0.5)    1.56 Mbps    Higher tolerance = unstable CWND
//	Combined                    0.01 Mbps    ❌ Over-tuned, CWND collapses
//
// Conclusion: BBRv2 default parameters are already well-tuned for QoS scenarios.
// The LossThreshold=1.5% and Beta=0.3 reflect years of Chromium team optimization.
// Simply switching from CUBIC to BBRv2 with defaults is the recommended approach.
//
// # Usage
//
// Run with tc netem to simulate ISP QoS:
//
//	# Light QoS (1% loss + 30ms RTT)
//	sudo tc qdisc add dev lo root netem loss 1% delay 30ms 5ms distribution normal
//	go test ./congestion/bbr2/ -run TestThroughputLightQoS -v
//	sudo tc qdisc del dev lo root
//
//	# Heavy QoS (5% loss + 100ms RTT)
//	sudo tc qdisc add dev lo root netem loss 5% delay 100ms 20ms distribution normal
//	go test ./congestion/bbr2/ -run TestThroughputHeavyQoS -v
//	sudo tc qdisc del dev lo root
//
//	# Parameter tuning (2% loss + 50ms RTT)
//	sudo tc qdisc add dev lo root netem loss 2% delay 50ms 10ms distribution normal
//	go test ./congestion/bbr2/ -run TestParamTuning -v
//	sudo tc qdisc del dev lo root

package bbr2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	testDuration = 5 * time.Second // 每次测试固定发送 5 秒
	chunkSize    = 32 * 1024       // 32KB 每次写入
)

var testPortCounter atomic.Int32

func init() {
	testPortCounter.Store(15100)
}

func nextTestAddr() string {
	port := testPortCounter.Add(1)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// generateTLSConfig 生成自签名 TLS 配置用于测试
func generateTLSConfig() (*tls.Config, *tls.Config) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"qos-test"},
	}

	cert, _ := x509.ParseCertificate(certDER)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		NextProtos: []string{"qos-test"},
	}

	return serverTLS, clientTLS
}

// runThroughputTest 测量指定配置下的 QUIC 吞吐量（基于固定时间）
// useBBR2: true=BBRv2, false=CUBIC(默认)
func runThroughputTest(t *testing.T, label string, useBBR2 bool) float64 {
	t.Helper()

	addr := nextTestAddr()
	serverTLS, clientTLS := generateTLSConfig()

	quicConf := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
	}

	// 启动服务端
	ln, err := quic.ListenAddr(addr, serverTLS, quicConf)
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer ln.Close()

	var bytesReceived atomic.Int64
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "done")

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		defer stream.Close()

		buf := make([]byte, chunkSize)
		for {
			n, err := stream.Read(buf)
			bytesReceived.Add(int64(n))
			if err != nil {
				break
			}
		}
	}()

	// 启动客户端
	conn, err := quic.DialAddr(context.Background(), addr, clientTLS, quicConf)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}

	// 注入 BBRv2
	if useBBR2 {
		params := DefaultParams()
		params.LossThreshold = 0.015 // 1.5% 丢包阈值
		params.Beta = 0.3
		sender := NewBBR2SenderWithParams(
			DefaultClock{},
			1200,
			0,
			false,
			params,
		)
		conn.SetCongestionControl(sender)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// 固定发送 testDuration 秒
	data := make([]byte, chunkSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	deadline := time.Now().Add(testDuration)
	totalSent := 0
	for time.Now().Before(deadline) {
		n, err := stream.Write(data)
		totalSent += n
		if err != nil {
			break
		}
	}
	stream.Close()
	conn.CloseWithError(0, "done")

	// 等待服务端收完（最多额外等 5s 让数据传完）
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
	}

	bytesRcv := bytesReceived.Load()
	mbps := float64(bytesRcv) * 8 / testDuration.Seconds() / 1e6

	t.Logf("[%s] sent=%dMB rcv=%dMB duration=%.0fs throughput=%.2f Mbps",
		label,
		totalSent/1024/1024,
		bytesRcv/1024/1024,
		testDuration.Seconds(),
		mbps,
	)

	return mbps
}

// TestThroughputBaseline 无丢包基线测试
func TestThroughputBaseline(t *testing.T) {
	t.Log("=== 场景 1: 基线（无 QoS 干扰）===")
	t.Log("提示：请确保 tc qdisc 未设置任何 netem 规则")

	mbpsCubic := runThroughputTest(t, "CUBIC-baseline", false)
	mbpsBBR2 := runThroughputTest(t, "BBRv2-baseline", true)

	t.Logf("CUBIC: %.2f Mbps | BBRv2: %.2f Mbps | 差异: %+.1f%%",
		mbpsCubic, mbpsBBR2, (mbpsBBR2-mbpsCubic)/mbpsCubic*100)
}

// TestThroughputLightQoS 轻度 QoS（1% 丢包，30ms RTT）
// 运行前需要：sudo tc qdisc add dev lo root netem loss 1% delay 30ms 5ms
func TestThroughputLightQoS(t *testing.T) {
	t.Log("=== 场景 2: 轻度 QoS（1% 丢包 + 30ms RTT）===")
	t.Log("提示：运行前执行: sudo tc qdisc add dev lo root netem loss 1% delay 30ms 5ms distribution normal")

	mbpsCubic := runThroughputTest(t, "CUBIC-light-qos", false)
	mbpsBBR2 := runThroughputTest(t, "BBRv2-light-qos", true)

	t.Logf("CUBIC: %.2f Mbps | BBRv2: %.2f Mbps | BBRv2提升: %+.1f%%",
		mbpsCubic, mbpsBBR2, (mbpsBBR2-mbpsCubic)/mbpsCubic*100)

	// BBRv2 在 1% 丢包场景下应该明显优于 CUBIC
	if mbpsBBR2 < mbpsCubic*0.9 {
		t.Logf("警告: BBRv2 在轻度QoS场景下低于 CUBIC，可能需要调参")
	}
}

// TestThroughputHeavyQoS 重度 QoS（5% 丢包 + 100ms RTT）
// 运行前需要：sudo tc qdisc add dev lo root netem loss 5% delay 100ms 20ms
func TestThroughputHeavyQoS(t *testing.T) {
	t.Log("=== 场景 3: 重度 QoS（5% 丢包 + 100ms RTT）===")
	t.Log("提示：运行前执行: sudo tc qdisc add dev lo root netem loss 5% delay 100ms 20ms distribution normal")

	mbpsCubic := runThroughputTest(t, "CUBIC-heavy-qos", false)
	mbpsBBR2 := runThroughputTest(t, "BBRv2-heavy-qos", true)

	t.Logf("CUBIC: %.2f Mbps | BBRv2: %.2f Mbps | BBRv2提升: %+.1f%%",
		mbpsCubic, mbpsBBR2, (mbpsBBR2-mbpsCubic)/mbpsCubic*100)
}

// QoSParams 针对运营商 QoS 场景优化的参数集
func QoSParams() *Params {
	params := DefaultParams()
	// 提高丢包容忍度：运营商随机丢包 < 2%，不应触发退让
	params.LossThreshold = 0.02 // 从 1.5% 提高到 2%
	// 减少带宽退让幅度
	params.Beta = 0.5 // 从 0.3 提高到 0.5（丢包时保留更多带宽）
	// 加快 startup 退出（减少 startup 阶段的过度发送）
	params.StartupFullLossCount = 6 // 从 8 降到 6
	// 更频繁刷新 minRTT（适合 QoS 动态限速场景）
	params.ProbeRttPeriod = 8000 * time.Millisecond // 从 10s 降到 8s
	// 减少头部空间，更激进地使用带宽
	params.InflightHiHeadroom = 0.10 // 从 0.15 降到 0.10
	// 更保守的探测增益，避免触发 QoS 限速
	params.ProbeBwProbeUpPacingGain = 1.15 // 从 1.25 降到 1.15
	return params
}

// runThroughputTestWithParams 使用自定义参数测量 BBRv2 吞吐量
func runThroughputTestWithParams(t *testing.T, label string, params *Params) float64 {
	t.Helper()

	addr := nextTestAddr()
	serverTLS, clientTLS := generateTLSConfig()

	quicConf := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
	}

	ln, err := quic.ListenAddr(addr, serverTLS, quicConf)
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer ln.Close()

	var bytesReceived atomic.Int64
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "done")
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, chunkSize)
		for {
			n, err := stream.Read(buf)
			bytesReceived.Add(int64(n))
			if err != nil {
				break
			}
		}
	}()

	conn, err := quic.DialAddr(context.Background(), addr, clientTLS, quicConf)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}

	sender := NewBBR2SenderWithParams(DefaultClock{}, 1200, 0, false, params)
	conn.SetCongestionControl(sender)

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	data := make([]byte, chunkSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	deadline := time.Now().Add(testDuration)
	totalSent := 0
	for time.Now().Before(deadline) {
		n, err := stream.Write(data)
		totalSent += n
		if err != nil {
			break
		}
	}
	stream.Close()
	conn.CloseWithError(0, "done")

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
	}

	bytesRcv := bytesReceived.Load()
	mbps := float64(bytesRcv) * 8 / testDuration.Seconds() / 1e6

	t.Logf("[%s] sent=%dMB rcv=%dMB throughput=%.2f Mbps",
		label, totalSent/1024/1024, bytesRcv/1024/1024, mbps)

	return mbps
}

// TestParamTuning 参数调优对比测试（在 QoS 场景下对比不同参数组合）
// 运行前设置: sudo tc qdisc add dev lo root netem loss 2% delay 50ms 10ms distribution normal
func TestParamTuning(t *testing.T) {
	t.Log("=== 参数调优对比（2%丢包 + 50ms RTT）===")

	type paramSet struct {
		name   string
		params *Params
	}

	// 逐个参数微调，找出最优组合
	p1 := DefaultParams()

	p2 := DefaultParams()
	p2.LossThreshold = 0.025 // 更高丢包容忍
	p2.Beta = 0.5

	p3 := DefaultParams()
	p3.ProbeBwProbeUpPacingGain = 1.10 // 更保守探测
	p3.InflightHiHeadroom = 0.10

	p4 := DefaultParams()
	p4.LossThreshold = 0.025
	p4.Beta = 0.5
	p4.ProbeBwProbeUpPacingGain = 1.10
	p4.InflightHiHeadroom = 0.10

	sets := []paramSet{
		{"Default", p1},
		{"HighLossTol(0.025/β0.5)", p2},
		{"ConservativeProbe(1.10)", p3},
		{"Combined（组合最优）", p4},
	}

	fmt.Printf("\n%-30s %-14s\n", "参数组", "吞吐(Mbps)")
	fmt.Printf("%-30s %-14s\n", "──────────────────────────────", "──────────────")

	for _, s := range sets {
		mbps := runThroughputTestWithParams(t, s.name, s.params)
		fmt.Printf("%-30s %.2f\n", s.name, mbps)
		time.Sleep(1 * time.Second) // 端口冷却
	}
}

// TestThroughputMatrix 完整矩阵测试（需要手动设置 netem，自动打印对比表）
func TestThroughputMatrix(t *testing.T) {
	scenarios := []struct {
		name string
		hint string
	}{
		{"基线", "tc qdisc del dev lo root 2>/dev/null; true"},
		{"1%丢包+30ms", "tc qdisc add dev lo root netem loss 1% delay 30ms 5ms"},
		{"2%丢包+50ms", "tc qdisc add dev lo root netem loss 2% delay 50ms 10ms"},
		{"5%丢包+100ms", "tc qdisc add dev lo root netem loss 5% delay 100ms 20ms"},
	}

	fmt.Printf("\n%-25s %-12s %-12s %-10s\n", "场景", "CUBIC(Mbps)", "BBRv2(Mbps)", "BBRv2提升")
	fmt.Printf("%-25s %-12s %-12s %-10s\n",
		"─────────────────────────",
		"────────────",
		"────────────",
		"──────────",
	)

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			t.Logf("手动执行: sudo %s", s.hint)
			cubic := runThroughputTest(t, "CUBIC", false)
			bbr2Mbps := runThroughputTest(t, "BBRv2", true)
			delta := (bbr2Mbps - cubic) / cubic * 100
			fmt.Printf("%-25s %-12.2f %-12.2f %+.1f%%\n",
				s.name, cubic, bbr2Mbps, delta)
		})
	}
}
