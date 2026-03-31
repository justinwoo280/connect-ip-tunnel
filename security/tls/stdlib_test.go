package tls

import (
	"crypto/tls"
	"errors"
	"testing"
)

// mockECHRejectionError 构造一个带 RetryConfigList 的 ECHRejectionError。
// Go 标准库中 ECHRejectionError 是一个具体类型，我们直接构造它。
func mockECHRejection(retryList []byte) error {
	return &tls.ECHRejectionError{RetryConfigList: retryList}
}

// --- NewClient 严格模式测试 ---

func TestNewClientECHDisabled_NoError(t *testing.T) {
	// EnableECH=false 时，即使没有任何 ECH 配置也应成功
	p := NewProvider()
	cfg, err := p.NewClient(nil, ClientOptions{
		ServerName:   "example.com",
		NextProtos:   []string{"h3"},
		UseSystemCAs: true,
	})
	if err != nil {
		t.Fatalf("expected no error when ECH disabled, got: %v", err)
	}
	defer cfg.Close()
}

func TestNewClientECHEnabled_NoConfig_ReturnsError(t *testing.T) {
	// EnableECH=true 但没有提供任何 ECH 配置来源，应返回错误（不降级）
	p := NewProvider()
	_, err := p.NewClient(nil, ClientOptions{
		ServerName: "example.com",
		NextProtos: []string{"h3"},
		EnableECH:  true,
		// 没有 ECHConfigList，没有 ECHManager
	})
	if err == nil {
		t.Fatal("expected error when ECH enabled but no config provided")
	}
}

func TestNewClientECHEnabled_WithStaticConfig_OK(t *testing.T) {
	// EnableECH=true + 静态 ECHConfigList 应成功
	fakeECHList := []byte{0x00, 0x01, 0x02, 0x03}
	p := NewProvider()
	cfg, err := p.NewClient(nil, ClientOptions{
		ServerName:    "example.com",
		NextProtos:    []string{"h3"},
		EnableECH:     true,
		ECHConfigList: fakeECHList,
	})
	if err != nil {
		t.Fatalf("expected success with static ECH config, got: %v", err)
	}
	defer cfg.Close()

	tlsCfg := cfg.TLSConfig()
	if len(tlsCfg.EncryptedClientHelloConfigList) == 0 {
		t.Fatal("expected ECH config to be set in tls.Config")
	}
}

func TestNewClientECHEnabled_MaxRetriesDefault(t *testing.T) {
	// 确认默认 maxRetries = 3
	fakeECHList := []byte{0x00, 0x01}
	p := NewProvider()
	cfg, err := p.NewClient(nil, ClientOptions{
		ServerName:    "example.com",
		NextProtos:    []string{"h3"},
		EnableECH:     true,
		ECHConfigList: fakeECHList,
		ECHMaxRetries: 0, // 0 = 使用默认值
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cfg.Close()

	sc := cfg.(*stdlibClientConfig)
	if sc.maxRetries != defaultECHMaxRetries {
		t.Fatalf("expected maxRetries=%d, got %d", defaultECHMaxRetries, sc.maxRetries)
	}
}

func TestNewClientECHEnabled_CustomMaxRetries(t *testing.T) {
	fakeECHList := []byte{0x00, 0x01}
	p := NewProvider()
	cfg, err := p.NewClient(nil, ClientOptions{
		ServerName:    "example.com",
		NextProtos:    []string{"h3"},
		EnableECH:     true,
		ECHConfigList: fakeECHList,
		ECHMaxRetries: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cfg.Close()

	sc := cfg.(*stdlibClientConfig)
	if sc.maxRetries != 5 {
		t.Fatalf("expected maxRetries=5, got %d", sc.maxRetries)
	}
}

// --- HandleHandshakeError 测试 ---

func TestHandleHandshakeError_NonECHError_PassThrough(t *testing.T) {
	// 非 ECH 错误直接透传，不重试
	cfg := &stdlibClientConfig{
		cfg:        &tls.Config{},
		baseCfg:    &tls.Config{},
		maxRetries: 3,
	}
	someErr := errors.New("some network error")
	retry, outErr := cfg.HandleHandshakeError(someErr)
	if retry {
		t.Fatal("expected retry=false for non-ECH error")
	}
	if outErr != someErr {
		t.Fatalf("expected original error, got: %v", outErr)
	}
}

func TestHandleHandshakeError_NilError(t *testing.T) {
	cfg := &stdlibClientConfig{
		cfg:        &tls.Config{},
		baseCfg:    &tls.Config{},
		maxRetries: 3,
	}
	retry, outErr := cfg.HandleHandshakeError(nil)
	if retry || outErr != nil {
		t.Fatalf("expected (false, nil) for nil error, got (%v, %v)", retry, outErr)
	}
}

func TestHandleHandshakeError_ECHRejected_WithRetryConfig_Retries(t *testing.T) {
	// 服务端拒绝 ECH 并返回 RetryConfigList → retry=true，更新配置
	retryList := []byte{0xAA, 0xBB, 0xCC}
	base := &tls.Config{ServerName: "example.com"}
	cfg := &stdlibClientConfig{
		cfg:        buildECHTLSConfig(base, []byte{0x11}),
		baseCfg:    base,
		maxRetries: 3,
		retryCount: 0,
	}

	retry, outErr := cfg.HandleHandshakeError(mockECHRejection(retryList))
	if !retry {
		t.Fatalf("expected retry=true, got false (err=%v)", outErr)
	}
	if outErr != nil {
		t.Fatalf("expected no error on first retry, got: %v", outErr)
	}
	if cfg.retryCount != 1 {
		t.Fatalf("expected retryCount=1, got %d", cfg.retryCount)
	}
	// 新的 TLS config 应该包含新的 ECH 配置
	if string(cfg.cfg.EncryptedClientHelloConfigList) != string(retryList) {
		t.Fatal("ECH config not updated with retry list")
	}
}

func TestHandleHandshakeError_ECHRejected_NoRetryConfig_Fails(t *testing.T) {
	// 服务端拒绝 ECH 但没有提供 RetryConfigList → 返回 ErrECHRejected，不重试
	base := &tls.Config{}
	cfg := &stdlibClientConfig{
		cfg:        buildECHTLSConfig(base, []byte{0x11}),
		baseCfg:    base,
		maxRetries: 3,
	}

	retry, outErr := cfg.HandleHandshakeError(mockECHRejection(nil))
	if retry {
		t.Fatal("expected retry=false when no RetryConfigList")
	}
	if !errors.Is(outErr, ErrECHRejected) {
		t.Fatalf("expected ErrECHRejected, got: %v", outErr)
	}
}

func TestHandleHandshakeError_ECHRejected_ExceedsMaxRetries(t *testing.T) {
	// 超过最大重试次数后，返回 ErrECHRejected，不再重试
	retryList := []byte{0xAA, 0xBB}
	base := &tls.Config{}
	cfg := &stdlibClientConfig{
		cfg:        buildECHTLSConfig(base, []byte{0x11}),
		baseCfg:    base,
		maxRetries: 3,
		retryCount: 3, // 已经重试了 3 次
	}

	retry, outErr := cfg.HandleHandshakeError(mockECHRejection(retryList))
	if retry {
		t.Fatal("expected retry=false after exceeding max retries")
	}
	if !errors.Is(outErr, ErrECHRejected) {
		t.Fatalf("expected ErrECHRejected, got: %v", outErr)
	}
}

func TestHandleHandshakeError_ECHRejected_FullRetrySequence(t *testing.T) {
	// 模拟完整序列：3次 HRR 重试后第4次失败
	retryList := []byte{0xAA, 0xBB}
	base := &tls.Config{ServerName: "example.com"}
	cfg := &stdlibClientConfig{
		cfg:        buildECHTLSConfig(base, []byte{0x11}),
		baseCfg:    base,
		maxRetries: 3,
	}

	// 第1次
	retry, err := cfg.HandleHandshakeError(mockECHRejection(retryList))
	if !retry || err != nil {
		t.Fatalf("attempt 1: expected retry=true, err=nil; got retry=%v err=%v", retry, err)
	}
	// 第2次
	retry, err = cfg.HandleHandshakeError(mockECHRejection(retryList))
	if !retry || err != nil {
		t.Fatalf("attempt 2: expected retry=true, err=nil; got retry=%v err=%v", retry, err)
	}
	// 第3次
	retry, err = cfg.HandleHandshakeError(mockECHRejection(retryList))
	if !retry || err != nil {
		t.Fatalf("attempt 3: expected retry=true, err=nil; got retry=%v err=%v", retry, err)
	}
	if cfg.retryCount != 3 {
		t.Fatalf("expected retryCount=3, got %d", cfg.retryCount)
	}
	// 第4次：超过上限，断连
	retry, err = cfg.HandleHandshakeError(mockECHRejection(retryList))
	if retry {
		t.Fatal("attempt 4: expected retry=false after exceeding max retries")
	}
	if !errors.Is(err, ErrECHRejected) {
		t.Fatalf("attempt 4: expected ErrECHRejected, got: %v", err)
	}
}

func TestHandleHandshakeError_NonECH_NoRetry_WhenECHEnabled(t *testing.T) {
	// ECH 模式下遇到非 ECH 错误（如网络超时），应透传不重试
	base := &tls.Config{}
	cfg := &stdlibClientConfig{
		cfg:        buildECHTLSConfig(base, []byte{0x11}),
		baseCfg:    base,
		maxRetries: 3,
	}
	netErr := errors.New("connection refused")
	retry, outErr := cfg.HandleHandshakeError(netErr)
	if retry {
		t.Fatal("expected retry=false for non-ECH error in ECH mode")
	}
	if outErr != netErr {
		t.Fatalf("expected original error, got: %v", outErr)
	}
}

func TestHandleHandshakeError_NoECHMode_PassThrough(t *testing.T) {
	// maxRetries=0 表示非 ECH 模式，所有错误直接透传
	cfg := &stdlibClientConfig{
		cfg:        &tls.Config{},
		baseCfg:    &tls.Config{},
		maxRetries: 0,
	}
	someErr := errors.New("any error")
	retry, outErr := cfg.HandleHandshakeError(someErr)
	if retry {
		t.Fatal("expected retry=false in non-ECH mode")
	}
	if outErr != someErr {
		t.Fatalf("expected original error, got: %v", outErr)
	}
}
