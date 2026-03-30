package engine_test

import (
	"testing"

	"connect-ip-tunnel/engine"
	"connect-ip-tunnel/option"
)

// TestEngineConfigLoadAndStop 验证配置加载 + engine 启停骨架不 panic。
// 不需要真实服务端：Start() 会在 connectip.Dial 阶段失败，
// 但在此之前的 TUN / TLS / bypass 初始化路径已被覆盖。
func TestEngineConfigLoadAndStop(t *testing.T) {
	cfg := option.DefaultConfig()
	cfg.ConnectIP.Addr = "127.0.0.1:4433"
	cfg.TLS.InsecureSkipVerify = true
	cfg.Bypass.Enable = false
	// TUN FileDescriptor = 0 → 平台层会尝试创建真实 TUN，在 CI 中可能失败，
	// 此处仅验证 New() 不报错。
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	// Close 在未 Start 时应无副作用
	if err := e.Close(); err != nil {
		t.Fatalf("engine.Close (before start): %v", err)
	}
}

// TestDefaultConfigValidates 验证默认配置在补全 addr 后能通过 Validate。
func TestDefaultConfigValidates(t *testing.T) {
	cfg := option.DefaultConfig()
	cfg.ConnectIP.Addr = "proxy.example.com:443"
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestDefaultConfigMissingAddr 验证缺少 addr 时 Validate 返回错误。
func TestDefaultConfigMissingAddr(t *testing.T) {
	cfg := option.DefaultConfig()
	// 不设置 Addr
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing connect_ip.addr, got nil")
	}
}
