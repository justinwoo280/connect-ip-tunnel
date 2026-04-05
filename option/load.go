package option

import (
	"encoding/json"
	"fmt"
	"os"
)

// DefaultConfig 返回客户端的默认配置。
func DefaultConfig() ClientConfig {
	cfg := ClientConfig{
		ConnectIP: ConnectIPConfig{
			URI:                  "https://localhost/.well-known/masque/ip",
			WaitForAddressAssign: true,
			EnableReconnect:      true,
		},
		HTTP3: HTTP3Config{
			EnableDatagrams: true,
		},
	}
	cfg.ApplyDefaults()
	return cfg
}

func Load(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("option: read config file: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("option: parse config file: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadOrDefault(path string) (Config, error) {
	if path == "" {
		return Config{}, fmt.Errorf("option: config file path is required")
	}
	return Load(path)
}

