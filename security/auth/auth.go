package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

// AuthMethod 定义鉴权方式
type AuthMethod string

const (
	AuthMethodNone   AuthMethod = "none"   // 无鉴权（测试用）
	AuthMethodBearer AuthMethod = "bearer" // Bearer Token（推荐）
	AuthMethodBasic  AuthMethod = "basic"  // HTTP Basic Auth
	AuthMethodCustom AuthMethod = "custom" // 自定义Header（兼容ewp-core）
)

// Config 鉴权配置
type Config struct {
	Method AuthMethod `json:"method"`

	// Bearer Token 模式
	BearerToken string `json:"bearer_token,omitempty"`

	// Basic Auth 模式
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Custom Header 模式
	HeaderName  string `json:"header_name,omitempty"`  // 例如 "X-Auth-Token"
	HeaderValue string `json:"header_value,omitempty"` // 例如 UUID
}

// Provider 鉴权提供者
type Provider struct {
	cfg Config
}

func NewProvider(cfg Config) *Provider {
	return &Provider{cfg: cfg}
}

// ApplyToRequest 将鉴权信息应用到HTTP请求
func (p *Provider) ApplyToRequest(req *http.Request) error {
	switch p.cfg.Method {
	case AuthMethodNone:
		return nil

	case AuthMethodBearer:
		if p.cfg.BearerToken == "" {
			return fmt.Errorf("auth: bearer token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+p.cfg.BearerToken)
		return nil

	case AuthMethodBasic:
		if p.cfg.Username == "" {
			return fmt.Errorf("auth: username is empty")
		}
		auth := p.cfg.Username + ":" + p.cfg.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Authorization", "Basic "+encoded)
		return nil

	case AuthMethodCustom:
		if p.cfg.HeaderName == "" || p.cfg.HeaderValue == "" {
			return fmt.Errorf("auth: custom header name or value is empty")
		}
		req.Header.Set(p.cfg.HeaderName, p.cfg.HeaderValue)
		return nil

	default:
		return fmt.Errorf("auth: unknown method %q", p.cfg.Method)
	}
}

// Validate 验证配置有效性
func (c *Config) Validate() error {
	switch c.Method {
	case AuthMethodNone:
		return nil

	case AuthMethodBearer:
		if c.BearerToken == "" {
			return fmt.Errorf("auth: bearer_token is required for bearer method")
		}
		return nil

	case AuthMethodBasic:
		if c.Username == "" {
			return fmt.Errorf("auth: username is required for basic method")
		}
		return nil

	case AuthMethodCustom:
		if c.HeaderName == "" {
			return fmt.Errorf("auth: header_name is required for custom method")
		}
		if c.HeaderValue == "" {
			return fmt.Errorf("auth: header_value is required for custom method")
		}
		return nil

	default:
		return fmt.Errorf("auth: invalid method %q (must be none/bearer/basic/custom)", c.Method)
	}
}
