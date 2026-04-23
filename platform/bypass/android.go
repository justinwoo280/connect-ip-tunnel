//go:build android

package bypass

type androidProvider struct{}

func NewProvider() Provider {
	return &androidProvider{}
}

func (p *androidProvider) Build(cfg Config) (Dialer, error) {
	// Android 上 socket 保护通常由 VPNService.protect(fd) 负责，
	// 此处先降级到标准 dialer，后续可引入 protect hook。
	if cfg.Strict {
		return nil, ErrNotImplemented
	}
	return newFallbackDialer(), nil
}
