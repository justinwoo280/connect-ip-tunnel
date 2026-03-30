package connectip

import (
	"context"
	"fmt"
	"net/http"

	h3transport "connect-ip-tunnel/transport/http3"
	"connect-ip-tunnel/platform/tun"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/yosida95/uritemplate/v3"
)

// Client 使用 HTTP/3 工厂建立 CONNECT-IP 会话。
type Client struct {
	h3  h3transport.ClientFactory
	dev tun.Device // 用于 ICMP 回包写回，可为 nil
}

func NewClient(h3 h3transport.ClientFactory, dev tun.Device) *Client {
	return &Client{h3: h3, dev: dev}
}

// Open 建立到 target 的 CONNECT-IP 会话。
// opts.URI 是路径部分（例如 "/.well-known/masque/ip"），
// 会自动拼接为 https://<authority><uri> 形式的 URI Template。
//
// 注意：客户端认证已通过 mTLS 在 TLS 握手阶段完成，无需在 HTTP 层注入鉴权信息。
func (c *Client) Open(ctx context.Context, target h3transport.Target, opts Options) (*Session, error) {
	clientConn, err := c.h3.Dial(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("connectip: dial h3: %w", err)
	}

	authority := opts.Authority
	if authority == "" {
		authority = target.Addr
	}

	uriStr := opts.URI
	// 若 URI 是相对路径，补全为完整 URI Template
	if len(uriStr) > 0 && uriStr[0] == '/' {
		uriStr = "https://" + authority + uriStr
	}

	tmpl, err := uritemplate.New(uriStr)
	if err != nil {
		return nil, fmt.Errorf("connectip: parse uri template %q: %w", uriStr, err)
	}

	// TODO: 当 connect-ip-go 支持自定义 header 时，在此处注入鉴权信息
	// 临时方案：opts.AuthFunc 保留接口，等待库更新
	conn, resp, err := connectipgo.Dial(ctx, clientConn, tmpl)
	if err != nil {
		return nil, fmt.Errorf("connectip: dial: %w", err)
	}
	if resp != nil {
		// 检查鉴权失败的响应
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, fmt.Errorf("connectip: authentication failed (status %d)", resp.StatusCode)
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}

	return newSession(conn, c.dev), nil
}
