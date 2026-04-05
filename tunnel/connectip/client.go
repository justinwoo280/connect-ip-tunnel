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

// 注意：HTTP 层鉴权（Bearer/Basic/Custom Header）已废弃。
// 鉴权统一通过 mTLS（TLS 握手阶段的客户端证书）完成。
// 详见 TLSConfig.EnableMTLS / ClientCertFile / ClientKeyFile。

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
// 鉴权通过 mTLS（客户端证书）在 TLS 握手阶段完成，
// 详见 TLSConfig.EnableMTLS / ClientCertFile / ClientKeyFile。
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

	conn, resp, err := connectipgo.Dial(ctx, clientConn, tmpl)
	if err != nil {
		return nil, fmt.Errorf("connectip: dial: %w", err)
	}
	// 注意：Connect-IP 协议中 resp.Body 就是长连接的 HTTP/3 stream 本身，
	// 不能 Close()，否则会立即关闭 stream 导致 ADDRESS_ASSIGN capsule 无法收发。
	// stream 的生命周期由 connectipgo.Conn 内部管理。
	if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		return nil, fmt.Errorf("connectip: server rejected connection (status %d) — check mTLS certificate", resp.StatusCode)
	}

	return newSession(conn, c.dev), nil
}
