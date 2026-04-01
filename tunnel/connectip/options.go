package connectip

// Options CONNECT-IP 会话选项。
// 鉴权通过 mTLS 在 TLS 握手阶段完成，此处无需鉴权参数。
type Options struct {
	URI       string
	Authority string
}
