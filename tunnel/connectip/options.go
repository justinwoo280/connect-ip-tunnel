package connectip

import "net/http"

type Options struct {
	URI       string
	Authority string
	AuthFunc  func(*http.Request) error // 可选的鉴权函数，用于修改CONNECT-IP请求
}
