package server

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireToken 返回一个 HTTP middleware，用于验证 Bearer token。
// 使用恒定时间比较防止时序攻击。
func requireToken(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 从 Authorization header 中提取 token
			auth := r.Header.Get("Authorization")
			if auth == "" {
				apiError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			// 检查格式：Bearer <token>
			const prefix = "Bearer "
			if !strings.HasPrefix(auth, prefix) {
				apiError(w, http.StatusUnauthorized, "invalid authorization format")
				return
			}

			providedToken := auth[len(prefix):]

			// 恒定时间比较，防止时序攻击
			if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
				apiError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// 验证通过，继续处理请求
			next.ServeHTTP(w, r)
		})
	}
}
