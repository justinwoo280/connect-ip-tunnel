package safe

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"connect-ip-tunnel/observability"
)

// recordPanic 在 observability.Global 已注册时记录一次 panic 计数。
// 在测试或 metrics 尚未初始化的场景下安全 no-op。
func recordPanic(component string) {
	if g := observability.Global; g != nil && g.Panics != nil {
		g.Panics.WithLabelValues(component).Inc()
	}
}

// Go starts a goroutine that recovers from panics.
// component is used for metric labels and logging.
func Go(component string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("goroutine panic",
					"component", component,
					"err", r,
					"stack", string(debug.Stack()))
				recordPanic(component)
			}
		}()
		fn()
	}()
}

// HTTP returns a middleware that wraps the handler with panic recovery.
func HTTP(component string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("http handler panic",
					"component", component,
					"path", r.URL.Path,
					"err", rec,
					"stack", string(debug.Stack()))
				recordPanic(component)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
