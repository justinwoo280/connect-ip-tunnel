package safe

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"connect-ip-tunnel/observability"
)

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
				observability.Global.Panics.WithLabelValues(component).Inc()
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
				observability.Global.Panics.WithLabelValues(component).Inc()
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
