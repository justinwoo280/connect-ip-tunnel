// Package observability 提供结构化日志、Prometheus 指标等可观测性基础设施。
package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Level 日志级别
type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// LoggerOptions 日志配置
type LoggerOptions struct {
	Level  Level
	Format string // "text" | "json"
	Output io.Writer
}

var defaultLogger = slog.Default()

// InitLogger 初始化全局结构化日志，替换 log/slog 默认 logger。
func InitLogger(opts LoggerOptions) {
	if opts.Output == nil {
		opts.Output = os.Stdout
	}

	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{Level: opts.Level}

	switch opts.Format {
	case "json":
		handler = slog.NewJSONHandler(opts.Output, handlerOpts)
	default:
		handler = slog.NewTextHandler(opts.Output, handlerOpts)
	}

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// Logger 返回全局 logger（可直接用 slog 包函数，也可用此方法注入）
func Logger() *slog.Logger {
	return defaultLogger
}

// WithSession 返回带 session_id 字段的子 logger
func WithSession(sessionID string) *slog.Logger {
	return defaultLogger.With(slog.String("session_id", sessionID))
}

// WithComponent 返回带组件名称的子 logger
func WithComponent(name string) *slog.Logger {
	return defaultLogger.With(slog.String("component", name))
}

// ContextWithLogger 将 logger 注入 context
func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// LoggerFromContext 从 context 中取出 logger，若没有则返回全局 logger
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return defaultLogger
}

type loggerKey struct{}
