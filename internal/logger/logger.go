// Package logger provides structured logging using Go's slog package.
// It supports configurable format (JSON/text) and log levels via environment variables.
package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// contextKey is a typed key for context values to avoid collisions.
type contextKey string

const requestIDKey contextKey = "request_id"

// Init initializes the global logger from environment variables.
//
// Environment variables:
//   - LOG_FORMAT: "json" (default) or "text"
//   - LOG_LEVEL: "DEBUG", "INFO" (default), "WARN", or "ERROR"
func Init() error {
	format := os.Getenv("LOG_FORMAT")
	if format == "" {
		format = "json"
	}

	levelStr := os.Getenv("LOG_LEVEL")
	if levelStr == "" {
		levelStr = "INFO"
	}

	var level slog.Level
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid LOG_LEVEL: %s (must be DEBUG, INFO, WARN, or ERROR)", levelStr)
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		return fmt.Errorf("invalid LOG_FORMAT: %s (must be json or text)", format)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return nil
}

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from context.
// Returns empty string if not present.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// FromContext returns a logger enriched with the request ID from context.
// If no request ID is present, returns the default logger.
func FromContext(ctx context.Context) *slog.Logger {
	if requestID := GetRequestID(ctx); requestID != "" {
		return slog.Default().With("request_id", requestID)
	}
	return slog.Default()
}

// Info logs at INFO level with context enrichment.
func Info(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Info(msg, args...)
}

// Error logs at ERROR level with context enrichment.
func Error(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Error(msg, args...)
}

// Warn logs at WARN level with context enrichment.
func Warn(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Warn(msg, args...)
}

// Debug logs at DEBUG level with context enrichment.
func Debug(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).Debug(msg, args...)
}
