// Package logging builds the process-wide slog.Logger: JSON in production,
// human-readable text in development.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a configured slog.Logger. format is "json" or "text"; level is
// one of debug, info, warn, error (defaulting to info).
func New(format, level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
