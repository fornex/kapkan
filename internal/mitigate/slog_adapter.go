package mitigate

import (
	"log/slog"

	bgplog "github.com/osrg/gobgp/v3/pkg/log"
)

// slogAdapter adapts gobgp's pkg/log.Logger interface to slog, so embedding
// gobgp does not spray logrus output to stderr. Passing this via
// server.LoggerOption replaces gobgp's default logger entirely.
type slogAdapter struct {
	l     *slog.Logger
	level bgplog.LogLevel
}

func newSlogAdapter(l *slog.Logger) *slogAdapter {
	return &slogAdapter{l: l.With("component", "gobgp"), level: bgplog.InfoLevel}
}

func (s *slogAdapter) kv(f bgplog.Fields) []any {
	out := make([]any, 0, len(f)*2)
	for k, v := range f {
		out = append(out, k, v)
	}
	return out
}

func (s *slogAdapter) Panic(msg string, fields bgplog.Fields) {
	s.l.Error(msg, s.kv(fields)...)
	panic(msg)
}

func (s *slogAdapter) Fatal(msg string, fields bgplog.Fields) { s.l.Error(msg, s.kv(fields)...) }
func (s *slogAdapter) Error(msg string, fields bgplog.Fields) { s.l.Error(msg, s.kv(fields)...) }
func (s *slogAdapter) Warn(msg string, fields bgplog.Fields)  { s.l.Warn(msg, s.kv(fields)...) }
func (s *slogAdapter) Info(msg string, fields bgplog.Fields)  { s.l.Info(msg, s.kv(fields)...) }
func (s *slogAdapter) Debug(msg string, fields bgplog.Fields) { s.l.Debug(msg, s.kv(fields)...) }

func (s *slogAdapter) SetLevel(level bgplog.LogLevel) { s.level = level }
func (s *slogAdapter) GetLevel() bgplog.LogLevel      { return s.level }
