package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/exporter"
)

// The nginx-exporter role run whole, observing an empty log: SIGHUP is logged
// and ignored — there is no file to reopen, the tailer follows logrotate on its
// own — and SIGTERM stops the role cleanly.
func TestNginxExporterRoleOutlivesSIGHUP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kapkan.json.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := exporter.Config{
		LogPath: path, APIBase: "http://127.0.0.1:8080", Observe: true,
		Window: 10 * time.Second, RPS: 50, MinRequests: 100, TTL: 5 * time.Minute,
		Log: log,
	}
	done := make(chan error, 1)
	go func() { done <- runExporter(cfg, log) }()
	logs.waitFor(t, "nginx-exporter started", 1)

	hupIgnored(t, "nginx-exporter", &logs, done)
	termStops(t, "nginx-exporter", done)
}
