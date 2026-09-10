package storage

import (
	"context"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

// TestFlushOnShutdownWithFullBatches: rows enqueued right before the context
// is cancelled all reach ClickHouse, even when they fill batches — the
// size-triggered flush must not send on the cancelled run context (which
// would fail with "context canceled" and drop rows that were already ours).
// Found by the real-ClickHouse suite: eleven rows, a batch size of ten, a
// cancel right after the writes — six inserts failed.
func TestFlushOnShutdownWithFullBatches(t *testing.T) {
	counter := func(result string) float64 {
		return testutil.ToFloat64(metrics.StorageRowsTotal.WithLabelValues("attack_events", result))
	}
	for attempt := 0; attempt < 20; attempt++ {
		rec := newRecorder()
		srv, cfg := rec.server(t)
		cfg.BatchSize = 2
		written, dropped, errored := counter("written"), counter("dropped"), counter("error")
		w := NewWriter(cfg, slog.New(slog.NewTextHandler(tLogWriter{t}, nil)))
		ctx, cancel := context.WithCancel(context.Background())
		w.Start(ctx)
		for i := 0; i < 7; i++ {
			w.WriteAttack(sampleAttack())
		}
		cancel()
		w.Stop()
		got := len(rec.inserts("attack_events"))
		srv.Close()
		if got != 7 {
			t.Fatalf("attempt %d: %d of 7 rows reached the server after a cancel with full batches pending (written +%v, dropped +%v, error +%v)",
				attempt, got, counter("written")-written, counter("dropped")-dropped, counter("error")-errored)
		}
	}
}
