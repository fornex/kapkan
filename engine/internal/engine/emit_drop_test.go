package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// dropCountHandler is a thread-safe slog.Handler that counts records whose
// message matches a target string. emit() logs the drop at Error level AND
// increments metrics.EventsDroppedTotal{kind}; this handler asserts the log,
// the test below also asserts the metric.
type dropCountHandler struct {
	target string
	mu     *sync.Mutex
	count  *int
}

func newDropCountHandler(target string) *dropCountHandler {
	return &dropCountHandler{target: target, mu: &sync.Mutex{}, count: new(int)}
}

func (h *dropCountHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *dropCountHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.target {
		h.mu.Lock()
		*h.count++
		h.mu.Unlock()
	}
	return nil
}

func (h *dropCountHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *dropCountHandler) WithGroup(string) slog.Handler      { return h }

func (h *dropCountHandler) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return *h.count
}

// TestEmitDropsWhenBufferFull exercises the channel-full default branch of
// emit(): with a tiny event buffer and NO consumer draining the channel, a
// single evalTick that detects more attacks than the buffer can hold must not
// block or deadlock. The buffer ends up holding exactly its capacity of events
// and every overflow is logged via the "dropping event" error.
//
// All existing engine tests drain() the channel, so this default branch was
// previously never executed.
func TestEmitDropsWhenBufferFull(t *testing.T) {
	const bufCap = 2
	const hostCount = 12 // far more than bufCap, so the buffer overflows

	clk := newMockClock()
	h := newDropCountHandler("engine event channel full, dropping event")
	e := New(testStore(t),
		WithClock(clk.Now),
		WithWindow(5),
		WithEventBuffer(bufCap),
		WithLogger(slog.New(h)),
	)
	// Deliberately do NOT call drain(e): the channel must stay un-consumed so
	// emit hits its default: case once the buffer is full.

	// Distinct destinations inside 203.0.113.0/24, skipping .0 (network),
	// .1 (protected_whitelist) and .255. Each will independently exceed the
	// 80000 pps threshold and produce one AttackStarted.
	dsts := make([]netip.Addr, 0, hostCount)
	for i := 0; i < hostCount; i++ {
		dsts = append(dsts, netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", 100+i)))
	}

	// Flood, mirroring TestAttackLifecycle: 200 records/sec, 1 pkt each,
	// sampling 1000 => 200000 corrected pps per host, well above 80000.
	// Fill three complete seconds so the 5s window is unambiguously above
	// threshold at evaluation time.
	inject := func() {
		for _, dst := range dsts {
			for i := 0; i < 200; i++ {
				e.Process(udpFlow(dst.String(), 100, 1, 1000))
			}
		}
	}
	inject()
	clk.Advance(time.Second)
	inject()
	clk.Advance(time.Second)
	inject()
	clk.Advance(time.Second)

	// Baseline the process-global drop counter; assert the delta below (the vec
	// is shared across tests, so absolute values are not meaningful).
	dropsBefore := testutil.ToFloat64(metrics.EventsDroppedTotal.WithLabelValues("attack_started"))

	// A single evalTick walks every tracked host and emits one AttackStarted
	// per detection. This is the call that must not block when the buffer
	// fills. Run it on a watched goroutine so a hang surfaces as a test
	// failure (in addition to the -race detector / package test timeout).
	done := make(chan struct{})
	go func() {
		e.evalTick(clk.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("evalTick blocked with a full event buffer — emit() did not " +
			"fall through to its non-blocking drop branch")
	}

	// (2) The buffer holds exactly its capacity; the rest were dropped.
	buffered := drainNow(e.Events())
	if len(buffered) != bufCap {
		t.Errorf("buffered events = %d, want exactly buffer capacity %d",
			len(buffered), bufCap)
	}
	for _, ev := range buffered {
		if ev.Kind != AttackStarted {
			t.Errorf("buffered event kind = %v, want AttackStarted", ev.Kind)
		}
	}

	// (3) The drop branch logged once per overflow event. We injected
	// hostCount detections; bufCap fit in the channel, so the remainder were
	// dropped and logged.
	wantDrops := hostCount - bufCap
	if got := h.Count(); got != wantDrops {
		t.Errorf("dropped-event logs = %d, want %d (hostCount %d - bufCap %d)",
			got, wantDrops, hostCount, bufCap)
	}

	// (4) The same drops were counted in EventsDroppedTotal under the
	// attack_started kind (every dropped event here is an AttackStarted).
	dropsAfter := testutil.ToFloat64(metrics.EventsDroppedTotal.WithLabelValues("attack_started"))
	if delta := dropsAfter - dropsBefore; delta != float64(wantDrops) {
		t.Errorf("EventsDroppedTotal{kind=attack_started} delta = %v, want %d", delta, wantDrops)
	}
}

// drainNow non-destructively reads all currently-buffered events from ch
// without blocking once the buffer is empty. Unlike the package drain helper
// (which spawns a goroutine that ranges forever), this returns immediately so
// the test can assert on the exact buffered count.
func drainNow(ch <-chan Event) []Event {
	var out []Event
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}
