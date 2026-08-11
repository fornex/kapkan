package engine

import (
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/flow"
)

// onsetYAML puts pps far below the flood these tests inject — so the crossing
// happens on the very first tick that has any data at all — and mbps and
// flows_per_sec far above it, so pps is unambiguously the metric that trips
// (all three are required to be > 0).
const onsetYAML = `
listen:
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
thresholds:
  pps: 20000
  mbps: 100000
  flows_per_sec: 10000000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 3
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
notify: {}
api:
  listen: "127.0.0.1:8080"
`

// onsetThreshold is onsetYAML's pps threshold.
const onsetThreshold = 20000

// nf9Flow is one NetFlow v9 data record carrying packets sampled packets of
// 64 bytes at a reported 1-in-rate sampling rate.
func nf9Flow(dst string, packets, rate uint64) flow.Flow {
	f := udpFlow(dst, packets*64, packets, rate)
	f.Wire = flow.ProtoNetFlow9
	return f
}

// The flood these tests inject: one second of it is 130 NetFlow records of 4
// packets each at a reported 1-in-1000 rate, i.e. 520 000 sampling-corrected
// pps — 26x the onsetYAML threshold.
const (
	onsetRecordsPerSec = 130
	onsetPktsPerRecord = 4
	onsetSamplingRate  = 1000
	onsetTruePPS       = onsetRecordsPerSec * onsetPktsPerRecord * onsetSamplingRate
)

// TestDetectionRateDilutedByPartialWindow pins why the rate a detection
// reports is a fraction of the sustained rate the wire data implies, and why
// that fraction moves with nothing but where the exporter's first datagram
// falls relative to a second boundary.
//
// windowedRates sums the window's completed seconds and always divides by the
// full window length, so a window in which only k of its windowSec seconds
// carried traffic yields trueRate*k/windowSec. An attack is detected on the
// FIRST window that crosses a threshold, which for any flood well over the
// threshold is the window holding a single second — so the AttackStarted event
// is stamped with trueRate/windowSec, or half that again when the exporter
// started mid-second. The engine's own live rate converges to trueRate a few
// seconds later; the event's copy never does, and every consumer that keeps it
// (the API's /api/v1/attacks record, notifications) keeps the onset number.
func TestDetectionRateDilutedByPartialWindow(t *testing.T) {
	dst := "203.0.113.45"

	newEngine := func(t *testing.T) (*Engine, *mockClock) {
		t.Helper()
		clk := newMockClock()
		return New(groupsStore(t, onsetYAML), WithClock(clk.Now), WithWindow(5)), clk
	}
	flood := func(e *Engine, records int) {
		for i := 0; i < records; i++ {
			e.Process(nf9Flow(dst, onsetPktsPerRecord, onsetSamplingRate))
		}
	}
	// started reads the lifecycle channel, which evalTick fills synchronously
	// (emit is a non-blocking send into a buffered channel), so polling it
	// right after a tick is deterministic — no drain goroutine to race.
	started := func(e *Engine) (Event, bool) {
		for {
			select {
			case ev := <-e.Events():
				if ev.Kind == AttackStarted {
					return ev, true
				}
			default:
				return Event{}, false
			}
		}
	}
	mustStart := func(t *testing.T, e *Engine) Event {
		t.Helper()
		ev, ok := started(e)
		if !ok {
			t.Fatal("no AttackStarted event")
		}
		return ev
	}
	livePPS := func(t *testing.T, e *Engine) float64 {
		t.Helper()
		for _, h := range e.Snapshot() {
			if h.Target.String() == dst {
				return h.Rates.PPS
			}
		}
		t.Fatalf("%s not tracked", dst)
		return 0
	}

	// A whole second of the flood, complete before the tick that reads it: the
	// window holds 1 of its 5 seconds, so the detection reports a fifth of the
	// real rate.
	t.Run("one full second in a five second window reports a fifth", func(t *testing.T) {
		e, clk := newEngine(t)
		flood(e, onsetRecordsPerSec)
		clk.Advance(time.Second) // that second is now complete
		e.evalTick(clk.Now())

		ev := mustStart(t, e)
		if want := float64(onsetTruePPS) / 5; ev.Rates.PPS != want {
			t.Errorf("AttackStarted pps = %v, want %v (one second of a five-second window)",
				ev.Rates.PPS, want)
		}
		if ev.Rate != ev.Rates.PPS {
			t.Errorf("event Rate = %v, Rates.PPS = %v; want the same number", ev.Rate, ev.Rates.PPS)
		}
	})

	// The same flood whose exporter happens to start halfway through a second:
	// the first completed second carries half the records, so the detection
	// reports a TENTH of the real rate. Nothing about the traffic or the
	// sampling rate changed — only the phase of the exporter's ticks against
	// the wall clock, which is why the reported number is not reproducible run
	// to run.
	t.Run("exporter starting mid second reports a tenth", func(t *testing.T) {
		e, clk := newEngine(t)
		flood(e, onsetRecordsPerSec/2)
		clk.Advance(time.Second)
		e.evalTick(clk.Now())

		ev := mustStart(t, e)
		if want := float64(onsetTruePPS) / 10; ev.Rates.PPS != want {
			t.Errorf("AttackStarted pps = %v, want %v (half a second of a five-second window)",
				ev.Rates.PPS, want)
		}
	})

	// The window fills a fifth per second and the live rate reaches the true
	// rate on the fifth tick, where it stays. The detection's frozen copy is
	// still the onset fifth — a number the engine itself contradicts four
	// seconds later.
	t.Run("live rate converges while the detection keeps the onset number", func(t *testing.T) {
		e, clk := newEngine(t)
		var onset Event
		// Fifths of the true rate the live window should read after each of
		// six seconds: it ramps, then holds at 5/5.
		for i, fifths := range []float64{1, 2, 3, 4, 5, 5} {
			flood(e, onsetRecordsPerSec)
			clk.Advance(time.Second)
			e.evalTick(clk.Now())
			if i == 0 {
				onset = mustStart(t, e)
			}
			if got, want := livePPS(t, e), float64(onsetTruePPS)*fifths/5; got != want {
				t.Errorf("after %d complete seconds live pps = %v, want %v", i+1, got, want)
			}
		}
		if want := float64(onsetTruePPS) / 5; onset.Rates.PPS != want {
			t.Errorf("AttackStarted pps = %v, want %v", onset.Rates.PPS, want)
		}
		if live := livePPS(t, e); live == onset.Rates.PPS {
			t.Fatalf("live pps and the detection's pps agree (%v); the test no longer "+
				"exercises the divergence it is here to pin", live)
		}
	})

	// The same dilution is what sets time-to-detect, which is the half of this
	// that a ban actually rides on: the crossing is judged on the diluted
	// window, so a flood must either clear windowSec x the threshold to trip on
	// its first second, or wait for enough of the window to fill. The closer a
	// flood sits to its threshold, the longer that takes, up to the full window.
	// This is the safe direction — a partial window can only under-report, so it
	// never bans a host early — but it is not free, and it is why a threshold
	// set just under a host's normal peak costs seconds of unmitigated traffic.
	t.Run("time to detect grows as the flood approaches the threshold", func(t *testing.T) {
		for _, tc := range []struct {
			overThreshold float64
			wantSeconds   int
		}{
			{26, 1},  // the flood above, 520 000 pps: trips on the first second
			{2, 3},   // 40 000 pps: fifths of 8 000, 16 000, 24 000
			{1.2, 5}, // 24 000 pps: needs the whole window
		} {
			e, clk := newEngine(t)
			// One record per second carrying that second's whole packet count,
			// so the injected rate is exact at any multiple of the threshold.
			pkts := uint64(onsetThreshold * tc.overThreshold / onsetSamplingRate)
			var got int
			for s := 1; s <= 6 && got == 0; s++ {
				e.Process(nf9Flow(dst, pkts, onsetSamplingRate))
				clk.Advance(time.Second)
				e.evalTick(clk.Now())
				if _, ok := started(e); ok {
					got = s
				}
			}
			if got != tc.wantSeconds {
				t.Errorf("flood at %gx the threshold detected after %d complete seconds, want %d",
					tc.overThreshold, got, tc.wantSeconds)
			}
		}
	})
}
