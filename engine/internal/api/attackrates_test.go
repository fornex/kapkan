package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/mitigate"

	"log/slog"
)

// settableClock is a monotonic-enough time source a test can step, so the
// engine's sliding window can be filled with completed seconds.
type settableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *settableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *settableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// serverWithEngineClock builds a Server whose engine runs on clk, and returns
// both so the test can feed the engine flows directly.
func serverWithEngineClock(t *testing.T, store *config.Store, clk *settableClock) (*Server, *engine.Engine) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	eng := engine.New(store, engine.WithLogger(log), engine.WithClock(clk.Now))
	mit, err := mitigate.New(store, log)
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	return New(store, eng, mit, log), eng
}

// floodFlow is one NetFlow v9 record carrying a whole second of 520 000
// sampling-corrected pps (520 sampled packets at a reported 1-in-1000 rate).
func floodFlow(dst string) flow.Flow {
	return flow.Flow{
		SrcAddr:      netip.MustParseAddr("198.51.100.7"),
		DstAddr:      netip.MustParseAddr(dst),
		IPProto:      17,
		SrcPort:      123,
		DstPort:      40000,
		Bytes:        520 * 64,
		Packets:      520,
		SamplingRate: 1000,
		Wire:         flow.ProtoNetFlow9,
	}
}

const floodPPS = 520 * 1000

// TestActiveAttackRatesAreLive covers handleAttacks replacing a live attack's
// detection-time measurement with the engine's current one.
//
// An attack record is stamped when the threshold crosses, which is the first
// sliding window with any data in it — a fifth of a sustained flood at the
// default window. Nothing rewrote it afterwards (AttackOngoing goes to
// mitigation, not the API), so a minutes-long attack reported its first, weakest
// second for its whole life, and /api/v1/attacks contradicted /api/v1/hosts
// about the same host at the same moment.
func TestActiveAttackRatesAreLive(t *testing.T) {
	target := netip.MustParseAddr("203.0.113.50")

	// fill runs the engine's window up to a steady floodPPS on target.
	fill := func(eng *engine.Engine, clk *settableClock) {
		for s := 0; s < 5; s++ {
			eng.Process(floodFlow(target.String()))
			clk.Advance(time.Second)
		}
	}
	// onset is the event the engine emits at detection: the flood measured over
	// a window holding one of its five seconds.
	onset := engine.Event{
		Kind:      engine.AttackStarted,
		Scope:     engine.ScopeHost,
		Target:    target,
		Direction: engine.DirIncoming,
		Metric:    engine.MetricPPS,
		Rate:      floodPPS / 5,
		Threshold: 80000,
		Rates:     engine.Rates{PPS: floodPPS / 5, Mbps: 26.624, FlowsPerSec: 200},
		At:        time.Now(),
	}
	get := func(t *testing.T, s *Server) (active, recent []Attack) {
		t.Helper()
		rec := do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var resp struct {
			Active []Attack `json:"active"`
			Recent []Attack `json:"recent"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Active, resp.Recent
	}

	t.Run("an active attack reports the engine's current rate", func(t *testing.T) {
		clk := &settableClock{t: time.Unix(1_700_000_000, 0)}
		s, eng := serverWithEngineClock(t, storeFromYAML(t, apiYAML), clk)
		s.RecordAttackStarted(onset, nil)
		fill(eng, clk)

		active, _ := get(t, s)
		if len(active) != 1 {
			t.Fatalf("active = %d, want 1", len(active))
		}
		a := active[0]
		if a.Rates.PPS != floodPPS {
			t.Errorf("rates.pps = %v, want %d (the live windowed rate)", a.Rates.PPS, floodPPS)
		}
		// The headline rate is re-derived for the metric that tripped, so
		// rate-vs-threshold stays a live comparison of the same quantity.
		if a.Rate != floodPPS {
			t.Errorf("rate = %v, want %d", a.Rate, floodPPS)
		}
		// The whole measurement is replaced, not just pps.
		if want := float64(floodPPS) * 64 * 8 / 1e6; a.Rates.Mbps != want {
			t.Errorf("rates.mbps = %v, want %v", a.Rates.Mbps, want)
		}
		// Metric and threshold name what tripped and must not move: the engine
		// judges the attack's end against the thresholds frozen at its start.
		if a.Metric != engine.MetricPPS {
			t.Errorf("metric = %q, want pps", a.Metric)
		}
		if a.Threshold != 80000 {
			t.Errorf("threshold = %v, want 80000", a.Threshold)
		}
	})

	t.Run("an ended attack keeps its final measurement", func(t *testing.T) {
		clk := &settableClock{t: time.Unix(1_700_000_000, 0)}
		s, eng := serverWithEngineClock(t, storeFromYAML(t, apiYAML), clk)
		s.RecordAttackStarted(onset, nil)
		fill(eng, clk)
		// The engine's last measurement before it declared the attack over. The
		// host is still tracked at floodPPS, so a refresh applied to the recent
		// ring would overwrite this with the live number.
		s.RecordAttackEnded(engine.Event{
			Kind: engine.AttackEnded, Scope: engine.ScopeHost, Target: target,
			Direction: engine.DirIncoming, Metric: engine.MetricPPS,
			Rate: 1234, Rates: engine.Rates{PPS: 1234}, At: clk.Now(),
		}, nil)

		active, recent := get(t, s)
		if len(active) != 0 || len(recent) != 1 {
			t.Fatalf("active = %d, recent = %d; want 0 and 1", len(active), len(recent))
		}
		if recent[0].Rates.PPS != 1234 {
			t.Errorf("recent rates.pps = %v, want 1234 (AttackEnded's measurement)", recent[0].Rates.PPS)
		}
	})

	t.Run("an attack whose host the engine dropped keeps its snapshot", func(t *testing.T) {
		clk := &settableClock{t: time.Unix(1_700_000_000, 0)}
		s, _ := serverWithEngineClock(t, storeFromYAML(t, apiYAML), clk)
		// Never fed to the engine, so it tracks no such host — a stand-in for a
		// host evicted after going quiet. A zero here would read as "the attack
		// stopped", so the snapshot must survive.
		s.RecordAttackStarted(onset, nil)

		active, _ := get(t, s)
		if len(active) != 1 {
			t.Fatalf("active = %d, want 1", len(active))
		}
		if active[0].Rates.PPS != floodPPS/5 {
			t.Errorf("rates.pps = %v, want %d (the detection-time snapshot)",
				active[0].Rates.PPS, floodPPS/5)
		}
	})
}
