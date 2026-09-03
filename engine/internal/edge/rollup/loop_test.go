package rollup_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// loop wires the decision service and the rollup the way `kapkan edge` will:
// every decision's log line comes back through the aggregator, the rules see
// every source of a closed window, and their verdicts land in the service.
type loop struct {
	now   time.Time
	svc   *decide.Service
	rules *rollup.Rules
	agg   *rollup.Aggregator
}

func newLoop(t *testing.T, rps, conc uint64, dryRun bool) *loop {
	t.Helper()
	l := &loop{now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return l.now }
	l.svc = decide.New(decide.Options{Now: clock, DryRun: dryRun})
	doc := edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{
		Name: "example.com", Origins: []string{"10.0.0.1:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, Rate: edgedoc.Rate{RPS: rps, Concurrency: conc}},
	})
	l.svc.SetZones(&doc)
	l.rules = &rollup.Rules{Now: clock}
	l.agg = &rollup.Aggregator{
		Window: 10 * time.Second,
		Now:    clock,
		OnRecord: func(r rollup.Record) {
			if r.Decided() {
				l.svc.Complete(r.Zone, r.Src)
			}
		},
		OnWindowFull: func(w rollup.WindowStats) { l.rules.Apply(w, l.svc) },
	}
	l.agg.SetZones([]string{"example.com"})
	return l
}

// request runs one request through decide and back through the log, as
// nginx would: the decision's status, reason and mark land in the record.
func (l *loop) request(src netip.Addr) decide.Verdict {
	v := l.svc.Decide("example.com", src)
	status, decision := 200, "200"
	if !v.Allow {
		status, decision = 403, "403"
		if v.Reason == decide.ReasonRate || v.Reason == decide.ReasonConcurrency {
			status = 429
		}
	}
	rec := rollup.Record{TS: l.now, Zone: "example.com", Src: src, Port: 443, Status: status, Decision: decision, Mark: v.Mark}
	if v.Denied() {
		rec.Reason = v.Reason
	}
	l.agg.Observe(rec)
	return v
}

// The local loop of edge-spec §5: the decision service enforces the zone's
// rate per request; its denials come back through the access log; the
// rollup's flood rule sees a source pushing through its ceiling and installs
// a deny; from then on the decision service refuses that source outright — no
// bucket, no brain — and its table denials do NOT escalate the deny further.
func TestDecisionLoopPromotesAFloodingSource(t *testing.T) {
	l := newLoop(t, 10, 100, false)
	attacker := netip.MustParseAddr("203.0.113.66")
	legit := netip.MustParseAddr("198.51.100.5")

	// A ten-second window: the attacker sends 200 requests (20 r/s against a
	// ceiling of 10), the legitimate client 5.
	denied := 0
	for i := 0; i < 200; i++ {
		if v := l.request(attacker); !v.Allow {
			denied++
		}
		if i%40 == 0 {
			if v := l.request(legit); !v.Allow {
				t.Fatalf("legitimate client denied at request %d: %+v", i, v)
			}
		}
		l.now = l.now.Add(50 * time.Millisecond)
	}
	if denied < 80 || denied > 120 {
		t.Fatalf("the bucket denied %d of 200 at 2x the rate; expected roughly half", denied)
	}
	if st := l.svc.Stats(); st.TableEntries != 0 {
		t.Fatalf("before the window closed: %+v", st)
	}

	// The window closes: the flood rule promotes the attacker.
	l.agg.Tick()
	verdicts := l.svc.Verdicts()
	if len(verdicts) != 1 || verdicts[0].Source != attacker || !verdicts[0].Deny || verdicts[0].Reason != "flood" {
		t.Fatalf("verdicts after the window: %+v", verdicts)
	}
	until := verdicts[0].Until
	if until.Sub(l.now) != rollup.DefaultDenyTTL {
		t.Fatalf("first deny lasts %v", until.Sub(l.now))
	}
	// From now on the attacker is refused before any bucket is consulted, and
	// the legitimate client is untouched.
	l.now = l.now.Add(time.Second)
	if v := l.request(attacker); v.Allow || v.Reason != "table:flood" {
		t.Fatalf("attacker after promotion: %+v", v)
	}
	if v := l.request(legit); !v.Allow || v.Mark != "" {
		t.Fatalf("legitimate client after promotion: %+v", v)
	}
	// The attacker keeps sending through the deny for two more windows: those
	// are table denials, not new evidence — the deny is neither renewed nor
	// escalated, and it expires on schedule.
	for w := 0; w < 2; w++ {
		for i := 0; i < 200; i++ {
			l.request(attacker)
			l.now = l.now.Add(50 * time.Millisecond)
		}
		l.agg.Tick()
	}
	vs := l.svc.Verdicts()
	if len(vs) != 1 || !vs[0].Until.Equal(until) {
		t.Fatalf("table denials re-promoted the source: %+v (was until %v)", vs, until)
	}
	l.now = until.Add(time.Second)
	if v := l.request(attacker); !v.Allow {
		t.Fatalf("attacker after the deny expired: %+v", v)
	}
}

// In watch-only mode the loop still runs: denials are 200s marked would-deny,
// the rollup reads the mark, the flood rule installs the deny, and the service
// answers it as would-deny:table:flood — the operator previews the promotion.
func TestDecisionLoopPreviewsPromotionsInDryRun(t *testing.T) {
	l := newLoop(t, 10, 0, true)
	attacker := netip.MustParseAddr("203.0.113.67")
	wouldDeny := 0
	for i := 0; i < 200; i++ {
		if v := l.request(attacker); v.DryRun {
			wouldDeny++
		}
		l.now = l.now.Add(50 * time.Millisecond)
	}
	if wouldDeny < 80 {
		t.Fatalf("only %d would-deny verdicts at 2x the rate", wouldDeny)
	}
	l.agg.Tick()
	if vs := l.svc.Verdicts(); len(vs) != 1 || !vs[0].Deny || vs[0].Reason != "flood" {
		t.Fatalf("dry-run promotion: %+v", vs)
	}
	l.now = l.now.Add(time.Second)
	if v := l.request(attacker); !v.Allow || !v.DryRun || v.Mark != "would-deny:table:flood" {
		t.Fatalf("attacker in dry-run after promotion: %+v", v)
	}
}
