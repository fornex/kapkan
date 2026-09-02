package rollup_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// The local loop of edge-spec §5, wired the way `kapkan edge` will wire it:
// the decision service enforces the zone's rate per request; its 403s come
// back through the access log; the rollup's flood rule sees a source pushing
// through its denials and installs a deny; from then on the decision service
// refuses that source outright — no bucket, no brain.
func TestDecisionLoopPromotesAFloodingSource(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc := decide.New(decide.Options{Now: clock})
	doc := edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{
		Name: "example.com", Origins: []string{"10.0.0.1:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, Rate: edgedoc.Rate{RPS: 10, Concurrency: 100}},
	})
	svc.SetZones(&doc)

	rules := &rollup.Rules{Now: clock}
	agg := &rollup.Aggregator{
		Window: 10 * time.Second,
		Now:    clock,
		OnRecord: func(r rollup.Record) {
			if r.Decided() {
				svc.Complete(r.Zone, r.Src)
			}
		},
		OnWindow: func(w rollup.WindowStats) { rules.Apply(w, svc) },
	}

	attacker := netip.MustParseAddr("203.0.113.66")
	legit := netip.MustParseAddr("198.51.100.5")

	// A ten-second window: the attacker sends 200 requests (20 r/s against a
	// ceiling of 10), the legitimate client 5.
	denied := 0
	for i := 0; i < 200; i++ {
		v := svc.Decide("example.com", attacker)
		status, decision := 200, "200"
		if !v.Allow {
			denied++
			status, decision = 403, "403"
		}
		agg.Observe(rollup.Record{TS: now, Zone: "example.com", Src: attacker, Port: 443, Status: status, Decision: decision})
		if i%40 == 0 {
			v := svc.Decide("example.com", legit)
			if !v.Allow {
				t.Fatalf("legitimate client denied at request %d: %+v", i, v)
			}
			agg.Observe(rollup.Record{TS: now, Zone: "example.com", Src: legit, Port: 443, Status: 200, Decision: "200"})
		}
		now = now.Add(50 * time.Millisecond)
	}
	if denied < 80 || denied > 120 {
		t.Fatalf("the bucket denied %d of 200 at 2x the rate; expected roughly half", denied)
	}
	if st := svc.Stats(); st.Inflight != 2 || st.TableEntries != 0 {
		t.Fatalf("before the window closed: %+v (every decided request was logged, so nothing is in flight beyond the entries)", st)
	}

	// The window closes: the flood rule promotes the attacker.
	agg.Tick()
	verdicts := svc.Verdicts()
	if len(verdicts) != 1 || verdicts[0].Source != attacker || !verdicts[0].Deny || verdicts[0].Reason != "flood" {
		t.Fatalf("verdicts after the window: %+v", verdicts)
	}
	// From now on the attacker is refused before any bucket is consulted, and
	// the legitimate client is untouched.
	now = now.Add(5 * time.Second)
	if v := svc.Decide("example.com", attacker); v.Allow || v.Reason != "table:flood" {
		t.Fatalf("attacker after promotion: %+v", v)
	}
	if v := svc.Decide("example.com", legit); !v.Allow || v.Mark != "" {
		t.Fatalf("legitimate client after promotion: %+v", v)
	}
	// The deny expires on its own (one minute on the first offence).
	now = now.Add(2 * time.Minute)
	if v := svc.Decide("example.com", attacker); !v.Allow {
		t.Fatalf("attacker after the deny expired: %+v", v)
	}
}
