package rollup_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// challengeLoop is loop with an AUTO zone (the rung enforcing) and requests
// that may carry a clearance cookie — the node's wiring for E4.4.
type challengeLoop struct {
	loop
	cookies map[netip.Addr]string
}

func newChallengeLoop(t *testing.T, rps uint64, dryRun bool, auto *edgedoc.AutoChallenge) *challengeLoop {
	t.Helper()
	l := &challengeLoop{loop: loop{now: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}, cookies: map[netip.Addr]string{}}
	clock := func() time.Time { return l.now }
	l.svc = decide.New(decide.Options{Now: clock, DryRun: dryRun})
	doc := edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{
		Name: "example.com", Origins: []string{"10.0.0.1:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeAuto,
			Rate: edgedoc.Rate{RPS: rps}, ChallengeOptions: &edgedoc.ChallengeOptions{DryRun: false, Auto: auto}},
	})
	l.svc.SetZones(&doc)
	l.rules = &rollup.Rules{Now: clock}
	l.rules.SetZones(rollup.ZoneRulesFromDoc(&doc))
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

// clear gives src a valid clearance, as the page would after a solved puzzle.
func (l *challengeLoop) clear(t *testing.T, src netip.Addr) {
	t.Helper()
	keys := l.svc.Keys("example.com")
	tok, err := clearance.Issue(keys[0], "example.com", edgedoc.SourceKey(src).String(), clearance.KindPoW, l.now.Add(30*time.Minute), l.now)
	if err != nil {
		t.Fatal(err)
	}
	l.cookies[src] = tok
}

// request runs one request through decide and back through the log, as
// nginx would, including the 401 → page path.
func (l *challengeLoop) request(src netip.Addr) decide.Verdict {
	v := l.svc.DecideRequest(decide.Request{Zone: "example.com", Src: src, Path: "/", RawURI: "/", Clearance: l.cookies[src]})
	status, decision := 200, "200"
	switch {
	case v.Allow:
	case v.Challenge:
		status, decision = 403, "401" // the clearance page's status
	default:
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

func (l *challengeLoop) flood(src netip.Addr, n int, gap time.Duration) (denied, challenged, allowed int) {
	for i := 0; i < n; i++ {
		v := l.request(src)
		switch {
		case v.Challenge && !v.Allow:
			challenged++
		case !v.Allow:
			denied++
		default:
			allowed++
		}
		l.now = l.now.Add(gap)
	}
	return
}

// TestDecisionLoopChallengesBeforeDenying pins the ladder end to end: a
// source flooding an auto zone is rate-limited, the window's flood rule sends
// it to the rung (a challenge verdict, 401s from then on), and only a source
// that keeps flooding through the challenge is denied — with the deny's
// doubling TTL, as before.
func TestDecisionLoopChallengesBeforeDenying(t *testing.T) {
	l := newChallengeLoop(t, 10, false, nil)
	attacker := netip.MustParseAddr("203.0.113.10")
	if denied, challenged, _ := l.flood(attacker, 200, 50*time.Millisecond); denied < 80 || challenged != 0 {
		t.Fatalf("first window: denied=%d challenged=%d", denied, challenged)
	}
	l.agg.Tick()
	vs := l.svc.Verdicts()
	if len(vs) != 1 || !vs[0].Challenge || vs[0].Reason != "flood" {
		t.Fatalf("after the first flood window: %+v", vs)
	}
	if !l.svc.Challenged("example.com", attacker) {
		t.Fatal("the source is not challenged")
	}
	// Under the challenge every request is a 401 (a browser would clear it;
	// this one keeps hammering), still within its rate.
	_, challenged, allowed := l.flood(attacker, 200, 50*time.Millisecond)
	if challenged == 0 || allowed != 0 {
		t.Fatalf("second window: challenged=%d allowed=%d", challenged, allowed)
	}
	l.agg.Tick()
	vs = l.svc.Verdicts()
	var deny *decide.VerdictEntry
	for i := range vs {
		if vs[i].Deny {
			deny = &vs[i]
		}
	}
	if deny == nil || deny.Reason != "flood" {
		t.Fatalf("a source flooding through its challenge was not denied: %+v", vs)
	}
	if !deny.Until.Equal(l.now.Add(rollup.DefaultDenyTTL)) {
		t.Fatalf("first deny TTL = %v, want %v", deny.Until.Sub(l.now), rollup.DefaultDenyTTL)
	}
	if v := l.request(attacker); v.Allow || v.Challenge || v.Reason != "table:flood" {
		t.Fatalf("denied attacker: %+v", v)
	}
	// A quiet source in the same zone is untouched throughout.
	if v := l.request(netip.MustParseAddr("203.0.113.11")); !v.Allow || v.Mark != "" {
		t.Fatalf("bystander: %+v", v)
	}
}

// TestDecisionLoopClearedFloodersAreDenied pins D9's other branch: a source
// that holds a valid clearance and floods anyway skips the rung and is denied.
func TestDecisionLoopClearedFloodersAreDenied(t *testing.T) {
	l := newChallengeLoop(t, 10, false, nil)
	bot := netip.MustParseAddr("203.0.113.20")
	l.clear(t, bot)
	if v := l.request(bot); !v.Allow || v.Mark != decide.MarkCleared {
		t.Fatalf("cleared request: %+v", v)
	}
	l.flood(bot, 200, 50*time.Millisecond)
	l.agg.Tick()
	vs := l.svc.Verdicts()
	if len(vs) != 1 || !vs[0].Deny || vs[0].Reason != "flood" {
		t.Fatalf("cleared flooder: %+v", vs)
	}
	if v := l.request(bot); v.Allow || v.Reason != "table:flood" {
		t.Fatalf("cleared flooder after the deny: %+v", v)
	}
}

// TestDecisionLoopZoneRPSFlipsAndHolds pins the zone-wide trigger: many
// sources each under their own ceiling but the zone over zone_rps flips the
// zone to challenge — every source, including the quiet ones — for the hold;
// a window still over the rate extends it; a cleared source passes; when the
// flood stops the flip lapses.
func TestDecisionLoopZoneRPSFlipsAndHolds(t *testing.T) {
	l := newChallengeLoop(t, 100, false, &edgedoc.AutoChallenge{ZoneRPS: 50, HoldSeconds: 60})
	proxies := make([]netip.Addr, 0, 100)
	for i := 0; i < 100; i++ {
		proxies = append(proxies, netip.MustParseAddr(netip.AddrFrom4([4]byte{198, 18, byte(i / 256), byte(i % 256)}).String()))
	}
	// 100 sources × 1 request per 100 ms each = 1000 rps for the zone, 10 rps
	// each: nobody trips the per-source ceiling.
	start := l.now
	for l.now.Sub(start) < 10*time.Second {
		for _, p := range proxies {
			if v := l.request(p); !v.Allow {
				t.Fatalf("a proxy was refused before the trigger: %+v", v)
			}
		}
		l.now = l.now.Add(100 * time.Millisecond)
	}
	l.agg.Tick()
	on, until, why := l.svc.ZoneChallenge("example.com")
	if !on || why != "zone-rps" || !until.Equal(l.now.Add(time.Minute)) {
		t.Fatalf("zone not flipped: on=%v until=%v why=%q", on, until, why)
	}
	// Everyone is challenged now, a bystander included; a cleared one passes.
	if v := l.request(proxies[0]); v.Allow || !v.Challenge || v.Reason != "challenge:zone:zone-rps" {
		t.Fatalf("proxy after the flip: %+v", v)
	}
	bystander := netip.MustParseAddr("203.0.113.99")
	if v := l.request(bystander); v.Allow || !v.Challenge {
		t.Fatalf("bystander after the flip: %+v", v)
	}
	l.clear(t, bystander)
	if v := l.request(bystander); !v.Allow || v.Mark != decide.MarkCleared {
		t.Fatalf("cleared bystander: %+v", v)
	}
	// Another window over the rate extends the hold from its close.
	start = l.now
	for l.now.Sub(start) < 10*time.Second {
		for _, p := range proxies {
			l.request(p)
		}
		l.now = l.now.Add(100 * time.Millisecond)
	}
	l.agg.Tick()
	if _, until2, _ := l.svc.ZoneChallenge("example.com"); !until2.Equal(l.now.Add(time.Minute)) {
		t.Fatalf("hold not extended: %v vs now %v", until2, l.now)
	}
	// The flood stops: quiet windows do not extend, and the flip lapses.
	l.now = l.now.Add(61 * time.Second)
	l.agg.Tick()
	if on, _, _ := l.svc.ZoneChallenge("example.com"); on {
		t.Fatal("flip did not lapse after the hold")
	}
	if v := l.request(proxies[1]); !v.Allow || v.Challenge {
		t.Fatalf("after the flood stopped: %+v", v)
	}
}

// TestDecisionLoopPreviewsChallengesInDryRun pins that the ladder previews
// itself: with the node in dry-run the challenge verdict lands, but every
// request it would have challenged is a 200 marked would-challenge, and the
// deny that follows a would-be flood is a would-deny.
func TestDecisionLoopPreviewsChallengesInDryRun(t *testing.T) {
	l := newChallengeLoop(t, 10, true, nil)
	attacker := netip.MustParseAddr("203.0.113.30")
	l.flood(attacker, 200, 50*time.Millisecond)
	l.agg.Tick()
	if vs := l.svc.Verdicts(); len(vs) != 1 || !vs[0].Challenge {
		t.Fatalf("dry-run ladder: %+v", vs)
	}
	l.now = l.now.Add(time.Second)
	if v := l.request(attacker); !v.Allow || !v.DryRun || !v.Challenge || v.Mark != "would-challenge:table:flood" {
		t.Fatalf("would-challenge: %+v", v)
	}
	// Flooding on: the would-challenges count as evidence and the deny lands
	// as a would-deny.
	l.flood(attacker, 200, 50*time.Millisecond)
	l.agg.Tick()
	denied := false
	for _, e := range l.svc.Verdicts() {
		denied = denied || e.Deny
	}
	if !denied {
		t.Fatalf("no deny after flooding through a would-challenge: %+v", l.svc.Verdicts())
	}
	l.now = l.now.Add(time.Second)
	if v := l.request(attacker); !v.Allow || !v.DryRun || v.Mark != "would-deny:table:flood" {
		t.Fatalf("would-deny: %+v", v)
	}
}
