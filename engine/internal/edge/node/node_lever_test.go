package node

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// TestNodeAppliesChallengeOverrideOnTheFastPath pins E4.6 on the node: a
// document that differs only by a challenge override reaches the decision
// service (the zone challenges) without a render — the terminator is not
// reloaded for a policy change — and the rules follow it.
func TestNodeAppliesChallengeOverrideOnTheFastPath(t *testing.T) {
	brain := &fakeBrain{}
	v1 := testDoc(10)
	v1.Zones[0].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false}
	brain.set(v1, `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	tester, reloader := &fakeTester{}, &fakeReloader{}
	opt := baseOptions(srv, state, sockets, tester, reloader)
	opt.DryRun = false
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })

	ip := netip.MustParseAddr("203.0.113.80")
	if v := n.svc.DecideRequest(decide.Request{Zone: "example.com", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("before the lever: %+v", v)
	}
	v2 := testDoc(10)
	v2.Zones[0].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false}
	v2.Zones[0].ChallengeOverride = &edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeManual, Until: time.Now().Add(time.Hour), Reason: "incident"}
	brain.set(v2, `"v2"`)
	waitFor(t, "the override document", func() bool { return n.Status().ZonesETag == `"v2"` })
	if v := n.svc.DecideRequest(decide.Request{Zone: "example.com", Src: ip}); v.Allow || !v.Challenge || v.Reason != "challenge:manual" {
		t.Fatalf("under the lever: %+v", v)
	}
	time.Sleep(100 * time.Millisecond)
	if n.Status().Generation != 1 || tester.calls.Load() != 1 || reloader.calls.Load() != 1 {
		t.Fatalf("a challenge override reloaded the terminator: gen=%d tester=%d reloader=%d", n.Status().Generation, tester.calls.Load(), reloader.calls.Load())
	}
	// The rules follow the lever too: under an AUTO override a flooder is
	// offered the rung, and the zone-wide trigger is armed.
	v2b := testDoc(10)
	v2b.Zones[0].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false, Auto: &edgedoc.AutoChallenge{ZoneRPS: 50}}
	v2b.Zones[0].ChallengeOverride = &edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeAuto, Until: time.Now().Add(time.Hour), Reason: "incident"}
	brain.set(v2b, `"v2b"`)
	waitFor(t, "the auto override document", func() bool { return n.Status().ZonesETag == `"v2b"` })
	flooder := netip.MustParseAddr("203.0.113.81")
	got := n.rules.Apply(rollup.WindowStats{Zone: "example.com", Requests: 600, Decided: 600, AdmittedRPS: 60,
		Sources: []rollup.SourceStats{{Src: flooder, Requests: 100, Decided: 100, Denied: 80, DeniedRate: 80}}}, n.svc)
	if got.Challenged != 1 || got.Denied != 0 || !got.ZoneChallenge || !n.svc.Challenged("example.com", flooder) {
		t.Fatalf("the rules under an auto override: %+v", got)
	}
	// Cleared: the file's mode again, still without a render.
	brain.set(v1, `"v3"`)
	waitFor(t, "the cleared document", func() bool { return n.Status().ZonesETag == `"v3"` })
	if v := n.svc.DecideRequest(decide.Request{Zone: "example.com", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("after the lever was cleared: %+v", v)
	}
	if n.Status().Generation != 1 {
		t.Fatalf("clearing the override reloaded the terminator: gen=%d", n.Status().Generation)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
