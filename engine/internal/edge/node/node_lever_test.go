package node

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
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
