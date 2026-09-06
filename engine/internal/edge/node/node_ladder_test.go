package node

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// TestNodeWiresTheLadder pins that a document's rung settings reach the
// node's rules: with an auto zone and a zone-wide trigger installed, a closed
// window's flood rule CHALLENGES (not denies) through the node's own decision
// service, and the trigger flips the zone. Without the wiring every zone
// reads as non-auto and E4.4 is silently off.
func TestNodeWiresTheLadder(t *testing.T) {
	brain := &fakeBrain{}
	doc := testDoc(10)
	doc.Zones[0].Policy.Challenge = edgedoc.ChallengeAuto
	doc.Zones[0].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false, Auto: &edgedoc.AutoChallenge{ZoneRPS: 50}}
	brain.set(doc, `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })

	src := netip.MustParseAddr("203.0.113.10")
	got := n.rules.Apply(rollup.WindowStats{
		Zone: "example.com", Requests: 600, Decided: 600, AdmittedRPS: 60,
		Sources: []rollup.SourceStats{{Src: src, Requests: 100, Decided: 100, Denied: 80, DeniedRate: 80}},
	}, n.svc)
	if got.Challenged != 1 || got.Denied != 0 || !got.ZoneChallenge {
		t.Fatalf("Applied = %+v: the document's rung settings did not reach the rules", got)
	}
	if !n.svc.Challenged("example.com", src) || n.svc.Denied("example.com", src) {
		t.Fatal("the flooder is not under a challenge verdict")
	}
	if on, _, why := n.svc.ZoneChallenge("example.com"); !on || why != "zone-rps" {
		t.Fatalf("zone flip: on=%v why=%q", on, why)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
