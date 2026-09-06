package node

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// TestNodeZoneDryRunIsPerZone pins E4.7 through the node: on an ENFORCING
// node, a document's zone with policy.dry_run marks what it would deny while
// its sibling zone denies — the flag reaches the node's own decision service
// with the document.
func TestNodeZoneDryRunIsPerZone(t *testing.T) {
	brain := &fakeBrain{}
	doc := testDoc(1)
	doc.Zones = append(doc.Zones, edgedoc.Zone{
		Name: "watched.example", Origins: []string{"10.0.0.2:8080"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, Rate: edgedoc.Rate{RPS: 1}, DryRun: true},
	})
	brain.set(doc, `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.DryRun = false // the node enforces; only the watched zone is watch-only
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })

	ip := netip.MustParseAddr("203.0.113.70")
	for _, z := range []string{"example.com", "watched.example"} {
		if v := n.svc.DecideRequest(decide.Request{Zone: z, Src: ip}); !v.Allow || v.DryRun {
			t.Fatalf("%s first request: %+v", z, v)
		}
	}
	if v := n.svc.DecideRequest(decide.Request{Zone: "example.com", Src: ip}); v.Allow || v.DryRun || v.Reason != decide.ReasonRate {
		t.Fatalf("the live zone over its rate: %+v", v)
	}
	if v := n.svc.DecideRequest(decide.Request{Zone: "watched.example", Src: ip}); !v.Allow || !v.DryRun || v.Mark != "would-deny:rate" {
		t.Fatalf("the watched zone over its rate: %+v", v)
	}
	if n.svc.DryRun() {
		t.Fatal("the node itself must be enforcing")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
