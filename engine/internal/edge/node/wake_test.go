package node

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// The E3 rig against Pebble showed a fresh node ordering its first
// certificate before the :80 listener existed (the ACME manager was woken
// before the render) and, after a reload, before the new workers answered —
// both a failed HTTP-01 and an hour of backoff. The manager is woken only
// after a document is rendered and live, reloadSettle after a reload, never
// for a refused document; and it only ever sees the RENDERED document's zones.
func TestACMEManagerIsWokenOnlyForALiveRender(t *testing.T) {
	old := reloadSettle
	reloadSettle = 300 * time.Millisecond
	t.Cleanup(func() { reloadSettle = old })

	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	tester, reloader := &fakeTester{}, &fakeReloader{}
	n := newNode(t, srv, state, sockets, tester, reloader)
	var wakes atomic.Int64
	var lastWake atomic.Int64
	n.wakeFn = func() { wakes.Add(1); lastWake.Store(time.Now().UnixNano()) }
	stop := run(t, n)

	// First document: installed with a reload → the wake comes, but only
	// reloadSettle after the reloader ran.
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	reloadedAt := time.Now()
	if wakes.Load() != 0 {
		t.Fatal("manager woken before the reload settled")
	}
	waitFor(t, "the settled wake", func() bool { return wakes.Load() == 1 })
	if since := time.Duration(lastWake.Load() - reloadedAt.UnixNano()); since < reloadSettle-100*time.Millisecond {
		t.Fatalf("woken %v after the reload, want at least %v", since, reloadSettle)
	}
	if z := n.zones(); len(z) != 1 || z[0].Name != "example.com" {
		t.Fatalf("manager's zones after the first render: %+v", z)
	}

	// A rate-only change: unchanged render, no reload → woken at once.
	brain.set(testDoc(1000), `"v2"`)
	waitFor(t, "the second document", func() bool { return n.Status().ZonesETag == `"v2"` })
	waitFor(t, "an immediate wake", func() bool { return wakes.Load() == 2 })

	// A refused document that adds a zone: no wake, and the manager does not
	// see the new zone — it would order for a name nothing answers on :80.
	tester.failWith("nginx: [emerg] bogus")
	d := testDoc(1000)
	d.Zones = append(d.Zones, edgedoc.Zone{Name: "b.example.com", Origins: []string{"10.0.0.2:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeNone, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}})
	brain.set(d, `"v3"`)
	waitFor(t, "the refusal", func() bool { return n.Status().LastError != "" })
	time.Sleep(2 * reloadSettle)
	if wakes.Load() != 2 {
		t.Fatalf("manager woken for a refused document (%d wakes)", wakes.Load())
	}
	if z := n.zones(); len(z) != 1 {
		t.Fatalf("manager sees an unrendered zone: %+v", z)
	}
	if st := n.Status(); st.Zones != 2 {
		t.Fatalf("the fast path should still hold both zones: %+v", st)
	}

	// The fix lands: the local retry applies it (a reload) and the wake
	// follows after the settle, with the new zone visible.
	tester.pass()
	waitFor(t, "the retry to apply", func() bool { return n.Status().Generation > 1 })
	appliedAt := time.Now()
	waitFor(t, "the wake after the retry", func() bool { return wakes.Load() == 3 })
	if since := time.Duration(lastWake.Load() - appliedAt.UnixNano()); since < reloadSettle-150*time.Millisecond {
		t.Fatalf("woken %v after the retried reload, want about %v", since, reloadSettle)
	}
	if z := n.zones(); len(z) != 2 {
		t.Fatalf("manager's zones after the retry: %+v", z)
	}
	_ = stop()
}
