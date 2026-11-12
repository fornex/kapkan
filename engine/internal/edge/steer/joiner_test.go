package steer

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"testing"
	"time"
)

// probeJoins is a fake join handshake: it logs each zone it is asked for, and
// fails the zones in fail.
type probeJoins struct {
	fail  map[string]bool
	calls []string
}

func (h *probeJoins) handshake(_ context.Context, sni string) error {
	h.calls = append(h.calls, sni)
	if h.fail[sni] {
		return errors.New("handshake failed")
	}
	return nil
}

// took returns the zones handshaken since the last call.
func (h *probeJoins) took() []string {
	calls := h.calls
	h.calls = nil
	return calls
}

func probeEntry(t *testing.T, got, want FirstEntry) {
	t.Helper()
	if got.Zones != want.Zones || got.Ready != want.Ready || !slices.Equal(got.Missing, want.Missing) {
		t.Fatalf("FirstEntry = %+v, want %+v", got, want)
	}
}

var probeT0 = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// Each zone with a rendered :443 server is handshaken until it passes, a
// failed one at most once per Retry, a passed one never again; the drain may
// lift once every zone is ready.
func TestJoinerHandshakesEachZoneUntilItPasses(t *testing.T) {
	ctx := context.Background()
	h := &probeJoins{fail: map[string]bool{"b.example": true}}
	j := Joiner{Handshake: h.handshake}
	zones := []string{"c.example", "b.example", "a.example"}
	rendered := []string{"a.example", "b.example"}

	f := j.Check(ctx, zones, rendered, probeT0)
	probeEntry(t, f, FirstEntry{Zones: 3, Ready: 1, Missing: []string{"b.example", "c.example"}})
	if got := h.took(); !slices.Equal(got, []string{"a.example", "b.example"}) {
		t.Fatalf("handshakes %v, want a then b — and not c, which has no :443 server", got)
	}

	j.Check(ctx, zones, rendered, probeT0.Add(DefaultJoinRetry-time.Second))
	if got := h.took(); len(got) != 0 {
		t.Fatalf("handshakes %v before Retry, want none: a passed, b waits", got)
	}
	j.Check(ctx, zones, rendered, probeT0.Add(DefaultJoinRetry))
	if got := h.took(); !slices.Equal(got, []string{"b.example"}) {
		t.Fatalf("handshakes %v at Retry, want b again", got)
	}

	h.fail = nil
	f = j.Check(ctx, zones, append(rendered, "c.example"), probeT0.Add(2*DefaultJoinRetry))
	probeEntry(t, f, FirstEntry{Zones: 3, Ready: 3})
	if !f.Done() || !slices.Equal(h.took(), []string{"b.example", "c.example"}) {
		t.Fatalf("FirstEntry %+v: want done after b and c pass", f)
	}
	f = j.Check(ctx, zones, append(rendered, "c.example"), probeT0.Add(time.Hour))
	if !f.Done() || len(h.took()) != 0 {
		t.Fatalf("FirstEntry %+v: want done, with no handshake for a passed zone", f)
	}
}

func TestJoinerNeedsAZone(t *testing.T) {
	h := &probeJoins{}
	j := Joiner{Handshake: h.handshake}
	f := j.Check(context.Background(), nil, []string{"a.example"}, probeT0)
	if f.Done() || f.Zones != 0 || len(h.calls) != 0 {
		t.Fatalf("no zones: %+v after %v, want not done and no handshake", f, h.calls)
	}
}

// A passed zone counts only while the live render serves it on :443.
func TestJoinerCountsOnlyRenderedZones(t *testing.T) {
	ctx := context.Background()
	h := &probeJoins{}
	j := Joiner{Handshake: h.handshake}
	zones := []string{"a.example"}
	if f := j.Check(ctx, zones, zones, probeT0); !f.Done() {
		t.Fatalf("%+v, want done", f)
	}
	probeEntry(t, j.Check(ctx, zones, nil, probeT0.Add(time.Minute)), FirstEntry{Zones: 1, Missing: []string{"a.example"}})
	if f := j.Check(ctx, zones, []string{"a.example", "z.example"}, probeT0.Add(2*time.Minute)); !f.Done() || f.Zones != 1 {
		t.Fatalf("%+v: want done, and a rendered zone outside the document not counted", f)
	}
	if got := h.took(); !slices.Equal(got, []string{"a.example"}) {
		t.Fatalf("handshakes %v, want a single one", got)
	}
}

func TestJoinerStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &probeJoins{}
	j := Joiner{Handshake: h.handshake}
	f := j.Check(ctx, []string{"b.example", "a.example"}, []string{"a.example", "b.example"}, probeT0)
	probeEntry(t, f, FirstEntry{Zones: 2, Missing: []string{"a.example", "b.example"}})
	if len(h.calls) != 0 {
		t.Fatalf("handshakes %v after the context ended, want none", h.calls)
	}
}

func TestJoinerCountsAZoneListedTwiceOnce(t *testing.T) {
	h := &probeJoins{}
	j := Joiner{Handshake: h.handshake}
	zones := []string{"a.example", "a.example"}
	f := j.Check(context.Background(), zones, zones, probeT0)
	if !f.Done() || f.Zones != 1 || len(h.calls) != 1 {
		t.Fatalf("%+v after %v, want one zone, one handshake, done", f, h.calls)
	}
}

func TestJoinerWithoutAHandshakePassesNothing(t *testing.T) {
	var j Joiner
	zones := []string{"a.example"}
	probeEntry(t, j.Check(context.Background(), zones, zones, probeT0), FirstEntry{Zones: 1, Missing: zones})
}

// A clock that steps back must not park a failed zone until it catches up.
func TestJoinerRetriesAfterTheClockStepsBack(t *testing.T) {
	ctx := context.Background()
	h := &probeJoins{fail: map[string]bool{"a.example": true}}
	j := Joiner{Handshake: h.handshake, Retry: time.Minute}
	zones := []string{"a.example"}
	j.Check(ctx, zones, zones, probeT0)
	j.Check(ctx, zones, zones, probeT0.Add(-time.Hour))
	if got := h.took(); len(got) != 2 {
		t.Fatalf("handshakes %v, want a retry after the step back", got)
	}
	j.Check(ctx, zones, zones, probeT0.Add(-time.Hour+30*time.Second))
	if got := h.took(); len(got) != 0 {
		t.Fatalf("handshakes %v within Retry of the last, want none", got)
	}
}

// The Joiner with the real handshake against a terminator that has a
// certificate for one zone of two.
func TestJoinerWithRealHandshakes(t *testing.T) {
	certA := probeCert(t, time.Now().Add(time.Hour), "a.example")
	port, _ := probeTLS(t, probeV4, func(sni string) (*tls.Certificate, error) {
		if sni == "a.example" {
			return &certA, nil
		}
		return nil, errors.New("no certificate for this name")
	})
	p := Prober{Port: port}
	j := Joiner{Handshake: func(ctx context.Context, sni string) error { return p.Handshake(ctx, probeV4, sni) }}
	zones := []string{"b.example", "a.example"}
	probeEntry(t, j.Check(context.Background(), zones, zones, time.Now()), FirstEntry{Zones: 2, Ready: 1, Missing: []string{"b.example"}})
}
