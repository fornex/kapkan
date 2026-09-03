package acme

import (
	"context"
	"strings"
	"testing"
)

// A CA that fills the finalize URL only once the order is ready must still
// work: the manager finalises where the READY order says to.
func TestFinalizeURLIsTakenFromTheReadyOrder(t *testing.T) {
	h := newHarness(t)
	h.ca.lateFinalize = true
	m := h.manager(t, nil)
	c, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did || c.Serial == "" {
		t.Fatalf("Ensure against a CA that fills finalize late: %+v %v %v", c, did, err)
	}
}

// The E3 acceptance rig against Pebble failed every order with
// `finalize: Post "": unsupported protocol scheme ""`: Pebble answers finalize
// with "processing" and no Location header, and x/crypto then polls an empty
// URL. The manager now polls the order URL it already knows and fetches the
// certificate itself.
func TestFinalizeWithoutLocationHeaderStillCompletes(t *testing.T) {
	h := newHarness(t)
	h.ca.finalizeProcessing, h.ca.finalizeNoLocation = true, true
	m := h.manager(t, nil)
	c, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did || c.Serial == "" {
		t.Fatalf("Ensure against a CA whose finalize carries no Location: %+v %v %v", c, did, err)
	}
	// A finalize that really fails still surfaces as a failure.
	h2 := newHarness(t)
	h2.ca.finalizeNoLocation, h2.ca.misissue = true, true
	m2 := h2.manager(t, nil)
	if _, did, err := m2.Ensure(context.Background(), zone("example.com")); did || err == nil || !strings.Contains(err.Error(), "does not carry the key") {
		t.Fatalf("mis-issue with the fallback path: did=%v err=%v", did, err)
	}
}
