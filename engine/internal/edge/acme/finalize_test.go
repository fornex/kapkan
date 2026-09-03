package acme

import (
	"context"
	"strings"
	"testing"
	"time"
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
	if h.ca.certFetches != 1 {
		t.Fatalf("certificate fetched %d times through the fallback", h.ca.certFetches)
	}
	// A mis-issued chain delivered THROUGH the fallback is still refused.
	h2 := newHarness(t)
	h2.ca.finalizeProcessing, h2.ca.finalizeNoLocation, h2.ca.misissue = true, true, true
	m2 := h2.manager(t, nil)
	if _, did, err := m2.Ensure(context.Background(), zone("example.com")); did || err == nil || !strings.Contains(err.Error(), "does not carry the key") {
		t.Fatalf("mis-issue through the fallback path: did=%v err=%v", did, err)
	}
	if h2.ca.certFetches != 1 {
		t.Fatalf("the mis-issued chain was fetched %d times", h2.ca.certFetches)
	}
}

// A finalize the CA refuses is reported as the CA's problem, at once, with no
// certificate fetch — the fallback must not turn it into a poll or hide it.
func TestFinalizeRefusedByTheCAIsReported(t *testing.T) {
	h := newHarness(t)
	h.ca.failFinalize = 400
	m := h.manager(t, nil)
	start := time.Now()
	_, did, err := m.Ensure(context.Background(), zone("example.com"))
	if did || err == nil || !strings.Contains(err.Error(), "badCSR") {
		t.Fatalf("refused finalize: did=%v err=%v", did, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("a refused finalize took %v", time.Since(start))
	}
	if h.ca.certFetches != 0 {
		t.Fatalf("a certificate was fetched after a refused finalize (%d)", h.ca.certFetches)
	}
}

// An order that goes INVALID after a Location-less finalize surfaces the CA's
// problem, not the empty-URL symptom.
func TestOrderInvalidAfterFinalizeReportsTheProblem(t *testing.T) {
	h := newHarness(t)
	h.ca.finalizeProcessing, h.ca.finalizeNoLocation, h.ca.invalidAfterFinalize = true, true, true
	m := h.manager(t, nil)
	_, did, err := m.Ensure(context.Background(), zone("example.com"))
	if did || err == nil {
		t.Fatalf("invalid order: did=%v err=%v", did, err)
	}
	if !strings.Contains(err.Error(), "could not sign the order") || strings.Contains(err.Error(), "unsupported protocol scheme") {
		t.Fatalf("the CA's problem is not the message: %v", err)
	}
	if h.ca.certFetches != 0 {
		t.Fatalf("a certificate was fetched for an invalid order (%d)", h.ca.certFetches)
	}
}
