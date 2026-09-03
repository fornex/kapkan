package acme

// Tests added for the E3.4 review: the on-disk set is atomic and verified,
// one broken zone does not stop the others, the slot wait has its own budget,
// EAB reaches the CA, a mis-issued certificate is refused, the fake CA's
// asynchronous paths work, renewals are lifetime-relative and per-node
// jittered, and concurrent Ensure calls order once.

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// A key from one issuance next to a chain from another must never load as a
// valid certificate: the store refuses it, the Manager says so and issues
// afresh.
func TestTornCertificateSetIsRefusedAndReissued(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, nil)
	ca, _, err := m.Ensure(context.Background(), zone("a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Ensure(context.Background(), zone("b.example.com")); err != nil {
		t.Fatal(err)
	}
	// The set is a generation directory behind `current`; the paths the
	// renderer gets go through the link.
	if !strings.HasSuffix(ca.Key, filepath.Join("a.example.com", "current", "privkey.pem")) {
		t.Fatalf("key path %q does not go through current/", ca.Key)
	}
	gen, err := os.Readlink(filepath.Join(h.dir, "certs", "a.example.com", "current"))
	if err != nil || strings.Contains(gen, "/") {
		t.Fatalf("current -> %q (%v); want a relative generation name", gen, err)
	}
	// Tear it: b's key over a's.
	bKey, _ := os.ReadFile(filepath.Join(h.dir, "certs", "b.example.com", "current", "privkey.pem"))
	if err := os.WriteFile(filepath.Join(h.dir, "certs", "a.example.com", gen, "privkey.pem"), bKey, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := newStore(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.load("a.example.com"); err == nil || !strings.Contains(err.Error(), "pair") {
		t.Fatalf("torn set loaded: %v", err)
	}
	// A fresh Manager: b is known, a is not — and a's next Ensure orders.
	m2 := h.manager(t, nil)
	if _, ok := m2.Cert("a.example.com"); ok {
		t.Fatal("torn set reported as a held certificate")
	}
	if _, ok := m2.Cert("b.example.com"); !ok {
		t.Fatal("the other zone was lost with the broken one")
	}
	orders := h.ca.newOrders
	if c, did, err := m2.Ensure(context.Background(), zone("a.example.com")); err != nil || !did || h.ca.newOrders != orders+1 {
		t.Fatalf("reissue: %+v %v %v", c, did, err)
	}
	// The renewal left one superseded generation and the current one.
	entries, _ := os.ReadDir(filepath.Join(h.dir, "certs", "a.example.com"))
	dirs := 0
	for _, e := range entries {
		if e.IsDir() {
			dirs++
		}
	}
	if dirs != 2 {
		t.Fatalf("%d generation dirs after one renewal, want 2 (current + one kept)", dirs)
	}
}

// meta.json is a marker, not the truth: a corrupt one, or one naming another
// zone, does not hide a good certificate; the files decide.
func TestMetaIsNotTrustedAndBrokenZoneIsSkipped(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, nil)
	a, _, err := m.Ensure(context.Background(), zone("a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Ensure(context.Background(), zone("b.example.com")); err != nil {
		t.Fatal(err)
	}
	// Corrupt a's meta; poison b's expiry in meta.
	if err := os.WriteFile(filepath.Join(h.dir, "certs", "a.example.com", "current", "meta.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "certs", "b.example.com", "current", "meta.json"), []byte(`{"zone":"b.example.com","not_after":"2099-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m2 := h.manager(t, nil)
	got, ok := m2.Cert("a.example.com")
	if !ok || !got.NotAfter.Equal(a.NotAfter) || got.Serial != a.Serial {
		t.Fatalf("a with a corrupt meta: %+v %v", got, ok)
	}
	if b, ok := m2.Cert("b.example.com"); !ok || b.NotAfter.Year() == 2099 {
		t.Fatalf("b's expiry taken from meta, not the leaf: %+v", b)
	}
	// A directory that is not a certificate set (an operator's stray copy)
	// is skipped, and the others still load.
	if err := os.MkdirAll(filepath.Join(h.dir, "certs", "Stray Dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nowhere", filepath.Join(h.dir, "certs", "c.example.com", "current")); err != nil {
		if err := os.MkdirAll(filepath.Join(h.dir, "certs", "c.example.com"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("nowhere", filepath.Join(h.dir, "certs", "c.example.com", "current")); err != nil {
			t.Fatal(err)
		}
	}
	m3 := h.manager(t, nil)
	if inv := m3.Inventory(); len(inv) != 2 {
		t.Fatalf("inventory with broken neighbours: %+v", inv)
	}
	// A zone name that is not a hostname never becomes a path.
	for _, bad := range []string{"../etc", "a/b", "Upper.Example", "-x.example", "x..example", ""} {
		if _, _, err := m3.Ensure(context.Background(), zone(bad)); err == nil {
			t.Fatalf("zone %q accepted", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(h.dir, "etc")); err == nil {
		t.Fatal("a traversal name created a directory")
	}
}

type refusingSlots struct {
	mu       sync.Mutex
	acquires int
	releases int
}

func (r *refusingSlots) Acquire(context.Context, string) (bool, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acquires++
	return false, 20 * time.Millisecond, nil
}

func (r *refusingSlots) Release(context.Context, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releases++
	return nil
}

// The slot wait is its own budget: a slot held longer than the order timeout
// does not turn into a counted CA failure — the node waits slotWait and then
// orders anyway, and the order gets its full timeout.
func TestSlotWaitOutlivesTheOrderTimeout(t *testing.T) {
	oldSlot, oldIssue := slotWait, issueTimeout
	slotWait, issueTimeout = 300*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { slotWait, issueTimeout = oldSlot, oldIssue })

	h := newHarness(t)
	slots := &refusingSlots{}
	m := h.manager(t, func(o *Options) { o.Slots = slots })
	start := time.Now()
	c, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did || c.Zone != "example.com" {
		t.Fatalf("Ensure with a held slot: %+v %v %v", c, did, err)
	}
	if el := time.Since(start); el < slotWait || el > slotWait+2*time.Second {
		t.Fatalf("waited %v; want about slotWait (%v) then an order", el, slotWait)
	}
	if slots.acquires < 5 || slots.releases != 0 {
		t.Fatalf("acquires=%d releases=%d", slots.acquires, slots.releases)
	}
	if h.ca.newOrders != 1 {
		t.Fatalf("newOrders=%d", h.ca.newOrders)
	}
	m.mu.Lock()
	f := m.failures["example.com"]
	m.mu.Unlock()
	if f != nil {
		t.Fatalf("a slot wait was recorded as a failure: %+v", f)
	}
}

// A caller that gives up mid-wait gets its own error and no failure record.
func TestCancelledSlotWaitIsNotAFailure(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, func(o *Options) { o.Slots = &refusingSlots{} })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, did, err := m.Ensure(ctx, zone("example.com"))
	if did || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if h.ca.newOrders != 0 {
		t.Fatal("ordered after the caller gave up")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failures["example.com"] != nil {
		t.Fatal("a cancelled attempt was counted as a failure")
	}
}

// A CA that requires an External Account Binding gets one when configured,
// and a clear error when not.
func TestExternalAccountBinding(t *testing.T) {
	h := newHarness(t)
	h.ca.requireEAB, h.ca.eabKID = true, "kid-42"
	m := h.manager(t, nil)
	if _, _, err := m.Ensure(context.Background(), zone("example.com")); err == nil || !strings.Contains(err.Error(), "externalAccountRequired") {
		t.Fatalf("without EAB: %v", err)
	}
	hmac := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	h2 := newHarness(t)
	h2.ca.requireEAB, h2.ca.eabKID = true, "kid-42"
	m2 := h2.manager(t, func(o *Options) { o.EAB = map[string]EAB{h2.ca.directory(): {KID: "kid-42", HMACKey: hmac}} })
	if _, did, err := m2.Ensure(context.Background(), zone("example.com")); err != nil || !did {
		t.Fatalf("with EAB: %v %v", did, err)
	}
	if len(h2.ca.eabSeen) != 1 || h2.ca.eabSeen[0] != "kid-42" {
		t.Fatalf("eab seen: %v", h2.ca.eabSeen)
	}
	// A malformed configuration is refused at New.
	if _, err := New(Options{StateDir: h.dir, Challenges: h.table, EAB: map[string]EAB{"x": {KID: "k", HMACKey: "not base64url!"}}}); err == nil {
		t.Fatal("bad EAB accepted")
	}
	if _, err := New(Options{StateDir: h.dir, Challenges: h.table, EAB: map[string]EAB{"x": {KID: "k"}}}); err == nil {
		t.Fatal("EAB without a key accepted")
	}
}

// A certificate that is not for the key this order generated is refused,
// counted as a failure, and nothing is written.
func TestMisissuedCertificateIsRefused(t *testing.T) {
	h := newHarness(t)
	h.ca.misissue = true
	m := h.manager(t, nil)
	_, did, err := m.Ensure(context.Background(), zone("example.com"))
	if did || err == nil || !strings.Contains(err.Error(), "does not carry the key") {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "certs", "example.com", "current")); err == nil {
		t.Fatal("a mis-issued certificate was installed")
	}
	if _, ok := m.Cert("example.com"); ok {
		t.Fatal("a mis-issued certificate is held")
	}
}

// The asynchronous CA paths: Accept answers processing and the VA validates
// later; finalize answers processing with the order's Location.
func TestAsynchronousValidationAndFinalize(t *testing.T) {
	h := newHarness(t)
	h.ca.asyncValidate, h.ca.finalizeProcessing = true, true
	m := h.manager(t, nil)
	c, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did || c.Serial == "" {
		t.Fatalf("async order: %+v %v %v", c, did, err)
	}
	if len(h.ca.validations) != 1 {
		t.Fatalf("validations: %v", h.ca.validations)
	}
}

// A validation the CA could not complete (nobody answers) is an order
// failure with a backoff — not a hang, not a success.
func TestFailedValidationIsAnOrderFailure(t *testing.T) {
	h := newHarness(t)
	h.ca.answerer = "http://127.0.0.1:1" // nothing listens
	m := h.manager(t, nil)
	_, did, err := m.Ensure(context.Background(), zone("example.com"))
	if did || err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("did=%v err=%v", did, err)
	}
	m.mu.Lock()
	f := m.failures["example.com"]
	m.mu.Unlock()
	if f == nil || f.consecutive != 1 {
		t.Fatalf("failure record: %+v", f)
	}
}

// Renewal is lifetime-relative and the jitter is bounded by the window: a
// 6-day certificate renews after 4 days, not hourly; a 12 h RenewBefore
// still renews before expiry.
func TestRenewalWindowFollowsTheLifetime(t *testing.T) {
	h := newHarness(t)
	h.ca.lifetime = 6 * 24 * time.Hour
	m := h.manager(t, nil)
	c, _, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	at := m.renewAt(c)
	if at.Before(c.NotAfter.Add(-2*24*time.Hour)) || !at.Before(c.NotAfter.Add(-36*time.Hour)) {
		t.Fatalf("renewAt %v for a 6-day cert (not_after %v): want in [-2d, -1.5d)", at, c.NotAfter)
	}
	if m.Due("example.com") {
		t.Fatal("fresh short certificate already due (would reissue hourly)")
	}
	// 35 h left: inside the window whatever the (clamped, ≤ 12 h) jitter.
	h.clock.add(4*24*time.Hour + 13*time.Hour)
	if !m.Due("example.com") {
		t.Fatal("short certificate not due after two thirds of its lifetime")
	}
	// RenewBefore below the jitter ceiling: the jitter is clamped so the
	// renewal always falls before NotAfter.
	h2 := newHarness(t)
	m2 := h2.manager(t, func(o *Options) { o.RenewBefore = 12 * time.Hour })
	c2, _, err := m2.Ensure(context.Background(), zone("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if at := m2.renewAt(c2); at.After(c2.NotAfter.Add(-9*time.Hour)) || at.Before(c2.NotAfter.Add(-12*time.Hour)) {
		t.Fatalf("renewAt %v with RenewBefore 12h (not_after %v)", at, c2.NotAfter)
	}
}

// The jitter separates nodes as well as zones.
func TestJitterIsPerNodeAndZone(t *testing.T) {
	seen := map[time.Duration]bool{}
	for _, n := range []string{"", "edge-1", "edge-2"} {
		for _, z := range []string{"a.example", "b.example"} {
			j := jitter(n, z)
			if j < 0 || j >= renewJitterMax {
				t.Fatalf("jitter(%q,%q)=%v out of range", n, z, j)
			}
			seen[j] = true
		}
	}
	if len(seen) < 5 {
		t.Fatalf("only %d distinct jitters across 6 (node, zone) pairs", len(seen))
	}
}

// Two callers for one zone at once: one order, one consistent set on disk.
func TestConcurrentEnsureOrdersOnce(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, nil)
	var wg sync.WaitGroup
	results := make([]bool, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, did, err := m.Ensure(context.Background(), zone("example.com"))
			if err != nil {
				t.Error(err)
			}
			results[i] = did
		}(i)
	}
	wg.Wait()
	issued := 0
	for _, d := range results {
		if d {
			issued++
		}
	}
	if issued != 1 || h.ca.newOrders != 1 {
		t.Fatalf("issued=%d newOrders=%d", issued, h.ca.newOrders)
	}
	// And a fresh load verifies the pair.
	if _, ok, err := m.store.load("example.com"); !ok || err != nil {
		t.Fatalf("load after concurrent Ensure: %v %v", ok, err)
	}
}

// A validation that failed while the brain was unreachable (the fan-out did
// not happen) retries soon and does not push the zone onto the fallback.
func TestPublishFailureDoesNotCountTowardTheFallback(t *testing.T) {
	h := newHarness(t)
	h.ca.answerer = "http://127.0.0.1:1"
	fallback := newFakeCA(t, h.clock.now, h.answerer.URL)
	pub := &fakePublisher{err: errors.New("brain unreachable")}
	m := h.manager(t, func(o *Options) { o.Publish = pub; o.Fallback = fallback.directory() })
	z := zone("example.com")
	for i := 0; i < fallbackAfter+1; i++ {
		if _, _, err := m.Ensure(context.Background(), z); err == nil {
			t.Fatalf("attempt %d succeeded with nobody answering", i)
		}
		h.clock.add(backoffMin + time.Second)
	}
	if fallback.newOrders != 0 {
		t.Fatalf("fallback tried %d times after publish failures", fallback.newOrders)
	}
	m.mu.Lock()
	f := m.failures["example.com"]
	m.mu.Unlock()
	if f == nil || f.consecutive != 0 {
		t.Fatalf("failure record after publish failures: %+v", f)
	}
}

// Removing a zone from the document drops its expiry gauge; the files stay.
func TestRunDropsTheGaugeOfARemovedZone(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, func(o *Options) { o.CheckEvery = 50 * time.Millisecond })
	var mu sync.Mutex
	zones := []edgedoc.Zone{zone("a.example.com"), zone("b.example.com")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = m.Run(ctx, func() []edgedoc.Zone {
			mu.Lock()
			defer mu.Unlock()
			return zones
		})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(m.Inventory()) < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	zones = zones[:1]
	mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(h.dir, "certs", "b.example.com", "current", "fullchain.pem")); err != nil {
		t.Fatalf("removed zone's files gone: %v", err)
	}
	if len(m.Inventory()) != 2 {
		t.Fatal("removed zone dropped from the inventory (its files are still held)")
	}
}
