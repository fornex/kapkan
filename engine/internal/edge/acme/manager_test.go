package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)} }

type harness struct {
	t        *testing.T
	clock    *clock
	table    *ChallengeTable
	answerer *httptest.Server
	ca       *fakeCA
	dir      string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	c := newClock()
	table := NewChallengeTable(c.now)
	answerer := httptest.NewServer(table.Handler())
	t.Cleanup(answerer.Close)
	ca := newFakeCA(t, c.now, answerer.URL)
	return &harness{t: t, clock: c, table: table, answerer: answerer, ca: ca, dir: filepath.Join(t.TempDir(), "state")}
}

func (h *harness) manager(t *testing.T, mutate func(*Options)) *Manager {
	t.Helper()
	opts := Options{StateDir: h.dir, Directory: h.ca.directory(), HTTPClient: h.ca.client(), Challenges: h.table, Now: h.clock.now}
	if mutate != nil {
		mutate(&opts)
	}
	m, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func zone(name string) edgedoc.Zone {
	return edgedoc.Zone{Name: name, Origins: []string{"10.0.0.1:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}}
}

func TestIssueRenewAndInventory(t *testing.T) {
	h := newHarness(t)
	var issued []string
	m := h.manager(t, func(o *Options) { o.OnCertificate = func(z string) { issued = append(issued, z) } })

	c, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did {
		t.Fatalf("Ensure: %+v %v %v", c, did, err)
	}
	if c.Zone != "example.com" || c.Issuer != "Fake Kapkan Test CA" || !c.NotAfter.Equal(h.clock.now().Add(90*24*time.Hour)) {
		t.Fatalf("Cert = %+v", c)
	}
	if len(issued) != 1 || issued[0] != "example.com" {
		t.Fatalf("OnCertificate calls: %v", issued)
	}
	// The files: key 0600, chain readable, meta last; the directory 0700.
	if runtime.GOOS != "windows" {
		st, err := os.Stat(c.Key)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("key mode: %v %v", st.Mode(), err)
		}
		dst, _ := os.Stat(filepath.Dir(c.Key))
		if dst.Mode().Perm() != 0o700 {
			t.Fatalf("cert dir mode %v", dst.Mode())
		}
		ast, _ := os.Stat(filepath.Join(h.dir, "acme"))
		if ast.Mode().Perm() != 0o700 {
			t.Fatalf("acme dir mode %v", ast.Mode())
		}
	}
	chainPEM, err := os.ReadFile(c.Fullchain)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(chainPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("leaf: %v %v", leaf, err)
	}
	if b2, _ := pem.Decode(rest); b2 == nil {
		t.Fatal("chain lacks the issuer certificate")
	}
	// The CA really validated through the answerer, and the challenge is gone
	// from the table once the order finished.
	if len(h.ca.validations) != 1 || !strings.HasPrefix(h.ca.validations[0], "example.com/") {
		t.Fatalf("validations: %v", h.ca.validations)
	}
	if got := h.table.Pending(); len(got) != 0 {
		t.Fatalf("challenge left pending: %+v", got)
	}

	// Not due: nothing happens, no new order.
	orders := h.ca.newOrders
	if _, did, err := m.Ensure(context.Background(), zone("example.com")); err != nil || did || h.ca.newOrders != orders {
		t.Fatalf("second Ensure: did=%v err=%v orders=%d", did, err, h.ca.newOrders)
	}
	// Day 61: due (30 days minus this zone's jitter remain), renewed with a
	// fresh key and a later expiry.
	h.clock.add(61 * 24 * time.Hour)
	if !m.Due("example.com") {
		t.Fatal("not due at day 61")
	}
	oldKey, _ := os.ReadFile(c.Key)
	c2, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did || !c2.NotAfter.After(c.NotAfter) {
		t.Fatalf("renewal: %+v %v %v", c2, did, err)
	}
	newKey, _ := os.ReadFile(c2.Key)
	if string(oldKey) == string(newKey) {
		t.Fatal("renewal reused the private key")
	}
	inv := m.Inventory()
	if len(inv) != 1 || inv[0].Zone != "example.com" || !inv[0].NotAfter.Equal(c2.NotAfter) {
		t.Fatalf("inventory: %+v", inv)
	}
	// A fresh Manager over the same state dir knows the certificate.
	m2 := h.manager(t, nil)
	if got, ok := m2.Cert("example.com"); !ok || !got.NotAfter.Equal(c2.NotAfter) {
		t.Fatalf("reloaded inventory: %+v %v", got, ok)
	}
	if m2.Due("example.com") {
		t.Fatal("freshly renewed certificate reported due after restart")
	}
}

func TestAccountKeyIsPerDirectoryAndReused(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, nil)
	if _, _, err := m.Ensure(context.Background(), zone("a.example.com")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Ensure(context.Background(), zone("b.example.com")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(h.dir, "acme"))
	if len(entries) != 1 {
		t.Fatalf("%d account keys for one directory", len(entries))
	}
	if len(h.ca.accounts) != 1 {
		t.Fatalf("%d accounts registered at the CA; the key must be reused", len(h.ca.accounts))
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(h.dir, "acme", entries[0].Name()))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("account key mode %v", st.Mode())
		}
	}
}

type fakeSlots struct {
	mu       sync.Mutex
	grant    bool
	err      error
	acquires int
	releases int
}

func (f *fakeSlots) Acquire(_ context.Context, zone string) (bool, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquires++
	if f.err != nil {
		return false, 0, f.err
	}
	if !f.grant && f.acquires < 3 {
		return false, time.Millisecond, nil
	}
	return true, 0, nil
}

func (f *fakeSlots) Release(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases++
	return nil
}

type fakePublisher struct {
	mu        sync.Mutex
	published []string
	err       error
}

func (f *fakePublisher) Publish(_ context.Context, zone, token, keyAuth string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, zone+"/"+token+"/"+keyAuth)
	return f.err
}

func TestSlotIsAskedThenReleasedAndChallengePublished(t *testing.T) {
	h := newHarness(t)
	slots := &fakeSlots{}
	pub := &fakePublisher{}
	m := h.manager(t, func(o *Options) { o.Slots = slots; o.Publish = pub })
	if _, _, err := m.Ensure(context.Background(), zone("example.com")); err != nil {
		t.Fatal(err)
	}
	// Refused twice with retry_after, granted the third time, released once.
	if slots.acquires != 3 || slots.releases != 1 {
		t.Fatalf("acquires=%d releases=%d", slots.acquires, slots.releases)
	}
	if len(pub.published) != 1 || !strings.HasPrefix(pub.published[0], "example.com/tok-") {
		t.Fatalf("published: %v", pub.published)
	}
	// The key authorization published is the one the CA verified.
	parts := strings.SplitN(pub.published[0], "/", 3)
	if !strings.HasPrefix(parts[2], parts[1]+".") {
		t.Fatalf("key authorization %q does not start with the token", parts[2])
	}
}

// The slot is advisory: a brain that errors, or a publisher that fails, does
// not stop an order.
func TestIssuanceProceedsWithoutTheBrain(t *testing.T) {
	h := newHarness(t)
	slots := &fakeSlots{err: errors.New("connection refused")}
	pub := &fakePublisher{err: errors.New("connection refused")}
	m := h.manager(t, func(o *Options) { o.Slots = slots; o.Publish = pub })
	c, did, err := m.Ensure(context.Background(), zone("example.com"))
	if err != nil || !did || c.Zone != "example.com" {
		t.Fatalf("Ensure without brain: %+v %v %v", c, did, err)
	}
	if slots.releases != 0 {
		t.Fatal("released a slot it never held")
	}
}

func TestFailuresBackOffThenUseTheFallback(t *testing.T) {
	h := newHarness(t)
	fallback := newFakeCA(t, h.clock.now, h.answerer.URL)
	h.ca.failNewOrder = 429
	m := h.manager(t, func(o *Options) { o.Fallback = fallback.directory() })
	z := zone("example.com")

	// Three failures against the primary, each followed by a backoff during
	// which Ensure does not even try.
	for i := 1; i <= fallbackAfter; i++ {
		_, did, err := m.Ensure(context.Background(), z)
		if err == nil || did {
			t.Fatalf("attempt %d: did=%v err=%v", i, did, err)
		}
		before := h.ca.newOrders
		if _, _, err := m.Ensure(context.Background(), z); err != nil || h.ca.newOrders != before {
			t.Fatalf("attempt %d: backoff not honoured (orders %d -> %d, err %v)", i, before, h.ca.newOrders, err)
		}
		h.clock.add(backoff(i) + time.Second)
	}
	if fallback.newOrders != 0 {
		t.Fatal("fallback used before the threshold")
	}
	// The next attempt turns to the fallback and succeeds.
	c, did, err := m.Ensure(context.Background(), z)
	if err != nil || !did || c.Directory != fallback.directory() {
		t.Fatalf("fallback attempt: %+v %v %v (fallback orders %d)", c, did, err, fallback.newOrders)
	}
	if _, ok := m.Cert("example.com"); !ok {
		t.Fatal("certificate not recorded")
	}
	// A zone's own fallback wins over the node default.
	zf := zone("other.example.com")
	zf.ACMEDirectory = h.ca.directory()
	zf.ACMEFallback = fallback.directory()
	m2 := h.manager(t, func(o *Options) { o.Fallback = "http://127.0.0.1:1/never" })
	for i := 1; i <= fallbackAfter; i++ {
		_, _, _ = m2.Ensure(context.Background(), zf)
		h.clock.add(backoff(i) + time.Second)
	}
	if c, did, err := m2.Ensure(context.Background(), zf); err != nil || !did || c.Directory != fallback.directory() {
		t.Fatalf("zone fallback: %+v %v %v", c, did, err)
	}
}

func TestChallengeTableAndHandler(t *testing.T) {
	c := newClock()
	table := NewChallengeTable(c.now)
	table.Add("example.com", "tok-"+strings.Repeat("a", 20), "tok-"+strings.Repeat("a", 20)+".thumb", time.Minute)
	table.SetFanned([]edgedoc.Challenge{
		{Zone: "other.example", Token: "tok-" + strings.Repeat("b", 20), KeyAuthorization: "fanned.thumb", ExpiresAt: c.now().Add(time.Minute)},
		{Zone: "other.example", Token: "bad token!", KeyAuthorization: "x", ExpiresAt: c.now().Add(time.Minute)},
	})
	h := table.Handler()
	do := func(method, path, zoneHdr, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if zoneHdr != "" {
			req.Header.Set("X-Kapkan-Zone", zoneHdr)
		}
		if host != "" {
			req.Host = host
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("GET", "/.well-known/acme-challenge/tok-"+strings.Repeat("a", 20), "example.com", ""); rec.Code != 200 || !strings.HasSuffix(rec.Body.String(), ".thumb") {
		t.Fatalf("own challenge: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do("GET", "/.well-known/acme-challenge/tok-"+strings.Repeat("b", 20), "", "other.example:80"); rec.Code != 200 || rec.Body.String() != "fanned.thumb" {
		t.Fatalf("fanned challenge by Host: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do("HEAD", "/.well-known/acme-challenge/tok-"+strings.Repeat("a", 20), "example.com", ""); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: %d body=%d", rec.Code, rec.Body.Len())
	}
	if rec := do("GET", "/.well-known/acme-challenge/tok-"+strings.Repeat("a", 20), "wrong.example", ""); rec.Code != 404 {
		t.Fatalf("zone mismatch: %d", rec.Code)
	}
	if rec := do("GET", "/.well-known/acme-challenge/../../etc/passwd", "example.com", ""); rec.Code != 404 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	if rec := do("POST", "/.well-known/acme-challenge/tok-"+strings.Repeat("a", 20), "example.com", ""); rec.Code != 405 {
		t.Fatalf("POST: %d", rec.Code)
	}
	if rec := do("GET", "/other", "example.com", ""); rec.Code != 404 {
		t.Fatalf("other path: %d", rec.Code)
	}
	// Expiry, and Remove.
	c.add(2 * time.Minute)
	if rec := do("GET", "/.well-known/acme-challenge/tok-"+strings.Repeat("a", 20), "example.com", ""); rec.Code != 404 {
		t.Fatalf("expired challenge still answered: %d", rec.Code)
	}
	table.Add("example.com", "tok-"+strings.Repeat("c", 20), "c.thumb", time.Minute)
	table.Remove("example.com", "tok-"+strings.Repeat("c", 20))
	if _, ok := table.Lookup("example.com", "tok-"+strings.Repeat("c", 20)); ok {
		t.Fatal("removed challenge still answered")
	}
}

func TestChallengeServerOverUnixSocket(t *testing.T) {
	c := newClock()
	table := NewChallengeTable(c.now)
	table.Add("example.com", "tok-"+strings.Repeat("d", 20), "d.thumb", time.Minute)
	path := filepath.Join(t.TempDir(), "c.sock")
	srv := &ChallengeServer{Table: table, Path: path}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (netConn, error) {
		return dialUnix(ctx, path)
	}}}
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/.well-known/acme-challenge/tok-"+strings.Repeat("d", 20), nil)
		req.Header.Set("X-Kapkan-Zone", "example.com")
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRunIssuesEveryZoneAndStops(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, func(o *Options) { o.CheckEvery = time.Hour })
	zones := []edgedoc.Zone{zone("a.example.com"), zone("b.example.com")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, func() []edgedoc.Zone { return zones }) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(m.Inventory()) < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if inv := m.Inventory(); len(inv) != 2 || inv[0].Zone != "a.example.com" || inv[1].Zone != "b.example.com" {
		t.Fatalf("inventory after Run: %+v", inv)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestInventoryNeverCarriesKeyMaterial(t *testing.T) {
	h := newHarness(t)
	m := h.manager(t, nil)
	if _, _, err := m.Ensure(context.Background(), zone("example.com")); err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Inventory() {
		for _, s := range []string{c.Fullchain, c.Key, c.Issuer, c.Directory, c.Zone} {
			if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "BEGIN") {
				t.Fatalf("inventory carries key material: %q", s)
			}
		}
	}
}
