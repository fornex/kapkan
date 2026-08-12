package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// divertYAML is apiYAML with a divert ladder, so ManualBan produces exactly the
// bans the rules document serves. dry_run defaults to true, which is the point:
// the whole endpoint must work in the trial window too.
const divertYAML = apiYAML + `
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
`

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestBuildRuleDoc(t *testing.T) {
	expiry := time.Date(2026, 8, 12, 10, 0, 17, 500, time.UTC) // deliberately off-quantum
	divert := func(addr, prefix string) mitigate.Ban {
		return mitigate.Ban{
			Target:    mustAddr(t, addr),
			Prefix:    mustPrefix(t, prefix),
			State:     mitigate.BanActive,
			Method:    config.MitigateDivert,
			DryRun:    true,
			ExpiresAt: expiry,
			FlowSpec:  []mitigate.FlowSpecRule{{Dst: mustPrefix(t, prefix), Proto: 17, SrcPort: 123, Action: config.FlowSpecDiscard}},
		}
	}

	withdrawn := divert("203.0.113.7", "203.0.113.7/32")
	withdrawn.State = mitigate.BanWithdrawn
	blackhole := divert("203.0.113.8", "203.0.113.8/32")
	blackhole.Method = config.MitigateBlackhole
	dataplane := divert("203.0.113.9", "203.0.113.9/32")
	dataplane.Method = config.MitigateDataplane

	// Deliberately out of order: the doc must sort by prefix.
	doc := buildRuleDoc([]mitigate.Ban{
		divert("203.0.113.20", "203.0.113.20/32"),
		withdrawn,
		blackhole,
		dataplane,
		divert("203.0.113.10", "203.0.113.10/32"),
	})

	if doc.Version != ruleDocVersion {
		t.Errorf("version = %d, want %d", doc.Version, ruleDocVersion)
	}
	if len(doc.Bans) != 2 {
		t.Fatalf("doc has %d bans, want 2 (only ACTIVE divert bans): %+v", len(doc.Bans), doc.Bans)
	}
	if got := doc.Bans[0].Prefix.String(); got != "203.0.113.10/32" {
		t.Errorf("bans not sorted by prefix: first is %s", got)
	}
	b := doc.Bans[0]
	if b.Method != config.MitigateDivert || !b.DryRun || len(b.FlowSpec) != 1 {
		t.Errorf("ban lost fields: %+v", b)
	}
	// The expiry is quantized (never later than the real one) and in UTC.
	want := expiry.Truncate(ruleExpiryQuantum)
	if !b.ExpiresAt.Equal(want) || b.ExpiresAt.After(expiry) {
		t.Errorf("expires_at = %v, want %v (quantized, fail-open direction)", b.ExpiresAt, want)
	}
}

func TestBuildRuleDocEmptyIsArray(t *testing.T) {
	body, etag, err := ruleDocBytes(buildRuleDoc(nil))
	if err != nil {
		t.Fatalf("ruleDocBytes: %v", err)
	}
	if etag == "" {
		t.Error("empty doc must still carry an ETag")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(m["bans"]) != "[]" {
		t.Errorf(`bans = %s, want [] (never null: agents range without an existence check)`, m["bans"])
	}
}

func TestRuleDocETagDeterministic(t *testing.T) {
	bans := []mitigate.Ban{{
		Target: mustAddr(t, "203.0.113.10"), Prefix: mustPrefix(t, "203.0.113.10/32"),
		State: mitigate.BanActive, Method: config.MitigateDivert,
		ExpiresAt: time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC),
	}}
	_, e1, err := ruleDocBytes(buildRuleDoc(bans))
	if err != nil {
		t.Fatal(err)
	}
	_, e2, _ := ruleDocBytes(buildRuleDoc(bans))
	if e1 != e2 {
		t.Errorf("same table produced different ETags: %s vs %s", e1, e2)
	}
	bans[0].ExpiresAt = bans[0].ExpiresAt.Add(ruleExpiryQuantum)
	_, e3, _ := ruleDocBytes(buildRuleDoc(bans))
	if e3 == e1 {
		t.Error("changed table kept the same ETag")
	}
}

func TestHoldGate(t *testing.T) {
	g := newHoldGate(2, 3)
	relA1, ok := g.acquire("a")
	if !ok {
		t.Fatal("first hold refused")
	}
	if _, ok = g.acquire("a"); !ok {
		t.Fatal("second hold for the same token refused")
	}
	if _, ok = g.acquire("a"); ok {
		t.Error("per-token cap not enforced")
	}
	if _, ok = g.acquire("b"); !ok {
		t.Fatal("another token's hold refused below the total cap")
	}
	if _, ok = g.acquire("c"); ok {
		t.Error("total cap not enforced")
	}
	relA1()
	relA1() // idempotent: a double release must not free a slot twice
	if _, ok = g.acquire("c"); !ok {
		t.Error("released slot not reusable")
	}
	if _, ok = g.acquire("c"); ok {
		t.Error("double release freed two slots")
	}
}

// heldPolls reads the gate's current hold count (test-side sync helper).
func heldPolls(s *Server) int {
	s.holds.mu.Lock()
	defer s.holds.mu.Unlock()
	return s.holds.held
}

// waitHolds blocks until exactly n polls are held, or fails the test.
func waitHolds(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for heldPolls(s) != n {
		if time.Now().After(deadline) {
			t.Fatalf("holds = %d, want %d (timed out waiting)", heldPolls(s), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// getRules performs one GET against the handler, with an optional
// If-None-Match and bearer token.
func getRules(h http.Handler, inm, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/rules", nil)
	if inm != "" {
		r.Header.Set("If-None-Match", inm)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestRulesEndpointServesDocument(t *testing.T) {
	s := testServer(t, storeFromYAML(t, divertYAML))
	h := s.Handler()

	rec := getRules(h, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the rules document")
	}
	var doc RuleDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Version != ruleDocVersion || len(doc.Bans) != 0 {
		t.Fatalf("empty table doc = %+v", doc)
	}

	if _, err := s.mit.ManualBan(mustAddr(t, "203.0.113.10")); err != nil {
		t.Fatalf("ManualBan: %v", err)
	}
	rec = getRules(h, etag, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after ban = %d, want an immediate 200 (ETag no longer matches)", rec.Code)
	}
	if rec.Header().Get("ETag") == etag {
		t.Error("ETag did not change with the table")
	}
	doc = RuleDoc{}
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Bans) != 1 || doc.Bans[0].Method != config.MitigateDivert || !doc.Bans[0].DryRun {
		t.Fatalf("doc after divert ban = %+v", doc)
	}
}

func TestRulesEndpointLongPollWakes(t *testing.T) {
	s := testServer(t, storeFromYAML(t, divertYAML))
	s.rulesHold = 3 * time.Second // bounds the FAILURE mode; a pass never waits this long
	h := s.Handler()

	etag := getRules(h, "", "").Header().Get("ETag")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- getRules(h, etag, "") }()
	waitHolds(t, s, 1)

	if _, err := s.mit.ManualBan(mustAddr(t, "203.0.113.20")); err != nil {
		t.Fatalf("ManualBan: %v", err)
	}
	rec := <-done
	if rec.Code != http.StatusOK {
		t.Fatalf("held poll = %d, want 200 after a ban landed", rec.Code)
	}
	var doc RuleDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Bans) != 1 {
		t.Fatalf("woken doc = %+v, want the new ban", doc)
	}
}

func TestRulesEndpointHoldTimesOut(t *testing.T) {
	s := testServer(t, storeFromYAML(t, divertYAML))
	s.rulesHold = 50 * time.Millisecond
	h := s.Handler()

	etag := getRules(h, "", "").Header().Get("ETag")
	rec := getRules(h, etag, "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("timed-out hold = %d, want 304", rec.Code)
	}
	if got := rec.Header().Get("ETag"); got != etag {
		t.Errorf("304 ETag = %q, want %q", got, etag)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("304 Cache-Control = %q, want %q (must repeat the 200's metadata)", got, "no-cache")
	}
	if heldPolls(s) != 0 {
		t.Errorf("holds = %d after timeout, want 0 (leak)", heldPolls(s))
	}
}

// TestEndHoldRechecksTable pins the honesty of a timed-out hold: TTL heartbeats
// move the document WITHOUT a broadcast wake, so the deadline path must verify
// "not modified" against the live table rather than assert it from the ETag the
// request arrived with.
func TestEndHoldRechecksTable(t *testing.T) {
	s := testServer(t, storeFromYAML(t, divertYAML))
	_, before, err := s.ruleSnapshot()
	if err != nil {
		t.Fatalf("ruleSnapshot: %v", err)
	}
	if _, err := s.mit.ManualBan(mustAddr(t, "203.0.113.40")); err != nil {
		t.Fatalf("ManualBan: %v", err)
	}

	rec := httptest.NewRecorder()
	s.endHold(rec, before) // table changed since this ETag: must serve the doc
	if rec.Code != http.StatusOK {
		t.Fatalf("endHold with a stale ETag = %d, want 200", rec.Code)
	}
	var doc RuleDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Bans) != 1 {
		t.Fatalf("endHold doc = %+v, want the new ban", doc)
	}

	_, cur, _ := s.ruleSnapshot()
	rec = httptest.NewRecorder()
	s.endHold(rec, cur) // genuinely unchanged: 304
	if rec.Code != http.StatusNotModified {
		t.Fatalf("endHold with the current ETag = %d, want 304", rec.Code)
	}
}

func TestRulesEndpointHoldCap(t *testing.T) {
	s := testServer(t, storeFromYAML(t, divertYAML))
	s.rulesHold = 5 * time.Second
	h := s.Handler()

	etag := getRules(h, "", "").Header().Get("ETag")
	var wg sync.WaitGroup
	for i := 0; i < maxRuleHoldsPerToken; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			getRules(h, etag, "")
		}()
	}
	waitHolds(t, s, maxRuleHoldsPerToken)

	rec := getRules(h, etag, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("hold over the cap = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	// An instant response must NOT be capped: only holds count.
	if rec := getRules(h, "", ""); rec.Code != http.StatusOK {
		t.Errorf("instant GET while at the hold cap = %d, want 200", rec.Code)
	}

	// Release the parked polls (a table change wakes them all) and verify the
	// slots come back.
	if _, err := s.mit.ManualBan(mustAddr(t, "203.0.113.30")); err != nil {
		t.Fatalf("ManualBan: %v", err)
	}
	wg.Wait()
	waitHolds(t, s, 0)
}

// TestRulesEndpointShutdownReleasesHold drives the REAL http.Server that
// ListenAndServe uses (RegisterOnShutdown hook included): a graceful Shutdown
// must complete promptly because held polls answer 304 on quit — not after
// sitting out their deadline.
func TestRulesEndpointShutdownReleasesHold(t *testing.T) {
	s := testServer(t, storeFromYAML(t, divertYAML))
	s.rulesHold = 30 * time.Second // far beyond the assertion below on purpose
	srv := s.httpServer()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	base := fmt.Sprintf("http://%s/api/v1/dataplane/rules", ln.Addr())

	resp, err := http.Get(base)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	etag := resp.Header.Get("ETag")
	_ = resp.Body.Close()

	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, base, nil)
		req.Header.Set("If-None-Match", etag)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{0, err}
			return
		}
		_ = resp.Body.Close()
		done <- result{resp.StatusCode, nil}
	}()
	waitHolds(t, s, 1)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v (a held poll stalled the graceful shutdown)", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown took %v, want prompt release of the held poll", elapsed)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("held poll errored on shutdown: %v", r.err)
	}
	if r.code != http.StatusNotModified {
		t.Errorf("held poll on shutdown = %d, want 304", r.code)
	}
}

func TestRulesEndpointRoles(t *testing.T) {
	// apiYAML ends inside the api: block, so the token list must be appended
	// BEFORE the top-level divert keys.
	const tokensYAML = apiYAML + `  tokens:
    - name: viewer1
      token_env: TEST_RULES_VIEWER
      role: viewer
    - name: op-scoped
      token_env: TEST_RULES_OP_SCOPED
      role: operator
      tenant: acme
    - name: op
      token_env: TEST_RULES_OP
      role: operator
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
hostgroups:
  - name: acme-web
    networks: ["203.0.113.128/25"]
    tenant: acme
`
	t.Setenv("TEST_RULES_VIEWER", "v-secret")
	t.Setenv("TEST_RULES_OP_SCOPED", "s-secret")
	t.Setenv("TEST_RULES_OP", "o-secret")
	s := testServer(t, storeFromYAML(t, tokensYAML))
	h := s.Handler()

	for _, tc := range []struct {
		name, bearer string
		want         int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"viewer", "v-secret", http.StatusForbidden},
		// The document is unscoped (every tenant's victims), so a tenant-scoped
		// operator is refused outright.
		{"scoped operator", "s-secret", http.StatusForbidden},
		{"unscoped operator", "o-secret", http.StatusOK},
	} {
		if rec := getRules(h, "", tc.bearer); rec.Code != tc.want {
			t.Errorf("%s: GET = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}
