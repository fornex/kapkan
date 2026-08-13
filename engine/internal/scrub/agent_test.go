package scrub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// fakeBackend records Install/Withdraw calls. kernel holds the "adopted"
// victim set a restarted agent would find in the pinned maps.
type fakeBackend struct {
	mu        sync.Mutex
	installs  map[netip.Prefix]dataplane.DynamicRules
	withdraws []netip.Prefix
	kernel    []netip.Prefix
	failNext  bool
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{installs: map[netip.Prefix]dataplane.DynamicRules{}}
}

func (f *fakeBackend) Victims() ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Prefix(nil), f.kernel...), nil
}
func (f *fakeBackend) Install(v netip.Prefix, r dataplane.DynamicRules) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return context.DeadlineExceeded
	}
	f.installs[v] = r
	return nil
}
func (f *fakeBackend) Withdraw(v netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdraws = append(f.withdraws, v)
	delete(f.installs, v)
	return nil
}
func (f *fakeBackend) installedTTL(v netip.Prefix) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.installs[v]
	return r.TTL, ok
}

func testAgent(t *testing.T, base string, dryRun bool, now time.Time) (*Agent, *fakeBackend) {
	t.Helper()
	be := newFakeBackend()
	a, err := New(Options{
		BaseURL: base, Token: "a-secret", Node: "fra1",
		DryRun: dryRun, Backend: be,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, be
}

func docBan(t *testing.T, prefix string, expires time.Time, dryRun bool) api.RuleDocBan {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	return api.RuleDocBan{
		Target: p.Addr(), Prefix: p, Method: config.MitigateDivert,
		DryRun: dryRun, ExpiresAt: expires,
		FlowSpec: []mitigate.FlowSpecRule{{Dst: p, Proto: 17, SrcPort: 123, Action: config.FlowSpecDiscard}},
	}
}

// TestApplyReconciles pins the whole reconcile contract in one arc: install,
// skip-unchanged, refresh-on-moved-expiry, withdraw-on-removal.
func TestApplyReconciles(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	a, be := testAgent(t, "http://unused", false, now)
	victim := netip.MustParsePrefix("203.0.113.5/32")

	// Install: the rules land with the mirrored TTL.
	doc := api.RuleDoc{Version: 1, Bans: []api.RuleDocBan{docBan(t, "203.0.113.5/32", now.Add(10*time.Minute), false)}}
	a.apply(doc)
	if ttl, ok := be.installedTTL(victim); !ok || ttl != 10*time.Minute {
		t.Fatalf("install ttl = %v (%v), want the mirrored 10m", ttl, ok)
	}

	// Same document again: no rewrite (the fingerprint short-circuits).
	be.installs = map[netip.Prefix]dataplane.DynamicRules{}
	a.apply(doc)
	if _, ok := be.installedTTL(victim); ok {
		t.Fatal("an unchanged entry was reinstalled")
	}

	// The brain refreshed the TTL: the moved expiry MUST reinstall, because
	// the reinstall is what renews the in-kernel deadline.
	doc.Bans[0].ExpiresAt = now.Add(20 * time.Minute)
	a.apply(doc)
	if ttl, ok := be.installedTTL(victim); !ok || ttl != 20*time.Minute {
		t.Fatalf("refresh ttl = %v (%v), want the extended 20m", ttl, ok)
	}

	// The ban is gone from the document: withdraw.
	a.apply(api.RuleDoc{Version: 1})
	if len(be.withdraws) != 1 || be.withdraws[0] != victim {
		t.Fatalf("withdraws = %v, want exactly the removed victim", be.withdraws)
	}
	// And a failed install must NOT be recorded as done — the next document
	// retries it.
	be.failNext = true
	a.apply(doc)
	a.apply(doc)
	if _, ok := be.installedTTL(victim); !ok {
		t.Fatal("a failed install was fingerprinted as done and never retried")
	}
}

// TestApplyDryRunContract: a LIVE node must never enforce a dry_run entry; a
// watch-only node installs it (its datapath counts without dropping).
func TestApplyDryRunContract(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	doc := api.RuleDoc{Version: 1, Bans: []api.RuleDocBan{docBan(t, "203.0.113.5/32", now.Add(time.Minute), true)}}

	live, liveBe := testAgent(t, "http://unused", false, now)
	live.apply(doc)
	if len(liveBe.installs) != 0 {
		t.Fatal("a LIVE node installed a dry_run entry — the frozen contract forbids enforcing it")
	}

	watch, watchBe := testAgent(t, "http://unused", true, now)
	watch.apply(doc)
	if len(watchBe.installs) != 1 {
		t.Fatal("a watch-only node must install dry_run entries (count-only end to end)")
	}
}

// TestApplyReconcilesAdoptedKernelState: an agent restarted over a kept pin
// set inherits rules its memory has never seen. The first reconcile must make
// the document the authority: adopted victims the document still lists are
// re-installed fresh; adopted victims it does not list — including a
// watch-only run's dry_run installs that a now-LIVE node must never enforce —
// are withdrawn.
func TestApplyReconcilesAdoptedKernelState(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	a, be := testAgent(t, "http://unused", false, now) // LIVE node
	kept := netip.MustParsePrefix("203.0.113.5/32")    // still in the document
	dryLeftover := netip.MustParsePrefix("203.0.113.6/32")
	unbanned := netip.MustParsePrefix("203.0.113.7/32")
	be.kernel = []netip.Prefix{kept, dryLeftover, unbanned}

	doc := api.RuleDoc{Version: 1, Bans: []api.RuleDocBan{
		docBan(t, "203.0.113.5/32", now.Add(time.Minute), false),
		docBan(t, "203.0.113.6/32", now.Add(time.Minute), true), // dry_run: LIVE node must not enforce
	}}
	a.apply(doc)

	if _, ok := be.installedTTL(kept); !ok {
		t.Error("an adopted victim the document still lists was not re-installed")
	}
	withdrawn := map[netip.Prefix]bool{}
	for _, p := range be.withdraws {
		withdrawn[p] = true
	}
	if !withdrawn[dryLeftover] {
		t.Error("a watch-only run's dry_run rules survived onto a LIVE node — the frozen contract violated")
	}
	if !withdrawn[unbanned] {
		t.Error("rules for a victim unbanned while the agent was down were not withdrawn")
	}
	if withdrawn[kept] {
		t.Error("a victim the document still lists was withdrawn")
	}
}

func TestApplySkipsLapsedAndRuleless(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	a, be := testAgent(t, "http://unused", false, now)

	lapsed := docBan(t, "203.0.113.5/32", now.Add(-time.Second), false)
	ruleless := docBan(t, "203.0.113.6/32", now.Add(time.Minute), false)
	ruleless.FlowSpec = nil
	a.apply(api.RuleDoc{Version: 1, Bans: []api.RuleDocBan{lapsed, ruleless}})
	if len(be.installs) != 0 {
		t.Fatalf("installs = %v, want none (lapsed and rule-less entries carry nothing to enforce)", be.installs)
	}
}

// TestPollLoop drives the real HTTP protocol against a fake brain: 200 with a
// document, then a held... no — the fake answers 304 immediately; the agent
// must treat both as healthy and carry the ETag on the second request.
func TestPollLoop(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var gotINM []string
	var gotNode string
	var reports int

	doc := api.RuleDoc{Version: 1, Bans: []api.RuleDocBan{docBan(t, "203.0.113.5/32", now.Add(time.Minute), false)}}
	body, _ := json.Marshal(doc)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer a-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/dataplane/rules":
			mu.Lock()
			gotNode = r.URL.Query().Get("node")
			inm := r.Header.Get("If-None-Match")
			gotINM = append(gotINM, inm)
			mu.Unlock()
			if inm == `"e1"` {
				w.Header().Set("ETag", `"e1"`)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"e1"`)
			_, _ = w.Write(body)
		case "/api/v1/dataplane/nodes/fra1/report":
			var rep api.NodeReport
			_ = json.NewDecoder(r.Body).Decode(&rep)
			mu.Lock()
			reports++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	be := newFakeBackend()
	a, err := New(Options{
		BaseURL: srv.URL, Token: "a-secret", Node: "fra1",
		Backend: be, Now: func() time.Time { return now },
		ReportInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !a.pollOnce(context.Background()) {
		t.Fatal("first poll (200) reported unhealthy")
	}
	if _, ok := be.installedTTL(netip.MustParsePrefix("203.0.113.5/32")); !ok {
		t.Fatal("the polled document was not installed")
	}
	if !a.pollOnce(context.Background()) {
		t.Fatal("second poll (304) reported unhealthy")
	}
	mu.Lock()
	if gotNode != "fra1" || len(gotINM) != 2 || gotINM[0] != "" || gotINM[1] != `"e1"` {
		t.Fatalf("node=%q INM=%v, want the identity and the carried ETag", gotNode, gotINM)
	}
	mu.Unlock()

	// The report loop posts on its cadence, carrying the current ETag.
	ctx, cancel := context.WithCancel(context.Background())
	go a.reportLoop(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := reports
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no self-report arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
}

// TestRunConcurrentLoops drives the REAL Run entry point — both goroutines at
// once — under the race detector: the poll loop writing the ETag while the
// report loop reads it is exactly the pair -race must see synchronized.
func TestRunConcurrentLoops(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	doc := api.RuleDoc{Version: 1, Bans: []api.RuleDocBan{docBan(t, "203.0.113.5/32", now.Add(time.Minute), false)}}
	body, _ := json.Marshal(doc)
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/dataplane/rules" {
			// A fresh ETag every time keeps the poll loop writing the field
			// the report loop reads.
			n++
			w.Header().Set("ETag", `"e`+string(rune('0'+n%10))+`"`)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	be := newFakeBackend()
	a, err := New(Options{
		BaseURL: srv.URL, Token: "a-secret", Node: "fra1", Backend: be,
		Now: func() time.Time { return now }, ReportInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	a.Run(ctx) // returns on ctx timeout; -race verifies the etag handoff
}

// TestPollRefusesUnknownVersion: a document version this agent does not know
// must install nothing and read as unhealthy (backoff), never as "enforce a
// guess".
func TestPollRefusesUnknownVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":2,"bans":[{"prefix":"203.0.113.5/32"}]}`))
	}))
	defer srv.Close()
	a, be := testAgent(t, srv.URL, false, time.Now())
	if a.pollOnce(context.Background()) {
		t.Fatal("an unknown document version was treated as healthy")
	}
	if len(be.installs) != 0 {
		t.Fatal("an unknown document version was enforced")
	}
}
