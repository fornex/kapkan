package api

// HTTP-layer tests for the source-block channel (sources.go): status mapping,
// tenant scoping, audit attribution. The enforcement semantics live in
// mitigate/sources.go and are tested there against a recording backend.

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"
	// The package rule "api must not import internal/dataplane" (dataplane.go)
	// protects the SHIPPED import graph and the API contract; this host-only
	// test file implements the mitigator's backend seam the same way
	// mitigate's own tests do, which needs the one exported rules type.
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// nopDataplane satisfies the mitigator's backend seam so BlockSource's
// "data plane present" gate passes; the fixture stays dry-run, so nothing
// would reach a real backend anyway.
type nopDataplane struct{}

func (nopDataplane) Install(netip.Prefix, dataplane.DynamicRules) error { return nil }
func (nopDataplane) Withdraw(netip.Prefix) error                        { return nil }

// sourcesAPIYAML is the tenant fixture plus an (unattached) data-plane block.
func sourcesAPIYAML() string {
	return tenantAPIYAML() + "dataplane:\n  enabled: true\n  interfaces: [\"eth0\"]\n"
}

func testServerWithDataplane(t *testing.T, store *config.Store) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	eng := engine.New(store, engine.WithLogger(log))
	mit, err := mitigate.New(store, log, mitigate.WithDataplane(nopDataplane{}))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	return New(store, eng, mit, log)
}

// TestSourceBlockLifecycleOverHTTP: block → 200 + audit, unblock → 200 +
// audit, second unblock → 404. The deployment is dry-run (the default), which
// must be visible on the returned pair.
func TestSourceBlockLifecycleOverHTTP(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")
	s := testServerWithDataplane(t, storeFromYAML(t, sourcesAPIYAML()))
	aw := &fakeAuditWriter{}
	s.SetAuditWriter(aw)
	h := s.Handler()

	body := `{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":300,"reason":"nginx: 429 storm"}`
	rec := reqWith(h, http.MethodPost, "/api/v1/dataplane/sources", body, "admin-secret", "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("block = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	var sb mitigate.SourceBlock
	if err := json.Unmarshal(rec.Body.Bytes(), &sb); err != nil {
		t.Fatalf("response: %v", err)
	}
	if sb.Source != netip.MustParseAddr("198.51.100.7") || sb.Victim != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("pair = %s->%s, want request's", sb.Source, sb.Victim)
	}
	if !sb.DryRun {
		t.Fatal("default-dry-run deployment returned a live pair")
	}
	if sb.ExpiresAt.IsZero() {
		t.Fatal("no expires_at on the returned pair")
	}

	rec = reqWith(h, http.MethodPost, "/api/v1/dataplane/sources/unblock",
		`{"victim":"203.0.113.10","source":"198.51.100.7"}`, "admin-secret", "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("unblock = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	rec = reqWith(h, http.MethodPost, "/api/v1/dataplane/sources/unblock",
		`{"victim":"203.0.113.10","source":"198.51.100.7"}`, "admin-secret", "application/json")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second unblock = %d, want 404", rec.Code)
	}

	if len(aw.rows) != 2 {
		t.Fatalf("audit rows = %d, want 2 (block, unblock): %+v", len(aw.rows), aw.rows)
	}
	const target = "198.51.100.7->203.0.113.10"
	if b := aw.rows[0]; b.Action != "source_block" || b.Result != "blocked" ||
		b.Target != target || b.TargetType != "source" || b.Operator != "admin" ||
		b.Reason != "nginx: 429 storm" || b.DryRun != 1 {
		t.Errorf("block audit = %+v", b)
	}
	if u := aw.rows[1]; u.Action != "source_unblock" || u.Result != "removed" || u.Target != target {
		t.Errorf("unblock audit = %+v", u)
	}
}

// TestSourceBlockTenantScoping: a scoped operator may only aim at victims it
// can see — uniform 403 on both endpoints, before any existence check.
func TestSourceBlockTenantScoping(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")
	s := testServerWithDataplane(t, storeFromYAML(t, sourcesAPIYAML()))
	h := s.Handler()

	// b-op (operator, custB) aims at custA's victim: uniform 403.
	foreign := `{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":60}`
	if rec := reqWith(h, http.MethodPost, "/api/v1/dataplane/sources", foreign, "b-secret", "application/json"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant block = %d, want 403; body=%s", rec.Code, rec.Body)
	}
	if rec := reqWith(h, http.MethodPost, "/api/v1/dataplane/sources/unblock", foreign, "b-secret", "application/json"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant unblock = %d, want 403 (no existence oracle); body=%s", rec.Code, rec.Body)
	}
	// Its own victim works.
	own := `{"victim":"203.0.113.70","source":"198.51.100.7","ttl_seconds":60}`
	if rec := reqWith(h, http.MethodPost, "/api/v1/dataplane/sources", own, "b-secret", "application/json"); rec.Code != http.StatusOK {
		t.Fatalf("own-tenant block = %d, want 200; body=%s", rec.Code, rec.Body)
	}
}

// TestSourceBlockErrorMapping: input mistakes are 400, policy refusals are
// 409 and audited, an absent data plane is refused rather than accepted.
func TestSourceBlockErrorMapping(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")

	// A server WITHOUT a data-plane backend: the plain test fixture.
	s := testServer(t, storeFromYAML(t, tenantAPIYAML()))
	aw := &fakeAuditWriter{}
	s.SetAuditWriter(aw)
	h := s.Handler()

	cases := []struct {
		name string
		body string
		want int
	}{
		{"invalid json", `{"victim":`, http.StatusBadRequest},
		{"bad source", `{"victim":"203.0.113.10","source":"nope","ttl_seconds":60}`, http.StatusBadRequest},
		{"bad ttl", `{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":0}`, http.StatusBadRequest},
		{"no data plane", `{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":60}`, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := reqWith(h, http.MethodPost, "/api/v1/dataplane/sources", tc.body, "admin-secret", "application/json")
			if rec.Code != tc.want {
				t.Fatalf("code = %d, want %d; body=%s", rec.Code, tc.want, rec.Body)
			}
		})
	}
	// Exactly the policy refusals are audited: "bad ttl" is ErrSourceBlockInput
	// (an input mistake reaching the mitigator) and IS audited as rejected too —
	// only the two parse-level 400s never reach audit.
	if len(aw.rows) != 2 {
		t.Fatalf("audit rows = %d, want 2 (bad ttl, no data plane): %+v", len(aw.rows), aw.rows)
	}
	for _, r := range aw.rows {
		if r.Action != "source_block" || r.Result != "rejected" || r.Reason == "" {
			t.Errorf("rejection audit = %+v, want action=source_block result=rejected with a reason", r)
		}
	}
}
