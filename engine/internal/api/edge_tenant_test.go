package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// E6.2: a zone's tenant label scopes the two human-facing edge reads. The
// fixture has three zones — a.example owned by acme (a tenant that also has a
// hostgroup), s.example owned by shop (a tenant NO hostgroup carries: the
// edge-only customer, legal since BindZones) and h.example, a house zone in
// mode none — and tokens: an agent bound to e1, an unscoped operator, an
// operator and a viewer scoped to acme, an operator scoped to shop.
const tenantZones = `
zones:
  - name: a.example
    tenant: acme
    origins: ["10.0.0.1:8080"]
  - name: s.example
    tenant: shop
    origins: ["10.0.0.2:8080"]
    tls: {h3: true}
  - name: h.example
    origins: ["10.0.0.3:8080"]
    tls: {h3: true}
    policy: {mode: none}
`

func tenantStore(t *testing.T) (store *config.Store, zonesPath string) {
	t.Helper()
	t.Setenv("TEST_TENANT_AGENT", "agent-secret")
	t.Setenv("TEST_TENANT_OP", "op-secret")
	t.Setenv("TEST_TENANT_ACME_OP", "acme-op-secret")
	t.Setenv("TEST_TENANT_ACME_VIEW", "acme-view-secret")
	t.Setenv("TEST_TENANT_SHOP_OP", "shop-op-secret")
	dir := t.TempDir()
	zonesPath = filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zonesPath, []byte(tenantZones), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "kapkan.yaml")
	yaml := apiYAML +
		"  tokens:\n" +
		"    - { name: agent, token_env: TEST_TENANT_AGENT, role: agent, node: e1 }\n" +
		"    - { name: op, token_env: TEST_TENANT_OP, role: operator }\n" +
		"    - { name: acme-op, token_env: TEST_TENANT_ACME_OP, role: operator, tenant: acme }\n" +
		"    - { name: acme-view, token_env: TEST_TENANT_ACME_VIEW, role: viewer, tenant: acme }\n" +
		"    - { name: shop-op, token_env: TEST_TENANT_SHOP_OP, role: operator, tenant: shop }\n" +
		"hostgroups:\n  - name: acme-web\n    networks: [\"203.0.113.128/25\"]\n    tenant: acme\n" +
		"\nedge:\n  zones_file: " + zonesPath + "\n  nodes:\n    - name: e1\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load (shop is a zone-only tenant and must pass BindZones): %v", err)
	}
	return config.NewStore(cfgPath, cfg), zonesPath
}

// TestEdgeZonesStatusTenantScoped: the unscoped view has every zone with its
// label, the file's mode, the reported figures and the certificates; a scoped
// token gets exactly its own zones — no foreign hostname or source anywhere in
// the body, no tenant field — and the node names.
func TestEdgeZonesStatusTenantScoped(t *testing.T) {
	store, _ := tenantStore(t)
	s := testServer(t, store)
	h := s.Handler()
	report := `{"version":"1.8.0","terminator":{"kind":"nginx","h3":{"state":"ready","module":true,"serving":["s.example","h.example"]}},` +
		`"certs":[{"zone":"a.example","not_after":"2026-12-01T00:00:00Z","issuer":"R11"},{"zone":"s.example","not_after":"2026-12-02T00:00:00Z","issuer":"R11"},{"zone":"ghost.example","not_after":"2026-12-03T00:00:00Z"}],"certs_truncated":1,` +
		`"zones":[{"zone":"a.example","rps":10,"requests":100,"top_sources":[{"source":"203.0.113.9","requests":50,"state":"would-deny"}]},` +
		`{"zone":"s.example","rps":20,"requests":200,"h3_requests":7,"top_sources":[{"source":"198.51.100.7","requests":60,"state":"would-challenge"}]},` +
		`{"zone":"ghost.example","rps":1,"requests":1}]}`
	if rec := postEdgeReport(h, "e1", report, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}

	doc, code := getEdgeZonesStatus(h, "op-secret")
	if code != http.StatusOK || doc.NodesAlive != 1 || len(doc.Zones) != 4 || doc.CertsTruncated != 1 {
		t.Fatalf("unscoped status = %d %+v, want four rows and certs_truncated 1", code, doc)
	}
	byName := map[string]EdgeZoneStatus{}
	for _, z := range doc.Zones {
		byName[z.Zone] = z
	}
	a := byName["a.example"]
	if a.Tenant != "acme" || a.Mode != "decide" || a.FileChallenge != "off" || a.Nodes != 1 || a.Requests != 100 ||
		len(a.Certs) != 1 || a.Certs[0].Node != "e1" || a.Certs[0].Issuer != "R11" || len(a.WouldBe) != 1 {
		t.Fatalf("a.example unscoped: %+v", a)
	}
	sz := byName["s.example"]
	if sz.Tenant != "shop" || sz.H3 == nil || !sz.H3.Enabled || len(sz.H3.Serving) != 1 || sz.H3.Serving[0] != "e1" || sz.H3.Requests != 7 || len(sz.Certs) != 1 {
		t.Fatalf("s.example unscoped: %+v", sz)
	}
	// A mode: none zone is in no report's zones section, yet its QUIC listener
	// is the node's terminator.h3 word — the row carries it.
	if hz := byName["h.example"]; hz.Tenant != "" || hz.Mode != "none" || hz.Nodes != 0 || hz.Requests != 0 || len(hz.Certs) != 0 ||
		hz.H3 == nil || !hz.H3.Enabled || len(hz.H3.Serving) != 1 || hz.H3.Serving[0] != "e1" {
		t.Fatalf("h.example (house, mode none, unreported, h3) unscoped: %+v", hz)
	}
	// A zone the node reports but the file no longer has: shown to the
	// unscoped token with no mode (nothing is known about it but the claim).
	if g := byName["ghost.example"]; g.Mode != "" || g.Nodes != 1 || g.Tenant != "" || len(g.Certs) != 1 {
		t.Fatalf("ghost.example unscoped: %+v", g)
	}

	for _, bearer := range []string{"acme-op-secret", "acme-view-secret"} {
		rec := getWith(h, "/api/v1/edge/zones/status", bearer)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", bearer, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, leak := range []string{"s.example", "h.example", "ghost.example", "198.51.100.7", `"tenant"`, "shop"} {
			if strings.Contains(body, leak) {
				t.Fatalf("%s sees %q in the scoped body: %s", bearer, leak, body)
			}
		}
		sd, _ := getEdgeZonesStatus(h, bearer)
		if len(sd.Zones) != 1 || sd.Zones[0].Zone != "a.example" || sd.Zones[0].Nodes != 1 || sd.Zones[0].Mode != "decide" ||
			sd.Zones[0].Requests != 100 || len(sd.Zones[0].WouldBe) != 1 || sd.Zones[0].WouldBe[0].Source != "203.0.113.9" ||
			len(sd.Zones[0].Certs) != 1 || sd.Zones[0].Certs[0].Node != "e1" || sd.NodesAlive != 1 {
			t.Fatalf("%s scoped rows: %+v", bearer, sd)
		}
	}
	// The zone-only tenant: exactly its zone, with the fleet's HTTP/3 word on it.
	rec := getWith(h, "/api/v1/edge/zones/status", "shop-op-secret")
	if strings.Contains(rec.Body.String(), "a.example") || strings.Contains(rec.Body.String(), "203.0.113.9") {
		t.Fatalf("shop sees acme's zone or source: %s", rec.Body.String())
	}
	sd, code := getEdgeZonesStatus(h, "shop-op-secret")
	if code != http.StatusOK || len(sd.Zones) != 1 || sd.Zones[0].Zone != "s.example" || sd.Zones[0].H3 == nil || !sd.Zones[0].H3.Enabled || sd.Zones[0].H3.Requests != 7 || sd.Zones[0].Tenant != "" {
		t.Fatalf("shop scoped rows: %d %+v", code, sd)
	}
}

// TestEdgeLeverTenantScoped: a scoped operator pulls the lever on its own
// zones; any other zone — another tenant's, a house zone, one gone from the
// file, one that never existed — answers the byte-identical unknown-zone 404;
// a viewer is refused by rank; the audit row carries the caller's tenant and
// the audit filter accepts the action.
func TestEdgeLeverTenantScoped(t *testing.T) {
	store, zonesPath := tenantStore(t)
	s := testServer(t, store)
	aw := &fakeAuditWriter{}
	s.SetStorageWriter(aw)
	fq := &fakeQuerier{}
	s.SetQuerier(fq)
	h := s.Handler()
	set := `{"mode":"manual","ttl_seconds":600,"reason":"credential stuffing"}`
	refused := testutil.ToFloat64(metrics.APIZoneRefused.WithLabelValues("edge_lever"))

	// The baseline is the GENUINE unknown-zone answer — an unscoped operator on
	// a name the file does not have — pinned literally; every scoped refusal
	// below must be that, byte for byte.
	unknown := lever(h, http.MethodPost, "nope.example", set, "op-secret")
	if unknown.Code != http.StatusNotFound || strings.TrimSpace(unknown.Body.String()) != `{"error":"unknown zone"}` {
		t.Fatalf("unknown zone = %d %q, want 404 {\"error\":\"unknown zone\"}", unknown.Code, unknown.Body.String())
	}
	// Decided before the body is read: a body the handler would refuse on the
	// caller's own zone (bad TTL, bad mode, not JSON, over the size limit) is
	// still the same 404 on a zone that is not its own.
	bodies := []string{set, `{"mode":"manual","ttl_seconds":1}`, `{"mode":"bogus","ttl_seconds":600}`, `not json`,
		`{"mode":"manual","ttl_seconds":600,"reason":"` + strings.Repeat("x", 5000) + `"}`}
	n := 0
	for _, zone := range []string{"s.example", "h.example", "ghost.example", "nope.example"} {
		for _, body := range bodies {
			rec := lever(h, http.MethodPost, zone, body, "acme-op-secret")
			n++
			if rec.Code != http.StatusNotFound || rec.Body.String() != unknown.Body.String() {
				t.Fatalf("POST %s as acme with body %.40q = %d %q, want the unknown-zone answer", zone, body, rec.Code, rec.Body.String())
			}
		}
		rec := lever(h, http.MethodDelete, zone, "", "acme-op-secret")
		n++
		if rec.Code != http.StatusNotFound || rec.Body.String() != unknown.Body.String() {
			t.Fatalf("DELETE %s as acme = %d %q, want the unknown-zone answer", zone, rec.Code, rec.Body.String())
		}
	}
	if len(aw.rows) != 0 {
		t.Fatalf("refusals wrote %d audit rows", len(aw.rows))
	}
	// The operator's trace: every scoped refusal counted, the unscoped 404 not.
	if got := testutil.ToFloat64(metrics.APIZoneRefused.WithLabelValues("edge_lever")) - refused; got != float64(n) {
		t.Fatalf("zone refusals counted = %v, want %d", got, n)
	}
	if rec := lever(h, http.MethodPost, "a.example", set, "acme-view-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped viewer = %d, want 403 (rank)", rec.Code)
	}
	if rec := lever(h, http.MethodPost, "a.example", set, "acme-op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("own zone = %d: %s", rec.Code, rec.Body.String())
	}
	if len(aw.rows) != 1 || aw.rows[0].Action != "edge_challenge" || aw.rows[0].Result != "set" || aw.rows[0].Tenant != "acme" || aw.rows[0].Target != "a.example" || aw.rows[0].Operator != "acme-op" {
		t.Fatalf("audit row for the scoped lever: %+v", aw.rows)
	}
	// The override shows in the owner's status and nowhere in shop's.
	if sd, _ := getEdgeZonesStatus(h, "acme-op-secret"); len(sd.Zones) != 1 || sd.Zones[0].Override == nil {
		t.Fatalf("owner's status after the lever: %+v", sd)
	}
	if rec := getWith(h, "/api/v1/edge/zones/status", "shop-op-secret"); strings.Contains(rec.Body.String(), "a.example") || strings.Contains(rec.Body.String(), "stuffing") {
		t.Fatalf("shop sees acme's lever: %s", rec.Body.String())
	}
	// The audit filter takes the action and binds the caller's tenant to the
	// query (a querier is attached, so the allowlist is really consulted).
	if rec := getWith(h, "/api/v1/audit?action=edge_challenge", "acme-op-secret"); rec.Code != http.StatusOK || fq.gotAudit.Action != "edge_challenge" || fq.gotAudit.Tenant != "acme" {
		t.Fatalf("audit?action=edge_challenge = %d, filter %+v; want 200 with action edge_challenge and tenant acme", rec.Code, fq.gotAudit)
	}

	// A lever on a zone a reload has since removed from the file is the
	// unscoped tokens' to clear: its former owner no longer sees it.
	if err := os.WriteFile(zonesPath, []byte(strings.Replace(tenantZones, "  - name: a.example\n    tenant: acme\n    origins: [\"10.0.0.1:8080\"]\n", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload without a.example (acme still has its hostgroup): %v", err)
	}
	if rec := lever(h, http.MethodDelete, "a.example", "", "acme-op-secret"); rec.Code != http.StatusNotFound || rec.Body.String() != unknown.Body.String() {
		t.Fatalf("clear on a removed zone as its former owner = %d %q, want the unknown-zone answer", rec.Code, rec.Body.String())
	}
	if sd, _ := getEdgeZonesStatus(h, "acme-op-secret"); len(sd.Zones) != 0 {
		t.Fatalf("former owner still sees the removed zone: %+v", sd)
	}
	if sd, _ := getEdgeZonesStatus(h, "op-secret"); len(sd.Zones) != 3 || sd.Zones[0].Zone != "a.example" || sd.Zones[0].Override == nil || sd.Zones[0].Mode != "" {
		t.Fatalf("unscoped status after the removal: %+v", sd)
	}
	if rec := lever(h, http.MethodDelete, "a.example", "", "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("clear on a removed zone as unscoped = %d: %s", rec.Code, rec.Body.String())
	}
}

// TestEdgeLeverRefusalLogAndMetric: a scoped token probing zones it does not
// own leaves the operator one Warn a minute per token (the E6.1 limiter,
// shared) naming the token, its tenant, the route and the zone asked for —
// and a count per refusal — while the caller sees nothing but the 404.
func TestEdgeLeverRefusalLogAndMetric(t *testing.T) {
	store, _ := tenantStore(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	eng := engine.New(store, engine.WithLogger(log))
	mit, err := mitigate.New(store, log)
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, eng, mit, log)
	h := s.Handler()
	before := testutil.ToFloat64(metrics.APIZoneRefused.WithLabelValues("edge_lever"))
	set := `{"mode":"manual","ttl_seconds":600}`
	for _, zone := range []string{"s.example", "s.example", "h.example", "ghost.example", strings.Repeat("z", 300) + ".example"} {
		if rec := lever(h, http.MethodPost, zone, set, "acme-op-secret"); rec.Code != http.StatusNotFound {
			t.Fatalf("acme on %.20s = %d, want 404", zone, rec.Code)
		}
	}
	if got := testutil.ToFloat64(metrics.APIZoneRefused.WithLabelValues("edge_lever")) - before; got != 5 {
		t.Fatalf("refusals counted = %v, want 5", got)
	}
	logged := buf.String()
	if n := strings.Count(logged, "zone refused"); n != 1 {
		t.Fatalf("Warn lines = %d, want one per token per minute:\n%s", n, logged)
	}
	if !strings.Contains(logged, "token=acme-op") || !strings.Contains(logged, "tenant=acme") || !strings.Contains(logged, "zone=s.example") || !strings.Contains(logged, "route=edge_lever") {
		t.Fatalf("the Warn line lacks its attributes:\n%s", logged)
	}
	if strings.Contains(logged, strings.Repeat("z", 300)) {
		t.Fatalf("a presented zone was logged untruncated:\n%s", logged)
	}
	// Another tenant's token gets its own line.
	if rec := lever(h, http.MethodDelete, "a.example", "", "shop-op-secret"); rec.Code != http.StatusNotFound {
		t.Fatalf("shop on a.example = %d, want 404", rec.Code)
	}
	if n := strings.Count(buf.String(), "zone refused"); n != 2 || !strings.Contains(buf.String(), "token=shop-op") {
		t.Fatalf("second token's refusal not logged as its own line:\n%s", buf.String())
	}
	// The unscoped operator's unknown zone is a plain 404: nothing to warn about.
	if rec := lever(h, http.MethodPost, "nope.example", set, "op-secret"); rec.Code != http.StatusNotFound {
		t.Fatalf("op on nope.example = %d", rec.Code)
	}
	if n := strings.Count(buf.String(), "zone refused"); n != 2 {
		t.Fatalf("an unscoped 404 was logged as a zone refusal:\n%s", buf.String())
	}
}

// TestReloadRefusesOrphanedZoneTenant: removing the only zone of a zone-only
// tenant while a token is still scoped to it fails the reload as a whole —
// the token would otherwise silently see nothing — and the previous zones
// stay live.
func TestReloadRefusesOrphanedZoneTenant(t *testing.T) {
	store, zonesPath := tenantStore(t)
	if err := os.WriteFile(zonesPath, []byte(strings.Replace(tenantZones, "    tenant: shop\n", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Reload()
	if err == nil || !strings.Contains(err.Error(), `api.tokens["shop-op"]: tenant "shop" is not used by any hostgroup or zone`) {
		t.Fatalf("reload that orphans the shop token: err = %v", err)
	}
	if z := zoneInFile(store.Get(), "s.example"); z == nil || z.Tenant != "shop" {
		t.Fatalf("the previous zones did not stay live: %+v", z)
	}
}
