package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// edgeStoreNodes is edgeStore with several configured edge nodes, for the
// coordination tests: a slot is only exclusive between two nodes.
func edgeStoreNodes(t *testing.T, zonesYAML string, nodes ...string) *config.Store {
	t.Helper()
	t.Setenv("TEST_EDGE_AGENT", "agent-secret")
	t.Setenv("TEST_EDGE_OP", "op-secret")
	t.Setenv("TEST_EDGE_OP_SCOPED", "scoped-secret")
	dir := t.TempDir()
	zonesPath := filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zonesPath, []byte(zonesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var nodeLines strings.Builder
	for _, n := range nodes {
		nodeLines.WriteString("    - name: " + n + "\n")
	}
	cfgPath := filepath.Join(dir, "kapkan.yaml")
	yaml := apiYAML +
		"  tokens:\n" +
		"    - { name: agent, token_env: TEST_EDGE_AGENT, role: agent }\n" +
		"    - { name: op, token_env: TEST_EDGE_OP, role: operator }\n" +
		"    - { name: op-scoped, token_env: TEST_EDGE_OP_SCOPED, role: operator, tenant: acme }\n" +
		"hostgroups:\n  - name: acme-web\n    networks: [\"203.0.113.128/25\"]\n    tenant: acme\n" +
		"\nedge:\n  zones_file: " + zonesPath + "\n  nodes:\n" + nodeLines.String()
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return config.NewStore(cfgPath, cfg)
}

func postACME(h http.Handler, node, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/edge/nodes/"+node+"/acme/"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func slotResp(t *testing.T, rec *httptest.ResponseRecorder) EdgeSlotResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("slot: status %d body %s", rec.Code, rec.Body.String())
	}
	var resp EdgeSlotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

const validToken = "tok_" + "abcdefghijklmnopqrstuvwxyz0123456789"
const validKeyAuth = validToken + "." + "thumbprint_abcdefghijklmnopqrstuvwxyz"

func challengeBody(zone, token, keyAuth string) string {
	return `{"zone":"` + zone + `","token":"` + token + `","key_authorization":"` + keyAuth + `"}`
}

func TestEdgeACMESlotIsExclusivePerZone(t *testing.T) {
	s := testServer(t, edgeStoreNodes(t, edgeZonesTwo, "e1", "e2"))
	h := s.Handler()

	// e1 takes a.example; e2 is told who holds it and for how long.
	r1 := slotResp(t, postACME(h, "e1", "slot", `{"zone":"a.example"}`, "agent-secret"))
	if !r1.Granted || r1.ExpiresAt == nil || time.Until(*r1.ExpiresAt) > issuanceSlotTTL {
		t.Fatalf("e1 grant: %+v", r1)
	}
	rec2 := postACME(h, "e2", "slot", `{"zone":"a.example"}`, "agent-secret")
	r2 := slotResp(t, rec2)
	if r2.Granted || r2.Holder != "e1" || r2.RetryAfterSeconds < 1 || r2.RetryAfterSeconds > 60 {
		t.Fatalf("e2 refusal: %+v", r2)
	}
	// A refusal carries no expires_at at all (the wire shape edge-spec §3 gives).
	if strings.Contains(rec2.Body.String(), "expires_at") {
		t.Fatalf("refusal body carries expires_at: %s", rec2.Body.String())
	}
	// Another zone is independent, and the holder re-acquiring extends.
	if r := slotResp(t, postACME(h, "e2", "slot", `{"zone":"b.example"}`, "agent-secret")); !r.Granted {
		t.Fatalf("e2 on b.example: %+v", r)
	}
	if r := slotResp(t, postACME(h, "e1", "slot", `{"zone":"a.example"}`, "agent-secret")); !r.Granted {
		t.Fatalf("e1 re-acquire: %+v", r)
	}
	// Only the holder can release; then the other node gets it.
	if rec := postACME(h, "e2", "slot", `{"zone":"a.example","release":true}`, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("e2 release (not holder): %d", rec.Code)
	}
	if r := slotResp(t, postACME(h, "e2", "slot", `{"zone":"a.example"}`, "agent-secret")); r.Granted {
		t.Fatalf("e2 got the slot after a release it did not own: %+v", r)
	}
	if rec := postACME(h, "e1", "slot", `{"zone":"a.example","release":true}`, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("e1 release: %d", rec.Code)
	}
	if r := slotResp(t, postACME(h, "e2", "slot", `{"zone":"a.example"}`, "agent-secret")); !r.Granted {
		t.Fatalf("e2 after e1 released: %+v", r)
	}
	// A release names a zone that is gone from the file: still 204 — it only
	// touches the caller's own grant.
	if rec := postACME(h, "e2", "slot", `{"zone":"gone.example","release":true}`, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("release of an unknown zone: %d %s", rec.Code, rec.Body.String())
	}
	// The grants show in the zones document, sorted by zone.
	rec := getZones(h, "", "op-secret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("zones: %d", rec.Code)
	}
	var doc EdgeDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.IssuanceGrants) != 2 || doc.IssuanceGrants[0].Zone != "a.example" || doc.IssuanceGrants[0].Node != "e2" || doc.IssuanceGrants[1].Zone != "b.example" || doc.IssuanceGrants[1].Node != "e2" {
		t.Fatalf("grants in doc: %+v", doc.IssuanceGrants)
	}
	if !doc.IssuanceGrants[0].ExpiresAt.Equal(doc.IssuanceGrants[0].ExpiresAt.Truncate(time.Second)) {
		t.Fatal("grant expiry not truncated to whole seconds (ETag would churn)")
	}
}

func TestEdgeACMESlotLeaseExpires(t *testing.T) {
	c := newIssuanceCoordinator()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	granted, _, _ := c.acquire("a.example", "e1", now)
	if !granted {
		t.Fatal("first acquire refused")
	}
	if granted, holder, _ := c.acquire("a.example", "e2", now.Add(issuanceSlotTTL-time.Second)); granted || holder != "e1" {
		t.Fatalf("before the deadline: %v %q", granted, holder)
	}
	if granted, _, _ := c.acquire("a.example", "e2", now.Add(issuanceSlotTTL)); !granted {
		t.Fatal("a dead node's lease must expire")
	}
}

func TestEdgeACMEChallengePublishFansOutAndWakesPollers(t *testing.T) {
	s := testServer(t, edgeStoreNodes(t, edgeZonesTwo, "e1", "e2"))
	s.rulesHold = 3 * time.Second
	h := s.Handler()

	// A publish needs the zone's slot: without it, 409 and nothing fanned out.
	if rec := postACME(h, "e1", "challenges", challengeBody("a.example", validToken, validKeyAuth), "agent-secret"); rec.Code != http.StatusConflict {
		t.Fatalf("publish without the slot: %d %s", rec.Code, rec.Body.String())
	}
	if r := slotResp(t, postACME(h, "e1", "slot", `{"zone":"a.example"}`, "agent-secret")); !r.Granted {
		t.Fatalf("slot: %+v", r)
	}

	first := getZones(h, "", "agent-secret", "e1")
	if first.Code != http.StatusOK {
		t.Fatalf("first GET: %d", first.Code)
	}
	etag := first.Header().Get("ETag")
	var before EdgeDoc
	_ = json.Unmarshal(first.Body.Bytes(), &before)
	if len(before.ACMEChallenges) != 0 {
		t.Fatalf("challenges before publish: %+v", before.ACMEChallenges)
	}

	// e2 parks a poll on the current document; e1 publishes a challenge; the
	// poll must answer at once with the challenge in it.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- getZones(h, etag, "agent-secret", "e2") }()
	waitEdgeHolds(t, s, 1)
	start := time.Now()
	if rec := postACME(h, "e1", "challenges", challengeBody("a.example", validToken, validKeyAuth), "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case rec := <-done:
		if el := time.Since(start); el > s.rulesHold/2 {
			t.Fatalf("poll answered after %v; a publish must wake it", el)
		}
		if rec.Code != http.StatusOK || rec.Header().Get("ETag") == etag {
			t.Fatalf("woken poll: %d etag %q (was %q)", rec.Code, rec.Header().Get("ETag"), etag)
		}
		var doc EdgeDoc
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.ACMEChallenges) != 1 || doc.ACMEChallenges[0].Zone != "a.example" || doc.ACMEChallenges[0].Token != validToken || doc.ACMEChallenges[0].KeyAuthorization != validKeyAuth {
			t.Fatalf("challenge in doc: %+v", doc.ACMEChallenges)
		}
		if until := time.Until(doc.ACMEChallenges[0].ExpiresAt); until <= 0 || until > edgeChallengeTTL {
			t.Fatalf("challenge expiry %v", doc.ACMEChallenges[0].ExpiresAt)
		}
	case <-time.After(s.rulesHold + time.Second):
		t.Fatal("parked poll never answered")
	}
	// Idempotent re-publish of the same token, and the document is stable
	// between publishes (same ETag on two consecutive GETs).
	if rec := postACME(h, "e1", "challenges", challengeBody("a.example", validToken, validKeyAuth), "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("re-publish: %d", rec.Code)
	}
	a := getZones(h, "", "op-secret", "")
	b := getZones(h, "", "op-secret", "")
	if a.Header().Get("ETag") != b.Header().Get("ETag") {
		t.Fatal("ETag churns without news")
	}
	// The same token with a DIFFERENT key authorization is refused — even
	// from the node that now holds the slot: first live writer wins.
	if rec := postACME(h, "e1", "challenges", challengeBody("a.example", validToken, validToken+".another_thumbprint_abcdefghijklmnop"), "agent-secret"); rec.Code != http.StatusConflict {
		t.Fatalf("overwrite by the holder: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postACME(h, "e1", "slot", `{"zone":"a.example","release":true}`, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("release: %d", rec.Code)
	}
	if r := slotResp(t, postACME(h, "e2", "slot", `{"zone":"a.example"}`, "agent-secret")); !r.Granted {
		t.Fatalf("e2 slot: %+v", r)
	}
	if rec := postACME(h, "e2", "challenges", challengeBody("a.example", validToken, validToken+".another_thumbprint_abcdefghijklmnop"), "agent-secret"); rec.Code != http.StatusConflict {
		t.Fatalf("overwrite by another node: %d %s", rec.Code, rec.Body.String())
	}
	c := getZones(h, "", "op-secret", "")
	var doc EdgeDoc
	_ = json.Unmarshal(c.Body.Bytes(), &doc)
	if len(doc.ACMEChallenges) != 1 || doc.ACMEChallenges[0].KeyAuthorization != validKeyAuth {
		t.Fatalf("document after refused overwrites: %+v", doc.ACMEChallenges)
	}
}

func TestEdgeACMEChallengeExpiresFromTheDocument(t *testing.T) {
	c := newIssuanceCoordinator()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	if granted, _, _ := c.acquire("a.example", "e1", now); !granted {
		t.Fatal("slot refused")
	}
	if got := c.publish("a.example", validToken, validKeyAuth, "e1", now); got != publishOK {
		t.Fatalf("publish: %v", got)
	}
	withZone := func() edgedoc.Doc {
		doc := buildEdgeDoc(nil)
		doc.Zones = []edgedoc.Zone{{Name: "a.example"}}
		return doc
	}
	doc := withZone()
	c.fill(&doc, now.Add(edgeChallengeTTL-time.Second))
	if len(doc.ACMEChallenges) != 1 {
		t.Fatalf("live challenge missing: %+v", doc.ACMEChallenges)
	}
	// A zone the document no longer lists takes its grants and challenges
	// with it.
	doc = buildEdgeDoc(nil)
	c.fill(&doc, now)
	if len(doc.ACMEChallenges) != 0 || len(doc.IssuanceGrants) != 0 {
		t.Fatalf("entries for an absent zone in the doc: %+v %+v", doc.ACMEChallenges, doc.IssuanceGrants)
	}
	doc = withZone()
	c.fill(&doc, now.Add(edgeChallengeTTL))
	if len(doc.ACMEChallenges) != 0 {
		t.Fatalf("expired challenge still in the doc: %+v", doc.ACMEChallenges)
	}
}

func TestEdgeACMEChallengeQuotas(t *testing.T) {
	c := newIssuanceCoordinator()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	c.acquire("a.example", "e1", now)
	c.acquire("b.example", "e2", now)
	token := func(i int) string { return fmt.Sprintf("%s-%06d", validToken, i) }
	// One node fills its quota; the 17th is refused as the node's, not the
	// fleet's, problem.
	for i := 0; i < maxChallengesPerNode; i++ {
		if got := c.publish("a.example", token(i), validKeyAuth, "e1", now); got != publishOK {
			t.Fatalf("publish %d: %v", i, got)
		}
	}
	if got := c.publish("a.example", token(maxChallengesPerNode), validKeyAuth, "e1", now); got != publishQuota {
		t.Fatalf("past the node quota: %v", got)
	}
	// A re-publish of a live entry is not a new one.
	if got := c.publish("a.example", token(0), validKeyAuth, "e1", now); got != publishOK {
		t.Fatalf("re-publish under quota pressure: %v", got)
	}
	// Another node is untouched by e1's quota.
	if got := c.publish("b.example", token(0), validKeyAuth, "e2", now); got != publishOK {
		t.Fatalf("other node: %v", got)
	}
	// Without the slot, nothing.
	if got := c.publish("a.example", token(99), validKeyAuth, "e2", now); got != publishNoSlot {
		t.Fatalf("publish without the slot: %v", got)
	}
	// A different key authorization for a live token is a conflict, even from
	// its own publisher.
	if got := c.publish("a.example", token(0), validToken+".other_thumbprint_abcdefghijklmnopq", "e1", now); got != publishConflict {
		t.Fatalf("overwrite: %v", got)
	}
	// Expiry frees the quota.
	if got := c.publish("a.example", token(maxChallengesPerNode), validKeyAuth, "e1", now.Add(edgeChallengeTTL)); got != publishNoSlot {
		// The slot lease (10 min) expired with the challenges; re-acquire.
		c.acquire("a.example", "e1", now.Add(edgeChallengeTTL))
		if got := c.publish("a.example", token(maxChallengesPerNode), validKeyAuth, "e1", now.Add(edgeChallengeTTL)); got != publishOK {
			t.Fatalf("after expiry: %v", got)
		}
	}
}

func TestEdgeACMERoutesValidate(t *testing.T) {
	s := testServer(t, edgeStoreNodes(t, edgeZonesOne, "e1"))
	h := s.Handler()
	cases := []struct {
		name, node, path, body, bearer string
		want                           int
	}{
		{"scoped token", "e1", "slot", `{"zone":"a.example"}`, "scoped-secret", http.StatusForbidden},
		{"scoped token challenge", "e1", "challenges", challengeBody("a.example", validToken, validKeyAuth), "scoped-secret", http.StatusForbidden},
		{"no token", "e1", "slot", `{"zone":"a.example"}`, "", http.StatusUnauthorized},
		{"unknown node", "e9", "slot", `{"zone":"a.example"}`, "agent-secret", http.StatusNotFound},
		{"unknown zone", "e1", "slot", `{"zone":"nobody.example"}`, "agent-secret", http.StatusNotFound},
		{"bad json", "e1", "slot", `{"zone":`, "agent-secret", http.StatusBadRequest},
		{"unknown field", "e1", "slot", `{"zone":"a.example","node":"e1"}`, "agent-secret", http.StatusBadRequest},
		{"bad token", "e1", "challenges", challengeBody("a.example", "short", validKeyAuth), "agent-secret", http.StatusBadRequest},
		{"bad key auth", "e1", "challenges", challengeBody("a.example", validToken, "no dot here at all"), "agent-secret", http.StatusBadRequest},
		{"challenge unknown zone", "e1", "challenges", challengeBody("nobody.example", validToken, validKeyAuth), "agent-secret", http.StatusNotFound},
		{"challenge without slot", "e1", "challenges", challengeBody("a.example", validToken, validKeyAuth), "agent-secret", http.StatusConflict},
		{"operator may too", "e1", "slot", `{"zone":"a.example"}`, "op-secret", http.StatusOK},
		{"oversized", "e1", "challenges", `{"zone":"a.example","token":"` + strings.Repeat("a", 5000) + `"}`, "agent-secret", http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := postACME(h, c.node, c.path, c.body, c.bearer)
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}
