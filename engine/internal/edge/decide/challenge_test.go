package decide

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// challengeZone is a decide-mode zone with the rung in the given mode, the
// document carrying one clearance key, and the rung ENFORCING (the zones
// file's default is watch-only; tests that want that set it).
func challengeZone(t *testing.T, name, mode string, rps uint64) (edgedoc.Zone, clearance.Key) {
	t.Helper()
	z := zone(name, rps, 0)
	z.Policy.Challenge = mode
	z.Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false}
	secret, err := clearance.DeriveZoneKey([]byte(strings.Repeat("m", 32)), name)
	if err != nil {
		t.Fatal(err)
	}
	c := newClock()
	k := clearance.Key{ID: "c1", Secret: secret, NotBefore: c.t.Add(-time.Hour), NotAfter: c.t.Add(47 * time.Hour)}
	z.ClearanceKeys = []edgedoc.ClearanceKey{{ID: k.ID, Secret: base64.RawURLEncoding.EncodeToString(secret), NotBefore: k.NotBefore, NotAfter: k.NotAfter}}
	return z, k
}

func cookieFor(t *testing.T, k clearance.Key, zone, srcKey string, c *clock) string {
	t.Helper()
	tok, err := clearance.Issue(k, zone, srcKey, clearance.KindPoW, c.t.Add(30*time.Minute), c.t)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestManualChallengesEveryoneWithoutAClearance pins the rung's shape: in a
// manual zone a request without a cookie is a 401 with the reason, a bad or
// foreign cookie is the same, and a valid one passes with the cleared mark.
func TestManualChallengesEveryoneWithoutAClearance(t *testing.T) {
	c := newClock()
	z, k := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	s := newService(t, c, z)
	ip := src("198.51.100.10")

	v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: "/cart"})
	if v.Allow || !v.Challenge || v.Reason != "challenge:manual" || !v.Denied() || v.DryRun {
		t.Fatalf("no cookie: %+v", v)
	}
	good := cookieFor(t, k, "shop.example", edgedoc.SourceKey(ip).String(), c)
	v = s.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: "/cart", Clearance: good})
	if !v.Allow || v.Challenge || v.Mark != MarkCleared || v.Reason != ReasonAllow {
		t.Fatalf("valid cookie: %+v", v)
	}
	// Bound to the source: the same cookie from another address is refused.
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.11"), Clearance: good}); v.Allow {
		t.Fatalf("cookie from another source accepted: %+v", v)
	}
	// Tampered, oversized, garbage.
	for _, bad := range []string{good[:len(good)-2] + "AA", strings.Repeat("x", 600), "v1.c1.pow.1.x", ""} {
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: bad}); v.Allow || !v.Challenge {
			t.Fatalf("bad cookie %q accepted: %+v", bad[:min(len(bad), 20)], v)
		}
	}
	// A no-JS clearance carries its own mark.
	nojs, err := clearance.Issue(k, "shop.example", edgedoc.SourceKey(ip).String(), clearance.KindNoJS, c.t.Add(5*time.Minute), c.t)
	if err != nil {
		t.Fatal(err)
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: nojs}); !v.Allow || v.Mark != MarkClearedNoJS {
		t.Fatalf("nojs cookie: %+v", v)
	}
	// An expired cookie is no cookie.
	c.add(31 * time.Minute)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: good}); v.Allow || !v.Challenge {
		t.Fatalf("expired cookie accepted: %+v", v)
	}
}

// TestClearedClientsStillMeetTheRate pins that a clearance passes the rung,
// not the ceiling: rate and concurrency apply to cleared clients.
func TestClearedClientsStillMeetTheRate(t *testing.T) {
	c := newClock()
	z, k := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 2)
	s := newService(t, c, z)
	ip := src("198.51.100.12")
	good := cookieFor(t, k, "shop.example", edgedoc.SourceKey(ip).String(), c)
	for i := 0; i < 2; i++ {
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: good}); !v.Allow || v.Mark != MarkCleared {
			t.Fatalf("request %d: %+v", i, v)
		}
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: good}); v.Allow || v.Challenge || v.Reason != ReasonRate {
		t.Fatalf("third request should be a rate deny: %+v", v)
	}
}

// TestChallengeDryRunLayers pins the two watch-only switches: the zone's
// (challenge_options.dry_run, the file's default) and the node's. Either
// answers a challenge as an allow marked would-challenge with the reason;
// the rate still applies to such a request and its deny is the stronger word.
func TestChallengeDryRunLayers(t *testing.T) {
	c := newClock()
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 1)
	z.Policy.ChallengeOptions = nil // the default: watch-only
	s := newService(t, c, z)
	ip := src("198.51.100.13")
	v := s.DecideRequest(Request{Zone: "shop.example", Src: ip})
	if !v.Allow || !v.Challenge || !v.DryRun || v.Mark != "would-challenge:manual" || v.Reason != "challenge:manual" || !v.Denied() {
		t.Fatalf("zone dry-run: %+v", v)
	}
	// Over the rate: the deny wins over the would-challenge (node enforcing).
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || v.Reason != ReasonRate || v.Challenge {
		t.Fatalf("rate over a would-challenge: %+v", v)
	}

	// Zone enforcing, node in dry-run: still watch-only.
	z2, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	s2 := New(Options{Now: c.now, DryRun: true})
	s2.SetZones(doc(z2))
	if v := s2.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || !v.DryRun || v.Mark != "would-challenge:manual" {
		t.Fatalf("node dry-run: %+v", v)
	}
	// Both enforcing: the 401.
	s3 := newService(t, c, z2)
	if v := s3.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge {
		t.Fatalf("enforcing: %+v", v)
	}
}

// TestExemptPathsSkipTheRungOnly pins D6: a request whose path starts with an
// exempt prefix is not challenged (query ignored, prefix not substring) — but
// it is still rate-limited.
func TestExemptPathsSkipTheRungOnly(t *testing.T) {
	c := newClock()
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 1)
	z.Policy.ChallengeOptions.ExemptPaths = []string{"/healthz", "/api/"}
	s := newService(t, c, z)
	ip := src("198.51.100.14")
	// A fresh source per path: the zone's rate is 1 rps, and this loop is
	// about the rung, not the ceiling.
	for i, p := range []string{"/healthz", "/healthz?deep=1", "/api/v1/x"} {
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: src(fmt.Sprintf("203.0.113.%d", 20+i)), Path: p}); !v.Allow || v.Challenge {
			t.Fatalf("exempt %s: %+v", p, v)
		}
	}
	for i, p := range []string{"/", "/apiary", "/x/healthz", "/cart?next=/api/"} {
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: src(fmt.Sprintf("203.0.113.%d", 40+i)), Path: p}); v.Allow {
			t.Fatalf("not exempt %s: %+v", p, v)
		}
	}
	// Exempt from the rung, not from the ceiling.
	s.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: "/healthz"})
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: "/healthz"}); v.Allow || v.Reason != ReasonRate {
		t.Fatalf("exempt path over the rate: %+v", v)
	}
}

// TestAutoChallengesOnlyWhenTold pins auto: nobody is challenged until a
// challenge verdict names the source or the zone is flipped; a deny outranks
// a challenge, which outranks a mark; the flip and the verdict expire.
func TestAutoChallengesOnlyWhenTold(t *testing.T) {
	c := newClock()
	z, k := challengeZone(t, "shop.example", edgedoc.ChallengeAuto, 0)
	s := newService(t, c, z)
	ip, other := src("198.51.100.30"), src("198.51.100.31")
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("auto with nothing told: %+v", v)
	}
	// A per-source challenge verdict.
	if !s.Challenge("shop.example", ip, 5*time.Minute, "flood") || !s.Challenged("shop.example", ip) || s.Challenged("shop.example", other) {
		t.Fatal("challenge verdict not installed or not reported")
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge || v.Reason != "challenge:table:flood" {
		t.Fatalf("challenged source: %+v", v)
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: other}); !v.Allow {
		t.Fatalf("other source: %+v", v)
	}
	// The cleared flooder passes the rung.
	good := cookieFor(t, k, "shop.example", edgedoc.SourceKey(ip).String(), c)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: good}); !v.Allow || v.Mark != MarkCleared {
		t.Fatalf("cleared flooder: %+v", v)
	}
	// Precedence: a mark loses to the challenge, a deny beats it.
	s.Mark("shop.example", ip, "vip", time.Hour)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || v.Reason != "challenge:table:flood" {
		t.Fatalf("mark over challenge: %+v", v)
	}
	s.Deny("shop.example", ip, time.Hour, "abuse")
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: good}); v.Allow || v.Challenge || v.Reason != "table:abuse" {
		t.Fatalf("deny over challenge (even cleared): %+v", v)
	}
	if s.Challenged("shop.example", ip) {
		t.Fatal("Challenged reported a denied source")
	}
	entries := s.Verdicts()
	var ch, dn int
	for _, e := range entries {
		if e.Challenge {
			ch++
		}
		if e.Deny {
			dn++
		}
	}
	if ch != 1 || dn != 1 || len(entries) != 3 {
		t.Fatalf("verdicts: %+v", entries)
	}
	// The verdict expires with its TTL.
	s.Clear("shop.example", ip)
	s.Challenge("shop.example", other, time.Minute, "flood")
	c.add(61 * time.Second)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: other}); !v.Allow {
		t.Fatalf("expired challenge verdict still in force: %+v", v)
	}

	// The zone-wide flip: everyone, until it lapses.
	until := c.t.Add(2 * time.Minute)
	if !s.SetZoneChallenge("shop.example", true, until, "zone-rps") || s.SetZoneChallenge("nobody.example", true, until, "x") {
		t.Fatal("SetZoneChallenge")
	}
	if on, u, why := s.ZoneChallenge("shop.example"); !on || !u.Equal(until) || why != "zone-rps" {
		t.Fatalf("ZoneChallenge: %v %v %q", on, u, why)
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.99")}); v.Allow || v.Reason != "challenge:zone:zone-rps" {
		t.Fatalf("flipped zone: %+v", v)
	}
	// A new document keeps the flip while the zone stays.
	s.SetZones(doc(z))
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.98")}); v.Allow {
		t.Fatalf("flip lost on SetZones: %+v", v)
	}
	c.add(3 * time.Minute)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.97")}); !v.Allow {
		t.Fatalf("flip did not lapse: %+v", v)
	}
	if on, _, _ := s.ZoneChallenge("shop.example"); on {
		t.Fatal("ZoneChallenge still on after until")
	}
}

// TestOffIgnoresChallengeMachinery pins that a zone with the rung off never
// challenges — not for a verdict, not for a flip — and does not mark a stale
// cookie as cleared either.
func TestOffIgnoresChallengeMachinery(t *testing.T) {
	c := newClock()
	z, k := challengeZone(t, "shop.example", edgedoc.ChallengeOff, 0)
	s := newService(t, c, z)
	ip := src("198.51.100.40")
	s.Challenge("shop.example", ip, time.Hour, "flood")
	s.SetZoneChallenge("shop.example", true, c.t.Add(time.Hour), "x")
	good := cookieFor(t, k, "shop.example", edgedoc.SourceKey(ip).String(), c)
	for _, clr := range []string{"", good} {
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: clr}); !v.Allow || v.Challenge || v.Mark != "" {
			t.Fatalf("off zone (cookie %v): %+v", clr != "", v)
		}
	}
}

// TestEphemeralKeyWhenTheDocumentHasNone pins the older-brain case: a zone
// without clearance keys gets one of the node's own, so the node can still
// verify what its own page (E4.3) signs — and nothing another node signed.
// The node's key is always there, LAST, so the page prefers a document key
// whenever one is live.
func TestEphemeralKeyWhenTheDocumentHasNone(t *testing.T) {
	c := newClock()
	z := zone("shop.example", 0, 0)
	z.Policy.Challenge = edgedoc.ChallengeManual
	z.Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false}
	s := newService(t, c, z)
	keys := s.Keys("shop.example")
	if len(keys) != 1 || keys[0].ID != LocalKeyID || len(keys[0].Secret) != clearance.SecretLen {
		t.Fatalf("keys: %+v", keys)
	}
	ip := src("198.51.100.50")
	tok := cookieFor(t, keys[0], "shop.example", edgedoc.SourceKey(ip).String(), c)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: tok}); !v.Allow || v.Mark != MarkCleared {
		t.Fatalf("own key: %+v", v)
	}
	other := newService(t, c, z)
	if v := other.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: tok}); v.Allow {
		t.Fatalf("another node's ephemeral key verified our cookie: %+v", v)
	}
	if s.Keys("nobody.example") != nil {
		t.Fatal("keys for an unknown zone")
	}
	// A document that carries keys puts them first; the node's stays last.
	zk, k := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	s.SetZones(doc(zk))
	keys = s.Keys("shop.example")
	if len(keys) != 2 || keys[0].ID != "c1" || keys[1].ID != LocalKeyID {
		t.Fatalf("document keys not adopted first: %+v", keys)
	}
	// Keys returns a copy: a caller cannot reach into the service's slice.
	keys[0].Secret[0] ^= 0xff
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: cookieFor(t, k, "shop.example", edgedoc.SourceKey(ip).String(), c)}); !v.Allow {
		t.Fatalf("Keys aliased the service's keys: %+v", v)
	}
}

// TestExpiredDocumentKeysDoNotWallEveryoneOut pins edge-spec §2.4 for the
// rung: with the brain gone, the document's keys age out after their 48 h.
// The zone must not then challenge with nothing able to verify — the node's
// own key keeps the rung workable on this node, and a cookie under the dead
// document key is refused.
func TestExpiredDocumentKeysDoNotWallEveryoneOut(t *testing.T) {
	c := newClock()
	z, k := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	s := newService(t, c, z)
	ip := src("198.51.100.55")
	tokDoc := cookieFor(t, k, "shop.example", edgedoc.SourceKey(ip).String(), c)
	c.add(72 * time.Hour) // every document key is past NotAfter
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: tokDoc}); v.Allow {
		t.Fatalf("a cookie under an expired document key verified: %+v", v)
	}
	// The rung is still in force — there is a live key (the node's own)...
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge {
		t.Fatalf("expired document keys switched the rung off: %+v", v)
	}
	// ...and a cookie under it clears, so the page can still let people in.
	keys := s.Keys("shop.example")
	local := keys[len(keys)-1]
	if local.ID != LocalKeyID {
		t.Fatalf("last key is %q", local.ID)
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Clearance: cookieFor(t, local, "shop.example", edgedoc.SourceKey(ip).String(), c)}); !v.Allow || v.Mark != MarkCleared {
		t.Fatalf("own key after the document's expired: %+v", v)
	}
	// With no LIVE key at all — a node without a local key (no entropy at
	// start) whose document keys have expired — the rung is off rather than
	// a wall: keys exist, none is live.
	s2 := New(Options{Now: c.now})
	s2.localMaster = nil
	s2.SetZones(doc(z))
	if keys := s2.Keys("shop.example"); len(keys) != 1 || keys[0].ID != "c1" {
		t.Fatalf("keys without a local master: %+v", keys)
	}
	if v := s2.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("a zone with keys but no live key challenged: %+v", v)
	}
}

// TestChallengedRequestsStillMeetTheRate pins that switching the rung on
// does not switch E3 off: a flood without cookies is rate-denied (a 429 the
// flood rule counts), not answered with a challenge page per request.
func TestChallengedRequestsStillMeetTheRate(t *testing.T) {
	c := newClock()
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 2)
	s := newService(t, c, z)
	ip := src("198.51.100.56")
	for i := 0; i < 2; i++ {
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge {
			t.Fatalf("request %d: %+v", i, v)
		}
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || v.Challenge || v.Reason != ReasonRate {
		t.Fatalf("third request should be a rate deny, not a challenge: %+v", v)
	}
	// Concurrency too.
	zc, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	zc.Policy.Rate.Concurrency = 1
	s2 := newService(t, c, zc)
	s2.DecideRequest(Request{Zone: "shop.example", Src: ip}) // opens a slot
	if v := s2.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || v.Challenge || v.Reason != ReasonConcurrency {
		t.Fatalf("second in-flight request should be a concurrency deny: %+v", v)
	}
}

// TestDormantChallengeEntryKeepsTheMark pins precedence when the stronger
// verdict does not apply: a challenge entry for a source in an off zone (or
// on an exempt path) must not swallow the mark the rollup also installed.
func TestDormantChallengeEntryKeepsTheMark(t *testing.T) {
	c := newClock()
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeOff, 0)
	s := newService(t, c, z)
	ip := src("198.51.100.57")
	s.Mark("shop.example", ip, "errors", time.Hour)
	s.Challenge("shop.example", ip, time.Hour, "flood")
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Mark != "errors" {
		t.Fatalf("mark lost behind a dormant challenge entry: %+v", v)
	}
	za, _ := challengeZone(t, "shop.example", edgedoc.ChallengeAuto, 0)
	za.Policy.ChallengeOptions.ExemptPaths = []string{"/healthz"}
	s2 := newService(t, c, za)
	s2.Mark("shop.example", ip, "errors", time.Hour)
	s2.Challenge("shop.example", ip, time.Hour, "flood")
	if v := s2.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: "/healthz"}); !v.Allow || v.Mark != "errors" {
		t.Fatalf("mark lost on an exempt path: %+v", v)
	}
	if v := s2.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: "/cart"}); v.Allow || v.Reason != "challenge:table:flood" {
		t.Fatalf("challenge not in force off the exempt path: %+v", v)
	}
}

// TestExemptPathsRefuseUnnormalisedForms pins the defence behind the two path
// headers: an exemption needs the normalised path AND the raw target to start
// with the prefix, and anything an origin could read differently from nginx
// — a dot segment, a path parameter, a backslash, an encoded slash/dot, a
// byte outside printable ASCII — is not exempt, whatever prefix it shows.
func TestExemptPathsRefuseUnnormalisedForms(t *testing.T) {
	c := newClock()
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	z.Policy.ChallengeOptions.ExemptPaths = []string{"/healthz", "/api/"}
	s := newService(t, c, z)
	ip := src("198.51.100.58")
	refused := []struct{ path, raw string }{
		{"/healthz/../admin", "/healthz/../admin"}, {"/healthz/..", "/healthz/.."}, {"/healthz/./x", "/healthz/./x"},
		{"/api/%2e%2e/admin", "/api/%2e%2e/admin"}, {"/healthz\\..\\admin", "/healthz\\..\\admin"},
		{"/healthz/..;/admin", "/healthz/..;/admin"},   // a servlet container reads ..; as ..
		{"/healthz", "/admin/..%2Fhealthz"},            // nginx collapsed it; an /admin route elsewhere
		{"/healthz", "/admin/..%2fhealthz?x=1"},        // lower-case escape, query
		{"/healthz/x", "/healthz%2Fx"},                 // an encoded slash: one segment to some routers
		{"/healthz", "/he%61lthz"},                     // an encoded letter is fine on its own, but...
		{"/healthz", ""},                               // ...a missing raw target is not exempt
		{"", "/healthz"},                               // nor a missing (unshaped) normalised path
		{"healthz", "healthz"}, {"/healthz\x01", "/healthz%01"}, {"/héalthz", "/h%C3%A9althz"},
		{"/api/x", "/API/x"},                           // prefixes are case-sensitive on both sides
	}
	for _, r := range refused {
		if r.path == "/healthz" && r.raw == "/he%61lthz" {
			continue // the one row that IS exempt, asserted below
		}
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip, Path: r.path, RawURI: r.raw}); v.Allow || !v.Challenge {
			t.Fatalf("path %q raw %q was exempt: %+v", r.path, r.raw, v)
		}
	}
	for _, ok := range []struct{ path, raw string }{
		{"/healthz", "/healthz"}, {"/healthz.old", "/healthz.old?deep=1"}, {"/api/v1/x", "/api/v1/x"}, {"/healthz", "/he%61lthz"},
	} {
		if ok.raw == "/he%61lthz" {
			// An encoded letter inside the prefix: the raw form no longer starts
			// with the prefix, so it is NOT exempt — the operator's prefix is
			// matched literally on both forms.
			if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.60"), Path: ok.path, RawURI: ok.raw}); v.Allow {
				t.Fatalf("encoded prefix letter exempted: %+v", v)
			}
			continue
		}
		if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.61"), Path: ok.path, RawURI: ok.raw}); !v.Allow || v.Challenge {
			t.Fatalf("plain exempt path %q refused: %+v", ok.path, v)
		}
	}
}

// TestZoneFlipFollowsTheMode pins that a flip belongs to auto: a manual or
// off zone refuses one, a mode change makes a standing flip go away, and an
// `until` already past flips nothing.
func TestZoneFlipFollowsTheMode(t *testing.T) {
	c := newClock()
	za, _ := challengeZone(t, "shop.example", edgedoc.ChallengeAuto, 0)
	zm, _ := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	s := newService(t, c, zm)
	if s.SetZoneChallenge("shop.example", true, c.t.Add(time.Hour), "x") {
		t.Fatal("a manual zone took a flip")
	}
	s.SetZones(doc(za))
	if s.SetZoneChallenge("shop.example", true, c.t, "x") {
		t.Fatal("a flip with until == now was taken")
	}
	if !s.SetZoneChallenge("shop.example", true, c.t.Add(time.Hour), "zone-rps") {
		t.Fatal("an auto zone refused a flip")
	}
	if on, _, _ := s.ZoneChallenge("shop.example"); !on {
		t.Fatal("flip not reported")
	}
	s.SetZones(doc(zm))
	if on, _, _ := s.ZoneChallenge("shop.example"); on {
		t.Fatal("a flip survived a change to manual")
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: src("198.51.100.59")}); v.Reason != "challenge:manual" {
		t.Fatalf("manual zone after the flip: %+v", v)
	}
}

// TestHandlerContractChallenge pins the HTTP side: a challenge is a 401 with
// the reason and no body; a clearance travels in X-Kapkan-Clearance and an
// oversized one is simply not a clearance; the URI header feeds exemptions.
func TestHandlerContractChallenge(t *testing.T) {
	c := newClock()
	z, k := challengeZone(t, "shop.example", edgedoc.ChallengeManual, 0)
	z.Policy.ChallengeOptions.ExemptPaths = []string{"/healthz"}
	s := newService(t, c, z)
	h := (&Server{Service: s}).Handler()
	do := func(clr, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/decide", nil)
		req.Header.Set(headerZone, "shop.example")
		req.Header.Set(headerClient, "198.51.100.60")
		if clr != "" {
			req.Header.Set(headerClearance, clr)
		}
		if path != "" {
			req.Header.Set(headerPath, path)
			req.Header.Set(headerURI, path+"?raw=1")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("", "/"); rec.Code != http.StatusUnauthorized || rec.Header().Get(headerReason) != "challenge:manual" || rec.Header().Get(headerMark) != "" || rec.Body.Len() != 0 {
		t.Fatalf("challenge: %d %v body=%d", rec.Code, rec.Header(), rec.Body.Len())
	}
	good := cookieFor(t, k, "shop.example", "198.51.100.60", c)
	if rec := do(good, "/"); rec.Code != 200 || rec.Header().Get(headerMark) != MarkCleared || rec.Header().Get(headerReason) != "" {
		t.Fatalf("cleared: %d %v", rec.Code, rec.Header())
	}
	if rec := do(strings.Repeat("a", 513), "/"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("oversized clearance: %d", rec.Code)
	}
	if rec := do("", "/healthz"); rec.Code != 200 {
		t.Fatalf("exempt path: %d", rec.Code)
	}
	if rec := do("", "/cart"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a non-exempt path: %d", rec.Code)
	}
	// The normalised path alone (raw target elsewhere) does not exempt.
	raw := httptest.NewRequest("GET", "/decide", nil)
	raw.Header.Set(headerZone, "shop.example")
	raw.Header.Set(headerClient, "198.51.100.60")
	raw.Header.Set(headerPath, "/healthz")
	raw.Header.Set(headerURI, "/admin/..%2Fhealthz")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, raw)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("normalised path exempt while the raw target says /admin: %d", rec.Code)
	}
	s.SetDryRun(true)
	if rec := do("", "/"); rec.Code != 200 || rec.Header().Get(headerMark) != "would-challenge:manual" || rec.Header().Get(headerReason) != "challenge:manual" {
		t.Fatalf("dry-run challenge: %d %v", rec.Code, rec.Header())
	}
}
