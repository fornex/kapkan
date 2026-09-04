package page

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
)

var t0 = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// fakeZones is the decision service's side: one zone with a document key
// and the node's local key, the rung on at MinDifficulty so tests solve fast.
type fakeZones struct {
	keys map[string][]clearance.Key
	pol  map[string]clearance.Policy
}

func (f *fakeZones) Keys(zone string) []clearance.Key { return f.keys[zone] }
func (f *fakeZones) Rung(zone string) (clearance.Policy, bool) {
	p, ok := f.pol[zone]
	return p, ok
}

func newFixture(t *testing.T) (*Server, *fakeZones, *clock) {
	t.Helper()
	c := &clock{t: t0}
	docSecret, _ := clearance.DeriveZoneKey([]byte(strings.Repeat("m", 32)), "shop.example")
	localSecret, _ := clearance.DeriveZoneKey([]byte(strings.Repeat("l", 32)), "shop.example")
	z := &fakeZones{
		keys: map[string][]clearance.Key{"shop.example": {
			{ID: "c1", Secret: docSecret, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(47 * time.Hour)},
			{ID: "local", Secret: localSecret, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<40, 0)},
		}},
		pol: map[string]clearance.Policy{"shop.example": {Difficulty: clearance.MinDifficulty, CookieTTL: 30 * time.Minute, NoJSTTL: 5 * time.Minute}},
	}
	s := &Server{Zones: z, Now: c.now}
	s.init()
	return s, z, c
}

// get performs a request as the renderer would forward it.
func do(h http.Handler, method, path string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Kapkan-Zone", "shop.example")
	req.Header.Set("X-Kapkan-Client", "203.0.113.4")
	req.Header.Set("X-Kapkan-Method", "GET")
	req.Header.Set("X-Kapkan-URI", "/cart?x=1")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var puzzleRe = regexp.MustCompile(`(?s)<script type="application/json" id="kapkan-puzzle">(.*?)</script>`)
var ticketRe = regexp.MustCompile(`name="t" value="([^"]+)"`)
var assetRe = regexp.MustCompile(`(/_kapkan/clearance/a/[a-z]+\.[0-9a-f]{12}\.(?:js|css))`)

func challengePage(t *testing.T, h http.Handler, hdr map[string]string) (rec *httptest.ResponseRecorder, p clearance.Puzzle, ticket string) {
	t.Helper()
	if hdr == nil {
		hdr = map[string]string{}
	}
	if _, ok := hdr["X-Kapkan-Reason"]; !ok {
		hdr["X-Kapkan-Reason"] = "challenge:manual"
	}
	rec = do(h, http.MethodGet, "/_kapkan/clearance/challenge", hdr, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("challenge page = %d: %s", rec.Code, rec.Body)
	}
	m := puzzleRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no puzzle block:\n%s", rec.Body)
	}
	if err := json.Unmarshal([]byte(m[1]), &p); err != nil {
		t.Fatalf("puzzle json: %v", err)
	}
	tm := ticketRe.FindStringSubmatch(rec.Body.String())
	if tm == nil {
		t.Fatalf("no ticket in the page:\n%s", rec.Body)
	}
	return rec, p, tm[1]
}

// TestChallengePageShape pins the entry from @kapkan_clearance: a 403 HTML
// page, never cached, with the puzzle as a data block, the no-JS form and
// timer, the hashed assets, a strict CSP, and the request's locale.
func TestChallengePageShape(t *testing.T) {
	s, _, _ := newFixture(t)
	h := s.Handler()
	rec, p, ticket := challengePage(t, h, map[string]string{"Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"})
	body := rec.Body.String()
	for k, want := range map[string]string{
		"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Language": "ru",
		"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Cookie") {
		t.Errorf("Vary = %q", rec.Header().Get("Vary"))
	}
	if p.Difficulty != clearance.MinDifficulty || p.Return != "/cart?x=1" || !strings.HasPrefix(p.Nonce, "c1.") {
		t.Fatalf("puzzle: %+v (the document key, not the local one, must issue)", p)
	}
	for _, want := range []string{
		`<html lang="ru">`, "Проверяем браузер", `role="status" aria-live="polite"`, "<noscript>",
		`<meta http-equiv="refresh" content="5;url=/_kapkan/clearance/nojs?t=` + ticket + `">`,
		`<form method="get" action="/_kapkan/clearance/nojs">`, `<form id="kapkan-answer" method="post" action="/_kapkan/clearance/answer" hidden>`,
		`name="return" value="/cart?x=1"`, `<button type="submit">Продолжить</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Error("the page references an external resource")
	}
	// Both assets by content hash, immutable, right types; nothing else there.
	assets := assetRe.FindAllString(body, -1)
	if len(assets) != 2 {
		t.Fatalf("assets in page: %v", assets)
	}
	for _, a := range assets {
		r := do(h, http.MethodGet, a, nil, "")
		if r.Code != 200 || r.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || r.Body.Len() == 0 {
			t.Errorf("asset %s: %d %q", a, r.Code, r.Header().Get("Cache-Control"))
		}
		wantType := "text/javascript; charset=utf-8"
		if strings.HasSuffix(a, ".css") {
			wantType = "text/css; charset=utf-8"
		}
		if got := r.Header().Get("Content-Type"); got != wantType {
			t.Errorf("asset %s type %q", a, got)
		}
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/a/app.000000000000.js", nil, ""); r.Code != 404 {
		t.Errorf("unknown asset = %d", r.Code)
	}
	// HEAD: headers, no body. Default locale: English.
	if r := do(h, http.MethodHead, "/_kapkan/clearance/challenge", map[string]string{"X-Kapkan-Reason": "challenge:manual", "Accept-Language": "xx"}, ""); r.Code != 403 || r.Body.Len() != 0 || r.Header().Get("Content-Language") != "en" {
		t.Errorf("HEAD: %d body=%d lang=%q", r.Code, r.Body.Len(), r.Header().Get("Content-Language"))
	}
}

// TestChallengeRefusals pins who gets what instead of the page: a non-GET
// original gets the compact JSON, a walk-in without X-Kapkan-Reason a 404, an
// unknown zone a 404, a subrequest off the contract a 400.
func TestChallengeRefusals(t *testing.T) {
	s, _, _ := newFixture(t)
	h := s.Handler()
	r := do(h, http.MethodGet, "/_kapkan/clearance/challenge", map[string]string{"X-Kapkan-Reason": "challenge:manual", "X-Kapkan-Method": "POST"}, "")
	if r.Code != 403 || r.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(r.Body.String()) != `{"error":"challenge_required"}` || r.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("POST original: %d %s %q", r.Code, r.Header().Get("Content-Type"), r.Body)
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/challenge", map[string]string{"X-Kapkan-Reason": ""}, ""); r.Code != 404 {
		t.Errorf("walk-in without a reason = %d", r.Code)
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/challenge", map[string]string{"X-Kapkan-Reason": "challenge:manual", "X-Kapkan-Zone": "nobody.example"}, ""); r.Code != 404 {
		t.Errorf("unknown zone = %d", r.Code)
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/challenge", map[string]string{"X-Kapkan-Reason": "challenge:manual", "X-Kapkan-Client": "not-an-ip"}, ""); r.Code != 400 {
		t.Errorf("bad client = %d", r.Code)
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/other", nil, ""); r.Code != 404 {
		t.Errorf("unknown path = %d", r.Code)
	}
	// An original whose URI is not a usable return path is sent home.
	_, p, _ := challengePage(t, h, map[string]string{"X-Kapkan-URI": "//evil.example/"})
	if p.Return != "/" {
		t.Errorf("return for a scheme-relative URI = %q", p.Return)
	}
}

// TestAnswerRoundTrip pins the flow a browser takes: page → solve → POST the
// form → 303 back to the request with the clearance cookie, whose value
// verifies under the zone's keys for this source and no other.
func TestAnswerRoundTrip(t *testing.T) {
	s, z, c := newFixture(t)
	h := s.Handler()
	_, p, _ := challengePage(t, h, nil)
	sol := clearance.Solve(p)
	c.add(20 * time.Second)
	form := url.Values{"nonce": {p.Nonce}, "solution": {sol}, "return": {p.Return}}.Encode()
	r := do(h, http.MethodPost, "/_kapkan/clearance/answer", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form)
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/cart?x=1" || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("answer: %d %v %s", r.Code, r.Header(), r.Body)
	}
	cookies := r.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %+v", cookies)
	}
	ck := cookies[0]
	if ck.Name != CookieName || ck.Path != "/" || !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 1800 || ck.Domain != "" {
		t.Fatalf("cookie attributes: %+v", ck)
	}
	keys := z.keys["shop.example"]
	if kind, ok := clearance.Verify(keys, "shop.example", "203.0.113.4", ck.Value, c.t); !ok || kind != clearance.KindPoW {
		t.Fatalf("cookie does not verify: %v %q", ok, kind)
	}
	if _, ok := clearance.Verify(keys, "shop.example", "203.0.113.5", ck.Value, c.t); ok {
		t.Fatal("cookie verifies for another source")
	}
	if _, ok := clearance.Verify(keys, "shop.example", "203.0.113.4", ck.Value, c.t.Add(31*time.Minute)); ok {
		t.Fatal("cookie outlives its TTL")
	}
	// The same answer as JSON works too.
	body, _ := json.Marshal(answer{Nonce: p.Nonce, Solution: sol, Return: p.Return})
	if r := do(h, http.MethodPost, "/_kapkan/clearance/answer", map[string]string{"Content-Type": "application/json"}, string(body)); r.Code != http.StatusSeeOther {
		t.Fatalf("json answer: %d %s", r.Code, r.Body)
	}
	// Wrong solution, wrong return (the redirect guard), another source's
	// nonce, a GET: all refused, none issue a cookie.
	for name, hdr := range map[string]map[string]string{
		"wrong solution":  {"Content-Type": "application/x-www-form-urlencoded"},
		"other return":    {"Content-Type": "application/x-www-form-urlencoded"},
		"other source":    {"Content-Type": "application/x-www-form-urlencoded", "X-Kapkan-Client": "203.0.113.9"},
		"absolute return": {"Content-Type": "application/x-www-form-urlencoded"},
	} {
		f := url.Values{"nonce": {p.Nonce}, "solution": {sol}, "return": {p.Return}}
		switch name {
		case "wrong solution":
			f.Set("solution", sol+"x")
		case "other return":
			f.Set("return", "/admin")
		case "absolute return":
			f.Set("return", "https://evil.example/")
		}
		r := do(h, http.MethodPost, "/_kapkan/clearance/answer", hdr, f.Encode())
		if r.Code != 403 || len(r.Result().Cookies()) != 0 || !strings.Contains(r.Body.String(), `"invalid"`) {
			t.Errorf("%s: %d %s cookies=%d", name, r.Code, r.Body, len(r.Result().Cookies()))
		}
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/answer", nil, ""); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET answer = %d", r.Code)
	}
	// A puzzle answered too late (the nonce's window passed) is invalid.
	c.add(10 * time.Minute)
	if r := do(h, http.MethodPost, "/_kapkan/clearance/answer", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form); r.Code != 403 {
		t.Errorf("stale answer = %d", r.Code)
	}
}

// TestNoJSTicket pins the fallback: redeemed too early it is refused with a
// small page (a no-JS client cannot read JSON), after the wait it grants the
// shorter nojs clearance, and after two minutes it is dead.
func TestNoJSTicket(t *testing.T) {
	s, z, c := newFixture(t)
	h := s.Handler()
	_, _, ticket := challengePage(t, h, nil)
	early := do(h, http.MethodGet, "/_kapkan/clearance/nojs?t="+url.QueryEscape(ticket), nil, "")
	if early.Code != 403 || !strings.Contains(early.Body.String(), "Not yet") || !strings.Contains(early.Body.String(), `<a href="/cart?x=1">`) || len(early.Result().Cookies()) != 0 {
		t.Fatalf("too early: %d %s", early.Code, early.Body)
	}
	c.add(5 * time.Second)
	r := do(h, http.MethodGet, "/_kapkan/clearance/nojs?t="+url.QueryEscape(ticket), nil, "")
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/cart?x=1" {
		t.Fatalf("redeem: %d %v %s", r.Code, r.Header(), r.Body)
	}
	cookies := r.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != 300 {
		t.Fatalf("nojs cookie: %+v", cookies)
	}
	if kind, ok := clearance.Verify(z.keys["shop.example"], "shop.example", "203.0.113.4", cookies[0].Value, c.t); !ok || kind != clearance.KindNoJS {
		t.Fatalf("nojs cookie kind: %v %q", ok, kind)
	}
	// Another source cannot redeem it; a tampered ticket is refused; dead
	// after two minutes.
	if r := do(h, http.MethodGet, "/_kapkan/clearance/nojs?t="+url.QueryEscape(ticket), map[string]string{"X-Kapkan-Client": "203.0.113.9"}, ""); r.Code != 403 {
		t.Errorf("other source redeemed = %d", r.Code)
	}
	if r := do(h, http.MethodGet, "/_kapkan/clearance/nojs?t="+url.QueryEscape(ticket[:len(ticket)-2]+"AA"), nil, ""); r.Code != 403 {
		t.Errorf("tampered ticket = %d", r.Code)
	}
	c.add(3 * time.Minute)
	if r := do(h, http.MethodGet, "/_kapkan/clearance/nojs?t="+url.QueryEscape(ticket), nil, ""); r.Code != 403 {
		t.Errorf("expired ticket = %d", r.Code)
	}
	if r := do(h, http.MethodPost, "/_kapkan/clearance/nojs?t=x", nil, ""); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST nojs = %d", r.Code)
	}
}

// TestIssuanceCaps pins D8's brake: a source is issued at most six
// clearances a minute, a zone at most its cap, and the minute rolls over.
func TestIssuanceCaps(t *testing.T) {
	s, _, c := newFixture(t)
	s.IssuePerZone = 8
	h := s.Handler()
	_, _, ticket := challengePage(t, h, nil)
	c.add(5 * time.Second)
	redeem := func(client string) int {
		return do(h, http.MethodGet, "/_kapkan/clearance/nojs?t="+url.QueryEscape(ticket), map[string]string{"X-Kapkan-Client": client}, "").Code
	}
	for i := 0; i < 6; i++ {
		if code := redeem("203.0.113.4"); code != http.StatusSeeOther {
			t.Fatalf("issuance %d = %d", i+1, code)
		}
	}
	if code := redeem("203.0.113.4"); code != http.StatusTooManyRequests {
		t.Fatalf("seventh issuance = %d, want 429", code)
	}
	// Another source gets its own budget — until the zone's cap holds.
	_, _, ticket2 := challengePage(t, h, map[string]string{"X-Kapkan-Client": "203.0.113.7"})
	ticket = ticket2
	c.add(5 * time.Second)
	if code := redeem("203.0.113.7"); code != http.StatusSeeOther {
		t.Fatalf("other source's first issuance = %d", code)
	}
	if code := redeem("203.0.113.7"); code != http.StatusSeeOther {
		t.Fatalf("other source's second issuance = %d", code)
	}
	if code := redeem("203.0.113.7"); code != http.StatusTooManyRequests {
		t.Fatalf("zone cap: %d, want 429", code)
	}
	// A minute later the windows are fresh.
	c.add(61 * time.Second)
	_, _, ticket3 := challengePage(t, h, map[string]string{"X-Kapkan-Client": "203.0.113.7"})
	ticket = ticket3
	c.add(5 * time.Second)
	if code := redeem("203.0.113.7"); code != http.StatusSeeOther {
		t.Fatalf("after the minute rolled: %d", code)
	}
}

// TestIssuingKeyPrefersTheDocument pins which key signs: the newest live
// document key, so a clearance verifies fleet-wide; the node's own only when
// no document key is live.
func TestIssuingKeyPrefersTheDocument(t *testing.T) {
	local := clearance.Key{ID: "local", Secret: make([]byte, 32), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<40, 0)}
	old := clearance.Key{ID: "c0", Secret: make([]byte, 32), NotBefore: t0.Add(-30 * time.Hour), NotAfter: t0.Add(18 * time.Hour)}
	cur := clearance.Key{ID: "c1", Secret: make([]byte, 32), NotBefore: t0.Add(-6 * time.Hour), NotAfter: t0.Add(42 * time.Hour)}
	dead := clearance.Key{ID: "c9", Secret: make([]byte, 32), NotBefore: t0.Add(-80 * time.Hour), NotAfter: t0.Add(-30 * time.Hour)}
	if k, ok := issuingKey([]clearance.Key{old, cur, local}, t0); !ok || k.ID != "c1" {
		t.Fatalf("issuing key = %v %v, want c1", k.ID, ok)
	}
	if k, ok := issuingKey([]clearance.Key{dead, local}, t0); !ok || k.ID != "local" {
		t.Fatalf("issuing key with dead document keys = %v %v, want local", k.ID, ok)
	}
	if _, ok := issuingKey([]clearance.Key{dead}, t0); ok {
		t.Fatal("a dead key issued")
	}
	if l := pickLocale("de-CH, fr;q=0.8"); l.Tag != "de" {
		t.Errorf("locale = %s", l.Tag)
	}
	if l := pickLocale(""); l.Tag != "en" {
		t.Errorf("default locale = %s", l.Tag)
	}
}
