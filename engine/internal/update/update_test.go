package update

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func testChecker(url, channel, current string) *Checker {
	return New(Config{Channel: channel, URL: url, Current: current},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestIsComparable(t *testing.T) {
	cases := map[string]bool{
		"v1.2.3":              true,
		"1.2.3":               true,
		"v1.2.3-rc.1":         true,
		"v0.0.0":              true,
		"(devel)":             false,
		"unknown":             false,
		"":                    false,
		"v0.0.0-SNAPSHOT-abc": false,
		"v1.2.0-3-g8fb4d6d":   false, // git describe between tags
		"v1.2":                false, // not three parts
		"vfoo":                false,
	}
	for v, want := range cases {
		if got := isComparable(v); got != want {
			t.Errorf("isComparable(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.2.0", "v1.3.0", true},
		{"v1.2.0", "v1.2.1", true},
		{"v1.2.0", "v2.0.0", true},
		{"v1.2.0", "v1.2.0", false},
		{"v1.3.0", "v1.2.0", false},
		{"v2.0.0", "v1.9.9", false},
		{"v1.2.0-rc.1", "v1.2.0", true},  // final outranks its prerelease
		{"v1.2.0", "v1.2.0-rc.1", false}, // prerelease does not outrank final
		{"v1.2.0-rc.1", "v1.2.0-rc.2", true},
		{"v1.2.0-rc.2", "v1.2.0-rc.1", false},
	}
	for _, tc := range cases {
		if got := newer(tc.a, tc.b); got != tc.want {
			t.Errorf("newer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDetectSecurity(t *testing.T) {
	if !detectSecurity("### Added\n- x\n\n### Security\n- fixed a thing\n") {
		t.Error("a ### Security heading should be detected")
	}
	if !detectSecurity("## Security") {
		t.Error("a ## Security heading should be detected")
	}
	if detectSecurity("### Added\n- mention of security inline, no heading") {
		t.Error("an inline mention without a heading must not count")
	}
	if detectSecurity("") {
		t.Error("empty body is not security")
	}
}

// releaseJSON is a minimal GitHub release object with a properly-escaped body.
func releaseJSON(tag, body string) string {
	b, _ := json.Marshal(body)
	return `{"tag_name":"` + tag + `","html_url":"https://example.test/releases/` + tag + `","body":` + string(b) + `}`
}

func TestCheckOnceStableAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("missing expected headers: UA=%q Accept=%q", r.Header.Get("User-Agent"), r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(releaseJSON("v1.3.0", "### Added\n- stuff")))
	}))
	defer srv.Close()

	st, err := testChecker(srv.URL, "stable", "v1.2.0").CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if !st.Available || st.LatestVersion != "v1.3.0" || st.Security {
		t.Fatalf("status = %+v, want available v1.3.0 non-security", st)
	}
	if st.URL == "" {
		t.Error("expected the release html_url to be carried through")
	}
}

func TestCheckOnceUpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON("v1.2.0", "notes")))
	}))
	defer srv.Close()
	st, err := testChecker(srv.URL, "stable", "v1.2.0").CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if st.Available {
		t.Errorf("equal versions must not be 'available': %+v", st)
	}
}

func TestCheckOnceSecurity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON("v1.3.0", "### Security\n- CVE fix")))
	}))
	defer srv.Close()
	st, err := testChecker(srv.URL, "stable", "v1.2.0").CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if !st.Available || !st.Security {
		t.Fatalf("status = %+v, want available + security", st)
	}
}

func TestCheckOnceDevBuildNeverAlarms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON("v9.9.9", "notes")))
	}))
	defer srv.Close()
	for _, current := range []string{"(devel)", "v1.2.0-3-g8fb4d6d", "0.0.0-SNAPSHOT-abc", "unknown"} {
		st, err := testChecker(srv.URL, "stable", current).CheckOnce(context.Background())
		if err != nil {
			t.Fatalf("CheckOnce(%q): %v", current, err)
		}
		if st.Available {
			t.Errorf("dev build %q must not report an update available", current)
		}
	}
}

func TestCheckOncePrereleaseChannelPicksNewest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"tag_name":"nightly","html_url":"x","body":"","draft":true},
			{"tag_name":"v1.3.0-rc.1","html_url":"x","body":""},
			{"tag_name":"v1.3.0-rc.2","html_url":"x","body":""},
			{"tag_name":"v1.2.0","html_url":"x","body":""}
		]`))
	}))
	defer srv.Close()
	st, err := testChecker(srv.URL, "prerelease", "v1.2.0").CheckOnce(context.Background())
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if !st.Available || st.LatestVersion != "v1.3.0-rc.2" {
		t.Fatalf("status = %+v, want newest comparable v1.3.0-rc.2", st)
	}
}

func TestCheckOnceErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := testChecker(srv.URL, "stable", "v1.2.0").CheckOnce(context.Background()); err == nil {
		t.Fatal("expected an error on HTTP 500")
	}
}

func TestETagNotModifiedKeepsStatus(t *testing.T) {
	var calls, conditional int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"v1.3.0-etag"` {
			conditional++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1.3.0-etag"`)
		_, _ = w.Write([]byte(releaseJSON("v1.3.0", "notes")))
	}))
	defer srv.Close()

	c := testChecker(srv.URL, "stable", "v1.2.0")
	ctx := context.Background()
	c.checkAndRecord(ctx) // 200, stores the ETag
	first := c.Status()
	if !first.Available || first.LatestVersion != "v1.3.0" {
		t.Fatalf("after first check: %+v", first)
	}
	c.checkAndRecord(ctx) // sends If-None-Match -> 304
	second := c.Status()
	if second != first {
		t.Errorf("304 must leave status unchanged: %+v vs %+v", first, second)
	}
	if conditional != 1 {
		t.Errorf("second request should have been conditional (If-None-Match); conditional=%d calls=%d", conditional, calls)
	}
}

func TestUserAgentDoesNotLeakCommitOrDirty(t *testing.T) {
	cases := map[string]string{
		"v1.5.0":            "kapkan/v1.5.0 (update-check)", // clean tag
		"v1.5.0-3-g8fb4d6d": "kapkan/v1.5.0 (update-check)", // git describe → core only
		"v1.5.0-dirty":      "kapkan/v1.5.0 (update-check)", // dirty suffix dropped
		"0da5d54-dirty":     "kapkan/dev (update-check)",    // bare SHA → dev
		"(devel)":           "kapkan/dev (update-check)",
	}
	for current, wantUA := range cases {
		var gotUA string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUA = r.Header.Get("User-Agent")
			_, _ = w.Write([]byte(releaseJSON("v1.6.0", "notes")))
		}))
		if _, err := testChecker(srv.URL, "stable", current).CheckOnce(context.Background()); err != nil {
			srv.Close()
			t.Fatalf("CheckOnce(%q): %v", current, err)
		}
		srv.Close()
		if gotUA != wantUA {
			t.Errorf("current %q: User-Agent = %q, want %q", current, gotUA, wantUA)
		}
		if strings.Contains(gotUA, "g8fb4d6d") || strings.Contains(gotUA, "dirty") || strings.Contains(gotUA, "0da5d54") {
			t.Errorf("current %q: User-Agent leaks build detail: %q", current, gotUA)
		}
	}
}

func TestReadBodyRejectsOversize(t *testing.T) {
	data := strings.Repeat("x", 100)
	if _, err := readBody(strings.NewReader(data), 99); err == nil {
		t.Error("readBody must error when the body exceeds the limit (truncation guard)")
	}
	got, err := readBody(strings.NewReader(data), 100)
	if err != nil || len(got) != 100 {
		t.Errorf("readBody at exactly the limit = %d bytes, %v; want 100, nil", len(got), err)
	}
	got, err = readBody(strings.NewReader(data), 1000)
	if err != nil || len(got) != 100 {
		t.Errorf("readBody under the limit = %d bytes, %v; want 100, nil", len(got), err)
	}
}

func TestOnAvailableFiresOncePerNewVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON("v1.3.0", "### Security\n- fix")))
	}))
	defer srv.Close()

	var fired int
	var lastSec bool
	c := New(Config{Channel: "stable", URL: srv.URL, Current: "v1.2.0",
		OnAvailable: func(st Status) { fired++; lastSec = st.Security }},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	c.checkAndRecord(context.Background())
	if fired != 1 || !lastSec {
		t.Fatalf("OnAvailable fired=%d security=%v, want 1 and true", fired, lastSec)
	}
	// Same version on the next poll must NOT re-fire (deduped by version).
	c.checkAndRecord(context.Background())
	if fired != 1 {
		t.Errorf("OnAvailable re-fired for an unchanged version: fired=%d", fired)
	}
}

func TestCheckAndRecordSetsMetric(t *testing.T) {
	avail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON("v1.3.0", "notes")))
	}))
	defer avail.Close()
	testChecker(avail.URL, "stable", "v1.2.0").checkAndRecord(context.Background())
	if n := testutil.CollectAndCount(metrics.UpdateAvailable); n != 1 {
		t.Errorf("kapkan_update_available series = %d, want 1 when an update exists", n)
	}

	uptodate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(releaseJSON("v1.2.0", "notes")))
	}))
	defer uptodate.Close()
	testChecker(uptodate.URL, "stable", "v1.2.0").checkAndRecord(context.Background())
	if n := testutil.CollectAndCount(metrics.UpdateAvailable); n != 0 {
		t.Errorf("kapkan_update_available series = %d, want 0 when up to date", n)
	}
}
