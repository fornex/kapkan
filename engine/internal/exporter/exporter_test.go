package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestParseLine(t *testing.T) {
	override := netip.Addr{}
	cases := []struct {
		name    string
		raw     string
		over    netip.Addr
		wantErr bool
		wantP   pair
		wantE   bool
	}{
		{
			name:  "documented format",
			raw:   `{"src":"198.51.100.7","dst":"203.0.113.10","status":"200"}`,
			over:  override,
			wantP: pair{victim: addr("203.0.113.10"), source: addr("198.51.100.7")},
		},
		{
			name:  "a 4xx is an error",
			raw:   `{"src":"198.51.100.7","dst":"203.0.113.10","status":"429"}`,
			over:  override,
			wantP: pair{victim: addr("203.0.113.10"), source: addr("198.51.100.7")},
			wantE: true,
		},
		{
			name:  "extra fields are the operator's business",
			raw:   `{"t":"2026-08-22T10:00:00","src":"198.51.100.7","dst":"203.0.113.10","status":"503","uri":"/x"}`,
			over:  override,
			wantP: pair{victim: addr("203.0.113.10"), source: addr("198.51.100.7")},
			wantE: true,
		},
		{
			name:  "the -victim override wins over dst",
			raw:   `{"src":"198.51.100.7","dst":"10.0.0.1","status":"200"}`,
			over:  addr("203.0.113.99"),
			wantP: pair{victim: addr("203.0.113.99"), source: addr("198.51.100.7")},
		},
		{
			name:  "override makes a dst-less line usable",
			raw:   `{"src":"198.51.100.7","status":"200"}`,
			over:  addr("203.0.113.99"),
			wantP: pair{victim: addr("203.0.113.99"), source: addr("198.51.100.7")},
		},
		{
			name:  "a 4-in-6 source is normalized",
			raw:   `{"src":"::ffff:198.51.100.7","dst":"203.0.113.10","status":"200"}`,
			over:  override,
			wantP: pair{victim: addr("203.0.113.10"), source: addr("198.51.100.7")},
		},
		{name: "combined format is not the contract", raw: `1.2.3.4 - - [22/Aug/2026] "GET /"`, over: override, wantErr: true},
		{name: "no src", raw: `{"dst":"203.0.113.10","status":"200"}`, over: override, wantErr: true},
		{name: "no dst and no override", raw: `{"src":"198.51.100.7","status":"200"}`, over: override, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, isErr, err := parseLine([]byte(tc.raw), tc.over)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsed garbage: %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLine: %v", err)
			}
			if p != tc.wantP || isErr != tc.wantE {
				t.Fatalf("got (%+v, %v), want (%+v, %v)", p, isErr, tc.wantP, tc.wantE)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	v, s1, s2 := addr("203.0.113.10"), addr("198.51.100.7"), addr("198.51.100.8")
	base := Config{Window: 10 * time.Second, RPS: 50, MinRequests: 100}

	t.Run("rate over the window arms, quiet sources do not", func(t *testing.T) {
		w := map[pair]*counts{
			{v, s1}: {total: 600}, // 60 rps
			{v, s2}: {total: 120}, // 12 rps — under
		}
		got := evaluate(w, &base)
		if len(got) != 1 || got[0].p.source != s1 {
			t.Fatalf("verdicts = %+v, want only %s", got, s1)
		}
		if got[0].rate != 60 {
			t.Fatalf("rate = %g, want 60", got[0].rate)
		}
	})

	t.Run("min-requests floors the arithmetic", func(t *testing.T) {
		cfg := base
		cfg.MinRequests = 1000
		w := map[pair]*counts{{v, s1}: {total: 600}} // 60 rps but under the floor
		if got := evaluate(w, &cfg); len(got) != 0 {
			t.Fatalf("verdicts = %+v, want none under the floor", got)
		}
	})

	t.Run("error-ratio is an AND-axis when set", func(t *testing.T) {
		cfg := base
		cfg.ErrorRatio = 0.5
		w := map[pair]*counts{
			{v, s1}: {total: 600, errors: 500}, // hot and erroring
			{v, s2}: {total: 600, errors: 30},  // hot but healthy — a real client burst
		}
		got := evaluate(w, &cfg)
		if len(got) != 1 || got[0].p.source != s1 {
			t.Fatalf("verdicts = %+v, want only the erroring source", got)
		}
	})

	t.Run("zero error-ratio disables the axis", func(t *testing.T) {
		w := map[pair]*counts{{v, s1}: {total: 600}} // all 200s
		if got := evaluate(w, &base); len(got) != 1 {
			t.Fatalf("verdicts = %+v, want the well-formed flood armed anyway", got)
		}
	})
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		LogPath: "/var/log/nginx/kapkan.json.log", APIBase: "http://127.0.0.1:8080",
		Token: "t", Window: 10 * time.Second, RPS: 50, MinRequests: 100,
		TTL: 5 * time.Minute,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"no log":           func(c *Config) { c.LogPath = "" },
		"no api":           func(c *Config) { c.APIBase = "" },
		"no token":         func(c *Config) { c.Token = "" },
		"window too long":  func(c *Config) { c.Window = time.Hour },
		"zero rps":         func(c *Config) { c.RPS = 0 },
		"zero min":         func(c *Config) { c.MinRequests = 0 },
		"ratio over 1":     func(c *Config) { c.ErrorRatio = 1.5 },
		"ttl out of range": func(c *Config) { c.TTL = 48 * time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mut(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Observe mode is the one tokenless configuration that must work.
	c := valid
	c.Token, c.Observe = "", true
	if err := c.Validate(); err != nil {
		t.Fatalf("observe mode without a token refused: %v", err)
	}
}

func TestTailerFollowsAndSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("history line — must NOT be delivered\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tl, err := newTailer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lines := tl.lines(ctx)

	appendTo := func(p, s string) {
		t.Helper()
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	next := func() string {
		t.Helper()
		select {
		case l := <-lines:
			return string(l)
		case <-ctx.Done():
			t.Fatal("timed out waiting for a line")
			return ""
		}
	}

	appendTo(path, "live 1\nlive 2\n")
	if got := next(); got != "live 1" {
		t.Fatalf("first line = %q (history must be skipped)", got)
	}
	if got := next(); got != "live 2" {
		t.Fatalf("second line = %q", got)
	}

	// logrotate create-new: move the file away, create a fresh one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	appendTo(path, "after rotation\n")
	if got := next(); got != "after rotation" {
		t.Fatalf("post-rotation line = %q", got)
	}

	// copytruncate: same inode, size shrinks. A poll must OBSERVE the shrunken
	// size before new content regrows past the consumed offset — that is the
	// documented copytruncate bound (see maybeReopen) — so give it two poll
	// intervals before appending, which is exactly what a real truncation
	// looks like: nginx does not refill the log within a millisecond.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * tailPollInterval)
	appendTo(path, "after truncate\n")
	if got := next(); got != "after truncate" {
		t.Fatalf("post-truncate line = %q", got)
	}
}

// TestRunEndToEnd drives the whole loop: a log file gains a flood, the
// exporter posts a block shaped exactly as the API documents, refreshes it
// only when the TTL has half-burned, and surfaces a brain refusal without
// dying.
func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	var (
		mu    sync.Mutex
		posts []blockRequest
		auths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/dataplane/sources" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var req blockRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("body: %v", err)
		}
		mu.Lock()
		posts = append(posts, req)
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"source":"198.51.100.7","victim":"203.0.113.10"}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			LogPath: path, APIBase: srv.URL, Token: "secret",
			Window: time.Second, RPS: 10, MinRequests: 10, TTL: 10 * time.Second,
			Log: slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		})
	}()
	// The tailer starts at the END of the file — history is not evidence — so
	// the flood must land after Run has opened it. newTailer runs first thing
	// in Run; half a second is a geological era for that.
	time.Sleep(500 * time.Millisecond)

	flood := func(n int) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			_, _ = fmt.Fprintln(f, `{"src":"198.51.100.7","dst":"203.0.113.10","status":"200"}`)
		}
		_ = f.Close()
	}

	// Window 1: hot -> first post.
	flood(50)
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(posts) >= 1 }, 5*time.Second)

	// Window 2 (immediately hot again): TTL 10s barely burned -> NO refresh.
	flood(50)
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	if len(posts) != 1 {
		mu.Unlock()
		t.Fatalf("posts = %d, want 1 — a fresh TTL must not be refreshed every window", len(posts))
	}
	req, auth := posts[0], auths[0]
	mu.Unlock()

	if req.Victim != "203.0.113.10" || req.Source != "198.51.100.7" || req.TTLSeconds != 10 {
		t.Fatalf("posted %+v, want the flood's pair with ttl_seconds 10", req)
	}
	if !strings.Contains(req.Reason, "nginx-exporter") {
		t.Fatalf("reason = %q, want it attributed", req.Reason)
	}
	if auth != "Bearer secret" {
		t.Fatalf("auth = %q", auth)
	}

	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}
}

// TestClientSurfacesRefusal: a brain refusal (409 with the audited reason)
// must come back verbatim — it is the operator's only clue that the
// allowlist, the tenant boundary or the slot budget said no.
func TestClientSurfacesRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprint(w, `{"error":"source is in dataplane.allowlist"}`)
	}))
	defer srv.Close()

	cl := newClient(srv.URL, "secret")
	err := cl.blockSource(context.Background(), addr("203.0.113.10"), addr("198.51.100.7"), time.Minute, "test")
	if err == nil {
		t.Fatal("a 409 did not surface as an error")
	}
	if !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("err = %v, want the status and the brain's reason verbatim", err)
	}
}

func waitFor(t *testing.T, cond func() bool, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
