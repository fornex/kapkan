package poll

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBrain struct {
	mu     sync.Mutex
	doc    string
	etag   string
	status int // 0 = behave; else answer this status to every poll
	noETag bool
	polls  atomic.Int64
	seen   []string // If-None-Match values
	auth   []string
	nodes  []string
}

func (b *fakeBrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.polls.Add(1)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seen = append(b.seen, r.Header.Get("If-None-Match"))
	b.auth = append(b.auth, r.Header.Get("Authorization"))
	b.nodes = append(b.nodes, r.URL.Query().Get("node"))
	if b.status != 0 {
		w.WriteHeader(b.status)
		return
	}
	if r.Header.Get("If-None-Match") == b.etag {
		// A held poll answered by the deadline.
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("ETag", b.etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if !b.noETag {
		w.Header().Set("ETag", b.etag)
	}
	_, _ = w.Write([]byte(b.doc))
}

func (b *fakeBrain) set(doc, etag string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.doc, b.etag = doc, etag
}

func newPoller(t *testing.T, srv *httptest.Server, b *fakeBrain, onDoc func([]byte, string) error) *Poller {
	t.Helper()
	p, err := New(Options{
		BaseURL: srv.URL, Path: "/api/v1/edge/zones", Token: "agent-secret", Node: "e1",
		OnDocument: onDoc, PollTimeout: time.Second, BackoffMin: 20 * time.Millisecond, BackoffMax: 50 * time.Millisecond,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPollDeliversDocumentsAndHolds(t *testing.T) {
	b := &fakeBrain{doc: `{"version":1}`, etag: `"e1"`}
	srv := httptest.NewServer(b)
	defer srv.Close()
	var got []string
	var mu sync.Mutex
	p := newPoller(t, srv, b, func(body []byte, etag string) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, etag+":"+string(body))
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && p.ETag() != `"e1"` {
		time.Sleep(5 * time.Millisecond)
	}
	if p.ETag() != `"e1"` {
		t.Fatalf("first document not accepted; ETag %q", p.ETag())
	}
	// Then held polls (304) with the ETag presented, no busy loop.
	time.Sleep(200 * time.Millisecond)
	if n := b.polls.Load(); n > 20 {
		t.Fatalf("%d polls in 200 ms: busy-looping instead of holding", n)
	}
	// A change is picked up.
	b.set(`{"version":1,"zones":[]}`, `"e2"`)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && p.ETag() != `"e2"` {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != `"e1":{"version":1}` || got[1] != `"e2":{"version":1,"zones":[]}` {
		t.Fatalf("documents delivered: %v", got)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.auth[0] != "Bearer agent-secret" || b.nodes[0] != "e1" || b.seen[0] != "" {
		t.Fatalf("first request: auth=%q node=%q inm=%q", b.auth[0], b.nodes[0], b.seen[0])
	}
	if b.seen[1] != `"e1"` {
		t.Fatalf("second request did not present the ETag: %q", b.seen[1])
	}
	if p.LastOK().IsZero() {
		t.Fatal("LastOK never set")
	}
}

func TestPollSeedsFromARestoredETag(t *testing.T) {
	b := &fakeBrain{doc: `{"version":1}`, etag: `"restored"`}
	srv := httptest.NewServer(b)
	defer srv.Close()
	delivered := 0
	p, err := New(Options{BaseURL: srv.URL, Path: "/x", ETag: `"restored"`, OnDocument: func([]byte, string) error { delivered++; return nil },
		PollTimeout: time.Second, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Once(context.Background()) || delivered != 0 {
		t.Fatalf("a restored ETag must 304, not re-deliver (delivered=%d)", delivered)
	}
}

func TestPollBacksOffOnFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		noETag bool
		refuse bool
	}{
		{"forbidden", http.StatusForbidden, false, false},
		{"unknown node", http.StatusNotFound, false, false},
		{"server error", http.StatusInternalServerError, false, false},
		{"no etag", 0, true, false},
		{"document refused", 0, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &fakeBrain{doc: `{"version":1}`, etag: `"e"`, status: c.status, noETag: c.noETag}
			srv := httptest.NewServer(b)
			defer srv.Close()
			p := newPoller(t, srv, b, func([]byte, string) error {
				if c.refuse {
					return errors.New("version 9 not understood")
				}
				return nil
			})
			if p.Once(context.Background()) {
				t.Fatal("a failing poll reported healthy")
			}
			if p.ETag() != "" {
				t.Fatalf("ETag advanced on a failure: %q", p.ETag())
			}
			// Run backs off: far fewer polls than a busy loop would make.
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			p.Run(ctx)
			if n := b.polls.Load(); n < 3 || n > 12 {
				t.Fatalf("%d polls in 200 ms with 20-50 ms backoff", n)
			}
		})
	}
}

func TestPollNeverFollowsRedirects(t *testing.T) {
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect followed; bearer %q leaked", r.Header.Get("Authorization"))
	}))
	defer leak.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, leak.URL, http.StatusFound)
	}))
	defer srv.Close()
	p, _ := New(Options{BaseURL: srv.URL, Path: "/x", Token: "s", OnDocument: func([]byte, string) error { return nil }, Logger: slog.New(slog.DiscardHandler)})
	if p.Once(context.Background()) {
		t.Fatal("a redirect counted as healthy")
	}
}
