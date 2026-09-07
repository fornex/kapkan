package poll

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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
		OnDocument: onDoc, PollTimeout: time.Second, BackoffMin: 20 * time.Millisecond, BackoffMax: 160 * time.Millisecond,
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
	okAfterFirst := p.LastOK()
	if okAfterFirst.IsZero() {
		t.Fatal("LastOK not set by the first 200")
	}
	// Then held polls (304) with the ETag presented, no busy loop — and every
	// 304 advances LastOK.
	time.Sleep(200 * time.Millisecond)
	if n := b.polls.Load(); n > 20 {
		t.Fatalf("%d polls in 200 ms: busy-looping instead of holding", n)
	}
	if !p.LastOK().After(okAfterFirst) {
		t.Fatal("a 304 did not advance LastOK")
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
	if p.LastOK().IsZero() {
		t.Fatal("a 304 did not set LastOK")
	}
}

// A brain failure backs off EXPONENTIALLY (20, 40, 80, 160, 160 ms with the
// options newPoller uses), leaves the ETag alone and never stamps LastOK.
//
// The sequence is read off the poller's own backoff seam, not off the wall
// clock: what is under test is the delay Run computes after each failure, and a
// real gap between two polls is that delay plus however long the machine felt
// like taking. That the delay is really waited out — that Run does not hammer a
// failing brain — is measured separately, and one-sidedly, by
// TestPollBackoffActuallyDelaysPolls.
func TestPollBacksOffOnFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		noETag bool
	}{
		{"forbidden", http.StatusForbidden, false},
		{"unknown node", http.StatusNotFound, false},
		{"server error", http.StatusInternalServerError, false},
		{"no etag", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &fakeBrain{doc: `{"version":1}`, etag: `"e"`, status: c.status, noETag: c.noETag}
			srv := httptest.NewServer(b)
			defer srv.Close()
			p := newPoller(t, srv, b, func([]byte, string) error { return nil })
			if p.Once(context.Background()) {
				t.Fatal("a failing poll reported healthy")
			}
			if p.ETag() != "" || !p.LastOK().IsZero() {
				t.Fatalf("ETag %q / LastOK %v advanced on a failure", p.ETag(), p.LastOK())
			}
			if p.opt.BackoffMin != 20*time.Millisecond || p.opt.BackoffMax != 160*time.Millisecond {
				t.Fatalf("the sequence below assumes 20/160 ms; newPoller now uses %v/%v", p.opt.BackoffMin, p.opt.BackoffMax)
			}
			// Every backoff Run computes is recorded and returns at once; the
			// sixth ends the loop. p.wait runs on Run's goroutine, which is this
			// one, so the slice needs no lock.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var backoffs []time.Duration
			p.wait = func(_ context.Context, d time.Duration) bool {
				backoffs = append(backoffs, d)
				if len(backoffs) == 6 {
					cancel()
					return false
				}
				return true
			}
			p.Run(ctx)
			ms := time.Millisecond
			want := []time.Duration{20 * ms, 40 * ms, 80 * ms, 160 * ms, 160 * ms, 160 * ms}
			if !slices.Equal(backoffs, want) {
				t.Fatalf("backoff sequence %v, want %v (BackoffMin doubling, capped at BackoffMax)", backoffs, want)
			}
			// One backoff per failure, no more: the Once above plus the six
			// polls Run made before the sixth backoff ended it.
			if n := b.polls.Load(); n != 7 {
				t.Fatalf("%d polls for 6 backoffs; want 7 (1 + 6)", n)
			}
			// And not one of those failures advanced anything: the ETag and
			// LastOK belong to a brain that answered.
			if p.ETag() != "" || !p.LastOK().IsZero() {
				t.Fatalf("ETag %q / LastOK %v advanced over 7 failing polls", p.ETag(), p.LastOK())
			}
		})
	}
}

// The computed backoff is really waited out: a failing brain is polled a
// handful of times, not thousands. The bound is one-sided on purpose — a loaded
// machine can only push a poll LATER, never earlier, so it holds under any
// scheduling, while dropping the wait from Run breaks it by orders of
// magnitude. The exact delays are TestPollBacksOffOnFailures' business.
func TestPollBackoffActuallyDelaysPolls(t *testing.T) {
	b := &fakeBrain{status: http.StatusInternalServerError}
	srv := httptest.NewServer(b)
	defer srv.Close()
	p := newPoller(t, srv, b, func([]byte, string) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	p.Run(ctx)
	// With 20, 40, 80 and 160 ms of backoff between them, the polls can start no
	// earlier than 0, 20, 60, 140 and 300 ms in — four of them inside a 300 ms
	// window, five if the last one races the deadline. More than that and the
	// backoff is not being waited out at all.
	n := b.polls.Load()
	if n > 5 {
		t.Fatalf("%d polls in 300 ms: the failure backoff is not being waited out", n)
	}
	// Only so the bound above cannot be satisfied by polling nothing at all;
	// the exact count is TestPollBacksOffOnFailures' business.
	if n < 2 {
		t.Fatalf("%d polls in 300 ms: the loop is not polling", n)
	}
}

// A document the caller refuses is NOT a brain failure: the poll advances to
// its ETag (so the next poll parks in a hold and the node stays alive to the
// brain), records the refusal, and stamps LastOK.
func TestPollRefusedDocumentAdvancesAndParks(t *testing.T) {
	b := &fakeBrain{doc: `{"version":1}`, etag: `"e1"`}
	srv := httptest.NewServer(b)
	defer srv.Close()
	var refuse atomic.Bool
	p := newPoller(t, srv, b, func([]byte, string) error {
		if refuse.Load() {
			return errors.New("candidate failed nginx -t")
		}
		return nil
	})
	if !p.Once(context.Background()) || p.ETag() != `"e1"` || p.LastRefusal() != "" {
		t.Fatalf("first accept: healthy=%v etag=%q refusal=%q", p.Once(context.Background()), p.ETag(), p.LastRefusal())
	}
	refuse.Store(true)
	b.set(`{"version":1,"zones":[]}`, `"e2"`)
	before := p.LastOK()
	time.Sleep(time.Millisecond)
	if !p.Once(context.Background()) {
		t.Fatal("a refused document was reported as a brain failure")
	}
	if p.ETag() != `"e2"` || p.LastRefusal() != "candidate failed nginx -t" || !p.LastOK().After(before) {
		t.Fatalf("after refusal: etag=%q refusal=%q lastOK advanced=%v", p.ETag(), p.LastRefusal(), p.LastOK().After(before))
	}
	// The next poll presents e2 and parks: the brain is not asked for the
	// same bytes again.
	delivered := b.polls.Load()
	if !p.Once(context.Background()) {
		t.Fatal("held poll unhealthy")
	}
	b.mu.Lock()
	last := b.seen[len(b.seen)-1]
	b.mu.Unlock()
	if last != `"e2"` || b.polls.Load() != delivered+1 {
		t.Fatalf("poll after a refusal presented %q", last)
	}
	// Accepting a later document clears the refusal.
	refuse.Store(false)
	b.set(`{"version":1,"zones":[],"x":1}`, `"e3"`)
	if !p.Once(context.Background()) || p.LastRefusal() != "" || p.ETag() != `"e3"` {
		t.Fatalf("after re-accept: refusal=%q etag=%q", p.LastRefusal(), p.ETag())
	}
}

// Cancellation mid-poll is shutdown, not a brain failure.
func TestPollCancellationIsNotAFailure(t *testing.T) {
	b := &fakeBrain{doc: `{"version":1}`, etag: `"e1"`}
	srv := httptest.NewServer(b)
	defer srv.Close()
	p := newPoller(t, srv, b, func([]byte, string) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !p.Once(ctx) {
		t.Fatal("cancellation counted as a brain failure")
	}
	if !p.LastOK().IsZero() {
		t.Fatal("cancellation stamped LastOK")
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
