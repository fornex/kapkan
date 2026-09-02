package decide

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)} }
func src(s string) netip.Addr        { return netip.MustParseAddr(s) }
func doc(zones ...edgedoc.Zone) *edgedoc.Doc {
	d := edgedoc.Empty()
	d.Zones = append(d.Zones, zones...)
	return &d
}

func zone(name string, rps, conc uint64) edgedoc.Zone {
	return edgedoc.Zone{Name: name, Origins: []string{"10.0.0.1:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, Rate: edgedoc.Rate{RPS: rps, Concurrency: conc}}}
}

func newService(t *testing.T, c *clock, zones ...edgedoc.Zone) *Service {
	t.Helper()
	s := New(Options{Now: c.now})
	s.SetZones(doc(zones...))
	return s
}

func TestUnknownZoneAndModeNonePass(t *testing.T) {
	c := newClock()
	none := zone("static.example.org", 1, 1)
	none.Policy.Mode = edgedoc.ModeNone
	s := newService(t, c, none)
	if v := s.Decide("nobody.example", src("198.51.100.1")); !v.Allow || v.Reason != ReasonUnknownZone {
		t.Fatalf("unknown zone: %+v", v)
	}
	for i := 0; i < 5; i++ {
		if v := s.Decide("static.example.org", src("198.51.100.1")); !v.Allow || v.Reason != ReasonModeNone {
			t.Fatalf("mode none: %+v", v)
		}
	}
}

func TestRateBucket(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 2, 0))
	ip := src("198.51.100.7")
	// One second of burst: two allowed at once, the third denied.
	for i := 0; i < 2; i++ {
		if v := s.Decide("example.com", ip); !v.Allow {
			t.Fatalf("request %d denied: %+v", i, v)
		}
	}
	if v := s.Decide("example.com", ip); v.Allow || v.Reason != ReasonRate {
		t.Fatalf("third request: %+v", v)
	}
	// Half a second refills one token.
	c.add(500 * time.Millisecond)
	if v := s.Decide("example.com", ip); !v.Allow {
		t.Fatalf("after refill: %+v", v)
	}
	if v := s.Decide("example.com", ip); v.Allow {
		t.Fatalf("bucket should be empty again: %+v", v)
	}
	// Another source has its own bucket.
	if v := s.Decide("example.com", src("198.51.100.8")); !v.Allow {
		t.Fatalf("other source: %+v", v)
	}
	// A rate change applies on the next decision, without a restart.
	s.SetZones(doc(zone("example.com", 100, 0)))
	c.add(10 * time.Second)
	for i := 0; i < 50; i++ {
		if v := s.Decide("example.com", ip); !v.Allow {
			t.Fatalf("after raising the rate, request %d denied: %+v", i, v)
		}
	}
}

func TestConcurrencyIsApproximateInflight(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 0, 2))
	ip := src("203.0.113.5")
	for i := 0; i < 2; i++ {
		if v := s.Decide("example.com", ip); !v.Allow {
			t.Fatalf("request %d: %+v", i, v)
		}
	}
	if v := s.Decide("example.com", ip); v.Allow || v.Reason != ReasonConcurrency {
		t.Fatalf("third in flight: %+v", v)
	}
	// The denied request is logged too, so it also completes; two completions
	// bring the count from 3 to 1 and the next request is allowed.
	s.Complete("example.com", ip)
	s.Complete("example.com", ip)
	if v := s.Decide("example.com", ip); !v.Allow {
		t.Fatalf("after completions: %+v", v)
	}
	// A count never goes negative, and idle drift is swept away.
	for i := 0; i < 10; i++ {
		s.Complete("example.com", ip)
	}
	c.add(2 * idleAfter)
	s.Decide("example.com", src("203.0.113.6")) // triggers a sweep
	if st := s.Stats(); st.Inflight != 1 {
		t.Fatalf("idle in-flight entries not swept: %+v", st)
	}
}

func TestVerdictTable(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("a.example.com", 0, 0), zone("b.example.com", 0, 0))
	ip := src("198.51.100.9")
	if !s.Deny("a.example.com", ip, time.Minute, "flood") {
		t.Fatal("Deny refused")
	}
	if v := s.Decide("a.example.com", ip); v.Allow || v.Reason != "table:flood" {
		t.Fatalf("denied source: %+v", v)
	}
	if v := s.Decide("b.example.com", ip); !v.Allow {
		t.Fatalf("a deny in zone a must not reach zone b: %+v", v)
	}
	// The every-zone wildcard.
	s.Mark("", ip, "suspicious", time.Minute)
	if v := s.Decide("b.example.com", ip); !v.Allow || v.Mark != "suspicious" {
		t.Fatalf("wildcard mark: %+v", v)
	}
	// The zone entry wins over the wildcard.
	if v := s.Decide("a.example.com", ip); v.Allow {
		t.Fatalf("zone deny must win over the wildcard mark: %+v", v)
	}
	// Expiry.
	c.add(61 * time.Second)
	if v := s.Decide("a.example.com", ip); !v.Allow || v.Mark != "" {
		t.Fatalf("after expiry: %+v", v)
	}
	if got := len(s.Verdicts()); got != 0 {
		t.Fatalf("%d live verdicts after expiry", got)
	}
	// Clear.
	s.Deny("a.example.com", ip, time.Hour, "x")
	s.Clear("a.example.com", ip)
	if v := s.Decide("a.example.com", ip); !v.Allow {
		t.Fatalf("after Clear: %+v", v)
	}
	// Marks are header-safe.
	s.Mark("a.example.com", ip, "bad mark\r\nX-Injected: 1", time.Minute)
	if v := s.Decide("a.example.com", ip); strings.ContainsAny(v.Mark, " \r\n") {
		t.Fatalf("unsanitised mark %q", v.Mark)
	}
}

func TestDryRunAnswersDenyAsMarkedAllow(t *testing.T) {
	c := newClock()
	s := New(Options{Now: c.now, DryRun: true})
	s.SetZones(doc(zone("example.com", 1, 0)))
	ip := src("198.51.100.10")
	s.Decide("example.com", ip)
	v := s.Decide("example.com", ip)
	if !v.Allow || !v.DryRun || v.Reason != ReasonRate || v.Mark != "would-deny:rate" {
		t.Fatalf("dry-run deny: %+v", v)
	}
	s.SetDryRun(false)
	if v := s.Decide("example.com", ip); v.Allow {
		t.Fatalf("enforcing again: %+v", v)
	}
}

func TestFullTablesPassUntracked(t *testing.T) {
	c := newClock()
	s := New(Options{Now: c.now, MaxSources: 2})
	s.SetZones(doc(zone("example.com", 1, 0)))
	s.Decide("example.com", src("198.51.100.1"))
	s.Decide("example.com", src("198.51.100.2"))
	// A third source cannot be tracked: it passes, and says so.
	v := s.Decide("example.com", src("198.51.100.3"))
	if !v.Allow || v.Reason != ReasonUntracked {
		t.Fatalf("third source: %+v", v)
	}
	// Once the others go idle, the sweep makes room.
	c.add(2 * idleAfter)
	if v := s.Decide("example.com", src("198.51.100.3")); v.Reason != ReasonAllow {
		t.Fatalf("after sweep: %+v", v)
	}
	if !s.Deny("example.com", src("198.51.100.4"), time.Minute, "a") || !s.Deny("example.com", src("198.51.100.5"), time.Minute, "b") {
		t.Fatal("table should take two entries")
	}
	if s.Deny("example.com", src("198.51.100.6"), time.Minute, "c") {
		t.Fatal("a full verdict table must refuse, not evict a live verdict")
	}
}

func TestHandlerContract(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 1, 0))
	s.Mark("example.com", src("198.51.100.20"), "vip", time.Hour)
	srv := &Server{Service: s}
	h := srv.Handler()

	do := func(path, zone, client string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if zone != "" {
			req.Header.Set(headerZone, zone)
		}
		if client != "" {
			req.Header.Set(headerClient, client)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("/decide", "example.com", "198.51.100.20"); rec.Code != 200 || rec.Header().Get(headerMark) != "vip" || rec.Body.Len() != 0 {
		t.Fatalf("allow+mark: %d %v body=%d", rec.Code, rec.Header(), rec.Body.Len())
	}
	if rec := do("/decide", "example.com", "198.51.100.20"); rec.Code != 403 || rec.Body.Len() != 0 {
		t.Fatalf("rate deny: %d body=%d", rec.Code, rec.Body.Len())
	}
	if rec := do("/decide", "", "198.51.100.1"); rec.Code != 400 {
		t.Fatalf("missing zone: %d", rec.Code)
	}
	if rec := do("/decide", "example.com", "not-an-ip"); rec.Code != 400 {
		t.Fatalf("bad client: %d", rec.Code)
	}
	if rec := do("/other", "example.com", "198.51.100.1"); rec.Code != 404 {
		t.Fatalf("other path: %d", rec.Code)
	}
	// An IPv4-mapped IPv6 address is the same source as its IPv4 form.
	if rec := do("/decide", "example.com", "::ffff:198.51.100.20"); rec.Code != 403 {
		t.Fatalf("mapped address not unmapped: %d", rec.Code)
	}
}

func TestListenAndServeOverUnixSocket(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 0, 0))
	path := filepath.Join(t.TempDir(), "d.sock")
	srv := &Server{Service: s, Path: path}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest("GET", "http://decide/decide", nil)
		req.Header.Set(headerZone, "example.com")
		req.Header.Set(headerClient, "198.51.100.30")
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("request over the socket: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
	if _, err := net.Dial("unix", path); err == nil {
		t.Fatal("socket file left behind")
	}
}
