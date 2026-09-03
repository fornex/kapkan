package decide

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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
	if v := s.Decide("nobody.example", src("198.51.100.1")); !v.Allow || v.Reason != ReasonUnknownZone || v.Denied() {
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
	if v := s.Decide("example.com", ip); v.Allow || v.Reason != ReasonRate || !v.Denied() {
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

// An IPv6 client is accounted by its /64: two addresses in one allocation
// share a bucket, so privacy-extension rotation buys no fresh burst.
func TestIPv6SourcesShareTheirSlash64(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 2, 0))
	a, b := src("2001:db8:1:2::10"), src("2001:db8:1:2:ffff::1")
	if v := s.Decide("example.com", a); !v.Allow {
		t.Fatalf("first: %+v", v)
	}
	if v := s.Decide("example.com", b); !v.Allow {
		t.Fatalf("second (same /64): %+v", v)
	}
	if v := s.Decide("example.com", src("2001:db8:1:2::dead")); v.Allow || v.Reason != ReasonRate {
		t.Fatalf("third address of the /64 must find the bucket empty: %+v", v)
	}
	if v := s.Decide("example.com", src("2001:db8:1:3::1")); !v.Allow {
		t.Fatalf("a different /64 has its own bucket: %+v", v)
	}
	if st := s.Stats(); st.Sources != 2 {
		t.Fatalf("Sources = %d, want 2 (/64 keys)", st.Sources)
	}
	// Denies and verdict reports use the key too.
	s.Deny("example.com", a, time.Minute, "x")
	if v := s.Decide("example.com", b); v.Allow {
		t.Fatalf("deny on the /64 must reach its other addresses: %+v", v)
	}
	if vs := s.Verdicts(); len(vs) != 1 || vs[0].Source.String() != "2001:db8:1:2::" {
		t.Fatalf("Verdicts = %+v", vs)
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
	// Extra completions never drive the count negative: after ten of them,
	// two decisions still fill the two slots and the third is denied.
	for i := 0; i < 10; i++ {
		s.Complete("example.com", ip)
	}
	s.Decide("example.com", ip)
	s.Decide("example.com", ip)
	if v := s.Decide("example.com", ip); v.Allow {
		t.Fatalf("count went negative: %+v", v)
	}
	// Idle entries are swept away.
	c.add(2 * idleAfter)
	s.Decide("example.com", src("203.0.113.6"))
	if st := s.Stats(); st.Inflight != 1 {
		t.Fatalf("idle in-flight entries not swept: %+v", st)
	}
}

// A lost log datagram leaves a phantom slot for inflightMaxAge, not forever:
// a steady client behind a lossy stream stays under its ceiling.
func TestInflightPhantomsAgeOut(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 0, 10))
	ip := src("203.0.113.9")
	// 1 rps for five minutes, 20% of completions lost: without aging the count
	// grows by one every five seconds and denies from the 50th second on
	// (~250 denials); with it at most six phantoms exist at once.
	denied := 0
	for i := 0; i < 300; i++ {
		if v := s.Decide("example.com", ip); !v.Allow {
			denied++
		}
		if i%5 != 0 {
			s.Complete("example.com", ip)
		}
		c.add(time.Second)
	}
	if denied != 0 {
		t.Fatalf("a client with a lossy log stream was denied %d of 300 times", denied)
	}
	// The same client with a limit the phantoms do exceed IS denied — the
	// ceiling still works — but only while phantoms are young.
	s2 := newService(t, c, zone("example.com", 0, 3))
	denied = 0
	for i := 0; i < 300; i++ {
		if v := s2.Decide("example.com", ip); !v.Allow {
			denied++
		}
		if i%5 != 0 {
			s2.Complete("example.com", ip)
		}
		c.add(time.Second)
	}
	if denied == 0 || denied == 300 {
		t.Fatalf("limit 3 with six phantoms: %d denials of 300; expected some, not all", denied)
	}
}

// A key whose log stream is dead — completions never arrive — must not be
// denied forever either: after idleAfter without a completion the ceiling is
// suspended for that key until completions resume.
func TestInflightSuspendsOnADeadLogStream(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 0, 5))
	ip := src("203.0.113.10")
	denied := 0
	for i := 0; i < 180; i++ {
		if v := s.Decide("example.com", ip); !v.Allow {
			denied++
		}
		c.add(time.Second)
	}
	// Denied from the 6th second until the stream was declared dead at the
	// 61st (and never again), not for the whole three minutes.
	if denied < 50 || denied > 60 {
		t.Fatalf("dead stream: %d denials of 180, want ~55 (until suspension)", denied)
	}
	// Completions resuming re-arm the ceiling.
	s.Complete("example.com", ip)
	for i := 0; i < 5; i++ {
		s.Decide("example.com", ip)
	}
	if v := s.Decide("example.com", ip); v.Allow {
		t.Fatalf("ceiling not re-armed after completions resumed: %+v", v)
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
	if !s.Denied("a.example.com", ip) || s.Denied("b.example.com", ip) {
		t.Fatal("Denied() disagrees with Decide()")
	}
	if v := s.Decide("b.example.com", ip); !v.Allow {
		t.Fatalf("a deny in zone a must not reach zone b: %+v", v)
	}
	// The every-zone wildcard.
	s.Mark("", ip, "suspicious", time.Minute)
	if v := s.Decide("b.example.com", ip); !v.Allow || v.Mark != "suspicious" {
		t.Fatalf("wildcard mark: %+v", v)
	}
	// Strength beats scope: a zone mark never hides an every-zone deny, and a
	// mark never displaces a deny for the same key.
	s.Deny("", ip, time.Minute, "operator")
	if v := s.Decide("b.example.com", ip); v.Allow || v.Reason != "table:operator" {
		t.Fatalf("every-zone deny under a zone mark: %+v", v)
	}
	s.Mark("a.example.com", ip, "errors", time.Minute)
	if v := s.Decide("a.example.com", ip); v.Allow {
		t.Fatalf("a mark displaced a deny: %+v", v)
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
	// Verdicts of a zone removed from the document are swept.
	s.Deny("a.example.com", ip, time.Hour, "x")
	s.SetZones(doc(zone("b.example.com", 0, 0)))
	c.add(sweepEvery)
	s.Decide("b.example.com", ip)
	for _, v := range s.Verdicts() {
		if v.Zone == "a.example.com" {
			t.Fatalf("verdict of a removed zone survived the sweep: %+v", v)
		}
	}
}

func TestDryRunAnswersDenyAsMarkedAllow(t *testing.T) {
	c := newClock()
	s := New(Options{Now: c.now, DryRun: true})
	s.SetZones(doc(zone("example.com", 1, 0)))
	ip := src("198.51.100.10")
	s.Decide("example.com", ip)
	v := s.Decide("example.com", ip)
	if !v.Allow || !v.DryRun || !v.Denied() || v.Reason != ReasonRate || v.Mark != "would-deny:rate" {
		t.Fatalf("dry-run deny: %+v", v)
	}
	s.Deny("example.com", ip, time.Minute, strings.Repeat("r", 80))
	if v := s.Decide("example.com", ip); len(v.Mark) > MaxMarkLen || !strings.HasPrefix(v.Mark, "would-deny:table:") {
		t.Fatalf("composed dry-run mark: %q (%d bytes)", v.Mark, len(v.Mark))
	}
	if !s.DryRun() {
		t.Fatal("DryRun() false")
	}
	s.SetDryRun(false)
	if v := s.Decide("example.com", ip); v.Allow {
		t.Fatalf("enforcing again: %+v", v)
	}
}

func TestFullTablesPassUntrackedWithoutSweepingEveryTime(t *testing.T) {
	c := newClock()
	s := New(Options{Now: c.now, MaxSources: 2})
	s.SetZones(doc(zone("example.com", 1, 0)))
	s.Mark("example.com", src("198.51.100.3"), "vip", time.Hour)
	s.Decide("example.com", src("198.51.100.1"))
	s.Decide("example.com", src("198.51.100.2"))
	// A third source cannot be tracked: it passes, says so — and keeps the
	// reputation mark the table gave it.
	v := s.Decide("example.com", src("198.51.100.3"))
	if !v.Allow || v.Reason != ReasonUntracked || v.Mark != "vip" {
		t.Fatalf("third source: %+v", v)
	}
	// The on-full sweep is paced: within fullSweepEvery a miss does not walk
	// the tables again.
	c.add(fullSweepEvery / 2)
	before := s.lastSweep
	s.Decide("example.com", src("198.51.100.4"))
	if s.lastSweep != before {
		t.Fatal("a second miss within fullSweepEvery swept again")
	}
	// Between periodic sweeps, an entry that went idle is reclaimed by the
	// paced on-full sweep and the newcomer gets a bucket.
	c.add(idleAfter)
	if v := s.Decide("example.com", src("198.51.100.5")); v.Reason != ReasonAllow {
		t.Fatalf("after the sources went idle: %+v", v)
	}
	// The verdict table refuses rather than evicts when full.
	if !s.Deny("example.com", src("198.51.100.6"), time.Minute, "b") {
		t.Fatal("table should take a second entry")
	}
	if s.Deny("example.com", src("198.51.100.7"), time.Minute, "c") {
		t.Fatal("a full verdict table must refuse, not evict a live verdict")
	}
}

// One zone's flood of sources must not switch rate limiting off for another
// zone's clients: each zone has a quota of the node's table.
func TestZoneQuotaIsolatesZones(t *testing.T) {
	c := newClock()
	s := New(Options{Now: c.now, MaxSources: 4 * minZoneQuota})
	s.SetZones(doc(zone("a.example.com", 1, 0), zone("b.example.com", 1, 0)))
	// Zone a: fill its quota (half the node) and then some.
	for i := 0; i < 3*minZoneQuota; i++ {
		s.Decide("a.example.com", netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if v := s.Decide("a.example.com", src("192.0.2.1")); v.Reason != ReasonUntracked {
		t.Fatalf("zone a past its quota: %+v", v)
	}
	// Zone b still gets buckets — and is rate limited.
	ip := src("198.51.100.20")
	if v := s.Decide("b.example.com", ip); v.Reason != ReasonAllow {
		t.Fatalf("zone b first request: %+v", v)
	}
	if v := s.Decide("b.example.com", ip); v.Allow {
		t.Fatalf("zone b must still be rate limited: %+v", v)
	}
}

func TestHandlerContract(t *testing.T) {
	c := newClock()
	s := newService(t, c, zone("example.com", 1, 0))
	s.Mark("example.com", src("198.51.100.20"), "vip", time.Hour)
	s.Deny("example.com", src("198.51.100.21"), time.Hour, "flood")
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
	if rec := do("/decide", "example.com", "198.51.100.20"); rec.Code != 200 || rec.Header().Get(headerMark) != "vip" || rec.Header().Get(headerReason) != "" || rec.Body.Len() != 0 {
		t.Fatalf("allow+mark: %d %v body=%d", rec.Code, rec.Header(), rec.Body.Len())
	}
	if rec := do("/decide", "example.com", "198.51.100.20"); rec.Code != 403 || rec.Header().Get(headerReason) != ReasonRate || rec.Body.Len() != 0 {
		t.Fatalf("rate deny: %d %v body=%d", rec.Code, rec.Header(), rec.Body.Len())
	}
	if rec := do("/decide", "example.com", "198.51.100.21"); rec.Code != 403 || rec.Header().Get(headerReason) != "table:flood" {
		t.Fatalf("table deny: %d %v", rec.Code, rec.Header())
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
	// Dry-run carries the reason too, on a 200.
	s.SetDryRun(true)
	if rec := do("/decide", "example.com", "198.51.100.21"); rec.Code != 200 || rec.Header().Get(headerReason) != "table:flood" || rec.Header().Get(headerMark) != "would-deny:table:flood" {
		t.Fatalf("dry-run: %d %v", rec.Code, rec.Header())
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
	if st, err := os.Lstat(path); err != nil || st.Mode().Perm() != DefaultSocketMode {
		t.Fatalf("socket mode %v (%v), want %o", st.Mode(), err, DefaultSocketMode)
	}
	// A second server must not steal a live socket.
	second := &Server{Service: s, Path: path}
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	if err := second.ListenAndServe(sctx); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Fatalf("second server on a live socket: %v", err)
	}
	if _, err := net.Dial("unix", path); err != nil {
		t.Fatalf("the first server's socket was disturbed: %v", err)
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
	// A stale socket file (nobody listening) is replaced.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- (&Server{Service: s, Path: path}).ListenAndServe(ctx2) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", path); err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel2()
	if err := <-done2; err != nil {
		t.Fatalf("server over a stale file: %v", err)
	}
}
