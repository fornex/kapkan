package rollup

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A frame exactly as nginx sends it with `nohostname,tag=kapkan` and the
// renderer's log_format kapkan_edge.
const nginxFrame = `<190>Sep  2 12:39:47 kapkan: {"ts":"2026-09-02T12:39:47+00:00","zone":"example.com","src":"172.17.0.1","port":443,"method":"GET","host":"example.com","uri":"/probe?x=1","status":429,"bytes":153,"rt":0.001,"urt":"","ua":"Go-http-client/1.1","decision":"403","reason":"rate","mark":""}`

func TestParseNginxFrame(t *testing.T) {
	r, err := Parse([]byte(nginxFrame + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Record{
		TS: time.Date(2026, 9, 2, 12, 39, 47, 0, time.UTC), Zone: "example.com", Src: netip.MustParseAddr("172.17.0.1"), Port: 443,
		Method: "GET", Host: "example.com", URI: "/probe?x=1", Status: 429, Bytes: 153, RT: 0.001, URT: "", UA: "Go-http-client/1.1", Decision: "403", Reason: "rate",
	}
	if !r.TS.Equal(want.TS) {
		t.Fatalf("TS = %v", r.TS)
	}
	r.TS = want.TS
	if r != want {
		t.Fatalf("Record = %+v\n  want %+v", r, want)
	}
	if !r.Decided() || r.Undecided() {
		t.Fatal("a 403 decision is a decided request")
	}
	// With a hostname in the header, and no header at all.
	for _, frame := range []string{
		`<190>Sep  2 12:39:47 edge-1 kapkan: ` + nginxFrame[strings.IndexByte(nginxFrame, '{'):],
		nginxFrame[strings.IndexByte(nginxFrame, '{'):],
	} {
		if _, err := Parse([]byte(frame)); err != nil {
			t.Errorf("%q: %v", frame[:30], err)
		}
	}
}

// nginx joins upstream variables across attempts: a pooled connection that
// died is retried, and the log then reads "502, 200". The answer is the last.
func TestParseReducesMultiAttemptValues(t *testing.T) {
	json := nginxFrame[strings.IndexByte(nginxFrame, '{'):]
	frame := strings.Replace(json, `"decision":"403"`, `"decision":"502, 403"`, 1)
	frame = strings.Replace(frame, `"reason":"rate"`, `"reason":", table:flood"`, 1)
	frame = strings.Replace(frame, `"urt":""`, `"urt":"0.000, 0.002"`, 1)
	r, err := Parse([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != "403" || !r.Decided() || r.Reason != "table:flood" || r.URT != "0.002" {
		t.Fatalf("Record = %+v", r)
	}
	if r, _ := Parse([]byte(strings.Replace(json, `"decision":"403"`, `"decision":"502, 200"`, 1))); r.Decision != "200" || !r.Decided() {
		t.Fatalf("retried allow: %+v", r)
	}
	dry := strings.Replace(json, `"mark":""`, `"mark":"would-deny:rate"`, 1)
	if r, _ := Parse([]byte(dry)); r.WouldDenyReason() != "rate" {
		t.Fatalf("would-deny mark: %+v", r)
	}
}

func TestParseRejects(t *testing.T) {
	json := nginxFrame[strings.IndexByte(nginxFrame, '{'):]
	cases := map[string]string{
		"no json":      `<190>Sep  2 12:39:47 kapkan: nothing here`,
		"bad json":     `{"ts":`,
		"bad zone":     strings.Replace(json, `"zone":"example.com"`, `"zone":"Example.com;"`, 1),
		"bad src":      strings.Replace(json, `"src":"172.17.0.1"`, `"src":"nope"`, 1),
		"bad ts":       strings.Replace(json, `"ts":"2026-09-02T12:39:47+00:00"`, `"ts":"yesterday"`, 1),
		"bad status":   strings.Replace(json, `"status":429`, `"status":7`, 1),
		"wrong types":  strings.Replace(json, `"status":429`, `"status":"429"`, 1),
		"empty":        ``,
		"garbage json": `{"zone": [1,2,3]}`,
	}
	for name, frame := range cases {
		if _, err := Parse([]byte(frame)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	undecided := strings.Replace(json, `"decision":"403"`, `"decision":"502"`, 1)
	r, err := Parse([]byte(undecided))
	if err != nil || r.Decided() || !r.Undecided() {
		t.Fatalf("undecided: %+v %v", r, err)
	}
}

type recOpt func(*Record)

func rec(zone, src string, status int, decision string, opts ...recOpt) Record {
	r := Record{TS: time.Now(), Zone: zone, Src: netip.MustParseAddr(src), Port: 443, Status: status, Decision: decision, Bytes: 100}
	if decision == "403" {
		r.Reason = "rate"
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func reason(s string) recOpt { return func(r *Record) { r.Reason = s } }
func mark(s string) recOpt   { return func(r *Record) { r.Mark = s } }
func port(p int) recOpt      { return func(r *Record) { r.Port = p } }

func TestAggregatorWindows(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var closed, full []WindowStats
	var records int
	a := &Aggregator{Window: 10 * time.Second, TopSources: 2, Now: func() time.Time { return now },
		OnWindow: func(w WindowStats) { closed = append(closed, w) }, OnWindowFull: func(w WindowStats) { full = append(full, w) },
		OnRecord: func(Record) { records++ }}
	for i := 0; i < 30; i++ {
		a.Observe(rec("a.example.com", "198.51.100.1", 200, "200"))
	}
	for i := 0; i < 10; i++ {
		a.Observe(rec("a.example.com", "198.51.100.2", 429, "403"))                        // over its ceiling
		a.Observe(rec("a.example.com", "198.51.100.3", 502, "502"))                        // undecided: no error of its own
		a.Observe(rec("a.example.com", "198.51.100.5", 403, "403", reason("table:flood"))) // the table at work
		a.Observe(rec("a.example.com", "198.51.100.6", 200, "200", mark("would-deny:rate")))
	}
	a.Observe(rec("a.example.com", "198.51.100.4", 404, ""))
	a.Observe(rec("a.example.com", "198.51.100.4", 301, "", port(80)))
	a.Observe(rec("b.example.com", "198.51.100.1", 301, "", port(80)))
	if len(closed) != 0 {
		t.Fatal("window closed early")
	}
	// The window closes on the first record (or tick) after it ran its
	// length; the elapsed time is the REAL one — 20 s here, not 10.
	now = now.Add(20 * time.Second)
	a.Tick()
	if len(closed) != 2 || closed[0].Zone != "a.example.com" || closed[1].Zone != "b.example.com" {
		t.Fatalf("closed = %+v", closed)
	}
	w := closed[0]
	if w.Requests != 72 || w.Decided != 60 || w.Denied != 20 || w.Undecided != 10 || w.Status2xx != 40 || w.Status3xx != 1 || w.Status4xx != 21 || w.Status5xx != 10 {
		t.Fatalf("zone a: %+v", w)
	}
	if w.Elapsed != 20*time.Second || w.RPS < 3.59 || w.RPS > 3.61 {
		t.Fatalf("rps must divide by the real elapsed: elapsed=%v rps=%v", w.Elapsed, w.RPS)
	}
	if w.SourcesTotal != 6 || len(w.Sources) != 2 || w.Sources[0].Src.String() != "198.51.100.1" || w.Sources[0].Requests != 30 {
		t.Fatalf("top sources: total=%d %+v", w.SourcesTotal, w.Sources)
	}
	if w.Sources[0].RPS < 1.49 || w.Sources[0].RPS > 1.51 {
		t.Fatalf("per-source rps must divide by the real elapsed: %v", w.Sources[0].RPS)
	}
	// The full window carries every source, with the denial split.
	if len(full) != 2 || len(full[0].Sources) != 6 {
		t.Fatalf("full window: %+v", full)
	}
	by := map[string]SourceStats{}
	for _, s := range full[0].Sources {
		by[s.Src.String()] = s
	}
	if s := by["198.51.100.2"]; s.Denied != 10 || s.DeniedRate != 10 || s.DeniedTable != 0 || s.Decided != 10 || s.Errors4xx != 0 {
		t.Fatalf("rate-denied source: %+v", s)
	}
	if s := by["198.51.100.5"]; s.Denied != 10 || s.DeniedTable != 10 || s.DeniedRate != 0 {
		t.Fatalf("table-denied source: %+v", s)
	}
	if s := by["198.51.100.3"]; s.Decided != 0 || s.Errors5xx != 0 || s.Requests != 10 {
		t.Fatalf("undecided source must not be charged with errors: %+v", s)
	}
	if s := by["198.51.100.6"]; s.WouldDenyRate != 10 || s.Decided != 10 || s.Denied != 0 {
		t.Fatalf("dry-run source: %+v", s)
	}
	if s := by["198.51.100.4"]; s.Requests != 2 || s.Decided != 0 || s.Errors4xx != 1 {
		t.Fatalf("non-deciding traffic: %+v", s)
	}
	if records != 73 {
		t.Fatalf("OnRecord saw %d records", records)
	}
	// A new window starts empty.
	now = now.Add(time.Second)
	a.Observe(rec("a.example.com", "198.51.100.9", 200, "200"))
	now = now.Add(10 * time.Second)
	a.Tick()
	if len(closed) != 3 || closed[2].Requests != 1 || closed[2].SourcesTotal != 1 {
		t.Fatalf("second window: %+v", closed[2:])
	}
	// Idle: a tick with nothing observed closes nothing.
	now = now.Add(time.Minute)
	a.Tick()
	if len(closed) != 3 {
		t.Fatal("idle tick produced a window")
	}
}

func TestAggregatorKeysSourcesBySlash64AndKnowsItsZones(t *testing.T) {
	now := time.Now()
	var closed []WindowStats
	var records int
	a := &Aggregator{Window: time.Second, Now: func() time.Time { return now },
		OnWindow: func(w WindowStats) { closed = append(closed, w) }, OnRecord: func(Record) { records++ }}
	a.SetZones([]string{"a.example.com"})
	a.Observe(rec("a.example.com", "2001:db8:1:2::1", 200, "200"))
	a.Observe(rec("a.example.com", "2001:db8:1:2:ffff::9", 200, "200"))
	a.Observe(rec("forged.example", "198.51.100.1", 200, "200"))
	now = now.Add(2 * time.Second)
	a.Tick()
	if len(closed) != 1 || closed[0].SourcesTotal != 1 || closed[0].Sources[0].Src.String() != "2001:db8:1:2::" || closed[0].Sources[0].Requests != 2 {
		t.Fatalf("window: %+v", closed)
	}
	if records != 2 {
		t.Fatalf("a record for an unknown zone reached OnRecord (%d records)", records)
	}
}

func TestAggregatorCapsPairsPerZone(t *testing.T) {
	now := time.Now()
	var closed []WindowStats
	a := &Aggregator{Window: time.Second, MaxPairs: 3, Now: func() time.Time { return now }, OnWindow: func(w WindowStats) { closed = append(closed, w) }}
	for i := 0; i < 10; i++ {
		a.Observe(rec("a.example.com", fmt.Sprintf("198.51.100.%d", i), 200, "200"))
	}
	// Another zone is not affected by the first one's flood of sources.
	a.Observe(rec("b.example.com", "198.51.100.200", 200, "200"))
	now = now.Add(2 * time.Second)
	a.Tick()
	if len(closed) != 2 || !closed[0].Overflow || closed[0].SourcesTotal != 3 || closed[0].Requests != 10 {
		t.Fatalf("capped window: %+v", closed)
	}
	if closed[1].Overflow || closed[1].SourcesTotal != 1 {
		t.Fatalf("other zone: %+v", closed[1])
	}
}

type fakeSink struct {
	denies     []string
	marks      []string
	challenges []string
	flips      []string
	ttls       []time.Duration
	denied     map[string]bool
	challenged map[string]bool
}

func (f *fakeSink) Deny(zone string, src netip.Addr, ttl time.Duration, reason string) bool {
	f.denies = append(f.denies, zone+"/"+src.String()+"/"+reason)
	f.ttls = append(f.ttls, ttl)
	return true
}

func (f *fakeSink) Mark(zone string, src netip.Addr, mark string, ttl time.Duration) bool {
	f.marks = append(f.marks, zone+"/"+src.String()+"/"+mark)
	return true
}

func (f *fakeSink) Denied(zone string, src netip.Addr) bool {
	return f.denied[zone+"/"+src.String()]
}

func (f *fakeSink) Challenge(zone string, src netip.Addr, ttl time.Duration, reason string) bool {
	f.challenges = append(f.challenges, zone+"/"+src.String()+"/"+reason+"/"+ttl.String())
	return true
}

func (f *fakeSink) Challenged(zone string, src netip.Addr) bool {
	return f.challenged[zone+"/"+src.String()]
}

func (f *fakeSink) SetZoneChallenge(zone string, on bool, until time.Time, reason string) bool {
	f.flips = append(f.flips, zone+"/"+reason+"/"+until.UTC().Format(time.RFC3339))
	return true
}

func TestRulesFloodAndErrors(t *testing.T) {
	now := time.Now()
	r := &Rules{Now: func() time.Time { return now }}
	sink := &fakeSink{denied: map[string]bool{"example.com/198.51.100.7": true}}
	w := WindowStats{Zone: "example.com", Requests: 1000, Status2xx: 800, Status4xx: 200, Denied: 150, Sources: []SourceStats{
		{Src: netip.MustParseAddr("198.51.100.1"), Requests: 100, Decided: 100, Denied: 80, DeniedRate: 80},                // flooding through denials
		{Src: netip.MustParseAddr("198.51.100.2"), Requests: 100, Decided: 100, Denied: 19, DeniedRate: 19},                // under the floor
		{Src: netip.MustParseAddr("198.51.100.3"), Requests: 100, Decided: 100, Denied: 20, DeniedRate: 20},                // 20%: a busy client, not a flood
		{Src: netip.MustParseAddr("198.51.100.4"), Requests: 60, Decided: 60, Errors4xx: 55},                               // a scanner: marked
		{Src: netip.MustParseAddr("198.51.100.5"), Requests: 10, Decided: 10, Errors4xx: 10},                               // too few to judge
		{Src: netip.MustParseAddr("198.51.100.6"), Requests: 100, Decided: 100, Denied: 60, DeniedRate: 60, Errors4xx: 40}, // flood wins over errors
		{Src: netip.MustParseAddr("198.51.100.7"), Requests: 100, Decided: 100, Denied: 100, DeniedTable: 100},             // already denied: skipped
		{Src: netip.MustParseAddr("198.51.100.8"), Requests: 100, Decided: 100, Denied: 30, DeniedTable: 30},               // table 403s are not flood evidence
		{Src: netip.MustParseAddr("198.51.100.9"), Requests: 60, Decided: 40, WouldDenyRate: 30},                           // dry-run: 30 of 40 decided
		{Src: netip.MustParseAddr("198.51.100.10"), Requests: 200, Decided: 60, Denied: 25, DeniedRate: 25},                // diluted by :80 hits, but 25/60 decided
	}}
	got := r.Apply(w, sink)
	if got.Denied != 4 || got.Marked != 1 || got.Skipped != 1 {
		t.Fatalf("Applied = %+v denies=%v marks=%v", got, sink.denies, sink.marks)
	}
	if strings.Join(sink.denies, ",") != "example.com/198.51.100.1/flood,example.com/198.51.100.6/flood,example.com/198.51.100.9/flood,example.com/198.51.100.10/flood" {
		t.Fatalf("denies = %v", sink.denies)
	}
	if strings.Join(sink.marks, ",") != "example.com/198.51.100.4/errors" {
		t.Fatalf("marks = %v", sink.marks)
	}
	if sink.ttls[0] != DefaultDenyTTL {
		t.Fatalf("first deny ttl = %v", sink.ttls[0])
	}
	// Escalation: the same source flooding again doubles, up to the cap; a
	// long quiet spell forgets it.
	for i, want := range []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute} {
		sink.ttls = nil
		r.Apply(WindowStats{Zone: "example.com", Requests: 100, Sources: w.Sources[:1]}, sink)
		if sink.ttls[0] != want {
			t.Fatalf("repeat %d: ttl = %v, want %v", i+1, sink.ttls[0], want)
		}
	}
	now = now.Add(2 * time.Hour)
	sink.ttls = nil
	r.Apply(WindowStats{Zone: "example.com", Requests: 100, Sources: w.Sources[:1]}, sink)
	if sink.ttls[0] != DefaultDenyTTL {
		t.Fatalf("after the memory expired: ttl = %v", sink.ttls[0])
	}
	// A zone that is erroring as a whole (origin down) marks nobody.
	sink.marks = nil
	r.Apply(WindowStats{Zone: "example.com", Requests: 100, Status5xx: 95, Sources: []SourceStats{{Src: netip.MustParseAddr("198.51.100.4"), Requests: 60, Decided: 60, Errors5xx: 58}}}, sink)
	if len(sink.marks) != 0 {
		t.Fatalf("marked during an origin outage: %v", sink.marks)
	}
	// A zone whose visitors are mostly being CHALLENGED (every challenge page
	// is a 403 or, before E4.3, a 503) is not an erroring origin: the scanner
	// among them is still marked.
	sink.marks = nil
	r.Apply(WindowStats{Zone: "example.com", Requests: 1000, Status4xx: 950, Challenged: 900, Sources: []SourceStats{{Src: netip.MustParseAddr("198.51.100.4"), Requests: 60, Decided: 60, Errors4xx: 58}}}, sink)
	if strings.Join(sink.marks, ",") != "example.com/198.51.100.4/errors" {
		t.Fatalf("challenged zone switched the errors rule off: marks = %v", sink.marks)
	}
}

func TestListenerReceivesDatagrams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.sock")
	got := make(chan Record, 16)
	l := &Listener{Path: path, Handle: func(r Record) { got <- r }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	var conn *net.UnixConn
	var err error
	for i := 0; i < 50; i++ {
		conn, err = net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(nginxFrame)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("<190>Sep  2 12:39:48 kapkan: not json")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(nginxFrame)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case r := <-got:
			if r.Zone != "example.com" || r.Status != 429 {
				t.Fatalf("record %d: %+v", i, r)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("record %d not received", i)
		}
	}
	select {
	case r := <-got:
		t.Fatalf("malformed datagram produced a record: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	// A second listener must not steal a live socket.
	second := &Listener{Path: path}
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	if err := second.Run(sctx); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Fatalf("second listener on a live socket: %v", err)
	}
	// An oversized datagram (Linux: darwin caps a unix datagram at 2 KiB) is
	// counted and dropped, not parsed.
	if runtime.GOOS == "linux" {
		big := []byte(nginxFrame[:strings.IndexByte(nginxFrame, '{')] + `{"ts":"2026-09-02T12:39:47+00:00","zone":"example.com","src":"172.17.0.1","uri":"/`)
		big = append(big, []byte(strings.Repeat("a", maxDatagram))...)
		big = append(big, []byte(`","status":200}`)...)
		if _, err := conn.Write(big); err != nil {
			t.Logf("oversized write refused by the kernel (%v); skipping that assertion", err)
		} else {
			select {
			case r := <-got:
				t.Fatalf("oversized datagram produced a record: %+v", r)
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not stop")
	}
}
