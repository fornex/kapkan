package rollup

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A frame exactly as nginx sends it with `nohostname,tag=kapkan` and the
// renderer's log_format kapkan_edge.
const nginxFrame = `<190>Sep  2 12:39:47 kapkan: {"ts":"2026-09-02T12:39:47+00:00","zone":"example.com","src":"172.17.0.1","port":443,"method":"GET","host":"example.com","uri":"/probe?x=1","status":403,"bytes":153,"rt":0.001,"urt":"","ua":"Go-http-client/1.1","decision":"403"}`

func TestParseNginxFrame(t *testing.T) {
	r, err := Parse([]byte(nginxFrame + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Record{
		TS: time.Date(2026, 9, 2, 12, 39, 47, 0, time.UTC), Zone: "example.com", Src: netip.MustParseAddr("172.17.0.1"), Port: 443,
		Method: "GET", Host: "example.com", URI: "/probe?x=1", Status: 403, Bytes: 153, RT: 0.001, URT: "", UA: "Go-http-client/1.1", Decision: "403",
	}
	if !r.TS.Equal(want.TS) {
		t.Fatalf("TS = %v", r.TS)
	}
	r.TS = want.TS
	if r != want {
		t.Fatalf("Record = %+v\n  want %+v", r, want)
	}
	if !r.Decided() {
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

func TestParseRejects(t *testing.T) {
	json := nginxFrame[strings.IndexByte(nginxFrame, '{'):]
	cases := map[string]string{
		"no json":      `<190>Sep  2 12:39:47 kapkan: nothing here`,
		"bad json":     `{"ts":`,
		"bad zone":     strings.Replace(json, `"zone":"example.com"`, `"zone":"Example.com;"`, 1),
		"bad src":      strings.Replace(json, `"src":"172.17.0.1"`, `"src":"nope"`, 1),
		"bad ts":       strings.Replace(json, `"ts":"2026-09-02T12:39:47+00:00"`, `"ts":"yesterday"`, 1),
		"bad status":   strings.Replace(json, `"status":403`, `"status":7`, 1),
		"wrong types":  strings.Replace(json, `"status":403`, `"status":"403"`, 1),
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
	if err != nil || r.Decided() {
		t.Fatalf("undecided: %+v %v", r, err)
	}
}

func rec(zone, src string, status int, decision string) Record {
	return Record{TS: time.Now(), Zone: zone, Src: netip.MustParseAddr(src), Port: 443, Status: status, Decision: decision, Bytes: 100}
}

func TestAggregatorWindows(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var closed []WindowStats
	var records int
	a := &Aggregator{Window: 10 * time.Second, TopSources: 2, Now: func() time.Time { return now },
		OnWindow: func(w WindowStats) { closed = append(closed, w) }, OnRecord: func(Record) { records++ }}
	for i := 0; i < 30; i++ {
		a.Observe(rec("a.example.com", "198.51.100.1", 200, "200"))
	}
	for i := 0; i < 10; i++ {
		a.Observe(rec("a.example.com", "198.51.100.2", 403, "403"))
		a.Observe(rec("a.example.com", "198.51.100.3", 502, "502"))
	}
	a.Observe(rec("a.example.com", "198.51.100.4", 404, ""))
	a.Observe(rec("b.example.com", "198.51.100.1", 301, ""))
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
	if w.Requests != 51 || w.Denied != 10 || w.Undecided != 10 || w.Status2xx != 30 || w.Status4xx != 11 || w.Status5xx != 10 || w.Bytes != 5100 {
		t.Fatalf("zone a: %+v", w)
	}
	if w.Elapsed != 20*time.Second || w.RPS < 2.54 || w.RPS > 2.56 {
		t.Fatalf("rps must divide by the real elapsed: elapsed=%v rps=%v", w.Elapsed, w.RPS)
	}
	if w.SourcesTotal != 4 || len(w.Sources) != 2 || w.Sources[0].Src.String() != "198.51.100.1" || w.Sources[0].Requests != 30 {
		t.Fatalf("top sources: total=%d %+v", w.SourcesTotal, w.Sources)
	}
	if w.Sources[1].Src.String() != "198.51.100.2" || w.Sources[1].Denied != 10 || w.Sources[1].Errors4xx != 0 {
		t.Fatalf("the decider's 403s are denials, not errors: %+v", w.Sources[1])
	}
	if records != 52 {
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

func TestAggregatorCapsPairs(t *testing.T) {
	now := time.Now()
	var closed []WindowStats
	a := &Aggregator{Window: time.Second, MaxPairs: 3, Now: func() time.Time { return now }, OnWindow: func(w WindowStats) { closed = append(closed, w) }}
	for i := 0; i < 10; i++ {
		a.Observe(rec("a.example.com", fmt.Sprintf("198.51.100.%d", i), 200, "200"))
	}
	now = now.Add(2 * time.Second)
	a.Tick()
	if len(closed) != 1 || !closed[0].Overflow || closed[0].SourcesTotal != 3 || closed[0].Requests != 10 {
		t.Fatalf("capped window: %+v", closed)
	}
}

type fakeSink struct {
	denies []string
	marks  []string
	ttls   []time.Duration
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

func TestRulesFloodAndErrors(t *testing.T) {
	now := time.Now()
	r := &Rules{Now: func() time.Time { return now }}
	sink := &fakeSink{}
	w := WindowStats{Zone: "example.com", Sources: []SourceStats{
		{Src: netip.MustParseAddr("198.51.100.1"), Requests: 100, Denied: 80},                // flooding through denials
		{Src: netip.MustParseAddr("198.51.100.2"), Requests: 100, Denied: 19},                // under the floor
		{Src: netip.MustParseAddr("198.51.100.3"), Requests: 100, Denied: 20},                // 20%: a busy client, not a flood
		{Src: netip.MustParseAddr("198.51.100.4"), Requests: 60, Errors4xx: 55},              // a scanner: marked
		{Src: netip.MustParseAddr("198.51.100.5"), Requests: 10, Errors4xx: 10},              // too few to judge
		{Src: netip.MustParseAddr("198.51.100.6"), Requests: 100, Denied: 60, Errors4xx: 40}, // flood wins over errors
	}}
	got := r.Apply(w, sink)
	if got.Denied != 2 || got.Marked != 1 {
		t.Fatalf("Applied = %+v denies=%v marks=%v", got, sink.denies, sink.marks)
	}
	if strings.Join(sink.denies, ",") != "example.com/198.51.100.1/flood,example.com/198.51.100.6/flood" {
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
		r.Apply(WindowStats{Zone: "example.com", Sources: w.Sources[:1]}, sink)
		if sink.ttls[0] != want {
			t.Fatalf("repeat %d: ttl = %v, want %v", i+1, sink.ttls[0], want)
		}
	}
	now = now.Add(2 * time.Hour)
	sink.ttls = nil
	r.Apply(WindowStats{Zone: "example.com", Sources: w.Sources[:1]}, sink)
	if sink.ttls[0] != DefaultDenyTTL {
		t.Fatalf("after the memory expired: ttl = %v", sink.ttls[0])
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
			if r.Zone != "example.com" || r.Status != 403 {
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
