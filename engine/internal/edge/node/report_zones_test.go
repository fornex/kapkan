package node

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// TestNodeReportsRollups pins the report's zones section (E4.5): every
// decide-mode zone of the LIVE generation appears (with zeros before its first
// window), a closed window fills its figures and busiest sources with what
// the node did to each, a zone-wide flip and the zone's watch-only state
// travel, and a mode:none zone does not.
func TestNodeReportsRollups(t *testing.T) {
	brain := &fakeBrain{}
	doc := testDoc(10)
	doc.Zones[0].Policy.Challenge = edgedoc.ChallengeAuto
	doc.Zones[0].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false}
	doc.Zones = append(doc.Zones,
		edgedoc.Zone{Name: "quiet.example", Origins: []string{"10.0.0.2:8080"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
			Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, DryRun: true}},
		edgedoc.Zone{Name: "passthrough.example", Origins: []string{"10.0.0.3:8080"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
			Policy: edgedoc.Policy{Mode: edgedoc.ModeNone, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}},
	)
	brain.set(doc, `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.DryRun = false
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })

	// Before any window: both decide zones, zeros, the watched one flagged,
	// each with its challenge mode.
	rep := n.report()
	if len(rep.Zones) != 2 || rep.Zones[0].Zone != "example.com" || rep.Zones[1].Zone != "quiet.example" {
		t.Fatalf("zones before a window: %+v", rep.Zones)
	}
	if rep.Zones[0].DryRun || !rep.Zones[1].DryRun || rep.Zones[0].Requests != 0 || rep.Zones[0].TopSources != nil {
		t.Fatalf("zone flags before a window: %+v", rep.Zones)
	}
	if rep.Zones[0].Challenge != edgedoc.ChallengeAuto || rep.Zones[1].Challenge != edgedoc.ChallengeOff {
		t.Fatalf("zone modes: %q %q", rep.Zones[0].Challenge, rep.Zones[1].Challenge)
	}

	// A closed window arrives through the aggregator's OnWindow, as the log
	// reader's Tick would deliver it — a RECENT one (the report reads a
	// window older than two aggregator windows as a quiet zone).
	start := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	w := rollup.WindowStats{
		Zone: "example.com", Start: start, Elapsed: 10 * time.Second, Requests: 300, Decided: 290, Denied: 40, Challenged: 20, Cleared: 5,
		WouldDeny: 3, WouldChallenge: 7, Status2xx: 230, Status4xx: 60, RPS: 30,
		Sources: []rollup.SourceStats{
			{Src: netip.MustParseAddr("203.0.113.1"), Requests: 100, Decided: 100, Denied: 40, DeniedTable: 40, RPS: 10},
			{Src: netip.MustParseAddr("203.0.113.2"), Requests: 80, Decided: 80, Challenged: 20, RPS: 8},
			{Src: netip.MustParseAddr("203.0.113.3"), Requests: 50, Decided: 50, WouldDeny: 3, WouldDenyRate: 3, RPS: 5},
			{Src: netip.MustParseAddr("203.0.113.4"), Requests: 40, Decided: 40, WouldChallenge: 7, RPS: 4},
			{Src: netip.MustParseAddr("203.0.113.5"), Requests: 20, Decided: 20, Cleared: 5, RPS: 2},
			{Src: netip.MustParseAddr("203.0.113.6"), Requests: 6, Decided: 6, Marked: 6, RPS: .6},
			{Src: netip.MustParseAddr("203.0.113.7"), Requests: 4, Decided: 4, Denied: 2, DeniedRate: 2, RPS: .4},
		},
	}
	n.agg.OnWindow(w)
	if !n.svc.SetZoneChallenge("example.com", true, start.Add(time.Hour), "zone-rps") {
		t.Fatal("flip refused")
	}
	rep = n.report()
	z := rep.Zones[0]
	if !z.At.Equal(start.Add(10*time.Second)) || z.WindowSeconds != 10 || z.RPS != 30 || z.Requests != 300 || z.Decided != 290 || z.Denied != 40 ||
		z.Challenged != 20 || z.Cleared != 5 || z.WouldDeny != 3 || z.WouldChallenge != 7 || z.Status2xx != 230 || z.Status4xx != 60 {
		t.Fatalf("zone figures: %+v", z)
	}
	// The flip bites here: the rung is enforced (challenge_options.dry_run
	// false) on an enforcing node.
	if z.ChallengeActive == nil || z.ChallengeActive.Reason != "zone-rps" || !z.ChallengeActive.Until.Equal(start.Add(time.Hour)) || z.ChallengeActive.DryRun {
		t.Fatalf("challenge active: %+v", z.ChallengeActive)
	}
	states := make([]string, 0, len(z.TopSources))
	for _, s := range z.TopSources {
		states = append(states, s.Source+"="+s.State)
	}
	want := "203.0.113.1=denied,203.0.113.2=challenged,203.0.113.3=would-deny,203.0.113.4=would-challenge,203.0.113.5=cleared,203.0.113.6=marked,203.0.113.7=allow"
	if strings.Join(states, ",") != want {
		t.Fatalf("source states:\n got %s\nwant %s", strings.Join(states, ","), want)
	}
	if rep.Zones[1].Requests != 0 || rep.Zones[1].ChallengeActive != nil {
		t.Fatalf("the quiet zone: %+v", rep.Zones[1])
	}
	// The wire shape: the report the brain receives carries the section.
	raw, _ := json.Marshal(rep)
	for _, want := range []string{`"zones":[{"zone":"example.com"`, `"challenge_active":{"reason":"zone-rps"`, `"top_sources":[{"source":"203.0.113.1"`, `"state":"denied"`, `"zone":"quiet.example","dry_run":true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report JSON lacks %s:\n%s", want, raw)
		}
	}
	if strings.Contains(string(raw), "passthrough.example") {
		t.Error("a mode:none zone is in the report")
	}
	// A zone that went quiet: its last window is older than two aggregator
	// windows, so the report shows a quiet zone — zeros, no sources, no At —
	// not a stopped flood as current.
	old := w
	old.Zone = "quiet.example"
	old.Start = time.Now().Add(-5 * time.Minute)
	n.agg.OnWindow(old)
	rep = n.report()
	if q := rep.Zones[1]; q.Requests != 0 || q.RPS != 0 || q.TopSources != nil || !q.At.IsZero() {
		t.Fatalf("a stale window was reported as current: %+v", q)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// TestNodeReportDryRunFloor pins the node's half of the zone's watch-only
// flag: on a dry-run node every zone reports dry_run, and a flip on it
// reports as a preview, whatever the zone's own flags say.
func TestNodeReportDryRunFloor(t *testing.T) {
	brain := &fakeBrain{}
	doc := testDoc(10)
	doc.Zones[0].Policy.Challenge = edgedoc.ChallengeAuto
	doc.Zones[0].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false}
	brain.set(doc, `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{}) // baseOptions: DryRun true
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	if !n.svc.SetZoneChallenge("example.com", true, time.Now().Add(time.Minute), "zone-rps") {
		t.Fatal("flip refused")
	}
	rep := n.report()
	if len(rep.Zones) != 1 || !rep.Zones[0].DryRun || rep.Zones[0].ChallengeActive == nil || !rep.Zones[0].ChallengeActive.DryRun {
		t.Fatalf("a dry-run node's zone: %+v", rep.Zones)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// TestSourceStatePrecedence pins the order of the strongest-thing rule when a
// source did several things in one window.
func TestSourceStatePrecedence(t *testing.T) {
	for _, tc := range []struct {
		s    rollup.SourceStats
		want string
	}{
		{rollup.SourceStats{DeniedTable: 1, Challenged: 5, WouldDeny: 2, Cleared: 3, Marked: 1}, api.SourceStateDenied},
		{rollup.SourceStats{Challenged: 3, Cleared: 2, Marked: 1, WouldChallenge: 4}, api.SourceStateChallenged},
		{rollup.SourceStats{WouldDeny: 1, WouldChallenge: 4, Cleared: 1}, api.SourceStateWouldDeny},
		{rollup.SourceStats{WouldChallenge: 1, Cleared: 9, Marked: 9}, api.SourceStateWouldChallenge},
		{rollup.SourceStats{Cleared: 1, Marked: 9, DeniedRate: 50}, api.SourceStateCleared},
		{rollup.SourceStats{Marked: 1, DeniedRate: 50}, api.SourceStateMarked},
		{rollup.SourceStats{Requests: 100, DeniedRate: 50}, api.SourceStateAllow},
	} {
		if got := sourceState(tc.s); got != tc.want {
			t.Errorf("sourceState(%+v) = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// TestTrimReportOrder pins what goes first when the report is too big: the
// sources that tell nothing, then every zone's list halved (busiest first
// kept) until it fits, then certificates from the tail, then zones from the
// tail — each counted.
func TestTrimReportOrder(t *testing.T) {
	// Every zone carries `sources` entries, alternating would-challenge (a
	// telling state) and allow, busiest first.
	big := func(zones, sources, certs int) api.EdgeReport {
		var rep api.EdgeReport
		for i := 0; i < zones; i++ {
			z := api.EdgeReportZone{Zone: "zone-" + strings.Repeat("x", 40) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Requests: 1}
			for j := 0; j < sources; j++ {
				state := api.SourceStateWouldChallenge
				if j%2 == 1 {
					state = api.SourceStateAllow
				}
				z.TopSources = append(z.TopSources, api.EdgeReportSource{Source: "2001:db8:" + strings.Repeat("f", 4) + ":" + string(rune('a'+j%26)) + "::", Requests: uint64(1000 - j), State: state})
			}
			rep.Zones = append(rep.Zones, z)
		}
		for i := 0; i < certs; i++ {
			rep.Certs = append(rep.Certs, api.EdgeReportCert{Zone: "cert-" + strings.Repeat("y", 60) + string(rune('a'+i%26)), NotAfter: time.Unix(0, 0), Issuer: "pebble"})
		}
		return rep
	}
	size := func(rep api.EdgeReport) int { b, _ := json.Marshal(rep); return len(b) }

	// Small: untouched.
	if rep := trimReport(big(3, 20, 10)); len(rep.Zones[0].TopSources) != 20 || rep.Zones[0].SourcesTruncated != 0 || rep.CertsTruncated != 0 || rep.ZonesTruncated != 0 {
		t.Fatalf("a small report was trimmed: %+v", rep)
	}
	// A little over: the sources that tell nothing go first, and that is
	// enough — every telling source survives, counted what went.
	rep := trimReport(big(45, 20, 10))
	if size(rep) > maxReportBytes || len(rep.Zones) != 45 || len(rep.Zones[0].TopSources) != 10 || rep.Zones[0].SourcesTruncated != 10 || rep.CertsTruncated != 0 || rep.ZonesTruncated != 0 {
		t.Fatalf("a little over: size=%d sources=%d shed=%d trunc=%d/%d", size(rep), len(rep.Zones[0].TopSources), rep.Zones[0].SourcesTruncated, rep.CertsTruncated, rep.ZonesTruncated)
	}
	for _, s := range rep.Zones[0].TopSources {
		if s.State != api.SourceStateWouldChallenge {
			t.Fatalf("a telling source went before an allowed one: %+v", rep.Zones[0].TopSources)
		}
	}
	// Well over: the lists are halved, busiest first kept, until it fits —
	// the zones and certs stay whole, and every zone keeps its busiest.
	rep = trimReport(big(200, 20, 50))
	if size(rep) > maxReportBytes || len(rep.Zones) != 200 || len(rep.Certs) != 50 || rep.CertsTruncated != 0 || rep.ZonesTruncated != 0 {
		t.Fatalf("halving: size=%d zones=%d certs=%d trunc=%d/%d", size(rep), len(rep.Zones), len(rep.Certs), rep.CertsTruncated, rep.ZonesTruncated)
	}
	if z := rep.Zones[0]; len(z.TopSources) == 0 || len(z.TopSources) >= 10 || z.TopSources[0].Requests != 1000 || z.SourcesTruncated+len(z.TopSources) != 20 {
		t.Fatalf("halving kept %d of 20 (shed %d), busiest %d", len(z.TopSources), z.SourcesTruncated, z.TopSources[0].Requests)
	}
	// Certificates next: the tail goes, the zones stay whole.
	rep = trimReport(big(100, 0, 3000))
	if size(rep) > maxReportBytes || len(rep.Zones) != 100 || rep.CertsTruncated == 0 || len(rep.Certs)+rep.CertsTruncated != 3000 || rep.ZonesTruncated != 0 {
		t.Fatalf("certs next: size=%d zones=%d certs=%d trunc=%d/%d", size(rep), len(rep.Zones), len(rep.Certs), rep.CertsTruncated, rep.ZonesTruncated)
	}
	// Zones last, only when nothing else is left to drop.
	rep = trimReport(big(2000, 0, 0))
	if size(rep) > maxReportBytes || rep.ZonesTruncated == 0 || len(rep.Zones)+rep.ZonesTruncated != 2000 || rep.Zones[0].Zone == "" {
		t.Fatalf("zones last: size=%d zones=%d trunc=%d", size(rep), len(rep.Zones), rep.ZonesTruncated)
	}
}
