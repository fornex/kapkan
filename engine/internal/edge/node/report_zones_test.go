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

	// Before any window: both decide zones, zeros, the watched one flagged.
	rep := n.report()
	if len(rep.Zones) != 2 || rep.Zones[0].Zone != "example.com" || rep.Zones[1].Zone != "quiet.example" {
		t.Fatalf("zones before a window: %+v", rep.Zones)
	}
	if rep.Zones[0].DryRun || !rep.Zones[1].DryRun || rep.Zones[0].Requests != 0 || rep.Zones[0].TopSources != nil {
		t.Fatalf("zone flags before a window: %+v", rep.Zones)
	}

	// A closed window arrives through the aggregator's OnWindow, as the log
	// reader's Tick would deliver it.
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
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
	if z.ChallengeActive == nil || z.ChallengeActive.Reason != "zone-rps" || !z.ChallengeActive.Until.Equal(start.Add(time.Hour)) {
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
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// TestTrimReportOrder pins what goes first when the report is too big: every
// zone's per-source detail, then certificates from the tail, then zones from
// the tail — each counted.
func TestTrimReportOrder(t *testing.T) {
	big := func(zones, sources, certs int) api.EdgeReport {
		var rep api.EdgeReport
		for i := 0; i < zones; i++ {
			z := api.EdgeReportZone{Zone: "zone-" + strings.Repeat("x", 40) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Requests: 1}
			for j := 0; j < sources; j++ {
				z.TopSources = append(z.TopSources, api.EdgeReportSource{Source: "2001:db8:" + strings.Repeat("f", 4) + ":" + string(rune('a'+j%26)) + "::", Requests: 1, State: api.SourceStateAllow})
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
	if rep := trimReport(big(3, 20, 10)); len(rep.Zones[0].TopSources) != 20 || rep.CertsTruncated != 0 || rep.ZonesTruncated != 0 {
		t.Fatalf("a small report was trimmed: %+v", rep)
	}
	// Sources alone put it over: they go, the zones and certs stay whole.
	rep := trimReport(big(200, 20, 50))
	if size(rep) > maxReportBytes || len(rep.Zones) != 200 || rep.Zones[0].TopSources != nil || len(rep.Certs) != 50 || rep.CertsTruncated != 0 || rep.ZonesTruncated != 0 {
		t.Fatalf("sources first: size=%d zones=%d certs=%d trunc=%d/%d", size(rep), len(rep.Zones), len(rep.Certs), rep.CertsTruncated, rep.ZonesTruncated)
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
