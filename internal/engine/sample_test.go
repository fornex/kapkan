package engine

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/geoip"
)

// fakeGeo is a static GeoIP resolver for tests: addresses absent from the map
// are reported as unplaced, mirroring a real database miss. hasASN mirrors
// whether an ASN database is loaded (false models a country-only deployment).
type fakeGeo struct {
	m      map[netip.Addr]geoip.Info
	hasASN bool
}

func (f fakeGeo) Lookup(a netip.Addr) (geoip.Info, bool) {
	i, ok := f.m[a]
	return i, ok
}

func (f fakeGeo) HasASN() bool { return f.hasASN }

// attackerFlow is a UDP flood record from a specific source/port pair.
func attackerFlow(src, dst string, srcPort uint16, rate uint64) flow.Flow {
	return flow.Flow{
		SrcAddr:      netip.MustParseAddr(src),
		DstAddr:      netip.MustParseAddr(dst),
		IPProto:      17,
		SrcPort:      srcPort,
		DstPort:      53,
		Bytes:        468,
		Packets:      1,
		SamplingRate: rate,
		Wire:         flow.ProtoSFlow5,
	}
}

// TestAttackSampleAggregation: the start event carries a sample whose top
// source, ports and protocol reflect the flood, sampling-corrected.
func TestAttackSampleAggregation(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := "203.0.113.20"

	// Dominant attacker: 150 records; background source: 50 records.
	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", dst, 123, 1000))
	}
	for i := 0; i < 50; i++ {
		e.Process(attackerFlow("198.51.100.8", dst, 40000, 1000))
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
	if ev.Kind != AttackStarted {
		t.Fatalf("event = %v, want AttackStarted", ev.Kind)
	}
	s := ev.Sample
	if s == nil {
		t.Fatal("AttackStarted.Sample = nil, want a sample")
	}

	if len(s.TopSources) < 2 || s.TopSources[0].Key != "198.51.100.7" {
		t.Fatalf("TopSources = %+v, want 198.51.100.7 first", s.TopSources)
	}
	// 150 records × 1 packet × sampling 1000.
	if s.TopSources[0].Packets != 150000 {
		t.Errorf("top source packets = %d, want 150000 (sampling-corrected)", s.TopSources[0].Packets)
	}
	if s.TopSrcPorts[0].Key != "123" {
		t.Errorf("top src port = %q, want 123", s.TopSrcPorts[0].Key)
	}
	if s.TopDstPorts[0].Key != "53" {
		t.Errorf("top dst port = %q, want 53", s.TopDstPorts[0].Key)
	}
	if len(s.Protocols) != 1 || s.Protocols[0].Key != "udp" {
		t.Errorf("protocols = %+v, want only udp", s.Protocols)
	}
	if len(s.Flows) == 0 || len(s.Flows) > 20 {
		t.Errorf("len(Flows) = %d, want 1..20 (flows_per_attack default)", len(s.Flows))
	}
	for _, f := range s.Flows {
		if f.Dst != dst {
			t.Errorf("sample flow dst = %q, want %q (only matching flows)", f.Dst, dst)
		}
	}
}

// TestAttackSampleASNEnrichment: with a GeoIP resolver attached, the sample
// carries a per-ASN breakdown that aggregates across distinct source IPs in
// the same AS, buckets unresolved sources under "unknown", and stamps each
// captured raw flow with its source ASN/country.
func TestAttackSampleASNEnrichment(t *testing.T) {
	a7 := netip.MustParseAddr("198.51.100.7")
	a8 := netip.MustParseAddr("198.51.100.8")
	// a7 and a8 share AS64500; a9 is deliberately absent (→ "unknown").
	geo := fakeGeo{hasASN: true, m: map[netip.Addr]geoip.Info{
		a7: {ASN: 64500, Org: "Evil Corp", Country: "RU"},
		a8: {ASN: 64500, Org: "Evil Corp", Country: "RU"},
	}}
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1), WithGeoIP(geo))
	events := drain(e)
	dst := "203.0.113.20"

	// Process the unknown source first and the dominant AS last so the newest
	// (captured) raw flows belong to a resolved source.
	for i := 0; i < 30; i++ {
		e.Process(attackerFlow("198.51.100.9", dst, 4444, 1000))
	}
	for i := 0; i < 50; i++ {
		e.Process(attackerFlow("198.51.100.8", dst, 222, 1000))
	}
	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", dst, 123, 1000))
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
	s := ev.Sample
	if s == nil {
		t.Fatal("AttackStarted.Sample = nil, want a sample")
	}

	if len(s.TopASNs) < 2 {
		t.Fatalf("TopASNs = %+v, want at least the AS64500 and unknown buckets", s.TopASNs)
	}
	// AS64500 aggregates a7 (150k) + a8 (50k) = 200k, ahead of unknown (30k).
	if s.TopASNs[0].Key != "AS64500 Evil Corp" {
		t.Errorf("TopASNs[0].Key = %q, want \"AS64500 Evil Corp\"", s.TopASNs[0].Key)
	}
	if s.TopASNs[0].Packets != 200000 {
		t.Errorf("TopASNs[0].Packets = %d, want 200000 (a7+a8, sampling-corrected)", s.TopASNs[0].Packets)
	}
	var unknown *Counter
	for i := range s.TopASNs {
		if s.TopASNs[i].Key == "unknown" {
			unknown = &s.TopASNs[i]
		}
	}
	if unknown == nil {
		t.Fatalf("TopASNs has no \"unknown\" bucket: %+v", s.TopASNs)
	}
	if unknown.Packets != 30000 {
		t.Errorf("unknown bucket packets = %d, want 30000 (a9)", unknown.Packets)
	}

	// Captured raw flows are newest-first → all from a7 (AS64500, RU).
	if len(s.Flows) == 0 {
		t.Fatal("no raw flows captured")
	}
	for _, f := range s.Flows {
		if f.Src != "198.51.100.7" {
			t.Fatalf("captured flow src = %q, want the newest source 198.51.100.7", f.Src)
		}
		if f.SrcASN != 64500 || f.SrcOrg != "Evil Corp" || f.SrcCountry != "RU" {
			t.Errorf("flow geo = {ASN:%d Org:%q Country:%q}, want 64500/Evil Corp/RU", f.SrcASN, f.SrcOrg, f.SrcCountry)
		}
	}
}

// TestSampleNoASNWithoutResolver: without a resolver the sample carries no ASN
// breakdown and raw flows carry no geo, so the feature is fully opt-in.
func TestSampleNoASNWithoutResolver(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.20", 123, 1000))
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Sample == nil {
			t.Fatal("sample missing")
		}
		if ev.Sample.TopASNs != nil {
			t.Errorf("TopASNs = %+v, want nil without a resolver", ev.Sample.TopASNs)
		}
		for _, f := range ev.Sample.Flows {
			if f.SrcASN != 0 || f.SrcOrg != "" || f.SrcCountry != "" {
				t.Errorf("flow carries geo without a resolver: %+v", f)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
}

// TestCountryOnlyNoASNBreakdown: a country-only GeoIP deployment (no ASN
// database) enriches per-flow source country but emits no per-ASN breakdown,
// rather than a degenerate all-"unknown" one.
func TestCountryOnlyNoASNBreakdown(t *testing.T) {
	a7 := netip.MustParseAddr("198.51.100.7")
	geo := fakeGeo{hasASN: false, m: map[netip.Addr]geoip.Info{
		a7: {Country: "RU"}, // country known, ASN unknown (no ASN DB)
	}}
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1), WithGeoIP(geo))
	events := drain(e)

	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.20", 123, 1000))
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Sample == nil {
			t.Fatal("sample missing")
		}
		if ev.Sample.TopASNs != nil {
			t.Errorf("TopASNs = %+v, want nil in a country-only deployment", ev.Sample.TopASNs)
		}
		if len(ev.Sample.Flows) == 0 {
			t.Fatal("no raw flows captured")
		}
		for _, f := range ev.Sample.Flows {
			if f.SrcCountry != "RU" {
				t.Errorf("flow SrcCountry = %q, want RU (country enrichment works without ASN)", f.SrcCountry)
			}
			if f.SrcASN != 0 {
				t.Errorf("flow SrcASN = %d, want 0 (no ASN DB)", f.SrcASN)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
}

// TestSampleMatchesOnlyTarget: flows to other hosts in the same shard window
// never leak into a target's sample.
func TestSampleMatchesOnlyTarget(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Flood the target and also send distinctive traffic to another host.
	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.20", 123, 1000))
	}
	for i := 0; i < 10; i++ {
		e.Process(attackerFlow("198.51.100.99", "203.0.113.21", 9999, 1))
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
	if ev.Sample == nil {
		t.Fatal("sample missing")
	}
	for _, c := range ev.Sample.TopSources {
		if c.Key == "198.51.100.99" {
			t.Error("sample includes a source that only hit a different host")
		}
	}
	for _, f := range ev.Sample.Flows {
		if f.Dst != "203.0.113.20" {
			t.Errorf("sample flow for wrong destination: %+v", f)
		}
	}
}

// TestOutgoingSampleUsesVictims: for outgoing attacks the sample's "sources"
// are the victims the compromised host is targeting.
func TestOutgoingSampleUsesVictims(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	src := "203.0.113.77"

	for i := 0; i < 60; i++ {
		f := outboundFlow(src, 1000)
		e.Process(f)
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
	if ev.Direction != DirOutgoing {
		t.Fatalf("direction = %q, want outgoing", ev.Direction)
	}
	if ev.Sample == nil {
		t.Fatal("outgoing attack sample missing")
	}
	if ev.Sample.TopSources[0].Key != "198.51.100.9" {
		t.Errorf("top 'source' = %q, want the victim 198.51.100.9", ev.Sample.TopSources[0].Key)
	}
	for _, f := range ev.Sample.Flows {
		if f.Src != src {
			t.Errorf("outgoing sample flow src = %q, want %q", f.Src, src)
		}
	}
}

// TestGroupSampleSpansMembers: a total group's sample aggregates flows to
// all member hosts (which live in different shards).
func TestGroupSampleSpansMembers(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Three pool members at 60000 pps each (sum 180000 > 150000).
	members := []string{"203.0.113.33", "203.0.113.34", "203.0.113.35"}
	for _, m := range members {
		for i := 0; i < 60; i++ {
			e.Process(attackerFlow("198.51.100.7", m, 123, 1000))
		}
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no group AttackStarted")
	}
	if ev.Scope != ScopeGroup {
		t.Fatalf("scope = %q, want group", ev.Scope)
	}
	if ev.Sample == nil {
		t.Fatal("group attack sample missing")
	}
	// All flood flows share one source; its packets must cover all members:
	// 3 hosts × 60 records × 1000 = 180000.
	if ev.Sample.TopSources[0].Packets != 180000 {
		t.Errorf("group sample top source packets = %d, want 180000 (all members)",
			ev.Sample.TopSources[0].Packets)
	}
	dsts := map[string]bool{}
	for _, f := range ev.Sample.Flows {
		dsts[f.Dst] = true
	}
	if len(dsts) < 2 {
		t.Errorf("group sample flows cover %d member hosts, want >= 2: %v", len(dsts), dsts)
	}
}

// TestSamplingDisabled: samples.enabled=false leaves events without samples
// and shards without rings.
func TestSamplingDisabled(t *testing.T) {
	yaml := strings.Replace(baseYAML, "thresholds:", "samples:\n  enabled: false\nthresholds:", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	for i := 0; i < 200; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.20", 123, 1000))
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Sample != nil {
			t.Errorf("Sample = %+v, want nil with sampling disabled", ev.Sample)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
	for _, sh := range e.shards {
		if sh.ring != nil {
			t.Fatal("shard ring allocated despite samples.enabled=false")
		}
	}
}

// TestRingWrapKeepsNewest: when the ring wraps, the sample reflects the most
// recent flows, not stale ones.
func TestRingWrapKeepsNewest(t *testing.T) {
	// 256 buffer slots = 1 per shard: every push overwrites the previous.
	yaml := strings.Replace(baseYAML, "thresholds:", "samples:\n  buffer_flows: 256\nthresholds:", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	dst := netip.MustParseAddr("203.0.113.20")

	// Older flow from source A, then newer from source B — same host, same
	// shard slot.
	e.Process(attackerFlow("198.51.100.1", dst.String(), 111, 1000))
	e.Process(attackerFlow("198.51.100.2", dst.String(), 222, 1000))

	sh := e.shardFor(dst)
	sh.mu.Lock()
	s := e.collectHostSample(sh, dst, dirIn, clk.Now().Unix()-e.windowSec)
	sh.mu.Unlock()
	if s == nil {
		t.Fatal("sample = nil")
	}
	if len(s.Flows) != 1 || s.Flows[0].Src != "198.51.100.2" {
		t.Errorf("wrapped ring sample = %+v, want only the newest flow (198.51.100.2)", s.Flows)
	}
}

// TestDirectionFilterIsLoadBearing: internal traffic X→Y is recorded twice
// (incoming for Y, outgoing for X). Without the direction filter the
// outgoing copy double-counts in group samples; with it, each flow counts
// once. Kills the mutation that drops the `se.dir != d` checks.
func TestDirectionFilterIsLoadBearing(t *testing.T) {
	// pool group is calculation:total over 203.0.113.32/28; enable outgoing
	// so internal flows are recorded in both directions.
	yaml := strings.Replace(groupsYAML, "thresholds:",
		"thresholds_outgoing:\n  pps: 1000000\nthresholds:", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Internal pool-member-to-pool-member traffic: X=.33 → Y=.34, distinct
	// source signature. Recorded as dirIn (for .34) AND dirOut (for .33);
	// both entries have a pool member as each monitored endpoint.
	for i := 0; i < 30; i++ {
		e.Process(attackerFlow("203.0.113.33", "203.0.113.34", 7777, 1000))
	}
	// External flood pushing the pool total over its 150000 pps threshold.
	for i := 0; i < 130; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.35", 123, 1000))
	}
	runTick(e, clk)

	var ev Event
	for {
		select {
		case ev = <-events:
		case <-time.After(time.Second):
			t.Fatal("no group AttackStarted")
		}
		if ev.Scope == ScopeGroup && ev.Direction == DirIncoming {
			break
		}
	}
	if ev.Sample == nil {
		t.Fatal("group sample missing")
	}
	for _, c := range ev.Sample.TopSources {
		if c.Key == "203.0.113.33" && c.Packets != 30000 {
			// 30 records × 1000; the dirOut copy must NOT double it to 60000.
			t.Errorf("internal source packets = %d, want 30000 (each flow counted once)", c.Packets)
		}
	}
}

// TestHostSampleIgnoresOtherDirectionInSameShard: when two hosts X and Y
// hash to the same shard and X→Y internal traffic is recorded in both
// directions into that one ring, Y's incoming sample must not include the
// outgoing copy. Kills the dir-check mutation in collectHostSample.
func TestHostSampleIgnoresOtherDirectionInSameShard(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))

	// Find two distinct in-network hosts sharing a shard.
	base := netip.MustParseAddr("203.0.113.34")
	var partner netip.Addr
	for i := 35; i < 254; i++ {
		a := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		if e.shardFor(a) == e.shardFor(base) {
			partner = a
			break
		}
	}
	if !partner.IsValid() {
		t.Skip("no same-shard partner found in /24")
	}

	// partner → base internal traffic, recorded both directions, one ring.
	for i := 0; i < 10; i++ {
		e.Process(attackerFlow(partner.String(), base.String(), 7777, 1000))
	}
	sh := e.shardFor(base)
	sh.mu.Lock()
	s := e.collectHostSample(sh, base, dirIn, clk.Now().Unix()-e.windowSec)
	sh.mu.Unlock()
	if s == nil {
		t.Fatal("sample = nil")
	}
	// 10 records × 1000 packets, counted exactly once despite the dirOut
	// twin entries in the same ring.
	if s.TopSources[0].Packets != 10000 {
		t.Errorf("packets = %d, want 10000 (dirOut entries must not match)", s.TopSources[0].Packets)
	}
}

// TestStaleRingEntriesExcluded: flows older than the window never leak into
// a sample even though they are still in the ring. Kills the mutation that
// drops the epoch < sinceEpoch exclusion in scanRing.
func TestStaleRingEntriesExcluded(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := "203.0.113.20"

	// Old, distinctive traffic: in the ring but outside the 1s window once
	// the clock advances.
	for i := 0; i < 10; i++ {
		e.Process(attackerFlow("198.51.100.99", dst, 9999, 1000))
	}
	clk.Advance(5 * time.Second)

	// Fresh flood triggers the attack.
	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", dst, 123, 1000))
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
	if ev.Sample == nil {
		t.Fatal("sample missing")
	}
	for _, c := range ev.Sample.TopSources {
		if c.Key == "198.51.100.99" {
			t.Error("stale (out-of-window) source leaked into the sample")
		}
	}
	for _, f := range ev.Sample.Flows {
		if f.Src == "198.51.100.99" {
			t.Error("stale flow record leaked into the sample")
		}
	}
}

// TestFlowsPerAttackHonored: the configured cap is read from config and
// enforced exactly. Kills the mutation hardcoding sampleFlows.
func TestFlowsPerAttackHonored(t *testing.T) {
	yaml := strings.Replace(baseYAML, "thresholds:",
		"samples:\n  flows_per_attack: 5\nthresholds:", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	for i := 0; i < 150; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.20", 123, 1000))
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Sample == nil {
			t.Fatal("sample missing")
		}
		if len(ev.Sample.Flows) != 5 {
			t.Errorf("len(Flows) = %d, want exactly the configured 5", len(ev.Sample.Flows))
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
}

// TestGroupSampleDominantMemberKeepsMinoritiesVisible: with one member
// dominating the match counts, minority members still get raw-flow slots
// and the global cap holds exactly. Kills the quota-floor mutation.
func TestGroupSampleDominantMemberKeepsMinoritiesVisible(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Dominant member .33 (160 matches), minorities .34/.35 (12 each).
	// Sum 184000 pps > pool's 150000 threshold.
	for i := 0; i < 160; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.33", 123, 1000))
	}
	for i := 0; i < 12; i++ {
		e.Process(attackerFlow("198.51.100.7", "203.0.113.34", 123, 1000))
		e.Process(attackerFlow("198.51.100.7", "203.0.113.35", 123, 1000))
	}
	runTick(e, clk)

	var ev Event
	select {
	case ev = <-events:
	case <-time.After(time.Second):
		t.Fatal("no group AttackStarted")
	}
	if ev.Sample == nil {
		t.Fatal("group sample missing")
	}
	if len(ev.Sample.Flows) != 20 {
		t.Errorf("len(Flows) = %d, want exactly the 20 cap (no under-fill, no overshoot)", len(ev.Sample.Flows))
	}
	dsts := map[string]int{}
	for _, f := range ev.Sample.Flows {
		dsts[f.Dst]++
	}
	for _, m := range []string{"203.0.113.33", "203.0.113.34", "203.0.113.35"} {
		if dsts[m] == 0 {
			t.Errorf("member %s missing from raw flows: %v", m, dsts)
		}
	}
	if dsts["203.0.113.33"] <= dsts["203.0.113.34"] {
		t.Errorf("dominant member should hold the largest share: %v", dsts)
	}
}

// TestIPv6AttackSample: samples work for IPv6 targets end to end.
func TestIPv6AttackSample(t *testing.T) {
	yaml := strings.Replace(baseYAML, `  - "203.0.113.0/24"`,
		`  - "203.0.113.0/24"`+"\n"+`  - "2001:db8::/32"`, 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := "2001:db8::42"

	for i := 0; i < 150; i++ {
		f := attackerFlow("198.51.100.7", "203.0.113.20", 123, 1000)
		f.SrcAddr = netip.MustParseAddr("2001:db8:ffff::1")
		f.DstAddr = netip.MustParseAddr(dst)
		e.Process(f)
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Target != netip.MustParseAddr(dst) {
			t.Fatalf("target = %v, want %s", ev.Target, dst)
		}
		if ev.Sample == nil {
			t.Fatal("IPv6 attack sample missing")
		}
		if ev.Sample.TopSources[0].Key != "2001:db8:ffff::1" {
			t.Errorf("top source = %q, want the v6 attacker", ev.Sample.TopSources[0].Key)
		}
		if ev.Sample.Flows[0].Dst != dst {
			t.Errorf("sample flow dst = %q, want %s", ev.Sample.Flows[0].Dst, dst)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted for the IPv6 target")
	}
}
