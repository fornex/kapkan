//go:build linux

package dataplane

// The IPv6 extension-header cap, pinned in both directions.
//
// WHAT IS BEING PINNED, and why it is worth a file of its own.
//
// kapkan_xdp.c walks at most KAPKAN_MAX_EXT_HDRS extension headers. A packet
// carrying more hits the cap, is counted as pass_exthdr_cap, and is FORWARDED —
// without the rule scan ever running. Not "the rules ran and none matched": the
// rules were never consulted. Allow-lists, static drops, dynamic mitigation
// rules and rate limits are all skipped together. For that packet, an attacker
// has turned the filter off with 64 bytes of padding.
//
// That verdict is correct and is not what these tests are here to change. The
// charter's default verdict is PASS, and a parser's budget must never become a
// default-deny — the same header chain arriving from a legitimate host would
// otherwise be blackholed by an implementation detail. The mitigation is
// VISIBILITY: Stat.BypassReason, kapkan_dataplane_filter_bypass_packets_total,
// the banner in the console and the block at the top of `kapkan dataplane
// status`.
//
// All of that visibility is calibrated on ONE NUMBER — dataplane.MaxIPv6ExtHdrs,
// which is quoted verbatim to operators in engine/deploy/dataplane-operations.md
// and in the console's own text. If somebody raises the cap to 12 for a verifier
// budget win, or the unroll silently changes where `i` lands, the documented
// threshold becomes a lie and the evasion window moves without a single test
// failing. Hence the assertion below is not "a big chain is passed" but exactly
// where the boundary is, measured against the compiled object, from both sides.
//
// The measurement matches the S2 review: 0–7 headers filtered, 8 and above
// bypassing.

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

// v6CapVictim is 2001:db8::2 — the destination ipv6() builds, so a rule on it
// matches every frame in this file.
var v6CapVictim = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

const (
	ipprotoHopOpts = 0  // hop-by-hop options
	ipprotoDstOpts = 60 // destination options
	ipprotoTCP     = 6
)

// v6ExtChain builds an IPv6 SYN to v6CapVictim behind n chained extension
// headers of type hdrType, each the minimum 8 bytes (hdrlen 0).
//
// n == 0 is a plain IPv6 SYN with no chain at all, which is the low end of the
// boundary sweep and the reason this exists next to smoke_linux_test.go's
// ipv6ExtChain rather than reusing it: that helper cannot express n == 0, and
// widening it would change the meaning of the tests that already call it.
func v6ExtChain(n int, hdrType uint8) []byte {
	first := uint8(ipprotoTCP)
	if n > 0 {
		first = hdrType
	}
	chain := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		next := hdrType
		if i == n-1 {
			next = ipprotoTCP
		}
		// hdrlen == 0 means "8 octets, nothing beyond the first unit", so each
		// header costs exactly 8 bytes and the padding arithmetic in the ops
		// document (8 headers = 64 bytes) is this literal.
		chain = append(chain, next, 0, 0, 0, 0, 0, 0, 0)
	}
	body := cat(chain, tcp(1024, 80, 0x02))
	return cat(eth(etherTypeIPv6), ipv6(first, len(body)), body)
}

// capTestObjs loads a fresh program with two static drop rules for the victim:
// one that needs the L4 header parsed (proto + port) and one that needs only the
// destination address.
//
// The second rule is what makes a PASS meaningful. With only the port rule, a
// passed packet would be ambiguous — the parser might simply have failed to
// reach the ports — and the test would prove nothing about the rule scan. A
// destination-only rule matches any IPv6 packet to the victim whatsoever, so if
// the packet is still passed, the scan did not run.
func capTestObjs(t *testing.T) *kapkanXDPObjects {
	t.Helper()
	objs := loadObjects(t)
	installStatics(t, objs, 0,
		mkRule(ruleOpts{
			id: 810, action: ActionDrop, dst6: &v6CapVictim, prefix6: 128, v6: true,
			proto: u8p(ipprotoTCP), dport: u16p(80),
		}),
		mkRule(ruleOpts{
			id: 811, action: ActionDrop, dst6: &v6CapVictim, prefix6: 128, v6: true,
		}),
	)
	setCfgFull(t, objs, cfgOpts{staticCount: 2})
	return objs
}

// TestIPv6ExtHdrCapBoundary is the drift gate on the evasion window.
//
// It sweeps the header count across the cap and asserts BOTH sides: every count
// below MaxIPv6ExtHdrs is filtered normally, and MaxIPv6ExtHdrs itself is the
// first count that bypasses. Asserting only the second half would let the cap
// silently fall to 4 — every documented "8 bypasses" claim still passing while
// the real window quadrupled.
func TestIPv6ExtHdrCapBoundary(t *testing.T) {
	// One below the cap must still be filtered, all the way down to no chain at
	// all. The rules are consulted, the L4 header is reached, the SYN is dropped.
	for n := 0; n < MaxIPv6ExtHdrs; n++ {
		t.Run(fmt.Sprintf("filtered/%d-headers", n), func(t *testing.T) {
			objs := capTestObjs(t)
			got := run(t, objs, v6ExtChain(n, ipprotoDstOpts))
			if got != xdpDrop {
				t.Fatalf("%d extension headers: verdict = %s, want XDP_DROP — the datapath stopped "+
					"filtering BELOW the documented cap of %d, so the evasion window is wider than "+
					"deploy/dataplane-operations.md says; counters:%s",
					n, verdictName(got), MaxIPv6ExtHdrs, dumpStats(t, objs))
			}
			if p, _ := readStat(t, objs, StatDropStatic); p != 1 {
				t.Errorf("%d extension headers: drop_static = %d, want 1; counters:%s",
					n, p, dumpStats(t, objs))
			}
			if p, _ := readStat(t, objs, StatPassExtHdrCap); p != 0 {
				t.Errorf("%d extension headers: pass_exthdr_cap = %d, want 0 — the cap fired below "+
					"the threshold this build documents", n, p)
			}
		})
	}

	// At the cap and above, the parser gives up and the packet is forwarded with
	// NO rule evaluated. The destination-only rule 811 would have matched any
	// IPv6 packet to this victim, so a PASS here is proof the scan never ran.
	for _, n := range []int{MaxIPv6ExtHdrs, MaxIPv6ExtHdrs + 1, MaxIPv6ExtHdrs + 4} {
		t.Run(fmt.Sprintf("bypassed/%d-headers", n), func(t *testing.T) {
			objs := capTestObjs(t)
			got := run(t, objs, v6ExtChain(n, ipprotoDstOpts))
			if got != xdpPass {
				t.Fatalf("%d extension headers: verdict = %s, want XDP_PASS — the charter's default "+
					"verdict is PASS and a parse limit must not become a default-deny; counters:%s",
					n, verdictName(got), dumpStats(t, objs))
			}
			if p, _ := readStat(t, objs, StatPassExtHdrCap); p != 1 {
				t.Errorf("%d extension headers: pass_exthdr_cap = %d, want 1 — the packet was passed "+
					"but NOT counted, which is the one outcome nothing downstream can detect; "+
					"counters:%s", n, p, dumpStats(t, objs))
			}
			// The whole point: a rule that matches everything to this victim did
			// not fire.
			if p, _ := readStat(t, objs, StatDropStatic); p != 0 {
				t.Errorf("%d extension headers: drop_static = %d, want 0", n, p)
			}
		})
	}

	// And the counter must be the one the alarm is wired to. If StatPassExtHdrCap
	// ever stops being a bypass reason, the metric, the console banner and the
	// CLI block all go silent while the datapath behaves identically.
	if _, ok := StatPassExtHdrCap.BypassReason(); !ok {
		t.Error("StatPassExtHdrCap.BypassReason() reports false: the counter that proves the filter " +
			"was bypassed is no longer classified as a bypass, so nothing alerts on it")
	}
}

// TestIPv6ExtHdrCapCostsSixtyFourBytes pins the figure the operations document
// quotes as the cost of the evasion: hop-by-hop padding, nothing else.
//
// It matters because it is the argument for treating any movement on this
// counter as hostile. If bypassing the filter took a megabyte of headers it
// would be self-limiting; it takes 64 bytes, which is cheaper than the TCP
// header it hides.
func TestIPv6ExtHdrCapCostsSixtyFourBytes(t *testing.T) {
	objs := capTestObjs(t)
	pkt := v6ExtChain(MaxIPv6ExtHdrs, ipprotoHopOpts)

	const wantPadding = MaxIPv6ExtHdrs * 8
	if got := len(pkt) - (14 + 40 + 20); got != wantPadding {
		t.Fatalf("the chain is %d bytes of padding, want %d — this test no longer measures what "+
			"the operations document claims", got, wantPadding)
	}
	if got := run(t, objs, pkt); got != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS; counters:%s", verdictName(got), dumpStats(t, objs))
	}
	p, b := readStat(t, objs, StatPassExtHdrCap)
	if p != 1 {
		t.Fatalf("pass_exthdr_cap = %d pkts, want 1; counters:%s", p, dumpStats(t, objs))
	}
	// Hop-by-hop is the cheapest chain to build and the one an attacker reaches
	// for; it must hit the same cap as destination options, or the documented
	// threshold only holds for the header type that happened to be tested.
	if b != uint64(len(pkt)) {
		t.Errorf("pass_exthdr_cap = %d bytes, want %d (the whole frame)", b, len(pkt))
	}
}

// TestInspectReportsTheBypass closes the loop between the datapath and the
// operator: a packet that skipped the rule scan has to arrive as an alarm in the
// read-only inspection that `kapkan dataplane status` renders and that a
// monitoring script parses as `.filter_bypass[]`.
//
// The boundary test above proves the kernel counts it. This proves somebody is
// told. The two halves can break independently — a counter classified out of
// BypassReason, a derivation that reads the wrong list — and either break is
// silent, because the datapath's behaviour does not change either way.
func TestInspectReportsTheBypass(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkxhc0")
	m := mustOpen(t, testOptions(t, dir, iface))

	// A clean data plane reports no alarm. Asserted BEFORE any traffic, because
	// "the field is populated" is worthless if it is populated unconditionally.
	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if ins.HasBypass() {
		t.Fatalf("a data plane that has seen no traffic reports a bypass: %+v", ins.Bypass)
	}

	const shots = 137
	prog := m.testProgram()
	for i := 0; i < shots; i++ {
		ret, err := prog.Run(&ebpf.RunOptions{Data: v6ExtChain(MaxIPv6ExtHdrs, ipprotoHopOpts)})
		if err != nil {
			t.Fatalf("PROG_TEST_RUN: %v", err)
		}
		if ret != xdpPass {
			t.Fatalf("verdict = %s, want XDP_PASS", verdictName(ret))
		}
	}

	ins, err = InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if !ins.HasBypass() {
		t.Fatalf("%d packets skipped the rule scan and the inspection reports no bypass; "+
			"terminal counters: %+v", shots, ins.Live.Terminal)
	}
	if len(ins.Bypass) != 1 {
		t.Fatalf("bypass signals = %+v, want exactly one", ins.Bypass)
	}
	b := ins.Bypass[0]
	if b.Reason != "ipv6_exthdr_cap" || b.Stat != "pass_exthdr_cap" || b.Pkts != shots {
		t.Errorf("signal = %+v, want reason ipv6_exthdr_cap, stat pass_exthdr_cap, %d pkts",
			b, shots)
	}
	if b.Message == "" {
		t.Error("the signal carries no message; the CLI and the -json document both print it")
	}
	// The alarm must not have quietly replaced the counter it came from: an
	// operator reconciling against an interface counter still needs the terminal
	// list to add up.
	var found bool
	for _, c := range ins.Live.Terminal {
		if c.Name == "pass_exthdr_cap" {
			found = true
			if c.Pkts != shots {
				t.Errorf("terminal pass_exthdr_cap = %d, want %d", c.Pkts, shots)
			}
		}
	}
	if !found {
		t.Error("pass_exthdr_cap left the terminal counter list when it became an alarm")
	}
	if ins.Live.TerminalTotal.Pkts != shots {
		t.Errorf("terminal total = %d, want %d — a bypassed packet is still a packet",
			ins.Live.TerminalTotal.Pkts, shots)
	}
}
