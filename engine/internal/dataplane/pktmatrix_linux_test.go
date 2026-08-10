//go:build linux

package dataplane

// The packet-path matrix: real frames from pkg/pktgen, through the real
// program, on a real kernel, with the maps filled by the same helpers the
// manager will use.
//
// TWO RULES THIS FILE FOLLOWS, both learned the hard way in this codebase:
//
//  1. Every case asserts the VERDICT and the exact set of COUNTERS that moved.
//     A verdict-only assertion cannot tell "passed because no rule matched"
//     from "passed because the allowlist caught it", and those two failures
//     look identical to an operator right up until the moment one of them is
//     dropping a customer's traffic. dpCase.expect compares the whole counter
//     delta as a set, so an unexpected counter is a failure too.
//
//  2. Frames come from pkg/pktgen, never from a byte literal. Hand-rolled
//     bytes drift from what a NIC actually delivers — a wrong IHL or a wrong
//     total length turns a test that claims to exercise IPv4 options into one
//     that exercises the malformed path and still passes.
//
// Run with `make dataplane-test`; see engine/bpf/README.md.

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

/* ------------------------------------------------------------- addresses */

var (
	// The victim under attack, and the /24 it belongs to. The /24 is the
	// "carpet" shape: a mitigation that covers a whole customer prefix rather
	// than a single host, which is what an operator actually installs when the
	// attack is spread across a subnet.
	dpVictim    = netip.MustParseAddr("203.0.113.9")
	dpVictim2   = netip.MustParseAddr("203.0.113.200") // same carpet, different host
	dpVictimNet = netip.MustParsePrefix("203.0.113.0/24")
	dpOffNet    = netip.MustParseAddr("203.0.114.9") // outside the carpet

	dpAttacker    = netip.MustParseAddr("198.51.100.7")
	dpAttackerNet = netip.MustParsePrefix("198.51.100.0/24")
	dpBystander   = netip.MustParseAddr("198.51.101.7") // outside the attacker /24

	dpVictim6    = netip.MustParseAddr("2001:db8:1::9")
	dpVictim6Net = netip.MustParsePrefix("2001:db8:1::/64")
	dpAttacker6  = netip.MustParseAddr("2001:db8:bad::7")

	dpVictimMAC = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dpRouterMAC = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// host32 is the /32 (or /128) prefix for one address, which is how a rule
// names a single endpoint.
func host32(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

/* ---------------------------------------------------------------- frames */

// baseFrame is the L2 skeleton every case starts from.
func baseFrame(src, dst netip.Addr) pktgen.Frame {
	return pktgen.Frame{
		SrcMAC: dpRouterMAC, DstMAC: dpVictimMAC,
		SrcIP: src, DstIP: dst, TTL: 64,
	}
}

// synFrame is the workhorse: a bare TCP SYN, the shape of a SYN flood.
func synFrame(src, dst netip.Addr) pktgen.Frame {
	return tcpFrame(src, dst, 1024, 80, pktgen.TCPSyn)
}

func tcpFrame(src, dst netip.Addr, sport, dport uint16, flags uint8) pktgen.Frame {
	f := baseFrame(src, dst)
	f.Proto = pktgen.ProtoTCP
	f.SrcPort, f.DstPort, f.TCPFlags = sport, dport, flags
	return f
}

func udpFrame(src, dst netip.Addr, sport, dport uint16) pktgen.Frame {
	f := baseFrame(src, dst)
	f.Proto = pktgen.ProtoUDP
	f.SrcPort, f.DstPort = sport, dport
	f.Payload = make([]byte, 16)
	return f
}

func icmpFrame(src, dst netip.Addr) pktgen.Frame {
	f := baseFrame(src, dst)
	if dst.Is6() {
		f.Proto, f.ICMPType = pktgen.ProtoICMPv6, 128
	} else {
		f.Proto, f.ICMPType = pktgen.ProtoICMP, 8
	}
	f.Payload = make([]byte, 32)
	return f
}

// tailFragment is a non-first IPv4 fragment: no L4 header at all, so a rule
// naming a port cannot match it and one naming only the fragment bit can.
func tailFragment(src, dst netip.Addr) pktgen.Frame {
	f := baseFrame(src, dst)
	f.Proto = pktgen.ProtoUDP
	f.IPID = 0x4321
	f.FragOffset = 185 // 1480/8, the second fragment of a full-MTU datagram
	f.Payload = make([]byte, 64)
	return f
}

// headFragment is the FIRST fragment: it still carries the L4 header, so it is
// both fragmented and port-matchable.
func headFragment(src, dst netip.Addr) pktgen.Frame {
	f := udpFrame(src, dst, 5000, 53413)
	f.IPID = 0x4321
	f.MoreFragments = true
	return f
}

func mustFrame(t *testing.T, f pktgen.Frame) []byte {
	t.Helper()
	b, err := f.Build()
	if err != nil {
		t.Fatalf("pktgen build: %v", err)
	}
	return b
}

/* -------------------------------------------------------------- fixture */

// dpCase is one loaded program plus the map helpers a case needs. Loading is
// the expensive part (the verifier runs), so a case loads once and drives many
// packets through it.
type dpCase struct {
	t    *testing.T
	objs *Objects
	m    *Maps
}

func newCase(t *testing.T) *dpCase {
	t.Helper()
	objs := loadObjects(t)
	c := &dpCase{t: t, objs: objs, m: objs.MapSet()}
	if err := PutConfig(c.m, ConfigSpec{}); err != nil {
		t.Fatalf("initial config: %v", err)
	}
	return c
}

// as rebinds the fixture to a subtest's *testing.T so failures are reported
// against the case that caused them. The loaded program is shared: loading
// costs a verifier run, and a subtest that only fires a packet does not need
// its own.
func (c *dpCase) as(t *testing.T) *dpCase {
	return &dpCase{t: t, objs: c.objs, m: c.m}
}

// setFlags flips dry_run / drop_malformed without disturbing the generation or
// the static count, so it can be called before or after the rules go in.
func (c *dpCase) setFlags(dryRun, dropMalformed bool) {
	c.t.Helper()
	cfg, err := ReadConfig(c.m)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := PutConfig(c.m, ConfigSpec{
		Generation:    cfg.Generation,
		StaticCount:   cfg.StaticCount,
		DryRun:        dryRun,
		DropMalformed: dropMalformed,
	}); err != nil {
		c.t.Fatal(err)
	}
}

// statics installs the operator rule set (precedence 3) and publishes it.
func (c *dpCase) statics(specs ...RuleSpec) {
	c.t.Helper()
	rules, err := EncodeRules(specs...)
	if err != nil {
		c.t.Fatalf("encode statics: %v", err)
	}
	gen, err := InactiveGeneration(c.m)
	if err != nil {
		c.t.Fatal(err)
	}
	n, err := PutStatics(c.m, gen, rules)
	if err != nil {
		c.t.Fatalf("install statics: %v", err)
	}
	if err := Activate(c.m, gen, n); err != nil {
		c.t.Fatalf("activate: %v", err)
	}
}

// policy points a prefix at a policy block in the live generation. The
// datapath consults the same trie on the source axis (precedence 4) and the
// destination axis (precedence 5), so the anchor decides which one finds it.
func (c *dpCase) policy(anchor netip.Prefix, id uint32, specs ...RuleSpec) {
	c.t.Helper()
	rules, err := EncodeRules(specs...)
	if err != nil {
		c.t.Fatalf("encode policy: %v", err)
	}
	cfg, err := ReadConfig(c.m)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := PutPolicy(c.m, cfg.Generation, id, rules); err != nil {
		c.t.Fatalf("put policy: %v", err)
	}
	if err := AddVictim(c.m, anchor, id); err != nil {
		c.t.Fatalf("add victim: %v", err)
	}
}

func (c *dpCase) allow(p netip.Prefix) {
	c.t.Helper()
	if err := AddAllowSource(c.m, p); err != nil {
		c.t.Fatal(err)
	}
}

func (c *dpCase) protect(p netip.Prefix) {
	c.t.Helper()
	if err := AddProtectedDestination(c.m, p); err != nil {
		c.t.Fatal(err)
	}
}

func (c *dpCase) profile(id uint32, s ProfileSpec) {
	c.t.Helper()
	if err := PutProfile(c.m, id, s); err != nil {
		c.t.Fatal(err)
	}
}

func (c *dpCase) snapshot() [StatMax]Counter {
	c.t.Helper()
	s, err := ReadStats(c.m)
	if err != nil {
		c.t.Fatal(err)
	}
	return s
}

// sendRaw drives one frame and returns the verdict plus every counter that
// moved. The delta is the assertion surface: absolute values would make each
// case depend on how many packets ran before it.
func (c *dpCase) sendRaw(pkt []byte) (uint32, map[Stat]Counter) {
	c.t.Helper()
	before := c.snapshot()
	ret, err := c.objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		c.t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	after := c.snapshot()

	delta := make(map[Stat]Counter)
	for s := Stat(0); s < StatMax; s++ {
		d := Counter{
			Pkts:  after[s].Pkts - before[s].Pkts,
			Bytes: after[s].Bytes - before[s].Bytes,
		}
		if d.Pkts != 0 || d.Bytes != 0 {
			delta[s] = d
		}
	}
	return ret, delta
}

func (c *dpCase) send(f pktgen.Frame) (uint32, map[Stat]Counter) {
	c.t.Helper()
	return c.sendRaw(mustFrame(c.t, f))
}

// fire drives a frame and returns only the verdict, skipping the two full
// counter snapshots. The bulk tests push thousands of packets and read the
// counters once at the end; snapshotting each one would dominate their runtime.
func (c *dpCase) fire(f pktgen.Frame) uint32 {
	c.t.Helper()
	ret, err := c.objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: mustFrame(c.t, f)})
	if err != nil {
		c.t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	return ret
}

// expect drives one frame and asserts the verdict and the EXACT set of
// counters that moved — each by one packet and by the frame's length.
//
// Listing every expected counter rather than just the interesting one is
// deliberate: several branches legitimately co-occur (a fragment bumps an
// observation counter on the way to whatever decides it), and pinning the
// whole set is what stops a future edit from quietly adding or losing one.
func (c *dpCase) expect(f pktgen.Frame, wantVerdict uint32, stats ...Stat) {
	c.t.Helper()
	c.expectRaw(mustFrame(c.t, f), wantVerdict, stats...)
}

func (c *dpCase) expectRaw(pkt []byte, wantVerdict uint32, stats ...Stat) {
	c.t.Helper()
	got, delta := c.sendRaw(pkt)
	if got != wantVerdict {
		c.t.Errorf("verdict = %s, want %s; counters moved:%s",
			verdictName(got), verdictName(wantVerdict), renderDelta(delta))
	}
	want := make(map[Stat]bool, len(stats))
	for _, s := range stats {
		want[s] = true
	}
	for s, d := range delta {
		if !want[s] {
			c.t.Errorf("counter %s moved by %d, but was not expected to move; all:%s",
				s, d.Pkts, renderDelta(delta))
			continue
		}
		if d.Pkts != 1 {
			c.t.Errorf("counter %s moved by %d packets, want 1", s, d.Pkts)
		}
		if d.Bytes != uint64(len(pkt)) {
			c.t.Errorf("counter %s moved by %d bytes, want %d (the frame length)",
				s, d.Bytes, len(pkt))
		}
	}
	for s := range want {
		if _, ok := delta[s]; !ok {
			c.t.Errorf("counter %s did not move; all that did:%s", s, renderDelta(delta))
		}
	}
}

func renderDelta(delta map[Stat]Counter) string {
	if len(delta) == 0 {
		return " (nothing)"
	}
	out := ""
	for s := Stat(0); s < StatMax; s++ {
		if d, ok := delta[s]; ok {
			out += " " + s.String() + "=" + itoa(d.Pkts)
		}
	}
	return out
}

/* =================================================== 1. the precedence ladder */

// dpLevel is a precedence step, numbered as in the packet-path precedence
// block at the top of kapkan_xdp.c.
type dpLevel int

const (
	lvlAllowSrc   dpLevel = 1 // src allowlist        -> PASS
	lvlProtectDst dpLevel = 2 // dst protected list   -> PASS
	lvlStatic     dpLevel = 3 // static rules
	lvlDynSrc     dpLevel = 4 // dynamic src rules
	lvlDynDst     dpLevel = 5 // dynamic dst rules
	lvlDefault    dpLevel = 6 // fall through         -> PASS
)

// installFrom installs every precedence level at or below `from`, each one set
// up so it WOULD claim the same packet: a SYN from dpAttacker to dpVictim.
// Whichever level actually claims it is the one the program ranks highest.
func installFrom(c *dpCase, from dpLevel) {
	if from <= lvlAllowSrc {
		c.allow(host32(dpAttacker))
	}
	if from <= lvlProtectDst {
		c.protect(host32(dpVictim))
	}
	if from <= lvlStatic {
		c.statics(RuleSpec{ID: 300, Action: ActionDrop, Dst: host32(dpVictim)})
	}
	if from <= lvlDynSrc {
		c.policy(host32(dpAttacker), 4,
			RuleSpec{ID: 400, Action: ActionDrop, Src: host32(dpAttacker), ExpiresAt: farFuture})
	}
	if from <= lvlDynDst {
		c.policy(host32(dpVictim), 5,
			RuleSpec{ID: 500, Action: ActionDrop, Dst: host32(dpVictim), ExpiresAt: farFuture})
	}
}

// TestPrecedenceLadder walks the six levels in order. Each case installs every
// level from N downwards, all of them matching the same packet, and asserts
// that level N is the one that decides it.
//
// The first two rows are the guarantees that matter most:
//
//   - an allowlisted SOURCE beats a matching drop rule, so a scrubber cannot be
//     talked into blackholing its own BGP peers or its monitoring;
//   - a protected DESTINATION beats one too. That is a different axis, and it
//     lives in the kernel rather than in the userspace sweep because a
//     rehydrated or racing rule would otherwise blackhole a protected customer
//     for up to a second.
func TestPrecedenceLadder(t *testing.T) {
	cases := []struct {
		name    string
		from    dpLevel
		verdict uint32
		stat    Stat
	}{
		{"1 src allowlist outranks every rule below it", lvlAllowSrc, xdpPass, StatPassAllowSrc},
		{"2 protected dst outranks every rule below it", lvlProtectDst, xdpPass, StatPassProtectDst},
		{"3 static rules outrank dynamic ones", lvlStatic, xdpDrop, StatDropStatic},
		{"4 dynamic src rules outrank dynamic dst rules", lvlDynSrc, xdpDrop, StatDropDynSrc},
		{"5 dynamic dst rules", lvlDynDst, xdpDrop, StatDropDynDst},
		{"6 default is always pass", lvlDefault, xdpPass, StatPassDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCase(t)
			installFrom(c, tc.from)
			c.expect(synFrame(dpAttacker, dpVictim), tc.verdict, tc.stat)
		})
	}
}

// TestAllowlistAndProtectedAreDifferentAxes: the two lists are not
// interchangeable, and collapsing them would be a silent, expensive mistake.
// The allowlist names SOURCES; the protected list names DESTINATIONS.
func TestAllowlistAndProtectedAreDifferentAxes(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *dpCase)
	}{
		{"the victim on the SOURCE allowlist does not save it", func(c *dpCase) {
			c.allow(host32(dpVictim))
		}},
		{"the attacker on the DESTINATION protected list does not save it", func(c *dpCase) {
			c.protect(host32(dpAttacker))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCase(t)
			c.statics(RuleSpec{ID: 301, Action: ActionDrop, Dst: host32(dpVictim)})
			tc.setup(c)
			c.expect(synFrame(dpAttacker, dpVictim), xdpDrop, StatDropStatic)
		})
	}
}

/* ============================================== 2. every field of the rule IR */

// dpShot is one frame fired at a rule, with the verdict and the exact counter
// set it must produce.
type dpShot struct {
	name    string
	frame   pktgen.Frame
	verdict uint32
	stats   []Stat
}

func hit(name string, f pktgen.Frame, extra ...Stat) dpShot {
	return dpShot{name: name, frame: f, verdict: xdpDrop, stats: append([]Stat{StatDropStatic}, extra...)}
}

func miss(name string, f pktgen.Frame, extra ...Stat) dpShot {
	return dpShot{name: name, frame: f, verdict: xdpPass, stats: append([]Stat{StatPassDefault}, extra...)}
}

// TestMatchFields drives one rule per case and fires both the traffic it must
// catch and the traffic it must spare. The sparing half is the half that
// matters: a rule that over-matches is an outage for whoever else was on that
// prefix.
//
// Every field of mitigate.FlowSpecRule appears here, because the promise is
// that a rule handed to a FlowSpec peer and the same rule handed to this data
// plane select the same packets.
func TestMatchFields(t *testing.T) {
	udp := uint8(pktgen.ProtoUDP)
	port53 := uint16(53)
	port80 := uint16(80)

	cases := []struct {
		name  string
		rule  RuleSpec
		shots []dpShot
	}{
		{
			name: "proto",
			rule: RuleSpec{ID: 310, Action: ActionDrop, Dst: host32(dpVictim), Proto: &udp},
			shots: []dpShot{
				hit("udp", udpFrame(dpAttacker, dpVictim, 1234, 53413)),
				miss("tcp", synFrame(dpAttacker, dpVictim)),
				miss("icmp", icmpFrame(dpAttacker, dpVictim)),
			},
		},
		{
			name: "src_port — the reflection shape",
			rule: RuleSpec{ID: 311, Action: ActionDrop, Dst: host32(dpVictim), Proto: &udp, SrcPort: &port53},
			shots: []dpShot{
				hit("from port 53", udpFrame(dpAttacker, dpVictim, 53, 40000)),
				miss("from an ephemeral port", udpFrame(dpAttacker, dpVictim, 40000, 53)),
			},
		},
		{
			name: "dst_port",
			rule: RuleSpec{ID: 312, Action: ActionDrop, Dst: host32(dpVictim), DstPort: &port80},
			shots: []dpShot{
				hit("to port 80", synFrame(dpAttacker, dpVictim)),
				miss("to port 443", tcpFrame(dpAttacker, dpVictim, 1024, 443, pktgen.TCPSyn)),
				miss("icmp has no ports at all", icmpFrame(dpAttacker, dpVictim)),
				// A non-first fragment carries no L4 header, so a rule naming a
				// port must not reach it — and it still bumps the fragment
				// observation counter on its way past.
				miss("a non-first fragment has no ports", tailFragment(dpAttacker, dpVictim),
					StatPassFragNoPorts),
			},
		},
		{
			name: "tcp_flags — RFC 8955 bitmask, which is why SYN catches SYN-ACK",
			rule: RuleSpec{ID: 313, Action: ActionDrop, Dst: host32(dpVictim)}.
				MatchTCPFlags(pktgen.TCPSyn),
			shots: []dpShot{
				hit("pure SYN", synFrame(dpAttacker, dpVictim)),
				hit("SYN-ACK", tcpFrame(dpAttacker, dpVictim, 1024, 80, pktgen.TCPSyn|pktgen.TCPAck)),
				miss("pure ACK", tcpFrame(dpAttacker, dpVictim, 1024, 80, pktgen.TCPAck)),
				miss("FIN", tcpFrame(dpAttacker, dpVictim, 1024, 80, pktgen.TCPFin)),
				miss("udp is not tcp", udpFrame(dpAttacker, dpVictim, 1, 2)),
			},
		},
		{
			name: "tcp_flags exact — the thing FlowSpec's bitmask cannot say",
			rule: RuleSpec{ID: 314, Action: ActionDrop, Dst: host32(dpVictim)}.
				MatchTCPFlagsExact(pktgen.TCPSyn),
			shots: []dpShot{
				hit("pure SYN", synFrame(dpAttacker, dpVictim)),
				miss("SYN-ACK is not an exact SYN",
					tcpFrame(dpAttacker, dpVictim, 1024, 80, pktgen.TCPSyn|pktgen.TCPAck)),
			},
		},
		{
			name: "fragment — matchable, never automatic",
			rule: RuleSpec{ID: 315, Action: ActionDrop, Dst: host32(dpVictim), Fragment: true},
			shots: []dpShot{
				hit("a non-first fragment", tailFragment(dpAttacker, dpVictim), StatPassFragNoPorts),
				hit("a first fragment is fragmented too", headFragment(dpAttacker, dpVictim)),
				miss("a whole datagram is spared", synFrame(dpAttacker, dpVictim)),
			},
		},
		{
			name: "src prefix anchoring",
			rule: RuleSpec{ID: 316, Action: ActionDrop, Src: dpAttackerNet, Dst: host32(dpVictim)},
			shots: []dpShot{
				hit("inside the attacker /24", synFrame(dpAttacker, dpVictim)),
				miss("outside it", synFrame(dpBystander, dpVictim)),
			},
		},
		{
			name: "carpet dst prefix, not just a /32",
			rule: RuleSpec{ID: 317, Action: ActionDrop, Dst: dpVictimNet},
			shots: []dpShot{
				hit("one host in the carpet", synFrame(dpAttacker, dpVictim)),
				hit("another host in the same carpet", synFrame(dpAttacker, dpVictim2)),
				miss("the neighbouring /24", synFrame(dpAttacker, dpOffNet)),
			},
		},
		{
			name: "ipv6 /128",
			rule: RuleSpec{ID: 318, Action: ActionDrop, Dst: host32(dpVictim6), IPv6: true},
			shots: []dpShot{
				hit("the named host", synFrame(dpAttacker6, dpVictim6)),
				miss("its neighbour", synFrame(dpAttacker6, netip.MustParseAddr("2001:db8:1::a"))),
			},
		},
		{
			name: "ipv6 /64 carpet — the awkward mask edge",
			rule: RuleSpec{ID: 319, Action: ActionDrop, Dst: dpVictim6Net, IPv6: true},
			shots: []dpShot{
				hit("inside the /64", synFrame(dpAttacker6, dpVictim6)),
				hit("elsewhere in the /64", synFrame(dpAttacker6, netip.MustParseAddr("2001:db8:1::ffff"))),
				miss("the neighbouring /64", synFrame(dpAttacker6, netip.MustParseAddr("2001:db8:2::9"))),
			},
		},
		{
			name: "a v4 rule never reaches v6 traffic",
			// The families are deliberately not normalised: see the
			// IPv4-mapped-IPv6 note at the top of kapkan_xdp.c. Normalising
			// would let an operator's v4 drop rule silently start dropping v6.
			rule: RuleSpec{ID: 320, Action: ActionDrop, Dst: dpVictimNet},
			shots: []dpShot{
				hit("v4", synFrame(dpAttacker, dpVictim)),
				miss("v6", synFrame(dpAttacker6, dpVictim6)),
			},
		},
		{
			name: "a v6 rule never reaches v4 traffic",
			rule: RuleSpec{ID: 321, Action: ActionDrop, Dst: dpVictim6Net, IPv6: true},
			shots: []dpShot{
				hit("v6", synFrame(dpAttacker6, dpVictim6)),
				miss("v4", synFrame(dpAttacker, dpVictim)),
			},
		},
		{
			name: "an all-any rule matches its whole family and nothing else",
			rule: RuleSpec{ID: 322, Action: ActionDrop},
			shots: []dpShot{
				hit("any v4 tcp", synFrame(dpAttacker, dpVictim)),
				hit("any v4 udp", udpFrame(dpBystander, dpOffNet, 1, 2)),
				miss("v6 is a different family", synFrame(dpAttacker6, dpVictim6)),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCase(t)
			c.statics(tc.rule)
			for _, s := range tc.shots {
				t.Run(s.name, func(t *testing.T) {
					c.as(t).expect(s.frame, s.verdict, s.stats...)
				})
			}
		})
	}
}

// TestSameRuleThroughAPolicyBlock proves precedence 5 uses the same matcher as
// precedence 3: an identical rule delivered as a per-victim dynamic rule
// selects exactly the same packets. If the two ever diverge, a rule would mean
// one thing in the config file and another when the detector installs it.
func TestSameRuleThroughAPolicyBlock(t *testing.T) {
	port80 := uint16(80)
	rule := RuleSpec{
		ID: 520, Action: ActionDrop, Dst: dpVictimNet, DstPort: &port80,
		ExpiresAt: farFuture,
	}.MatchTCPFlags(pktgen.TCPSyn)

	c := newCase(t)
	c.policy(dpVictimNet, 7, rule)

	c.expect(synFrame(dpAttacker, dpVictim), xdpDrop, StatDropDynDst)
	c.expect(synFrame(dpAttacker, dpVictim2), xdpDrop, StatDropDynDst)
	c.expect(tcpFrame(dpAttacker, dpVictim, 1024, 443, pktgen.TCPSyn), xdpPass, StatPassDefault)
	c.expect(synFrame(dpAttacker, dpOffNet), xdpPass, StatPassDefault)
}

// TestCarpetVictimPrefixInTheTrie covers the LPM lookup itself rather than the
// rule match: the victim trie is keyed by prefix, so one policy block can serve
// a whole customer /24 (or /64) instead of one entry per host. Without this,
// mitigating a spread-out attack would need one trie entry per address.
func TestCarpetVictimPrefixInTheTrie(t *testing.T) {
	t.Run("ipv4 /24", func(t *testing.T) {
		c := newCase(t)
		c.policy(dpVictimNet, 11,
			RuleSpec{ID: 530, Action: ActionDrop, Dst: dpVictimNet, ExpiresAt: farFuture})

		c.expect(synFrame(dpAttacker, dpVictim), xdpDrop, StatDropDynDst)
		c.expect(synFrame(dpAttacker, dpVictim2), xdpDrop, StatDropDynDst)
		// Outside the carpet the trie misses entirely, so nothing is even
		// evaluated: pass_default, not a drop counter.
		c.expect(synFrame(dpAttacker, dpOffNet), xdpPass, StatPassDefault)
	})

	t.Run("ipv6 /64", func(t *testing.T) {
		c := newCase(t)
		c.policy(dpVictim6Net, 12,
			RuleSpec{ID: 531, Action: ActionDrop, Dst: dpVictim6Net, IPv6: true, ExpiresAt: farFuture})

		c.expect(synFrame(dpAttacker6, dpVictim6), xdpDrop, StatDropDynDst)
		c.expect(synFrame(dpAttacker6, netip.MustParseAddr("2001:db8:1::ffff")), xdpDrop, StatDropDynDst)
		c.expect(synFrame(dpAttacker6, netip.MustParseAddr("2001:db8:2::9")), xdpPass, StatPassDefault)
	})
}

// TestSourceAnchoredPolicySparesOtherClients is the shape
// mitigate.sourceAnchoredRules() emits: {victim as dst, attacker as src}. It
// must drop that attacker and spare every other client of the same victim —
// the sparing is the entire reason source anchoring exists.
func TestSourceAnchoredPolicySparesOtherClients(t *testing.T) {
	c := newCase(t)
	c.policy(dpVictimNet, 13, RuleSpec{
		ID: 540, Action: ActionDrop, Src: dpAttackerNet, Dst: dpVictimNet, ExpiresAt: farFuture,
	})

	c.expect(synFrame(dpAttacker, dpVictim), xdpDrop, StatDropDynDst)
	c.expect(synFrame(dpBystander, dpVictim), xdpPass, StatPassDefault)
}

/* ================================================ 3. frame shapes at the wire */

// TestFrameShapes drives the L2/L3 encodings a scrubber actually sees, against
// one rule that names a destination port. The port is the discriminator: a
// parser that mislocates the L4 header (by not skipping a VLAN tag or an IPv4
// option block) reads two arbitrary bytes as the port and the rule silently
// stops firing.
func TestFrameShapes(t *testing.T) {
	port80 := uint16(80)
	rule := RuleSpec{ID: 330, Action: ActionDrop, Dst: host32(dpVictim), DstPort: &port80}

	vlan := synFrame(dpAttacker, dpVictim)
	vlan.VLANs = []uint16{100}

	qinq := synFrame(dpAttacker, dpVictim)
	qinq.VLANs = []uint16{100, 10}

	opts := synFrame(dpAttacker, dpVictim)
	opts.IPv4Options = []byte{0x01, 0x01, 0x01, 0x00} // NOP NOP NOP EOL

	maxOpts := synFrame(dpAttacker, dpVictim)
	maxOpts.IPv4Options = make([]byte, 40) // IHL 15, the ceiling
	for i := range maxOpts.IPv4Options {
		maxOpts.IPv4Options[i] = 0x01
	}

	vlanOpts := synFrame(dpAttacker, dpVictim)
	vlanOpts.VLANs = []uint16{100}
	vlanOpts.IPv4Options = []byte{0x01, 0x01, 0x01, 0x00}

	cases := []dpShot{
		{"plain ipv4", synFrame(dpAttacker, dpVictim), xdpDrop, []Stat{StatDropStatic}},
		{"one vlan tag", vlan, xdpDrop, []Stat{StatDropStatic}},
		{"ipv4 options", opts, xdpDrop, []Stat{StatDropStatic}},
		{"the maximum 40 bytes of options", maxOpts, xdpDrop, []Stat{StatDropStatic}},
		{"vlan and options together", vlanOpts, xdpDrop, []Stat{StatDropStatic}},
		{
			// QinQ is counted and passed rather than parsed: the scrubber sees
			// at most one tag on the deployments Kapkan targets, and a second
			// level is verifier state spent on traffic that could not be
			// attributed to a victim anyway. The rule is never consulted.
			"qinq is passed, not parsed", qinq, xdpPass, []Stat{StatPassVLANDepth},
		},
		{
			"a non-first fragment reaches the rules with no ports",
			tailFragment(dpAttacker, dpVictim), xdpPass,
			[]Stat{StatPassFragNoPorts, StatPassDefault},
		},
	}

	c := newCase(t)
	c.statics(rule)
	for _, s := range cases {
		t.Run(s.name, func(t *testing.T) {
			c.as(t).expect(s.frame, s.verdict, s.stats...)
		})
	}
}

// TestMalformedFrames covers the one place in the program that can drop
// something no rule named, and only because the operator asked for it.
//
// The frames are built well-formed and then TRUNCATED, because that is what a
// truncated frame is on the wire — a real header with bytes missing — and it is
// the one shape pktgen cannot describe as a Frame.
func TestMalformedFrames(t *testing.T) {
	full := mustFrame(t, synFrame(dpAttacker, dpVictim))
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"ethernet says ipv4 but the header is cut", full[:14+10]},
		{"the tcp header is cut in half", full[:14+20+10]},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("drop_malformed off passes it", func(t *testing.T) {
				c := newCase(t)
				c.expectRaw(tc.pkt, xdpPass, StatPassMalformed)
			})
			t.Run("drop_malformed on drops it", func(t *testing.T) {
				c := newCase(t)
				c.setFlags(false, true)
				c.expectRaw(tc.pkt, xdpDrop, StatDropMalformed)
			})
			t.Run("drop_malformed under dry_run still counts it", func(t *testing.T) {
				c := newCase(t)
				c.setFlags(true, true)
				c.expectRaw(tc.pkt, xdpPass, StatDropMalformed, StatDryRunWouldDrop)
			})
		})
	}
}

// TestFirstFragmentKeepsItsL4Header is a regression test for a bug this suite
// found in kapkan_parse_l4: it used to bail out on pkt->is_frag, with a comment
// explaining that a NON-first fragment has no L4 header. But is_frag is set for
// a FIRST fragment too (IPv4 MF with offset 0), and a first fragment carries
// the whole L4 header — so every port, TCP-flag and ports-bearing rule silently
// missed the leading fragment of every fragmented flood. Fragmented UDP
// amplification is one of the commonest shapes this data plane exists to shed,
// so the hole was not theoretical. It also mis-reported those packets under
// pass_frag_noports, whose entire meaning is "there was no L4 header here".
//
// The three assertions below are the three halves of the contract, and each
// one fails on its own if the guard comes back:
//
//	a first fragment    -> ports and flags are readable, so a port rule fires;
//	a non-first fragment -> no ports, so the same rule cannot fire;
//	the counter          -> pass_frag_noports only for the one with no L4.
func TestFirstFragmentKeepsItsL4Header(t *testing.T) {
	dport := uint16(53413)
	c := newCase(t)
	c.statics(RuleSpec{ID: 370, Action: ActionDrop, Dst: host32(dpVictim), DstPort: &dport})

	// The first fragment of a fragmented UDP datagram: MF set, offset 0, and a
	// complete UDP header right behind the IPv4 header.
	c.as(t).expect(headFragment(dpAttacker, dpVictim), xdpDrop, StatDropStatic)

	// The continuation carries no L4 header at all, so the same rule must not
	// reach it — and this is the packet pass_frag_noports is about.
	c.as(t).expect(tailFragment(dpAttacker, dpVictim), xdpPass,
		StatPassFragNoPorts, StatPassDefault)

	// TCP flags come from the first fragment too.
	syn := headFragment(dpAttacker, dpVictim)
	syn.Proto = pktgen.ProtoTCP
	syn.DstPort = 80
	syn.TCPFlags = pktgen.TCPSyn
	syn.Payload = make([]byte, 8)

	c2 := newCase(t)
	c2.statics(RuleSpec{ID: 371, Action: ActionDrop, Dst: host32(dpVictim)}.
		MatchTCPFlags(pktgen.TCPSyn))
	c2.expect(syn, xdpDrop, StatDropStatic)
}

/* ================================================================ 4. expiry */

// TestExpiredRulesArePassedThrough is the fail-safe that makes a dead userspace
// harmless. Every dynamic rule carries a boot-clock deadline; past it the rule
// is treated as ABSENT, so a manager that crashes mid-attack degrades the box
// to a wire instead of leaving a customer blackholed forever.
func TestExpiredRulesArePassedThrough(t *testing.T) {
	t.Run("an expired static falls through to the default", func(t *testing.T) {
		c := newCase(t)
		c.statics(RuleSpec{ID: 340, Action: ActionDrop, Dst: host32(dpVictim), ExpiresAt: longExpired})
		c.expect(synFrame(dpAttacker, dpVictim), xdpPass, StatPassRuleExpired, StatPassDefault)
	})

	t.Run("an expired dynamic rule falls through too", func(t *testing.T) {
		c := newCase(t)
		c.policy(host32(dpVictim), 21,
			RuleSpec{ID: 341, Action: ActionDrop, Dst: host32(dpVictim), ExpiresAt: longExpired})
		c.expect(synFrame(dpAttacker, dpVictim), xdpPass, StatPassRuleExpired, StatPassDefault)
	})

	t.Run("expiry 0 means never, which is what statics use", func(t *testing.T) {
		c := newCase(t)
		c.statics(RuleSpec{ID: 342, Action: ActionDrop, Dst: host32(dpVictim), ExpiresAt: neverExpires})
		c.expect(synFrame(dpAttacker, dpVictim), xdpDrop, StatDropStatic)
	})

	t.Run("an expired rule does not shadow a live one behind it", func(t *testing.T) {
		c := newCase(t)
		c.statics(
			RuleSpec{ID: 343, Action: ActionPass, Dst: host32(dpVictim), ExpiresAt: longExpired},
			RuleSpec{ID: 344, Action: ActionDrop, Dst: host32(dpVictim), ExpiresAt: farFuture},
		)
		c.expect(synFrame(dpAttacker, dpVictim), xdpDrop, StatPassRuleExpired, StatDropStatic)
	})
}

/* =============================================================== 5. dry run */

// TestDryRunAccountingMatchesLive is the promise dry run makes to an operator
// staging a policy: the verdict becomes PASS, and every counter reads exactly
// as it would have if the policy were live. Anything less and "what would this
// have dropped?" is unanswerable.
//
// The test runs each scenario twice — once live, once dry — and requires the
// counter deltas to be IDENTICAL apart from dryrun_would_drop. Asserting
// specific numbers would be weaker: this compares against the real thing.
func TestDryRunAccountingMatchesLive(t *testing.T) {
	scenarios := []struct {
		name  string
		setup func(c *dpCase)
		pkts  []pktgen.Frame
	}{
		{
			name: "a static drop",
			setup: func(c *dpCase) {
				c.statics(RuleSpec{ID: 350, Action: ActionDrop, Dst: host32(dpVictim)})
			},
			pkts: []pktgen.Frame{
				synFrame(dpAttacker, dpVictim),
				synFrame(dpBystander, dpVictim),
				synFrame(dpAttacker, dpOffNet), // spared either way
			},
		},
		{
			name: "a dynamic per-victim drop",
			setup: func(c *dpCase) {
				c.policy(dpVictimNet, 31,
					RuleSpec{ID: 351, Action: ActionDrop, Dst: dpVictimNet, ExpiresAt: farFuture})
			},
			pkts: []pktgen.Frame{
				synFrame(dpAttacker, dpVictim),
				synFrame(dpAttacker, dpVictim2),
			},
		},
		{
			name: "a rate limiter shedding traffic",
			setup: func(c *dpCase) {
				c.profile(1, ProfileSpec{PPS: 1, BurstPackets: 1})
				c.statics(RuleSpec{
					ID: 352, Action: ActionRateLimit, Profile: 1, Dst: host32(dpVictim),
				})
			},
			pkts: []pktgen.Frame{
				synFrame(dpAttacker, dpVictim),
				synFrame(dpAttacker, dpVictim),
				synFrame(dpAttacker, dpVictim),
			},
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			live := runScenario(t, sc.setup, sc.pkts, false)
			dry := runScenario(t, sc.setup, sc.pkts, true)

			if live.drops == 0 {
				t.Fatal("the live run dropped nothing, so this proves nothing about dry run")
			}
			if dry.drops != 0 {
				t.Errorf("dry run dropped %d packets, want 0: it must never actually shed", dry.drops)
			}
			liveCounters := withoutDryRunMarker(live.delta)
			dryCounters := withoutDryRunMarker(dry.delta)
			if !sameDelta(liveCounters, dryCounters) {
				t.Errorf("dry run accounted differently from a live run\n live:%s\n  dry:%s",
					renderDelta(liveCounters), renderDelta(dryCounters))
			}
			if got := dry.delta[StatDryRunWouldDrop].Pkts; got != uint64(live.drops) {
				t.Errorf("dryrun_would_drop = %d, want %d (every drop the live run made)",
					got, live.drops)
			}
			// Per-rule accounting must survive dry run too: the console reads
			// it to show which rule would have fired.
			if live.ruleHits == 0 {
				t.Fatal("no per-rule counter moved in the live run; the scenario is not instrumented")
			}
			if dry.ruleHits != live.ruleHits {
				t.Errorf("per-rule hits: dry %d, live %d", dry.ruleHits, live.ruleHits)
			}
		})
	}
}

type scenarioResult struct {
	drops    int
	delta    map[Stat]Counter
	ruleHits uint64
}

// runScenario builds a fresh program, applies the setup, fires the frames and
// returns the aggregate counter movement.
func runScenario(t *testing.T, setup func(c *dpCase), frames []pktgen.Frame, dryRun bool) scenarioResult {
	t.Helper()
	c := newCase(t)
	setup(c)
	c.setFlags(dryRun, false)

	// Instrument every rule id the scenarios use; a missing entry is not an
	// error in the datapath, it just means "not measured".
	ids := []uint32{350, 351, 352}
	if err := EnsureRuleStats(c.m, ids...); err != nil {
		t.Fatal(err)
	}

	before := c.snapshot()
	drops := 0
	for _, f := range frames {
		if got, _ := c.send(f); got == xdpDrop {
			drops++
		}
	}
	after := c.snapshot()

	delta := make(map[Stat]Counter)
	for s := Stat(0); s < StatMax; s++ {
		d := Counter{Pkts: after[s].Pkts - before[s].Pkts, Bytes: after[s].Bytes - before[s].Bytes}
		if d.Pkts != 0 {
			delta[s] = d
		}
	}
	var hits uint64
	for _, id := range ids {
		cnt, ok, err := ReadRuleStats(c.m, id)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			hits += cnt.Pkts
		}
	}
	return scenarioResult{drops: drops, delta: delta, ruleHits: hits}
}

func withoutDryRunMarker(in map[Stat]Counter) map[Stat]Counter {
	out := make(map[Stat]Counter, len(in))
	for s, c := range in {
		if s == StatDryRunWouldDrop {
			continue
		}
		out[s] = c
	}
	return out
}

func sameDelta(a, b map[Stat]Counter) bool {
	if len(a) != len(b) {
		return false
	}
	for s, ca := range a {
		cb, ok := b[s]
		if !ok || ca != cb {
			return false
		}
	}
	return true
}

/* ============================================== 6. the empty-policy baseline */

// TestEmptyPolicyBlocksNothing is the charter as an executable statement. With
// no rules installed, a full spread of real attack traffic — every pattern
// pkg/pktgen knows, both address families — must pass in its entirety, and the
// block rate must be exactly zero.
//
// "Exactly" is the point. A data plane whose idle block rate is 0.01% is one
// that drops a few thousand packets a second on a busy link for no reason
// anyone configured, and it would sail past any assertion phrased as "roughly
// none".
func TestEmptyPolicyBlocksNothing(t *testing.T) {
	patterns := []pktgen.Pattern{
		pktgen.UDPFlood, pktgen.SYNFlood, pktgen.ACKFlood,
		pktgen.DNSAmplification, pktgen.NTPMonlist, pktgen.CLDAPAmplification,
		pktgen.MemcachedAmplification, pktgen.SSDPAmplification, pktgen.ChargenAmplification,
		pktgen.ICMPFlood, pktgen.FragmentFlood, pktgen.MixedVector,
	}
	victims := []netip.Addr{dpVictim, dpVictim6}

	c := newCase(t)
	before := c.snapshot()

	total := 0
	for _, victim := range victims {
		for _, p := range patterns {
			frames := pktgen.Generate(p, pktgen.GenConfig{Victim: victim, Count: 8})
			for i, f := range frames {
				got := c.fire(f)
				total++
				if got != xdpPass {
					t.Fatalf("%v frame %d toward %v: verdict = %s, want XDP_PASS with no policy installed",
						p, i, victim, verdictName(got))
				}
			}
		}
	}
	after := c.snapshot()

	var blocked uint64
	for _, s := range []Stat{
		StatDropMalformed, StatDropStatic, StatDropDynSrc, StatDropDynDst, StatDropRL,
		StatDryRunWouldDrop,
	} {
		blocked += after[s].Pkts - before[s].Pkts
	}
	if blocked != 0 {
		t.Errorf("block rate = %d/%d packets, want exactly 0 with an empty policy", blocked, total)
	}

	// Every packet must still be accounted for: the terminal counters partition
	// the traffic, so their sum is the packet count. A packet that passes
	// without bumping anything is a hole in the accounting, not a success.
	var terminal uint64
	for s := Stat(0); s < StatMax; s++ {
		if s.IsObservation() {
			continue
		}
		terminal += after[s].Pkts - before[s].Pkts
	}
	if terminal != uint64(total) {
		t.Errorf("terminal counters sum to %d, want %d (one per packet)", terminal, total)
	}
}

/* ======================================================= 7. the rate limiter */

// TestPerSourceRateLimitUnderManySources is the capability BGP FlowSpec
// structurally cannot express. FlowSpec's traffic-rate community caps an
// AGGREGATE, so "cap every source at N pps" needs one rule per source; here one
// rule gives each attacker its own budget, keyed {victim, source, profile}.
//
// The offered load is 2x the ceiling from every source at once, which is the
// realistic shape: a flood is many sources each a little over the line, not one
// source a lot over it.
func TestPerSourceRateLimitUnderManySources(t *testing.T) {
	const (
		burst    = 4
		sources  = 16
		perAttac = burst * 2 // 2x the allowance
	)

	c := newCase(t)
	// 1 pps refills ~1 token/second; the whole test runs in milliseconds, so
	// the burst is the entire budget and the arithmetic is deterministic.
	c.profile(1, ProfileSpec{PPS: 1, BurstPackets: burst})
	c.statics(RuleSpec{ID: 360, Action: ActionRateLimit, Profile: 1, Dst: dpVictimNet})

	admitted := make([]int, sources)
	for i := 0; i < sources; i++ {
		src := nthSource(i)
		for j := 0; j < perAttac; j++ {
			if c.fire(synFrame(src, dpVictim)) == xdpPass {
				admitted[i]++
			}
		}
	}

	for i, n := range admitted {
		if n != burst {
			t.Errorf("source %v admitted %d packets, want exactly its own burst of %d "+
				"(buckets are keyed per {victim, source, profile})", nthSource(i), n, burst)
		}
	}

	wantAdmit := uint64(sources * burst)
	wantDrop := uint64(sources * (perAttac - burst))
	if got, err := ReadStat(c.m, StatPassRLAdmit); err != nil {
		t.Fatal(err)
	} else if got.Pkts != wantAdmit {
		t.Errorf("pass_rl_admit = %d, want %d", got.Pkts, wantAdmit)
	}
	if got, err := ReadStat(c.m, StatDropRL); err != nil {
		t.Fatal(err)
	} else if got.Pkts != wantDrop {
		t.Errorf("drop_rl = %d, want %d", got.Pkts, wantDrop)
	}

	// A source that stays UNDER its cap must never lose a packet. This is the
	// half of a rate limiter that is easy to get wrong and expensive to miss:
	// a limiter that sheds well-behaved traffic is worse than no limiter.
	polite := netip.MustParseAddr("198.51.200.1")
	for i := 0; i < burst; i++ {
		c.expect(synFrame(polite, dpVictim), xdpPass, StatPassRLAdmit)
	}

	// The bucket is anchored on the packet's DESTINATION for a static rule
	// ("cap each source at N pps towards this prefix"). Reading one back proves
	// the key the Go helper builds is byte-for-byte the key the datapath wrote
	// — a byte-order slip there would silently give every packet a fresh
	// bucket, i.e. no rate limiting at all, with counters that look healthy.
	b, ok, err := ReadBucket(c.m, dpVictim, nthSource(0), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no bucket for the first source: the key the helper builds does not match the datapath's")
	}
	if b.TokensPktQ32 >= 1<<32 {
		t.Errorf("exhausted bucket still holds %d Q32 tokens (>= one whole packet)", b.TokensPktQ32)
	}
}

// nthSource spreads attackers across a /24 so each gets its own bucket.
func nthSource(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + i)})
}

// TestRateLimitFailsOpen: every lookup the limiter cannot complete admits the
// packet. There is no default-deny anywhere in this program, and the rate
// limiter's error paths are the easiest place to introduce one by accident.
func TestRateLimitFailsOpen(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *dpCase)
	}{
		{"a profile userspace never wrote", func(c *dpCase) {
			c.statics(RuleSpec{ID: 361, Action: ActionRateLimit, Profile: 200, Dst: dpVictimNet})
		}},
		{"a profile that caps neither packets nor bytes", func(c *dpCase) {
			c.profile(2, ProfileSpec{})
			c.statics(RuleSpec{ID: 362, Action: ActionRateLimit, Profile: 2, Dst: dpVictimNet})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCase(t)
			tc.setup(c)
			for i := 0; i < 3; i++ {
				c.expect(synFrame(dpAttacker, dpVictim), xdpPass, StatPassRLAdmit)
			}
		})
	}
}
