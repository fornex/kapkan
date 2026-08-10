//go:build linux

package dataplane

// Behavioural tests for the packet path: the six precedence levels, the token
// bucket, rule expiry, the generation flip and dry run. Every case drives a
// real packet through BPF_PROG_TEST_RUN on a real kernel and asserts both the
// verdict AND which counter moved, because "it returned XDP_PASS" is only half
// an answer — passing for the wrong reason is a bug that would otherwise hide
// until an operator asked why a rule never fired.
//
// Run them with `make dataplane-test` (see engine/bpf/README.md).

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

/* ------------------------------------------------------------- addresses */

var (
	victimIP   = [4]byte{203, 0, 113, 9}   // TEST-NET-3, the dst in ipv4()
	attackerIP = [4]byte{198, 51, 100, 7}  // TEST-NET-2, the src in ipv4()
	otherIP    = [4]byte{198, 51, 100, 88} // a second attacker
)

// ipv4From builds a 20-byte IPv4 header with explicit endpoints, so a test can
// drive several distinct sources at one victim (which is the whole point of a
// per-source rate limiter).
func ipv4From(src, dst [4]byte, proto uint8, fragOff uint16, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(h[6:], fragOff)
	h[8] = 64
	h[9] = proto
	copy(h[12:], src[:])
	copy(h[16:], dst[:])
	return h
}

// synPacket is the workhorse: a TCP SYN from attackerIP to victimIP.
func synPacket() []byte {
	return cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 6, 0, 20), tcp(1024, 80, 0x02))
}

func synPacketFrom(src [4]byte) []byte {
	return cat(eth(etherTypeIPv4), ipv4From(src, victimIP, 6, 0, 20), tcp(1024, 80, 0x02))
}

/* ------------------------------------------------------------ fixtures */

// cfgOpts is the full kapkan_cfg[0] a packet-path test needs. Strides come
// from the real map sizes so the generation arithmetic under test is the same
// arithmetic the manager will use.
type cfgOpts struct {
	generation    uint32
	staticCount   uint32
	dryRun        bool
	dropMalformed bool
}

func setCfgFull(t *testing.T, objs *kapkanXDPObjects, o cfgOpts) {
	t.Helper()
	if err := PutConfig(objs.MapSet(), ConfigSpec{
		Generation:    o.generation,
		StaticCount:   o.staticCount,
		DryRun:        o.dryRun,
		DropMalformed: o.dropMalformed,
	}); err != nil {
		t.Fatalf("write kapkan_cfg[0]: %v", err)
	}
}

// neverExpires and longExpired are the two ends of the expiry contract. A
// boot-clock timestamp of 1ns is unconditionally in the past on any machine
// that has finished booting, which keeps the test free of clock plumbing.
const (
	neverExpires = uint64(0)
	longExpired  = uint64(1)
	farFuture    = uint64(1) << 62
)

// ruleOpts builds a kapkan_rule without making every test spell out the
// "any" flags. Zero value = matches every IPv4 packet.
type ruleOpts struct {
	id       uint32
	action   Action
	profile  uint32
	expires  uint64
	src      *[4]byte
	dst      *[4]byte
	src6     *[16]byte
	dst6     *[16]byte
	prefix6  uint8 // prefix length for src6/dst6; 0 means /128
	proto    *uint8
	sport    *uint16
	dport    *uint16
	tcpFlags uint8 // expected bits
	tcpMask  uint8 // 0 = do not test
	fragment bool
	v6       bool
}

// mkRule funnels these older tests through the production encoder rather than
// filling struct fields itself: a second hand-rolled encoder in the test file
// would be free to agree with a broken RuleSpec.Encode, which is the one thing
// these tests must not do. It panics rather than taking a *testing.T because
// every caller passes a literal, so a failure here is a bug in this file.
func mkRule(o ruleOpts) Rule {
	bits := o.prefix6
	if bits == 0 {
		bits = 128
	}
	spec := RuleSpec{
		ID:           o.id,
		Action:       o.action,
		Profile:      o.profile,
		ExpiresAt:    o.expires,
		Proto:        o.proto,
		SrcPort:      o.sport,
		DstPort:      o.dport,
		TCPFlags:     o.tcpFlags,
		TCPFlagsMask: o.tcpMask,
		Fragment:     o.fragment,
		IPv6:         o.v6,
	}
	if o.src != nil {
		spec.Src = netip.PrefixFrom(netip.AddrFrom4(*o.src), 32)
	}
	if o.dst != nil {
		spec.Dst = netip.PrefixFrom(netip.AddrFrom4(*o.dst), 32)
	}
	if o.src6 != nil {
		spec.Src = netip.PrefixFrom(netip.AddrFrom16(*o.src6), int(bits))
	}
	if o.dst6 != nil {
		spec.Dst = netip.PrefixFrom(netip.AddrFrom16(*o.dst6), int(bits))
	}
	r, err := spec.Encode()
	if err != nil {
		panic("mkRule: " + err.Error())
	}
	return r
}

func u8p(v uint8) *uint8    { return &v }
func u16p(v uint16) *uint16 { return &v }

// installStatics writes rules into the given generation's half of
// kapkan_statics. The caller sets static_count through setCfgFull.
func installStatics(t *testing.T, objs *kapkanXDPObjects, gen uint32, rules ...Rule) {
	t.Helper()
	if _, err := PutStatics(objs.MapSet(), gen, rules); err != nil {
		t.Fatalf("install statics: %v", err)
	}
}

// installPolicy points a victim prefix at a policy block in the given
// generation. anchor is looked up by the datapath as either the packet's
// source (precedence 4) or destination (precedence 5).
func installPolicy(t *testing.T, objs *kapkanXDPObjects, gen, policyID uint32, anchor [4]byte, rules ...Rule) {
	t.Helper()
	m := objs.MapSet()
	if err := PutPolicy(m, gen, policyID, rules); err != nil {
		t.Fatalf("write policy block: %v", err)
	}
	if err := AddVictim(m, netip.PrefixFrom(netip.AddrFrom4(anchor), 32), policyID); err != nil {
		t.Fatalf("write victims4: %v", err)
	}
}

func addPrefix4(t *testing.T, m *ebpf.Map, addr [4]byte, bits uint32) {
	t.Helper()
	key := kapkanXDPKapkanLpmKeyV4{Prefixlen: bits, Addr: addr}
	if err := m.Put(&key, uint8(1)); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
}

// run drives one packet and returns the verdict.
func run(t *testing.T, objs *kapkanXDPObjects, pkt []byte) uint32 {
	t.Helper()
	ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	return ret
}

// wantVerdict asserts the verdict and that exactly the expected counter moved.
func wantVerdict(t *testing.T, objs *kapkanXDPObjects, got, want uint32, stat Stat) {
	t.Helper()
	if got != want {
		t.Errorf("verdict = %s, want %s; counters:%s",
			verdictName(got), verdictName(want), dumpStats(t, objs))
	}
	if p, _ := readStat(t, objs, stat); p != 1 {
		t.Errorf("%s = %d, want 1; counters:%s", stat, p, dumpStats(t, objs))
	}
}

/* ------------------------------------------------------- precedence 1-2 */

// TestAllowlistOutranksEverything is the precedence-1 guarantee: a source on
// dataplane.allowlist is never touched, even by an operator's own drop rule.
// That is what stops a scrubber being talked into blackholing its own BGP
// peers or its monitoring.
func TestAllowlistOutranksEverything(t *testing.T) {
	objs := loadObjects(t)

	// A static rule that would otherwise drop this exact packet.
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	// Without the allowlist it drops.
	if got := run(t, objs, synPacket()); got != xdpDrop {
		t.Fatalf("precondition: verdict = %s, want XDP_DROP", verdictName(got))
	}

	// Allowlist the source; now it must pass, and for the RIGHT reason.
	objs2 := loadObjects(t)
	installStatics(t, objs2, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs2, cfgOpts{staticCount: 1})
	addPrefix4(t, objs2.KapkanAllow4, attackerIP, 32)

	wantVerdict(t, objs2, run(t, objs2, synPacket()), xdpPass, StatPassAllowSrc)
	if p, _ := readStat(t, objs2, StatDropStatic); p != 0 {
		t.Errorf("drop_static = %d, want 0: the allowlist must short-circuit before the scan", p)
	}
}

// TestProtectedDestinationOutranksRules is precedence 2, and it is a different
// axis from precedence 1: protected_whitelist names a VICTIM that must never be
// banned. It lives in the kernel so that a rehydrated or racing rule cannot
// blackhole a protected prefix for the up-to-one-second it would take the
// userspace sweep to notice.
func TestProtectedDestinationOutranksRules(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})
	addPrefix4(t, objs.KapkanProtect4, victimIP, 32)

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpPass, StatPassProtectDst)
	if p, _ := readStat(t, objs, StatDropStatic); p != 0 {
		t.Errorf("drop_static = %d, want 0", p)
	}
}

// TestAllowlistIsSourceProtectedIsDestination proves the two lists are not
// interchangeable: putting the VICTIM on the source allowlist must not save
// the packet, and putting the ATTACKER on the protected list must not either.
// If these ever collapse into one list the mistake is silent and expensive.
func TestAllowlistIsSourceProtectedIsDestination(t *testing.T) {
	t.Run("victim on the source allowlist does not help", func(t *testing.T) {
		objs := loadObjects(t)
		installStatics(t, objs, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})
		addPrefix4(t, objs.KapkanAllow4, victimIP, 32) // wrong axis

		wantVerdict(t, objs, run(t, objs, synPacket()), xdpDrop, StatDropStatic)
	})

	t.Run("attacker on the protected list does not help", func(t *testing.T) {
		objs := loadObjects(t)
		installStatics(t, objs, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})
		addPrefix4(t, objs.KapkanProtect4, attackerIP, 32) // wrong axis

		wantVerdict(t, objs, run(t, objs, synPacket()), xdpDrop, StatDropStatic)
	})
}

/* --------------------------------------------------------- precedence 3 */

func TestStaticRuleDrop(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 7, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	// Userspace creates the per-rule counter when it installs the rule.
	if err := EnsureRuleStats(objs.MapSet(), 7); err != nil {
		t.Fatalf("create rule_stats entry: %v", err)
	}

	pkt := synPacket()
	wantVerdict(t, objs, run(t, objs, pkt), xdpDrop, StatDropStatic)

	// Per-rule accounting must show the packet, not just the global counter.
	c, ok, err := ReadRuleStats(objs.MapSet(), 7)
	if err != nil || !ok {
		t.Fatalf("read rule_stats: ok=%v err=%v", ok, err)
	}
	if c.Pkts != 1 || c.Bytes != uint64(len(pkt)) {
		t.Errorf("rule_stats[7] = %d pkts / %d bytes, want 1 / %d", c.Pkts, c.Bytes, len(pkt))
	}
}

// TestStaticFirstMatchWins: the scan stops at the first matching rule, so an
// earlier PASS shields the packet from a later DROP.
func TestStaticFirstMatchWins(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0,
		mkRule(ruleOpts{id: 1, action: ActionPass, dst: &victimIP, proto: u8p(6)}),
		mkRule(ruleOpts{id: 2, action: ActionDrop, dst: &victimIP}),
	)
	setCfgFull(t, objs, cfgOpts{staticCount: 2})

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpPass, StatPassStatic)
}

// TestStaticCountBoundsTheScan: rules physically present in the map but beyond
// static_count must not fire. This is what makes a generation half safe to
// build up incrementally.
func TestStaticCountBoundsTheScan(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs, cfgOpts{staticCount: 0}) // the rule is there but not live

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpPass, StatPassDefault)
}

/* ------------------------------------------------------- precedence 4-5 */

// TestDynamicDstRule is the common case: an incoming attack on a protected
// victim, matched by an LPM lookup on the DESTINATION.
func TestDynamicDstRule(t *testing.T) {
	objs := loadObjects(t)
	setCfgFull(t, objs, cfgOpts{})
	installPolicy(t, objs, 0, 3, victimIP,
		mkRule(ruleOpts{id: 11, action: ActionDrop, dst: &victimIP, proto: u8p(6), expires: farFuture}))

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpDrop, StatDropDynDst)
}

// TestDynamicSrcRule is the outgoing case: a compromised host's outbound
// flood, which mitigate anchors on Src, matched by an LPM lookup on the
// packet's SOURCE. It proves precedence 4 is wired to the source axis.
func TestDynamicSrcRule(t *testing.T) {
	objs := loadObjects(t)
	setCfgFull(t, objs, cfgOpts{})
	installPolicy(t, objs, 0, 4, attackerIP,
		mkRule(ruleOpts{id: 12, action: ActionDrop, src: &attackerIP, expires: farFuture}))

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpDrop, StatDropDynSrc)
}

// TestCompositeSourceAnchoredRule is the shape sourceAnchoredRules() emits:
// {victim as dst, attacker as src}. It must drop that attacker and spare every
// other client of the same victim — that sparing is the entire reason source
// anchoring exists.
func TestCompositeSourceAnchoredRule(t *testing.T) {
	objs := loadObjects(t)
	setCfgFull(t, objs, cfgOpts{})
	installPolicy(t, objs, 0, 5, victimIP,
		mkRule(ruleOpts{id: 13, action: ActionDrop, src: &attackerIP, dst: &victimIP, expires: farFuture}))

	if got := run(t, objs, synPacketFrom(attackerIP)); got != xdpDrop {
		t.Errorf("named attacker: verdict = %s, want XDP_DROP", verdictName(got))
	}
	if got := run(t, objs, synPacketFrom(otherIP)); got != xdpPass {
		t.Errorf("innocent client of the same victim: verdict = %s, want XDP_PASS",
			verdictName(got))
	}
}

// TestPolicyScanBoundedByNRules: slots past n_rules must not fire even though
// the block physically holds eight.
func TestPolicyScanBoundedByNRules(t *testing.T) {
	objs := loadObjects(t)
	setCfgFull(t, objs, cfgOpts{})

	block := kapkanXDPKapkanPolicyBlock{N_rules: 0}
	block.Rules[0] = mkRule(ruleOpts{id: 14, action: ActionDrop, dst: &victimIP, expires: farFuture})
	stride := objs.KapkanPolicies.MaxEntries() / Generations
	if err := objs.KapkanPolicies.Put(uint32(0)*stride+6, &block); err != nil {
		t.Fatal(err)
	}
	key := kapkanXDPKapkanLpmKeyV4{Prefixlen: 32, Addr: victimIP}
	if err := objs.KapkanVictims4.Put(&key, uint32(6)); err != nil {
		t.Fatal(err)
	}

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpPass, StatPassDefault)
}

// TestVictimWithoutPolicyBlockFailsOpen: the trie points at a block index the
// array cannot serve. Userspace is mid-update or buggy; the packet must still
// be forwarded, loudly counted.
func TestVictimWithoutPolicyBlockFailsOpen(t *testing.T) {
	objs := loadObjects(t)
	setCfgFull(t, objs, cfgOpts{})
	key := kapkanXDPKapkanLpmKeyV4{Prefixlen: 32, Addr: victimIP}
	// Way past max_entries: the ARRAY lookup bounds-checks and returns NULL.
	if err := objs.KapkanVictims4.Put(&key, objs.KapkanPolicies.MaxEntries()+1000); err != nil {
		t.Fatal(err)
	}

	wantVerdict(t, objs, run(t, objs, synPacket()), xdpPass, StatErrPolicyMissing)
}

/* --------------------------------------------------------------- expiry */

// TestExpiredRuleIsTreatedAsAbsent is the fail-safe that makes a dead
// userspace harmless: every dynamic rule ages out on its own boot-clock
// deadline, so a crashed manager degrades the box to a wire rather than
// leaving it blackholing a customer forever.
func TestExpiredRuleIsTreatedAsAbsent(t *testing.T) {
	t.Run("static", func(t *testing.T) {
		objs := loadObjects(t)
		installStatics(t, objs, 0,
			mkRule(ruleOpts{id: 21, action: ActionDrop, dst: &victimIP, expires: longExpired}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})

		if got := run(t, objs, synPacket()); got != xdpPass {
			t.Errorf("verdict = %s, want XDP_PASS for an expired rule", verdictName(got))
		}
		if p, _ := readStat(t, objs, StatPassRuleExpired); p != 1 {
			t.Errorf("pass_rule_expired = %d, want 1", p)
		}
		if p, _ := readStat(t, objs, StatPassDefault); p != 1 {
			t.Errorf("pass_default = %d, want 1: an expired rule must fall through", p)
		}
	})

	t.Run("dynamic", func(t *testing.T) {
		objs := loadObjects(t)
		setCfgFull(t, objs, cfgOpts{})
		installPolicy(t, objs, 0, 2, victimIP,
			mkRule(ruleOpts{id: 22, action: ActionDrop, dst: &victimIP, expires: longExpired}))

		if got := run(t, objs, synPacket()); got != xdpPass {
			t.Errorf("verdict = %s, want XDP_PASS", verdictName(got))
		}
		if p, _ := readStat(t, objs, StatPassRuleExpired); p != 1 {
			t.Errorf("pass_rule_expired = %d, want 1", p)
		}
	})

	t.Run("expiry 0 means never", func(t *testing.T) {
		objs := loadObjects(t)
		installStatics(t, objs, 0,
			mkRule(ruleOpts{id: 23, action: ActionDrop, dst: &victimIP, expires: neverExpires}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})

		wantVerdict(t, objs, run(t, objs, synPacket()), xdpDrop, StatDropStatic)
	})

	// An expired rule must not shadow a live one behind it.
	t.Run("scan continues past an expired match", func(t *testing.T) {
		objs := loadObjects(t)
		installStatics(t, objs, 0,
			mkRule(ruleOpts{id: 24, action: ActionPass, dst: &victimIP, expires: longExpired}),
			mkRule(ruleOpts{id: 25, action: ActionDrop, dst: &victimIP, expires: farFuture}),
		)
		setCfgFull(t, objs, cfgOpts{staticCount: 2})

		wantVerdict(t, objs, run(t, objs, synPacket()), xdpDrop, StatDropStatic)
	})
}

/* --------------------------------------------------------- match fields */

// TestTCPFlagsBitmaskSemantics pins the one semantic most likely to drift from
// the BGP encoder. RFC 8955's bitmask match with the MATCH bit set means "all
// these bits are set", NOT equality — which is why FlowSpecRule documents that
// a SYN rule also catches SYN-ACK. If this ever becomes an equality test, a
// SYN-flood rule silently stops catching half the flood.
func TestTCPFlagsBitmaskSemantics(t *testing.T) {
	const (
		fin = 0x01
		syn = 0x02
		ack = 0x10
	)
	cases := []struct {
		name  string
		flags uint8
		drop  bool
	}{
		{"pure SYN", syn, true},
		{"SYN-ACK also matches the SYN bitmask", syn | ack, true},
		{"pure ACK does not match", ack, false},
		{"FIN does not match", fin, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadObjects(t)
			installStatics(t, objs, 0, mkRule(ruleOpts{
				id: 31, action: ActionDrop, dst: &victimIP,
				proto: u8p(6), tcpFlags: syn, tcpMask: syn,
			}))
			setCfgFull(t, objs, cfgOpts{staticCount: 1})

			pkt := cat(eth(etherTypeIPv4),
				ipv4From(attackerIP, victimIP, 6, 0, 20), tcp(1024, 80, tc.flags))
			got := run(t, objs, pkt)
			want := uint32(xdpPass)
			if tc.drop {
				want = xdpDrop
			}
			if got != want {
				t.Errorf("flags 0x%02x: verdict = %s, want %s",
					tc.flags, verdictName(got), verdictName(want))
			}
		})
	}

	// An exact match (mask 0xFF) is the thing FlowSpec's bitmask cannot say,
	// and it must NOT catch SYN-ACK.
	t.Run("exact mask 0xFF is exact", func(t *testing.T) {
		objs := loadObjects(t)
		installStatics(t, objs, 0, mkRule(ruleOpts{
			id: 32, action: ActionDrop, dst: &victimIP,
			proto: u8p(6), tcpFlags: syn, tcpMask: 0xFF,
		}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})

		if got := run(t, objs, cat(eth(etherTypeIPv4),
			ipv4From(attackerIP, victimIP, 6, 0, 20), tcp(1024, 80, syn))); got != xdpDrop {
			t.Errorf("pure SYN: verdict = %s, want XDP_DROP", verdictName(got))
		}
		if got := run(t, objs, cat(eth(etherTypeIPv4),
			ipv4From(attackerIP, victimIP, 6, 0, 20), tcp(1024, 80, syn|ack))); got != xdpPass {
			t.Errorf("SYN-ACK under an exact mask: verdict = %s, want XDP_PASS", verdictName(got))
		}
	})
}

// TestPortMatching, including the fragment interaction: a non-first fragment
// has no L4 header, so a rule naming a port must not match it.
func TestPortMatching(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 41, action: ActionDrop, dst: &victimIP, proto: u8p(17), sport: u16p(53),
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	// DNS reflection shape: UDP source port 53 -> drop.
	hit := cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0, 16), udp(53, 33333, 8), make([]byte, 8))
	if got := run(t, objs, hit); got != xdpDrop {
		t.Errorf("udp/53: verdict = %s, want XDP_DROP", verdictName(got))
	}
	// Different source port -> spared.
	miss := cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0, 16), udp(1234, 33333, 8), make([]byte, 8))
	if got := run(t, objs, miss); got != xdpPass {
		t.Errorf("udp/1234: verdict = %s, want XDP_PASS", verdictName(got))
	}
	// A non-first fragment carries no ports at all: the rule must not match.
	frag := cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0x00b9, 32), make([]byte, 32))
	if got := run(t, objs, frag); got != xdpPass {
		t.Errorf("non-first fragment: verdict = %s, want XDP_PASS (no L4 header to match a port against)",
			verdictName(got))
	}
}

// TestFragmentMatching: fragments are matchable via the rule's fragment bit and
// are NEVER dropped merely for being fragments.
func TestFragmentMatching(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 51, action: ActionDrop, dst: &victimIP, fragment: true,
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	frag := cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0x00b9, 32), make([]byte, 32))
	if got := run(t, objs, frag); got != xdpDrop {
		t.Errorf("fragment: verdict = %s, want XDP_DROP", verdictName(got))
	}
	// A whole datagram must be spared by a fragment-only rule.
	if got := run(t, objs, synPacket()); got != xdpPass {
		t.Errorf("whole datagram: verdict = %s, want XDP_PASS", verdictName(got))
	}
}

// TestAddressFamilyIsolation pins the IPv4-mapped-IPv6 decision: families are
// never normalised into each other, so a v4 rule cannot reach a v6 packet.
func TestAddressFamilyIsolation(t *testing.T) {
	objs := loadObjects(t)
	// A v4 rule that matches everything in its family.
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 61, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	v6pkt := cat(eth(etherTypeIPv6), ipv6(6, 20), tcp(1024, 80, 0x02))
	if got := run(t, objs, v6pkt); got != xdpPass {
		t.Errorf("ipv6 packet against a v4 rule: verdict = %s, want XDP_PASS", verdictName(got))
	}
}

// TestIPv6Rule exercises the 128-bit prefix compare, including a /64 (the
// awkward edge where the low half's mask is empty).
func TestIPv6Rule(t *testing.T) {
	// 2001:db8::2, the dst that ipv6() builds.
	var v6dst [16]byte
	copy(v6dst[:], []byte{0x20, 0x01, 0x0d, 0xb8})
	v6dst[15] = 2

	for _, bits := range []uint8{128, 64, 32} {
		t.Run("prefix", func(t *testing.T) {
			objs := loadObjects(t)
			installStatics(t, objs, 0, mkRule(ruleOpts{
				id: 71, action: ActionDrop, dst6: &v6dst, prefix6: bits, v6: true,
			}))
			setCfgFull(t, objs, cfgOpts{staticCount: 1})

			pkt := cat(eth(etherTypeIPv6), ipv6(6, 20), tcp(1024, 80, 0x02))
			if got := run(t, objs, pkt); got != xdpDrop {
				t.Errorf("/%d: verdict = %s, want XDP_DROP", bits, verdictName(got))
			}
		})
	}

	// A prefix that does NOT contain the victim must not match.
	t.Run("non-matching /128", func(t *testing.T) {
		other := v6dst
		other[15] = 99
		objs := loadObjects(t)
		installStatics(t, objs, 0, mkRule(ruleOpts{
			id: 72, action: ActionDrop, dst6: &other, prefix6: 128, v6: true,
		}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})

		pkt := cat(eth(etherTypeIPv6), ipv6(6, 20), tcp(1024, 80, 0x02))
		if got := run(t, objs, pkt); got != xdpPass {
			t.Errorf("verdict = %s, want XDP_PASS", verdictName(got))
		}
	})
}

/* ---------------------------------------------------- double buffering */

// TestGenerationFlip proves a policy swap is atomic from the packet's point of
// view: the inactive half can hold a completely different rule set, and one
// u32 store moves every packet from one to the other.
func TestGenerationFlip(t *testing.T) {
	objs := loadObjects(t)

	// Generation 0: pass. Generation 1: drop. Same slot index.
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 81, action: ActionPass, dst: &victimIP}))
	installStatics(t, objs, 1, mkRule(ruleOpts{id: 82, action: ActionDrop, dst: &victimIP}))

	setCfgFull(t, objs, cfgOpts{generation: 0, staticCount: 1})
	if got := run(t, objs, synPacket()); got != xdpPass {
		t.Errorf("generation 0: verdict = %s, want XDP_PASS", verdictName(got))
	}

	setCfgFull(t, objs, cfgOpts{generation: 1, staticCount: 1})
	if got := run(t, objs, synPacket()); got != xdpDrop {
		t.Errorf("generation 1: verdict = %s, want XDP_DROP", verdictName(got))
	}

	setCfgFull(t, objs, cfgOpts{generation: 0, staticCount: 1})
	if got := run(t, objs, synPacket()); got != xdpPass {
		t.Errorf("flipped back: verdict = %s, want XDP_PASS", verdictName(got))
	}
}

// TestGenerationFlipPolicies is the same guarantee for the per-victim blocks.
func TestGenerationFlipPolicies(t *testing.T) {
	objs := loadObjects(t)
	installPolicy(t, objs, 0, 9, victimIP,
		mkRule(ruleOpts{id: 83, action: ActionPass, dst: &victimIP, expires: farFuture}))
	installPolicy(t, objs, 1, 9, victimIP,
		mkRule(ruleOpts{id: 84, action: ActionDrop, dst: &victimIP, expires: farFuture}))

	setCfgFull(t, objs, cfgOpts{generation: 0})
	if got := run(t, objs, synPacket()); got != xdpPass {
		t.Errorf("generation 0: verdict = %s, want XDP_PASS", verdictName(got))
	}
	setCfgFull(t, objs, cfgOpts{generation: 1})
	if got := run(t, objs, synPacket()); got != xdpDrop {
		t.Errorf("generation 1: verdict = %s, want XDP_DROP", verdictName(got))
	}
}

/* --------------------------------------------------------------- dry run */

// TestDryRunRewritesRuleDrops: dry run turns a DROP into a PASS at the very
// last moment, AFTER every counter has been bumped. An operator staging a
// policy has to be able to read off exactly what would have been shed, which
// is impossible if the accounting is short-circuited along with the drop.
func TestDryRunRewritesRuleDrops(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 91, action: ActionDrop, dst: &victimIP}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1, dryRun: true})

	if err := EnsureRuleStats(objs.MapSet(), 91); err != nil {
		t.Fatal(err)
	}

	if got := run(t, objs, synPacket()); got != xdpPass {
		t.Errorf("verdict = %s, want XDP_PASS under dry_run", verdictName(got))
	}
	if p, _ := readStat(t, objs, StatDropStatic); p != 1 {
		t.Errorf("drop_static = %d, want 1: dry run must not skip the verdict counter", p)
	}
	if p, _ := readStat(t, objs, StatDryRunWouldDrop); p != 1 {
		t.Errorf("dryrun_would_drop = %d, want 1", p)
	}
	c, ok, err := ReadRuleStats(objs.MapSet(), 91)
	if err != nil || !ok {
		t.Fatalf("read rule_stats: ok=%v err=%v", ok, err)
	}
	if c.Pkts != 1 {
		t.Errorf("rule_stats[91] = %d, want 1: dry run must not skip per-rule accounting", c.Pkts)
	}
}

/* ---------------------------------------------------------- rate limiting */

// putProfile writes a kapkan_profile with the Q32 reciprocals the datapath
// needs. This mirrors exactly what the userspace encoder will have to do:
// intern a rate into a profile with NO division left for the kernel.
func putProfile(t *testing.T, objs *kapkanXDPObjects, id uint32, pps, burstPps, bps, burstBps uint64) {
	t.Helper()
	if err := PutProfile(objs.MapSet(), id, ProfileSpec{
		PPS: pps, BurstPackets: burstPps,
		BytesPerSecond: bps, BurstBytes: burstBps,
	}); err != nil {
		t.Fatalf("write profile %d: %v", id, err)
	}
}

// TestRateLimitPPS: a burst of 2 packets/s at 1 pps admits exactly the burst
// and then denies, because the test runs far faster than one refill interval.
func TestRateLimitPPS(t *testing.T) {
	objs := loadObjects(t)
	putProfile(t, objs, 1, 1 /*pps*/, 2 /*burst*/, 0, 0)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 101, action: ActionRateLimit, profile: 1, dst: &victimIP,
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	var passed, dropped int
	for i := 0; i < 6; i++ {
		if run(t, objs, synPacket()) == xdpPass {
			passed++
		} else {
			dropped++
		}
	}
	if passed != 2 {
		t.Errorf("admitted %d packets, want exactly the burst of 2", passed)
	}
	if dropped != 4 {
		t.Errorf("denied %d packets, want 4", dropped)
	}
	if p, _ := readStat(t, objs, StatPassRLAdmit); p != 2 {
		t.Errorf("pass_rl_admit = %d, want 2", p)
	}
	if p, _ := readStat(t, objs, StatDropRL); p != 4 {
		t.Errorf("drop_rl = %d, want 4", p)
	}
}

// TestRateLimitIsPerSource is the headline capability, and the one thing BGP
// FlowSpec structurally cannot express: FlowSpec's traffic-rate community caps
// an AGGREGATE, so "cap EVERY source at N pps" would need one rule per source.
// One rule here gives each attacker its own independent budget.
func TestRateLimitIsPerSource(t *testing.T) {
	objs := loadObjects(t)
	putProfile(t, objs, 1, 1, 2, 0, 0)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 102, action: ActionRateLimit, profile: 1, dst: &victimIP,
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	// Drain the first source's bucket completely.
	for i := 0; i < 5; i++ {
		run(t, objs, synPacketFrom(attackerIP))
	}
	if got := run(t, objs, synPacketFrom(attackerIP)); got != xdpDrop {
		t.Fatalf("precondition: first source should be exhausted, got %s", verdictName(got))
	}

	// A different source must still have its full burst.
	var passed int
	for i := 0; i < 2; i++ {
		if run(t, objs, synPacketFrom(otherIP)) == xdpPass {
			passed++
		}
	}
	if passed != 2 {
		t.Errorf("second source admitted %d, want its own full burst of 2 "+
			"(buckets are keyed per {victim, source, profile})", passed)
	}
}

// TestRateLimitBPS: the byte ceiling denies on its own, with no pps cap set.
func TestRateLimitBPS(t *testing.T) {
	pkt := synPacket()
	n := uint64(len(pkt))

	objs := loadObjects(t)
	// Burst of exactly two packets' worth of bytes, refilling at 1 byte/s.
	putProfile(t, objs, 2, 0, 0, 1 /*bytes/s*/, 2*n)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 103, action: ActionRateLimit, profile: 2, dst: &victimIP,
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	var passed int
	for i := 0; i < 5; i++ {
		if run(t, objs, pkt) == xdpPass {
			passed++
		}
	}
	if passed != 2 {
		t.Errorf("admitted %d packets, want 2 (a burst of %d bytes at %d bytes each)",
			passed, 2*n, n)
	}
}

// TestRateLimitWhicheverCeilingIsHitFirst: a generous pps cap paired with a
// tight byte cap must still deny, and vice versa. config.RateLimitProfile
// documents both ceilings applying at once.
func TestRateLimitWhicheverCeilingIsHitFirst(t *testing.T) {
	pkt := synPacket()
	n := uint64(len(pkt))

	t.Run("byte ceiling binds", func(t *testing.T) {
		objs := loadObjects(t)
		putProfile(t, objs, 3, 1000000, 1000000, 1, n) // huge pps, 1 packet of bytes
		installStatics(t, objs, 0, mkRule(ruleOpts{
			id: 104, action: ActionRateLimit, profile: 3, dst: &victimIP,
		}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})

		var passed int
		for i := 0; i < 4; i++ {
			if run(t, objs, pkt) == xdpPass {
				passed++
			}
		}
		if passed != 1 {
			t.Errorf("admitted %d, want 1: the byte ceiling should bind", passed)
		}
	})

	t.Run("packet ceiling binds", func(t *testing.T) {
		objs := loadObjects(t)
		putProfile(t, objs, 4, 1, 1, 1000000000, 1000000000) // 1 packet, huge bytes
		installStatics(t, objs, 0, mkRule(ruleOpts{
			id: 105, action: ActionRateLimit, profile: 4, dst: &victimIP,
		}))
		setCfgFull(t, objs, cfgOpts{staticCount: 1})

		var passed int
		for i := 0; i < 4; i++ {
			if run(t, objs, pkt) == xdpPass {
				passed++
			}
		}
		if passed != 1 {
			t.Errorf("admitted %d, want 1: the packet ceiling should bind", passed)
		}
	})
}

// TestRateLimitUnknownProfileFailsOpen: a rule naming a profile userspace never
// wrote must admit, not deny. There is no default-deny anywhere in this
// program, and that includes the rate limiter's error paths.
func TestRateLimitUnknownProfileFailsOpen(t *testing.T) {
	objs := loadObjects(t)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 106, action: ActionRateLimit, profile: 200, dst: &victimIP, // never written
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1})

	for i := 0; i < 3; i++ {
		if got := run(t, objs, synPacket()); got != xdpPass {
			t.Fatalf("verdict = %s, want XDP_PASS for an unknown profile", verdictName(got))
		}
	}
	if p, _ := readStat(t, objs, StatPassRLAdmit); p != 3 {
		t.Errorf("pass_rl_admit = %d, want 3", p)
	}
}

// TestRateLimitDryRun: dry run must show the shed traffic without shedding it.
func TestRateLimitDryRun(t *testing.T) {
	objs := loadObjects(t)
	putProfile(t, objs, 5, 1, 1, 0, 0)
	installStatics(t, objs, 0, mkRule(ruleOpts{
		id: 107, action: ActionRateLimit, profile: 5, dst: &victimIP,
	}))
	setCfgFull(t, objs, cfgOpts{staticCount: 1, dryRun: true})

	for i := 0; i < 3; i++ {
		if got := run(t, objs, synPacket()); got != xdpPass {
			t.Fatalf("packet %d: verdict = %s, want XDP_PASS under dry_run", i, verdictName(got))
		}
	}
	if p, _ := readStat(t, objs, StatDropRL); p != 2 {
		t.Errorf("drop_rl = %d, want 2: dry run must still count what it would have shed", p)
	}
	if p, _ := readStat(t, objs, StatDryRunWouldDrop); p != 2 {
		t.Errorf("dryrun_would_drop = %d, want 2", p)
	}
}

/* ---------------------------------------------------------- benchmarks */

// benchObjs loads the program for a benchmark. It duplicates loadObjects
// rather than sharing it because the *testing.T plumbing (Fatalf, Cleanup,
// the EPERM skip) does not carry over to *testing.B.
func benchObjs(b *testing.B) *kapkanXDPObjects {
	b.Helper()
	var objs kapkanXDPObjects
	if err := loadKapkanXDPObjects(&objs, nil); err != nil {
		b.Skipf("cannot load (needs CAP_BPF): %v", err)
	}
	b.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// benchRun drives the kernel's own repeat loop, which is the same path the
// capacity numbers in the docs come from.
func benchRun(b *testing.B, objs *kapkanXDPObjects, pkt []byte, wantDrop bool) {
	b.Helper()
	b.ResetTimer()
	ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt, Repeat: uint32(b.N)})
	if err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	want := uint32(xdpPass)
	if wantDrop {
		want = xdpDrop
	}
	if ret != want {
		b.Fatalf("verdict = %s, want %s", verdictName(ret), verdictName(want))
	}
}

// benchCfg writes kapkan_cfg without the *testing.T helpers.
func benchCfg(b *testing.B, objs *kapkanXDPObjects, staticCount uint32) {
	b.Helper()
	cfg := kapkanXDPKapkanConfig{
		MapSchemaVersion: MapSchemaVersion,
		PolicyStride:     objs.KapkanPolicies.MaxEntries() / Generations,
		StaticStride:     objs.KapkanStatics.MaxEntries() / Generations,
		StaticCount:      staticCount,
	}
	if err := objs.KapkanCfg.Put(uint32(0), &cfg); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkVictimPolicyWorstCase: the packet is evaluated against a full
// 8-rule policy block and matches only the LAST rule, so the whole unrolled
// scan runs. This is the realistic mitigation hot path.
func BenchmarkVictimPolicyWorstCase(b *testing.B) {
	objs := benchObjs(b)
	benchCfg(b, objs, 0)

	block := kapkanXDPKapkanPolicyBlock{N_rules: RulesPerPolicy}
	for i := 0; i < RulesPerPolicy-1; i++ {
		// Non-matching filler: a protocol the packet is not.
		block.Rules[i] = mkRule(ruleOpts{
			id: uint32(200 + i), action: ActionDrop, dst: &victimIP,
			proto: u8p(47), expires: farFuture,
		})
	}
	block.Rules[RulesPerPolicy-1] = mkRule(ruleOpts{
		id: 299, action: ActionDrop, dst: &victimIP, proto: u8p(6), expires: farFuture,
	})
	stride := objs.KapkanPolicies.MaxEntries() / Generations
	if err := objs.KapkanPolicies.Put(uint32(0)*stride+1, &block); err != nil {
		b.Fatal(err)
	}
	key := kapkanXDPKapkanLpmKeyV4{Prefixlen: 32, Addr: victimIP}
	if err := objs.KapkanVictims4.Put(&key, uint32(1)); err != nil {
		b.Fatal(err)
	}

	benchRun(b, objs, synPacket(), true)
}

// BenchmarkStaticScan measures the cost of the linear static scan at several
// depths. The runtime cost is proportional to static_count, NOT to the 256
// compile-time ceiling — only the verifier pays for the ceiling — and these
// numbers are what prove it.
func BenchmarkStaticScan(b *testing.B) {
	for _, n := range []int{1, 16, 64, 256} {
		b.Run(itoa(uint64(n)), func(b *testing.B) {
			objs := benchObjs(b)
			// All non-matching, so every one of the n rules is examined.
			rules := make([]kapkanXDPKapkanRule, n)
			for i := range rules {
				rules[i] = mkRule(ruleOpts{
					id: uint32(1000 + i), action: ActionDrop,
					dst: &victimIP, proto: u8p(47),
				})
			}
			stride := objs.KapkanStatics.MaxEntries() / Generations
			for i, r := range rules {
				if err := objs.KapkanStatics.Put(uint32(0)*stride+uint32(i), &r); err != nil {
					b.Fatal(err)
				}
			}
			benchCfg(b, objs, uint32(n))
			benchRun(b, objs, synPacket(), false)
		})
	}
}

// BenchmarkRateLimit measures the token-bucket path: an LRU lookup plus the
// Q32 refill arithmetic, on a bucket that always admits.
func BenchmarkRateLimit(b *testing.B) {
	objs := benchObjs(b)
	if err := PutProfile(objs.MapSet(), 1, ProfileSpec{PPS: 1 << 30, BurstPackets: 1 << 30}); err != nil {
		b.Fatal(err)
	}
	r := mkRule(ruleOpts{id: 301, action: ActionRateLimit, profile: 1, dst: &victimIP})
	stride := objs.KapkanStatics.MaxEntries() / Generations
	if err := objs.KapkanStatics.Put(uint32(0)*stride, &r); err != nil {
		b.Fatal(err)
	}
	benchCfg(b, objs, 1)

	benchRun(b, objs, synPacket(), false)
}

// TestTerminalCountersPartitionTraffic pins the counter contract that the API
// and console depend on: every packet bumps exactly ONE terminal counter, so
// the terminal counters sum to the packet count. Observation counters
// (fragments seen, rules found expired, dry-run rewrites, missing policy
// blocks) ride alongside and are excluded — if that split ever breaks, an
// operator's dashboard silently stops adding up.
func TestTerminalCountersPartitionTraffic(t *testing.T) {
	objs := loadObjects(t)
	putProfile(t, objs, 1, 1, 1, 0, 0)
	installStatics(t, objs, 0,
		mkRule(ruleOpts{id: 401, action: ActionDrop, dst: &victimIP, proto: u8p(6), dport: u16p(9999)}),
		mkRule(ruleOpts{id: 402, action: ActionRateLimit, profile: 1, dst: &victimIP, proto: u8p(17)}),
		mkRule(ruleOpts{id: 403, action: ActionDrop, dst: &victimIP, proto: u8p(1), expires: longExpired}),
	)
	setCfgFull(t, objs, cfgOpts{staticCount: 3})
	addPrefix4(t, objs.KapkanAllow4, otherIP, 32)

	// A deliberately varied mix that lands on many different branches.
	pkts := [][]byte{
		synPacket(),                               // pass_default
		synPacketFrom(otherIP),                    // pass_allow_src
		cat(eth(etherTypeARP), make([]byte, 28)),  // pass_not_ip
		cat(eth(etherTypeIPv4), make([]byte, 10)), // pass_malformed
		cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 6, 0, 20), tcp(1, 9999, 0x02)),             // drop_static
		cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0, 16), udp(1, 2, 8), make([]byte, 8)), // rl admit
		cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0, 16), udp(1, 2, 8), make([]byte, 8)), // rl deny
		cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 1, 0, 8), make([]byte, 8)),                 // expired -> default
		cat(eth(etherTypeIPv4), ipv4From(attackerIP, victimIP, 17, 0x00b9, 32), make([]byte, 32)),         // fragment
		cat(eth(etherTypeIPv6), ipv6(6, 20), tcp(1024, 80, 0x02)),                                         // pass_default (v6)
		ipv6ExtChain(9), // pass_exthdr_cap
	}
	for _, p := range pkts {
		run(t, objs, p)
	}

	var terminal, observation uint64
	for s := Stat(0); s < StatMax; s++ {
		p, _ := readStat(t, objs, s)
		if s.IsObservation() {
			observation += p
			continue
		}
		terminal += p
	}
	if terminal != uint64(len(pkts)) {
		t.Errorf("terminal counters sum to %d, want %d (one per packet); counters:%s",
			terminal, len(pkts), dumpStats(t, objs))
	}
	if observation == 0 {
		t.Errorf("no observation counters fired; the mix was supposed to include " +
			"a fragment and an expired rule, so this test is not proving the split")
	}
}
