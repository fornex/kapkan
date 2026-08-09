package blockrate

import (
	"net/netip"

	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/pkg/flowgen"
	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

// Capture sizing. These are the three numbers behind every rate the suite
// reports, so they are stated once, here.
//
// attackFrameCount sets the block rate's resolution: at 200 frames one leaked
// frame is 0.005, so the 0.98 floor has four frames of headroom and the 0.95
// floor has ten. legitFrameCount and allowFrameCount are deliberately NOT in
// the thousands, because the false-positive ceiling of 0.001 is below 1/80 —
// which is the point. "At most 0.001" over this baseline can only be satisfied
// by ZERO drops, and a suite that permitted one would be quietly agreeing that
// dropping a customer's traffic is sometimes fine.
const (
	attackFrameCount = 200
	legitFrameCount  = 80
	allowFrameCount  = 25

	// telemetryRecords is the flow records one fixture contributes per round.
	// Kept small because every host fixture feeds ONE engine simultaneously and
	// the per-shard sample ring is finite: a fixture that flooded the ring would
	// evict another fixture's flows and break its classification, which would
	// show up as an unrelated fixture "failing".
	telemetryRecords = 40
	// telemetryPackets and the byte figures are per record, pre-sampling.
	telemetryPackets = 200
)

// Single-vector floods are held to 0.98 and everything else to 0.95. The
// difference is not a hedge: a rate-limited or source-anchored policy admits a
// bounded number of frames BY DESIGN (one per source per burst), and a fixture
// that demanded 0.98 there would be asserting the token bucket does not work.
const (
	blockRateSingleVector = 0.98
	blockRateComposite    = 0.95
	falsePositiveCeiling  = 0.001
)

// Fixtures returns the whole catalog, in a stable order.
//
// Eighteen fixtures, one per vector the classifier can actually name plus the
// four structural shapes that have their own failure modes (a carpet bomb, a
// source flood through the token bucket, a VLAN tag, an IPv6 extension-header
// chain). Nothing here is a vector invented for the suite: every WantClass is
// a constant from internal/engine/classify.go.
func Fixtures() []Fixture {
	return []Fixture{
		udpFloodV4(),
		udpFloodV6(),
		synFloodV4(),
		synFloodV6(),
		amplification("dns_amplification", netip.MustParseAddr("203.0.113.12"),
			flowgen.DNSAmplification, pktgen.DNSAmplification, 53,
			engine.AttackDNSAmplification,
			"A DNS reflection: the rule must narrow to UDP source port 53, so the victim's "+
				"other UDP traffic survives and a DNS response to a NEIGHBOUR is untouched."),
		amplification("ntp_monlist", netip.MustParseAddr("203.0.113.13"),
			flowgen.NTPAmplification, pktgen.NTPMonlist, 123,
			engine.AttackNTPAmplification,
			"An NTP monlist reflection off UDP/123."),
		amplification("cldap_amplification", netip.MustParseAddr("203.0.113.14"),
			flowgen.CLDAPAmplification, pktgen.CLDAPAmplification, 389,
			engine.AttackCLDAPAmplification,
			"A CLDAP reflection off UDP/389."),
		amplification("ssdp_amplification", netip.MustParseAddr("203.0.113.15"),
			flowgen.SSDPAmplification, pktgen.SSDPAmplification, 1900,
			engine.AttackSSDPAmplification,
			"An SSDP reflection off UDP/1900."),
		amplification("memcached_amplification", netip.MustParseAddr("203.0.113.16"),
			flowgen.MemcachedAmplification, pktgen.MemcachedAmplification, 11211,
			engine.AttackMemcachedAmplification,
			"A memcached reflection off UDP/11211, the highest-ratio vector in the set."),
		amplification("chargen_amplification", netip.MustParseAddr("203.0.113.17"),
			flowgen.ChargenAmplification, pktgen.ChargenAmplification, 19,
			engine.AttackChargenAmplification,
			"A chargen reflection off UDP/19."),
		icmpFloodV4(),
		fragmentFloodV4(),
		tcpACKFloodV4(),
		multiVectorMix(),
		sourceFloodRateLimit(),
		vlanTaggedUDPFlood(),
		ipv6ExtHdrUDPFlood(),
		carpetBombV4(),
	}
}

/* ========================================================================= */
/* Volumetric floods                                                          */
/* ========================================================================= */

func udpFloodV4() Fixture {
	victim := netip.MustParseAddr("203.0.113.10")
	attack := attackFrames(pktgen.UDPFlood, victim, attackFrameCount, sourceRange(attackerV4, 32), 512)
	legit := concat(
		tcpFrames(50, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		icmpFrames(10, clientV4, victim, 98),
		udpFrames(20, clientV4, neighbourV4, 0, 53, 300),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "udp_flood_v4",
		Doc: "A generic high-pps UDP flood. The rule narrows to UDP only, so the victim's TCP " +
			"and ICMP keep flowing — the difference between a mitigation and a blackhole.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackUDPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.UDPFlood, victim, telemetryRecords, attackerV4,
			telemetryPackets*512, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func udpFloodV6() Fixture {
	victim := netip.MustParseAddr("2001:db8:cafe::10")
	attack := attackFrames(pktgen.UDPFlood, victim, attackFrameCount, sourceRange(attackerV6, 32), 512)
	legit := concat(
		tcpFrames(50, clientV6, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		icmpFrames(10, clientV6, victim, 118),
		udpFrames(20, clientV6, neighbourV6, 0, 53, 300),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV6))
	return Fixture{
		Name: "udp_flood_v6",
		Doc: "The same flood over IPv6. It is a separate fixture because the datapath keeps the " +
			"families strictly apart — it never normalises ::ffff:a.b.c.d — so an IPv4 rule " +
			"proves nothing about the IPv6 path.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackUDPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.UDPFlood, victim, telemetryRecords, attackerV6,
			telemetryPackets*512, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func synFloodV4() Fixture {
	victim := netip.MustParseAddr("203.0.113.11")
	attack := attackFrames(pktgen.SYNFlood, victim, attackFrameCount, sourceRange(attackerV4, 64), 0)
	legit := synFloodBaseline(victim, clientV4)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "syn_flood_v4",
		Doc: "A TCP SYN flood. The rule is an RFC 8955 tcp-flags BITMASK match, so it also " +
			"catches SYN-ACK — deliberately, and identically at a FlowSpec peer. The baseline " +
			"is therefore established traffic (ACK/PSH) rather than any segment carrying SYN.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackSYNFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.SYNFlood, victim, telemetryRecords, attackerV4,
			telemetryPackets*60, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func synFloodV6() Fixture {
	victim := netip.MustParseAddr("2001:db8:cafe::11")
	attack := attackFrames(pktgen.SYNFlood, victim, attackFrameCount, sourceRange(attackerV6, 64), 0)
	legit := synFloodBaseline(victim, clientV6)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV6))
	return Fixture{
		Name:  "syn_flood_v6",
		Doc:   "The SYN flood over IPv6.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackSYNFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.SYNFlood, victim, telemetryRecords, attackerV6,
			telemetryPackets*60, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

// synFloodBaseline is the legitimate traffic a SYN-flood rule must spare:
// established TCP (no SYN bit anywhere), plus UDP and ICMP, which the rule's
// protocol match excludes outright.
func synFloodBaseline(victim, client netip.Addr) []pktgen.Frame {
	return concat(
		tcpFrames(40, client, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 700),
		udpFrames(30, client, victim, 0, 443, 400),
		icmpFrames(10, client, victim, 98),
	)
}

func icmpFloodV4() Fixture {
	victim := netip.MustParseAddr("203.0.113.18")
	attack := attackFrames(pktgen.ICMPFlood, victim, attackFrameCount, sourceRange(attackerV4, 32), 98)
	legit := concat(
		tcpFrames(40, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		udpFrames(30, clientV4, victim, 0, 443, 400),
		icmpFrames(10, clientV4, neighbourV4, 98),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "icmp_flood_v4",
		Doc: "An ICMP echo flood. The rule narrows to protocol 1, and the baseline includes " +
			"ICMP to a NEIGHBOUR so a rule that widened past the victim would show up as a " +
			"false positive rather than as a better block rate.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackICMPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.ICMPFlood, victim, telemetryRecords, attackerV4,
			telemetryPackets*98, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func fragmentFloodV4() Fixture {
	victim := netip.MustParseAddr("203.0.113.19")
	// pktgen alternates first fragments (MF set, offset 0) with continuations
	// (offset 185, no L4 header). BOTH must be dropped: the datapath sets
	// is_frag for either, and a rule that only caught continuations would leak
	// half the flood.
	attack := attackFrames(pktgen.FragmentFlood, victim, attackFrameCount, sourceRange(attackerV4, 32), 1400)
	legit := concat(
		tcpFrames(40, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		udpFrames(30, clientV4, victim, 0, 443, 400),
		icmpFrames(10, clientV4, victim, 98),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "fragment_flood_v4",
		Doc: "An IPv4 fragment flood, alternating first fragments and continuations. The rule " +
			"matches on the fragment bit alone, with no protocol or port — a continuation " +
			"carries no L4 header, so a rule that needed ports could never fire on one.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackFragmentFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.FragmentFlood, victim, telemetryRecords, attackerV4,
			telemetryPackets*1400, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func tcpACKFloodV4() Fixture {
	victim := netip.MustParseAddr("203.0.113.20")
	attack := attackFrames(pktgen.ACKFlood, victim, attackFrameCount, sourceRange(attackerV4, 64), 0)
	legit := concat(
		udpFrames(40, clientV4, victim, 0, 443, 400),
		icmpFrames(20, clientV4, victim, 98),
		tcpFrames(20, clientV4, neighbourV4, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "tcp_ack_flood_v4",
		Doc: "A TCP ACK flood: TCP-dominant with the pure-SYN share at zero, which is the only " +
			"thing separating it from a SYN flood at the classifier. It must come out as " +
			"tcp_flood (a protocol-wide rule), NOT syn_flood — a misclassification here would " +
			"install a flags rule that never fires and score a block rate of zero.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackTCPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.ACKFlood, victim, telemetryRecords, attackerV4,
			telemetryPackets*60, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

/* ========================================================================= */
/* Amplification                                                              */
/* ========================================================================= */

// amplification builds one reflected-service fixture. All six share a shape
// and differ only in the abused port, so they share a constructor — and the
// port is threaded through from BOTH generators and the expected
// classification, so a fixture cannot silently be built for one port and
// asserted for another.
func amplification(name string, victim netip.Addr, fp flowgen.AttackPattern, pp pktgen.Pattern,
	port uint16, want engine.AttackType, doc string,
) Fixture {
	const respBytes = 1200
	attack := attackFrames(pp, victim, attackFrameCount, sourceRange(attackerV4, 48), respBytes)
	legit := concat(
		// The victim's own UDP, from ports that are not the abused one.
		udpFrames(30, clientV4, victim, 0, 40000, 500),
		tcpFrames(30, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		// A genuine response from the same service to a NEIGHBOUR: identical in
		// every respect except the destination.
		udpFrames(20, clientV4, neighbourV4, port, 40000, respBytes),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: name, Doc: doc,
		Scope: ScopeHost, Victim: victim,
		WantClass: want, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(fp, victim, telemetryRecords, attackerV4,
			telemetryPackets*respBytes, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

/* ========================================================================= */
/* Structural shapes                                                          */
/* ========================================================================= */

func multiVectorMix() Fixture {
	victim := netip.MustParseAddr("203.0.113.21")
	// Three vectors at a third each: no protocol class reaches the classifier's
	// 0.5 dominance gate, so nothing wins and the answer is `mixed`.
	tel := concat3(
		pattern(flowgen.DNSAmplification, victim, 20, attackerV4, telemetryPackets*1200, telemetryPackets),
		pattern(flowgen.ACKFlood, victim, 20, nextAddr(attackerV4, 100), telemetryPackets*60, telemetryPackets),
		pattern(flowgen.ICMPFlood, victim, 20, nextAddr(attackerV4, 150), telemetryPackets*98, telemetryPackets),
	)
	attack := attackFrames(pktgen.MixedVector, victim, attackFrameCount, sourceRange(attackerV4, 32), 0)
	// The rule set for a mixed vector is ANCHOR-ONLY: nothing to the victim
	// survives, by policy. A same-host baseline would therefore be measuring
	// the policy, not the data plane, so the baseline is the neighbours — which
	// is the real question anyway ("did the blast radius stay on one host?").
	legit := concat(
		tcpFrames(40, clientV4, neighbourV4, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		udpFrames(30, clientV4, neighbourV4, 0, 53, 400),
		icmpFrames(10, clientV4, neighbourV4, 98),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "multi_vector_mix",
		Doc: "Three vectors at once, none dominant. The classifier must answer `mixed`, which " +
			"yields an ANCHOR-ONLY rule plus one per reflector port the sample saw — the only " +
			"case where the mitigation is deliberately blunt. The baseline is the victim's " +
			"NEIGHBOURS, so the fixture measures blast radius rather than re-measuring policy.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackMixed, WantRuleCount: 2,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: tel,
		Frames:    frames, Roles: roles,
	}
}

// rateLimitVictim is the host in the rate-limited hostgroup. It is a package
// constant because ConfigYAML has to name the same address.
const rateLimitVictim = "203.0.113.40"

func sourceFloodRateLimit() Fixture {
	victim := netip.MustParseAddr(rateLimitVictim)
	// FOUR sources, evenly weighted, one of them ALLOWLISTED. Even weighting
	// puts the concentration at 1.0 after four rules, above the 0.8 gate, so
	// source anchoring engages deterministically and every source gets a rule —
	// including the allowlisted one. That is the sharp version of the allowlist
	// assertion: a rule NAMES this source, and the kernel must still pass it.
	sources := []netip.Addr{
		nextAddr(attackerV4, 0), nextAddr(attackerV4, 1), nextAddr(attackerV4, 2), AllowV4,
	}
	tel := make([]flow.Flow, 0, telemetryRecords)
	for i := 0; i < telemetryRecords; i++ {
		tel = append(tel, flow.Flow{
			SrcAddr: sources[i%len(sources)], DstAddr: victim,
			SrcPort: uint16(1024 + i), DstPort: 53413, IPProto: 17,
			Bytes: telemetryPackets * 512, Packets: telemetryPackets,
			SamplingRate: 1, Wire: flow.ProtoNetFlow9,
		})
	}

	attack := attackFrames(pktgen.UDPFlood, victim, attackFrameCount, sources[:3], 512)
	// Same vector, same victim, DIFFERENT sources. Sparing these is the entire
	// argument for source anchoring, so they are the baseline.
	legit := concat(
		udpFrames(50, clientV4, victim, 0, 53413, 512),
		tcpFrames(30, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
	)
	allow := attackFrames(pktgen.UDPFlood, victim, allowFrameCount, []netip.Addr{AllowV4}, 512)
	frames, roles := weave(attack, legit, allow)
	return Fixture{
		Name:  "source_flood_ratelimit",
		Group: RateLimitGroup,
		Doc: "A concentrated source flood under a rate_limit + source_anchored policy: the only " +
			"path that reaches the in-kernel token bucket through the real chain. The rules are " +
			"composite {victim, attacker}, the profile is interned from the ban's ceiling, and " +
			"the bucket is keyed per source — so exactly one frame per attacking source is " +
			"admitted and everything else is denied. Legitimate clients of the SAME victim on " +
			"the SAME vector are untouched, which is what source anchoring is for.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackUDPFlood, WantSourceAnchored: true, WantRuleCount: 4,
		// Three admitted frames out of 200 is 0.985, and those three are the
		// bucket working, not the mitigation leaking.
		MinBlockRate: blockRateComposite, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: tel,
		Frames:    frames, Roles: roles,
	}
}

func vlanTaggedUDPFlood() Fixture {
	victim := netip.MustParseAddr("203.0.113.22")
	const vid = 100
	attack := tagVLAN(attackFrames(pktgen.UDPFlood, victim, attackFrameCount, sourceRange(attackerV4, 32), 512), vid)
	legit := concat(
		tagVLAN(tcpFrames(40, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600), vid),
		tcpFrames(20, clientV4, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 600),
		tagVLAN(udpFrames(20, clientV4, neighbourV4, 0, 53, 400), vid),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV4))
	return Fixture{
		Name: "vlan_tagged_udp_flood",
		Doc: "The UDP flood again, but every frame carries an 802.1Q tag. The datapath walks one " +
			"tag; a parser that read the ethertype at a fixed offset would see 0x8100, decide " +
			"the frame is not IP, and pass the entire flood while reporting a healthy filter.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackUDPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.UDPFlood, victim, telemetryRecords, nextAddr(attackerV4, 200),
			telemetryPackets*512, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func ipv6ExtHdrUDPFlood() Fixture {
	victim := netip.MustParseAddr("2001:db8:cafe::12")
	chain := []pktgen.ExtHdr{
		{Type: pktgen.ExtHopByHop, Data: make([]byte, 6)},
		{Type: pktgen.ExtDstOpts, Data: make([]byte, 14)},
		{Type: pktgen.ExtRouting, Data: make([]byte, 22)},
	}
	attack := withExtHdrs(
		attackFrames(pktgen.UDPFlood, victim, attackFrameCount, sourceRange(attackerV6, 32), 512), chain)
	legit := concat(
		withExtHdrs(tcpFrames(40, clientV6, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 700), chain),
		tcpFrames(20, clientV6, victim, 443, pktgen.TCPAck|pktgen.TCPPsh, 700),
		withExtHdrs(udpFrames(20, clientV6, neighbourV6, 0, 53, 500), chain),
	)
	frames, roles := weave(attack, legit, rewriteSource(attack[:allowFrameCount], AllowV6))
	return Fixture{
		Name: "ipv6_exthdr_udp_flood",
		Doc: "An IPv6 UDP flood behind a three-header extension chain (hop-by-hop, destination " +
			"options, routing). The rule matches on protocol and the victim, so the verdict " +
			"depends entirely on the datapath's bounded extension-header walk finding UDP at a " +
			"variable offset. The baseline puts the SAME chain on legitimate TCP, so a walk " +
			"that gave up and passed everything would show as a block rate of zero rather than " +
			"as a clean run.",
		Scope: ScopeHost, Victim: victim,
		WantClass: engine.AttackUDPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: pattern(flowgen.UDPFlood, victim, telemetryRecords, nextAddr(attackerV6, 200),
			telemetryPackets*512, telemetryPackets),
		Frames: frames, Roles: roles,
	}
}

func carpetBombV4() Fixture {
	prefix := CarpetNet
	// Eight hosts inside the /24, each far under any per-host threshold; only
	// the aggregate crosses, and only with the fan-out gate satisfied.
	const hosts = 8
	var tel []flow.Flow
	for h := 0; h < hosts; h++ {
		tel = append(tel, pattern(flowgen.UDPFlood, nextAddr(prefix.Addr(), 10+h),
			telemetryRecords/hosts, nextAddr(attackerV4, h*8),
			telemetryPackets*512, telemetryPackets)...)
	}

	// Frames spread over the same hosts, so the /24 rule is doing prefix work
	// rather than host work.
	var attack, legit []pktgen.Frame
	for h := 0; h < hosts; h++ {
		dst := nextAddr(prefix.Addr(), 10+h)
		attack = append(attack, attackFrames(pktgen.UDPFlood, dst, attackFrameCount/hosts,
			sourceRange(nextAddr(attackerV4, h*8), 8), 512)...)
		legit = append(legit, tcpFrames(legitFrameCount/hosts, clientV4, dst, 443,
			pktgen.TCPAck|pktgen.TCPPsh, 600)...)
	}
	allow := rewriteSource(attack[:allowFrameCount], AllowV4)
	frames, roles := weave(attack, legit, allow)
	return Fixture{
		Name: "carpet_bomb_v4_24",
		Doc: "A carpet bomb: eight hosts in one /24, every one of them under the per-host " +
			"threshold, detected only by the aggregate plus the fan-out gate. The rule anchors " +
			"on the WHOLE /24 but still narrows to the vector, so ordinary TCP to every member " +
			"survives. It runs the SAME end-to-end chain as the other seventeen — carpet " +
			"detection, the fan-out gate, banPrefix's safety rules, generateCarpetRules, " +
			"dataplaneRules and Installer.Install, all reached through carpet.mitigation: " +
			"dataplane — so one kernel rule covering 256 addresses is measured by the same " +
			"block rate, false-positive and allowlist assertions as one covering a single host.",
		Scope: ScopePrefix, Prefix: prefix,
		WantClass: engine.AttackUDPFlood, WantRuleCount: 1,
		MinBlockRate: blockRateSingleVector, MaxFalsePositiveRate: falsePositiveCeiling,
		Telemetry: tel,
		Frames:    frames, Roles: roles,
	}
}

/* ========================================================================= */
/* Small helpers                                                              */
/* ========================================================================= */

func concat(sets ...[]pktgen.Frame) []pktgen.Frame {
	var out []pktgen.Frame
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

func concat3(sets ...[]flow.Flow) []flow.Flow {
	var out []flow.Flow
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// tagVLAN puts a single 802.1Q tag on every frame.
func tagVLAN(frames []pktgen.Frame, vid uint16) []pktgen.Frame {
	for i := range frames {
		frames[i].VLANs = []uint16{vid}
	}
	return frames
}

// withExtHdrs attaches an IPv6 extension chain to every frame.
func withExtHdrs(frames []pktgen.Frame, chain []pktgen.ExtHdr) []pktgen.Frame {
	for i := range frames {
		frames[i].ExtHdrs = chain
	}
	return frames
}
