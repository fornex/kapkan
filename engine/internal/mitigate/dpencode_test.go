package mitigate

// Tests for the FlowSpecRule -> data-plane rule compiler.
//
// These run on EVERY host, macOS included, and that is the reason the compiler
// has no build tag. The alternative — testing it only inside the privileged
// container that `make dataplane-test` spins up — would mean the code that
// decides which packets get dropped is exercised by whichever developer
// remembered to run the container target.
//
// The centrepiece is TestEncodersAgree. Everything else here checks one encoder
// against a table; that one checks the two encoders against EACH OTHER, through
// gobgp's own component types, which is the only way to catch the failure that
// actually matters: a rule that means one thing to an upstream peer and another
// thing to this kernel, under one ban record that claims they are the same.

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const testTTL = 5 * time.Minute

func mustCompile(t *testing.T, rules ...FlowSpecRule) dataplane.DynamicRules {
	t.Helper()
	set, err := dataplaneRules(rules, testTTL)
	if err != nil {
		t.Fatalf("dataplaneRules(%v): %v", rules, err)
	}
	return set
}

// encodeOne compiles a single rule all the way to the kernel struct, which is
// what the datapath actually reads. Asserting on RuleSpec alone would leave the
// flag arithmetic — where "any" lives — untested.
func encodeOne(t *testing.T, r FlowSpecRule) dataplane.Rule {
	t.Helper()
	set := mustCompile(t, r)
	out, err := dataplane.EncodeRules(set.Specs...)
	if err != nil {
		t.Fatalf("EncodeRules(%v): %v", r, err)
	}
	return out[0]
}

/* ------------------------------------------------------------- the mapping */

// TestDataplaneRuleMapping walks the mapping table in dpencode.go's header
// field by field, in both directions: the fields the rule names must be set
// with their ANY bit cleared, and the fields it does not name must keep it.
func TestDataplaneRuleMapping(t *testing.T) {
	victim4 := netip.MustParsePrefix("203.0.113.9/32")
	victim6 := netip.MustParsePrefix("2001:db8::9/128")
	attacker4 := netip.MustParsePrefix("198.51.100.7/32")

	cases := []struct {
		name  string
		in    FlowSpecRule
		check func(t *testing.T, r dataplane.Rule)
	}{
		{
			name: "victim-anchored discard: dst pinned, everything else any",
			in:   FlowSpecRule{Dst: victim4, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				wantFlags := dataplane.RuleValid | dataplane.RuleSrcAny |
					dataplane.RuleProtoAny | dataplane.RuleSportAny | dataplane.RuleDportAny
				if r.Flags != wantFlags {
					t.Errorf("flags = %#02x, want %#02x", r.Flags, wantFlags)
				}
				if got := netip.AddrFrom4([4]byte(r.Dst[:4])); got != victim4.Addr() {
					t.Errorf("dst = %s, want %s", got, victim4.Addr())
				}
				if r.DstPrefixlen != 32 {
					t.Errorf("dst prefixlen = %d, want 32", r.DstPrefixlen)
				}
				if r.Action != uint8(dataplane.ActionDrop) {
					t.Errorf("action = %d, want drop", r.Action)
				}
			},
		},
		{
			name: "amplification: udp + reflected source port",
			in:   FlowSpecRule{Dst: victim4, Proto: 17, SrcPort: 123, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Flags&dataplane.RuleProtoAny != 0 || r.Proto != 17 {
					t.Errorf("proto = %d flags %#02x, want 17 with PROTO_ANY clear", r.Proto, r.Flags)
				}
				if r.Flags&dataplane.RuleSportAny != 0 || r.Sport != 123 {
					t.Errorf("sport = %d flags %#02x, want 123 with SPORT_ANY clear", r.Sport, r.Flags)
				}
				if r.Flags&dataplane.RuleDportAny == 0 {
					t.Error("DPORT_ANY cleared for a rule that names no destination port")
				}
			},
		},
		{
			name: "syn flood: RFC 8955 bitmask, so flags == mask",
			in:   FlowSpecRule{Dst: victim4, Proto: 6, TCPFlags: tcpSYN, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.TcpFlags != tcpSYN || r.TcpFlagsMask != tcpSYN {
					t.Errorf("tcp flags/mask = %#02x/%#02x, want %#02x/%#02x "+
						"(bitmask semantics: every bit in the value must be set in the packet)",
						r.TcpFlags, r.TcpFlagsMask, tcpSYN, tcpSYN)
				}
				// The property the mask buys, spelled out: a SYN-ACK matches.
				if got := uint8(0x12) & r.TcpFlagsMask; got != r.TcpFlags {
					t.Errorf("SYN-ACK (0x12) & mask %#02x = %#02x, want %#02x — a SYN rule must "+
						"also catch SYN-ACK, exactly as it does at a FlowSpec peer",
						r.TcpFlagsMask, got, r.TcpFlags)
				}
			},
		},
		{
			name: "fragment flood",
			in:   FlowSpecRule{Dst: victim4, Fragment: true, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Flags&dataplane.RuleFragment == 0 {
					t.Error("RF_FRAGMENT not set for a fragment rule")
				}
			},
		},
		{
			name: "no fragment component means the rule is indifferent",
			in:   FlowSpecRule{Dst: victim4, Proto: 17, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Flags&dataplane.RuleFragment != 0 {
					t.Error("RF_FRAGMENT set on a rule that never named fragments; it would " +
						"stop matching whole datagrams")
				}
			},
		},
		{
			name: "source-anchored composite: both ends pinned",
			in:   FlowSpecRule{Dst: victim4, Src: attacker4, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Flags&dataplane.RuleSrcAny != 0 || r.Flags&dataplane.RuleDstAny != 0 {
					t.Errorf("flags %#02x still say 'any' for a rule naming both ends", r.Flags)
				}
				if got := netip.AddrFrom4([4]byte(r.Src[:4])); got != attacker4.Addr() {
					t.Errorf("src = %s, want %s", got, attacker4.Addr())
				}
			},
		},
		{
			name: "outgoing attack: the victim is the SOURCE",
			in:   FlowSpecRule{Src: victim4, Proto: 17, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Flags&dataplane.RuleDstAny == 0 {
					t.Error("DST_ANY cleared on a source-anchored rule")
				}
				if got := netip.AddrFrom4([4]byte(r.Src[:4])); got != victim4.Addr() {
					t.Errorf("src = %s, want %s", got, victim4.Addr())
				}
			},
		},
		{
			name: "IPv6 victim sets the family bit",
			in:   FlowSpecRule{Dst: victim6, Proto: 58, Action: config.FlowSpecDiscard},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Flags&dataplane.RuleIPv6 == 0 {
					t.Error("RF_IPV6 not set for an IPv6 victim; the rule would never match")
				}
				if got := netip.AddrFrom16(r.Dst); got != victim6.Addr() {
					t.Errorf("dst = %s, want %s", got, victim6.Addr())
				}
			},
		},
		{
			name: "rate limit becomes the ratelimit action",
			in:   FlowSpecRule{Dst: victim4, Action: config.FlowSpecRateLimit, RateBytes: 1_250_000},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Action != uint8(dataplane.ActionRateLimit) {
					t.Errorf("action = %d, want ratelimit", r.Action)
				}
			},
		},
		{
			name: "rate_limit at rate 0 is a discard, exactly as on the wire",
			in:   FlowSpecRule{Dst: victim4, Action: config.FlowSpecRateLimit, RateBytes: 0},
			check: func(t *testing.T, r dataplane.Rule) {
				if r.Action != uint8(dataplane.ActionDrop) {
					t.Errorf("action = %d, want drop: RFC 8955 traffic-rate 0 means discard, and a "+
						"profile capping nothing would ADMIT here — the opposite of what the peer does", r.Action)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, encodeOne(t, tc.in))
		})
	}
}

// TestDataplaneRateAndTTL checks the two fields that ride beside the specs.
func TestDataplaneRateAndTTL(t *testing.T) {
	victim := netip.MustParsePrefix("203.0.113.9/32")

	set := mustCompile(t, FlowSpecRule{Dst: victim, Action: config.FlowSpecRateLimit, RateBytes: 1_250_000})
	if set.RateBytesPerSecond != 1_250_000 {
		t.Errorf("rate = %d, want 1250000", set.RateBytesPerSecond)
	}
	if set.TTL != testTTL {
		t.Errorf("ttl = %s, want %s", set.TTL, testTTL)
	}

	set = mustCompile(t, FlowSpecRule{Dst: victim, Action: config.FlowSpecDiscard})
	if set.RateBytesPerSecond != 0 {
		t.Errorf("a discard rule set asked for rate %d, want 0", set.RateBytesPerSecond)
	}
}

// TestCompilerLeavesAllocationAlone pins the split of responsibility between
// the compiler and the installer. If the compiler ever starts filling these in,
// the installer's overwrite would silently discard them and a reader of this
// package would have two plausible sources of truth for a rule id.
func TestCompilerLeavesAllocationAlone(t *testing.T) {
	set := mustCompile(t,
		FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.9/32"), Action: config.FlowSpecRateLimit, RateBytes: 100},
		FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.9/32"), Proto: 6, Action: config.FlowSpecRateLimit, RateBytes: 100},
	)
	for i, s := range set.Specs {
		if s.ID != 0 || s.Profile != 0 || s.ExpiresAt != 0 {
			t.Errorf("spec %d carries allocation the installer owns: id=%d profile=%d expires=%d",
				i, s.ID, s.Profile, s.ExpiresAt)
		}
	}
}

/* ---------------------------------------------------------- the refusals */

// TestDataplaneEncoderRejects covers every refusal, because each one exists to
// stop a rule that would be WIDER than what the operator's ban record says.
func TestDataplaneEncoderRejects(t *testing.T) {
	victim := netip.MustParsePrefix("203.0.113.9/32")

	cases := []struct {
		name  string
		rules []FlowSpecRule
	}{
		{
			name:  "no rules at all",
			rules: nil,
		},
		{
			name: "a rule anchored on nothing would match every packet of its family",
			rules: []FlowSpecRule{
				{Proto: 6, Action: config.FlowSpecDiscard},
			},
		},
		{
			name: "unknown action (the zero FlowSpecAction is not discard)",
			rules: []FlowSpecRule{
				{Dst: victim},
			},
		},
		{
			name: "a rate that is not a number",
			rules: []FlowSpecRule{
				{Dst: victim, Action: config.FlowSpecRateLimit, RateBytes: math.NaN()},
			},
		},
		{
			name: "an infinite rate",
			rules: []FlowSpecRule{
				{Dst: victim, Action: config.FlowSpecRateLimit, RateBytes: math.Inf(1)},
			},
		},
		{
			name: "two rates in one ban would need two profiles",
			rules: []FlowSpecRule{
				{Dst: victim, Action: config.FlowSpecRateLimit, RateBytes: 100},
				{Dst: victim, Proto: 6, Action: config.FlowSpecRateLimit, RateBytes: 200},
			},
		},
		{
			name:  "more rules than a policy block holds",
			rules: tooManyRules(victim),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if set, err := dataplaneRules(tc.rules, testTTL); err == nil {
				t.Fatalf("accepted %v, compiling to %d specs; the caller would install a rule "+
					"that does not mean what the ban record says", tc.rules, len(set.Specs))
			}
		})
	}
}

func tooManyRules(victim netip.Prefix) []FlowSpecRule {
	out := make([]FlowSpecRule, dataplane.RulesPerPolicy+1)
	for i := range out {
		p := uint16(1000 + i)
		out[i] = FlowSpecRule{Dst: victim, Proto: 17, SrcPort: p, Action: config.FlowSpecDiscard}
	}
	return out
}

// TestDataplaneEncoderRejectsMappedIPv6 checks the refusal that lives one layer
// down, in RuleSpec.Encode, because the compiler must not paper over it: the
// datapath never normalises ::ffff:a.b.c.d, so an accepted mapped prefix would
// be a rule that silently matches nothing.
func TestDataplaneEncoderRejectsMappedIPv6(t *testing.T) {
	mapped := netip.MustParsePrefix("::ffff:203.0.113.9/128")
	set, err := dataplaneRules([]FlowSpecRule{{Dst: mapped, Action: config.FlowSpecDiscard}}, testTTL)
	if err != nil {
		return // rejected already; fine
	}
	if _, err := dataplane.EncodeRules(set.Specs...); err == nil {
		t.Fatal("an IPv4-mapped IPv6 prefix compiled and encoded; the datapath never normalises " +
			"those, so the rule would match nothing and the ban would claim it does")
	}
}

/* ------------------------------------------------- the two encoders agree */

// TestEncodersAgree builds the BGP FlowSpec NLRI and the kernel rule from the
// SAME FlowSpecRule and checks that they select the same packets, component by
// component.
//
// It is deliberately exhaustive in both directions: every component gobgp emits
// must have a matching non-"any" field in the kernel rule, AND every non-"any"
// field in the kernel rule must have a matching component. A one-directional
// check would miss the more dangerous half — a kernel rule that is WIDER than
// the FlowSpec one, dropping traffic the upstream would have passed.
func TestEncodersAgree(t *testing.T) {
	rules := []FlowSpecRule{
		{Dst: netip.MustParsePrefix("203.0.113.9/32"), Action: config.FlowSpecDiscard},
		{Dst: netip.MustParsePrefix("203.0.113.9/32"), Proto: 17, SrcPort: 123, Action: config.FlowSpecDiscard},
		{Dst: netip.MustParsePrefix("203.0.113.9/32"), Proto: 6, TCPFlags: tcpSYN, Action: config.FlowSpecDiscard},
		{Dst: netip.MustParsePrefix("203.0.113.9/32"), Fragment: true, Action: config.FlowSpecDiscard},
		{Dst: netip.MustParsePrefix("203.0.113.9/32"), Proto: 6, DstPort: 443, Action: config.FlowSpecDiscard},
		{
			Dst: netip.MustParsePrefix("203.0.113.9/32"), Src: netip.MustParsePrefix("198.51.100.7/32"),
			Action: config.FlowSpecDiscard,
		},
		{Src: netip.MustParsePrefix("203.0.113.88/32"), Proto: 17, Action: config.FlowSpecDiscard},
		{Dst: netip.MustParsePrefix("2001:db8::9/128"), Proto: 58, Action: config.FlowSpecDiscard},
		{
			Dst: netip.MustParsePrefix("2001:db8::9/128"), Proto: 6, TCPFlags: tcpSYN,
			Action: config.FlowSpecRateLimit, RateBytes: 1_250_000,
		},
		{Dst: netip.MustParsePrefix("198.51.100.0/24"), Proto: 17, SrcPort: 11211, Action: config.FlowSpecDiscard},
	}

	for _, r := range rules {
		t.Run(r.String(), func(t *testing.T) {
			kernel := encodeOne(t, r)
			comps := flowSpecComponents(t, r)

			seen := map[bgp.BGPFlowSpecType]bool{}
			for _, c := range comps {
				seen[c.Type()] = true
				checkComponentAgrees(t, c, kernel)
			}

			// The other direction: a kernel field that is not "any" but has no
			// component would be a rule narrower or wider than the peer's.
			assertAnyMatchesComponent(t, kernel, seen)
		})
	}
}

// flowSpecComponents runs a rule through the real BGP encoder and decodes the
// components back out, so the comparison is against what a peer would receive
// rather than against the intermediate values this package built.
func flowSpecComponents(t *testing.T, r FlowSpecRule) []bgp.FlowSpecComponentInterface {
	t.Helper()
	any, family, err := flowSpecNLRI(r)
	if err != nil {
		t.Fatalf("flowSpecNLRI(%v): %v", r, err)
	}
	// The AFI the peer sees must match the family bit the kernel rule carries,
	// or the two backends disagree about which packets exist at all.
	wantV6 := family == familyV6FS
	if gotV6 := encodeOne(t, r).Flags&dataplane.RuleIPv6 != 0; gotV6 != wantV6 {
		t.Fatalf("FlowSpec family is v6=%v but the kernel rule says v6=%v", wantV6, gotV6)
	}
	var nlri api.FlowSpecNLRI
	if err := any.UnmarshalTo(&nlri); err != nil {
		t.Fatalf("unmarshal FlowSpecNLRI: %v", err)
	}
	comps, err := apiutil.UnmarshalFlowSpecRules(nlri.Rules)
	if err != nil {
		t.Fatalf("UnmarshalFlowSpecRules: %v", err)
	}
	return comps
}

func checkComponentAgrees(t *testing.T, c bgp.FlowSpecComponentInterface, k dataplane.Rule) {
	t.Helper()
	switch v := c.(type) {
	case *bgp.FlowSpecDestinationPrefix:
		assertPrefix(t, "dst", v.Prefix.String(), k.Dst[:], k.DstPrefixlen, k.Flags&dataplane.RuleDstAny)
	case *bgp.FlowSpecSourcePrefix:
		assertPrefix(t, "src", v.Prefix.String(), k.Src[:], k.SrcPrefixlen, k.Flags&dataplane.RuleSrcAny)
	case *bgp.FlowSpecDestinationPrefix6:
		assertPrefix(t, "dst", v.Prefix.String(), k.Dst[:], k.DstPrefixlen, k.Flags&dataplane.RuleDstAny)
	case *bgp.FlowSpecSourcePrefix6:
		assertPrefix(t, "src", v.Prefix.String(), k.Src[:], k.SrcPrefixlen, k.Flags&dataplane.RuleSrcAny)
	case *bgp.FlowSpecComponent:
		if len(v.Items) != 1 {
			t.Fatalf("component %s has %d items; the encoder emits exactly one", v.Type(), len(v.Items))
		}
		item := v.Items[0]
		switch v.Type() {
		case bgp.FLOW_SPEC_TYPE_IP_PROTO:
			assertNumeric(t, "proto", item.Value, uint64(k.Proto), k.Flags&dataplane.RuleProtoAny)
		case bgp.FLOW_SPEC_TYPE_SRC_PORT:
			assertNumeric(t, "sport", item.Value, uint64(k.Sport), k.Flags&dataplane.RuleSportAny)
		case bgp.FLOW_SPEC_TYPE_DST_PORT:
			assertNumeric(t, "dport", item.Value, uint64(k.Dport), k.Flags&dataplane.RuleDportAny)
		case bgp.FLOW_SPEC_TYPE_TCP_FLAG:
			if item.Op&bgp.BITMASK_FLAG_OP_MATCH == 0 {
				t.Errorf("tcp-flag component op %#02x lacks the MATCH bit; without it the peer "+
					"tests 'any of these bits' while the kernel tests 'all of them'", item.Op)
			}
			if item.Value != uint64(k.TcpFlags) || uint64(k.TcpFlagsMask) != item.Value {
				t.Errorf("tcp flags: peer matches %#02x, kernel matches %#02x under mask %#02x",
					item.Value, k.TcpFlags, k.TcpFlagsMask)
			}
		case bgp.FLOW_SPEC_TYPE_FRAGMENT:
			if k.Flags&dataplane.RuleFragment == 0 {
				t.Error("the peer gets a fragment component but the kernel rule is fragment-indifferent")
			}
		default:
			t.Errorf("unhandled component type %s: the two encoders may have diverged", v.Type())
		}
	default:
		t.Errorf("unhandled component %T", c)
	}
}

// assertAnyMatchesComponent is the reverse direction: a kernel field the rule
// pins must correspond to a component the peer received.
func assertAnyMatchesComponent(t *testing.T, k dataplane.Rule, seen map[bgp.BGPFlowSpecType]bool) {
	t.Helper()
	for _, c := range []struct {
		what    string
		pinned  bool
		compTyp bgp.BGPFlowSpecType
	}{
		{"dst prefix", k.Flags&dataplane.RuleDstAny == 0, bgp.FLOW_SPEC_TYPE_DST_PREFIX},
		{"src prefix", k.Flags&dataplane.RuleSrcAny == 0, bgp.FLOW_SPEC_TYPE_SRC_PREFIX},
		{"proto", k.Flags&dataplane.RuleProtoAny == 0, bgp.FLOW_SPEC_TYPE_IP_PROTO},
		{"src port", k.Flags&dataplane.RuleSportAny == 0, bgp.FLOW_SPEC_TYPE_SRC_PORT},
		{"dst port", k.Flags&dataplane.RuleDportAny == 0, bgp.FLOW_SPEC_TYPE_DST_PORT},
		{"tcp flags", k.TcpFlagsMask != 0, bgp.FLOW_SPEC_TYPE_TCP_FLAG},
		{"fragment", k.Flags&dataplane.RuleFragment != 0, bgp.FLOW_SPEC_TYPE_FRAGMENT},
	} {
		if c.pinned && !seen[c.compTyp] {
			t.Errorf("the kernel rule pins %s but the peer got no %s component: the kernel rule is "+
				"NARROWER than the announced one", c.what, c.compTyp)
		}
		if !c.pinned && seen[c.compTyp] {
			t.Errorf("the peer got a %s component but the kernel rule says 'any' for %s: the kernel "+
				"rule is WIDER than the announced one and would drop traffic the upstream passes",
				c.compTyp, c.what)
		}
	}
}

func assertPrefix(t *testing.T, what, wire string, kernel []byte, bits uint8, anyBit uint8) {
	t.Helper()
	if anyBit != 0 {
		t.Errorf("%s: the peer got a prefix but the kernel rule says 'any'", what)
		return
	}
	want, err := netip.ParsePrefix(wire)
	if err != nil {
		t.Fatalf("parse wire prefix %q: %v", wire, err)
	}
	var got netip.Addr
	if want.Addr().Is4() {
		got = netip.AddrFrom4([4]byte(kernel[:4]))
	} else {
		got = netip.AddrFrom16([16]byte(kernel[:16]))
	}
	if netip.PrefixFrom(got, int(bits)) != want {
		t.Errorf("%s: peer has %s, kernel has %s", what, want, netip.PrefixFrom(got, int(bits)))
	}
}

func assertNumeric(t *testing.T, what string, wire, kernel uint64, anyBit uint8) {
	t.Helper()
	if anyBit != 0 {
		t.Errorf("%s: the peer matches %d but the kernel rule says 'any'", what, wire)
		return
	}
	if wire != kernel {
		t.Errorf("%s: peer matches %d, kernel matches %d", what, wire, kernel)
	}
}

/* ------------------------------------------- the generator feeds them both */

// TestGeneratedRulesCompile runs every rule set generateRules can produce
// through the compiler. The generator is shared with the FlowSpec backend and
// predates this one, so the real risk is not a bad mapping but a shape the
// compiler refuses — which would degrade every ban of that attack type to a
// blackhole, quietly, for one class of attack.
func TestGeneratedRulesCompile(t *testing.T) {
	victim := netip.MustParseAddr("203.0.113.9")
	victim6 := netip.MustParseAddr("2001:db8::9")

	for _, tc := range attackShapes() {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range []netip.Addr{victim, victim6} {
				rules := generateRules(target, tc.dir, tc.cls, tc.sample,
					config.FlowSpecDiscard, 0, tc.srcAnchored, 0.8)
				if len(rules) == 0 {
					t.Fatalf("generateRules produced nothing for %s/%s", tc.name, target)
				}
				set, err := dataplaneRules(rules, testTTL)
				if err != nil {
					t.Fatalf("compiling %s rules for %s failed, so every ban of this attack type "+
						"would fall back to a blackhole: %v", tc.name, target, err)
				}
				if _, err := dataplane.EncodeRules(set.Specs...); err != nil {
					t.Fatalf("encoding %s rules for %s failed: %v", tc.name, target, err)
				}
			}
		})
	}
}

// TestDynamicRulesNeverSetMatchExt holds the static-only line on the extended
// match axis.
//
// dataplane.Rule.MatchExt has no mitigate.FlowSpecRule counterpart, because
// RFC 8955 has no component for a payload predicate. That asymmetry is fine
// while only the config file can set one — but a generated rule that carried
// it would mean the two encoders no longer agree: the same ban would drop one
// set of packets in this box's kernel and ask a FlowSpec peer to drop a wider
// one, and the ladder's dataplane→flowspec escalation would silently widen the
// blast radius at the moment it fires. Nothing in dpencode.go sets the field
// today; this is what notices when something starts to.
func TestDynamicRulesNeverSetMatchExt(t *testing.T) {
	victim := netip.MustParseAddr("203.0.113.9")
	victim6 := netip.MustParseAddr("2001:db8::9")

	for _, tc := range attackShapes() {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range []netip.Addr{victim, victim6} {
				for _, act := range []config.FlowSpecAction{config.FlowSpecDiscard, config.FlowSpecRateLimit} {
					var rate float64
					if act == config.FlowSpecRateLimit {
						rate = 125_000
					}
					rules := generateRules(target, tc.dir, tc.cls, tc.sample, act, rate, tc.srcAnchored, 0.8)
					set, err := dataplaneRules(rules, testTTL)
					if err != nil {
						t.Fatalf("compiling %s rules for %s: %v", tc.name, target, err)
					}
					for i, spec := range set.Specs {
						if spec.MatchExt != 0 {
							t.Errorf("spec %d of %s/%s carries match_ext %#02x; the data plane "+
								"would then select different packets than the FlowSpec peer given "+
								"the same ban", i, tc.name, target, spec.MatchExt)
						}
					}
				}
			}
		})
	}
}

func attackShapes() []struct {
	name        string
	dir         engine.Direction
	cls         *engine.Classification
	sample      *engine.AttackSample
	srcAnchored bool
} {
	sample := &engine.AttackSample{
		TotalPackets: 100,
		TopSources: []engine.Counter{
			{Key: "198.51.100.7", Packets: 90},
		},
		TopSrcPorts: []engine.Counter{{Key: "123", Packets: 90}},
	}
	sample6 := &engine.AttackSample{
		TotalPackets: 100,
		TopSources:   []engine.Counter{{Key: "2001:db8::7", Packets: 90}},
	}
	var out []struct {
		name        string
		dir         engine.Direction
		cls         *engine.Classification
		sample      *engine.AttackSample
		srcAnchored bool
	}
	add := func(name string, dir engine.Direction, typ engine.AttackType, s *engine.AttackSample, anchored bool) {
		var cls *engine.Classification
		if typ != "" {
			cls = &engine.Classification{Type: typ}
		}
		out = append(out, struct {
			name        string
			dir         engine.Direction
			cls         *engine.Classification
			sample      *engine.AttackSample
			srcAnchored bool
		}{name, dir, cls, s, anchored})
	}
	for _, typ := range []engine.AttackType{
		engine.AttackNTPAmplification, engine.AttackDNSAmplification,
		engine.AttackCLDAPAmplification, engine.AttackMemcachedAmplification,
		engine.AttackSSDPAmplification, engine.AttackChargenAmplification,
		engine.AttackSYNFlood, engine.AttackFragmentFlood, engine.AttackICMPFlood,
		engine.AttackUDPFlood, engine.AttackTCPFlood, "",
	} {
		name := string(typ)
		if name == "" {
			name = "unclassified"
		}
		add(name, engine.DirIncoming, typ, sample, false)
	}
	add("outgoing", engine.DirOutgoing, engine.AttackUDPFlood, sample, false)
	add("source-anchored-v4", engine.DirIncoming, engine.AttackUDPFlood, sample, true)
	add("source-anchored-v6", engine.DirIncoming, engine.AttackUDPFlood, sample6, true)
	add("no sample", engine.DirIncoming, "", nil, false)
	return out
}
