//go:build linux

package dataplane

// Tests for the map-population helpers themselves: the pure encoders
// (RuleSpec.Encode, ProfileSpec.Encode) and the double-buffer bookkeeping.
//
// These are separate from the packet-path suite on purpose. A packet test can
// only observe "the rule fired" or "it did not", so an encoder that sets the
// wrong bit and a datapath that reads the wrong bit cancel out and both look
// correct. Here the encoded bytes are asserted directly against freeze point
// F6, so a drift on either side has somewhere to fail.
//
// They need no kernel and no privileges — everything except the generation
// tests is pure Go — so they run under `make test` on CI as well as in the
// privileged container.

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad test prefix %q: %v", s, err)
	}
	return p
}

// TestRuleSpecEncodeFields pins the spec-to-struct mapping field by field. The
// "any" flags get the most attention because they are the part most likely to
// be got wrong in a way nothing else notices: a rule that accidentally keeps
// RF_DPORT_ANY matches far MORE traffic than the operator asked for, and the
// only symptom is somebody else's packets disappearing.
func TestRuleSpecEncodeFields(t *testing.T) {
	proto := uint8(17)
	sport := uint16(53)
	dport := uint16(33333)

	cases := []struct {
		name  string
		spec  RuleSpec
		check func(t *testing.T, r Rule)
	}{
		{
			name: "empty spec matches every ipv4 packet",
			spec: RuleSpec{ID: 1, Action: ActionDrop},
			check: func(t *testing.T, r Rule) {
				wantFlags := RuleValid | RuleSrcAny | RuleDstAny |
					RuleProtoAny | RuleSportAny | RuleDportAny
				if r.Flags != wantFlags {
					t.Errorf("flags = %#02x, want %#02x (all-any, valid, v4)", r.Flags, wantFlags)
				}
				if r.Action != uint8(ActionDrop) {
					t.Errorf("action = %d, want %d", r.Action, ActionDrop)
				}
			},
		},
		{
			name: "ipv4 prefixes clear their any bits",
			spec: RuleSpec{
				ID:  2,
				Src: mustPrefix(t, "198.51.100.0/24"),
				Dst: mustPrefix(t, "203.0.113.9/32"),
			},
			check: func(t *testing.T, r Rule) {
				if r.Flags&RuleSrcAny != 0 || r.Flags&RuleDstAny != 0 {
					t.Errorf("flags = %#02x, want SRC_ANY and DST_ANY cleared", r.Flags)
				}
				if r.Flags&RuleIPv6 != 0 {
					t.Errorf("flags = %#02x, want IPV6 clear", r.Flags)
				}
				if r.SrcPrefixlen != 24 || r.DstPrefixlen != 32 {
					t.Errorf("prefix lengths = %d/%d, want 24/32", r.SrcPrefixlen, r.DstPrefixlen)
				}
				if got := r.Src[:4]; got[0] != 198 || got[1] != 51 || got[2] != 100 || got[3] != 0 {
					t.Errorf("src = %v, want 198.51.100.0 left-aligned", got)
				}
				// Everything past the v4 address must stay zero: the datapath
				// reads the 16-byte slot as two u64s.
				for i := 4; i < 16; i++ {
					if r.Src[i] != 0 || r.Dst[i] != 0 {
						t.Fatalf("byte %d of a v4 address is not zero: src=%v dst=%v", i, r.Src, r.Dst)
					}
				}
			},
		},
		{
			name: "host bits are masked off",
			spec: RuleSpec{ID: 3, Dst: netip.PrefixFrom(netip.MustParseAddr("203.0.113.200"), 24)},
			check: func(t *testing.T, r Rule) {
				if r.Dst[3] != 0 {
					t.Errorf("dst = %v, want the /24's host byte masked to 0", r.Dst[:4])
				}
			},
		},
		{
			name: "ipv6 prefix sets the family bit",
			spec: RuleSpec{ID: 4, Dst: mustPrefix(t, "2001:db8::/64"), IPv6: true},
			check: func(t *testing.T, r Rule) {
				if r.Flags&RuleIPv6 == 0 {
					t.Errorf("flags = %#02x, want IPV6 set", r.Flags)
				}
				if r.DstPrefixlen != 64 {
					t.Errorf("dst prefixlen = %d, want 64", r.DstPrefixlen)
				}
				if r.Dst[0] != 0x20 || r.Dst[1] != 0x01 || r.Dst[2] != 0x0d || r.Dst[3] != 0xb8 {
					t.Errorf("dst = %v, want 2001:db8:: in network order", r.Dst)
				}
			},
		},
		{
			name: "proto and ports clear their any bits",
			spec: RuleSpec{ID: 5, Proto: &proto, SrcPort: &sport, DstPort: &dport},
			check: func(t *testing.T, r Rule) {
				if r.Flags&(RuleProtoAny|RuleSportAny|RuleDportAny) != 0 {
					t.Errorf("flags = %#02x, want PROTO/SPORT/DPORT any cleared", r.Flags)
				}
				if r.Proto != 17 || r.Sport != 53 || r.Dport != 33333 {
					t.Errorf("proto/sport/dport = %d/%d/%d, want 17/53/33333", r.Proto, r.Sport, r.Dport)
				}
			},
		},
		{
			name: "protocol 0 is a real protocol, not 'any'",
			// IPv6 hop-by-hop is protocol 0. Encoding it as "any" would turn a
			// narrow rule into one that matches everything, which is exactly
			// the reason the spec uses a pointer here.
			spec: RuleSpec{ID: 6, Proto: new(uint8)},
			check: func(t *testing.T, r Rule) {
				if r.Flags&RuleProtoAny != 0 {
					t.Errorf("flags = %#02x, want PROTO_ANY cleared for proto 0", r.Flags)
				}
				if r.Proto != 0 {
					t.Errorf("proto = %d, want 0", r.Proto)
				}
			},
		},
		{
			name: "MatchTCPFlags sets bitmask semantics",
			spec: RuleSpec{ID: 7}.MatchTCPFlags(0x02),
			check: func(t *testing.T, r Rule) {
				if r.TcpFlags != 0x02 || r.TcpFlagsMask != 0x02 {
					t.Errorf("flags/mask = %#02x/%#02x, want 0x02/0x02 (SYN also matches SYN-ACK)",
						r.TcpFlags, r.TcpFlagsMask)
				}
			},
		},
		{
			name: "MatchTCPFlagsExact widens the mask, not the value",
			spec: RuleSpec{ID: 8}.MatchTCPFlagsExact(0x00),
			check: func(t *testing.T, r Rule) {
				if r.TcpFlags != 0x00 || r.TcpFlagsMask != 0xFF {
					t.Errorf("flags/mask = %#02x/%#02x, want 0x00/0xff (a NULL scan)",
						r.TcpFlags, r.TcpFlagsMask)
				}
			},
		},
		{
			name: "fragment and expiry",
			spec: RuleSpec{ID: 9, Fragment: true, ExpiresAt: 1234567890},
			check: func(t *testing.T, r Rule) {
				if r.Flags&RuleFragment == 0 {
					t.Errorf("flags = %#02x, want FRAGMENT set", r.Flags)
				}
				if r.ExpiresAtNs != 1234567890 {
					t.Errorf("expires_at_ns = %d, want 1234567890", r.ExpiresAtNs)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := tc.spec.Encode()
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if r.Flags&RuleValid == 0 {
				t.Errorf("flags = %#02x, want RF_VALID set: a rule without it is an empty slot", r.Flags)
			}
			if r.RuleId != tc.spec.ID {
				t.Errorf("rule_id = %d, want %d", r.RuleId, tc.spec.ID)
			}
			tc.check(t, r)
		})
	}
}

// TestRuleSpecEncodeRejects covers the encoder bugs that must not reach the
// kernel. Every one of them would otherwise install a rule that either never
// fires or fires on the wrong family, and both failures are silent.
func TestRuleSpecEncodeRejects(t *testing.T) {
	cases := map[string]RuleSpec{
		"unknown action": {ID: 1, Action: Action(9)},
		"flag bits outside the mask": {
			ID: 2, TCPFlags: 0x12, TCPFlagsMask: 0x02,
		},
		"mixed families across src and dst": {
			ID: 3, Src: mustPrefix(t, "198.51.100.0/24"), Dst: mustPrefix(t, "2001:db8::/64"), IPv6: true,
		},
		"IPv6 flag disagrees with a v4 prefix": {
			ID: 4, Dst: mustPrefix(t, "203.0.113.0/24"), IPv6: true,
		},
		"IPv6 flag missing on a v6 prefix": {
			ID: 5, Dst: mustPrefix(t, "2001:db8::/64"),
		},
		"IPv4-mapped IPv6 prefix": {
			ID: 6, Dst: netip.PrefixFrom(netip.MustParseAddr("::ffff:203.0.113.9"), 128), IPv6: true,
		},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := spec.Encode(); err == nil {
				t.Errorf("Encode() error = nil, want a rejection")
			}
		})
	}
}

// TestEncodeRulesNamesTheBadRule: a rule set is encoded as a batch, and a
// failure has to say which entry so the manager's log points at the rule
// rather than at the batch.
func TestEncodeRulesNamesTheBadRule(t *testing.T) {
	_, err := EncodeRules(
		RuleSpec{ID: 1, Action: ActionDrop},
		RuleSpec{ID: 2, Action: Action(200)},
	)
	if err == nil {
		t.Fatal("EncodeRules() error = nil, want a rejection")
	}
	if got := err.Error(); !contains(got, "rule 1 of 2") {
		t.Errorf("error %q does not identify the offending index", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestProfileSpecEncode pins the fixed-point arithmetic that keeps DIVISION
// out of the datapath. The kernel refills a bucket with
// (elapsed_ns * tokens_per_ns) >> 32, so a wrong reciprocal here is a rate
// limiter that is silently off by orders of magnitude.
func TestProfileSpecEncode(t *testing.T) {
	cases := []struct {
		name  string
		spec  ProfileSpec
		check func(t *testing.T, p Profile)
	}{
		{
			name: "pps reciprocal",
			spec: ProfileSpec{PPS: 1_000_000, BurstPackets: 2_000_000},
			check: func(t *testing.T, p Profile) {
				// 1e6 pps is one packet per 1000ns; in Q32 that is
				// 2^32/1000 = 4294967 tokens-per-ns.
				if want := uint64(4294967); p.PktPerNsQ32 != want {
					t.Errorf("pkt_per_ns_q32 = %d, want %d", p.PktPerNsQ32, want)
				}
				if p.NsPerPkt != 1000 {
					t.Errorf("ns_per_pkt = %d, want 1000", p.NsPerPkt)
				}
				if p.BurstPps != 2_000_000 {
					t.Errorf("burst_pps = %d, want the explicit 2000000", p.BurstPps)
				}
			},
		},
		{
			name: "burst defaults to one second of rate",
			spec: ProfileSpec{PPS: 500},
			check: func(t *testing.T, p Profile) {
				if p.BurstPps != 500 {
					t.Errorf("burst_pps = %d, want 500 (one second of the rate)", p.BurstPps)
				}
			},
		},
		{
			name: "a burst is never zero while a rate is set",
			// A zero depth against a non-zero rate denies every packet until
			// the first refill, which is a default-deny arrived at by
			// accident. The charter has none of those.
			spec: ProfileSpec{PPS: 0, BytesPerSecond: 3},
			check: func(t *testing.T, p Profile) {
				if p.BurstBps == 0 {
					t.Error("burst_bps = 0 with a byte rate set: that denies every packet")
				}
			},
		},
		{
			name: "an unset ceiling stays unset",
			spec: ProfileSpec{PPS: 10},
			check: func(t *testing.T, p Profile) {
				if p.RateBps != 0 || p.BytePerNsQ32 != 0 || p.BurstBps != 0 {
					t.Errorf("byte ceiling = %d/%d/%d, want all zero so the datapath skips it",
						p.RateBps, p.BytePerNsQ32, p.BurstBps)
				}
			},
		},
		{
			name: "rate above the Q32 ceiling saturates rather than wrapping",
			// The kernel clamps the reciprocal to 2^32-1 so that
			// delta(<=2^32) * q cannot wrap a u64. That caps the refill at one
			// token per nanosecond. The encoder must not produce something
			// that wraps on the way there either.
			spec: ProfileSpec{BytesPerSecond: 10_000_000_000}, // 80 Gbit/s
			check: func(t *testing.T, p Profile) {
				if p.BytePerNsQ32 == 0 {
					t.Error("byte_per_ns_q32 = 0: the shift wrapped")
				}
				if p.RateBps != 10_000_000_000 {
					t.Errorf("rate_bps = %d, want the requested value preserved for display",
						p.RateBps)
				}
			},
		},
		{
			name: "mbps converts to bytes per second",
			spec: ProfileFromConfig(0, 100), // 100 Mbit/s
			check: func(t *testing.T, p Profile) {
				if want := uint64(12_500_000); p.RateBps != want {
					t.Errorf("rate_bps = %d, want %d bytes/s for 100 Mbit/s", p.RateBps, want)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, tc.spec.Encode())
		})
	}
}

// TestGenerationHelpers covers the double-buffer bookkeeping against the real
// maps: strides derived from the object, the inactive half, and the flip.
func TestGenerationHelpers(t *testing.T) {
	objs := loadObjects(t)
	m := objs.MapSet()

	if err := PutConfig(m, ConfigSpec{}); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadConfig(m)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MapSchemaVersion != MapSchemaVersion {
		t.Errorf("map_schema_version = %d, want %d: a pinned program is only adopted when it matches",
			cfg.MapSchemaVersion, MapSchemaVersion)
	}
	if cfg.PolicyStride != PolicyStride(m) || cfg.StaticStride != StaticStride(m) {
		t.Errorf("strides = %d/%d, want %d/%d from the real map sizes",
			cfg.PolicyStride, cfg.StaticStride, PolicyStride(m), StaticStride(m))
	}
	if got, want := m.KapkanPolicies.MaxEntries(), PolicyStride(m)*Generations; got != want {
		t.Errorf("kapkan_policies max_entries = %d, want %d x %d generations",
			got, PolicyStride(m), Generations)
	}

	inactive, err := InactiveGeneration(m)
	if err != nil {
		t.Fatal(err)
	}
	if inactive != 1 {
		t.Errorf("inactive generation = %d, want 1 while 0 is active", inactive)
	}

	if err := Activate(m, 1, 3); err != nil {
		t.Fatal(err)
	}
	cfg, err = ReadConfig(m)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Generation != 1 || cfg.StaticCount != 3 {
		t.Errorf("after Activate: generation/static_count = %d/%d, want 1/3",
			cfg.Generation, cfg.StaticCount)
	}
	if cfg.MapSchemaVersion != MapSchemaVersion || cfg.PolicyStride != PolicyStride(m) {
		t.Error("Activate clobbered a field it does not own")
	}
	inactive, err = InactiveGeneration(m)
	if err != nil {
		t.Fatal(err)
	}
	if inactive != 0 {
		t.Errorf("inactive generation = %d, want 0 after activating 1", inactive)
	}
}

// TestGenerationHelpersReject covers the out-of-range arguments, all of which
// would otherwise write into another generation's half or past the map.
func TestGenerationHelpersReject(t *testing.T) {
	objs := loadObjects(t)
	m := objs.MapSet()
	if err := PutConfig(m, ConfigSpec{}); err != nil {
		t.Fatal(err)
	}

	if err := PutConfig(m, ConfigSpec{Generation: Generations}); err == nil {
		t.Error("PutConfig accepted an out-of-range generation")
	}
	if err := Activate(m, Generations, 0); err == nil {
		t.Error("Activate accepted an out-of-range generation")
	}
	if err := Activate(m, 0, StaticStride(m)+1); err == nil {
		t.Error("Activate accepted a static_count past the stride")
	}
	if err := PutPolicy(m, 0, 0, make([]Rule, RulesPerPolicy+1)); err == nil {
		t.Errorf("PutPolicy accepted %d rules in a %d-rule block", RulesPerPolicy+1, RulesPerPolicy)
	}
	if err := PutPolicy(m, 0, PolicyStride(m), nil); err == nil {
		t.Error("PutPolicy accepted a policy id past the generation stride")
	}
	if _, err := PutStatics(m, 0, make([]Rule, StaticStride(m)+1)); err == nil {
		t.Error("PutStatics accepted more rules than the stride holds")
	}
}

// TestPutStaticsZeroesTheTail is the load-bearing half of the lossless swap.
//
// Activate cannot be a single atomic store — static_count and generation both
// have to move, and F6 has one count rather than one per generation — so a
// packet in flight can read the new count against the old generation. That is
// only harmless because every slot past a generation's rule set is zeroed, and
// a zeroed slot has KAPKAN_RF_VALID clear so it can never match. Without this,
// growing the rule set would expose whatever a previous, longer set left
// behind: traffic dropped by a rule the operator already removed.
func TestPutStaticsZeroesTheTail(t *testing.T) {
	objs := loadObjects(t)
	m := objs.MapSet()

	long, err := EncodeRules(
		RuleSpec{ID: 1, Action: ActionDrop},
		RuleSpec{ID: 2, Action: ActionDrop},
		RuleSpec{ID: 3, Action: ActionDrop},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PutStatics(m, 0, long); err != nil {
		t.Fatal(err)
	}

	// Now a shorter set in the same half.
	short, err := EncodeRules(RuleSpec{ID: 9, Action: ActionDrop})
	if err != nil {
		t.Fatal(err)
	}
	n, err := PutStatics(m, 0, short)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("PutStatics returned %d, want 1", n)
	}

	for i := uint32(1); i < 3; i++ {
		var r Rule
		if err := m.KapkanStatics.Lookup(i, &r); err != nil {
			t.Fatal(err)
		}
		if r.Flags&RuleValid != 0 {
			t.Errorf("static slot %d still has RF_VALID set (rule_id %d): a stale rule survived a "+
				"shorter reload and would fire on a torn read of static_count", i, r.RuleId)
		}
	}
}

// TestPrefixHelpersRoundTrip checks that the LPM keys the helpers build are the
// ones the datapath looks up — both families, and both list axes. A wrong
// prefixlen or a byte-order slip here is invisible until traffic that should
// have been spared is dropped.
func TestPrefixHelpersRoundTrip(t *testing.T) {
	objs := loadObjects(t)
	m := objs.MapSet()

	v4 := mustPrefix(t, "198.51.100.0/24")
	v6 := mustPrefix(t, "2001:db8::/32")
	if err := AddAllowSource(m, v4); err != nil {
		t.Fatal(err)
	}
	if err := AddAllowSource(m, v6); err != nil {
		t.Fatal(err)
	}
	if err := AddProtectedDestination(m, mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}

	// An LPM trie answers a /32 query from a /24 entry, which is the whole
	// point of storing prefixes rather than addresses.
	var out uint8
	k4 := LPMKeyV4{Prefixlen: 32, Addr: [4]byte{198, 51, 100, 7}}
	if err := m.KapkanAllow4.Lookup(&k4, &out); err != nil {
		t.Errorf("198.51.100.7 not covered by the /24 allowlist entry: %v", err)
	}
	k6 := LPMKeyV6{Prefixlen: 128, Addr: netip.MustParseAddr("2001:db8::dead").As16()}
	if err := m.KapkanAllow6.Lookup(&k6, &out); err != nil {
		t.Errorf("2001:db8::dead not covered by the /32 allowlist entry: %v", err)
	}

	// Removing is idempotent: the manager reconciles toward a desired set and
	// must be safe to run twice.
	if err := DeleteAllowSource(m, v4); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAllowSource(m, v4); err != nil {
		t.Errorf("second DeleteAllowSource returned %v, want nil (absent is not an error)", err)
	}
	if err := m.KapkanAllow4.Lookup(&k4, &out); err == nil {
		t.Error("198.51.100.7 still matches the allowlist after the entry was removed")
	}

	if err := DeleteProtectedDestination(m, mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVictim(m, mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Errorf("DeleteVictim on an absent prefix returned %v, want nil", err)
	}

	// IPv4-mapped IPv6 is rejected everywhere, for the reason spelled out at
	// the top of kapkan_xdp.c: the datapath never normalises families, so a
	// mapped prefix would sit in the v6 trie and never be consulted.
	mapped := netip.PrefixFrom(netip.MustParseAddr("::ffff:198.51.100.7"), 128)
	if err := AddAllowSource(m, mapped); err == nil {
		t.Error("AddAllowSource accepted an IPv4-mapped IPv6 prefix")
	}
	if err := AddVictim(m, mapped, 1); err == nil {
		t.Error("AddVictim accepted an IPv4-mapped IPv6 prefix")
	}
}
