package dataplane

// This file is the Go half of freeze point F6. Every constant here mirrors one
// in engine/bpf/include/kapkan_maps.h, and TestContractMatchesC re-reads that
// header and fails if the two ever disagree. Nothing in this file may be
// changed without changing the header (and, for a layout change, bumping
// MapSchemaVersion).
//
// It deliberately imports nothing: the encoder, the manager and the tests all
// need these values, and several of them run on hosts where the kernel side
// cannot even be loaded.

// MapSchemaVersion is written into kapkan_cfg[0].map_schema_version at attach.
// A binary that finds an already-pinned program ADOPTS it only when the pinned
// value equals this one; otherwise it tears the pins down and recreates them,
// because the map layouts would be reinterpreted wrongly. Bump this on any
// incompatible change to a struct in kapkan_maps.h.
//
// 2: E2 added the kapkan_fp_events ring buffer and kapkan_fp_sampler maps and
// appended the fp_* fields to kapkan_config. New maps and a changed kapkan_config
// layout both require a previous process's pins to be rebuilt rather than
// adopted.
const MapSchemaVersion = 2

// RulesPerPolicy is the number of match rules in one victim's policy block. It
// mirrors both KAPKAN_RULES_PER_POLICY in C and config.maxDataplaneRulesPerBan
// (a ban installs at most this many rules), so a whole ban fits in one block
// and the datapath needs a single map lookup to evaluate it.
const RulesPerPolicy = 8

// MaxIPv6ExtHdrs is how many IPv6 extension headers the datapath's parser walks
// before it gives up. It mirrors KAPKAN_MAX_EXT_HDRS in bpf/kapkan_xdp.c.
//
// It is a SECURITY-RELEVANT number, not a tuning knob, and that is why it is
// restated on this side of the boundary instead of being left in C where only
// the verifier ever reads it. A packet carrying this many extension headers is
// passed on WITHOUT ANY RULE BEING EVALUATED — see BypassReason — so this
// constant is the exact width of the datapath's blind spot, and
// TestIPv6ExtHdrCapBoundary pins it against the compiled object in both
// directions so it cannot move without somebody noticing.
const MaxIPv6ExtHdrs = 8

// Generations is the double-buffer depth of kapkan_policies and
// kapkan_statics. Userspace fills the inactive half, then flips
// kapkan_cfg[0].generation so a packet sees either the whole old rule set or
// the whole new one. It costs 2x the map memory; that is the price of a
// lossless policy swap.
const Generations = 2

// Default and fixed map sizings.
//
// The three Default* values are what the ELF is compiled with AND what
// config's defaultMax* constants resolve to when the operator names no limits.
// They agree by hand in three places (this file, kapkan_maps.h, config.go), so
// TestContractMatchesC and TestDefaultLimitsMatchConfig gate all three.
//
// The Manager REWRITES the first three (and defaultMaxRuleStats, which is
// derived from them) on the CollectionSpec before the maps are created, so an
// operator who lowers dataplane.limits.max_ratelimit_sources actually gets a
// smaller LRU rather than paying for the compiled-in 1M entries. See
// Limits.MapSizing.
const (
	// DefaultMaxDynamicRules mirrors config.defaultMaxDynamicRules.
	DefaultMaxDynamicRules = 4096
	// DefaultMaxStaticRules mirrors config.defaultMaxStaticRules.
	DefaultMaxStaticRules = 256
	// DefaultMaxRatelimitSources mirrors config.defaultMaxRatelimitSources.
	// This one dominates the map footprint: two LRU hashes of this many
	// entries are 94% of the measured 234.9 MiB (see
	// deploy/dataplane-operations.md §2).
	DefaultMaxRatelimitSources = 1 << 20

	// MaxProfiles is the hard ceiling on rate-limit profile ids, not
	// operator-settable: the map is 16 KiB at full size, so there is nothing
	// to save by shrinking it and a limit would only add a way to fail.
	MaxProfiles = 256

	// DynamicProfileBase splits kapkan_profiles into a config half [0, base)
	// and a mitigator half [base, MaxProfiles).
	//
	// WHY A STATIC PARTITION AND NOT A SHARED FREE LIST. The two allocators run
	// at different times and neither can see the other's future. compilePolicy
	// assigns config ids by NAME, keeping an id a name already had and filling
	// the lowest free slots for new names, so that a reload does not silently
	// reassign every rate. A reload that adds a profile would therefore hand
	// out the lowest free id — which, in a shared space, is a slot the
	// mitigator interned a live ban's rate into ten seconds earlier. PutProfile
	// would overwrite it in place and that ban's rate-limit rules would
	// silently start enforcing the OPERATOR's number. No error, no log line,
	// just a different rate than either party asked for. Reserving a band makes
	// that unrepresentable rather than merely unlikely.
	//
	// The split is 192/64. Config profiles are named ceilings an operator
	// writes by hand, and 192 is far past what anyone maintains; dynamic ones
	// are interned per DISTINCT RATE, not per ban, and a deployment has as many
	// distinct rates as it has groups with a rate_limit flowspec action —
	// typically one. compilePolicy refuses a config that exceeds 192 with a
	// message naming this reservation, and the Installer fails an install (and
	// therefore falls back to blackhole) rather than reusing a slot when the
	// dynamic band is full.
	DynamicProfileBase = 192
	// MaxPrefixes is the ceiling on entries in each LPM trie. Also not
	// operator-settable, and deliberately not rewritten: an LPM_TRIE
	// allocates nothing up front and grows per insert (measured: 0 bytes at
	// max_entries 65536), so max_entries here is a ceiling, not a
	// reservation.
	MaxPrefixes = 65536

	// defaultMaxRuleStats is the compiled-in size of kapkan_rule_stats. The
	// loader replaces it with MaxDynamicRules+MaxStaticRules, which is the
	// real bound on live rule ids, so it is a baked default and not a
	// contract value.
	defaultMaxRuleStats = 8192

	// FPSnapLen is the per-event capture ceiling of the fingerprint plane, in
	// bytes of L4 payload, mirroring KAPKAN_FP_SNAP_LEN. It sizes the Data field
	// of a ring-buffer event and is the ceiling the reader decodes up to; the
	// kernel records the real captured length in FPEvent.SnapLen.
	FPSnapLen = 1536

	// FPRingBytes is the byte size of the kapkan_fp_events ring, mirroring
	// KAPKAN_FP_RING_BYTES. A full ring drops the copy (StatFPRingFull) rather
	// than stalling the datapath, so this bounds only how much burst the reader
	// may fall behind by, never the datapath.
	FPRingBytes = 1 << 20
)

// Map names. These are contract: the pinned bpffs paths are derived from them,
// so renaming one orphans an operator's pins across an upgrade.
const (
	MapAllow4    = "kapkan_allow4"
	MapAllow6    = "kapkan_allow6"
	MapProtect4  = "kapkan_protect4"
	MapProtect6  = "kapkan_protect6"
	MapVictims4  = "kapkan_victims4"
	MapVictims6  = "kapkan_victims6"
	MapPolicies  = "kapkan_policies"
	MapStatics   = "kapkan_statics"
	MapRLSrc4    = "kapkan_rl_src4"
	MapRLSrc6    = "kapkan_rl_src6"
	MapProfiles  = "kapkan_profiles"
	MapCfg       = "kapkan_cfg"
	MapStats     = "kapkan_stats"
	MapRuleStats = "kapkan_rule_stats"
	// MapFPEvents is the fingerprint plane's copy ring (BPF_MAP_TYPE_RINGBUF);
	// MapFPSampler is its per-CPU copy-rate limiter. Both are E2.
	MapFPEvents  = "kapkan_fp_events"
	MapFPSampler = "kapkan_fp_sampler"
)

// ProgramName is the BPF program the loader attaches. It lives in the "xdp"
// ELF section.
const ProgramName = "kapkan_xdp_filter"

// AllMaps is every map the object must define, in the order kapkan_maps.h
// declares them. The load path asserts the object provides exactly this set,
// so a map dropped from the C side is caught at startup rather than by a nil
// dereference on the first rule install.
var AllMaps = []string{
	MapAllow4, MapAllow6,
	MapProtect4, MapProtect6,
	MapVictims4, MapVictims6,
	MapPolicies,
	MapStatics,
	MapRLSrc4, MapRLSrc6,
	MapProfiles,
	MapCfg,
	MapStats,
	MapRuleStats,
	MapFPEvents, MapFPSampler,
}

// Action is a rule verdict, mirroring enum kapkan_action.
type Action uint8

// Rule actions. These mirror config.StaticActionPass/Drop/RateLimit and, for
// dynamic rules, mitigate.FlowSpecRule.Action.
const (
	ActionPass      Action = 0
	ActionDrop      Action = 1
	ActionRateLimit Action = 2
)

// Rule flag bits, mirroring enum kapkan_rule_flag. "Any" is an explicit bit
// rather than a zero-valued field because 0 is a legal value for protocol
// (IPv6 hop-by-hop) and for TCP flags (a NULL scan).
const (
	RuleValid    uint8 = 1 << 0
	RuleSrcAny   uint8 = 1 << 1
	RuleDstAny   uint8 = 1 << 2
	RuleProtoAny uint8 = 1 << 3
	RuleSportAny uint8 = 1 << 4
	RuleDportAny uint8 = 1 << 5
	RuleFragment uint8 = 1 << 6
	RuleIPv6     uint8 = 1 << 7
)

// Extended match bits, mirroring enum kapkan_match_ext. They live in
// Rule.MatchExt rather than Rule.Flags because Flags is full — all eight bits
// are spoken for, and widening it would move every field after it in a frozen
// 64-byte layout. MatchExt was the struct's _pad0, so nothing moved.
//
// Adding a bit here does NOT oblige a MapSchemaVersion bump. That stamp is for
// layout changes; this is not one, and tryAdopt already refuses a pinned
// program whose tag differs from the one this binary loads, so a binary that
// understands a new bit can never meet a program that does not.
//
// STATIC RULES ONLY. mitigate.FlowSpecRule has no counterpart for this axis
// because RFC 8955 has no payload component, so a dynamic rule carrying one
// would select different packets through this encoder than through the NLRI
// encoder while claiming to be the same rule. TestDynamicRulesNeverSetMatchExt
// holds that line.
const (
	// MatchTLSClientHello requires the TCP payload to open a TLS handshake
	// record carrying a ClientHello. The datapath decides that from three
	// bytes at fixed offsets and never reassembles, so a split or truncated
	// record does not match and the packet is forwarded.
	MatchTLSClientHello uint8 = 1 << 0
	// MatchQUICInitial requires the UDP payload to open a QUIC v1 Initial —
	// the UDP twin of the bit above. The datapath decides that from five
	// bytes at fixed offsets (long-header form + fixed bit + Initial type,
	// then version 1); version negotiation and QUIC v2 do not match, and a
	// payload too short to decide is forwarded.
	MatchQUICInitial uint8 = 1 << 1
)

// knownMatchExt is every extended-match bit this build implements in the
// datapath. Encode refuses a spec carrying anything outside it, because an
// unimplemented narrowing predicate would be ignored in the kernel and the rule
// would match more than the caller asked for.
const knownMatchExt = MatchTLSClientHello | MatchQUICInitial

// Stat indexes kapkan_stats. Append only — the console renders by index.
//
// Two kinds of counter share this space, and anything that aggregates them
// needs the distinction:
//
//   - TERMINAL counters partition the traffic. Exactly one is bumped per
//     packet, naming the branch that decided its fate, so their sum is the
//     packet count.
//   - OBSERVATION counters are bumped on the way past and CO-OCCUR with a
//     terminal counter for the same packet. IsObservation reports which.
//
// Summing every index to reconcile against an interface counter therefore
// over-counts by the number of observations; sum only the terminal ones.
type Stat uint32

// IsObservation reports whether s is bumped alongside a terminal verdict
// rather than instead of one. See the enum comment in bpf/include/kapkan_maps.h,
// which this mirrors.
func (s Stat) IsObservation() bool {
	switch s {
	case StatPassFragNoPorts, StatPassRuleExpired, StatDryRunWouldDrop,
		StatErrPolicyMissing,
		// The fingerprint plane's copy counters co-occur with a terminal
		// verdict — the packet is still passed or dropped on its own merits.
		StatFPEmitted, StatFPThrottled, StatFPRingFull:
		return true
	}
	return false
}

// Verdict/reason counters, mirroring enum kapkan_stat. The precedence numbers
// in the comments refer to the packet-path precedence documented at the top of
// kapkan_xdp.c.
const (
	StatPassDefault      Stat = 0  // fell through every rule (precedence 6)
	StatPassNotIP        Stat = 1  // ARP, LLDP, ...: not our traffic
	StatPassMalformed    Stat = 2  // unparseable, drop_malformed off
	StatDropMalformed    Stat = 3  // unparseable, drop_malformed on
	StatPassVLANDepth    Stat = 4  // more VLAN tags than the parser walks
	StatPassExtHdrCap    Stat = 5  // hit the IPv6 extension-header cap
	StatPassFragNoPorts  Stat = 6  // observation: non-first fragment, no L4
	StatPassAllowSrc     Stat = 7  // precedence 1
	StatPassProtectDst   Stat = 8  // precedence 2
	StatPassStatic       Stat = 9  // precedence 3, action=pass
	StatDropStatic       Stat = 10 // precedence 3, action=drop
	StatPassDynSrc       Stat = 11 // precedence 4, action=pass
	StatDropDynSrc       Stat = 12 // precedence 4, action=drop
	StatPassDynDst       Stat = 13 // precedence 5, action=pass
	StatDropDynDst       Stat = 14 // precedence 5, action=drop
	StatPassRLAdmit      Stat = 15 // ratelimit, tokens remained
	StatDropRL           Stat = 16 // ratelimit, bucket empty
	StatPassRuleExpired  Stat = 17 // observation: matched a rule past its TTL
	StatDryRunWouldDrop  Stat = 18 // observation: a drop rewritten to a pass
	StatErrCfgMissing    Stat = 19 // kapkan_cfg[0] lookup failed
	StatErrPolicyMissing Stat = 20 // observation: victim hit, policy block absent
	StatFPEmitted        Stat = 21 // observation: a fingerprint copy hit the ring
	StatFPThrottled      Stat = 22 // observation: the sampler denied a copy
	StatFPRingFull       Stat = 23 // observation: ring full, copy skipped
	StatMax              Stat = 24
)

// statNames maps each counter to the identifier the C enum uses, so the API
// and console can label them without a second table.
var statNames = [StatMax]string{
	StatPassDefault:      "pass_default",
	StatPassNotIP:        "pass_not_ip",
	StatPassMalformed:    "pass_malformed",
	StatDropMalformed:    "drop_malformed",
	StatPassVLANDepth:    "pass_vlan_depth",
	StatPassExtHdrCap:    "pass_exthdr_cap",
	StatPassFragNoPorts:  "pass_frag_noports",
	StatPassAllowSrc:     "pass_allow_src",
	StatPassProtectDst:   "pass_protect_dst",
	StatPassStatic:       "pass_static",
	StatDropStatic:       "drop_static",
	StatPassDynSrc:       "pass_dyn_src",
	StatDropDynSrc:       "drop_dyn_src",
	StatPassDynDst:       "pass_dyn_dst",
	StatDropDynDst:       "drop_dyn_dst",
	StatPassRLAdmit:      "pass_rl_admit",
	StatDropRL:           "drop_rl",
	StatPassRuleExpired:  "pass_rule_expired",
	StatDryRunWouldDrop:  "dryrun_would_drop",
	StatErrCfgMissing:    "err_cfg_missing",
	StatErrPolicyMissing: "err_policy_missing",
	StatFPEmitted:        "fp_emitted",
	StatFPThrottled:      "fp_throttled",
	StatFPRingFull:       "fp_ring_full",
}

// String renders the counter's stable name, used as a Prometheus label and in
// the console.
func (s Stat) String() string {
	if s >= StatMax {
		return "unknown"
	}
	return statNames[s]
}

// BypassReason reports whether s counts a FILTER BYPASS — a packet the datapath
// forwarded without evaluating a single rule, because it hit a parse limit
// before the rule scan ever started — and names the class if so.
//
// This is the one distinction in the counter block that is a security signal
// rather than a statistic. Every other pass_* counter means "the rules were
// consulted and none of them said drop". These mean "the rules were never
// consulted at all", which is the shape of an evasion attempt: an attacker who
// can construct a packet the parser gives up on has, for that packet, turned
// the filter off. The verdict is still PASS and deliberately so — the charter
// forbids a parse limit becoming a default-deny, because the same packet shape
// arriving from a legitimate host must not be blackholed by a parser's
// budget — so VISIBILITY is the entire mitigation, and it has to be loud.
//
// Only the IPv6 extension-header cap qualifies today. StatPassVLANDepth is the
// other parse-limit pass and is deliberately NOT here: QinQ is ordinary traffic
// on a carrier trunk, so that counter is non-zero on healthy boxes and an alarm
// wired to it would be noise. Nothing legitimate chains eight IPv6 extension
// headers, so any movement on this one is worth a human's attention.
//
// The returned string is a stable Prometheus label value; do not rename it.
func (s Stat) BypassReason() (string, bool) {
	if s == StatPassExtHdrCap {
		return "ipv6_exthdr_cap", true
	}
	return "", false
}
