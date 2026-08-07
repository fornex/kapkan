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
const MapSchemaVersion = 1

// RulesPerPolicy is the number of match rules in one victim's policy block. It
// mirrors both KAPKAN_RULES_PER_POLICY in C and config.maxDataplaneRulesPerBan
// (a ban installs at most this many rules), so a whole ban fits in one block
// and the datapath needs a single map lookup to evaluate it.
const RulesPerPolicy = 8

// Generations is the double-buffer depth of kapkan_policies and
// kapkan_statics. Userspace fills the inactive half, then flips
// kapkan_cfg[0].generation so a packet sees either the whole old rule set or
// the whole new one. It costs 2x the map memory; that is the price of a
// lossless policy swap.
const Generations = 2

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
		StatErrPolicyMissing:
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
	StatMax              Stat = 21
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
}

// String renders the counter's stable name, used as a Prometheus label and in
// the console.
func (s Stat) String() string {
	if s >= StatMax {
		return "unknown"
	}
	return statNames[s]
}
