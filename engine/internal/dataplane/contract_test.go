package dataplane

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	mapsHeaderPath = "../../bpf/include/kapkan_maps.h"
	configPath     = "../../internal/config/config.go"
	// xdpSourcePath holds the parser limits, which are program constants rather
	// than map layout and so live in the .c rather than the header.
	xdpSourcePath = "../../bpf/kapkan_xdp.c"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// cDefine extracts the integer value of a `#define NAME <int>` or of the shift
// form the header uses for the large map sizes (`#define X (1 << 20)`).
//
// The shift form is accepted rather than normalised away in the C, because
// "1 << 20" is how an operator reads a million-entry LRU and "1048576" is not.
func cDefine(t *testing.T, src, name string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(name) +
		`\s+\(?(\d+)(?:\s*<<\s*(\d+))?\)?\s*(?:/\*|$)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("#define %s not found (or not in a form this test can read) in %s", name, mapsHeaderPath)
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("#define %s: %v", name, err)
	}
	if m[2] != "" {
		sh, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("#define %s: %v", name, err)
		}
		v <<= sh
	}
	return v
}

// TestContractMatchesC is the freeze-point F6 drift gate. The Go constants in
// contract.go and the C constants in kapkan_maps.h describe the same bytes in
// the same maps; if they drift, the encoder writes rules the datapath reads as
// something else, which in the worst case means dropping traffic the operator
// never asked to drop. Grepping the header is crude but it is the only check
// that runs on every host, including the macOS ones where the object cannot be
// loaded at all.
func TestContractMatchesC(t *testing.T) {
	src := readFile(t, mapsHeaderPath)

	for _, tc := range []struct {
		cName string
		goVal int
	}{
		{"KAPKAN_MAP_SCHEMA_VERSION", MapSchemaVersion},
		{"KAPKAN_RULES_PER_POLICY", RulesPerPolicy},
		{"KAPKAN_GENERATIONS", Generations},

		// The map sizings. These matter more now than they did when the header
		// was written: the loader REWRITES max_entries from dataplane.limits
		// before the maps are created, so these values are what an operator gets
		// when they name no limits — and they have to be the same number in
		// three files (this one, the header, and config's defaultMax*, which
		// TestDefaultLimitsMatchConfig checks).
		//
		// The two that are not operator-settable are here for a different
		// reason: MaxProfiles bounds the profile ids userspace may assign, and
		// MaxPrefixes bounds every prefix list. Exceeding either is not an error
		// the datapath can report — a rule pointing at a profile that was never
		// written caps nothing and admits — so they are checked at compile time
		// in compilePolicy against these constants.
		{"KAPKAN_MAX_DYNAMIC_RULES", DefaultMaxDynamicRules},
		{"KAPKAN_MAX_STATIC_RULES", DefaultMaxStaticRules},
		{"KAPKAN_MAX_RL_SOURCES", DefaultMaxRatelimitSources},
		{"KAPKAN_MAX_PROFILES", MaxProfiles},
		{"KAPKAN_MAX_PREFIXES", MaxPrefixes},
		{"KAPKAN_MAX_RULE_STATS", defaultMaxRuleStats},

		// The fingerprint plane (E2). FPSnapLen sizes the FPEvent.Data field the
		// reader decodes and MUST match the C array; FPRingBytes is the ring size.
		{"KAPKAN_FP_SNAP_LEN", FPSnapLen},
		{"KAPKAN_FP_RING_BYTES", FPRingBytes},
	} {
		if got := cDefine(t, src, tc.cName); got != tc.goVal {
			t.Errorf("%s = %d in C, %d in Go", tc.cName, got, tc.goVal)
		}
	}
}

// TestExtHdrCapMatchesC pins MaxIPv6ExtHdrs against KAPKAN_MAX_EXT_HDRS.
//
// This is the HOST-side half of the extension-header cap gate, and it exists
// because the other half cannot run here. TestIPv6ExtHdrCapBoundary measures the
// real threshold against the compiled object, which needs a privileged Linux
// container; this one is a grep, so it runs in `make test` on every developer's
// laptop and in CI on hosts that have no bpf(2) at all.
//
// What drifting costs is unusual for a constant. Below the cap, traffic is
// filtered; at or above it, the datapath forwards the packet WITHOUT EVALUATING
// A SINGLE RULE. So this number is not a tuning parameter — it is the published
// width of a hole in the filter, quoted verbatim to operators in
// engine/deploy/dataplane-operations.md §6, in the console's banner text and in
// the CLI report. A C-side change that this mirror did not follow would leave
// every one of those places confidently stating the wrong threshold.
func TestExtHdrCapMatchesC(t *testing.T) {
	src := readFile(t, xdpSourcePath)
	re := regexp.MustCompile(`(?m)^#define\s+KAPKAN_MAX_EXT_HDRS\s+(\d+)\s*(?:/\*|$)`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("#define KAPKAN_MAX_EXT_HDRS not found (or not in a form this test can read) in %s",
			xdpSourcePath)
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("#define KAPKAN_MAX_EXT_HDRS: %v", err)
	}
	if got != MaxIPv6ExtHdrs {
		t.Errorf("KAPKAN_MAX_EXT_HDRS = %d in C, MaxIPv6ExtHdrs = %d in Go. This is the number of "+
			"IPv6 extension headers a packet needs to carry to skip the rule scan entirely; the "+
			"operations guide, the console banner and `kapkan dataplane status` all quote the Go "+
			"value, so a mismatch means they are misreporting where the filter stops working.",
			got, MaxIPv6ExtHdrs)
	}
}

// TestExtHdrCapIsTheOnlyBypassReason pins the classification that every alarm
// hangs off: the metric label, the console banner and the CLI block are all
// driven by Stat.BypassReason, so a counter silently gaining or losing that
// status changes what operators are told without changing any datapath code.
//
// StatPassVLANDepth is asserted NOT to be one on purpose. It is the other
// parse-limit pass, and it looks like the same thing, but QinQ is ordinary
// traffic on a carrier trunk — wiring an alarm to it would produce a permanent
// alert on healthy boxes, and a permanent alert is an ignored one.
func TestExtHdrCapIsTheOnlyBypassReason(t *testing.T) {
	got := map[Stat]string{}
	for s := Stat(0); s < StatMax; s++ {
		if reason, ok := s.BypassReason(); ok {
			got[s] = reason
		}
	}
	want := map[Stat]string{StatPassExtHdrCap: "ipv6_exthdr_cap"}
	if len(got) != len(want) {
		t.Fatalf("bypass reasons = %v, want %v", got, want)
	}
	for s, reason := range want {
		if got[s] != reason {
			t.Errorf("%s.BypassReason() = %q, want %q — this string is a Prometheus label value on "+
				"kapkan_dataplane_filter_bypass_packets_total and an operator's alert rule may name it",
				s, got[s], reason)
		}
	}
	if _, ok := StatPassVLANDepth.BypassReason(); ok {
		t.Error("pass_vlan_depth is now a bypass reason: it fires on ordinary QinQ traffic, so the " +
			"filter-bypass alarm would be permanently on and therefore permanently ignored")
	}
}

// TestRuleFlagsMatchC pins every rule-flag BIT POSITION against the C enum.
//
// This is not the same check as the struct-layout gate above, and it exists
// for a specific hazard: kapkan_rule_match() reads these flags as bare shift
// amounts — (f >> 7) for IPv6, kapkan_test_mask(f, 3) for PROTO_ANY — for the
// instruction budget on an unrolled 8-rule scan. Renumbering the enum
// therefore compiles clean and silently changes what every rule matches. The
// C side asserts the same thing at build time; this catches the other
// direction, where Go's mirror of the flags drifts away from the header.
func TestRuleFlagsMatchC(t *testing.T) {
	src := readFile(t, mapsHeaderPath)
	re := regexp.MustCompile(`(?m)^\s*KAPKAN_RF_(\w+)\s*=\s*1\s*<<\s*(\d+),`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no KAPKAN_RF_* enumerators found in %s", mapsHeaderPath)
	}

	// Every flag the datapath reads by literal position must appear here. A
	// new C flag with no Go counterpart fails below rather than passing
	// unnoticed, which is the point: the encoder cannot set what it cannot name.
	want := map[string]uint8{
		"VALID":     RuleValid,
		"SRC_ANY":   RuleSrcAny,
		"DST_ANY":   RuleDstAny,
		"PROTO_ANY": RuleProtoAny,
		"SPORT_ANY": RuleSportAny,
		"DPORT_ANY": RuleDportAny,
		"FRAGMENT":  RuleFragment,
		"IPV6":      RuleIPv6,
	}
	seen := make(map[string]bool, len(want))
	for _, m := range matches {
		name, shift := m[1], m[2]
		bit, err := strconv.Atoi(shift)
		if err != nil {
			t.Fatal(err)
		}
		goVal, ok := want[name]
		if !ok {
			t.Errorf("KAPKAN_RF_%s exists in C with no constant in contract.go", name)
			continue
		}
		seen[name] = true
		if goVal != 1<<bit {
			t.Errorf("KAPKAN_RF_%s = bit %d in C, %#x in Go", name, bit, goVal)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("Go declares %s but KAPKAN_RF_%s is gone from the C header", name, name)
		}
	}
}

// TestMatchExtFlagsMatchC is TestRuleFlagsMatchC for the second flag byte.
//
// It is a separate test rather than a second table in that one because the two
// bytes fail differently. A drifted KAPKAN_RF_* bit makes a rule match the
// wrong field; a drifted KAPKAN_MX_* bit makes a NARROWING predicate vanish,
// and a rule that was meant to catch ClientHellos silently catches every packet
// the rest of its match admits. Same mechanism, opposite blast radius, so the
// failure message has to say which one happened.
func TestMatchExtFlagsMatchC(t *testing.T) {
	src := readFile(t, mapsHeaderPath)
	re := regexp.MustCompile(`(?m)^\s*KAPKAN_MX_(\w+)\s*=\s*1\s*<<\s*(\d+),`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no KAPKAN_MX_* enumerators found in %s", mapsHeaderPath)
	}

	want := map[string]uint8{
		"TLS_CLIENT_HELLO": MatchTLSClientHello,
		"QUIC_INITIAL":     MatchQUICInitial,
	}
	seen := make(map[string]bool, len(want))
	var all uint8
	for _, m := range matches {
		name, shift := m[1], m[2]
		bit, err := strconv.Atoi(shift)
		if err != nil {
			t.Fatal(err)
		}
		all |= 1 << bit
		goVal, ok := want[name]
		if !ok {
			t.Errorf("KAPKAN_MX_%s exists in C with no constant in contract.go — "+
				"Encode would reject the bit as unimplemented", name)
			continue
		}
		seen[name] = true
		if goVal != 1<<bit {
			t.Errorf("KAPKAN_MX_%s = bit %d in C, %#x in Go — a rule would carry a predicate "+
				"the datapath tests somewhere else", name, bit, goVal)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("Go declares %s but KAPKAN_MX_%s is gone from the C header — every rule "+
				"naming it would silently widen to whatever the rest of its match admits", name, name)
		}
	}
	// knownMatchExt is what Encode accepts. If C grows a bit that Go knows and
	// this constant does not, every rule using it is rejected at install time.
	if all != knownMatchExt {
		t.Errorf("C defines match_ext bits %#02x, knownMatchExt is %#02x", all, knownMatchExt)
	}
}

// TestRulesPerPolicyMatchesBanCap ties the kernel-side policy block to
// config.maxDataplaneRulesPerBan. A ban installs at most that many rules and
// the block holds exactly RulesPerPolicy of them, so if the cap ever rises
// above the block size a ban silently loses rules — the attack keeps flowing
// and nothing logs an error. config's constant is unexported, so this reads
// the source.
func TestRulesPerPolicyMatchesBanCap(t *testing.T) {
	src := readFile(t, configPath)
	re := regexp.MustCompile(`(?m)^const maxDataplaneRulesPerBan = (\d+)\b`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("maxDataplaneRulesPerBan not found in %s", configPath)
	}
	want, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if want != RulesPerPolicy {
		t.Errorf("config.maxDataplaneRulesPerBan = %d, dataplane.RulesPerPolicy = %d; "+
			"a policy block must hold every rule one ban can install", want, RulesPerPolicy)
	}
}

// TestStatEnumMatchesC checks every kapkan_stat enumerator against the Go
// mirror by value AND by name. The console renders these counters by index, so
// an inserted enumerator would silently relabel every counter after it.
func TestStatEnumMatchesC(t *testing.T) {
	src := readFile(t, mapsHeaderPath)
	re := regexp.MustCompile(`(?m)^\s*KAPKAN_STAT_?(\w*)\s*=\s*(\d+),`)
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatalf("no KAPKAN_STAT_* enumerators found in %s", mapsHeaderPath)
	}

	var maxSeen int
	for _, m := range matches {
		name, val := m[1], m[2]
		v, err := strconv.Atoi(val)
		if err != nil {
			t.Fatal(err)
		}
		if name == "_MAX" {
			if Stat(v) != StatMax {
				t.Errorf("KAPKAN_STAT__MAX = %d in C, StatMax = %d in Go", v, StatMax)
			}
			continue
		}
		maxSeen++
		want := strings.ToLower(name)
		if got := Stat(v).String(); got != want {
			t.Errorf("stat %d: C says %q, Go says %q", v, want, got)
		}
	}
	if Stat(maxSeen) != StatMax {
		t.Errorf("C declares %d stats, StatMax = %d", maxSeen, StatMax)
	}
}

// TestAllMapsMatchesObject asserts the committed object defines exactly the
// map set the contract names — no more, no less. It parses the embedded ELF,
// which needs no kernel, so it guards the darwin developer loop too: a map
// deleted from the C side fails here rather than at attach on a production
// box.
func TestAllMapsMatchesObject(t *testing.T) {
	spec, err := loadKapkanXDP()
	if err != nil {
		t.Fatalf("load embedded CollectionSpec: %v", err)
	}

	want := make(map[string]bool, len(AllMaps))
	for _, n := range AllMaps {
		want[n] = true
	}
	for name := range spec.Maps {
		if !want[name] {
			t.Errorf("object defines map %q that AllMaps does not list", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("AllMaps lists map %q that the object does not define", name)
	}

	if _, ok := spec.Programs[ProgramName]; !ok {
		t.Errorf("object has no program %q (has %v)", ProgramName, programNames(spec.Programs))
	}
}

func programNames[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
