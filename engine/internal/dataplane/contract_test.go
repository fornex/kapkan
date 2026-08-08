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
	} {
		if got := cDefine(t, src, tc.cName); got != tc.goVal {
			t.Errorf("%s = %d in C, %d in Go", tc.cName, got, tc.goVal)
		}
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
