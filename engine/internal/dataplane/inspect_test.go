package dataplane

// The host-independent half of the inspection tests: the arithmetic, the
// counter split, the config drift gate, and the structural read-only guard.
//
// Untagged so they run on the macOS development host as well as in the
// container. The kernel-side proofs live in inspect_linux_test.go.

import (
	"os"
	"strings"
	"testing"
)

// TestDefaultPinPathMatchesConfig is the drift gate on DefaultPinPath. The CLI
// falls back to it when it cannot read a config file, so if config's own default
// ever moves, `kapkan dataplane status` would confidently report "the data plane
// has never run here" about a directory nobody uses.
func TestDefaultPinPathMatchesConfig(t *testing.T) {
	// A dataplane block that names no pin_path, so config's validate() resolves
	// it to config's own default — which is the value this constant mirrors.
	cfg := mustParse(t, "\ndataplane:\n  enabled: true\n  interfaces: [\"eth0\"]\n")
	if cfg.DataplaneCfg.PinPath != DefaultPinPath {
		t.Errorf("config resolves dataplane.pin_path to %q, DefaultPinPath is %q — "+
			"`kapkan dataplane status` would inspect the wrong directory",
			cfg.DataplaneCfg.PinPath, DefaultPinPath)
	}
}

// TestSplitCountersKeepsObservationsOut is the arithmetic behind the report's
// two-block layout. An observation counter co-occurs with a terminal one for the
// same packet, so including it in the total produces a packet count that is
// larger than the number of packets.
func TestSplitCountersKeepsObservationsOut(t *testing.T) {
	var c [StatMax]Counter
	c[StatPassDefault] = Counter{Pkts: 100, Bytes: 1000}
	c[StatDropStatic] = Counter{Pkts: 7, Bytes: 70}
	c[StatDryRunWouldDrop] = Counter{Pkts: 7, Bytes: 70}  // observation
	c[StatPassRuleExpired] = Counter{Pkts: 3, Bytes: 30}  // observation
	c[StatErrPolicyMissing] = Counter{Pkts: 1, Bytes: 10} // observation
	c[StatPassFragNoPorts] = Counter{Pkts: 2, Bytes: 20}  // observation
	c[StatPassNotIP] = Counter{Pkts: 0, Bytes: 0}         // zero: suppressed

	terminal, observation, total := splitCounters(c)

	if total.Pkts != 107 || total.Bytes != 1070 {
		t.Errorf("terminal total = %d pkts / %d bytes, want 107/1070 — observations leaked into it",
			total.Pkts, total.Bytes)
	}
	if len(terminal) != 2 {
		t.Errorf("terminal = %+v, want only the two non-zero terminal counters", terminal)
	}
	if len(observation) != 4 {
		t.Errorf("observation = %+v, want the four non-zero observation counters", observation)
	}
	for _, e := range terminal {
		if Stat(e.Index).IsObservation() {
			t.Errorf("%s is an observation counter but appears in the terminal list", e.Name)
		}
	}
	for _, e := range observation {
		if !Stat(e.Index).IsObservation() {
			t.Errorf("%s is terminal but appears in the observation list", e.Name)
		}
	}
	// Every counter the enum defines is classified, so nothing can be dropped
	// silently by being neither.
	seen := map[string]bool{}
	for _, e := range append(append([]StatCount{}, terminal...), observation...) {
		seen[e.Name] = true
	}
	for s := Stat(0); s < StatMax; s++ {
		if c[s].Pkts == 0 && c[s].Bytes == 0 {
			continue
		}
		if !seen[s.String()] {
			t.Errorf("non-zero counter %s appears in neither list", s)
		}
	}
}

// TestDynamicRuleTotals covers the three numbers the report gives for the
// mitigator's rules, and in particular the expiry split: an expired rule still
// occupies its slot but the datapath treats it as absent, which is the fail-safe
// that keeps a dead userspace from leaving a customer blackholed.
func TestDynamicRuleTotals(t *testing.T) {
	const now = 1_000_000_000 // 1s of boot time, in ns

	mk := func(n uint32, deadlines ...uint64) PolicyBlock {
		b := PolicyBlock{N_rules: n}
		for i, d := range deadlines {
			b.Rules[i] = Rule{ExpiresAtNs: d, Flags: RuleValid}
		}
		return b
	}

	blocks := []PolicyBlock{
		{},                          // empty
		mk(2, now+1, now+2),         // both live
		mk(2, now-1, now+5),         // one expired
		mk(1, 0),                    // a never-expiring (static-style) rule
		mk(3, now-10, now-9, now-8), // all expired
	}
	used, rules, expired := dynamicRuleTotals(blocks, now)
	if used != 4 {
		t.Errorf("occupied blocks = %d, want 4", used)
	}
	if rules != 8 {
		t.Errorf("rules = %d, want 8", rules)
	}
	if expired != 4 {
		t.Errorf("expired = %d, want 4", expired)
	}

	// With no readable boot clock, nothing is claimed to be expired: reporting
	// "0 of 8 expired" is a guess, and this function does not guess.
	if _, _, e := dynamicRuleTotals(blocks, 0); e != 0 {
		t.Errorf("expired = %d with an unknown boot clock, want 0", e)
	}

	// A block claiming more rules than fit is clamped rather than panicking on
	// the slice: the map is kernel memory and a diagnostic must survive garbage.
	if _, r, _ := dynamicRuleTotals([]PolicyBlock{{N_rules: 9999}}, now); r != RulesPerPolicy {
		t.Errorf("rules = %d for an over-long block, want the block size %d", r, RulesPerPolicy)
	}
}

// TestInspectIsStructurallyReadOnly is the source-level half of the read-only
// guarantee. The kernel enforces it at runtime (see
// TestInspectMapFDsAreReadOnlyToTheKernel), and this stops a future edit from
// reaching for Manager.Open() or a Put because it needed one more field.
//
// It is a grep, and that is on purpose: the property has to be checkable by a
// reviewer reading the diff, not only by a test suite with a kernel.
func TestInspectIsStructurallyReadOnly(t *testing.T) {
	const path = "inspect_linux.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Strip comments: every forbidden identifier below is DISCUSSED in this
	// file's documentation, which is the point of the documentation.
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}

	for _, forbidden := range []string{
		".Put(",          // map write
		".Delete(",       // map delete
		".Pin(",          // create a pin
		".Unpin(",        // remove a pin
		"os.Remove",      // remove anything
		"os.Mkdir",       // create anything
		"os.WriteFile",   // ditto
		"os.Create",      // ditto
		"os.OpenFile",    // could create or truncate
		"LoadAndAssign",  // loads a program and creates maps
		"NewCollection",  // ditto
		"AttachXDP",      // attaches
		"LinkUpdate",     // swaps a link's program
		"discardLinkPin", // detaches
		"removeOurPins",  // removes pins
		"pinObjects",     // creates pins
		"ensurePinDir",   // creates the directory
		"Open(",          // Manager.Open: adopts-or-creates and attaches
	} {
		if strings.Contains(code.String(), forbidden) {
			t.Errorf("%s contains %q. This file must never mutate the data plane it is "+
				"diagnosing: an operator runs it at 3am on a box that is already misbehaving, and a "+
				"rebuild would drop every dynamic rule the mitigator has installed. If a new field "+
				"genuinely needs one of these, it does not belong in the read-only path.",
				path, forbidden)
		}
	}

	// The positive half: every map really is opened through readOnly().
	if n := strings.Count(code.String(), "LoadPinnedMap("); n == 0 {
		t.Fatal("no LoadPinnedMap call found; this test is no longer checking anything")
	}
	if strings.Contains(code.String(), "LoadPinnedMap(") &&
		!strings.Contains(code.String(), "LoadPinnedMap(mapPin(dir, name), readOnly())") {
		t.Error("a pinned map is opened without readOnly(), losing the kernel's BPF_F_RDONLY enforcement")
	}
}

// TestInspectStatesAreDistinct guards the enum against a copy-paste that gives
// two states the same string, which would silently merge two exit codes.
func TestInspectStatesAreDistinct(t *testing.T) {
	all := []InspectState{
		StateNotBPFFS, StateNoPinPath, StateNoProgram,
		StateTorn, StateSchemaSkew, StateDetached, StateAttachUnknown, StateEnforcing,
	}
	seen := map[InspectState]bool{}
	for _, s := range all {
		if s == "" {
			t.Error("an InspectState is the empty string")
		}
		if seen[s] {
			t.Errorf("duplicate InspectState %q", s)
		}
		seen[s] = true
	}
	if !StateEnforcing.Enforcing() {
		t.Error("StateEnforcing.Enforcing() = false")
	}
	for _, s := range all {
		if s != StateEnforcing && s.Enforcing() {
			t.Errorf("%s.Enforcing() = true", s)
		}
	}
}
