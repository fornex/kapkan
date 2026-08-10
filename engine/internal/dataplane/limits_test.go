package dataplane

// Tests for the limits rewrite — the one piece of the manager that needs no
// kernel at all, because a CollectionSpec is parsed from the embedded ELF.
//
// Which is why they live here rather than in the Linux-only file: the arithmetic
// that decides how much memory an operator's box gives up is checkable on every
// contributor's machine, and only the assertion that the CREATED map really is
// that size needs a kernel (see TestLimitsRewriteCreatedMapSizes in
// manager_linux_test.go, which reads the size back from the kernel and not from
// the spec).

import (
	"regexp"
	"strconv"
	"testing"
)

func TestMapSizingFromLimits(t *testing.T) {
	cases := []struct {
		name string
		lim  Limits
		want MapSizing
	}{
		{
			// The defaults must reproduce the sizes the ELF is compiled with,
			// for every map except kapkan_rule_stats — which the loader sizes
			// from the real rule bound instead of the compiled-in 8192.
			name: "defaults reproduce the compiled-in sizes",
			lim:  DefaultLimits(),
			want: MapSizing{
				Policies:     1024, // 2 generations x (4096/8) blocks
				Statics:      1024, // 2 generations x (256 x 2 families)
				RLSources:    1 << 20,
				RuleStats:    4096 + 512,
				PolicyStride: 512,
				StaticStride: 512,
			},
		},
		{
			// The case that motivates the whole file: a small box. 94% of the
			// footprint is the two LRUs, and this is an operator asking for 1/16
			// of it.
			name: "a small box",
			lim:  Limits{MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 65536},
			want: MapSizing{
				Policies: 64, Statics: 128, RLSources: 65536, RuleStats: 256 + 64,
				PolicyStride: 32, StaticStride: 64,
			},
		},
		{
			// Rounding UP: 4097 rules must not silently become 4096.
			name: "policy blocks round up",
			lim:  Limits{MaxDynamicRules: 4097, MaxStaticRules: 1, MaxRatelimitSources: 1},
			want: MapSizing{
				Policies: 1026, Statics: 4, RLSources: 1, RuleStats: 4097 + 2,
				PolicyStride: 513, StaticStride: 2,
			},
		},
		{
			name: "one of everything",
			lim:  Limits{MaxDynamicRules: 1, MaxStaticRules: 1, MaxRatelimitSources: 1},
			want: MapSizing{
				Policies: 2, Statics: 4, RLSources: 1, RuleStats: 3,
				PolicyStride: 1, StaticStride: 2,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.lim.MapSizing()
			if err != nil {
				t.Fatalf("MapSizing(%+v): %v", tc.lim, err)
			}
			if got != tc.want {
				t.Errorf("MapSizing(%+v):\n got %+v\nwant %+v", tc.lim, got, tc.want)
			}
		})
	}
}

func TestMapSizingRejectsNonsense(t *testing.T) {
	for _, lim := range []Limits{
		{MaxDynamicRules: 0, MaxStaticRules: 1, MaxRatelimitSources: 1},
		{MaxDynamicRules: 1, MaxStaticRules: 0, MaxRatelimitSources: 1},
		{MaxDynamicRules: 1, MaxStaticRules: 1, MaxRatelimitSources: 0},
		{MaxDynamicRules: -1, MaxStaticRules: 1, MaxRatelimitSources: 1},
		// Big enough that the uint32 conversion would wrap and produce a small,
		// wrong map instead of an error.
		{MaxDynamicRules: 1, MaxStaticRules: 1, MaxRatelimitSources: 1 << 40},
		{MaxDynamicRules: 1 << 40, MaxStaticRules: 1, MaxRatelimitSources: 1},
	} {
		if _, err := lim.MapSizing(); err == nil {
			t.Errorf("MapSizing(%+v) accepted a limit it must reject", lim)
		}
	}
}

// TestApplySizingRewritesTheSpec is the debt-(a) unit test: the sizes on the
// spec after applySizing are the operator's, not the ELF's.
//
// It deliberately reads the BEFORE values from the object rather than hard-coding
// them, so it also proves the rewrite is a real change on this build and not a
// pair of numbers that happen to agree.
func TestApplySizingRewritesTheSpec(t *testing.T) {
	spec, err := loadKapkanXDP()
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]uint32{}
	for name, ms := range spec.Maps {
		before[name] = ms.MaxEntries
	}

	lim := Limits{MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 65536}
	sizing, err := lim.MapSizing()
	if err != nil {
		t.Fatal(err)
	}
	if err := applySizing(spec, sizing); err != nil {
		t.Fatalf("applySizing: %v", err)
	}

	want := sizing.resizable()
	for _, name := range AllMaps {
		got := spec.Maps[name].MaxEntries
		if w, resizable := want[name]; resizable {
			if got != w {
				t.Errorf("%s max_entries = %d after applySizing, want %d", name, got, w)
			}
			if got == before[name] {
				t.Errorf("%s max_entries is still the compiled-in %d: this test is not "+
					"exercising the rewrite (pick limits that differ from the defaults)", name, got)
			}
			t.Logf("%-18s %7d -> %7d", name, before[name], got)
			continue
		}
		if got != before[name] {
			t.Errorf("%s max_entries changed from %d to %d; it is not a resizable map",
				name, before[name], got)
		}
	}
}

// TestApplySizingRejectsAWrongFixedSize proves the fixed-size maps are verified
// and not merely left alone. kapkan_stats must cover StatMax or every counter
// read past the truncation point silently returns nothing.
func TestApplySizingRejectsAWrongFixedSize(t *testing.T) {
	spec, err := loadKapkanXDP()
	if err != nil {
		t.Fatal(err)
	}
	spec.Maps[MapStats].MaxEntries = uint32(StatMax) - 1
	sizing, err := DefaultLimits().MapSizing()
	if err != nil {
		t.Fatal(err)
	}
	if err := applySizing(spec, sizing); err == nil {
		t.Fatalf("applySizing accepted kapkan_stats sized below StatMax")
	} else {
		t.Logf("refused as it should: %v", err)
	}
}

// TestApplySizingClassifiesEveryMap fails when a map is added to the C side and
// nobody decided whether the operator's limits should size it.
func TestApplySizingClassifiesEveryMap(t *testing.T) {
	sizing, err := DefaultLimits().MapSizing()
	if err != nil {
		t.Fatal(err)
	}
	resize, fixed := sizing.resizable(), fixedSizes()
	if got := len(resize) + len(fixed); got != len(AllMaps) {
		t.Fatalf("%d resizable + %d fixed = %d maps, AllMaps names %d",
			len(resize), len(fixed), got, len(AllMaps))
	}
	for _, name := range AllMaps {
		_, r := resize[name]
		_, f := fixed[name]
		switch {
		case r && f:
			t.Errorf("map %q is listed as both resizable and fixed-size", name)
		case !r && !f:
			t.Errorf("map %q is classified as neither resizable nor fixed-size", name)
		}
	}
}

// TestDefaultLimitsMatchConfig ties this package's defaults to config's.
//
// They have to agree for a specific reason: config applies its defaults when the
// operator names no limits, and this package's defaults are what a hand-built
// Options gets. If they drifted, a Manager built from a Config and a Manager
// built by a test would size their maps differently, and every kernel-side
// assertion about a stride would be testing the wrong number.
//
// config's constants are unexported, so this reads the source — the same
// technique TestRulesPerPolicyMatchesBanCap already uses.
func TestDefaultLimitsMatchConfig(t *testing.T) {
	src := readFile(t, configPath)
	for _, tc := range []struct {
		goName, cName string
		goVal         int
	}{
		{"DefaultMaxDynamicRules", "defaultMaxDynamicRules", DefaultMaxDynamicRules},
		{"DefaultMaxStaticRules", "defaultMaxStaticRules", DefaultMaxStaticRules},
		{"DefaultMaxRatelimitSources", "defaultMaxRatelimitSources", DefaultMaxRatelimitSources},
	} {
		got := goConstInt(t, src, tc.cName)
		if got != tc.goVal {
			t.Errorf("config.%s = %d, dataplane.%s = %d", tc.cName, got, tc.goName, tc.goVal)
		}
	}
}

// goConstInt extracts an integer const from Go source, accepting the shift form
// config uses for the LRU size (`1 << 20`).
func goConstInt(t *testing.T, src, name string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*=\s*(\d+)(?:\s*<<\s*(\d+))?\s*$`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("const %s not found in %s", name, configPath)
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if m[2] != "" {
		sh, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		v <<= sh
	}
	return v
}
