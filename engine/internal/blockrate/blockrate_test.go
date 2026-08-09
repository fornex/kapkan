package blockrate

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
)

// TestCatalogIsWellFormed runs every fixture's own invariants. It is the cheap
// half of the suite and it runs on EVERY host, so a fixture that lost its
// legitimate baseline, its allowlisted frames or its telemetry fails on the
// development loop rather than in the privileged container.
func TestCatalogIsWellFormed(t *testing.T) {
	fixtures := Fixtures()
	if len(fixtures) != 18 {
		t.Errorf("catalog holds %d fixtures, want 18 — the suite's coverage is a stated claim", len(fixtures))
	}
	seen := map[string]bool{}
	targets := map[string]string{}
	for _, f := range fixtures {
		if err := f.Validate(); err != nil {
			t.Errorf("%v", err)
			continue
		}
		if seen[f.Name] {
			t.Errorf("duplicate fixture name %q", f.Name)
		}
		seen[f.Name] = true
		// Two fixtures sharing a victim would interfere: they run against one
		// kernel at the same time, so one fixture's rules would score the
		// other's frames.
		if prev, dup := targets[f.Target()]; dup {
			t.Errorf("fixtures %q and %q share the target %s; their rules would collide",
				prev, f.Name, f.Target())
		}
		targets[f.Target()] = f.Name
	}
}

// TestEveryClassifiedVectorHasAFixture is the coverage gate. The classifier
// names eleven vectors plus `mixed`; a release that added a twelfth and no
// fixture for it would ship a vector with no measured block rate, which is
// precisely the gap this suite exists to close.
func TestEveryClassifiedVectorHasAFixture(t *testing.T) {
	covered := map[engine.AttackType]string{}
	for _, f := range Fixtures() {
		if prev, ok := covered[f.WantClass]; !ok {
			covered[f.WantClass] = f.Name
		} else {
			_ = prev // several fixtures may share a class (v4/v6, VLAN, ext hdrs)
		}
	}
	for _, typ := range engine.AttackTypes() {
		if _, ok := covered[typ]; !ok {
			t.Errorf("the classifier can produce %q but no fixture covers it; "+
				"documentation may not quote a block rate for it", typ)
		}
	}
}

// TestCommittedFixturesMatchTheCatalog is the drift gate: the bytes on disk
// must be exactly what the catalog generates. Without it the committed
// captures would be a snapshot of some earlier version of the fixtures, and
// the suite would keep reporting numbers for an attack it no longer describes.
func TestCommittedFixturesMatchTheCatalog(t *testing.T) {
	fixtures := Fixtures()
	want := map[string]bool{}
	for _, f := range fixtures {
		want[f.PcapName()] = true
		t.Run(f.Name, func(t *testing.T) {
			generated, err := f.Pcap()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			committed, err := f.CommittedPcap()
			if err != nil {
				t.Fatalf("read committed capture: %v", err)
			}
			if !bytes.Equal(generated, committed) {
				t.Fatalf("the committed capture (%d bytes) differs from the catalog (%d bytes); "+
					"run `make blockrate-fixtures` and commit the result",
					len(committed), len(generated))
			}
			// And it must read back into the same number of frames the roles
			// label, or every rate the suite reports is computed against the
			// wrong denominators.
			if _, err := f.CommittedFrames(); err != nil {
				t.Fatalf("%v", err)
			}
		})
	}

	names, err := CommittedNames()
	if err != nil {
		t.Fatalf("list committed captures: %v", err)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("testdata/%s belongs to no fixture; it is embedded and would look like "+
				"part of the suite — run `make blockrate-fixtures`", n)
		}
	}
}

// TestSuiteConfigsAreReal parses the two YAML documents the suite runs under
// through the product's own validator. A configuration a customer could not
// write would make every number below it unquotable.
func TestSuiteConfigsAreReal(t *testing.T) {
	for name, yaml := range map[string]string{
		"hosts":  ConfigYAML("/sys/fs/bpf/kapkan-blockrate"),
		"carpet": CarpetConfigYAML("/sys/fs/bpf/kapkan-blockrate-carpet"),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfig(yaml)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if !cfg.DataplaneEnabled() {
				t.Error("the data plane is not enabled; the suite would measure nothing")
			}
			if cfg.DryRun {
				t.Error("dry_run is on; the live pass would install nothing")
			}
		})
	}
}

// TestFixturePolicyMatchesTheConfig checks the two halves that have to agree by
// hand: a fixture that names a hostgroup must land in it, and every victim must
// be inside the configured networks (a victim outside them is refused by the
// mitigator's own safety rule and would score a block rate of zero for a
// reason that has nothing to do with the data plane).
func TestFixturePolicyMatchesTheConfig(t *testing.T) {
	hosts, err := ParseConfig(ConfigYAML("/sys/fs/bpf/kapkan-blockrate"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	carpet, err := ParseConfig(CarpetConfigYAML("/sys/fs/bpf/kapkan-blockrate-carpet"))
	if err != nil {
		t.Fatalf("%v", err)
	}

	for _, f := range Fixtures() {
		cfg := hosts
		if f.Scope == ScopePrefix {
			cfg = carpet
		}
		t.Run(f.Name, func(t *testing.T) {
			switch f.Scope {
			case ScopeHost:
				if !cfg.InNetworks(f.Victim) {
					t.Fatalf("victim %s is outside the configured networks", f.Victim)
				}
				if cfg.IsWhitelisted(f.Victim) {
					t.Fatalf("victim %s is on protected_whitelist and can never be banned", f.Victim)
				}
				want := f.Group
				if want == "" {
					want = config.GlobalGroup
				}
				if got := cfg.GroupFor(f.Victim).Name; got != want {
					t.Errorf("victim %s resolves to group %q, fixture wants %q", f.Victim, got, want)
				}
			case ScopePrefix:
				if !cfg.PrefixInNetworks(f.Prefix) {
					t.Fatalf("prefix %s is outside the configured networks", f.Prefix)
				}
				if cfg.PrefixContainsWhitelisted(f.Prefix) {
					t.Fatalf("prefix %s contains a whitelisted address; carpet mitigation refuses it", f.Prefix)
				}
			}
		})
	}
}

// TestAllowlistedSourcesAreOnlyEverAllowlisted guards a mistake that would make
// the allowlist assertion vacuous in the opposite direction: if an allowlisted
// address were also used as an ordinary attacker or client source, a fixture's
// attack or legitimate frames would be passed at precedence 1 and the block
// rate would silently be measured against a smaller denominator.
func TestAllowlistedSourcesAreOnlyEverAllowlisted(t *testing.T) {
	allow := map[netip.Addr]bool{AllowV4: true, AllowV6: true}
	for _, f := range Fixtures() {
		for i, role := range f.Roles {
			src := f.Frames[i].SrcIP
			switch role {
			case RoleAllow:
				if !allow[src] {
					t.Errorf("%s: frame %d is labelled allowlisted but its source is %s", f.Name, i, src)
				}
			default:
				if allow[src] {
					t.Errorf("%s: frame %d (%s) comes from the allowlisted source %s; it would "+
						"pass at precedence 1 and corrupt the rate", f.Name, i, role, src)
				}
			}
		}
	}
}
