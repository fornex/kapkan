//go:build linux

package dataplane

import (
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
)

// readKernelFlags reads kapkan_cfg[0] back out of the kernel, which is the only
// honest source for what the datapath is actually doing.
func readKernelFlags(t *testing.T, m *Manager) (dryRun, dropMalformed bool) {
	t.Helper()
	var cfg Config
	if err := m.Maps().KapkanCfg.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("read kapkan_cfg[0]: %v", err)
	}
	return cfg.DryRun != 0, cfg.DropMalformed != 0
}

// TestAdoptionRewritesFlags is the regression test for a silent lie: an adopted
// data plane used to keep the PREVIOUS process's dry_run and drop_malformed,
// because installInitialPolicy only stamped kapkan_cfg on the fresh path.
//
// The operator-visible version: run with dry_run: true, satisfy yourself the
// rules match, set dry_run: false, restart. The pins are adopted (dry_run is map
// CONTENTS, so nothing in MapSpec.Compatible or the program tag notices), the
// API reports dry_run: false, and every drop is still rewritten to a pass. The
// config says the filter is armed and the kernel says it is not.
func TestAdoptionRewritesFlags(t *testing.T) {
	dir := pinDir(t)

	// First process: dry-run on, drop_malformed on.
	opts := testOptions(t, dir, "lo")
	opts.DryRun, opts.DropMalformed = true, true
	first := mustOpen(t, opts)
	if dry, drop := readKernelFlags(t, first); !dry || !drop {
		t.Fatalf("first process: kernel dry_run=%v drop_malformed=%v, want both true", dry, drop)
	}
	if err := first.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close(keep): %v", err)
	}

	// Second process, same pins, both flags now OFF. This must be reflected in
	// the kernel, not just in the config the API echoes.
	next := testOptions(t, dir, "lo")
	next.DryRun, next.DropMalformed = false, false
	second := mustOpen(t, next)
	if !second.Health().Adopted {
		t.Fatal("the second Open did not adopt the pinned set, so this test proves nothing")
	}
	if dry, drop := readKernelFlags(t, second); dry || drop {
		t.Errorf("adopted data plane kept the previous process's flags: "+
			"kernel dry_run=%v drop_malformed=%v, config says both false", dry, drop)
	}
	// And the manager must report the kernel's truth, not the config's claim.
	if got := second.EffectiveDryRun(); got {
		t.Errorf("EffectiveDryRun() = true after adopting with dry_run: false")
	}
}

// TestEffectiveDryRunReadsTheKernel proves EffectiveDryRun is a read of
// kapkan_cfg and not an echo of Options, which is the whole reason the API
// exposes dataplane_dry_run as a separate scalar from the global dry_run.
func TestEffectiveDryRunReadsTheKernel(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")
	opts.DryRun = false
	m := mustOpen(t, opts)

	if m.EffectiveDryRun() {
		t.Fatal("EffectiveDryRun() = true with dry_run: false")
	}
	// Flip the flag underneath the manager, the way a reload does.
	if err := m.WithMaps(func(maps *Maps, _ uint32) error {
		return putFlags(maps, Options{DryRun: true})
	}); err != nil {
		t.Fatalf("putFlags: %v", err)
	}
	if !m.EffectiveDryRun() {
		t.Error("EffectiveDryRun() did not follow the kernel flag; it is echoing Options")
	}
}
