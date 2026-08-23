//go:build linux

package dataplane

import "testing"

// TestManagerWritesFingerprintConfig proves the E2.3 wiring end to end in the
// kernel: Options carrying the fingerprint knobs (from OptionsFromConfig) are
// stamped into kapkan_cfg at attach, so the datapath's fp path is actually armed
// by the operator's config — not left off as it was in the E2.1 kernel-only cut.
func TestManagerWritesFingerprintConfig(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkfpc")
	opts := testOptions(t, dir, iface)
	opts.FPEnabled = true
	opts.FPSamplePPS = 500

	m := mustOpen(t, opts)
	cfg, err := ReadConfig(m.Maps())
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.FpEnabled != 1 {
		t.Errorf("kapkan_cfg.fp_enabled = %d, want 1 (Options.FPEnabled was true)", cfg.FpEnabled)
	}
	if want := q32PerNs(500); cfg.FpRatePerNsQ32 != want {
		t.Errorf("kapkan_cfg.fp_rate_per_ns_q32 = %d, want %d", cfg.FpRatePerNsQ32, want)
	}
	if cfg.FpBurst != 500 {
		t.Errorf("kapkan_cfg.fp_burst = %d, want 500 (default = one second of the rate)", cfg.FpBurst)
	}
}

// TestManagerFingerprintOffByDefault confirms a Manager opened without the fp
// knobs leaves the plane disabled in the kernel — the copy path stays inert
// until an operator turns it on.
func TestManagerFingerprintOffByDefault(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkfpd")
	m := mustOpen(t, testOptions(t, dir, iface))
	cfg, err := ReadConfig(m.Maps())
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.FpEnabled != 0 {
		t.Errorf("kapkan_cfg.fp_enabled = %d, want 0 by default", cfg.FpEnabled)
	}
}
