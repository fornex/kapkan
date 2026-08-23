package config

import (
	"strings"
	"testing"
)

const goodJA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"

func TestParseAcceptsFingerprint(t *testing.T) {
	yaml := validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n" +
		"  fingerprint:\n    enabled: true\n    sample_pps: 500\n    block_ttl_seconds: 60\n" +
		"    ja4_blocklist: [\"" + goodJA4 + "\"]\n"
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("a valid fingerprint block should parse, got: %v", err)
	}
	if !cfg.DataplaneCfg.FingerprintEnabled {
		t.Error("DataplaneCfg.FingerprintEnabled = false, want true")
	}
	if cfg.DataplaneCfg.FingerprintSamplePPS != 500 {
		t.Errorf("FingerprintSamplePPS = %d, want 500", cfg.DataplaneCfg.FingerprintSamplePPS)
	}
	fp := cfg.Dataplane.Fingerprint
	if fp.BlockTTLSeconds != 60 || len(fp.JA4Blocklist) != 1 || fp.JA4Blocklist[0] != goodJA4 {
		t.Errorf("fingerprint = %+v, want ttl 60 and one JA4", fp)
	}
}

func TestFingerprintDefaults(t *testing.T) {
	yaml := validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n" +
		"  fingerprint:\n    enabled: true\n"
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("fingerprint with only enabled should parse, got: %v", err)
	}
	fp := cfg.Dataplane.Fingerprint
	if fp.SamplePPS != defaultFingerprintSamplePPS {
		t.Errorf("sample_pps default = %d, want %d", fp.SamplePPS, defaultFingerprintSamplePPS)
	}
	if fp.BlockTTLSeconds != defaultFingerprintBlockTTLSeconds {
		t.Errorf("block_ttl_seconds default = %d, want %d", fp.BlockTTLSeconds, defaultFingerprintBlockTTLSeconds)
	}
}

func TestParseRejectsFingerprint(t *testing.T) {
	cases := []struct {
		name, block, wantErr string
	}{
		{
			name:    "enabled without a data plane",
			block:   "  enabled: false\n  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n",
			wantErr: "requires dataplane.enabled",
		},
		{
			name:    "malformed JA4",
			block:   "  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n    ja4_blocklist: [\"not-a-ja4\"]\n",
			wantErr: "not a JA4",
		},
		{
			name:    "duplicate JA4",
			block:   "  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n    ja4_blocklist: [\"" + goodJA4 + "\", \"" + goodJA4 + "\"]\n",
			wantErr: "duplicate",
		},
		{
			name:    "TTL too large",
			block:   "  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n    block_ttl_seconds: 999999\n",
			wantErr: "block_ttl_seconds",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(validBase + "\ndataplane:\n" + tc.block))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
