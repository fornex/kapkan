package config

import (
	"strings"
	"testing"
)

func TestUpdateCheckDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.UpdateCheck.Enabled {
		t.Error("update_check must default to disabled")
	}
	if cfg.UpdateCheck.Channel != "stable" {
		t.Errorf("channel default = %q, want stable", cfg.UpdateCheck.Channel)
	}
	if cfg.UpdateCheck.IntervalSeconds != 21600 {
		t.Errorf("interval_seconds default = %d, want 21600", cfg.UpdateCheck.IntervalSeconds)
	}
}

func TestUpdateCheckValidation(t *testing.T) {
	withBlock := func(block string) string { return validYAML + "\n" + block }

	// A fully-specified valid block parses.
	cfg, err := Parse([]byte(withBlock("update_check:\n  enabled: true\n  channel: prerelease\n  interval_seconds: 3600\n  url: \"https://example.test/r\"\n")))
	if err != nil {
		t.Fatalf("valid block: %v", err)
	}
	if !cfg.UpdateCheck.Enabled || cfg.UpdateCheck.Channel != "prerelease" || cfg.UpdateCheck.IntervalSeconds != 3600 {
		t.Fatalf("parsed = %+v", cfg.UpdateCheck)
	}

	cases := []struct {
		name, block, wantErr string
	}{
		{"bad channel", "update_check:\n  channel: nightly\n", "channel"},
		{"interval below floor", "update_check:\n  interval_seconds: 60\n", "interval_seconds"},
		{"non-http url", "update_check:\n  url: \"ftp://x/y\"\n", "url"},
		{"garbage url", "update_check:\n  url: \"not a url\"\n", "url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(withBlock(tc.block)))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
