package config

import (
	"strings"
	"testing"
)

const validScrubYAML = `
controller:
  url: "https://kapkan.example.net:8443"
  token_env: KAPKAN_AGENT_TOKEN
  name: scrub-fra1
dataplane:
  interfaces: [eth0]
`

func TestParseScrubDefaults(t *testing.T) {
	sc, err := ParseScrub([]byte(validScrubYAML))
	if err != nil {
		t.Fatalf("ParseScrub: %v", err)
	}
	// The remote-role safety default: absent dry_run means TRUE.
	if !sc.DryRunResolved() {
		t.Error("absent dry_run must resolve to true on a remote role")
	}
	if sc.Controller.ReportIntervalSeconds != 10 {
		t.Errorf("report interval default = %d, want 10", sc.Controller.ReportIntervalSeconds)
	}
	// The dataplane block resolves through the same validator as the daemon's.
	if !sc.DataplaneCfg.Enabled || sc.DataplaneCfg.Interfaces != "eth0" {
		t.Errorf("resolved dataplane = %+v", sc.DataplaneCfg)
	}
	if sc.DataplaneCfg.XDPMode != XDPModeAuto || sc.DataplaneCfg.PinPath == "" {
		t.Errorf("dataplane defaults not applied: %+v", sc.DataplaneCfg)
	}

	// An explicit false is honored — it just cannot be the accident.
	sc, err = ParseScrub([]byte("dry_run: false\n" + validScrubYAML))
	if err != nil {
		t.Fatalf("ParseScrub(dry_run:false): %v", err)
	}
	if sc.DryRunResolved() {
		t.Error("explicit dry_run: false must resolve to false")
	}
}

func TestParseScrubRejections(t *testing.T) {
	cases := []struct{ name, yaml, wantErr string }{
		{"no controller url", strings.Replace(validScrubYAML, "  url: \"https://kapkan.example.net:8443\"\n", "", 1), "controller.url is required"},
		{"bad scheme", strings.Replace(validScrubYAML, "https://kapkan.example.net:8443", "ftp://x", 1), "must be an http(s) URL"},
		{"url with path", strings.Replace(validScrubYAML, "https://kapkan.example.net:8443", "https://x/api", 1), "must not carry a path"},
		{"no token env", strings.Replace(validScrubYAML, "  token_env: KAPKAN_AGENT_TOKEN\n", "", 1), "token_env"},
		{"bad node name", strings.Replace(validScrubYAML, "scrub-fra1", "no spaces!", 1), "controller.name"},
		{"no dataplane", strings.Replace(validScrubYAML, "dataplane:\n  interfaces: [eth0]\n", "", 1), "dataplane block is required"},
		{"dataplane disabled", strings.Replace(validScrubYAML, "dataplane:\n", "dataplane:\n  enabled: false\n", 1), "must not be false"},
		{"unknown key", validScrubYAML + "policy: {}\n", "field policy not found"},
		{"dataplane keys validated", strings.Replace(validScrubYAML, "[eth0]", "[\"bad iface!\"]", 1), "not a valid interface name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseScrub([]byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParseScrub error = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
}
