package config

import (
	"net/netip"
	"testing"
)

// TestDataplaneAllowlistContains covers the parsed-allowlist helper the
// source-block path refuses against: bare addresses, CIDRs, family
// separation, and the 4-in-6 normalization.
func TestDataplaneAllowlistContains(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
dataplane:
  enabled: true
  interfaces: ["eth0"]
  allowlist:
    - "198.51.100.7"
    - "192.0.2.0/28"
    - "2001:db8:a::/48"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		addr string
		want bool
	}{
		{"198.51.100.7", true},        // bare address entry
		{"198.51.100.8", false},       // neighbour of the bare entry
		{"192.0.2.5", true},           // inside the v4 CIDR
		{"192.0.2.16", false},         // one past the /28
		{"2001:db8:a::1", true},       // inside the v6 CIDR
		{"2001:db8:b::1", false},      // sibling /48
		{"::ffff:198.51.100.7", true}, // 4-in-6 form of a v4 entry
	}
	for _, tc := range cases {
		if got := cfg.DataplaneAllowlistContains(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("DataplaneAllowlistContains(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}

	// No dataplane block: nothing is allowlisted, nothing panics.
	bare, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("parse bare: %v", err)
	}
	if bare.DataplaneAllowlistContains(netip.MustParseAddr("198.51.100.7")) {
		t.Error("bare config allowlisted an address")
	}
}
