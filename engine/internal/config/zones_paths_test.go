package config

import (
	"strings"
	"testing"
)

// The zone name and the extra_directives_file are interpolated into the node's
// nginx configuration and into a file name; these are the limits the brain
// enforces before a document is ever served (the renderer mirrors them).
func TestParseZonesRejectsUnrenderableValues(t *testing.T) {
	longName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 47) // 239
	if len(longName) != 239 {
		t.Fatalf("test name is %d characters", len(longName))
	}
	okName := longName[:238]
	if okName[len(okName)-1] == '.' {
		t.Fatal("test name ends in a dot")
	}
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"239-character name", "zones:\n  - name: " + longName + "\n    origins: [\"10.0.0.1:443\"]\n", "at most 238"},
		{"glob in extra file", "zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    extra_directives_file: \"/etc/kapkan/[prod]-extra.conf\"\n", "misread"},
		{"star in extra file", "zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    extra_directives_file: \"/etc/kapkan/*.conf\"\n", "misread"},
		{"semicolon in extra file", "zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    extra_directives_file: \"/etc/kapkan/x.conf;\"\n", "misread"},
		{"space in extra file", "zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    extra_directives_file: \"/etc/kapkan/my extra.conf\"\n", "misread"},
		{"fallback not a URL", "zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    acme:\n      fallback: not-a-url\n", "acme.fallback must be an http(s) URL"},
		{"fallback equals directory", "zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    acme:\n      directory: https://ca.example/dir\n      fallback: https://ca.example/dir\n", "different directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseZones([]byte(c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
	// The boundary itself is accepted.
	if _, err := ParseZones([]byte("zones:\n  - name: " + okName + "\n    origins: [\"10.0.0.1:443\"]\n")); err != nil {
		t.Fatalf("238-character name rejected: %v", err)
	}
	if _, err := ParseZones([]byte("zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    extra_directives_file: /etc/kapkan/extra/example.com.conf\n")); err != nil {
		t.Fatalf("plain extra_directives_file rejected: %v", err)
	}
	z, err := ParseZones([]byte("zones:\n  - name: example.com\n    origins: [\"10.0.0.1:443\"]\n    acme:\n      directory: https://ca.example/dir\n      fallback: https://other-ca.example/dir\n"))
	if err != nil || z.Zones[0].ACME.Fallback != "https://other-ca.example/dir" {
		t.Fatalf("acme.fallback: %+v %v", z, err)
	}
}
