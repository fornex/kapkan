//go:build !js

package config

import (
	"strings"
	"testing"
)

// These pin that, on a normal (server) build, statFile is the real os.Stat:
// the geoip-database and exec-hook file checks in validate() still reject a
// missing path. The wasm build replaces statFile with a stub that defers these
// checks (see statfile_js.go); that deferral is exercised in-browser, not here.
func TestStatFileChecksRejectMissingPathsNatively(t *testing.T) {
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{
			name:    "missing geoip database",
			extra:   "\ngeoip:\n  enabled: true\n  asn_database: \"/nonexistent/GeoLite2-ASN.mmdb\"\n",
			wantErr: "geoip.asn_database",
		},
		{
			name:    "missing exec hook",
			extra:   "\nnotify:\n  exec:\n    command: \"/nonexistent/kapkan-hook.sh\"\n",
			wantErr: "notify.exec.command",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(validBase + c.extra))
			if err == nil {
				t.Fatalf("expected rejection for %s, got nil", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.wantErr)
			}
		})
	}
}
