package edgedoc

import (
	"net/netip"
	"testing"
)

func TestSourceKey(t *testing.T) {
	cases := map[string]string{
		"198.51.100.7":                  "198.51.100.7",
		"::ffff:198.51.100.7":           "198.51.100.7",
		"2001:db8:1:2:3:4:5:6":          "2001:db8:1:2::",
		"2001:db8:1:2:ffff:ffff:ffff:1": "2001:db8:1:2::",
		"2001:db8:1:3::1":               "2001:db8:1:3::",
		"::1":                           "::",
	}
	for in, want := range cases {
		if got := SourceKey(netip.MustParseAddr(in)); got.String() != want {
			t.Errorf("SourceKey(%s) = %s, want %s", in, got, want)
		}
	}
}
