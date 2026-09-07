package config

import (
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// tls.h3 is accepted from E5.3 on; its options default to "announce, a day"
// and are refused on a zone that does not speak h3.
func TestParseZonesH3(t *testing.T) {
	z, err := ParseZones([]byte(`
zones:
  - name: h3.example
    origins: ["10.0.0.1:8080"]
    tls: {h3: true}
  - name: quiet.example
    origins: ["10.0.0.2:8080"]
    tls: {h3: true, h3_options: {advertise: false, alt_svc_max_age_seconds: 300}}
  - name: tcp.example
    origins: ["10.0.0.3:8080"]
`))
	if err != nil {
		t.Fatal(err)
	}
	h3, quiet, tcp := z.Zones[0].TLS, z.Zones[1].TLS, z.Zones[2].TLS
	if !h3.H3 || h3.H3Options.Advertise == nil || !*h3.H3Options.Advertise || h3.H3Options.AltSvcMaxAgeSeconds != edgedoc.DefaultAltSvcMaxAge {
		t.Errorf("h3 defaults: %+v", h3)
	}
	if !quiet.H3 || quiet.H3Options.Advertise == nil || *quiet.H3Options.Advertise || quiet.H3Options.AltSvcMaxAgeSeconds != 300 {
		t.Errorf("quiet: %+v", quiet)
	}
	if tcp.H3 || tcp.H3Options.Advertise != nil || tcp.H3Options.AltSvcMaxAgeSeconds != 0 {
		t.Errorf("a zone without h3 must keep zero options (the document stays byte-identical): %+v", tcp)
	}
	// Boundaries of the range are accepted.
	for _, ma := range []int{60, 604800} {
		if _, err := ParseZones([]byte("zones:\n  - name: a.example\n    origins: [\"10.0.0.1:80\"]\n    tls: {h3: true, h3_options: {alt_svc_max_age_seconds: " + itoa(ma) + "}}\n")); err != nil {
			t.Errorf("alt_svc_max_age_seconds %d refused: %v", ma, err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
