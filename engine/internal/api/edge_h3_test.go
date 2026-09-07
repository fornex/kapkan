package api

import (
	"bytes"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// The document carries tls.h3_options only where a zone departs from the
// defaults: a zones file that only turns h3 on yields the same bytes as one
// written for E3 plus the "h3": true flag, and nothing more.
func TestBuildEdgeDocH3Options(t *testing.T) {
	zones := func(tls string) *config.Zones {
		z, err := config.ParseZones([]byte("zones:\n  - name: a.example\n    origins: [\"10.0.0.1:80\"]\n    tls: {" + tls + "}\n"))
		if err != nil {
			t.Fatal(err)
		}
		return z
	}
	plain := buildEdgeDoc(zones(`min_version: "1.2"`)).Zones[0].TLS
	if plain.H3 || plain.H3Options != nil {
		t.Fatalf("no h3: %+v", plain)
	}
	on := buildEdgeDoc(zones(`h3: true`)).Zones[0].TLS
	if !on.H3 || on.H3Options != nil {
		t.Fatalf("h3 at the defaults must carry no options: %+v %+v", on, on.H3Options)
	}
	explicit := buildEdgeDoc(zones(`h3: true, h3_options: {advertise: true, alt_svc_max_age_seconds: 86400}`)).Zones[0].TLS
	if explicit.H3Options != nil {
		t.Fatalf("explicit defaults must carry no options: %+v", explicit.H3Options)
	}
	bOn, _, _ := edgeDocBytes(buildEdgeDoc(zones(`h3: true`)))
	bExplicit, _, _ := edgeDocBytes(buildEdgeDoc(zones(`h3: true, h3_options: {advertise: true, alt_svc_max_age_seconds: 86400}`)))
	if !bytes.Equal(bOn, bExplicit) {
		t.Fatal("spelling the defaults out changed the document's bytes")
	}
	quiet := buildEdgeDoc(zones(`h3: true, h3_options: {advertise: false}`)).Zones[0].TLS
	if quiet.H3Options == nil || quiet.H3Options.Advertise == nil || *quiet.H3Options.Advertise || quiet.H3Options.AltSvcMaxAgeSeconds != 0 {
		t.Fatalf("advertise false must travel, the default max-age must not: %+v", quiet.H3Options)
	}
	short := buildEdgeDoc(zones(`h3: true, h3_options: {alt_svc_max_age_seconds: 300}`)).Zones[0].TLS
	if short.H3Options == nil || short.H3Options.Advertise != nil || short.H3Options.AltSvcMaxAgeSeconds != 300 {
		t.Fatalf("a short max-age must travel alone: %+v", short.H3Options)
	}
	_ = edgedoc.DefaultAltSvcMaxAge
}
