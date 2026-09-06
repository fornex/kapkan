package config

import "testing"

// TestParseZonesDryRunIsPerZone pins E4.7's knob in the zones file: a zone's
// policy.dry_run is read and defaults to false (the zone follows its node).
func TestParseZonesDryRunIsPerZone(t *testing.T) {
	z, err := ParseZones([]byte(`
zones:
  - name: watched.example
    origins: ["10.0.0.1:8080"]
    policy: {dry_run: true, rate: {rps: 10}}
  - name: live.example
    origins: ["10.0.0.2:8080"]
    policy: {rate: {rps: 10}}
`))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	if len(z.Zones) != 2 || !z.Zones[0].Policy.DryRun || z.Zones[1].Policy.DryRun {
		t.Fatalf("dry_run per zone: %+v", z.Zones)
	}
}
