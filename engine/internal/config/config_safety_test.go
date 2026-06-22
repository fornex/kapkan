package config

import (
	"strings"
	"testing"
)

// withBanField appends a single extra field to the ban block of validYAML.
// The base ban block ends with "max_active_bans: 50"; we splice the new line
// (with the same 2-space indent) right after it so the field lands inside the
// ban mapping rather than at the document root.
func withBanField(line string) func(string) string {
	return func(s string) string {
		return strings.Replace(s,
			"  max_active_bans: 50\n",
			"  max_active_bans: 50\n  "+line+"\n", 1)
	}
}

// withCarpet appends a carpet block to validYAML. The block is valid on its
// own; callers pass an override line that replaces one field inside it to make
// it invalid for exactly one reason. carpet validation runs (validateCarpet)
// before the ban-fraction/rate checks, so a corrupted carpet field surfaces
// the carpet error rather than an unrelated later guard.
func withCarpet(block string) func(string) string {
	return func(s string) string {
		return s + "\ncarpet:\n" + block
	}
}

// validCarpet is a minimally-valid carpet block: aggregation prefixes in range,
// min_hosts >= 2, at least one aggregate threshold set, and a sane prefix-ban
// cap. Tests corrupt exactly one line of this to exercise a single guard.
const validCarpet = `  aggregation_prefix_v4: 24
  aggregation_prefix_v6: 48
  min_hosts: 64
  max_active_prefix_bans: 10
  thresholds:
    pps: 500000
`

// TestParseSafetyValidators proves the safety-critical validators in validate()
// and validateCarpet() actually REJECT out-of-bounds input. These guards bound
// blast radius (max_banned_fraction), throttle ban storms (max_bans_per_window
// + ban_window_seconds), and constrain carpet aggregation/fan-out — a future
// refactor silently dropping any of them would otherwise go uncaught.
//
// Mirrors TestParseErrors: table-driven {name, mutate, wantErr} over validYAML,
// asserting the validation error contains wantErr.
func TestParseSafetyValidators(t *testing.T) {
	// Sanity: the carpet skeleton tests build on must parse cleanly on its own,
	// so a carpet failure below is attributable to the single corrupted field
	// and not to a broken base block.
	if _, err := Parse([]byte(withCarpet(validCarpet)(validYAML))); err != nil {
		t.Fatalf("base validYAML + validCarpet must parse, got error: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		// --- Ban.MaxBannedFraction bounds [0,1] (config.go:~922) ---
		{
			name:    "max_banned_fraction negative",
			mutate:  withBanField("max_banned_fraction: -0.5"),
			wantErr: "ban.max_banned_fraction must be between 0 and 1",
		},
		{
			name:    "max_banned_fraction above one",
			mutate:  withBanField("max_banned_fraction: 1.5"),
			wantErr: "ban.max_banned_fraction must be between 0 and 1",
		},

		// --- Ban.MaxBansPerWindow / Ban.BanWindowSeconds (config.go:~925-932) ---
		{
			name:    "max_bans_per_window negative",
			mutate:  withBanField("max_bans_per_window: -1"),
			wantErr: "ban.max_bans_per_window must be >= 0",
		},
		{
			name:    "ban_window_seconds negative",
			mutate:  withBanField("ban_window_seconds: -10"),
			wantErr: "ban.ban_window_seconds must be >= 0",
		},
		{
			// Cross-field rule: a rate is set but the window is zero/unset, so the
			// rate limiter would never reset — must be rejected.
			name:    "rate set with zero window",
			mutate:  withBanField("max_bans_per_window: 5"),
			wantErr: "ban.ban_window_seconds must be > 0 when ban.max_bans_per_window is set",
		},

		// --- validateCarpet aggregation_prefix_v4 (8..32) ---
		{
			name: "carpet v4 prefix too low",
			mutate: withCarpet(strings.Replace(validCarpet,
				"aggregation_prefix_v4: 24", "aggregation_prefix_v4: 4", 1)),
			wantErr: "carpet.aggregation_prefix_v4 must be in 8..32",
		},
		{
			name: "carpet v4 prefix too high",
			mutate: withCarpet(strings.Replace(validCarpet,
				"aggregation_prefix_v4: 24", "aggregation_prefix_v4: 40", 1)),
			wantErr: "carpet.aggregation_prefix_v4 must be in 8..32",
		},

		// --- validateCarpet aggregation_prefix_v6 (16..128) ---
		{
			name: "carpet v6 prefix too low",
			mutate: withCarpet(strings.Replace(validCarpet,
				"aggregation_prefix_v6: 48", "aggregation_prefix_v6: 8", 1)),
			wantErr: "carpet.aggregation_prefix_v6 must be in 16..128",
		},
		{
			name: "carpet v6 prefix too high",
			mutate: withCarpet(strings.Replace(validCarpet,
				"aggregation_prefix_v6: 48", "aggregation_prefix_v6: 130", 1)),
			wantErr: "carpet.aggregation_prefix_v6 must be in 16..128",
		},

		// --- validateCarpet min_hosts (>= 2) ---
		{
			name: "carpet min_hosts too low",
			mutate: withCarpet(strings.Replace(validCarpet,
				"min_hosts: 64", "min_hosts: 1", 1)),
			wantErr: "carpet.min_hosts must be >= 2",
		},

		// --- validateCarpet max_active_prefix_bans (>= 1) ---
		// 0 is a defaulting sentinel (-> 10), so use a negative to hit the guard.
		{
			name: "carpet max_active_prefix_bans below one",
			mutate: withCarpet(strings.Replace(validCarpet,
				"max_active_prefix_bans: 10", "max_active_prefix_bans: -1", 1)),
			wantErr: "carpet.max_active_prefix_bans must be >= 1",
		},

		// --- validateCarpet zero thresholds ---
		// Remove the only threshold line so Thresholds.Zero() is true.
		{
			name: "carpet zero thresholds",
			mutate: withCarpet(strings.Replace(validCarpet,
				"  thresholds:\n    pps: 500000\n", "", 1)),
			wantErr: "carpet.thresholds: set at least one aggregate threshold",
		},

		// --- validateCarpet invalid mitigation method ---
		{
			name:    "carpet invalid mitigation",
			mutate:  withCarpet(validCarpet + "  mitigation: \"teleport\"\n"),
			wantErr: "carpet.mitigation must be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(validYAML)))
			if err == nil {
				t.Fatal("Parse() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
