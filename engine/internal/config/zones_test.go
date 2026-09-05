package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalZones is the smallest zones.yaml that validates: one zone, one origin,
// every policy key left to its default.
const minimalZones = `
zones:
  - name: a.example
    origins: ["10.0.0.1:8080"]
`

func TestParseZonesResolvesDefaults(t *testing.T) {
	z, err := ParseZones([]byte(`
zones:
  - name: Example.COM
    origins: ["10.0.0.1:8080", "[2001:db8::1]:8080", "origin.internal:443"]
`))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	if len(z.Zones) != 1 {
		t.Fatalf("zones = %d, want 1", len(z.Zones))
	}
	zn := z.Zones[0]
	if zn.Name != "example.com" {
		t.Errorf("name = %q, want lowercased example.com", zn.Name)
	}
	if zn.TLS.MinVersion != ZoneTLS12 {
		t.Errorf("tls.min_version = %q, want default %q", zn.TLS.MinVersion, ZoneTLS12)
	}
	if zn.Policy.Mode != ZonePolicyDecide || zn.Policy.FailureMode != ZoneFailOpen || zn.Policy.Challenge != ZoneChallengeOff {
		t.Errorf("policy defaults = %+v, want decide/open/off", zn.Policy)
	}
	if zn.Policy.Rate.RPS != 0 || zn.Policy.Rate.Concurrency != 0 {
		t.Errorf("rate defaults = %+v, want 0/0 (unlimited)", zn.Policy.Rate)
	}
}

// TestParseZonesAcceptsEmpty: "an edge with nothing to serve yet" is legal in
// every spelling a tenant might use for it — an explicit empty list, a 0-byte
// file, a comment-only stub, a blank line — not only `zones: []`.
func TestParseZonesAcceptsEmpty(t *testing.T) {
	for _, in := range []string{"zones: []\n", "", "# zones go here\n", "\n", "---\n", "zones:\n"} {
		z, err := ParseZones([]byte(in))
		if err != nil {
			t.Errorf("ParseZones(%q): %v, want an empty zone set", in, err)
			continue
		}
		if len(z.Zones) != 0 {
			t.Errorf("ParseZones(%q): zones = %d, want 0", in, len(z.Zones))
		}
	}
}

// TestParseZonesCanonicalisesOrigins pins the stored spelling of an origin:
// lowercase hostname or canonical IP text (IPv6 re-bracketed), decimal port —
// so the renderer and the duplicate check see one form per upstream, in file
// order.
func TestParseZonesCanonicalisesOrigins(t *testing.T) {
	z, err := ParseZones([]byte(`
zones:
  - name: a.example
    origins: ["Origin.Internal:443", "[2001:DB8::1]:8443", "10.0.0.1:80"]
`))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	want := []string{"origin.internal:443", "[2001:db8::1]:8443", "10.0.0.1:80"}
	got := z.Zones[0].Origins
	if len(got) != len(want) {
		t.Fatalf("origins = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("origins[%d] = %q, want canonical %q", i, got[i], want[i])
		}
	}
}

func TestParseZonesRejects(t *testing.T) {
	const ok = `    origins: ["10.0.0.1:8080"]`
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"unknown key", "zones:\n  - name: a.example\n" + ok + "\n    colour: blue\n", "colour"},
		{"missing name", "zones:\n  - origins: [\"10.0.0.1:8080\"]\n", "hostname is required"},
		{"wildcard", "zones:\n  - name: \"*.example\"\n" + ok + "\n", "wildcards are not supported"},
		{"ip as name", "zones:\n  - name: 203.0.113.10\n" + ok + "\n", "is an IP address"},
		{"trailing dot", "zones:\n  - name: a.example.\n" + ok + "\n", "must not end with a dot"},
		{"bad label", "zones:\n  - name: -a.example\n" + ok + "\n", "not a valid hostname"},
		{"duplicate zone (case-insensitive)", "zones:\n  - name: a.example\n" + ok + "\n  - name: A.EXAMPLE\n" + ok + "\n", "duplicate zone"},
		{"no origins", "zones:\n  - name: a.example\n    origins: []\n", "at least one host:port"},
		{"origin without port", "zones:\n  - name: a.example\n    origins: [\"10.0.0.1\"]\n", "must be host:port"},
		{"origin port 0", "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:0\"]\n", "port must be 1..65535"},
		{"origin port too big", "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:70000\"]\n", "port must be 1..65535"},
		{"origin bad host", "zones:\n  - name: a.example\n    origins: [\"-bad-:80\"]\n", "neither an IP nor a valid hostname"},
		{"duplicate origin", "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\", \"10.0.0.1:8080\"]\n", "duplicate origin"},
		{"h3 not yet", "zones:\n  - name: a.example\n" + ok + "\n    tls: {h3: true}\n", "tls.h3 is not supported yet"},
		{"bad min_version", "zones:\n  - name: a.example\n" + ok + "\n    tls: {min_version: \"1.1\"}\n", "tls.min_version must be"},
		{"bad acme directory", "zones:\n  - name: a.example\n" + ok + "\n    acme: {directory: \"not a url\"}\n", "acme.directory must be an http(s) URL"},
		{"bad policy mode", "zones:\n  - name: a.example\n" + ok + "\n    policy: {mode: maybe}\n", "policy.mode must be"},
		{"bad failure_mode", "zones:\n  - name: a.example\n" + ok + "\n    policy: {failure_mode: sometimes}\n", "policy.failure_mode must be"},
		{"challenge unknown word", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: js}\n", "policy.challenge must be \"off\", \"manual\" or \"auto\""},
		{"exempt path relative", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [healthz]}}\n", "must be an absolute path prefix"},
		{"exempt path with query", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a?b\"]}}\n", "must be a plain path prefix"},
		{"exempt path with encoding", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a%2Fb\"]}}\n", "must be a plain path prefix"},
		{"exempt path with a path parameter", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a;b/\"]}}\n", "must be a plain path prefix"},
		{"exempt path with a backslash", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a\\\\b/\"]}}\n", "must be a plain path prefix"},
		{"exempt path with a space", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a b/\"]}}\n", "must be a plain path prefix"},
		{"exempt path with a fragment", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a#b/\"]}}\n", "must be a plain path prefix"},
		{"exempt path with braces", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/api/{tenant}/\"]}}\n", "must be a plain path prefix"},
		{"exempt path with non-ASCII", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/api/données/\"]}}\n", "must be a plain path prefix"},
		{"exempt path with a dot segment", "zones:\n  - name: a.example\n" + ok + "\n    policy: {challenge: manual, challenge_options: {exempt_paths: [\"/a/../b\"]}}\n", "must not contain a dot segment"},
		{"relative extra directives", "zones:\n  - name: a.example\n" + ok + "\n    extra_directives_file: conf.d/extra.conf\n", "extra_directives_file must be an absolute path"},
		{"trailing second document", "zones:\n  - name: a.example\n" + ok + "\n---\nzones: []\n", "exactly one YAML document"},
		{"origin port with a sign", "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:+80\"]\n", "port must be 1..65535"},
		{"origin port with a leading zero", "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:0080\"]\n", "leading zero"},
		{"bracketed hostname origin", "zones:\n  - name: a.example\n    origins: [\"[origin.internal]:443\"]\n", "brackets are only for IPv6"},
		{"bracketed IPv4 origin", "zones:\n  - name: a.example\n    origins: [\"[10.0.0.1]:443\"]\n", "brackets are only for IPv6"},
		{"all-digit top-level label", "zones:\n  - name: example.123\n" + ok + "\n", "top-level label must not be all digits"},
		{"duplicate origin after canonicalisation", "zones:\n  - name: a.example\n    origins: [\"Origin.Internal:443\", \"origin.internal:443\"]\n", "duplicate origin"},
		{"duplicate IPv6 origin after canonicalisation", "zones:\n  - name: a.example\n    origins: [\"[2001:DB8::1]:443\", \"[2001:db8:0:0:0:0:0:1]:443\"]\n", "duplicate origin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseZones([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("accepted; want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// writeEdgePair writes a zones.yaml and a kapkan.yaml that references it into
// one temp dir and returns both paths. The config is validBase plus an edge block.
func writeEdgePair(t *testing.T, zonesYAML string) (cfgPath, zonesPath string) {
	t.Helper()
	dir := t.TempDir()
	zonesPath = filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zonesPath, []byte(zonesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "kapkan.yaml")
	cfg := validBase + "\nedge:\n  zones_file: " + zonesPath + "\n  nodes:\n    - name: e1\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, zonesPath
}

func TestLoadFollowsZonesFile(t *testing.T) {
	cfgPath, _ := writeEdgePair(t, minimalZones)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Edge == nil || cfg.ZonesCfg == nil {
		t.Fatalf("Edge=%v ZonesCfg=%v, want both set", cfg.Edge != nil, cfg.ZonesCfg != nil)
	}
	if len(cfg.ZonesCfg.Zones) != 1 || cfg.ZonesCfg.Zones[0].Name != "a.example" {
		t.Errorf("zones = %+v, want the one zone from the file", cfg.ZonesCfg.Zones)
	}
	if cfg.Edge.StaleAfterSeconds != 15 {
		t.Errorf("edge.stale_after_seconds default = %d, want 15", cfg.Edge.StaleAfterSeconds)
	}
}

// TestParseDoesNotReadZones pins the wasm-safety split: Parse validates the edge
// BLOCK but never touches the zones file (it is what the browser validator
// compiles), so ZonesCfg is nil after Parse and set only after Load.
func TestParseDoesNotReadZones(t *testing.T) {
	cfgPath, _ := writeEdgePair(t, minimalZones)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Edge == nil {
		t.Fatal("Parse dropped the edge block")
	}
	if cfg.ZonesCfg != nil {
		t.Fatal("Parse read the zones file; it must stay pure")
	}
}

func TestLoadRejectsBrokenZonesFile(t *testing.T) {
	cfgPath, _ := writeEdgePair(t, "zones:\n  - name: a.example\n    origins: []\n")
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("Load accepted a config whose zones file does not validate")
	}
	if !strings.Contains(err.Error(), "edge.zones_file") || !strings.Contains(err.Error(), "at least one host:port") {
		t.Errorf("err = %q, want it to name edge.zones_file and the zones error", err)
	}
}

func TestLoadRejectsMissingZonesFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kapkan.yaml")
	cfg := validBase + "\nedge:\n  zones_file: " + filepath.Join(dir, "absent.yaml") + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err == nil || !strings.Contains(err.Error(), "edge.zones_file") {
		t.Fatalf("err = %v, want an edge.zones_file read error", err)
	}
}

// TestReloadKeepsPreviousZonesOnBrokenFile is the brain end of "a broken zone
// edit never reaches a running nginx": a zones file that stops validating fails
// the reload as a whole, and the previous zones — not an empty set — stay live.
func TestReloadKeepsPreviousZonesOnBrokenFile(t *testing.T) {
	cfgPath, zonesPath := writeEdgePair(t, minimalZones)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	store := NewStore(cfgPath, cfg)

	if err := os.WriteFile(zonesPath, []byte("zones:\n  - name: a.example\n    origins: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err == nil {
		t.Fatal("Reload accepted a broken zones file")
	}
	if got := store.Get().ZonesCfg; got == nil || len(got.Zones) != 1 {
		t.Fatalf("after failed reload zones = %+v, want the previous single zone still live", got)
	}

	// Fix the file: the reload now applies and the second zone appears.
	two := minimalZones + "  - name: b.example\n    origins: [\"10.0.0.2:8080\"]\n"
	if err := os.WriteFile(zonesPath, []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("Reload after fix: %v", err)
	}
	if got := store.Get().ZonesCfg; got == nil || len(got.Zones) != 2 {
		t.Fatalf("after fixed reload zones = %+v, want 2", got)
	}
}

// TestStoreChangedFiresOnSuccessfulReload pins the wake contract the edge
// long-poll relies on: Changed closes on a successful reload, and a FAILED
// reload leaves waiters asleep (nothing changed, so nothing to re-read).
func TestStoreChangedFiresOnSuccessfulReload(t *testing.T) {
	cfgPath, zonesPath := writeEdgePair(t, minimalZones)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	store := NewStore(cfgPath, cfg)

	closed := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		case <-time.After(200 * time.Millisecond):
			return false
		}
	}

	ch := store.Changed()
	if closed(ch) {
		t.Fatal("Changed closed before any reload")
	}
	if store.Changed() != ch {
		t.Fatal("two subscribers before a reload must share one channel")
	}

	// A failed reload must not wake anyone.
	if err := os.WriteFile(zonesPath, []byte("zones: [{name: a.example}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err == nil {
		t.Fatal("expected the broken zones file to fail the reload")
	}
	if closed(ch) {
		t.Fatal("a failed reload closed the Changed channel")
	}

	// A successful reload wakes the waiter exactly once and hands out a fresh
	// channel to the next subscriber.
	if err := os.WriteFile(zonesPath, []byte(minimalZones), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !closed(ch) {
		t.Fatal("a successful reload did not close the Changed channel")
	}
	if next := store.Changed(); next == ch || closed(next) {
		t.Fatal("after a wake, Changed must return a fresh, open channel")
	}
}
