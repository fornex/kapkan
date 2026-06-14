package config

import (
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validYAML = `
dry_run: true
listen:
  sflow: ":6343"
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
  - "2001:db8::/32"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
notify:
  telegram:
    token_env: "KAPKAN_TG_TOKEN"
    chat_id: "-1001234567890"
  webhook:
    url: ""
api:
  listen: "127.0.0.1:8080"
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.DryRun {
		t.Error("DryRun = false, want true")
	}
	if got := len(cfg.NetworkPrefixes); got != 2 {
		t.Errorf("len(NetworkPrefixes) = %d, want 2", got)
	}
	if cfg.BGP.CommunityValue != 65000<<16|666 {
		t.Errorf("CommunityValue = %d, want %d", cfg.BGP.CommunityValue, 65000<<16|666)
	}
	if !cfg.InNetworks(netip.MustParseAddr("203.0.113.7")) {
		t.Error("InNetworks(203.0.113.7) = false, want true")
	}
	if cfg.InNetworks(netip.MustParseAddr("198.51.100.1")) {
		t.Error("InNetworks(198.51.100.1) = true, want false")
	}
	if !cfg.IsWhitelisted(netip.MustParseAddr("203.0.113.1")) {
		t.Error("IsWhitelisted(203.0.113.1) = false, want true")
	}
}

func TestDryRunDefaultsTrue(t *testing.T) {
	yaml := strings.Replace(validYAML, "dry_run: true\n", "", 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.DryRun {
		t.Error("absent dry_run must default to true")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "bad cidr",
			mutate:  func(s string) string { return strings.Replace(s, "203.0.113.0/24", "203.0.113.0/99", 1) },
			wantErr: "invalid CIDR",
		},
		{
			name:    "overlapping networks",
			mutate:  func(s string) string { return strings.Replace(s, `"2001:db8::/32"`, `"203.0.113.0/25"`, 1) },
			wantErr: "overlaps",
		},
		{
			name:    "duplicate networks",
			mutate:  func(s string) string { return strings.Replace(s, `"2001:db8::/32"`, `"203.0.113.0/24"`, 1) },
			wantErr: "duplicate",
		},
		{
			name:    "zero pps threshold",
			mutate:  func(s string) string { return strings.Replace(s, "pps: 80000", "pps: 0", 1) },
			wantErr: "thresholds",
		},
		{
			name:    "zero mbps threshold",
			mutate:  func(s string) string { return strings.Replace(s, "mbps: 1000", "mbps: 0", 1) },
			wantErr: "thresholds",
		},
		{
			name: "no networks",
			mutate: func(s string) string {
				return strings.Replace(s, "networks:\n  - \"203.0.113.0/24\"\n  - \"2001:db8::/32\"\n", "networks: []\n", 1)
			},
			wantErr: "at least one protected prefix",
		},
		{
			name:    "bad whitelist ip",
			mutate:  func(s string) string { return strings.Replace(s, `"203.0.113.1"`, `"not-an-ip"`, 1) },
			wantErr: "protected_whitelist",
		},
		{
			name:    "zero ttl",
			mutate:  func(s string) string { return strings.Replace(s, "ttl_seconds: 600", "ttl_seconds: 0", 1) },
			wantErr: "ttl_seconds",
		},
		{
			name:    "zero max bans",
			mutate:  func(s string) string { return strings.Replace(s, "max_active_bans: 50", "max_active_bans: 0", 1) },
			wantErr: "max_active_bans",
		},
		{
			name:    "bad community",
			mutate:  func(s string) string { return strings.Replace(s, `community: "65000:666"`, `community: "no-colon"`, 1) },
			wantErr: "community",
		},
		{
			name: "bad router id",
			mutate: func(s string) string {
				return strings.Replace(s, `router_id: "10.0.0.1"`, `router_id: "2001:db8::1"`, 1)
			},
			wantErr: "router_id",
		},
		{
			name:    "bad neighbor address",
			mutate:  func(s string) string { return strings.Replace(s, `address: "10.0.0.254"`, `address: "nope"`, 1) },
			wantErr: "neighbors",
		},
		{
			name:    "zero neighbor asn",
			mutate:  func(s string) string { return strings.Replace(s, "remote_asn: 65000", "remote_asn: 0", 1) },
			wantErr: "remote_asn",
		},
		{
			name:    "zero sampling rate",
			mutate:  func(s string) string { return strings.Replace(s, "default_rate: 1000", "default_rate: 0", 1) },
			wantErr: "default_rate",
		},
		{
			name:    "unknown field",
			mutate:  func(s string) string { return s + "\nbogus_key: 1\n" },
			wantErr: "bogus_key",
		},
		{
			name:    "bad api listen",
			mutate:  func(s string) string { return strings.Replace(s, `listen: "127.0.0.1:8080"`, `listen: "???"`, 1) },
			wantErr: "api.listen",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(validYAML)))
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

const hostgroupsYAML = validYAML + `
hostgroups:
  - name: web
    networks:
      - "203.0.113.0/26"
    thresholds:
      pps: 10000
      mbps: 100
      flows_per_sec: 5000
  - name: web-special
    networks:
      - "203.0.113.0/28"
    ban: false
  - name: dns-total
    networks:
      - "203.0.113.64/26"
    calculation: total
    thresholds:
      pps: 200000
      mbps: 2000
      flows_per_sec: 100000
`

func TestHostgroupsResolved(t *testing.T) {
	cfg, err := Parse([]byte(hostgroupsYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(cfg.Groups) != 4 {
		t.Fatalf("len(Groups) = %d, want 4 (implicit global + 3)", len(cfg.Groups))
	}
	if g := cfg.Groups[0]; g.Name != GlobalGroup || g.Calc != CalcPerHost || !g.BanEnabled || g.Thresholds != cfg.Thresholds {
		t.Errorf("Groups[0] = %+v, want implicit global group with top-level thresholds", g)
	}

	tests := []struct {
		addr      string
		wantGroup string
		wantPPS   uint64
		wantCalc  CalcMethod
		wantBan   bool
	}{
		// /28 beats /26 by longest prefix match; thresholds inherited.
		{"203.0.113.5", "web-special", 80000, CalcPerHost, false},
		// inside /26 but outside /28.
		{"203.0.113.20", "web", 10000, CalcPerHost, true},
		// total group never bans.
		{"203.0.113.70", "dns-total", 200000, CalcTotal, false},
		// inside networks but no hostgroup → global.
		{"203.0.113.200", GlobalGroup, 80000, CalcPerHost, true},
		{"2001:db8::1", GlobalGroup, 80000, CalcPerHost, true},
	}
	for _, tt := range tests {
		g := cfg.GroupFor(netip.MustParseAddr(tt.addr))
		if g.Name != tt.wantGroup {
			t.Errorf("GroupFor(%s).Name = %q, want %q", tt.addr, g.Name, tt.wantGroup)
			continue
		}
		if g.Thresholds.PPS != tt.wantPPS {
			t.Errorf("GroupFor(%s).Thresholds.PPS = %d, want %d", tt.addr, g.Thresholds.PPS, tt.wantPPS)
		}
		if g.Calc != tt.wantCalc {
			t.Errorf("GroupFor(%s).Calc = %q, want %q", tt.addr, g.Calc, tt.wantCalc)
		}
		if g.BanEnabled != tt.wantBan {
			t.Errorf("GroupFor(%s).BanEnabled = %v, want %v", tt.addr, g.BanEnabled, tt.wantBan)
		}
	}
}

func TestNoHostgroupsStillHasGlobalGroup(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(cfg.Groups) != 1 {
		t.Fatalf("len(Groups) = %d, want 1", len(cfg.Groups))
	}
	if g := cfg.GroupFor(netip.MustParseAddr("203.0.113.7")); g.Name != GlobalGroup {
		t.Errorf("GroupFor() = %q, want %q", g.Name, GlobalGroup)
	}
}

func TestHostgroupErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "missing name",
			mutate:  func(s string) string { return strings.Replace(s, "name: web\n", `name: ""`+"\n", 1) },
			wantErr: "name is required",
		},
		{
			name:    "reserved name",
			mutate:  func(s string) string { return strings.Replace(s, "name: web\n", "name: global\n", 1) },
			wantErr: "reserved",
		},
		{
			name:    "duplicate name",
			mutate:  func(s string) string { return strings.Replace(s, "name: web-special", "name: web", 1) },
			wantErr: "duplicate name",
		},
		{
			name:    "bad calculation",
			mutate:  func(s string) string { return strings.Replace(s, "calculation: total", "calculation: median", 1) },
			wantErr: "calculation",
		},
		{
			name:    "bad group cidr",
			mutate:  func(s string) string { return strings.Replace(s, `"203.0.113.0/26"`, `"203.0.113.0/99"`, 1) },
			wantErr: "invalid CIDR",
		},
		{
			name:    "prefix outside networks",
			mutate:  func(s string) string { return strings.Replace(s, `"203.0.113.64/26"`, `"198.51.100.0/26"`, 1) },
			wantErr: "not inside any configured networks",
		},
		{
			name:    "duplicate prefix across groups",
			mutate:  func(s string) string { return strings.Replace(s, `"203.0.113.0/28"`, `"203.0.113.0/26"`, 1) },
			wantErr: "already belongs to group",
		},
		{
			name:    "zero group threshold",
			mutate:  func(s string) string { return strings.Replace(s, "pps: 10000", "pps: 0", 1) },
			wantErr: "must all be > 0",
		},
		{
			name: "ban true on total group",
			mutate: func(s string) string {
				return strings.Replace(s, "calculation: total", "calculation: total\n    ban: true", 1)
			},
			wantErr: "ban: true is not allowed",
		},
		{
			name: "empty group networks",
			mutate: func(s string) string {
				return strings.Replace(s, "networks:\n      - \"203.0.113.0/28\"\n", "networks: []\n", 1)
			},
			wantErr: "at least one prefix",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(hostgroupsYAML)))
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseCommunity(t *testing.T) {
	tests := []struct {
		in      string
		want    uint32
		wantErr bool
	}{
		{"65000:666", 65000<<16 | 666, false},
		{"0:0", 0, false},
		{"65535:65535", 0xFFFFFFFF, false},
		{"65536:1", 0, true},
		{"1:65536", 0, true},
		{"no-colon", 0, true},
		{"a:b", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseCommunity(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseCommunity(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseCommunity(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStoreReload(t *testing.T) {
	path := writeTemp(t, validYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	store := NewStore(path, cfg)

	// Threshold change is allowed.
	updated := strings.Replace(validYAML, "pps: 80000", "pps: 90000", 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := store.Reload()
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if next.Thresholds.PPS != 90000 {
		t.Errorf("PPS after reload = %d, want 90000", next.Thresholds.PPS)
	}
	if store.Get().Thresholds.PPS != 90000 {
		t.Error("Get() did not observe the reloaded config")
	}

	// Invalid file keeps the previous config active.
	if err := os.WriteFile(path, []byte("thresholds: {pps: 0}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err == nil {
		t.Fatal("Reload() with invalid file: error = nil, want error")
	}
	if store.Get().Thresholds.PPS != 90000 {
		t.Error("failed reload must keep previous config")
	}

	// Listen address change is rejected.
	relisten := strings.Replace(updated, `sflow: ":6343"`, `sflow: ":9999"`, 1)
	if err := os.WriteFile(path, []byte(relisten), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("Reload() with listen change: error = %v, want listen-change rejection", err)
	}
}

const outgoingYAML = hostgroupsYAML + `
thresholds_outgoing:
  pps: 50000
  udp_pps: 20000
`

func TestOutgoingThresholdsResolved(t *testing.T) {
	cfg, err := Parse([]byte(outgoingYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.OutgoingEnabled {
		t.Error("OutgoingEnabled = false, want true")
	}
	// Global group and groups without their own block inherit the global
	// outgoing thresholds.
	if got := cfg.Groups[0].OutThresholds; got == nil || got.PPS != 50000 || got.UDPPPS != 20000 {
		t.Errorf("global group OutThresholds = %+v, want pps 50000 / udp_pps 20000", got)
	}
	if got := cfg.GroupFor(netip.MustParseAddr("203.0.113.20")).OutThresholds; got == nil || got.PPS != 50000 {
		t.Errorf("web group OutThresholds = %+v, want inherited global outgoing", got)
	}
}

func TestNoOutgoingMeansDisabled(t *testing.T) {
	cfg, err := Parse([]byte(hostgroupsYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.OutgoingEnabled {
		t.Error("OutgoingEnabled = true without any thresholds_outgoing block")
	}
	if cfg.Groups[0].OutThresholds != nil {
		t.Error("global group OutThresholds must be nil when outgoing is not configured")
	}
}

func TestGroupOutgoingOverride(t *testing.T) {
	yaml := strings.Replace(outgoingYAML, "  - name: web\n", "  - name: web\n    thresholds_outgoing:\n      tcp_syn_pps: 5000\n", 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	g := cfg.GroupFor(netip.MustParseAddr("203.0.113.20"))
	if g.Name != "web" {
		t.Fatalf("group = %q, want web", g.Name)
	}
	if g.OutThresholds == nil || g.OutThresholds.TCPSYNPPS != 5000 || g.OutThresholds.PPS != 0 {
		t.Errorf("web OutThresholds = %+v, want only tcp_syn_pps 5000", g.OutThresholds)
	}
}

func TestPerProtocolThresholdsParsed(t *testing.T) {
	yaml := strings.Replace(validYAML, "  flows_per_sec: 35000\n",
		"  flows_per_sec: 35000\n  udp_pps: 40000\n  tcp_syn_pps: 5000\n  frag_pps: 3000\n", 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	th := cfg.Thresholds
	if th.UDPPPS != 40000 || th.TCPSYNPPS != 5000 || th.FragPPS != 3000 {
		t.Errorf("per-protocol thresholds = %+v, want udp 40000 / syn 5000 / frag 3000", th)
	}
	if th.TCPPPS != 0 {
		t.Errorf("unset tcp_pps = %d, want 0 (disabled)", th.TCPPPS)
	}
}

func TestOutgoingValidationErrors(t *testing.T) {
	empty := validYAML + "\nthresholds_outgoing: {}\n"
	if _, err := Parse([]byte(empty)); err == nil || !strings.Contains(err.Error(), "thresholds_outgoing") {
		t.Errorf("empty global outgoing block: error = %v, want thresholds_outgoing rejection", err)
	}
	groupEmpty := strings.Replace(hostgroupsYAML, "  - name: web\n", "  - name: web\n    thresholds_outgoing: {}\n", 1)
	if _, err := Parse([]byte(groupEmpty)); err == nil || !strings.Contains(err.Error(), "thresholds_outgoing") {
		t.Errorf("empty group outgoing block: error = %v, want thresholds_outgoing rejection", err)
	}
}

func TestSampleSettings(t *testing.T) {
	// Defaults with no block.
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := SampleSettings{Enabled: true, BufferFlows: 65536, FlowsPerAttack: 20}
	if cfg.SampleCfg != want {
		t.Errorf("default SampleCfg = %+v, want %+v", cfg.SampleCfg, want)
	}

	// Explicit values.
	cfg, err = Parse([]byte(validYAML + "\nsamples:\n  buffer_flows: 1024\n  flows_per_attack: 50\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.SampleCfg.BufferFlows != 1024 || cfg.SampleCfg.FlowsPerAttack != 50 || !cfg.SampleCfg.Enabled {
		t.Errorf("SampleCfg = %+v, want 1024/50/enabled", cfg.SampleCfg)
	}

	// Disabled skips size validation.
	cfg, err = Parse([]byte(validYAML + "\nsamples:\n  enabled: false\n  buffer_flows: 8\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.SampleCfg.Enabled {
		t.Error("SampleCfg.Enabled = true, want false")
	}

	// Errors.
	if _, err := Parse([]byte(validYAML + "\nsamples:\n  buffer_flows: 8\n")); err == nil {
		t.Error("tiny buffer_flows accepted, want error")
	}
	if _, err := Parse([]byte(validYAML + "\nsamples:\n  flows_per_attack: 1000\n")); err == nil {
		t.Error("oversized flows_per_attack accepted, want error")
	}
}

func TestReloadRejectsSampleChanges(t *testing.T) {
	path := writeTemp(t, validYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	store := NewStore(path, cfg)
	if err := os.WriteFile(path, []byte(validYAML+"\nsamples:\n  buffer_flows: 1024\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err == nil || !strings.Contains(err.Error(), "samples") {
		t.Errorf("Reload() with samples change: error = %v, want samples-change rejection", err)
	}
}

func TestReloadAcceptsUnchangedAndDisabledSampleEdits(t *testing.T) {
	// Unchanged samples block (with explicit enabled pointer) must reload
	// fine — the guard compares resolved settings, not raw pointers.
	withSamples := validYAML + "\nsamples:\n  enabled: true\n  buffer_flows: 1024\n"
	path := writeTemp(t, withSamples)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	store := NewStore(path, cfg)
	if err := os.WriteFile(path, []byte(withSamples), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Errorf("Reload() with unchanged samples block: error = %v, want success", err)
	}

	// Editing sizes while sampling stays disabled changes nothing at
	// runtime and must not demand a restart.
	disabledA := validYAML + "\nsamples:\n  enabled: false\n  buffer_flows: 1024\n"
	disabledB := validYAML + "\nsamples:\n  enabled: false\n  buffer_flows: 2048\n"
	path2 := writeTemp(t, disabledA)
	cfg2, err := Load(path2)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	store2 := NewStore(path2, cfg2)
	if err := os.WriteFile(path2, []byte(disabledB), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Reload(); err != nil {
		t.Errorf("Reload() editing sizes while disabled: error = %v, want success", err)
	}
}

func TestBufferFlowsUpperBound(t *testing.T) {
	if _, err := Parse([]byte(validYAML + "\nsamples:\n  buffer_flows: 16777216\n")); err == nil || !strings.Contains(err.Error(), "buffer_flows") {
		t.Errorf("oversized buffer_flows: error = %v, want bound rejection", err)
	}
}

func TestNotifyChannelValidation(t *testing.T) {
	add := func(block string) string { return strings.Replace(validYAML, "notify:\n", "notify:\n"+block, 1) }

	// Valid: all three channels configured (/bin/sh exists and is executable).
	good := add("  slack:\n    webhook_url: \"https://hooks.slack.com/services/T0/B0/x\"\n" +
		"  email:\n    smtp_host: \"mail.example.com:587\"\n    from: \"kapkan@example.com\"\n    to: [\"ops@example.com\"]\n" +
		"  exec:\n    command: \"/bin/sh\"\n")
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Notify.Exec.TimeoutSeconds != 10 {
		t.Errorf("exec timeout default = %d, want 10", cfg.Notify.Exec.TimeoutSeconds)
	}

	// http to loopback is allowed (local relays, tests).
	if _, err := Parse([]byte(add("  slack:\n    webhook_url: \"http://127.0.0.1:9000/hook\"\n"))); err != nil {
		t.Errorf("loopback http slack URL rejected: %v", err)
	}

	nonExec := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(nonExec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, block, wantErr string
	}{
		{"bad slack url", "  slack:\n    webhook_url: \"not a url\"\n", "slack.webhook_url"},
		{"plain http slack url", "  slack:\n    webhook_url: \"http://hooks.example.com/x\"\n", "must be https"},
		{"email without port", "  email:\n    smtp_host: \"mail.example.com\"\n    from: \"a@b\"\n    to: [\"c@d\"]\n", "smtp_host"},
		{"email without from", "  email:\n    smtp_host: \"mail.example.com:587\"\n    to: [\"c@d\"]\n", "email.from"},
		{"email without recipients", "  email:\n    smtp_host: \"mail.example.com:587\"\n    from: \"a@b\"\n", "email.to"},
		{"relative exec path", "  exec:\n    command: \"hook.sh\"\n", "absolute path"},
		{"missing exec file", "  exec:\n    command: \"/nonexistent/kapkan-hook\"\n", "exec.command"},
		{"non-executable exec file", "  exec:\n    command: \"" + nonExec + "\"\n", "not an executable"},
		{"exec timeout out of range", "  exec:\n    command: \"/bin/sh\"\n    timeout_seconds: 9000\n", "timeout_seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(add(tt.block)))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestHostgroupNameCharset(t *testing.T) {
	for _, bad := range []string{"web group", "web\r\nBcc: x@y", "web<b>", "тест", strings.Repeat("a", 65)} {
		yaml := strings.Replace(hostgroupsYAML, "name: web\n", "name: \""+strings.ReplaceAll(bad, "\r\n", `\r\n`)+"\"\n", 1)
		if _, err := Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "must match") {
			t.Errorf("name %q: error = %v, want charset rejection", bad, err)
		}
	}
	// The allowed charset keeps realistic names working.
	yaml := strings.Replace(hostgroupsYAML, "name: web\n", "name: \"Web_pool.v2-east\"\n", 1)
	if _, err := Parse([]byte(yaml)); err != nil {
		t.Errorf("valid name rejected: %v", err)
	}
}

func TestBaselineResolution(t *testing.T) {
	// No block: baselines off everywhere.
	cfg, err := Parse([]byte(hostgroupsYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	for _, g := range cfg.Groups {
		if g.Baseline != nil {
			t.Errorf("group %q has baselines without a baseline block", g.Name)
		}
	}

	// Global block with defaults applied; groups inherit.
	withBase := hostgroupsYAML + "\nbaseline:\n  floor:\n    pps: 5000\n    mbps: 50\n    flows_per_sec: 2000\n"
	cfg, err = Parse([]byte(withBase))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	bs := cfg.Groups[0].Baseline
	if bs == nil {
		t.Fatal("global group baseline = nil, want resolved settings")
	}
	if bs.Factor != 3 || bs.WarmupSeconds != 600 {
		t.Errorf("defaults = factor %g / warmup %d, want 3 / 600", bs.Factor, bs.WarmupSeconds)
	}
	// alpha = 1 - 2^(-1/half_life), pinned exactly: a 1/half_life
	// approximation differs by ~44% and must not pass.
	wantAlpha := 1 - math.Exp2(-1.0/3600)
	if math.Abs(bs.Alpha-wantAlpha) > 1e-12 {
		t.Errorf("alpha = %.10g, want %.10g (1 - 2^(-1/half_life))", bs.Alpha, wantAlpha)
	}
	if g := cfg.GroupFor(netip.MustParseAddr("203.0.113.20")); g.Baseline != bs {
		t.Error("hostgroup did not inherit the global baseline settings")
	}

	// Per-group override and per-group opt-out.
	override := strings.Replace(withBase, "  - name: web\n",
		"  - name: web\n    baseline:\n      factor: 5\n      floor:\n        pps: 1000\n        mbps: 10\n        flows_per_sec: 500\n", 1)
	override = strings.Replace(override, "  - name: web-special\n",
		"  - name: web-special\n    baseline:\n      enabled: false\n", 1)
	cfg, err = Parse([]byte(override))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if g := cfg.GroupFor(netip.MustParseAddr("203.0.113.20")); g.Baseline == nil || g.Baseline.Factor != 5 {
		t.Errorf("web override = %+v, want factor 5", g.Baseline)
	}
	if g := cfg.GroupFor(netip.MustParseAddr("203.0.113.5")); g.Baseline != nil {
		t.Errorf("web-special opted out but Baseline = %+v", g.Baseline)
	}
}

func TestBaselineValidation(t *testing.T) {
	base := validYAML + "\nbaseline:\n  floor:\n    pps: 5000\n    mbps: 50\n    flows_per_sec: 2000\n"
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"missing floor", validYAML + "\nbaseline:\n  factor: 3\n", "floor"},
		{"tiny factor", strings.Replace(base, "baseline:\n", "baseline:\n  factor: 1.1\n", 1), "factor"},
		{"nan factor", strings.Replace(base, "baseline:\n", "baseline:\n  factor: .nan\n", 1), "factor"},
		{"bad half life", strings.Replace(base, "baseline:\n", "baseline:\n  half_life_seconds: 5\n", 1), "half_life"},
		{"bad warmup", strings.Replace(base, "baseline:\n", "baseline:\n  warmup_seconds: 90000\n", 1), "warmup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestAPIDashboardAndToken(t *testing.T) {
	// Defaults: dashboard on, no token.
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.API.DashboardEnabled() {
		t.Error("dashboard should default to enabled")
	}
	if cfg.API.TokenEnv != "" {
		t.Errorf("token_env = %q, want empty by default", cfg.API.TokenEnv)
	}

	// Explicit disable + token.
	y := strings.Replace(validYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  dashboard: false\n  token_env: \"KAPKAN_API_TOKEN\"\n", 1)
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.API.DashboardEnabled() {
		t.Error("dashboard: false not honored")
	}
	if cfg.API.TokenEnv != "KAPKAN_API_TOKEN" {
		t.Errorf("token_env = %q, want KAPKAN_API_TOKEN", cfg.API.TokenEnv)
	}

	// Bad token env name.
	bad := strings.Replace(validYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  token_env: \"bad name!\"\n", 1)
	if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "token_env") {
		t.Errorf("bad token_env: error = %v, want rejection", err)
	}
}

func TestStorageResolution(t *testing.T) {
	// Absent: disabled.
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.StorageCfg.Enabled {
		t.Error("storage enabled without a clickhouse url")
	}

	// Configured with defaults.
	y := validYAML + "\nstorage:\n  clickhouse:\n    url: \"http://127.0.0.1:8123/\"\n"
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	s := cfg.StorageCfg
	if !s.Enabled || s.URL != "http://127.0.0.1:8123" || s.Database != "kapkan" {
		t.Errorf("storage = %+v, want enabled, trimmed url, default db", s)
	}
	if s.TTLDays != 7 || s.BatchSize != 1000 || s.QueueSize != 100000 {
		t.Errorf("defaults = %+v, want 7/1000/100000", s)
	}
	if s.FlushInterval != 5*time.Second || s.TrafficInterval != 10*time.Second {
		t.Errorf("interval defaults = %v/%v, want 5s/10s", s.FlushInterval, s.TrafficInterval)
	}

	tests := []struct{ name, block, wantErr string }{
		{"bad url", "  clickhouse:\n    url: \"ftp://x\"\n", "url"},
		{"bad db", "  clickhouse:\n    url: \"http://x:8123\"\n    database: \"bad-name\"\n", "database"},
		{"ttl out of range", "  clickhouse:\n    url: \"http://x:8123\"\n    ttl_days: 9999\n", "ttl_days"},
		{"batch over queue", "  clickhouse:\n    url: \"http://x:8123\"\n    batch_size: 50\n    queue_size: 10\n", "batch_size"},
		{"bad username env", "  clickhouse:\n    url: \"http://x:8123\"\n    username_env: \"no good\"\n", "username_env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(validYAML + "\nstorage:\n" + tt.block))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestMitigationResolution(t *testing.T) {
	// Default: blackhole everywhere.
	cfg, err := Parse([]byte(hostgroupsYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	for _, g := range cfg.Groups {
		if g.Mitigation != MitigateBlackhole {
			t.Errorf("group %q method = %q, want blackhole default", g.Name, g.Mitigation)
		}
	}

	// Global flowspec/discard, one group overriding to rate_limit.
	y := strings.Replace(hostgroupsYAML, "hostgroups:",
		"mitigation: flowspec\nflowspec:\n  action: discard\nhostgroups:", 1)
	y = strings.Replace(y, "  - name: web\n",
		"  - name: web\n    mitigation: flowspec\n    flowspec:\n      action: rate_limit\n      rate_mbps: 100\n", 1)
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if g := cfg.Groups[0]; g.Mitigation != MitigateFlowSpec || g.FlowSpecAction != FlowSpecDiscard || g.FlowSpecRateBps != 0 {
		t.Errorf("global group = %+v, want flowspec/discard/0", g)
	}
	web := cfg.GroupFor(netip.MustParseAddr("203.0.113.20"))
	if web.Name != "web" || web.Mitigation != MitigateFlowSpec || web.FlowSpecAction != FlowSpecRateLimit {
		t.Fatalf("web group = %+v, want flowspec/rate_limit", web)
	}
	if web.FlowSpecRateBps != 100*1e6/8 {
		t.Errorf("web rate = %v bytes/s, want %v (100 Mbit/s)", web.FlowSpecRateBps, 100*1e6/8)
	}

	tests := []struct{ name, mut, wantErr string }{
		{"bad method", strings.Replace(hostgroupsYAML, "hostgroups:", "mitigation: nope\nhostgroups:", 1), "method"},
		{"rate_limit without rate", strings.Replace(hostgroupsYAML, "hostgroups:", "mitigation: flowspec\nflowspec:\n  action: rate_limit\nhostgroups:", 1), "rate_mbps"},
		{"bad action", strings.Replace(hostgroupsYAML, "hostgroups:", "mitigation: flowspec\nflowspec:\n  action: bogus\nhostgroups:", 1), "action"},
		{"flowspec on total group", strings.Replace(hostgroupsYAML, "    calculation: total\n", "    calculation: total\n    mitigation: flowspec\n", 1), "total"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.mut)); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestEscalationResolution(t *testing.T) {
	// No escalation block: synthesized single rung from the method.
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	g := cfg.Groups[0]
	if len(g.Escalation) != 1 || g.Escalation[0].AfterSeconds != 0 || g.Escalation[0].Action != EscalateBlackhole {
		t.Errorf("default ladder = %+v, want one blackhole rung at 0", g.Escalation)
	}

	// Global ladder none → flowspec → blackhole; flowspec policy resolved
	// even though the single `mitigation` is the default blackhole.
	y := validYAML + "\nflowspec:\n  action: discard\nescalation:\n" +
		"  - {after_seconds: 0, action: none}\n" +
		"  - {after_seconds: 30, action: flowspec}\n" +
		"  - {after_seconds: 120, action: blackhole}\n"
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	g = cfg.Groups[0]
	if len(g.Escalation) != 3 {
		t.Fatalf("ladder = %+v, want 3 rungs", g.Escalation)
	}
	want := []EscalationStage{{0, EscalateNone}, {30, EscalateFlowSpec}, {120, EscalateBlackhole}}
	for i, s := range want {
		if g.Escalation[i] != s {
			t.Errorf("rung %d = %+v, want %+v", i, g.Escalation[i], s)
		}
	}
	if g.FlowSpecAction != FlowSpecDiscard {
		t.Errorf("flowspec policy not resolved for a flowspec stage: action=%q", g.FlowSpecAction)
	}

	tests := []struct{ name, esc, wantErr string }{
		{"first not zero", "  - {after_seconds: 5, action: blackhole}\n", "after_seconds must be 0"},
		{"not increasing", "  - {after_seconds: 0, action: none}\n  - {after_seconds: 0, action: blackhole}\n", "greater than"},
		{"bad action", "  - {after_seconds: 0, action: nuke}\n", "action must be"},
		{"too many", "  - {after_seconds: 0, action: none}\n  - {after_seconds: 1, action: none}\n  - {after_seconds: 2, action: none}\n  - {after_seconds: 3, action: none}\n  - {after_seconds: 4, action: none}\n  - {after_seconds: 5, action: none}\n", "at most"},
		{"de-escalate blackhole→flowspec", "  - {after_seconds: 0, action: blackhole}\n  - {after_seconds: 5, action: flowspec}\n", "de-escalates"},
		{"de-escalate flowspec→none", "  - {after_seconds: 0, action: flowspec}\n  - {after_seconds: 5, action: none}\n", "de-escalates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(validYAML + "\nescalation:\n" + tt.esc)); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestEscalationTotalGroup(t *testing.T) {
	// Explicit flowspec stage on a total group is an error.
	y := strings.Replace(hostgroupsYAML, "    calculation: total\n",
		"    calculation: total\n    escalation:\n      - {after_seconds: 0, action: flowspec}\n", 1)
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "total") {
		t.Errorf("explicit flowspec stage on total group: error = %v, want total-group rejection", err)
	}

	// Inherited global flowspec stage degrades to blackhole on the total group.
	y = hostgroupsYAML + "\nflowspec:\n  action: discard\nescalation:\n  - {after_seconds: 0, action: flowspec}\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	tot := cfg.GroupFor(netip.MustParseAddr("203.0.113.70")) // dns-total
	if tot.Calc != CalcTotal {
		t.Fatalf("group = %+v, want the total group", tot)
	}
	if tot.Escalation[0].Action != EscalateBlackhole {
		t.Errorf("total group inherited stage = %q, want degraded to blackhole", tot.Escalation[0].Action)
	}
	// A per_host group keeps the inherited flowspec stage.
	web := cfg.GroupFor(netip.MustParseAddr("203.0.113.20"))
	if web.Escalation[0].Action != EscalateFlowSpec {
		t.Errorf("web group stage = %q, want flowspec inherited", web.Escalation[0].Action)
	}
}

func TestBGPAttributesResolution(t *testing.T) {
	// Global defaults flow into the implicit global group.
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	g := cfg.Groups[0]
	if g.BlackholeNextHop != "192.0.2.1" || g.BlackholeCommunityStr != "65000:666" {
		t.Errorf("global next-hop/community = %q/%q", g.BlackholeNextHop, g.BlackholeCommunityStr)
	}
	if len(g.BlackholeCommunities) != 1 || g.BlackholeCommunities[0] != 65000<<16|666 {
		t.Errorf("global communities = %v", g.BlackholeCommunities)
	}
	if g.LocalPref != 0 {
		t.Errorf("global local-pref = %d, want 0 (unset)", g.LocalPref)
	}

	// Per-group override: own communities, next-hops, and local-pref.
	override := hostgroupsYAML + `
  - name: customer-a
    networks:
      - "203.0.113.128/26"
    bgp:
      next_hop: "192.0.2.50"
      next_hop6: "100::50"
      communities: ["65000:100", "65001:200"]
      local_pref: 250
`
	cfg, err = Parse([]byte(override))
	if err != nil {
		t.Fatalf("Parse() with bgp override error = %v", err)
	}
	ca := cfg.GroupFor(netip.MustParseAddr("203.0.113.130"))
	if ca.Name != "customer-a" {
		t.Fatalf("GroupFor(.130) = %q, want customer-a", ca.Name)
	}
	if ca.BlackholeNextHop != "192.0.2.50" || ca.BlackholeNextHop6 != "100::50" {
		t.Errorf("override next-hops = %q / %q", ca.BlackholeNextHop, ca.BlackholeNextHop6)
	}
	want := []uint32{65000<<16 | 100, 65001<<16 | 200}
	if len(ca.BlackholeCommunities) != 2 || ca.BlackholeCommunities[0] != want[0] || ca.BlackholeCommunities[1] != want[1] {
		t.Errorf("override communities = %v, want %v", ca.BlackholeCommunities, want)
	}
	if ca.BlackholeCommunityStr != "65000:100 65001:200" {
		t.Errorf("override community str = %q", ca.BlackholeCommunityStr)
	}
	if ca.LocalPref != 250 {
		t.Errorf("override local-pref = %d, want 250", ca.LocalPref)
	}

	// A group with no bgp override inherits the global attributes.
	web := cfg.GroupFor(netip.MustParseAddr("203.0.113.32")) // "web", no bgp block
	if web.Name != "web" {
		t.Fatalf("GroupFor(.32) = %q, want web", web.Name)
	}
	if web.BlackholeNextHop != "192.0.2.1" || web.BlackholeCommunityStr != "65000:666" || web.LocalPref != 0 {
		t.Errorf("inherited attrs = %q / %q / %d", web.BlackholeNextHop, web.BlackholeCommunityStr, web.LocalPref)
	}

	// Global multi-community + local-pref defaults propagate to groups without
	// an override.
	gy := strings.Replace(validYAML, "  community: \"65000:666\"\n",
		"  community: \"65000:666\"\n  communities: [\"65000:1\", \"65000:2\"]\n  local_pref: 120\n", 1)
	cfg, err = Parse([]byte(gy))
	if err != nil {
		t.Fatalf("Parse() global communities error = %v", err)
	}
	g = cfg.Groups[0]
	if len(g.BlackholeCommunities) != 2 || g.LocalPref != 120 || g.BlackholeCommunityStr != "65000:1 65000:2" {
		t.Errorf("global multi-community/local-pref = %v / %d / %q", g.BlackholeCommunities, g.LocalPref, g.BlackholeCommunityStr)
	}

	// Invalid per-group overrides are rejected.
	bad := []struct{ name, block, wantErr string }{
		{"bad community", "      communities: [\"nope\"]\n", "communities"},
		{"empty community list", "      communities: []\n", "at least one community"},
		{"next_hop wrong family", "      next_hop: \"2001:db8::1\"\n", "next_hop must be a valid IPv4"},
		{"next_hop6 wrong family", "      next_hop6: \"192.0.2.9\"\n", "next_hop6 must be a valid IPv6"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			y := hostgroupsYAML + "\n  - name: c\n    networks:\n      - \"203.0.113.200/29\"\n    bgp:\n" + tt.block
			if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want contains %q", err, tt.wantErr)
			}
		})
	}

	// An explicitly-empty global communities list is rejected too (rather than
	// silently falling back to the single community).
	ge := strings.Replace(validYAML, "  community: \"65000:666\"\n",
		"  community: \"65000:666\"\n  communities: []\n", 1)
	if _, err := Parse([]byte(ge)); err == nil || !strings.Contains(err.Error(), "at least one community") {
		t.Errorf("global empty communities: error = %v, want rejection", err)
	}
}
