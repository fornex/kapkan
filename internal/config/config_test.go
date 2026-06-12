package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
