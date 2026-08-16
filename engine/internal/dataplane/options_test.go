package dataplane

// Tests for the config-to-Options translation and the restart-required rules.
// No kernel involved, so these run on every host — which is the point: this is
// the layer that turns an operator's YAML into the numbers the kernel is given,
// and getting it wrong means a rule that never fires.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
)

// baseYAML is the smallest config that validates, matching the one in
// internal/config's own tests.
const baseYAML = `
listen:
  sflow: ":6343"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
thresholds:
  pps: 1000
  mbps: 100
  flows_per_sec: 500
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 60
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
api:
  listen: "127.0.0.1:8080"
`

func mustParse(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(baseYAML + extra))
	if err != nil {
		t.Fatalf("config.Parse: %v\n--- yaml ---\n%s", err, baseYAML+extra)
	}
	return cfg
}

func TestOptionsFromConfig(t *testing.T) {
	cfg := mustParse(t, `
protected_whitelist:
  - "203.0.113.5"
dataplane:
  interfaces: ["eth0", "eth1"]
  xdp_mode: generic
  on_exit: detach
  pin_path: /sys/fs/bpf/kap
  drop_malformed: true
  allowlist:
    - "198.51.100.0/24"
    - "2001:db8::1"
  ratelimit_profiles:
    - {name: slow, pps: 1000}
    - {name: fat, mbps: 100}
  static_rules:
    - name: drop-chargen
      match: {proto: udp, src_port: 19}
      action: drop
    - name: cap-icmp
      match: {proto: icmp}
      action: ratelimit
      profile: slow
    - name: allow-mgmt
      match: {src: "192.0.2.7", proto: tcp, dst_port: 22}
      action: pass
  limits:
    max_dynamic_rules: 512
    max_static_rules: 64
    max_ratelimit_sources: 65536
`)
	opts, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}

	if got, want := strings.Join(opts.Interfaces, ","), "eth0,eth1"; got != want {
		t.Errorf("Interfaces = %q, want %q", got, want)
	}
	if opts.XDPMode != config.XDPModeGeneric {
		t.Errorf("XDPMode = %q", opts.XDPMode)
	}
	if opts.OnExit != config.OnExitDetach {
		t.Errorf("OnExit = %q", opts.OnExit)
	}
	if opts.PinPath != "/sys/fs/bpf/kap" {
		t.Errorf("PinPath = %q", opts.PinPath)
	}
	if !opts.DropMalformed {
		t.Error("DropMalformed = false, config said true")
	}
	want := Limits{MaxDynamicRules: 512, MaxStaticRules: 64, MaxRatelimitSources: 65536}
	if opts.Limits != want {
		t.Errorf("Limits = %+v, want %+v", opts.Limits, want)
	}

	// Allowlist: a bare address becomes a host route, a CIDR stays a CIDR.
	gotAllow := prefixStringSet(opts.Policy.Allow)
	for _, w := range []string{"198.51.100.0/24", "2001:db8::1/128"} {
		if !gotAllow[w] {
			t.Errorf("allowlist is missing %s (got %v)", w, opts.Policy.Allow)
		}
	}
	// protected_whitelist is a list of bare addresses in config and becomes host
	// routes here. Both axes must be in the kernel: "never touch this sender"
	// and "never ban this victim" are different questions.
	if got := prefixStringSet(opts.Policy.Protected); !got["203.0.113.5/32"] {
		t.Errorf("protected list = %v, want 203.0.113.5/32", opts.Policy.Protected)
	}

	if len(opts.Policy.Profiles) != 2 {
		t.Fatalf("profiles = %+v", opts.Policy.Profiles)
	}
	if opts.Policy.Profiles[0] != (NamedRate{Name: "slow", PPS: 1000}) {
		t.Errorf("profile[0] = %+v", opts.Policy.Profiles[0])
	}

	if len(opts.Policy.Statics) != 3 {
		t.Fatalf("statics = %+v", opts.Policy.Statics)
	}
	r0 := opts.Policy.Statics[0]
	if r0.Name != "drop-chargen" || r0.Action != ActionDrop || r0.Proto == nil || *r0.Proto != protoUDP ||
		r0.SrcPort == nil || *r0.SrcPort != 19 || r0.DstPort != nil || r0.Src.IsValid() {
		t.Errorf("drop-chargen compiled to %+v", r0)
	}
	r2 := opts.Policy.Statics[2]
	if r2.Src.String() != "192.0.2.7/32" || r2.Action != ActionPass ||
		r2.DstPort == nil || *r2.DstPort != 22 {
		t.Errorf("allow-mgmt compiled to %+v", r2)
	}
}

// TestPayloadMatchCompilesToMatchExt walks the whole path a ClientHello rule
// takes on its way to the kernel: config YAML -> StaticRule -> encoded
// kapkan_rule. It is one test rather than three because the interesting failure
// is a break anywhere along it, and the symptom is always the same silent one —
// match_ext left at zero, so the rule stops narrowing and rate-limits every
// packet the rest of its match admits, which for the canonical rule is all of
// tcp/443.
func TestPayloadMatchCompilesToMatchExt(t *testing.T) {
	cfg := mustParse(t, `
dataplane:
  interfaces: ["eth0"]
  ratelimit_profiles:
    - {name: hs, pps: 20}
  static_rules:
    - name: cap-handshakes
      match: {proto: tcp, dst_port: 443, payload: tls_client_hello}
      action: ratelimit
      profile: hs
    - name: cap-https
      match: {proto: tcp, dst_port: 443}
      action: ratelimit
      profile: hs
`)
	opts, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	if len(opts.Policy.Statics) != 2 {
		t.Fatalf("statics = %+v", opts.Policy.Statics)
	}

	hs := opts.Policy.Statics[0]
	if hs.MatchExt != MatchTLSClientHello {
		t.Errorf("cap-handshakes MatchExt = %#02x, want %#02x", hs.MatchExt, MatchTLSClientHello)
	}
	// The neighbouring rule differs only in the payload line. If it also
	// carried the bit, the mapping would be reading the wrong field and the
	// first assertion would still pass.
	if plain := opts.Policy.Statics[1]; plain.MatchExt != 0 {
		t.Errorf("cap-https MatchExt = %#02x, want 0 — it names no payload predicate", plain.MatchExt)
	}

	r, err := RuleSpec{
		Action:   ActionRateLimit,
		Proto:    hs.Proto,
		DstPort:  hs.DstPort,
		MatchExt: hs.MatchExt,
	}.Encode()
	if err != nil {
		t.Fatalf("encoding the compiled rule: %v", err)
	}
	if r.MatchExt != MatchTLSClientHello {
		t.Errorf("encoded MatchExt = %#02x, want %#02x", r.MatchExt, MatchTLSClientHello)
	}
}

// TestEncodeRejectsUnknownMatchExt covers the direction that matters. An
// unimplemented narrowing bit cannot be dropped on the floor: the datapath
// would ignore it and the rule would match MORE than the caller asked for, so
// the encoder refuses instead.
func TestEncodeRejectsUnknownMatchExt(t *testing.T) {
	_, err := RuleSpec{Action: ActionDrop, MatchExt: 1 << 7}.Encode()
	if err == nil {
		t.Fatal("Encode accepted an unimplemented match_ext bit; the rule would have widened silently")
	}
	if !strings.Contains(err.Error(), "match more than intended") {
		t.Errorf("error %q does not say what goes wrong", err)
	}
}

func prefixStringSet(p []netip.Prefix) map[string]bool {
	out := map[string]bool{}
	for _, x := range p {
		out[x.String()] = true
	}
	return out
}

// TestOptionsFromConfigRefusesDisabled proves a caller cannot accidentally get a
// zero Options for a disabled block and attach it to nothing.
func TestOptionsFromConfigRefusesDisabled(t *testing.T) {
	for name, extra := range map[string]string{
		"absent":   "",
		"disabled": "\ndataplane:\n  enabled: false\n  interfaces: [\"eth0\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OptionsFromConfig(mustParse(t, extra)); err == nil {
				t.Fatalf("OptionsFromConfig accepted a %s dataplane block", name)
			}
		})
	}
}

// TestDefaultsMatchConfigDefaults: an operator who names no limits, no mode and
// no pin path must get the same thing through OptionsFromConfig as through
// Options.normalize. If those two disagreed, a Manager built from a Config and
// one built by a test would size their maps differently.
func TestDefaultsMatchConfigDefaults(t *testing.T) {
	cfg := mustParse(t, "\ndataplane:\n  interfaces: [\"eth0\"]\n")
	opts, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.normalize(); err != nil {
		t.Fatal(err)
	}
	if opts.Limits != DefaultLimits() {
		t.Errorf("Limits = %+v, DefaultLimits = %+v", opts.Limits, DefaultLimits())
	}
	if opts.XDPMode != config.XDPModeAuto {
		t.Errorf("XDPMode = %q, want auto", opts.XDPMode)
	}
	if opts.OnExit != config.OnExitKeep {
		t.Errorf("OnExit = %q, want keep", opts.OnExit)
	}
	if opts.PinPath != "/sys/fs/bpf/kapkan" {
		t.Errorf("PinPath = %q", opts.PinPath)
	}
}

// TestRestartRequiredMatchesConfigsRule is the belt-and-braces check on the
// reconciliation case the task calls out: a reload that would shrink the limits.
//
// It asserts BOTH halves, because they are separate mechanisms that must agree:
// config.Store.Reload refuses the file, and Options.restartRequired refuses the
// Manager call even if something bypassed the store.
func TestRestartRequiredMatchesConfigsRule(t *testing.T) {
	const dpBase = `
dataplane:
  interfaces: ["eth0"]
  limits:
    max_ratelimit_sources: 1048576
`
	cases := []struct {
		name          string
		extra         string
		wantRestart   bool
		wantSubstring string
	}{
		{
			name:  "a static rule added — hot reload",
			extra: "  static_rules:\n    - {name: r, match: {proto: udp}, action: drop}\n",
		},
		{
			name:  "an allowlist entry added — hot reload",
			extra: "  allowlist: [\"198.51.100.0/24\"]\n",
		},
		{
			name:          "max_ratelimit_sources shrunk — restart",
			extra:         "", // replaced below
			wantRestart:   true,
			wantSubstring: "limits",
		},
		{
			name:          "an interface added — restart",
			wantRestart:   true,
			wantSubstring: "interfaces",
		},
		{
			name:          "xdp_mode changed — restart",
			wantRestart:   true,
			wantSubstring: "xdp_mode",
		},
	}

	prevCfg := mustParse(t, dpBase)
	prev, err := OptionsFromConfig(prevCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := prev.normalize(); err != nil {
		t.Fatal(err)
	}

	nextYAML := map[string]string{
		"a static rule added — hot reload":       dpBase + "  static_rules:\n    - {name: r, match: {proto: udp}, action: drop}\n",
		"an allowlist entry added — hot reload":  dpBase + "  allowlist: [\"198.51.100.0/24\"]\n",
		"max_ratelimit_sources shrunk — restart": "\ndataplane:\n  interfaces: [\"eth0\"]\n  limits:\n    max_ratelimit_sources: 65536\n",
		"an interface added — restart":           "\ndataplane:\n  interfaces: [\"eth0\", \"eth1\"]\n  limits:\n    max_ratelimit_sources: 1048576\n",
		"xdp_mode changed — restart":             "\ndataplane:\n  interfaces: [\"eth0\"]\n  xdp_mode: generic\n  limits:\n    max_ratelimit_sources: 1048576\n",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextCfg := mustParse(t, nextYAML[tc.name])
			next, err := OptionsFromConfig(nextCfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := next.normalize(); err != nil {
				t.Fatal(err)
			}

			// Half 1: the manager's own check.
			diff := prev.restartRequired(next)
			if tc.wantRestart {
				if diff == "" {
					t.Fatalf("restartRequired said a reload is fine")
				}
				if !strings.Contains(diff, tc.wantSubstring) {
					t.Errorf("restartRequired = %q, want it to name %q", diff, tc.wantSubstring)
				}
				t.Logf("manager refuses: %s", diff)
			} else if diff != "" {
				t.Fatalf("restartRequired demanded a restart for a hot-reloadable change: %s", diff)
			}

			// Half 2: config's own DataplaneSettings comparison, which is what
			// Store.Reload uses. Same verdict, independently derived.
			settingsDiffer := nextCfg.DataplaneCfg != prevCfg.DataplaneCfg
			if settingsDiffer != tc.wantRestart {
				t.Errorf("config.DataplaneSettings differ = %v, manager wants restart = %v; "+
					"the two restart-required rules have drifted apart", settingsDiffer, tc.wantRestart)
			}
		})
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := map[string]Options{
		"no interfaces":     {PinPath: "/sys/fs/bpf/k"},
		"duplicate":         {Interfaces: []string{"eth0", "eth0"}, PinPath: "/sys/fs/bpf/k"},
		"empty name":        {Interfaces: []string{""}, PinPath: "/sys/fs/bpf/k"},
		"bad mode":          {Interfaces: []string{"eth0"}, XDPMode: "hardware", PinPath: "/sys/fs/bpf/k"},
		"bad on_exit":       {Interfaces: []string{"eth0"}, OnExit: "burn", PinPath: "/sys/fs/bpf/k"},
		"relative pin path": {Interfaces: []string{"eth0"}, PinPath: "bpf/k"},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			if err := o.normalize(); err == nil {
				t.Fatalf("normalize accepted %+v", o)
			}
		})
	}
}

func TestHealthSummary(t *testing.T) {
	if got := (Health{}).Summary(); got != "dataplane: disabled" {
		t.Errorf("disabled summary = %q", got)
	}
	h := Health{
		Enabled:  true,
		Degraded: true,
		Interfaces: []InterfaceStatus{
			{Name: "eth0", Attached: true, Mode: "native"},
			{Name: "eth1", Attached: false},
		},
		Conditions: []Condition{
			{Kind: CondUnattached, Interface: "eth1", Message: "no XDP attachment"},
		},
	}
	got := h.Summary()
	for _, want := range []string{"DEGRADED", "1/2 interfaces attached", "unattached[eth1]"} {
		if !strings.Contains(got, want) {
			t.Errorf("Summary() = %q, missing %q", got, want)
		}
	}
}

func TestErrorSentinelsAreDistinct(t *testing.T) {
	all := []error{ErrUnsupported, ErrKernelTooOld, ErrMissingCapability,
		ErrPinPathUnsafe, ErrRestartRequired, ErrClosed}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %v and %v are not distinguishable", a, b)
			}
		}
	}
}
