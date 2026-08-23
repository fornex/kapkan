package dataplane

// Tests for the config-to-Options translation and the restart-required rules.
// No kernel involved, so these run on every host — which is the point: this is
// the layer that turns an operator's YAML into the numbers the kernel is given,
// and getting it wrong means a rule that never fires.

import (
	"errors"
	"fmt"
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
    - name: cap-quic
      match: {proto: udp, dst_port: 443, payload: quic_initial}
      action: ratelimit
      profile: hs
`)
	opts, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	if len(opts.Policy.Statics) != 3 {
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
	// Each payload value maps to ITS bit: quic_initial must not compile to
	// the TLS bit or carry both.
	if quic := opts.Policy.Statics[2]; quic.MatchExt != MatchQUICInitial {
		t.Errorf("cap-quic MatchExt = %#02x, want %#02x", quic.MatchExt, MatchQUICInitial)
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
func TestOptionsFromConfigFingerprint(t *testing.T) {
	cfg := mustParse(t, `
dataplane:
  interfaces: ["eth0"]
  fingerprint:
    enabled: true
    sample_pps: 750
    block_ttl_seconds: 120
    ja4_blocklist: ["t13d1516h2_8daaf6152771_e5627efa2ab1"]
`)
	opts, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	if !opts.FPEnabled {
		t.Error("FPEnabled = false, the config enabled the plane")
	}
	if opts.FPSamplePPS != 750 {
		t.Errorf("FPSamplePPS = %d, want 750", opts.FPSamplePPS)
	}
	// FPBurst rides at 0 through Options; PutConfig defaults it from the rate, so
	// the burst is a kernel-write concern, not a config-mapping one.
	if opts.FPBurst != 0 {
		t.Errorf("FPBurst = %d, want 0", opts.FPBurst)
	}
}

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
		{
			name:          "fingerprint enabled — restart",
			wantRestart:   true,
			wantSubstring: "fingerprint",
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
		"fingerprint enabled — restart":          "\ndataplane:\n  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n  limits:\n    max_ratelimit_sources: 1048576\n",
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

/* ------------------------------------------- unreachable static rules */

// TestShadowedByEarlierRule is the first-match-wins half of the reachability
// analysis: a static rule below one whose match set contains it can never be
// reached, and nothing else in the system will ever say so — the rule's counter
// in `kapkan dataplane status` stays at zero, which is exactly what a correct
// rule looks like on a quiet day.
//
// The NOT-shadowed cases carry as much weight as the shadowed ones. A partial
// overlap between two rules is ordinary, correct policy and appears in configs
// everywhere; an analysis that flagged it would be worse than no analysis.
func TestShadowedByEarlierRule(t *testing.T) {
	pfx := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }

	cases := []struct {
		name string
		// rules is the static list in config order.
		rules []StaticRule
		// dead is the rule that must be reported, or "" for "report nothing".
		dead string
		// by names the earlier rule(s) the report must blame.
		by []string
	}{
		{
			name: "an identical earlier rule",
			rules: []StaticRule{
				{Name: "cap-https", Action: ActionRateLimit, Profile: "https", Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
				{Name: "cap-https-again", Action: ActionRateLimit, Profile: "tighter", Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
			},
			dead: "cap-https-again",
			by:   []string{"cap-https"},
		},
		{
			// The shape that motivated this: a broad cap on a port, then the
			// narrower rule the operator actually cared about, written below it.
			name: "a strictly broader earlier rule",
			rules: []StaticRule{
				{Name: "cap-https", Action: ActionRateLimit, Profile: "https", Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
				{Name: "cap-partner-https", Action: ActionRateLimit, Profile: "partner",
					Src: pfx("198.51.100.0/24"), Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
			},
			dead: "cap-partner-https",
			by:   []string{"cap-https"},
		},
		{
			// The same two rules the right way round, which is the whole point
			// of first match wins and must stay silent.
			name: "a narrower earlier rule shadows nothing",
			rules: []StaticRule{
				{Name: "cap-partner-https", Action: ActionRateLimit, Profile: "partner",
					Src: pfx("198.51.100.0/24"), Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
				{Name: "cap-https", Action: ActionRateLimit, Profile: "https", Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
			},
		},
		{
			// The arrangement the documentation recommends, and the one the
			// shipped example config uses. Every scalar field agrees, so
			// without the match_ext term the analysis "proves" the second rule
			// dead — a warning on the correct config, pointing at the rule that
			// handles nearly all the traffic on that port.
			name: "a payload predicate makes the earlier rule narrower, not broader",
			rules: []StaticRule{
				{Name: "cap-handshakes", Action: ActionRateLimit, Profile: "hs",
					Proto: ptr(protoTCP), DstPort: ptr(uint16(443)), MatchExt: MatchTLSClientHello},
				{Name: "cap-https", Action: ActionRateLimit, Profile: "https",
					Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
			},
		},
		{
			// The same pair the wrong way round: this IS the defect, and it is
			// the one that motivated the whole check.
			name: "a rule with no payload predicate shadows one that has it",
			rules: []StaticRule{
				{Name: "cap-https", Action: ActionRateLimit, Profile: "https",
					Proto: ptr(protoTCP), DstPort: ptr(uint16(443))},
				{Name: "cap-handshakes", Action: ActionRateLimit, Profile: "hs",
					Proto: ptr(protoTCP), DstPort: ptr(uint16(443)), MatchExt: MatchTLSClientHello},
			},
			dead: "cap-handshakes",
			by:   []string{"cap-https"},
		},
		{
			name: "identical payload predicates shadow as any other equal field would",
			rules: []StaticRule{
				{Name: "drop-handshakes", Action: ActionDrop,
					Proto: ptr(protoTCP), MatchExt: MatchTLSClientHello},
				{Name: "cap-handshakes", Action: ActionRateLimit, Profile: "hs",
					Proto: ptr(protoTCP), DstPort: ptr(uint16(443)), MatchExt: MatchTLSClientHello},
			},
			dead: "cap-handshakes",
			by:   []string{"drop-handshakes"},
		},
		{
			name: "containment, not equality, decides the source prefix",
			rules: []StaticRule{
				{Name: "drop-net", Action: ActionDrop, Src: pfx("10.0.0.0/8")},
				{Name: "drop-host", Action: ActionDrop, Src: pfx("10.1.2.3/32")},
			},
			dead: "drop-host",
			by:   []string{"drop-net"},
		},
		{
			// The datapath tests a rule's family bit unconditionally, so a v4
			// rule cannot take a v6 rule's packets however broad it is.
			name: "the two address families never shadow each other",
			rules: []StaticRule{
				{Name: "drop-v4", Action: ActionDrop, Src: pfx("0.0.0.0/0")},
				{Name: "drop-v6", Action: ActionDrop, Src: pfx("2001:db8::/32")},
			},
		},
		{
			name: "icmp and icmp6 pin different families",
			rules: []StaticRule{
				{Name: "cap-icmp", Action: ActionRateLimit, Profile: "icmp", Proto: ptr(protoICMP)},
				{Name: "cap-icmp6", Action: ActionRateLimit, Profile: "icmp", Proto: ptr(protoICMPv6)},
			},
		},
		{
			// A rule with no match.src compiles to one kernel rule per family,
			// so it is only dead when BOTH families are taken — here by two
			// different earlier rules.
			name: "both families taken, one earlier rule each",
			rules: []StaticRule{
				{Name: "drop-all-v4", Action: ActionDrop, Src: pfx("0.0.0.0/0")},
				{Name: "drop-all-v6", Action: ActionDrop, Src: pfx("::/0")},
				{Name: "cap-udp", Action: ActionRateLimit, Profile: "udp", Proto: ptr(protoUDP)},
			},
			dead: "cap-udp",
			by:   []string{"drop-all-v4", "drop-all-v6"},
		},
		{
			// Only one family is covered, so the rule still fires on the other.
			name: "one family covered is not dead",
			rules: []StaticRule{
				{Name: "drop-all-v4", Action: ActionDrop, Src: pfx("0.0.0.0/0")},
				{Name: "cap-udp", Action: ActionRateLimit, Profile: "udp", Proto: ptr(protoUDP)},
			},
		},
		{
			// The dangerous one, and the reason this axis reports pass rules
			// while the allowlist axis does not: the operator believes they have
			// exempted their resolver, and its traffic is being dropped.
			name: "an exemption written below the drop it is meant to escape",
			rules: []StaticRule{
				{Name: "drop-udp", Action: ActionDrop, Proto: ptr(protoUDP)},
				{Name: "allow-resolver", Action: ActionPass,
					Src: pfx("192.0.2.53/32"), Proto: ptr(protoUDP), DstPort: ptr(uint16(53))},
			},
			dead: "allow-resolver",
			by:   []string{"drop-udp"},
		},
		{
			// A partial overlap: the earlier rule constrains a field the later
			// one leaves open, so traffic exists that only the later one takes.
			name: "a partial overlap is ordinary policy",
			rules: []StaticRule{
				{Name: "drop-chargen", Action: ActionDrop, Proto: ptr(protoUDP), SrcPort: ptr(uint16(19))},
				{Name: "cap-udp", Action: ActionRateLimit, Profile: "udp", Proto: ptr(protoUDP)},
			},
		},
		{
			// The example configuration shipped in deploy/config.example.yaml
			// and quoted in the docs. It must stay silent, or every operator who
			// copied it gets a warning on upgrade.
			// Keep this in step with deploy/config.example.yaml. Shipping a
			// commented-out block that the analysis would warn about teaches
			// the wrong thing on first read, and the example is the one policy
			// every operator starts from.
			name: "the shipped example config",
			rules: []StaticRule{
				{Name: "drop_chargen", Action: ActionDrop, Proto: ptr(protoUDP), SrcPort: ptr(uint16(19))},
				{Name: "cap_icmp", Action: ActionRateLimit, Profile: "icmp_cap", Proto: ptr(protoICMP)},
				{Name: "cap_tls_handshakes", Action: ActionRateLimit, Profile: "handshake_cap",
					Proto: ptr(protoTCP), DstPort: ptr(uint16(443)), MatchExt: MatchTLSClientHello},
				{Name: "cap_quic_handshakes", Action: ActionRateLimit, Profile: "quic_handshake_cap",
					Proto: ptr(protoUDP), DstPort: ptr(uint16(443)), MatchExt: MatchQUICInitial},
			},
		},
		{
			// The QUIC twin of the motivating case, and the migration trap the
			// docs now warn about: the previous release's documented QUIC
			// advice WAS the broad udp/443 ceiling, so an operator who adds
			// the new handshake rule below it has built exactly this.
			name: "a broad udp rule shadows a quic_initial rule below it",
			rules: []StaticRule{
				{Name: "cap-udp-443", Action: ActionRateLimit, Profile: "udp443",
					Proto: ptr(protoUDP), DstPort: ptr(uint16(443))},
				{Name: "cap-quic-handshakes", Action: ActionRateLimit, Profile: "qhs",
					Proto: ptr(protoUDP), DstPort: ptr(uint16(443)), MatchExt: MatchQUICInitial},
			},
			dead: "cap-quic-handshakes",
			by:   []string{"cap-udp-443"},
		},
		{
			// Cross-bit: the two payload predicates are DIFFERENT narrowings,
			// so neither covers the other — pinned here so coversMatchExt can
			// never regress into treating match_ext as a boolean.
			name: "a tls payload rule does not shadow a quic payload rule",
			rules: []StaticRule{
				{Name: "cap-tls-handshakes", Action: ActionRateLimit, Profile: "hs",
					DstPort: ptr(uint16(443)), MatchExt: MatchTLSClientHello},
				{Name: "cap-quic-handshakes", Action: ActionRateLimit, Profile: "qhs",
					DstPort: ptr(uint16(443)), MatchExt: MatchQUICInitial},
			},
		},
		{
			name: "an unset field is any, so a bare rule takes everything below it",
			rules: []StaticRule{
				{Name: "cap-everything", Action: ActionRateLimit, Profile: "global"},
				{Name: "drop-chargen", Action: ActionDrop, Proto: ptr(protoUDP), SrcPort: ptr(uint16(19))},
			},
			dead: "drop-chargen",
			by:   []string{"cap-everything"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShadowedStatics(StaticPolicy{Statics: tc.rules})
			if tc.dead == "" {
				if len(got) != 0 {
					t.Fatalf("reported %v, but every rule here can still fire", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("reported %v, want exactly one entry naming %q", got, tc.dead)
			}
			if !strings.HasPrefix(got[0], tc.dead+" ") {
				t.Errorf("reported %q, want it to name the dead rule %q first", got[0], tc.dead)
			}
			for _, by := range tc.by {
				if !strings.Contains(got[0], fmt.Sprintf("%q", by)) {
					t.Errorf("reported %q, want it to blame %q", got[0], by)
				}
			}
		})
	}
}

// TestShadowedByAllowlist is the other axis, kept honest here rather than only
// in the kernel test that covers it end to end: the allowlist is precedence 1
// and stops evaluation, so it can kill a static rule outright — but a PASS rule
// it covers is harmless, because both verdicts admit the packet.
func TestShadowedByAllowlist(t *testing.T) {
	pol := StaticPolicy{
		Allow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Statics: []StaticRule{
			{Name: "drop-that-host", Action: ActionDrop, Src: netip.MustParsePrefix("198.51.100.7/32")},
			{Name: "allow-that-host", Action: ActionPass, Src: netip.MustParsePrefix("198.51.100.8/32")},
			{Name: "drop-elsewhere", Action: ActionDrop, Src: netip.MustParsePrefix("203.0.113.0/24")},
		},
	}
	got := ShadowedStatics(pol)
	if len(got) != 1 || !strings.HasPrefix(got[0], "drop-that-host ") {
		t.Fatalf("reported %v, want only drop-that-host", got)
	}
	if !strings.Contains(got[0], "198.51.100.0/24") {
		t.Errorf("reported %q, want it to name the allowlist entry that covers the rule", got[0])
	}
}

// TestShadowedStaticsFromYAML runs the analysis on the real chain — YAML through
// config.Parse and PolicyFromConfig — so a mistake in how a match is parsed
// cannot hide behind hand-built rules.
func TestShadowedStaticsFromYAML(t *testing.T) {
	cfg := mustParse(t, `
dataplane:
  interfaces: ["eth0"]
  ratelimit_profiles:
    - {name: https_cap, pps: 20000}
    - {name: partner_cap, pps: 2000}
  static_rules:
    - name: cap_https_per_source
      match: {proto: tcp, dst_port: 443}
      action: ratelimit
      profile: https_cap
    - name: cap_partner_https
      match: {src: "198.51.100.0/24", proto: tcp, dst_port: 443}
      action: ratelimit
      profile: partner_cap
`)
	pol, err := PolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("PolicyFromConfig: %v", err)
	}
	got := ShadowedStatics(pol)
	if len(got) != 1 {
		t.Fatalf("reported %v, want the second rule reported as unreachable", got)
	}
	if !strings.Contains(got[0], "cap_partner_https") || !strings.Contains(got[0], `"cap_https_per_source"`) {
		t.Errorf("reported %q, want it to name both the dead rule and the one covering it", got[0])
	}
	t.Logf("%s", got[0])
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
