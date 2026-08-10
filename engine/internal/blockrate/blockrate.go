// Package blockrate is the CATALOG behind kapkan's pcap block-rate suite: the
// eighteen attack fixtures every public performance claim has to survive, and
// the committed capture files that make them reproducible.
//
// ==========================================================================
// WHY A CATALOG PACKAGE AND NOT A TEST FILE
// ==========================================================================
// The suite that consumes this runs against a real kernel and therefore lives
// behind //go:build linux, in internal/mitigate (the only package that can see
// the whole chain: the detector, the FlowSpec IR, the kernel encoder and the
// installer, with no import cycle). But the fixtures themselves — the
// telemetry that drives detection and the frames that get replayed — must be
// GENERATED AND DIFFED on a macOS development host where bpf(2) does not
// exist, or the committed pcaps could only ever be regenerated inside a
// privileged container. So the data lives here, untagged, and the kernel half
// imports it.
//
// ==========================================================================
// WHAT A FIXTURE IS, AND WHAT IT DELIBERATELY IS NOT
// ==========================================================================
// A fixture is NOT "some frames and a rule". Hand-written rules would test the
// BPF program and nothing else, and the number that comes out of that is not a
// product claim. Every fixture carries TELEMETRY, and the suite drives it
// through the whole chain:
//
//	flowgen-shaped telemetry
//	  -> engine.Engine          (the real detector: windows, thresholds)
//	  -> engine.classify        (the real classifier: the vector)
//	  -> mitigate.generateRules (the real FlowSpec IR)
//	  -> mitigate.dataplaneRules(the real IR -> RuleSpec encoder)
//	  -> dataplane.Installer    (real ids, real profiles, real kernel maps)
//	  -> pktgen frames -> BPF_PROG_TEST_RUN -> verdicts
//
// A regression anywhere on that line — a threshold that stops tripping, a
// classifier that names the wrong vector, an encoder that drops a port, an
// installer that mis-allocates a profile — fails the suite. That is the whole
// point of the shape.
//
// Every fixture also carries its own LEGITIMATE baseline. A block rate with no
// false-positive denominator is not a measurement; "we dropped 100% of the
// attack" is trivially achievable by dropping everything, and the two numbers
// are only meaningful together.
package blockrate

import (
	"fmt"
	"net/netip"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/pkg/flowgen"
	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

// Role labels what a frame in a fixture's capture is FOR. The capture is one
// interleaved stream, exactly as a tap would see it; the roles are what make
// the three rates (block, false-positive, allowlist) separable.
type Role uint8

// Frame roles.
const (
	// RoleAttack is a frame of the attack vector. The block rate is the share
	// of these the kernel drops.
	RoleAttack Role = iota
	// RoleLegit is a frame of the victim's (or its neighbours') ordinary
	// traffic. The false-positive rate is the share of these the kernel drops,
	// and it must be ~zero.
	RoleLegit
	// RoleAllow is a frame that is byte-for-byte an attack frame except that
	// its SOURCE is on dataplane.allowlist. Precedence 1 must pass it, whatever
	// rule the detector installed. Not one of these may ever be dropped.
	RoleAllow
)

// String renders the role for test output.
func (r Role) String() string {
	switch r {
	case RoleAttack:
		return "attack"
	case RoleLegit:
		return "legit"
	case RoleAllow:
		return "allowlisted"
	default:
		return "unknown"
	}
}

// Scope distinguishes a per-host fixture from the carpet-bombing one, which is
// detected and mitigated on an aggregation PREFIX rather than a host.
type Scope uint8

// Fixture scopes.
const (
	ScopeHost Scope = iota
	ScopePrefix
)

// Fixture is one attack vector's end-to-end case.
type Fixture struct {
	// Name is the fixture id and the basename of its capture file.
	Name string
	// Doc says what this fixture proves that no other fixture proves. It is
	// printed in the suite's output so the table a human reads explains itself.
	Doc string

	// Scope selects the host or the carpet (prefix) path.
	Scope Scope
	// Victim is the attacked host (ScopeHost).
	Victim netip.Addr
	// Prefix is the attacked aggregation prefix (ScopePrefix).
	Prefix netip.Prefix

	// Group names the config hostgroup whose policy must apply. Empty means the
	// implicit global group. The suite asserts the ban was created under it, so
	// a fixture that needs rate_limit cannot silently be mitigated by a discard.
	Group string

	// WantClass is the classification the REAL classifier must produce. It is
	// asserted, not assumed: a fixture whose telemetry stops reading as its
	// vector is a broken fixture and must fail loudly rather than quietly
	// measure a different attack.
	WantClass engine.AttackType
	// WantSourceAnchored records that this fixture's rules must come out
	// composite (victim + attacker source) rather than victim-anchored.
	WantSourceAnchored bool
	// WantRuleCount, when non-zero, is the exact number of FlowSpec rules the
	// generator must produce.
	WantRuleCount int

	// MinBlockRate is the floor this fixture's block rate must clear.
	// Single-vector floods are held to 0.98; composite and rate-limited shapes,
	// where a bounded number of frames is admitted BY DESIGN, to 0.95.
	MinBlockRate float64
	// MaxFalsePositiveRate is the ceiling on dropped legitimate frames. It is
	// 0.001 everywhere, and since no fixture carries a thousand legitimate
	// frames that is a long-hand spelling of "not one".
	MaxFalsePositiveRate float64

	// Telemetry is ONE ROUND of the synthetic flow records that drive
	// detection. The suite replays it until the engine reports an attack.
	Telemetry []flow.Flow

	// Frames is the capture, interleaved; Roles is index-aligned with it.
	Frames []pktgen.Frame
	Roles  []Role
}

// PcapName is the fixture's committed capture file, relative to testdata/.
func (f Fixture) PcapName() string { return f.Name + ".pcap" }

// Target renders the fixture's victim (host or prefix) for output.
func (f Fixture) Target() string {
	if f.Scope == ScopePrefix {
		return f.Prefix.String()
	}
	return f.Victim.String()
}

// Count returns how many frames carry the given role.
func (f Fixture) Count(r Role) int {
	var n int
	for _, got := range f.Roles {
		if got == r {
			n++
		}
	}
	return n
}

// Validate checks the invariants a fixture must hold for its numbers to mean
// anything. It runs on every host as part of the catalog's own unit test, so a
// malformed fixture is caught before it ever reaches a kernel.
func (f Fixture) Validate() error {
	if len(f.Frames) != len(f.Roles) {
		return fmt.Errorf("%s: %d frames but %d roles", f.Name, len(f.Frames), len(f.Roles))
	}
	if f.Count(RoleAttack) == 0 {
		return fmt.Errorf("%s: no attack frames", f.Name)
	}
	// A block rate with no legitimate denominator is not a measurement.
	if f.Count(RoleLegit) == 0 {
		return fmt.Errorf("%s: no legitimate baseline; the block rate would be meaningless", f.Name)
	}
	if f.Count(RoleAllow) == 0 {
		return fmt.Errorf("%s: no allowlisted frames; allowlist inviolability would be untested", f.Name)
	}
	if len(f.Telemetry) == 0 {
		return fmt.Errorf("%s: no telemetry; the fixture would test the BPF program, not the product", f.Name)
	}
	if f.WantClass == "" {
		return fmt.Errorf("%s: no expected classification", f.Name)
	}
	if f.MinBlockRate < 0.95 {
		return fmt.Errorf("%s: min block rate %.3f is below the suite's floor of 0.95", f.Name, f.MinBlockRate)
	}
	if f.MaxFalsePositiveRate > 0.001 {
		return fmt.Errorf("%s: max false-positive rate %.4f exceeds the suite's ceiling of 0.001",
			f.Name, f.MaxFalsePositiveRate)
	}
	switch f.Scope {
	case ScopeHost:
		if !f.Victim.IsValid() {
			return fmt.Errorf("%s: host-scoped fixture with no victim", f.Name)
		}
	case ScopePrefix:
		if !f.Prefix.IsValid() {
			return fmt.Errorf("%s: prefix-scoped fixture with no prefix", f.Name)
		}
	}
	for i, fr := range f.Frames {
		if _, err := fr.Build(); err != nil {
			return fmt.Errorf("%s: frame %d does not build: %w", f.Name, i, err)
		}
	}
	return nil
}

/* ========================================================================= */
/* The address plan                                                           */
/* ========================================================================= */

// The whole suite runs inside documentation address space (RFC 5737 / RFC
// 3849 / RFC 2544), so a capture that escapes into a bug report or a doc page
// names nothing real.
//
//	203.0.113.0/24     protected v4 space (the victims and their neighbours)
//	2001:db8:cafe::/48 protected v6 space
//	198.18.0.0/24      protected v4 space used ONLY by the carpet fixture, so
//	                   the /24 aggregate of the other fixtures never trips
//	                   carpet detection and cross-contaminates them
//	198.51.100.0/24    attacker / reflector sources (v4)
//	2001:db8:beef::/48 attacker / reflector sources (v6)
//	192.0.2.0/24       legitimate client sources
var (
	// NetV4, NetV6 and CarpetNet are the protected networks.
	NetV4      = netip.MustParsePrefix("203.0.113.0/24")
	NetV6      = netip.MustParsePrefix("2001:db8:cafe::/48")
	CarpetNet  = netip.MustParsePrefix("198.18.0.0/24")
	attackerV4 = netip.MustParseAddr("198.51.100.0")
	attackerV6 = netip.MustParseAddr("2001:db8:beef::")
	clientV4   = netip.MustParseAddr("192.0.2.0")
	clientV6   = netip.MustParseAddr("2001:db8:c11e::")

	// AllowV4 and AllowV6 are the dataplane.allowlist SOURCES. A frame from
	// one of these is an attack frame in every respect except that the kernel
	// must pass it at precedence 1.
	AllowV4 = netip.MustParseAddr("198.51.100.250")
	AllowV6 = netip.MustParseAddr("2001:db8:beef::fa")

	// WhitelistV4 and WhitelistV6 are protected_whitelist entries: hosts the
	// mitigator may never ban. They carry no fixture traffic; they exist so the
	// suite runs against a config that has the destination guard populated.
	WhitelistV4 = netip.MustParseAddr("203.0.113.1")
	WhitelistV6 = netip.MustParseAddr("2001:db8:cafe::1")

	// neighbourV4/V6 are protected hosts that are never victims. They carry the
	// legitimate baseline for the fixtures whose rule is anchor-only (a mixed
	// vector, a carpet bomb), where by policy nothing to the victim survives
	// and a same-host baseline would be measuring the policy rather than the
	// data plane.
	neighbourV4 = netip.MustParseAddr("203.0.113.200")
	neighbourV6 = netip.MustParseAddr("2001:db8:cafe::200")
)

/* ========================================================================= */
/* Telemetry helpers                                                          */
/* ========================================================================= */

// telemetryFrom converts flowgen records into the normalized flow.Flow the
// detector consumes. Going through flowgen rather than hand-building flows is
// the point: the shapes the suite detects are the same ones the engine's own
// tests and the documentation screenshots are built from, so a fixture cannot
// drift into an attack the product has never otherwise seen.
func telemetryFrom(recs []flowgen.Record) []flow.Flow {
	out := make([]flow.Flow, len(recs))
	for i, r := range recs {
		out[i] = flow.Flow{
			SrcAddr:      r.SrcAddr,
			DstAddr:      r.DstAddr,
			SrcPort:      r.SrcPort,
			DstPort:      r.DstPort,
			IPProto:      r.Proto,
			TCPFlags:     r.TCPFlags,
			Fragment:     r.Fragment,
			Bytes:        uint64(r.Bytes),
			Packets:      uint64(r.Packets),
			SamplingRate: 1,
			Wire:         flow.ProtoNetFlow9,
		}
	}
	return out
}

// pattern builds one round of telemetry for a flowgen pattern against a
// victim. records is kept small deliberately: the suite feeds every fixture
// into ONE engine at the same time, and the engine's per-shard sample ring is
// finite, so a fixture that floods the ring would starve another fixture's
// attack sample and break its classification.
func pattern(p flowgen.AttackPattern, victim netip.Addr, records int, srcBase netip.Addr, bytesPer, pktsPer uint32) []flow.Flow {
	return telemetryFrom(flowgen.PatternParams{
		Pattern:          p,
		Victim:           victim,
		Records:          records,
		SrcBase:          srcBase,
		BytesPerRecord:   bytesPer,
		PacketsPerRecord: pktsPer,
	}.Build())
}

/* ========================================================================= */
/* Frame helpers                                                              */
/* ========================================================================= */

// attackerMAC / victimMAC are the lab L2 addresses. The datapath never looks
// at them; they are fixed so the captures are byte-stable.
var (
	attackerMAC = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	victimMAC   = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
)

// nextAddr returns base offset by n inside its family, mirroring the helper
// both generators use so a fixture's telemetry sources and its frame sources
// walk the same space.
func nextAddr(base netip.Addr, n int) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(n)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := base.As16()
	lo := uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	lo += uint32(n)
	b[12], b[13], b[14], b[15] = byte(lo>>24), byte(lo>>16), byte(lo>>8), byte(lo)
	return netip.AddrFrom16(b)
}

// stamp applies the fixed lab MACs to a generated frame set.
func stamp(frames []pktgen.Frame) []pktgen.Frame {
	for i := range frames {
		frames[i].SrcMAC, frames[i].DstMAC = attackerMAC, victimMAC
	}
	return frames
}

// attackFrames generates n frames of a pktgen pattern aimed at victim from the
// given sources.
func attackFrames(p pktgen.Pattern, victim netip.Addr, n int, sources []netip.Addr, size int) []pktgen.Frame {
	return stamp(pktgen.Generate(p, pktgen.GenConfig{
		Victim: victim, Sources: sources, Count: n, Size: size,
		VictimMAC: victimMAC, RouterMAC: attackerMAC,
	}))
}

// sourceRange returns n consecutive addresses starting at base.
func sourceRange(base netip.Addr, n int) []netip.Addr {
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = nextAddr(base, i)
	}
	return out
}

// rewriteSource copies frames with a new source address — how the allowlisted
// set is built, so it is provably the attack traffic and not a lookalike.
func rewriteSource(frames []pktgen.Frame, src netip.Addr) []pktgen.Frame {
	out := make([]pktgen.Frame, len(frames))
	copy(out, frames)
	for i := range out {
		out[i].SrcIP = src
	}
	return out
}

// tcpFrames builds n TCP frames from a rotating client range to dst. It is the
// workhorse of the legitimate baselines: for every fixture whose rule narrows
// on UDP, ICMP, fragments or a reflected port, ordinary TCP to the same victim
// is exactly the traffic a surgical mitigation has to spare.
func tcpFrames(n int, clientBase, dst netip.Addr, dstPort uint16, flags uint8, size int) []pktgen.Frame {
	out := make([]pktgen.Frame, n)
	for i := range out {
		out[i] = pktgen.Frame{
			SrcMAC: attackerMAC, DstMAC: victimMAC,
			SrcIP: nextAddr(clientBase, i%64), DstIP: dst,
			Proto: pktgen.ProtoTCP, TCPFlags: flags,
			SrcPort: uint16(20000 + i%1000), DstPort: dstPort, TTL: 61,
			Payload: payload(size, ethIPTCPOverhead(dst.Is6())),
		}
	}
	return out
}

// udpFrames builds n UDP frames from a rotating client range to dst.
func udpFrames(n int, clientBase, dst netip.Addr, srcPort, dstPort uint16, size int) []pktgen.Frame {
	out := make([]pktgen.Frame, n)
	for i := range out {
		sp := srcPort
		if sp == 0 {
			sp = uint16(30000 + i%1000)
		}
		out[i] = pktgen.Frame{
			SrcMAC: attackerMAC, DstMAC: victimMAC,
			SrcIP: nextAddr(clientBase, i%64), DstIP: dst,
			Proto: pktgen.ProtoUDP, SrcPort: sp, DstPort: dstPort, TTL: 61,
			Payload: payload(size, ethIPUDPOverhead(dst.Is6())),
		}
	}
	return out
}

// icmpFrames builds n ICMP (or ICMPv6) echo replies to dst.
func icmpFrames(n int, clientBase, dst netip.Addr, size int) []pktgen.Frame {
	out := make([]pktgen.Frame, n)
	for i := range out {
		f := pktgen.Frame{
			SrcMAC: attackerMAC, DstMAC: victimMAC,
			SrcIP: nextAddr(clientBase, i%64), DstIP: dst,
			Proto: pktgen.ProtoICMP, ICMPType: 0, TTL: 61, // echo reply
			Payload: payload(size, 14+20+4),
		}
		if dst.Is6() {
			f.Proto, f.ICMPType = pktgen.ProtoICMPv6, 129 // echo reply
			f.Payload = payload(size, 14+40+4)
		}
		out[i] = f
	}
	return out
}

func ethIPTCPOverhead(v6 bool) int {
	if v6 {
		return 14 + 40 + 20
	}
	return 14 + 20 + 20
}

func ethIPUDPOverhead(v6 bool) int {
	if v6 {
		return 14 + 40 + 8
	}
	return 14 + 20 + 8
}

// payload sizes an L4 payload so the whole frame lands on target bytes.
func payload(target, overhead int) []byte {
	n := target - overhead
	if n <= 0 {
		return nil
	}
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

/* ========================================================================= */
/* Interleaving                                                               */
/* ========================================================================= */

// weave interleaves the three frame sets into one capture and returns the
// parallel role slice.
//
// The order is DETERMINISTIC (the capture files are committed and byte-compared)
// and it is INTERLEAVED rather than concatenated, which matters for one
// fixture in particular: the per-source token bucket's behaviour depends on the
// order frames arrive in, so a capture that replayed every attack frame before
// the first legitimate one would measure a bucket state no real traffic mix
// would produce.
func weave(attack, legit, allow []pktgen.Frame) ([]pktgen.Frame, []Role) {
	total := len(attack) + len(legit) + len(allow)
	frames := make([]pktgen.Frame, 0, total)
	roles := make([]Role, 0, total)

	ai, li, wi := 0, 0, 0
	for i := 0; i < total; i++ {
		switch {
		// Every 11th slot is an allowlisted frame, every 3rd a legitimate one,
		// with the remainder attack — then whatever is left over is drained in
		// order, so no set can be silently truncated by the ratio.
		case wi < len(allow) && i%11 == 7:
			frames, roles = append(frames, allow[wi]), append(roles, RoleAllow)
			wi++
		case li < len(legit) && i%3 == 1:
			frames, roles = append(frames, legit[li]), append(roles, RoleLegit)
			li++
		case ai < len(attack):
			frames, roles = append(frames, attack[ai]), append(roles, RoleAttack)
			ai++
		case li < len(legit):
			frames, roles = append(frames, legit[li]), append(roles, RoleLegit)
			li++
		case wi < len(allow):
			frames, roles = append(frames, allow[wi]), append(roles, RoleAllow)
			wi++
		}
	}
	return frames, roles
}

/* ========================================================================= */
/* Config                                                                     */
/* ========================================================================= */

// ConfigYAML is the configuration the suite runs the host-scoped fixtures
// under. It is a real, validated config — parsed by config.Parse, not
// hand-assembled — so a fixture cannot depend on a policy an operator could
// not actually write.
//
// pinPath is the bpffs directory for the data plane's pins.
func ConfigYAML(pinPath string) string {
	return fmt.Sprintf(`dry_run: false
listen:
  netflow: ":0"
sampling:
  default_rate: 1
networks:
  - %q
  - %q
protected_whitelist:
  - %q
  - %q
thresholds:
  pps: 1000
  mbps: 1000000
  flows_per_sec: 100000000
hostgroups:
  - name: %q
    networks: ["%s/32"]
    flowspec:
      action: rate_limit
      # 0.008 Mbit/s is 1000 bytes/s. The data plane's bucket is keyed
      # {victim, source, profile}, so this is a PER-SOURCE ceiling with a
      # one-second burst: each attacking source gets exactly one frame through
      # before its bucket is empty. That is what makes the admitted count an
      # assertion about the bucket rather than a rounding artefact.
      rate_mbps: 0.008
      source_anchored: true
    escalation:
      - {after_seconds: 0, action: dataplane}
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 1
  max_active_bans: 64
escalation:
  - {after_seconds: 0, action: dataplane}
dataplane:
  enabled: true
  interfaces: ["lo"]
  xdp_mode: generic
  pin_path: %q
  on_exit: detach
  allowlist:
    - %q
    - %q
  limits:
    max_dynamic_rules: 1024
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:0"
`,
		NetV4, NetV6, WhitelistV4, WhitelistV6,
		RateLimitGroup, rateLimitVictim,
		pinPath, AllowV4, AllowV6)
}

// RateLimitGroup is the hostgroup whose flowspec policy is rate_limit +
// source_anchored, which is the only way to reach the data plane's token
// bucket through the real chain.
const RateLimitGroup = "ratelimited"

// CarpetConfigYAML is the configuration for the carpet-bombing fixture, which
// needs its own run for a reason worth stating: carpet detection aggregates
// EVERY protected host into its /24, so a config with carpet enabled would
// fold the other seventeen fixtures' victims into one 203.0.113.0/24 attack
// and mitigate the whole prefix out from under them.
//
// carpet.mitigation is "dataplane" — the same method the other seventeen
// fixtures reach through the global ladder. It used to be "flowspec", because
// config.validateCarpet accepted only flowspec|blackhole and the suite had to
// make the last hop (dataplaneRules + Installer.Install) by hand. It no longer
// does: this fixture now runs the identical chain, ending in the real
// Mitigator.banPrefix -> installDataplaneLocked, and the ONLY thing that
// distinguishes it from the other seventeen is that its rules are anchored on a
// /24 instead of a /32.
func CarpetConfigYAML(pinPath string) string {
	return fmt.Sprintf(`dry_run: false
listen:
  netflow: ":0"
sampling:
  default_rate: 1
networks:
  - %q
protected_whitelist: []
thresholds:
  pps: 100000000
  mbps: 1000000
  flows_per_sec: 100000000
carpet:
  aggregation_prefix_v4: 24
  min_hosts: 4
  mitigation: dataplane
  thresholds:
    pps: 1000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 1
  max_active_bans: 64
mitigation: flowspec
escalation:
  - {after_seconds: 0, action: flowspec}
dataplane:
  enabled: true
  interfaces: ["lo"]
  xdp_mode: generic
  pin_path: %q
  on_exit: detach
  allowlist:
    - %q
  limits:
    max_dynamic_rules: 1024
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:0"
`, CarpetNet, pinPath, AllowV4)
}

// ParseConfig parses one of the YAML documents above, failing loudly rather
// than returning a half-built config: every caller is a test whose next step
// would be an unexplainable skip.
func ParseConfig(yaml string) (*config.Config, error) {
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		return nil, fmt.Errorf("blockrate: parsing the suite config: %w", err)
	}
	return cfg, nil
}
