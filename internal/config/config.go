// Package config loads, validates and hot-reloads the kapkan YAML
// configuration. Load returns an immutable *Config; consumers that support
// hot reload hold a Store and read a fresh snapshot per evaluation cycle.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of the kapkan configuration. Fields mirror the YAML
// shape exactly; parsed derivatives (prefixes, addresses, community value)
// are populated during validation and must not be set by hand.
type Config struct {
	DryRun             bool       `yaml:"dry_run"`
	Listen             Listen     `yaml:"listen"`
	Sampling           Sampling   `yaml:"sampling"`
	Networks           []string   `yaml:"networks"`
	ProtectedWhitelist []string   `yaml:"protected_whitelist"`
	Thresholds         Thresholds `yaml:"thresholds"`
	// ThresholdsOutgoing enables detection of attacks ORIGINATED by
	// protected hosts (compromised machines). Absent, outgoing traffic is
	// not even counted.
	ThresholdsOutgoing *Thresholds `yaml:"thresholds_outgoing"`
	Hostgroups         []Hostgroup `yaml:"hostgroups"`
	Ban                Ban         `yaml:"ban"`
	BGP                BGP         `yaml:"bgp"`
	Notify             Notify      `yaml:"notify"`
	API                API         `yaml:"api"`

	// Parsed forms, populated by validate().
	NetworkPrefixes []netip.Prefix `yaml:"-"`
	WhitelistAddrs  []netip.Addr   `yaml:"-"`
	// Groups are the resolved hostgroups; Groups[0] is always the implicit
	// global fallback group carrying the top-level thresholds.
	Groups []Group `yaml:"-"`
	// OutgoingEnabled reports whether any group has outgoing thresholds, so
	// the engine can skip outgoing accounting entirely when unused.
	OutgoingEnabled bool `yaml:"-"`
	// groupRoutes maps prefixes to Groups indexes, longest prefix first.
	groupRoutes []groupRoute
}

// Listen holds the UDP listen addresses for flow ingestion.
type Listen struct {
	SFlow   string `yaml:"sflow"`
	NetFlow string `yaml:"netflow"`
}

// Sampling controls sampling-rate handling.
type Sampling struct {
	// DefaultRate is used when an exporter does not report its own rate.
	DefaultRate uint64 `yaml:"default_rate"`
}

// Thresholds are per-host limits after sampling correction. The base trio
// (pps/mbps/flows_per_sec) must be > 0 in an incoming threshold set; the
// per-protocol limits default to 0, which disables them. Any crossed
// threshold triggers detection (they are OR-ed).
type Thresholds struct {
	PPS         uint64 `yaml:"pps" json:"pps"`
	Mbps        uint64 `yaml:"mbps" json:"mbps"`
	FlowsPerSec uint64 `yaml:"flows_per_sec" json:"flows_per_sec"`

	TCPPPS     uint64 `yaml:"tcp_pps" json:"tcp_pps,omitempty"`
	TCPMbps    uint64 `yaml:"tcp_mbps" json:"tcp_mbps,omitempty"`
	UDPPPS     uint64 `yaml:"udp_pps" json:"udp_pps,omitempty"`
	UDPMbps    uint64 `yaml:"udp_mbps" json:"udp_mbps,omitempty"`
	ICMPPPS    uint64 `yaml:"icmp_pps" json:"icmp_pps,omitempty"`
	ICMPMbps   uint64 `yaml:"icmp_mbps" json:"icmp_mbps,omitempty"`
	TCPSYNPPS  uint64 `yaml:"tcp_syn_pps" json:"tcp_syn_pps,omitempty"`
	TCPSYNMbps uint64 `yaml:"tcp_syn_mbps" json:"tcp_syn_mbps,omitempty"`
	FragPPS    uint64 `yaml:"frag_pps" json:"frag_pps,omitempty"`
	FragMbps   uint64 `yaml:"frag_mbps" json:"frag_mbps,omitempty"`
}

// Zero reports whether no threshold is set at all.
func (t Thresholds) Zero() bool { return t == Thresholds{} }

// CalcMethod selects how a hostgroup's thresholds are applied.
type CalcMethod string

// Hostgroup calculation methods.
const (
	// CalcPerHost evaluates every host in the group against the group's
	// thresholds individually.
	CalcPerHost CalcMethod = "per_host"
	// CalcTotal evaluates the summed traffic of the whole group. Total
	// groups alert only; they never trigger automatic bans because there is
	// no single host to blackhole.
	CalcTotal CalcMethod = "total"
)

// GlobalGroup is the name of the implicit fallback group that applies the
// top-level thresholds to hosts not matched by any configured hostgroup.
const GlobalGroup = "global"

// Hostgroup groups prefixes under a shared threshold set and mitigation
// policy. Fields mirror the YAML shape; the resolved form lives in
// Config.Groups.
type Hostgroup struct {
	Name     string   `yaml:"name"`
	Networks []string `yaml:"networks"`
	// Calculation is "per_host" (default) or "total".
	Calculation string `yaml:"calculation"`
	// Thresholds override the global thresholds; when omitted the group
	// inherits them.
	Thresholds *Thresholds `yaml:"thresholds"`
	// ThresholdsOutgoing overrides the global outgoing thresholds; when
	// omitted the group inherits them (or stays disabled if there are none).
	ThresholdsOutgoing *Thresholds `yaml:"thresholds_outgoing"`
	// Ban controls automatic RTBH for the group's hosts (default true).
	// Must not be set to true for total groups, which never auto-ban.
	Ban *bool `yaml:"ban"`
}

// Group is the resolved, immutable form of a hostgroup used by the engine.
type Group struct {
	Name       string     `json:"name"`
	Calc       CalcMethod `json:"calculation"`
	Thresholds Thresholds `json:"thresholds"`
	// OutThresholds is nil when outgoing detection is disabled for the group.
	OutThresholds *Thresholds `json:"thresholds_outgoing,omitempty"`
	BanEnabled    bool        `json:"ban"`
}

// groupRoute maps one prefix to its owning group for longest-prefix-match
// lookup.
type groupRoute struct {
	prefix netip.Prefix
	group  int // index into Config.Groups
}

// Ban controls the lifecycle of blackhole announcements.
type Ban struct {
	TTLSeconds             int `yaml:"ttl_seconds"`
	UnbanHysteresisSeconds int `yaml:"unban_hysteresis_seconds"`
	MaxActiveBans          int `yaml:"max_active_bans"`
}

// TTL returns the ban TTL as a duration.
func (b Ban) TTL() time.Duration { return time.Duration(b.TTLSeconds) * time.Second }

// UnbanHysteresis returns the hysteresis as a duration.
func (b Ban) UnbanHysteresis() time.Duration {
	return time.Duration(b.UnbanHysteresisSeconds) * time.Second
}

// BGP configures the embedded BGP speaker.
type BGP struct {
	LocalASN  uint32     `yaml:"local_asn"`
	RouterID  string     `yaml:"router_id"`
	NextHop   string     `yaml:"next_hop"`
	NextHop6  string     `yaml:"next_hop6"`
	Community string     `yaml:"community"`
	Neighbors []Neighbor `yaml:"neighbors"`
	// ListenPort is the local BGP listen port; -1 (default) disables
	// listening so kapkan only dials out. Used by tests.
	ListenPort int32 `yaml:"listen_port"`

	// CommunityValue is the parsed Community, populated by validate().
	CommunityValue uint32 `yaml:"-"`
}

// Neighbor is one BGP peer.
type Neighbor struct {
	Address   string `yaml:"address"`
	RemoteASN uint32 `yaml:"remote_asn"`
	// Port overrides the neighbor's BGP port (default 179). Used by tests.
	Port uint32 `yaml:"port"`
}

// Notify configures attack notifications.
type Notify struct {
	Telegram Telegram `yaml:"telegram"`
	Webhook  Webhook  `yaml:"webhook"`
}

// Telegram notification settings. The bot token is read from the
// environment variable named in TokenEnv, never from the config file.
type Telegram struct {
	TokenEnv string `yaml:"token_env"`
	ChatID   string `yaml:"chat_id"`
}

// Webhook is a generic JSON POST notification target.
type Webhook struct {
	URL string `yaml:"url"`
}

// API configures the REST API listener.
type API struct {
	Listen string `yaml:"listen"`
}

// Load reads, parses and validates the configuration file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse parses and validates raw YAML configuration bytes.
func Parse(raw []byte) (*Config, error) {
	// Safety default: mitigation is dry-run unless the file explicitly
	// says otherwise. Setting it before unmarshal means an absent key
	// keeps the safe value.
	cfg := &Config{DryRun: true}
	cfg.BGP.ListenPort = -1
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen.SFlow == "" && c.Listen.NetFlow == "" {
		return fmt.Errorf("listen: at least one of sflow/netflow must be set")
	}
	for name, addr := range map[string]string{"sflow": c.Listen.SFlow, "netflow": c.Listen.NetFlow} {
		if addr == "" {
			continue
		}
		if _, err := netip.ParseAddrPort(normalizeListen(addr)); err != nil {
			return fmt.Errorf("listen.%s: invalid address %q: %w", name, addr, err)
		}
	}

	if c.Sampling.DefaultRate < 1 {
		return fmt.Errorf("sampling.default_rate must be >= 1, got %d", c.Sampling.DefaultRate)
	}

	if len(c.Networks) == 0 {
		return fmt.Errorf("networks: at least one protected prefix is required")
	}
	c.NetworkPrefixes = make([]netip.Prefix, 0, len(c.Networks))
	for _, s := range c.Networks {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("networks: invalid CIDR %q: %w", s, err)
		}
		p = p.Masked()
		for _, prev := range c.NetworkPrefixes {
			if prev == p {
				return fmt.Errorf("networks: duplicate prefix %s", p)
			}
			if prev.Overlaps(p) {
				return fmt.Errorf("networks: %s overlaps %s; remove the redundant entry", p, prev)
			}
		}
		c.NetworkPrefixes = append(c.NetworkPrefixes, p)
	}

	c.WhitelistAddrs = make([]netip.Addr, 0, len(c.ProtectedWhitelist))
	for _, s := range c.ProtectedWhitelist {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("protected_whitelist: invalid IP %q: %w", s, err)
		}
		c.WhitelistAddrs = append(c.WhitelistAddrs, a)
	}

	if c.Thresholds.PPS == 0 || c.Thresholds.Mbps == 0 || c.Thresholds.FlowsPerSec == 0 {
		return fmt.Errorf("thresholds: pps, mbps and flows_per_sec must all be > 0")
	}
	if c.ThresholdsOutgoing != nil && c.ThresholdsOutgoing.Zero() {
		return fmt.Errorf("thresholds_outgoing: set at least one threshold or remove the block")
	}

	if err := c.validateHostgroups(); err != nil {
		return err
	}

	if c.Ban.TTLSeconds <= 0 {
		return fmt.Errorf("ban.ttl_seconds must be > 0, got %d", c.Ban.TTLSeconds)
	}
	if c.Ban.UnbanHysteresisSeconds < 0 {
		return fmt.Errorf("ban.unban_hysteresis_seconds must be >= 0, got %d", c.Ban.UnbanHysteresisSeconds)
	}
	if c.Ban.MaxActiveBans <= 0 {
		return fmt.Errorf("ban.max_active_bans must be > 0, got %d", c.Ban.MaxActiveBans)
	}

	if err := c.validateBGP(); err != nil {
		return err
	}

	if c.API.Listen == "" {
		return fmt.Errorf("api.listen must be set")
	}
	if _, err := netip.ParseAddrPort(normalizeListen(c.API.Listen)); err != nil {
		return fmt.Errorf("api.listen: invalid address %q: %w", c.API.Listen, err)
	}
	return nil
}

// validateHostgroups checks the hostgroups section and builds the resolved
// Groups slice and the longest-prefix-first lookup table. It runs after the
// networks and thresholds sections have been validated, so it can rely on
// NetworkPrefixes and on the global thresholds being sane.
func (c *Config) validateHostgroups() error {
	c.Groups = make([]Group, 0, len(c.Hostgroups)+1)
	c.Groups = append(c.Groups, Group{
		Name:          GlobalGroup,
		Calc:          CalcPerHost,
		Thresholds:    c.Thresholds,
		OutThresholds: c.ThresholdsOutgoing,
		BanEnabled:    true,
	})
	c.groupRoutes = nil

	names := make(map[string]bool, len(c.Hostgroups))
	seen := make(map[netip.Prefix]string) // prefix → owning group name
	for i, hg := range c.Hostgroups {
		if hg.Name == "" {
			return fmt.Errorf("hostgroups[%d]: name is required", i)
		}
		if hg.Name == GlobalGroup {
			return fmt.Errorf("hostgroups[%d]: name %q is reserved for the implicit fallback group", i, GlobalGroup)
		}
		if names[hg.Name] {
			return fmt.Errorf("hostgroups[%d]: duplicate name %q", i, hg.Name)
		}
		names[hg.Name] = true

		calc := CalcMethod(hg.Calculation)
		if calc == "" {
			calc = CalcPerHost
		}
		if calc != CalcPerHost && calc != CalcTotal {
			return fmt.Errorf("hostgroups[%q]: calculation must be %q or %q, got %q",
				hg.Name, CalcPerHost, CalcTotal, hg.Calculation)
		}

		banEnabled := hg.Ban == nil || *hg.Ban
		if calc == CalcTotal {
			if hg.Ban != nil && *hg.Ban {
				return fmt.Errorf("hostgroups[%q]: ban: true is not allowed with calculation: total — total groups alert only, there is no single host to blackhole", hg.Name)
			}
			banEnabled = false
		}

		th := c.Thresholds
		if hg.Thresholds != nil {
			th = *hg.Thresholds
			if th.PPS == 0 || th.Mbps == 0 || th.FlowsPerSec == 0 {
				return fmt.Errorf("hostgroups[%q]: thresholds: pps, mbps and flows_per_sec must all be > 0 (omit the block to inherit global thresholds)", hg.Name)
			}
		}

		outTh := c.ThresholdsOutgoing
		if hg.ThresholdsOutgoing != nil {
			if hg.ThresholdsOutgoing.Zero() {
				return fmt.Errorf("hostgroups[%q]: thresholds_outgoing: set at least one threshold or remove the block", hg.Name)
			}
			outTh = hg.ThresholdsOutgoing
		}

		if len(hg.Networks) == 0 {
			return fmt.Errorf("hostgroups[%q]: at least one prefix is required", hg.Name)
		}
		groupIdx := len(c.Groups)
		for _, s := range hg.Networks {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("hostgroups[%q]: invalid CIDR %q: %w", hg.Name, s, err)
			}
			p = p.Masked()
			if owner, dup := seen[p]; dup {
				return fmt.Errorf("hostgroups[%q]: prefix %s already belongs to group %q", hg.Name, p, owner)
			}
			seen[p] = hg.Name
			contained := false
			for _, np := range c.NetworkPrefixes {
				if np.Contains(p.Addr()) && np.Bits() <= p.Bits() {
					contained = true
					break
				}
			}
			if !contained {
				return fmt.Errorf("hostgroups[%q]: prefix %s is not inside any configured networks entry — flows to it are never processed", hg.Name, p)
			}
			c.groupRoutes = append(c.groupRoutes, groupRoute{prefix: p, group: groupIdx})
		}

		c.Groups = append(c.Groups, Group{
			Name:          hg.Name,
			Calc:          calc,
			Thresholds:    th,
			OutThresholds: outTh,
			BanEnabled:    banEnabled,
		})
	}

	for i := range c.Groups {
		if c.Groups[i].OutThresholds != nil {
			c.OutgoingEnabled = true
			break
		}
	}

	// Longest prefix first so GroupFor's first match is the most specific.
	sort.SliceStable(c.groupRoutes, func(i, j int) bool {
		return c.groupRoutes[i].prefix.Bits() > c.groupRoutes[j].prefix.Bits()
	})
	return nil
}

// GroupIndexFor returns the index into Groups of the group owning addr by
// longest prefix match; 0 (the implicit global group) when no hostgroup
// prefix matches.
func (c *Config) GroupIndexFor(addr netip.Addr) int {
	for i := range c.groupRoutes {
		if c.groupRoutes[i].prefix.Contains(addr) {
			return c.groupRoutes[i].group
		}
	}
	return 0
}

// GroupFor returns the resolved group owning addr by longest prefix match,
// falling back to the implicit global group. The returned pointer is into
// the immutable Config and must not be modified.
func (c *Config) GroupFor(addr netip.Addr) *Group {
	return &c.Groups[c.GroupIndexFor(addr)]
}

func (c *Config) validateBGP() error {
	b := &c.BGP
	if b.LocalASN == 0 {
		return fmt.Errorf("bgp.local_asn must be > 0")
	}
	rid, err := netip.ParseAddr(b.RouterID)
	if err != nil || !rid.Is4() {
		return fmt.Errorf("bgp.router_id must be a valid IPv4 address, got %q", b.RouterID)
	}
	nh, err := netip.ParseAddr(b.NextHop)
	if err != nil || !nh.Is4() {
		return fmt.Errorf("bgp.next_hop must be a valid IPv4 address, got %q", b.NextHop)
	}
	if b.NextHop6 != "" {
		nh6, err := netip.ParseAddr(b.NextHop6)
		if err != nil || !nh6.Is6() || nh6.Is4In6() {
			return fmt.Errorf("bgp.next_hop6 must be a valid IPv6 address, got %q", b.NextHop6)
		}
	}
	val, err := ParseCommunity(b.Community)
	if err != nil {
		return fmt.Errorf("bgp.community: %w", err)
	}
	b.CommunityValue = val
	for i, n := range b.Neighbors {
		if _, err := netip.ParseAddr(n.Address); err != nil {
			return fmt.Errorf("bgp.neighbors[%d]: invalid address %q: %w", i, n.Address, err)
		}
		if n.RemoteASN == 0 {
			return fmt.Errorf("bgp.neighbors[%d]: remote_asn must be > 0", i)
		}
	}
	return nil
}

// ParseCommunity parses an "ASN:value" BGP community string into its uint32
// wire representation.
func ParseCommunity(s string) (uint32, error) {
	hi, lo, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("community %q must have form ASN:value", s)
	}
	h, err := strconv.ParseUint(hi, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("community %q: bad ASN part: %w", s, err)
	}
	l, err := strconv.ParseUint(lo, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("community %q: bad value part: %w", s, err)
	}
	return uint32(h)<<16 | uint32(l), nil
}

// InNetworks reports whether addr falls inside any protected prefix.
func (c *Config) InNetworks(addr netip.Addr) bool {
	for _, p := range c.NetworkPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsWhitelisted reports whether addr must never be banned.
func (c *Config) IsWhitelisted(addr netip.Addr) bool {
	for _, a := range c.WhitelistAddrs {
		if a == addr {
			return true
		}
	}
	return false
}

// normalizeListen turns ":6343" into a parseable "0.0.0.0:6343".
func normalizeListen(s string) string {
	if strings.HasPrefix(s, ":") {
		return "0.0.0.0" + s
	}
	return s
}

// Store holds the current configuration snapshot and supports atomic
// replacement on SIGHUP-driven reload.
type Store struct {
	path string
	cur  atomic.Pointer[Config]
}

// NewStore creates a Store serving cfg, remembering path for Reload.
func NewStore(path string, cfg *Config) *Store {
	s := &Store{path: path}
	s.cur.Store(cfg)
	return s
}

// Get returns the current configuration snapshot. The returned value is
// immutable; callers must not modify it.
func (s *Store) Get() *Config { return s.cur.Load() }

// Reload re-reads the config file. On any error the previous configuration
// stays active and the error is returned. Listen addresses and BGP identity
// cannot change at runtime; a reload that alters them is rejected.
func (s *Store) Reload() (*Config, error) {
	next, err := Load(s.path)
	if err != nil {
		return nil, err
	}
	prev := s.cur.Load()
	if next.Listen != prev.Listen {
		return nil, fmt.Errorf("reload: listen addresses cannot change at runtime (restart required)")
	}
	if next.BGP.LocalASN != prev.BGP.LocalASN || next.BGP.RouterID != prev.BGP.RouterID {
		return nil, fmt.Errorf("reload: bgp identity (local_asn, router_id) cannot change at runtime (restart required)")
	}
	if next.API.Listen != prev.API.Listen {
		return nil, fmt.Errorf("reload: api.listen cannot change at runtime (restart required)")
	}
	s.cur.Store(next)
	return next, nil
}
