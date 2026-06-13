// Package config loads, validates and hot-reloads the kapkan YAML
// configuration. Load returns an immutable *Config; consumers that support
// hot reload hold a Store and read a fresh snapshot per evaluation cycle.
package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	// Baseline enables continuous per-host learned thresholds; static
	// thresholds remain as floor/ceiling guards.
	Baseline *Baseline `yaml:"baseline"`
	// Mitigation selects the default mitigation method (blackhole|flowspec);
	// hostgroups may override it.
	Mitigation string `yaml:"mitigation"`
	// FlowSpec is the default FlowSpec action policy, used by groups whose
	// method is flowspec.
	FlowSpec *FlowSpec `yaml:"flowspec"`
	// Escalation is the default mitigation ladder; when set it supersedes
	// the single `mitigation` method. Hostgroups may override it.
	Escalation []EscalationStep `yaml:"escalation"`
	Hostgroups []Hostgroup      `yaml:"hostgroups"`
	Samples    Samples          `yaml:"samples"`
	Storage    Storage          `yaml:"storage"`
	Ban        Ban              `yaml:"ban"`
	BGP        BGP              `yaml:"bgp"`
	Notify     Notify           `yaml:"notify"`
	API        API              `yaml:"api"`

	// Parsed forms, populated by validate().
	NetworkPrefixes []netip.Prefix `yaml:"-"`
	WhitelistAddrs  []netip.Addr   `yaml:"-"`
	// Groups are the resolved hostgroups; Groups[0] is always the implicit
	// global fallback group carrying the top-level thresholds.
	Groups []Group `yaml:"-"`
	// OutgoingEnabled reports whether any group has outgoing thresholds, so
	// the engine can skip outgoing accounting entirely when unused.
	OutgoingEnabled bool `yaml:"-"`
	// SampleCfg is the resolved (defaults applied) form of Samples. It is
	// comparable so reload can detect changes that require a restart.
	SampleCfg SampleSettings `yaml:"-"`
	// StorageCfg is the resolved ClickHouse configuration.
	StorageCfg StorageSettings `yaml:"-"`
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

// Samples configures the traffic buffer used to attach flow samples to
// attack events. Fields mirror the YAML shape; the resolved form (defaults
// applied) lives in Config.SampleCfg.
type Samples struct {
	// Enabled defaults to true; set false to disable the buffer entirely.
	Enabled *bool `yaml:"enabled"`
	// BufferFlows is the total capacity of the recent-flows ring across the
	// engine (default 65536, max 1048576). More flows = better samples at
	// high rates, at roughly 120 bytes per slot of fixed memory.
	BufferFlows int `yaml:"buffer_flows"`
	// FlowsPerAttack caps the raw flow records attached to one attack
	// event (default 20).
	FlowsPerAttack int `yaml:"flows_per_attack"`
}

// SampleSettings is the resolved, comparable form of Samples.
type SampleSettings struct {
	Enabled        bool
	BufferFlows    int
	FlowsPerAttack int
}

// Storage configures optional long-term persistence. ClickHouse is the only
// backend; absent, kapkan keeps everything in-process (live data only).
type Storage struct {
	ClickHouse ClickHouse `yaml:"clickhouse"`
}

// ClickHouse configures the optional ClickHouse writer. kapkan talks to the
// server's HTTP interface with the standard library — no driver dependency.
// Credentials are read from the environment, never the config file.
type ClickHouse struct {
	// URL is the ClickHouse HTTP endpoint, e.g. "http://127.0.0.1:8123".
	// Empty disables persistence entirely.
	URL         string `yaml:"url"`
	Database    string `yaml:"database"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
	// TTLDays is how long rows are retained (default 7).
	TTLDays int `yaml:"ttl_days"`
	// FlushIntervalSeconds bounds how long a batch waits before being sent
	// (default 5).
	FlushIntervalSeconds int `yaml:"flush_interval_seconds"`
	// BatchSize flushes early once this many rows are queued (default 1000).
	BatchSize int `yaml:"batch_size"`
	// QueueSize bounds the in-memory row buffer; rows are dropped (and
	// counted) when it is full so storage never blocks detection (default
	// 100000).
	QueueSize int `yaml:"queue_size"`
	// TrafficIntervalSeconds is how often a per-host/per-group traffic
	// snapshot is persisted (default 10).
	TrafficIntervalSeconds int `yaml:"traffic_interval_seconds"`
}

// StorageSettings is the resolved ClickHouse configuration.
type StorageSettings struct {
	Enabled         bool
	URL             string
	Database        string
	UsernameEnv     string
	PasswordEnv     string
	TTLDays         int
	FlushInterval   time.Duration
	BatchSize       int
	QueueSize       int
	TrafficInterval time.Duration
}

// Baseline configures continuous EWMA-learned per-host thresholds. Fields
// mirror the YAML shape; the resolved form lives in BaselineSettings.
type Baseline struct {
	// Enabled defaults to true when the block is present.
	Enabled *bool `yaml:"enabled"`
	// Factor multiplies the learned baseline into the effective threshold
	// (default 3): traffic above baseline*factor is an attack.
	Factor float64 `yaml:"factor"`
	// HalfLifeSeconds is the EWMA half-life (default 3600): how long until
	// a sustained change moves the baseline halfway to the new level.
	HalfLifeSeconds int `yaml:"half_life_seconds"`
	// WarmupSeconds is how long a host must be observed before its
	// baseline gates detection (default 600). Until then only the static
	// thresholds apply.
	WarmupSeconds int `yaml:"warmup_seconds"`
	// Floor is the minimum effective threshold per metric — a quiet host's
	// tiny baseline must not make detection hair-trigger. Required.
	Floor BaselineFloor `yaml:"floor"`
}

// BaselineFloor bounds the effective thresholds from below.
type BaselineFloor struct {
	PPS         uint64 `yaml:"pps" json:"pps"`
	Mbps        uint64 `yaml:"mbps" json:"mbps"`
	FlowsPerSec uint64 `yaml:"flows_per_sec" json:"flows_per_sec"`
}

// BaselineSettings is the resolved form of Baseline used by the engine.
type BaselineSettings struct {
	Factor float64 `json:"factor"`
	// Alpha is the derived per-second EWMA weight: 1 - 2^(-1/half_life).
	Alpha         float64       `json:"-"`
	WarmupSeconds int           `json:"warmup_seconds"`
	Floor         BaselineFloor `json:"floor"`
}

// MitigationMethod selects how an attack is mitigated.
type MitigationMethod string

// Mitigation methods.
const (
	// MitigateBlackhole announces an RTBH /32 or /128 — drops ALL traffic to
	// the victim (the default; takes the victim offline).
	MitigateBlackhole MitigationMethod = "blackhole"
	// MitigateFlowSpec announces BGP FlowSpec rules matching the attack
	// vector — surgical drops that can spare the victim's legitimate
	// traffic. Requires upstreams that honor FlowSpec.
	MitigateFlowSpec MitigationMethod = "flowspec"
)

// FlowSpecAction is the action attached to generated FlowSpec rules.
type FlowSpecAction string

// FlowSpec actions.
const (
	// FlowSpecDiscard drops every packet matching a rule (traffic-rate 0).
	FlowSpecDiscard FlowSpecAction = "discard"
	// FlowSpecRateLimit caps matching traffic at a configured rate.
	FlowSpecRateLimit FlowSpecAction = "rate_limit"
)

// EscalationAction is one rung of a mitigation ladder.
type EscalationAction string

// Escalation actions.
const (
	// EscalateNone alerts only — no route is announced at this stage.
	EscalateNone EscalationAction = "none"
	// EscalateFlowSpec announces FlowSpec rules at this stage.
	EscalateFlowSpec EscalationAction = "flowspec"
	// EscalateBlackhole announces an RTBH route at this stage.
	EscalateBlackhole EscalationAction = "blackhole"
)

// EscalationStep is one configured rung of the ladder (YAML shape).
type EscalationStep struct {
	// AfterSeconds is the delay from attack start at which this rung
	// applies, provided the attack is still active. The first rung must be 0.
	AfterSeconds int `yaml:"after_seconds"`
	// Action is none | flowspec | blackhole.
	Action string `yaml:"action"`
}

// EscalationStage is one resolved rung used by the mitigator.
type EscalationStage struct {
	AfterSeconds int              `json:"after_seconds"`
	Action       EscalationAction `json:"action"`
}

// FlowSpec is the FlowSpec action policy. Fields mirror the YAML; the
// resolved per-second byte rate lives in Group.FlowSpecRateBps.
type FlowSpec struct {
	// Action is "discard" (default) or "rate_limit".
	Action string `yaml:"action"`
	// RateMbps is the rate-limit ceiling in megabits/sec; required and used
	// only when Action is rate_limit.
	RateMbps float64 `yaml:"rate_mbps"`
}

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

// groupNameRe restricts hostgroup names to a log-, JSON- and header-safe
// charset.
var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// envNameRe matches a POSIX-ish environment variable name.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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
	// Baseline overrides the global baseline block wholesale; when omitted
	// the group inherits it (or stays static-only if there is none).
	Baseline *Baseline `yaml:"baseline"`
	// Mitigation overrides the default method (blackhole|flowspec) for this
	// group; empty inherits the global default.
	Mitigation string `yaml:"mitigation"`
	// FlowSpec overrides the default FlowSpec action policy for this group.
	FlowSpec *FlowSpec `yaml:"flowspec"`
	// Escalation overrides the default mitigation ladder for this group;
	// when set it supersedes the group's `mitigation` method.
	Escalation []EscalationStep `yaml:"escalation"`
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
	// Baseline is nil when learned thresholds are disabled for the group.
	Baseline *BaselineSettings `json:"baseline,omitempty"`
	// Mitigation is the resolved method for this group.
	Mitigation MitigationMethod `json:"mitigation"`
	// FlowSpecAction and FlowSpecRateBps describe the action for generated
	// FlowSpec rules (rate is per-second bytes; 0 for discard).
	FlowSpecAction  FlowSpecAction `json:"flowspec_action,omitempty"`
	FlowSpecRateBps float64        `json:"-"`
	// Escalation is the resolved mitigation ladder; always at least one
	// stage (synthesized from Mitigation when not explicitly configured).
	Escalation []EscalationStage `json:"escalation,omitempty"`
	BanEnabled bool              `json:"ban"`
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
	Slack    Slack    `yaml:"slack"`
	Email    Email    `yaml:"email"`
	Exec     Exec     `yaml:"exec"`
}

// Slack posts notifications to a Slack incoming webhook.
type Slack struct {
	WebhookURL string `yaml:"webhook_url"`
}

// Email sends notifications over SMTP. Credentials are read from the named
// environment variables, never from the config file. With no credentials
// the message is sent unauthenticated (e.g. a local relay). STARTTLS is
// used whenever the server offers it.
type Email struct {
	// SMTPHost is "host:port" of the SMTP server; empty disables email.
	SMTPHost    string   `yaml:"smtp_host"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
	// RequireTLS refuses to send unless the server offers STARTTLS,
	// protecting against active downgrade. It is implied whenever
	// credentials are configured; without it, plaintext delivery to a
	// non-loopback host is loudly logged.
	RequireTLS bool `yaml:"require_tls"`
}

// Exec runs an operator-provided hook on every attack event. The payload
// JSON (docs/callback-schema.json, versioned via its schema_version field)
// is written to the hook's stdin; the event name is passed as argv[1]. The
// command runs directly, without a shell.
type Exec struct {
	// Command is the absolute path of the executable; empty disables.
	Command string `yaml:"command"`
	// TimeoutSeconds bounds one invocation (default 10).
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// Timeout returns the exec hook timeout as a duration.
func (e Exec) Timeout() time.Duration { return time.Duration(e.TimeoutSeconds) * time.Second }

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
	// Dashboard serves the embedded web UI on the API listener. Defaults to
	// true; set false to expose only the JSON API and metrics.
	Dashboard *bool `yaml:"dashboard"`
	// TokenEnv names an environment variable holding a bearer token. When
	// set, every /api/v1 request must carry "Authorization: Bearer <token>".
	// The token is read from the environment, never from the config file.
	// Unset (default) leaves the API open — safe only on a trusted listener
	// such as the default 127.0.0.1 bind.
	TokenEnv string `yaml:"token_env"`
}

// DashboardEnabled reports whether the embedded UI should be served.
func (a API) DashboardEnabled() bool { return a.Dashboard == nil || *a.Dashboard }

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
	if err := c.validateSamples(); err != nil {
		return err
	}
	if err := c.validateStorage(); err != nil {
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

	if err := c.validateNotify(); err != nil {
		return err
	}

	if c.API.Listen == "" {
		return fmt.Errorf("api.listen must be set")
	}
	if _, err := netip.ParseAddrPort(normalizeListen(c.API.Listen)); err != nil {
		return fmt.Errorf("api.listen: invalid address %q: %w", c.API.Listen, err)
	}
	if c.API.TokenEnv != "" {
		if !envNameRe.MatchString(c.API.TokenEnv) {
			return fmt.Errorf("api.token_env %q is not a valid environment variable name", c.API.TokenEnv)
		}
	}
	return nil
}

// validateHostgroups checks the hostgroups section and builds the resolved
// Groups slice and the longest-prefix-first lookup table. It runs after the
// networks and thresholds sections have been validated, so it can rely on
// NetworkPrefixes and on the global thresholds being sane.
func (c *Config) validateHostgroups() error {
	globalBaseline, err := resolveBaseline(c.Baseline)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}

	globalMethod, globalAction, globalRate, err := resolveMitigation(c.Mitigation, c.FlowSpec, MitigateBlackhole, nil)
	if err != nil {
		return fmt.Errorf("mitigation: %w", err)
	}
	globalStages, err := resolveEscalation(c.Escalation, globalMethod)
	if err != nil {
		return err
	}
	// A FlowSpec stage needs an action policy even if the single `mitigation`
	// method is blackhole (e.g. escalation: none → flowspec).
	if usesFlowSpec(globalStages) && globalAction == "" {
		if globalAction, globalRate, err = resolveFlowSpecPolicy(c.FlowSpec, nil); err != nil {
			return fmt.Errorf("flowspec: %w", err)
		}
	}

	c.Groups = make([]Group, 0, len(c.Hostgroups)+1)
	c.Groups = append(c.Groups, Group{
		Name:            GlobalGroup,
		Calc:            CalcPerHost,
		Thresholds:      c.Thresholds,
		OutThresholds:   c.ThresholdsOutgoing,
		Baseline:        globalBaseline,
		Mitigation:      globalMethod,
		FlowSpecAction:  globalAction,
		FlowSpecRateBps: globalRate,
		Escalation:      globalStages,
		BanEnabled:      true,
	})
	c.groupRoutes = nil

	names := make(map[string]bool, len(c.Hostgroups))
	seen := make(map[netip.Prefix]string) // prefix → owning group name
	for i, hg := range c.Hostgroups {
		if hg.Name == "" {
			return fmt.Errorf("hostgroups[%d]: name is required", i)
		}
		// Group names travel into logs, JSON payloads, chat messages and
		// email headers; a restricted charset closes injection vectors
		// (CRLF into RFC 5322 headers, mrkdwn/HTML metacharacters) at the
		// single central point.
		if !groupNameRe.MatchString(hg.Name) {
			return fmt.Errorf("hostgroups[%d]: name %q must match %s", i, hg.Name, groupNameRe)
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

		groupBaseline := globalBaseline
		if hg.Baseline != nil {
			groupBaseline, err = resolveBaseline(hg.Baseline)
			if err != nil {
				return fmt.Errorf("hostgroups[%q]: baseline: %w", hg.Name, err)
			}
		}

		method, action, rate, err := resolveMitigation(hg.Mitigation, hg.FlowSpec, globalMethod, c.FlowSpec)
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: mitigation: %w", hg.Name, err)
		}
		// A total group has no single victim to write a dst-match rule for.
		// An explicit flowspec choice is an error; an inherited one (from the
		// global default) silently falls back to blackhole — like ban does.
		if calc == CalcTotal && method == MitigateFlowSpec {
			if hg.Mitigation == string(MitigateFlowSpec) {
				return fmt.Errorf("hostgroups[%q]: mitigation: flowspec is not valid with calculation: total (no single victim prefix)", hg.Name)
			}
			method, action, rate = MitigateBlackhole, "", 0
		}

		// Resolve the mitigation ladder: the group's own escalation, else the
		// global one, else a single rung synthesized from the method.
		escSteps, escExplicit := hg.Escalation, hg.Escalation != nil
		if escSteps == nil {
			escSteps = c.Escalation
		}
		stages, err := resolveEscalation(escSteps, method)
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: %w", hg.Name, err)
		}
		if calc == CalcTotal && usesFlowSpec(stages) {
			if escExplicit {
				return fmt.Errorf("hostgroups[%q]: escalation: a flowspec stage is not valid with calculation: total (no single victim prefix)", hg.Name)
			}
			for i := range stages {
				if stages[i].Action == EscalateFlowSpec {
					stages[i].Action = EscalateBlackhole // inherited; degrade like the method case
				}
			}
		}
		if usesFlowSpec(stages) && action == "" {
			if action, rate, err = resolveFlowSpecPolicy(hg.FlowSpec, c.FlowSpec); err != nil {
				return fmt.Errorf("hostgroups[%q]: flowspec: %w", hg.Name, err)
			}
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
			Name:            hg.Name,
			Calc:            calc,
			Thresholds:      th,
			OutThresholds:   outTh,
			Baseline:        groupBaseline,
			Mitigation:      method,
			FlowSpecAction:  action,
			FlowSpecRateBps: rate,
			Escalation:      stages,
			BanEnabled:      banEnabled,
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

// resolveBaseline validates one baseline block and applies defaults. A nil
// block (or enabled: false) resolves to nil — static thresholds only.
func resolveBaseline(b *Baseline) (*BaselineSettings, error) {
	if b == nil || (b.Enabled != nil && !*b.Enabled) {
		return nil, nil
	}
	s := &BaselineSettings{
		Factor:        b.Factor,
		WarmupSeconds: b.WarmupSeconds,
		Floor:         b.Floor,
	}
	half := b.HalfLifeSeconds
	if half == 0 {
		half = 3600
	}
	if s.Factor == 0 {
		s.Factor = 3
	}
	if b.WarmupSeconds == 0 {
		s.WarmupSeconds = 600
	}
	if !(s.Factor >= 1.5 && s.Factor <= 100) {
		// Negated form rejects NaN too (NaN fails every comparison). Below
		// 1.5, normal jitter around the learned level trips constantly.
		return nil, fmt.Errorf("factor must be in 1.5..100, got %g", s.Factor)
	}
	if half < 10 || half > 7*86400 {
		return nil, fmt.Errorf("half_life_seconds must be in 10..604800, got %d", half)
	}
	if s.WarmupSeconds < 0 || s.WarmupSeconds > 86400 {
		return nil, fmt.Errorf("warmup_seconds must be in 0..86400, got %d", b.WarmupSeconds)
	}
	if s.Floor.PPS == 0 || s.Floor.Mbps == 0 || s.Floor.FlowsPerSec == 0 {
		return nil, fmt.Errorf("floor: pps, mbps and flows_per_sec must all be > 0 (hair-trigger guard)")
	}
	s.Alpha = 1 - math.Exp2(-1/float64(half))
	return s, nil
}

// dbNameRe restricts the ClickHouse database/table identifiers we
// interpolate into DDL to a safe charset (no injection surface).
var dbNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// resolveMitigation resolves a (method, flowspec) pair against a fallback
// default. methodStr empty inherits defMethod; the flowspec block falls back
// to defFlow (the global flowspec policy) when the group omits its own. It
// returns the resolved method, action, and rate-limit ceiling in bytes/sec
// (0 for discard or for the blackhole method).
func resolveMitigation(methodStr string, flow *FlowSpec, defMethod MitigationMethod, defFlow *FlowSpec) (MitigationMethod, FlowSpecAction, float64, error) {
	method := defMethod
	if methodStr != "" {
		method = MitigationMethod(methodStr)
		if method != MitigateBlackhole && method != MitigateFlowSpec {
			return "", "", 0, fmt.Errorf("method must be %q or %q, got %q", MitigateBlackhole, MitigateFlowSpec, methodStr)
		}
	}
	if method != MitigateFlowSpec {
		return method, "", 0, nil
	}
	action, rate, err := resolveFlowSpecPolicy(flow, defFlow)
	return method, action, rate, err
}

// resolveFlowSpecPolicy resolves the FlowSpec action policy (own block, else
// the default), returning the action and the rate-limit ceiling in bytes/sec
// (0 for discard).
func resolveFlowSpecPolicy(flow, defFlow *FlowSpec) (FlowSpecAction, float64, error) {
	fs := flow
	if fs == nil {
		fs = defFlow
	}
	action := FlowSpecDiscard
	var rateMbps float64
	if fs != nil {
		if fs.Action != "" {
			action = FlowSpecAction(fs.Action)
		}
		rateMbps = fs.RateMbps
	}
	switch action {
	case FlowSpecDiscard:
		return action, 0, nil
	case FlowSpecRateLimit:
		if rateMbps <= 0 {
			return "", 0, fmt.Errorf("flowspec.rate_mbps must be > 0 for the rate_limit action")
		}
		// Mbit/s → bytes/s for the FlowSpec traffic-rate extended community.
		return action, rateMbps * 1e6 / 8, nil
	default:
		return "", 0, fmt.Errorf("flowspec.action must be %q or %q, got %q", FlowSpecDiscard, FlowSpecRateLimit, fs.Action)
	}
}

// maxEscalationStages bounds a mitigation ladder.
const maxEscalationStages = 5

// methodAction maps a single mitigation method to its ladder action.
func methodAction(m MitigationMethod) EscalationAction {
	if m == MitigateFlowSpec {
		return EscalateFlowSpec
	}
	return EscalateBlackhole
}

// resolveEscalation resolves a mitigation ladder. An empty steps slice
// synthesizes a single rung from method (the back-compatible behavior).
// Otherwise the ladder must start at 0, strictly increase, and use valid
// actions.
func resolveEscalation(steps []EscalationStep, method MitigationMethod) ([]EscalationStage, error) {
	if len(steps) == 0 {
		return []EscalationStage{{AfterSeconds: 0, Action: methodAction(method)}}, nil
	}
	if len(steps) > maxEscalationStages {
		return nil, fmt.Errorf("escalation: at most %d stages, got %d", maxEscalationStages, len(steps))
	}
	stages := make([]EscalationStage, len(steps))
	prev := -1
	prevSev := -1
	for i, s := range steps {
		act := EscalationAction(s.Action)
		switch act {
		case EscalateNone, EscalateFlowSpec, EscalateBlackhole:
		default:
			return nil, fmt.Errorf("escalation[%d].action must be none|flowspec|blackhole, got %q", i, s.Action)
		}
		if i == 0 && s.AfterSeconds != 0 {
			return nil, fmt.Errorf("escalation[0].after_seconds must be 0 (the initial stage)")
		}
		if s.AfterSeconds <= prev {
			return nil, fmt.Errorf("escalation[%d].after_seconds (%d) must be greater than the previous stage (%d)", i, s.AfterSeconds, prev)
		}
		if s.AfterSeconds > 86400 {
			return nil, fmt.Errorf("escalation[%d].after_seconds must be <= 86400, got %d", i, s.AfterSeconds)
		}
		// A ladder may only hold or strengthen the response. De-escalating
		// (e.g. blackhole then flowspec) is a configuration error: an
		// escalation ladder climbs, it does not back off.
		sev := escalationSeverity(act)
		if sev < prevSev {
			return nil, fmt.Errorf("escalation[%d].action (%q) de-escalates from the previous stage; a ladder may only hold or strengthen the response", i, s.Action)
		}
		prevSev = sev
		prev = s.AfterSeconds
		stages[i] = EscalationStage{AfterSeconds: s.AfterSeconds, Action: act}
	}
	return stages, nil
}

// escalationSeverity ranks ladder actions so a ladder can be validated as
// non-decreasing: none < flowspec < blackhole.
func escalationSeverity(a EscalationAction) int {
	switch a {
	case EscalateBlackhole:
		return 2
	case EscalateFlowSpec:
		return 1
	default: // EscalateNone
		return 0
	}
}

// usesFlowSpec reports whether any stage announces FlowSpec.
func usesFlowSpec(stages []EscalationStage) bool {
	for _, s := range stages {
		if s.Action == EscalateFlowSpec {
			return true
		}
	}
	return false
}

// validateStorage resolves the storage block into StorageCfg with defaults.
// A nil/empty URL leaves persistence disabled with no further checks.
func (c *Config) validateStorage() error {
	ch := c.Storage.ClickHouse
	if ch.URL == "" {
		c.StorageCfg = StorageSettings{}
		return nil
	}
	u, err := url.ParseRequestURI(ch.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("storage.clickhouse.url must be an http(s) URL, got %q", ch.URL)
	}
	s := StorageSettings{
		Enabled:         true,
		URL:             strings.TrimRight(ch.URL, "/"),
		Database:        ch.Database,
		UsernameEnv:     ch.UsernameEnv,
		PasswordEnv:     ch.PasswordEnv,
		TTLDays:         ch.TTLDays,
		BatchSize:       ch.BatchSize,
		QueueSize:       ch.QueueSize,
		FlushInterval:   time.Duration(ch.FlushIntervalSeconds) * time.Second,
		TrafficInterval: time.Duration(ch.TrafficIntervalSeconds) * time.Second,
	}
	if s.Database == "" {
		s.Database = "kapkan"
	}
	if !dbNameRe.MatchString(s.Database) {
		return fmt.Errorf("storage.clickhouse.database %q must match %s", s.Database, dbNameRe)
	}
	for env, name := range map[string]string{ch.UsernameEnv: "username_env", ch.PasswordEnv: "password_env"} {
		if env != "" && !envNameRe.MatchString(env) {
			return fmt.Errorf("storage.clickhouse.%s %q is not a valid environment variable name", name, env)
		}
	}
	if s.TTLDays == 0 {
		s.TTLDays = 7
	}
	if s.BatchSize == 0 {
		s.BatchSize = 1000
	}
	if s.QueueSize == 0 {
		s.QueueSize = 100000
	}
	if s.FlushInterval == 0 {
		s.FlushInterval = 5 * time.Second
	}
	if s.TrafficInterval == 0 {
		s.TrafficInterval = 10 * time.Second
	}
	if s.TTLDays < 1 || s.TTLDays > 365 {
		return fmt.Errorf("storage.clickhouse.ttl_days must be in 1..365, got %d", s.TTLDays)
	}
	if s.BatchSize < 1 || s.BatchSize > s.QueueSize {
		return fmt.Errorf("storage.clickhouse.batch_size must be in 1..queue_size (%d), got %d", s.QueueSize, s.BatchSize)
	}
	if s.QueueSize < 1 || s.QueueSize > 10_000_000 {
		return fmt.Errorf("storage.clickhouse.queue_size must be in 1..10000000, got %d", s.QueueSize)
	}
	if s.FlushInterval < time.Second || s.FlushInterval > time.Hour {
		return fmt.Errorf("storage.clickhouse.flush_interval_seconds must be in 1..3600, got %d", ch.FlushIntervalSeconds)
	}
	if s.TrafficInterval < time.Second || s.TrafficInterval > time.Hour {
		return fmt.Errorf("storage.clickhouse.traffic_interval_seconds must be in 1..3600, got %d", ch.TrafficIntervalSeconds)
	}
	c.StorageCfg = s
	return nil
}

// validateSamples resolves the samples block into SampleCfg with defaults.
func (c *Config) validateSamples() error {
	s := SampleSettings{
		Enabled:        c.Samples.Enabled == nil || *c.Samples.Enabled,
		BufferFlows:    c.Samples.BufferFlows,
		FlowsPerAttack: c.Samples.FlowsPerAttack,
	}
	if !s.Enabled {
		// Sizes are meaningless while disabled; normalize them so reload
		// does not demand a restart for edits that change nothing.
		c.SampleCfg = SampleSettings{}
		return nil
	}
	if s.BufferFlows == 0 {
		s.BufferFlows = 65536
	}
	if s.FlowsPerAttack == 0 {
		s.FlowsPerAttack = 20
	}
	if s.BufferFlows < 256 || s.BufferFlows > 1<<20 {
		// Lower bound: one slot per shard. Upper bound: ~120 MB of fixed
		// memory, and sample collection cost scales linearly with ring
		// size while shard locks are held — an unbounded value lets a
		// config typo OOM the daemon or stall the evaluation loop.
		return fmt.Errorf("samples.buffer_flows must be in 256..1048576, got %d", s.BufferFlows)
	}
	if s.FlowsPerAttack < 1 || s.FlowsPerAttack > 500 {
		return fmt.Errorf("samples.flows_per_attack must be in 1..500, got %d", s.FlowsPerAttack)
	}
	c.SampleCfg = s
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

// validateNotify checks the optional notification channels and applies the
// exec hook's default timeout.
func (c *Config) validateNotify() error {
	n := &c.Notify
	if n.Slack.WebhookURL != "" {
		u, err := url.ParseRequestURI(n.Slack.WebhookURL)
		if err != nil {
			return fmt.Errorf("notify.slack.webhook_url: invalid URL %q", n.Slack.WebhookURL)
		}
		// Slack webhooks are https-only and the path is a bearer secret;
		// plain http would leak it. The loopback exception exists for
		// local relays and tests.
		if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
			return fmt.Errorf("notify.slack.webhook_url must be https (or http to a loopback address), got %q", n.Slack.WebhookURL)
		}
	}

	if n.Email.SMTPHost != "" {
		host, portStr, err := net.SplitHostPort(n.Email.SMTPHost)
		if err != nil || host == "" {
			return fmt.Errorf("notify.email.smtp_host must be host:port, got %q", n.Email.SMTPHost)
		}
		if port, err := strconv.Atoi(portStr); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("notify.email.smtp_host: bad port %q", portStr)
		}
		if n.Email.From == "" {
			return fmt.Errorf("notify.email.from is required when smtp_host is set")
		}
		if len(n.Email.To) == 0 {
			return fmt.Errorf("notify.email.to needs at least one recipient when smtp_host is set")
		}
		for i, rcpt := range n.Email.To {
			if rcpt == "" {
				return fmt.Errorf("notify.email.to[%d] is empty", i)
			}
		}
	}

	if n.Exec.Command != "" {
		if !filepath.IsAbs(n.Exec.Command) {
			return fmt.Errorf("notify.exec.command must be an absolute path, got %q", n.Exec.Command)
		}
		// Fail at config load, not at the first attack: a typo'd hook
		// path discovered mid-incident means silently lost notifications.
		fi, err := os.Stat(n.Exec.Command)
		if err != nil {
			return fmt.Errorf("notify.exec.command: %w", err)
		}
		if fi.IsDir() || fi.Mode()&0o111 == 0 {
			return fmt.Errorf("notify.exec.command %q is not an executable file", n.Exec.Command)
		}
	}
	if n.Exec.TimeoutSeconds == 0 {
		n.Exec.TimeoutSeconds = 10
	}
	if n.Exec.TimeoutSeconds < 1 || n.Exec.TimeoutSeconds > 300 {
		return fmt.Errorf("notify.exec.timeout_seconds must be in 1..300, got %d", n.Exec.TimeoutSeconds)
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

// isLoopbackHost reports whether host names the local machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
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
	if next.SampleCfg != prev.SampleCfg {
		return nil, fmt.Errorf("reload: samples settings cannot change at runtime (restart required)")
	}
	if next.StorageCfg != prev.StorageCfg {
		return nil, fmt.Errorf("reload: storage settings cannot change at runtime (restart required)")
	}
	s.cur.Store(next)
	return next, nil
}
