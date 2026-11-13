package config

// The edge node's own configuration file (edge.yaml; milestone E3.5). Like
// scrub.yaml it is a separate file for a separate role: a box that runs
// `kapkan edge` is not the brain, must not read kapkan.yaml by accident, and
// carries exactly what the role needs — where the brain is, who this node
// is, where its state and sockets live, how to drive the terminator, and
// which CA to ask. Zones themselves never appear here: they arrive from the
// brain as the document and are cached on disk by the role.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// Default locations of the edge role's own directories — its own, not the
// brain's /var/lib/kapkan and /run/kapkan: systemd re-chowns a shared
// StateDirectory to each unit's user on every start and removes a shared
// RuntimeDirectory on stop, so a brain and an edge on one host must not
// share them.
const (
	DefaultEdgeStateDir   = "/var/lib/kapkan-edge"
	DefaultEdgeSocketsDir = "/run/kapkan-edge"
)

// EdgeNodeConfig is the parsed edge.yaml.
type EdgeNodeConfig struct {
	// DryRun is the NODE-side watch-only flag: decisions are counted and
	// marked, none enforced. A POINTER because the default for any remote
	// role is TRUE — a box that starts refusing requests because a key was
	// forgotten is the accident the default exists to prevent — and a plain
	// bool could not tell "absent" from an explicit false.
	DryRun *bool `yaml:"dry_run"`
	// Controller is the brain this node serves; name must equal an
	// edge.nodes[] entry there.
	Controller Controller `yaml:"controller"`
	// StateDir holds the cached document, the rendered generations, the ACME
	// account keys and certificates (0600) and the empty root. Absolute;
	// default /var/lib/kapkan-edge.
	StateDir string `yaml:"state_dir"`
	// SocketsDir holds the decision, challenge and log sockets nginx talks
	// to. Absolute; default /run/kapkan-edge.
	SocketsDir string `yaml:"sockets_dir"`
	// SocketGroup is the terminator's worker group (nginx, www-data, angie):
	// the decision and log sockets are 0660 and chowned to it; the challenge
	// socket answers public tokens and is 0666. Empty leaves the two
	// group-restricted sockets owner-only — fine only when kapkan and the
	// terminator run as one user.
	SocketGroup string `yaml:"socket_group"`
	// Terminator is how the node drives nginx or Angie.
	Terminator EdgeTerminator `yaml:"terminator"`
	// ACME is the node's default CA configuration; a zone's own acme block
	// overrides directory and fallback.
	ACME EdgeACME `yaml:"acme"`
	// StatusListen serves /healthz and /metrics for this node when set, e.g.
	// "127.0.0.1:9102". Unauthenticated: keep it on loopback or a private
	// address.
	StatusListen string `yaml:"status_listen"`
	// OmitCatchAll drops kapkan's default servers on :80/:443, for an
	// nginx.conf that declares its own. DisableIPv6 drops the [::] listeners.
	OmitCatchAll bool `yaml:"omit_catch_all"`
	DisableIPv6  bool `yaml:"disable_ipv6"`
	// QUIC is the node's HTTP/3 switch (edge-spec §8, E5).
	QUIC EdgeQUIC `yaml:"quic"`
	// Steering is the node's testimony about itself: should this box carry
	// each address in vips (edge-spec §8, E7.2)? Off unless enabled.
	Steering EdgeSteering `yaml:"steering"`
}

// EdgeQUIC is the node-level HTTP/3 configuration. Whether a ZONE speaks
// HTTP/3 is the zones file's tls.h3; this block says whether THIS box may
// render it at all.
type EdgeQUIC struct {
	// H3 is auto (default: render QUIC for zones that ask, when the binary
	// was built with --with-http_v3_module) or off (never render QUIC on this
	// node — the switch for a build whose HTTP/3 the operator does not trust,
	// e.g. one the probe flags with an advisory). Zones asking for h3 are
	// served over TCP here and the node's report says so.
	H3 string `yaml:"h3"`
	// Retry is nginx's quic_retry, node-wide (nginx decides it from the
	// address's default server, before SNI names a zone): absent or true makes
	// every new client address prove it can receive before the handshake costs
	// the node anything — the anti-amplification stance; false turns it off
	// and saves the round trip. A change is a new tested generation.
	Retry *bool `yaml:"retry"`
	// OmitAnchor drops kapkan's QUIC anchor under omit_catch_all — for an
	// nginx.conf whose own default server already listens `443 quic
	// reuseport` (a second reuseport on the address fails `nginx -t`).
	OmitAnchor bool `yaml:"omit_anchor"`
}

// RetryResolved is the effective quic_retry: absent means on.
func (q EdgeQUIC) RetryResolved() bool { return q.Retry == nil || *q.Retry }

// Values of quic.h3.
const (
	EdgeH3Auto = "auto"
	EdgeH3Off  = "off"
)

// EdgeSteering is edge.yaml's steering block. A key left out (0) takes
// internal/edge/steer's default. The damping keys map one to one onto
// steer.Config, whose comments give each default and bound.
type EdgeSteering struct {
	Enabled         bool         `yaml:"enabled"`
	IntervalSeconds int          `yaml:"interval_seconds"`
	FailAfter       int          `yaml:"fail_after"`
	FailWindow      int          `yaml:"fail_window"`
	RecoverAfter    int          `yaml:"recover_after"`
	HoldDown        EdgeHoldDown `yaml:"hold_down"`
	// VIPs are the addresses — never prefixes — the operator's speaker
	// announces from this node; empty means one verdict for the node itself.
	VIPs []string `yaml:"vips"`
	// VIPAddrs is VIPs as validate parsed them: unmapped, in file order.
	VIPAddrs []netip.Addr `yaml:"-"`
}

// EdgeHoldDown is steering.hold_down.
type EdgeHoldDown struct {
	MinSeconds int `yaml:"min_seconds"`
	MaxSeconds int `yaml:"max_seconds"`
}

// MaxSteeringVIPs bounds steering.vips: each is a probe per tick and a
// metric series.
const MaxSteeringVIPs = 64

// SteerConfig is the block as the automaton takes it: steer.DefaultConfig()
// with every key the file sets (> 0) in place of its default, so every field
// is explicit (LevelReset stays steer's default).
func (s EdgeSteering) SteerConfig() steer.Config {
	c := steer.DefaultConfig()
	if s.IntervalSeconds > 0 {
		c.Interval = steerSeconds(s.IntervalSeconds)
	}
	if s.FailAfter > 0 {
		c.FailAfter = s.FailAfter
	}
	if s.FailWindow > 0 {
		c.FailWindow = s.FailWindow
	}
	if s.RecoverAfter > 0 {
		c.RecoverAfter = s.RecoverAfter
	}
	if s.HoldDown.MinSeconds > 0 {
		c.HoldDownMin = steerSeconds(s.HoldDown.MinSeconds)
	}
	if s.HoldDown.MaxSeconds > 0 {
		c.HoldDownMax = steerSeconds(s.HoldDown.MaxSeconds)
	}
	return c
}

// maxSteerSeconds bounds steering's *_seconds keys before they become
// durations. n×time.Second overflows int64 near 9.2e9 seconds and wraps to a
// negative, which steer reads as "use the default": a key that huge would
// pass for an absent one. A day is far past every bound steer enforces.
const maxSteerSeconds = 86400

// steerSeconds is n seconds, saturating where the product would wrap.
// validate refuses anything above maxSteerSeconds first; this keeps a caller
// that skips validate from turning a huge key into the default.
func steerSeconds(n int) time.Duration {
	if int64(n) > math.MaxInt64/int64(time.Second) {
		return math.MaxInt64
	}
	return time.Duration(n) * time.Second
}

// validateSteering checks the steering block whether or not it is enabled,
// so a block staged with enabled: false is already valid and turning it on
// changes nothing else. Only the last two rules bind an enabled block alone,
// so a node that sets omit_catch_all with steering off stays valid. It fills
// VIPAddrs. The first error returns.
func (e *EdgeNodeConfig) validateSteering() error {
	s := &e.Steering
	if len(s.VIPs) > MaxSteeringVIPs {
		return fmt.Errorf("steering.vips lists %d addresses; at most %d", len(s.VIPs), MaxSteeringVIPs)
	}
	s.VIPAddrs = nil
	// seen maps a target key to the spelling that first named it: two
	// spellings of one address are one target, with one drain file and one
	// verdict.
	seen := make(map[string]string, len(s.VIPs))
	for i, raw := range s.VIPs {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("steering.vips[%d] %q is not an address (a VIP is one address, never a prefix)", i, raw)
		}
		if a.Zone() != "" {
			return fmt.Errorf("steering.vips[%d] %q carries a zone; a VIP is a global address", i, raw)
		}
		a = a.Unmap()
		if !a.IsGlobalUnicast() {
			return fmt.Errorf("steering.vips[%d] %s is not a unicast address this box can carry (loopback, unspecified, multicast, link-local and broadcast are refused)", i, a)
		}
		// The key is the one the node and the Store use, so "listed twice"
		// here is exactly "one target" there.
		key := steer.VIPTarget(a).Key
		if first, dup := seen[key]; dup {
			return fmt.Errorf("steering.vips[%d] %s is listed twice (as %q and %q)", i, key, first, raw)
		}
		seen[key] = raw
		if a.Is6() && e.DisableIPv6 {
			return fmt.Errorf("steering.vips[%d] %s is IPv6 and disable_ipv6 is true: the node renders no [::]:443, so nothing could answer its probe", i, a)
		}
		s.VIPAddrs = append(s.VIPAddrs, a)
	}
	keys := []struct {
		name    string
		v       int
		seconds bool
	}{
		{"interval_seconds", s.IntervalSeconds, true},
		{"fail_after", s.FailAfter, false},
		{"fail_window", s.FailWindow, false},
		{"recover_after", s.RecoverAfter, false},
		{"hold_down.min_seconds", s.HoldDown.MinSeconds, true},
		{"hold_down.max_seconds", s.HoldDown.MaxSeconds, true},
	}
	// steer reads a negative as its default, so Validate would pass one; and
	// a huge count of seconds wraps to a negative on its way to a duration.
	for _, k := range keys {
		if k.v < 0 {
			return fmt.Errorf("steering.%s must not be negative (0 means the default), got %d", k.name, k.v)
		}
	}
	for _, k := range keys {
		if k.seconds && k.v > maxSteerSeconds {
			return fmt.Errorf("steering.%s %d is out of range", k.name, k.v)
		}
	}
	if err := s.SteerConfig().Validate(); err != nil {
		return fmt.Errorf("steering: %w", err)
	}
	if s.Enabled && e.StatusListen == "" {
		return errors.New("steering.enabled needs status_listen: GET /steer is served there (keep it on loopback)")
	}
	if s.Enabled && e.OmitCatchAll {
		return errors.New("steering.enabled refuses omit_catch_all: true in this release: without kapkan's catch-all, a document that leaves the node no zone with a certificate leaves :443 refusing on every node, and the document would withdraw the fleet")
	}
	return nil
}

// EdgeTerminator names the terminator and how to test and reload it.
type EdgeTerminator struct {
	// Binary is the executable ("nginx" default; "angie").
	Binary string `yaml:"binary"`
	// MainConf is passed as -c to test and reload; empty uses the binary's
	// compiled-in default. The file must include
	// <state_dir>/conf/live/*.conf inside http{}.
	MainConf string `yaml:"main_conf"`
	// Reload is exec (default: `<binary> -s reload`), signal (SIGHUP to the
	// pid in pid_file) or command (run `command`, e.g. systemctl reload nginx).
	Reload  string   `yaml:"reload"`
	PIDFile string   `yaml:"pid_file"`
	Command []string `yaml:"command"`
}

// EdgeACME is the node-level issuance configuration.
type EdgeACME struct {
	// Directory is the default CA (Let's Encrypt production when empty).
	Directory string `yaml:"directory"`
	// Fallback is the default fallback CA after repeated failures ("" none).
	Fallback string `yaml:"fallback"`
	// Contact is the account contact list, e.g. ["mailto:ops@example.com"].
	Contact []string `yaml:"contact"`
	// EAB lists External Account Binding credentials, one per CA directory
	// that requires them (ZeroSSL, Google Trust Services). The HMAC key is a
	// secret and comes from an environment variable, like the agent token;
	// a directory without an entry here registers with the account key alone.
	EAB []EdgeACMEEAB `yaml:"eab"`
	// Disabled issues nothing: zones stay on :80 answering 503 (a lab that
	// exercises everything but issuance). Operator-supplied certificates are
	// not a feature yet.
	Disabled bool `yaml:"disabled"`
}

// EdgeACMEEAB binds a CA directory to the external account it hands out.
type EdgeACMEEAB struct {
	// Directory is the CA directory URL the binding is for.
	Directory string `yaml:"directory"`
	// KID is the key identifier the CA issued.
	KID string `yaml:"kid"`
	// HMACKeyEnv names the environment variable holding the CA's
	// base64url-encoded HMAC key.
	HMACKeyEnv string `yaml:"hmac_key_env"`
}

// EdgeEABCredentials is a resolved binding: kid and the HMAC key itself.
type EdgeEABCredentials struct {
	KID     string
	HMACKey string
}

// ResolveEAB reads every binding's HMAC key from its environment variable,
// checks it is base64url (a CA portal's padded form is accepted and
// normalised) and returns the bindings keyed by directory URL. A missing or
// malformed key is an error: a node that silently registered without the
// binding would fail at the CA later, with a worse message.
func (a *EdgeACME) ResolveEAB() (map[string]EdgeEABCredentials, error) {
	if len(a.EAB) == 0 {
		return nil, nil
	}
	out := make(map[string]EdgeEABCredentials, len(a.EAB))
	for _, b := range a.EAB {
		key := strings.TrimRight(strings.TrimSpace(os.Getenv(b.HMACKeyEnv)), "=")
		if key == "" {
			return nil, fmt.Errorf("acme.eab for %s: environment variable %s is empty or unset", b.Directory, b.HMACKeyEnv)
		}
		if _, err := base64.RawURLEncoding.DecodeString(key); err != nil {
			return nil, fmt.Errorf("acme.eab for %s: %s is not a base64url HMAC key", b.Directory, b.HMACKeyEnv)
		}
		out[b.Directory] = EdgeEABCredentials{KID: b.KID, HMACKey: key}
	}
	return out, nil
}

// Reload methods.
const (
	EdgeReloadExec    = "exec"
	EdgeReloadSignal  = "signal"
	EdgeReloadCommand = "command"
)

// DryRunResolved is the node's effective watch-only flag: absent means TRUE.
func (e *EdgeNodeConfig) DryRunResolved() bool { return e.DryRun == nil || *e.DryRun }

// LoadEdgeNode reads, parses and validates an edge.yaml.
func LoadEdgeNode(path string) (*EdgeNodeConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read edge config: %w", err)
	}
	return ParseEdgeNode(raw)
}

// ParseEdgeNode parses and validates raw edge.yaml bytes. KnownFields is on:
// a typo'd key is a rejection, not a silently ignored intention.
func ParseEdgeNode(raw []byte) (*EdgeNodeConfig, error) {
	e := &EdgeNodeConfig{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(e); err != nil {
		return nil, fmt.Errorf("parse edge config: %w", err)
	}
	if err := e.validate(); err != nil {
		return nil, fmt.Errorf("validate edge config: %w", err)
	}
	return e, nil
}

func (e *EdgeNodeConfig) validate() error {
	if err := e.Controller.validate("edge.nodes[]"); err != nil {
		return err
	}
	if e.StateDir == "" {
		e.StateDir = DefaultEdgeStateDir
	}
	if e.SocketsDir == "" {
		e.SocketsDir = DefaultEdgeSocketsDir
	}
	for _, d := range []struct{ key, path string }{{"state_dir", e.StateDir}, {"sockets_dir", e.SocketsDir}} {
		if !filepath.IsAbs(d.path) || strings.ContainsAny(d.path, " \t\r\n;{}#\"'\\$*?[]") {
			return fmt.Errorf("%s must be an absolute path without characters nginx would misread, got %q", d.key, d.path)
		}
	}
	if e.SocketGroup != "" && !groupNameRe.MatchString(e.SocketGroup) {
		return fmt.Errorf("socket_group %q must match %s", e.SocketGroup, groupNameRe)
	}
	t := &e.Terminator
	if t.Binary == "" {
		t.Binary = "nginx"
	}
	if t.MainConf != "" && !filepath.IsAbs(t.MainConf) {
		return fmt.Errorf("terminator.main_conf must be an absolute path, got %q", t.MainConf)
	}
	switch t.Reload {
	case "":
		t.Reload = EdgeReloadExec
	case EdgeReloadExec:
	case EdgeReloadSignal:
		if !filepath.IsAbs(t.PIDFile) {
			return fmt.Errorf("terminator.reload signal needs terminator.pid_file (absolute), got %q", t.PIDFile)
		}
	case EdgeReloadCommand:
		if len(t.Command) == 0 {
			return fmt.Errorf("terminator.reload command needs terminator.command (an argv, e.g. [systemctl, reload, nginx])")
		}
	default:
		return fmt.Errorf("terminator.reload %q is not exec, signal or command", t.Reload)
	}
	for _, d := range []struct{ key, url string }{{"acme.directory", e.ACME.Directory}, {"acme.fallback", e.ACME.Fallback}} {
		if d.url == "" {
			continue
		}
		u, err := url.Parse(d.url)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("%s must be an http(s) URL with a host, got %q", d.key, d.url)
		}
	}
	// An empty acme.directory means Let's Encrypt production; a fallback
	// equal to the RESOLVED primary would alternate between two identical
	// CAs and never escape the duplicate-certificate ceiling it exists for.
	primary := e.ACME.Directory
	if primary == "" {
		primary = edgedoc.DefaultACMEDirectory
	}
	if e.ACME.Fallback != "" && e.ACME.Fallback == primary {
		return fmt.Errorf("acme.fallback must name a different directory than the primary (%s)", primary)
	}
	for _, c := range e.ACME.Contact {
		if !strings.HasPrefix(c, "mailto:") {
			return fmt.Errorf("acme.contact entries must be mailto: URLs, got %q", c)
		}
	}
	seenEAB := make(map[string]bool, len(e.ACME.EAB))
	for i, b := range e.ACME.EAB {
		u, err := url.Parse(b.Directory)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("acme.eab[%d].directory must be an http(s) URL with a host, got %q", i, b.Directory)
		}
		if seenEAB[b.Directory] {
			return fmt.Errorf("acme.eab[%d]: directory %s listed twice", i, b.Directory)
		}
		seenEAB[b.Directory] = true
		if strings.TrimSpace(b.KID) == "" {
			return fmt.Errorf("acme.eab[%d].kid is required", i)
		}
		if !envNameRe.MatchString(b.HMACKeyEnv) {
			return fmt.Errorf("acme.eab[%d].hmac_key_env %q is not a valid environment variable name (the HMAC key is a secret and never sits in the file)", i, b.HMACKeyEnv)
		}
	}
	if e.StatusListen != "" {
		if _, _, err := net.SplitHostPort(e.StatusListen); err != nil {
			return fmt.Errorf("status_listen must be host:port, got %q: %v", e.StatusListen, err)
		}
	}
	switch e.QUIC.H3 {
	case "":
		e.QUIC.H3 = EdgeH3Auto
	case EdgeH3Auto, EdgeH3Off:
	default:
		return fmt.Errorf("quic.h3 %q is not auto or off", e.QUIC.H3)
	}
	if e.QUIC.OmitAnchor && !e.OmitCatchAll {
		return errors.New("quic.omit_anchor only applies with omit_catch_all: true (kapkan's catch-all carries the QUIC listener otherwise)")
	}
	return e.validateSteering()
}

// validate checks the controller block; peer names the brain-side list the
// node's name must appear in, for the message.
func (c *Controller) validate(peer string) error {
	if c.URL == "" {
		return fmt.Errorf("controller.url is required (the brain's API base, e.g. https://kapkan.example.net:8443)")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("controller.url must be an http(s) URL with a host, got %q", c.URL)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("controller.url must not carry a path, got %q", c.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("controller.url must not carry a query or fragment, got %q", c.URL)
	}
	if u.User != nil {
		// Basic-auth userinfo is never sent (the bearer is the credential) but
		// it would be echoed by -check and every startup log line.
		return fmt.Errorf("controller.url must not carry credentials (the token comes from %s)", c.TokenEnv)
	}
	if !envNameRe.MatchString(c.TokenEnv) {
		return fmt.Errorf("controller.token_env %q is not a valid environment variable name (required: the poll identity needs a credential)", c.TokenEnv)
	}
	if !groupNameRe.MatchString(c.Name) {
		return fmt.Errorf("controller.name %q must match %s (it must equal an %s name on the brain)", c.Name, groupNameRe, peer)
	}
	if c.ReportIntervalSeconds == 0 {
		c.ReportIntervalSeconds = 10
	}
	if c.ReportIntervalSeconds < 1 {
		return fmt.Errorf("controller.report_interval_seconds must be > 0, got %d", c.ReportIntervalSeconds)
	}
	return nil
}
