package config

// The edge node's own configuration file (edge.yaml; milestone E3.5). Like
// scrub.yaml it is a separate file for a separate role: a box that runs
// `kapkan edge` is not the brain, must not read kapkan.yaml by accident, and
// carries exactly what the role needs — where the brain is, who this node
// is, where its state and sockets live, how to drive the terminator, and
// which CA to ask. Zones themselves never appear here: they arrive from the
// brain as the document and are cached on disk by the role.

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
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
	// default /var/lib/kapkan/edge.
	StateDir string `yaml:"state_dir"`
	// SocketsDir holds the decision, challenge and log sockets nginx talks
	// to. Absolute; default /run/kapkan.
	SocketsDir string `yaml:"sockets_dir"`
	// SocketGroup is the terminator's worker group (nginx, www-data, angie):
	// the decision and log sockets are 0660 and chowned to it. Empty leaves
	// the sockets owner-only — fine only when kapkan and the terminator run
	// as one user.
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
	// Disabled turns issuance off (a lab with its own certificates).
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

// ResolveEAB reads every binding's HMAC key from its environment variable and
// returns them keyed by directory URL. A missing variable is an error: a node
// that silently registered without the binding would fail at the CA later,
// with a worse message.
func (a *EdgeACME) ResolveEAB() (map[string]EdgeEABCredentials, error) {
	if len(a.EAB) == 0 {
		return nil, nil
	}
	out := make(map[string]EdgeEABCredentials, len(a.EAB))
	for _, b := range a.EAB {
		key := os.Getenv(b.HMACKeyEnv)
		if key == "" {
			return nil, fmt.Errorf("acme.eab for %s: environment variable %s is empty or unset", b.Directory, b.HMACKeyEnv)
		}
		out[b.Directory] = EdgeEABCredentials{KID: b.KID, HMACKey: strings.TrimSpace(key)}
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
		e.StateDir = "/var/lib/kapkan/edge"
	}
	if e.SocketsDir == "" {
		e.SocketsDir = "/run/kapkan"
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
	if e.ACME.Fallback != "" && e.ACME.Fallback == e.ACME.Directory {
		return fmt.Errorf("acme.fallback must name a different directory than acme.directory")
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
	return nil
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
