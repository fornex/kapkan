package config

// The scrub-node role's OWN configuration file (`kapkan scrub -config
// scrub.yaml`). One file per role, per the data-plane spec: a scrub node has
// no detection engine, no BGP and no listeners — it pulls the active rule
// table from the brain over the API and enforces it in its local XDP data
// plane — so its config is three things and nothing else: how to reach the
// brain, the local dataplane block (the SAME block kapkan.yaml carries, same
// keys, same validator), and the role-wide dry-run flag.
//
// This file follows the house wasm discipline like the rest of the package:
// no filesystem probes beyond reading the file, no netlink, no
// internal/dataplane import.

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScrubConfig is the parsed scrub.yaml.
type ScrubConfig struct {
	// DryRun is the NODE-side watch-only flag, written into the local
	// datapath's kapkan_cfg: rules are installed and counters move, but every
	// drop is rewritten into a pass. A POINTER because the default for any
	// remote role is TRUE — a box that starts enforcing because a key was
	// forgotten is the exact accident the default exists to prevent — and a
	// plain bool could not tell "absent" from an explicit false.
	DryRun *bool `yaml:"dry_run"`
	// Controller is the brain this node serves.
	Controller Controller `yaml:"controller"`
	// Dataplane is the local XDP filter: interfaces, static policy, limits —
	// the same block, keys and defaults as kapkan.yaml's. Required: a scrub
	// node without a data plane has no way to do its one job.
	Dataplane *Dataplane `yaml:"dataplane"`

	// DataplaneCfg is the resolved comparable form, populated by validation.
	DataplaneCfg DataplaneSettings `yaml:"-"`
}

// Controller is how the node reaches the brain and who it claims to be.
type Controller struct {
	// URL is the brain's API base, e.g. "https://kapkan.example.net:8443".
	URL string `yaml:"url"`
	// TokenEnv names the environment variable holding the agent token.
	// REQUIRED: the rules poll's ?node= identity — this node's liveness
	// signal — is refused without a real credential, so a token-less scrub
	// node would enforce correctly and still be counted dead.
	TokenEnv string `yaml:"token_env"`
	// Name is the identity presented on every poll; it must match a
	// scrubbing.nodes[] entry on the brain, or every poll is a loud 404.
	Name string `yaml:"name"`
	// ReportIntervalSeconds is how often the node posts its advisory
	// self-report; 0 (default) resolves to 10.
	ReportIntervalSeconds int `yaml:"report_interval_seconds"`
}

// DryRunResolved is the node's effective watch-only flag: absent means TRUE.
func (s *ScrubConfig) DryRunResolved() bool { return s.DryRun == nil || *s.DryRun }

// LoadScrub reads, parses and validates a scrub.yaml.
func LoadScrub(path string) (*ScrubConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scrub config: %w", err)
	}
	return ParseScrub(raw)
}

// ParseScrub parses and validates raw scrub.yaml bytes. KnownFields is on,
// like the daemon config's Parse: a typo'd key is a rejection, not a silently
// ignored intention.
func ParseScrub(raw []byte) (*ScrubConfig, error) {
	sc := &ScrubConfig{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(sc); err != nil {
		return nil, fmt.Errorf("parse scrub config: %w", err)
	}
	if err := sc.validate(); err != nil {
		return nil, fmt.Errorf("validate scrub config: %w", err)
	}
	return sc, nil
}

func (s *ScrubConfig) validate() error {
	c := &s.Controller
	if c.URL == "" {
		return fmt.Errorf("controller.url is required (the brain's API base, e.g. https://kapkan.example.net:8443)")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("controller.url must be an http(s) URL with a host, got %q", c.URL)
	}
	if u.Path != "" && u.Path != "/" {
		// The agent appends /api/v1/... itself; a path here would silently
		// double up. Refused rather than trimmed so the file says what runs.
		return fmt.Errorf("controller.url must not carry a path, got %q", c.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		// Same reasoning as the path: the agent composes the query itself, and
		// a stray "?x=1" would produce a garbage URL with a misleading 404.
		return fmt.Errorf("controller.url must not carry a query or fragment, got %q", c.URL)
	}
	if u.User != nil {
		// Never sent (the bearer is the credential), but it would be echoed
		// by every startup log line.
		return fmt.Errorf("controller.url must not carry credentials (the token comes from %s)", c.TokenEnv)
	}
	if !envNameRe.MatchString(c.TokenEnv) {
		return fmt.Errorf("controller.token_env %q is not a valid environment variable name (required: the poll identity needs a credential)", c.TokenEnv)
	}
	if !groupNameRe.MatchString(c.Name) {
		return fmt.Errorf("controller.name %q must match %s (it must equal a scrubbing.nodes[] name on the brain)", c.Name, groupNameRe)
	}
	if c.ReportIntervalSeconds == 0 {
		c.ReportIntervalSeconds = 10
	}
	if c.ReportIntervalSeconds < 1 {
		return fmt.Errorf("controller.report_interval_seconds must be > 0, got %d", c.ReportIntervalSeconds)
	}

	if s.Dataplane == nil {
		return fmt.Errorf("dataplane block is required: a scrub node's one job is enforcing in its local XDP data plane")
	}
	set, err := validateDataplaneBlock(s.Dataplane)
	if err != nil {
		return err
	}
	if !set.Enabled {
		return fmt.Errorf("dataplane.enabled must not be false on a scrub node (remove the block's enabled key, or do not run this role)")
	}
	// The fingerprint plane has no reader on the scrub role — only the main
	// daemon (kapkan) constructs it. Accepting it here would arm the kernel copy
	// path (paying the sampling cost, filling and dropping the ring) with nothing
	// draining it or enforcing a JA4 block: a silent no-op, exactly the "a plane
	// that does not run" hazard. Fail closed until a scrub-side reader exists.
	if s.Dataplane.Fingerprint.Enabled {
		return fmt.Errorf("dataplane.fingerprint is not supported on the scrub role: " +
			"the JA4 reader runs only in the main kapkan daemon, so enabling it here would " +
			"copy handshakes in the kernel with nothing to classify or block them")
	}
	s.DataplaneCfg = set
	return nil
}
