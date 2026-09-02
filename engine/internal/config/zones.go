package config

// The edge track's ZONE model (edge-spec §4; milestone E3.1). A zone is one
// served hostname: where its origins are, its TLS policy, its ACME directory,
// and the per-request policy the edge node's decision service enforces. Zones
// are TENANT DATA and live in their own file — `edge.zones_file` in kapkan.yaml
// points at it — so a tenant's zone edit never touches the operator's daemon
// configuration, and the two files can be owned and reviewed by different
// people.
//
// This file follows the house wasm discipline like the rest of the package: no
// filesystem probes beyond reading the file (ParseZones is pure and is what the
// browser-side validator will compile), no netlink, no imports outside the
// standard library and yaml. A path in a zone (extra_directives_file) is checked
// for SHAPE here and for existence on the node that renders it — the brain may
// not even have that file.
//
// E3 scope is deliberately narrow: h3 is refused (E5), and challenge modes are
// refused (E4). Both are keys already, so a file written for E3 keeps parsing
// unchanged when those milestones land — they only widen the accepted values.

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Zones is the parsed zones.yaml.
type Zones struct {
	// Zones lists every served hostname. An empty list is legal — an edge
	// with nothing to serve yet — and the brain then serves an empty document.
	Zones []Zone `yaml:"zones"`
}

// Zone is one served hostname and everything the edge needs to serve it.
type Zone struct {
	// Name is the hostname clients connect to: an explicit lowercase DNS name
	// (RFC 1123 labels), no wildcards, no trailing dot. It is also the
	// certificate's subject and the zone's identity in every API and report,
	// so it is normalised to lowercase and must be unique within the file.
	Name string `yaml:"name"`
	// Origins are the upstreams the terminator proxies to, as host:port, at
	// least one. The edge never forwards client bytes itself (edge-spec §0):
	// these are rendered into the terminator's upstream block.
	Origins []string `yaml:"origins"`
	// TLS is the zone's transport policy.
	TLS ZoneTLS `yaml:"tls"`
	// ACME selects where this zone's certificates are issued.
	ACME ZoneACME `yaml:"acme"`
	// Policy is what the node's local decision service does per request.
	Policy ZonePolicy `yaml:"policy"`
	// ExtraDirectivesFile is the one escape hatch (edge-spec §4): an absolute
	// path, on the NODE, to a file of extra nginx directives included verbatim
	// into the zone's server block. Shape-checked here; existence and syntax are
	// the renderer's `nginx -t` gate. There is no template override.
	ExtraDirectivesFile string `yaml:"extra_directives_file"`
}

// ZoneTLS is a zone's TLS policy.
type ZoneTLS struct {
	// MinVersion is the lowest TLS version offered: "1.2" (default) or "1.3".
	MinVersion string `yaml:"min_version"`
	// H3 enables HTTP/3 for the zone. NOT YET SUPPORTED: QUIC/HTTP3 in earnest
	// is milestone E5, so E3 refuses true rather than silently ignoring it.
	H3 bool `yaml:"h3"`
}

// ZoneACME selects the zone's certificate authority.
type ZoneACME struct {
	// Directory overrides the node's default ACME directory URL for this zone
	// (e.g. a staging or private CA). Empty means the node default.
	Directory string `yaml:"directory"`
}

// ZonePolicy is the per-request policy the edge node enforces locally
// (edge-spec §5): no verdict ever comes from the brain.
type ZonePolicy struct {
	// Mode is "decide" (default — every request is checked by the node's
	// decision service through auth_request) or "none" (the zone opts out and
	// the subrequest is not even rendered).
	Mode string `yaml:"mode"`
	// FailureMode is what a request gets when the decision service itself is
	// unreachable: "open" (default — pass, the edge fails open like every other
	// kapkan layer) or "closed" (refuse).
	FailureMode string `yaml:"failure_mode"`
	// Challenge is the client-challenge rung. NOT YET SUPPORTED: challenges are
	// milestone E4, so E3 accepts only "off" (the default).
	Challenge string `yaml:"challenge"`
	// Rate is the per-source ceiling the decision service enforces.
	Rate ZoneRate `yaml:"rate"`
}

// ZoneRate is a per-source ceiling; 0 leaves that dimension unlimited.
type ZoneRate struct {
	RPS         uint64 `yaml:"rps"`
	Concurrency uint64 `yaml:"concurrency"`
}

// Zone policy vocabulary. Exported so the API document and the node agree on
// the exact strings without a second definition.
const (
	ZonePolicyDecide = "decide"
	ZonePolicyNone   = "none"

	ZoneFailOpen   = "open"
	ZoneFailClosed = "closed"

	ZoneChallengeOff = "off"

	ZoneTLS12 = "1.2"
	ZoneTLS13 = "1.3"
)

// hostnameLabelRe is one RFC 1123 label: 1-63 chars of [a-z0-9-], not starting
// or ending with '-'. Uppercase is normalised away before matching.
var hostnameLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// LoadZones reads, parses and validates a zones.yaml.
func LoadZones(path string) (*Zones, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read zones file: %w", err)
	}
	return ParseZones(raw)
}

// ParseZones parses and validates raw zones.yaml bytes. KnownFields is on, like
// the daemon config's Parse: a typo'd key is a rejection, not a silently
// ignored intention. Zone names are normalised to lowercase.
func ParseZones(raw []byte) (*Zones, error) {
	z := &Zones{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(z); err != nil {
		return nil, fmt.Errorf("parse zones: %w", err)
	}
	if err := z.validate(); err != nil {
		return nil, fmt.Errorf("validate zones: %w", err)
	}
	return z, nil
}

func (z *Zones) validate() error {
	seen := make(map[string]int, len(z.Zones))
	for i := range z.Zones {
		zone := &z.Zones[i]
		if err := zone.validate(); err != nil {
			return fmt.Errorf("zones[%d]: %w", i, err)
		}
		if j, dup := seen[zone.Name]; dup {
			return fmt.Errorf("zones[%d]: duplicate zone %q (also zones[%d])", i, zone.Name, j)
		}
		seen[zone.Name] = i
	}
	return nil
}

func (zone *Zone) validate() error {
	name, err := normalizeHostname(zone.Name)
	if err != nil {
		return fmt.Errorf("name: %w", err)
	}
	zone.Name = name

	if len(zone.Origins) == 0 {
		return fmt.Errorf("%s: origins: at least one host:port upstream is required", zone.Name)
	}
	seenOrigin := make(map[string]struct{}, len(zone.Origins))
	for i, o := range zone.Origins {
		if err := validateHostPort(o); err != nil {
			return fmt.Errorf("%s: origins[%d]: %w", zone.Name, i, err)
		}
		if _, dup := seenOrigin[o]; dup {
			return fmt.Errorf("%s: origins[%d]: duplicate origin %q", zone.Name, i, o)
		}
		seenOrigin[o] = struct{}{}
	}

	switch zone.TLS.MinVersion {
	case "":
		zone.TLS.MinVersion = ZoneTLS12
	case ZoneTLS12, ZoneTLS13:
	default:
		return fmt.Errorf("%s: tls.min_version must be %q or %q, got %q", zone.Name, ZoneTLS12, ZoneTLS13, zone.TLS.MinVersion)
	}
	if zone.TLS.H3 {
		return fmt.Errorf("%s: tls.h3 is not supported yet (HTTP/3 is a later milestone); remove the key or set false", zone.Name)
	}

	if d := zone.ACME.Directory; d != "" {
		u, err := url.Parse(d)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("%s: acme.directory must be an http(s) URL with a host, got %q", zone.Name, d)
		}
	}

	p := &zone.Policy
	switch p.Mode {
	case "":
		p.Mode = ZonePolicyDecide
	case ZonePolicyDecide, ZonePolicyNone:
	default:
		return fmt.Errorf("%s: policy.mode must be %q or %q, got %q", zone.Name, ZonePolicyDecide, ZonePolicyNone, p.Mode)
	}
	switch p.FailureMode {
	case "":
		p.FailureMode = ZoneFailOpen
	case ZoneFailOpen, ZoneFailClosed:
	default:
		return fmt.Errorf("%s: policy.failure_mode must be %q or %q, got %q", zone.Name, ZoneFailOpen, ZoneFailClosed, p.FailureMode)
	}
	switch p.Challenge {
	case "":
		p.Challenge = ZoneChallengeOff
	case ZoneChallengeOff:
	default:
		return fmt.Errorf("%s: policy.challenge %q is not supported yet (challenges are a later milestone); only %q is accepted", zone.Name, p.Challenge, ZoneChallengeOff)
	}

	if f := zone.ExtraDirectivesFile; f != "" && !filepath.IsAbs(f) {
		// Absolute so the file means the same thing on every node and in
		// every review; existence is the node's business (see the field doc).
		return fmt.Errorf("%s: extra_directives_file must be an absolute path, got %q", zone.Name, f)
	}
	return nil
}

// normalizeHostname lowercases and validates an explicit DNS hostname: RFC 1123
// labels joined by dots, at most 253 characters, no wildcard, no trailing dot,
// no IP address (a zone is a name a certificate is issued for).
func normalizeHostname(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("a hostname is required")
	}
	name := strings.ToLower(strings.TrimSpace(s))
	if strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("%q must not end with a dot", s)
	}
	if strings.Contains(name, "*") {
		return "", fmt.Errorf("%q: wildcards are not supported; list each name explicitly", s)
	}
	if len(name) > 253 {
		return "", fmt.Errorf("%q exceeds 253 characters", s)
	}
	if net.ParseIP(name) != nil {
		return "", fmt.Errorf("%q is an IP address, not a hostname", s)
	}
	for _, label := range strings.Split(name, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return "", fmt.Errorf("%q is not a valid hostname (label %q must be 1-63 of [a-z0-9-], not starting or ending with '-')", s, label)
		}
	}
	return name, nil
}

// validateHostPort accepts an origin of the form host:port (or [v6]:port): the
// host an IP or a hostname, the port 1..65535.
func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%q must be host:port", s)
	}
	if host == "" {
		return fmt.Errorf("%q: host is required", s)
	}
	if net.ParseIP(host) == nil {
		if _, err := normalizeHostname(host); err != nil {
			return fmt.Errorf("%q: host is neither an IP nor a valid hostname", s)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q: port must be 1..65535", s)
	}
	return nil
}
