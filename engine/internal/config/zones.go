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
// standard library and yaml — plus internal/edge/edgedoc, the standard-library-
// only leaf that owns the policy vocabulary the brain and the node share. A
// path in a zone (extra_directives_file) is checked
// for SHAPE here and for existence on the node that renders it — the brain may
// not even have that file.
//
// E3 scope is deliberately narrow: h3 is refused (E5), and challenge modes are
// refused (E4). Both are keys already, so a file written for E3 keeps parsing
// unchanged when those milestones land — they only widen the accepted values.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
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
	// Fallback is the directory a node turns to after repeated failures with
	// the primary — the answer to Let's Encrypt's duplicate-certificate
	// ceiling on a fleet (edge-spec §3, §9). Empty means the node default
	// fallback, which may be none. A success from either directory clears
	// the failure state, so the following renewal tries the primary first.
	// A CA that requires an External Account Binding (ZeroSSL, Google Trust
	// Services) needs its kid and HMAC key in the NODE's configuration — the
	// zones file carries no secrets — or it refuses the account.
	Fallback string `yaml:"fallback"`
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
	// Challenge is the proof-of-work rung (E4): "off" (default), "manual"
	// (every request without a valid clearance is challenged) or "auto" (a
	// source or the whole zone is challenged when the node's rollups or the
	// brain say so). Watch-only by default — see ChallengeOptions.DryRun.
	Challenge string `yaml:"challenge"`
	// ChallengeOptions tunes the rung.
	ChallengeOptions ZoneChallengeOptions `yaml:"challenge_options"`
	// Rate is the per-source ceiling the decision service enforces.
	Rate ZoneRate `yaml:"rate"`
}

// ZoneChallengeOptions tunes the proof-of-work rung of one zone.
type ZoneChallengeOptions struct {
	// DryRun keeps the rung watch-only: a challenge is answered as an allow
	// marked would-challenge:<why>, so an operator sees who WOULD have been
	// challenged. Default TRUE — a zone cannot challenge anyone until this is
	// written false, whatever policy.challenge says.
	DryRun *bool `yaml:"dry_run"`
	// ExemptPaths are request-path prefixes the rung never challenges (health
	// checks, API clients, webhooks): absolute paths, matched as prefixes of
	// the request path without its query.
	ExemptPaths []string `yaml:"exempt_paths"`
}

// ZoneRate is a per-source ceiling; 0 leaves that dimension unlimited.
type ZoneRate struct {
	RPS         uint64 `yaml:"rps"`
	Concurrency uint64 `yaml:"concurrency"`
}

// Zone policy vocabulary. ONE definition, owned by the wire-contract package
// the node's renderer also imports, so the file, the API document and the node
// cannot drift on a string.
const (
	ZonePolicyDecide = edgedoc.ModeDecide
	ZonePolicyNone   = edgedoc.ModeNone

	ZoneFailOpen   = edgedoc.FailOpen
	ZoneFailClosed = edgedoc.FailClosed

	ZoneChallengeOff    = edgedoc.ChallengeOff
	ZoneChallengeManual = edgedoc.ChallengeManual
	ZoneChallengeAuto   = edgedoc.ChallengeAuto

	ZoneTLS12 = edgedoc.TLS12
	ZoneTLS13 = edgedoc.TLS13
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
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse zones: %w", err)
		}
		// An empty or comment-only file is the documented "nothing to serve
		// yet" state, not an error; yaml.v3 reports it as io.EOF.
		*z = Zones{}
	} else if err := dec.Decode(&yaml.Node{}); err == nil {
		// Exactly one YAML document: a trailing `---` document would otherwise
		// be discarded silently, taking its zones with it.
		return nil, fmt.Errorf("parse zones: the file must contain exactly one YAML document (remove the trailing --- document)")
	} else if !errors.Is(err, io.EOF) {
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
	// Origins are stored in their CANONICAL spelling (see canonicalHostPort), so
	// two spellings of one upstream cannot slip past the duplicate check and the
	// renderer never sees a form the terminator rejects. File order is kept.
	seenOrigin := make(map[string]struct{}, len(zone.Origins))
	for i, o := range zone.Origins {
		c, err := canonicalHostPort(o)
		if err != nil {
			return fmt.Errorf("%s: origins[%d]: %w", zone.Name, i, err)
		}
		if _, dup := seenOrigin[c]; dup {
			return fmt.Errorf("%s: origins[%d]: duplicate origin %q", zone.Name, i, o)
		}
		seenOrigin[c] = struct{}{}
		zone.Origins[i] = c
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

	for _, d := range []struct{ key, url string }{{"acme.directory", zone.ACME.Directory}, {"acme.fallback", zone.ACME.Fallback}} {
		if d.url == "" {
			continue
		}
		u, err := url.Parse(d.url)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("%s: %s must be an http(s) URL with a host, got %q", zone.Name, d.key, d.url)
		}
	}
	if zone.ACME.Fallback != "" && zone.ACME.Fallback == zone.ACME.Directory {
		return fmt.Errorf("%s: acme.fallback must name a different directory than acme.directory", zone.Name)
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
	case ZoneChallengeOff, ZoneChallengeManual, ZoneChallengeAuto:
	default:
		return fmt.Errorf("%s: policy.challenge must be %q, %q or %q, got %q", zone.Name, ZoneChallengeOff, ZoneChallengeManual, ZoneChallengeAuto, p.Challenge)
	}
	if p.ChallengeOptions.DryRun == nil {
		// Watch-only until an operator writes false: the rung must show who it
		// would challenge before it challenges anyone (edge-spec §5).
		dry := true
		p.ChallengeOptions.DryRun = &dry
	}
	if n := len(p.ChallengeOptions.ExemptPaths); n > maxExemptPaths {
		return fmt.Errorf("%s: policy.challenge_options.exempt_paths has %d entries; at most %d are accepted", zone.Name, n, maxExemptPaths)
	}
	for i, ep := range p.ChallengeOptions.ExemptPaths {
		if ep == "" || ep[0] != '/' {
			return fmt.Errorf("%s: policy.challenge_options.exempt_paths[%d] %q must be an absolute path prefix", zone.Name, i, ep)
		}
		if len(ep) > maxExemptPathLen {
			return fmt.Errorf("%s: policy.challenge_options.exempt_paths[%d] is %d bytes; at most %d are accepted", zone.Name, i, len(ep), maxExemptPathLen)
		}
		if strings.ContainsAny(ep, "?# \t") || strings.ContainsFunc(ep, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("%s: policy.challenge_options.exempt_paths[%d] %q must be a path prefix: no query, fragment, spaces or control characters", zone.Name, i, ep)
		}
	}

	if len(zone.Name) > maxZoneNameLen {
		// The name becomes a file name on the node (kapkan_zone_<name>.conf,
		// within NAME_MAX); DNS allows 253, nothing real is longer than this.
		return fmt.Errorf("%s: name is %d characters; at most %d are accepted", zone.Name, len(zone.Name), maxZoneNameLen)
	}
	if f := zone.ExtraDirectivesFile; f != "" {
		if !filepath.IsAbs(f) {
			// Absolute so the file means the same thing on every node and in
			// every review; existence is the node's business (see the field doc).
			return fmt.Errorf("%s: extra_directives_file must be an absolute path, got %q", zone.Name, f)
		}
		// The path is interpolated into an nginx `include`. A character that
		// ends or comments out the directive is a config injection; a glob
		// metacharacter turns the include into a pattern, and a pattern that
		// matches nothing passes `nginx -t` — voiding the one guard the escape
		// hatch has. Refused here so a renderer never sees either.
		if strings.ContainsAny(f, " \t\r\n;{}#\"'\\$*?[]") {
			return fmt.Errorf("%s: extra_directives_file %q contains a character nginx would misread (whitespace, ; { } # quotes \\ $ or a glob metacharacter)", zone.Name, f)
		}
	}
	return nil
}

// maxZoneNameLen bounds a zone name so that the node's per-zone file name
// (kapkan_zone_<name>.conf) stays within NAME_MAX. Mirrored by the renderer.
const maxZoneNameLen = 238

// Bounds on the rung's exempt-path list: the decision service compares every
// challenged request's path against each prefix.
const (
	maxExemptPaths   = 64
	maxExemptPathLen = 256
)

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
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !hostnameLabelRe.MatchString(label) {
			return "", fmt.Errorf("%q is not a valid hostname (label %q must be 1-63 of [a-z0-9-], not starting or ending with '-')", s, label)
		}
	}
	// RFC 3696 §2: the top-level label must not be all digits — such a name is
	// not a DNS hostname and no CA will issue for it.
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "", fmt.Errorf("%q: the top-level label must not be all digits", s)
	}
	return name, nil
}

// canonicalHostPort validates an origin of the form host:port (or [v6]:port)
// and returns its canonical spelling: a lowercase hostname or the IP's canonical
// text (an IPv6 literal re-bracketed), and the port in plain decimal. Two
// spellings of one upstream therefore compare equal, and the terminator config
// never sees a form nginx rejects (a signed or zero-padded port, a bracketed
// hostname). The host is an IP or a hostname; the port is 1..65535, unsigned,
// with no leading zero.
func canonicalHostPort(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("%q must be host:port", s)
	}
	if host == "" {
		return "", fmt.Errorf("%q: host is required", s)
	}
	bracketed := strings.HasPrefix(s, "[")
	var chost string
	switch ip := net.ParseIP(host); {
	case ip != nil && ip.To4() == nil:
		// An IPv6 literal is only a valid host:port when bracketed (an
		// unbracketed one never survives SplitHostPort), and nginx wants the
		// brackets too.
		if !bracketed {
			return "", fmt.Errorf("%q: an IPv6 origin must be written [addr]:port", s)
		}
		chost = "[" + ip.String() + "]"
	case ip != nil:
		if bracketed {
			return "", fmt.Errorf("%q: brackets are only for IPv6 addresses", s)
		}
		chost = ip.String()
	default:
		if bracketed {
			return "", fmt.Errorf("%q: brackets are only for IPv6 addresses, not hostnames", s)
		}
		h, err := normalizeHostname(host)
		if err != nil {
			return "", fmt.Errorf("%q: host is neither an IP nor a valid hostname", s)
		}
		chost = h
	}
	if len(port) > 1 && port[0] == '0' {
		return "", fmt.Errorf("%q: port must not have a leading zero", s)
	}
	n, err := strconv.ParseUint(port, 10, 16) // rejects a sign as well as a range overflow
	if err != nil || n < 1 {
		return "", fmt.Errorf("%q: port must be 1..65535", s)
	}
	return chost + ":" + strconv.FormatUint(n, 10), nil
}
