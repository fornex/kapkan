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
// The keys were all present from E3; E4 widened the challenge modes and E5
// (E5.3) the tls.h3 switch, so a file written for an earlier milestone keeps
// parsing unchanged — the milestones only widen the accepted values.

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
	// Tenant is the zone's optional ownership label (E6.2), on the same axis
	// as a hostgroup's tenant: an API token scoped to it sees the zone in the
	// edge status and may pull its lever; a zone without a label is a house
	// zone, visible to unscoped tokens only. Ownership, not placement, and
	// never inherited — not from a placement group, not from kapkan.yaml's
	// top-level tenant — so an upgrade hands nothing to anyone. The label
	// never enters the document the nodes render: a labelled file yields the
	// bytes and ETag the unlabelled one did.
	Tenant string `yaml:"tenant"`
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
	// H3 serves the zone over HTTP/3 (QUIC) beside TLS-over-TCP (edge-spec §8,
	// E5) — on the nodes whose terminator carries the HTTP/3 module and whose
	// edge.yaml does not switch it off; elsewhere the zone stays on TCP and
	// the node's report says so. Default false. Turning it on or off is a new
	// tested generation on every node (a reload); nothing else about a zone is.
	H3 bool `yaml:"h3"`
	// H3Options tunes HTTP/3; refused without H3.
	H3Options ZoneH3Options `yaml:"h3_options"`
}

// ZoneH3Options is what a zone may tune about its HTTP/3. Both act after SNI
// has named the zone, which is why they are per zone — Retry, 0-RTT and the
// host key are node-wide by nginx's design and live in the node's edge.yaml.
type ZoneH3Options struct {
	// Advertise controls the Alt-Svc header on TLS-over-TCP responses: true
	// (default) announces h3; false renders the QUIC listener without
	// announcing it — the canary reachable only by clients that already speak
	// HTTP/3 to the name, since a transport has no watch-only mode.
	Advertise *bool `yaml:"advertise"`
	// AltSvcMaxAgeSeconds is Alt-Svc's ma — how long a client may remember the
	// alternative: 60..604800, default 86400. A short value is the rollout
	// step between the silent canary and the default.
	AltSvcMaxAgeSeconds int `yaml:"alt_svc_max_age_seconds"`
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
	// DryRun makes THIS zone watch-only: the node counts and marks its
	// decisions (would-deny:<reason>, would-challenge:<why>) and enforces
	// none, while its sibling zones enforce as before. The node's own dry_run
	// (edge.yaml) is the floor a zone cannot go below — a zone can only be
	// more watch-only than its node, never less. Default false: the zone
	// follows the node.
	DryRun bool `yaml:"dry_run"`
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
	// Difficulty is the puzzle's leading zero bits, 12..22 (default 18: a
	// fraction of a second natively, a few seconds in a browser Worker; each
	// step doubles the work). Pricing a clearance in CPU is the point — but a
	// slow phone must still finish inside the two-minute puzzle window.
	Difficulty int `yaml:"difficulty"`
	// CookieTTLSeconds is how long a solved puzzle's clearance lasts, 60..86400
	// (default 1800). A cleared client re-solves when it expires or when its
	// address (IPv6: /64) changes; the no-JS ticket's clearance is fixed at
	// five minutes.
	CookieTTLSeconds int `yaml:"cookie_ttl_seconds"`
	// Auto tunes policy.challenge: auto — when the node challenges on its own.
	Auto ZoneAutoChallenge `yaml:"auto"`
}

// ZoneAutoChallenge is the automatic rung's triggers. A flooding source in an
// auto zone is challenged before it is denied whatever these say; these add
// the zone-wide trigger.
type ZoneAutoChallenge struct {
	// ZoneRPS is the zone-wide ADMITTED request rate (per node) — decided
	// requests the node did not refuse — at which every source is challenged:
	// the residential-proxy flood, where no single source trips its ceiling.
	// Refused traffic is not load. 0 (default) = off.
	ZoneRPS uint64 `yaml:"zone_rps"`
	// HoldSeconds is how long the zone-wide challenge stays on after the
	// window that tripped it, 30..3600 (default 300); each window still over
	// the rate extends it.
	HoldSeconds int `yaml:"hold_seconds"`
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

	// The label travels into JSON, logs and authorization decisions: the
	// same log/JSON/header-safe charset as hostgroup names and tenants.
	if zone.Tenant != "" && !groupNameRe.MatchString(zone.Tenant) {
		return fmt.Errorf("%s: tenant %q must match %s", zone.Name, zone.Tenant, groupNameRe)
	}

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
	if o := &zone.TLS.H3Options; !zone.TLS.H3 {
		// Options on a zone that does not speak h3 would be a silent no-op;
		// refusing them tells the author which key they forgot.
		if o.Advertise != nil || o.AltSvcMaxAgeSeconds != 0 {
			return fmt.Errorf("%s: tls.h3_options needs tls.h3: true", zone.Name)
		}
	} else {
		if o.Advertise == nil {
			adv := true
			o.Advertise = &adv
		}
		switch ma := o.AltSvcMaxAgeSeconds; {
		case ma == 0:
			o.AltSvcMaxAgeSeconds = edgedoc.DefaultAltSvcMaxAge
		case ma < edgedoc.MinAltSvcMaxAge || ma > edgedoc.MaxAltSvcMaxAge:
			return fmt.Errorf("%s: tls.h3_options.alt_svc_max_age_seconds must be %d..%d, got %d", zone.Name, edgedoc.MinAltSvcMaxAge, edgedoc.MaxAltSvcMaxAge, ma)
		}
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
	switch d := p.ChallengeOptions.Difficulty; {
	case d == 0:
		p.ChallengeOptions.Difficulty = edgedoc.DefaultChallengeDifficulty
	case d < minChallengeDifficulty || d > maxChallengeDifficulty:
		return fmt.Errorf("%s: policy.challenge_options.difficulty must be %d..%d, got %d", zone.Name, minChallengeDifficulty, maxChallengeDifficulty, d)
	}
	switch ttl := p.ChallengeOptions.CookieTTLSeconds; {
	case ttl == 0:
		p.ChallengeOptions.CookieTTLSeconds = edgedoc.DefaultCookieTTLSeconds
	case ttl < edgedoc.MinCookieTTLSeconds || ttl > edgedoc.MaxCookieTTLSeconds:
		return fmt.Errorf("%s: policy.challenge_options.cookie_ttl_seconds must be %d..%d, got %d", zone.Name, edgedoc.MinCookieTTLSeconds, edgedoc.MaxCookieTTLSeconds, ttl)
	}
	switch hold := p.ChallengeOptions.Auto.HoldSeconds; {
	case hold == 0:
		p.ChallengeOptions.Auto.HoldSeconds = edgedoc.DefaultChallengeHoldSeconds
	case hold < edgedoc.MinChallengeHoldSeconds || hold > edgedoc.MaxChallengeHoldSeconds:
		return fmt.Errorf("%s: policy.challenge_options.auto.hold_seconds must be %d..%d, got %d", zone.Name, edgedoc.MinChallengeHoldSeconds, edgedoc.MaxChallengeHoldSeconds, hold)
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
		// The decision service exempts a request only when its normalised
		// path AND its raw target — as the client sent it, percent-encoded —
		// both start with the prefix (decide.pathExempt). A compliant client
		// encodes everything outside RFC 3986's path characters, so a prefix
		// carrying a non-ASCII letter, a space, a brace or a quote could never
		// match a raw target; nor could one with a dot segment, ';', a
		// backslash or an escape. Such a prefix is refused here rather than
		// ignored in silence.
		if !exemptPrefixByte(ep) {
			return fmt.Errorf("%s: policy.challenge_options.exempt_paths[%d] %q must be a plain path prefix: letters, digits, - _ . ~ / and $ & + , : = @ only — no space, ';', backslash, percent-encoding, quotes, brackets or non-ASCII (clients send those encoded, so the prefix would never match)", zone.Name, i, ep)
		}
		for _, seg := range strings.Split(ep[1:], "/") {
			if seg == "." || seg == ".." || strings.HasPrefix(seg, "..") {
				return fmt.Errorf("%s: policy.challenge_options.exempt_paths[%d] %q must not contain a dot segment", zone.Name, i, ep)
			}
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
	// The puzzle's difficulty range: the clearance package's own bounds
	// (12 is trivial, 22 is the ceiling a slow phone still finishes inside
	// the puzzle window).
	minChallengeDifficulty = 12
	maxChallengeDifficulty = 22
)

// exemptPrefixByte reports whether every byte of an exempt prefix is one a
// compliant client sends unencoded in a request target: RFC 3986 unreserved
// (letters, digits, - _ . ~), '/', and the sub-delimiters browsers and HTTP
// libraries leave alone ($ & + , : = @). Everything else — space, ';', '\',
// '%', quotes, brackets, braces, '!', '*', ”', '(', ')' (Go's net/http
// escapes those), bytes outside ASCII — would arrive percent-encoded and the
// prefix would never match the raw target.
func exemptPrefixByte(p string) bool {
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '~' || c == '/':
		case c == '$' || c == '&' || c == '+' || c == ',' || c == ':' || c == '=' || c == '@':
		default:
			return false
		}
	}
	return true
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
