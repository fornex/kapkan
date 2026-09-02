// Package render turns the edge document into the nginx/Angie configuration an
// edge node installs (edge-spec §4, milestone E3.2).
//
// WHAT IT EMITS. One shared file, kapkan_00_common.conf (the JSON log format,
// the unix-socket upstreams for the decision and ACME services, the rate-limit
// zones), and one kapkan_zone_<name>.conf per zone: an upstream of the zone's
// origins, a plain-HTTP server that answers ACME challenges and redirects, and
// — once the zone has a certificate — the TLS server that terminates, consults
// the decision service and proxies to the origin. The operator's nginx.conf
// includes the live generation once, inside http{}:
//
//	include /var/lib/kapkan/edge/conf/live/*.conf;
//
// nginx includes a glob in name order, which is why the shared file sorts first.
//
// THE FAIL-OPEN IDIOM (the milestone's one real technical risk). Every request
// in a decide-mode zone is gated by auth_request on an internal location that
// proxies headers-only to the decision service over a unix socket. The service
// answers 200 (allow, optionally X-Kapkan-Mark) or 403 (deny) — nothing else,
// by contract. If the service is down or slow the subrequest fails with a 5xx,
// auth_request turns that into a 500 for the main request, and the zone's
// failure_mode decides what a location-level error_page does with it: `open`
// redirects the request to the named pass-through location and it reaches the
// origin undecided; `closed` redirects it to a location that answers 503. The
// pass-through location is where EVERY allowed request ends (try_files falls
// through to it), so there is one origin path, not two; and because named
// locations do not inherit a location's error_page, an origin failure inside
// it is reported as-is, never retried. Rate limiting answers 429, deliberately
// outside the 5xx set the error_page catches. This idiom is what the
// real-terminator test exercises on stock nginx and Angie: a config that only
// passes `nginx -t` proves syntax, not that undecided requests pass.
//
// WHAT IT DOES NOT DO. There is no template override mechanism (edge-spec §4:
// "that way lies unsupportable config drift"); the one escape hatch is a zone's
// extra_directives_file, included verbatim at the end of the TLS server block
// and guarded by nothing but `nginx -t`. Nothing is ever proxied over
// cleartext: a zone without a certificate renders only the :80 listener, and
// that serves ACME challenges and 503. HTTP/3 is refused upstream (E5), so no
// QUIC directives appear here. Rendering is pure — no clock, no filesystem —
// so the tests are tables and golden files, and the same inputs always give
// the same bytes (the applier's idempotence check hashes them).
//
// LOGIC LIVES IN GO, TEMPLATES ARE DUMB. Every conditional a template takes is
// a boolean or string computed and validated here first; a template never
// inspects policy strings. That keeps the "which directive under which policy"
// decisions testable in Go and the templates readable as nginx.
package render

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var tmpl = template.Must(template.New("kapkan-edge").ParseFS(templateFS, "templates/*.tmpl"))

const (
	// CommonFile holds the shared definitions. It sorts ahead of every zone
	// file by name because nginx includes a glob in name order and the zone
	// files reference what it defines.
	CommonFile = "kapkan_00_common.conf"
	// ZoneFilePrefix + <zone name> + ".conf" is a zone's file; zone names are
	// validated hostnames, so they are safe as file names.
	ZoneFilePrefix = "kapkan_zone_"

	// Defaults for the node-side paths. /run is where the kapkan edge process
	// listens; /var/lib/kapkan/edge is its state directory (edge-spec §3).
	DefaultDecideSocket    = "/run/kapkan/edge-decide.sock"
	DefaultChallengeSocket = "/run/kapkan/edge-challenge.sock"
	DefaultLogSocket       = "/run/kapkan/edge-log.sock"
	DefaultEmptyRoot       = "/var/lib/kapkan/edge/empty"

	// sslCiphersTLS12 is the ECDHE subset of Mozilla's "intermediate" list: no
	// DHE (would need a dhparam file the node does not manage), no CBC. Only
	// consulted when a zone allows TLS 1.2; TLS 1.3 suites are not configurable.
	sslCiphersTLS12 = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
		"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)

var (
	// zoneNameRe is a lower-case RFC 1123 hostname: what the zones file accepts
	// after normalisation. Checked again here because the document crossed a
	// network and the name becomes a file name and a server_name.
	zoneNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	// originRe is the canonical host:port the zones file emits (bracketed IPv6,
	// dotted IPv4 or a lower-case hostname; a port without a leading zero).
	// Anything else could carry a character with meaning to nginx.
	originRe = regexp.MustCompile(`^(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*):[1-9][0-9]{0,4}$`)
)

// Inputs is everything a render needs. JSON tags make a whole Inputs a test
// fixture; the fields are the three things that vary independently: what the
// brain says (Doc), what this node has issued (Certs) and where this node's
// own services listen (Node).
type Inputs struct {
	Doc *edgedoc.Doc `json:"doc"`
	// Certs maps a zone name to its certificate files. A zone absent here has
	// no certificate yet and renders without its TLS server.
	Certs map[string]Cert `json:"certs,omitempty"`
	Node  Node            `json:"node"`
}

// Cert is the pair of files nginx loads for a zone. Both are absolute paths
// under the node's state directory (edge-spec §3: keys 0600, never leave the
// node). Only the PATHS pass through here; the renderer never reads them.
type Cert struct {
	Fullchain string `json:"fullchain"`
	Key       string `json:"key"`
}

// Node is where this node's own services listen and the few local paths the
// rendered configuration must name. Zero values take the Default* constants.
type Node struct {
	// DecideSocket is the unix socket of the decision service (edge-spec §5).
	DecideSocket string `json:"decide_socket,omitempty"`
	// ChallengeSocket is the unix socket answering ACME HTTP-01 (edge-spec §3).
	ChallengeSocket string `json:"challenge_socket,omitempty"`
	// LogSocket is the unix datagram socket the access log is shipped to.
	LogSocket string `json:"log_socket,omitempty"`
	// EmptyRoot is a directory that contains nothing; try_files stats a path
	// under it so that it always falls through to the pass-through location.
	EmptyRoot string `json:"empty_root,omitempty"`
	// DisableIPv6 drops the [::] listeners, for hosts and containers without an
	// IPv6 stack (binding [::]:443 there fails at start, not at `nginx -t`).
	DisableIPv6 bool `json:"disable_ipv6,omitempty"`
}

func (n Node) withDefaults() Node {
	if n.DecideSocket == "" {
		n.DecideSocket = DefaultDecideSocket
	}
	if n.ChallengeSocket == "" {
		n.ChallengeSocket = DefaultChallengeSocket
	}
	if n.LogSocket == "" {
		n.LogSocket = DefaultLogSocket
	}
	if n.EmptyRoot == "" {
		n.EmptyRoot = DefaultEmptyRoot
	}
	return n
}

func (n Node) validate() error {
	for _, p := range []struct{ name, path string }{
		{"decide_socket", n.DecideSocket},
		{"challenge_socket", n.ChallengeSocket},
		{"log_socket", n.LogSocket},
		{"empty_root", n.EmptyRoot},
	} {
		if err := safeAbsPath(p.path); err != nil {
			return fmt.Errorf("node.%s: %w", p.name, err)
		}
	}
	return nil
}

// safeAbsPath accepts an absolute path free of the characters that would end
// or comment out an nginx directive.
func safeAbsPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q is not an absolute path", p)
	}
	if strings.ContainsAny(p, " \t\r\n;{}#\"'\\$") {
		return fmt.Errorf("%q contains a character nginx would misread", p)
	}
	return nil
}

// Files is the rendered configuration: file name → content. Names never
// contain a path separator; the applier writes them into one generation
// directory.
type Files map[string][]byte

// Names lists the files in the order nginx will include them.
func (f Files) Names() []string {
	names := make([]string, 0, len(f))
	for n := range f {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Hash is a content hash over every file, name-ordered, so two renders that
// would install identical bytes compare equal. The applier uses it to skip a
// test-and-reload for a render that changed nothing.
func (f Files) Hash() string {
	h := sha256.New()
	for _, n := range f.Names() {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", n, len(f[n]))
		_, _ = h.Write(f[n])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ZoneFile is the file name a zone renders to.
func ZoneFile(name string) string {
	return ZoneFilePrefix + name + ".conf"
}

// commonData feeds the shared-file template.
type commonData struct {
	Node  Node
	Zones []zoneData
}

// zoneData is one zone with every decision already made. The template only
// tests booleans and prints strings.
type zoneData struct {
	Name string
	// ID is a nginx-identifier-safe derivative of Name used to name the zone's
	// upstream and limit zones (dots and dashes are legal there too, but a
	// stable, unambiguous identifier reads better in error messages).
	ID             string
	Origins        []string
	OriginUpstream string
	HasCert        bool
	Cert           Cert
	SSLProtocols   string
	// SSLCiphers is empty when only TLS 1.3 is allowed (its suites are fixed).
	SSLCiphers          string
	Decide              bool
	FailOpen            bool
	RPS                 uint64
	Burst               uint64
	Concurrency         uint64
	ExtraDirectivesFile string
	CommonFile          string
	Node                Node
}

// Render produces the configuration files for the document. It validates
// everything it interpolates: the document crossed a network, and a value that
// ends a directive early is a config injection.
func Render(in Inputs) (Files, error) {
	if in.Doc == nil {
		return nil, errors.New("render: nil edge document")
	}
	if in.Doc.Version != edgedoc.Version {
		return nil, fmt.Errorf("render: edge document version %d, this renderer speaks version %d", in.Doc.Version, edgedoc.Version)
	}
	node := in.Node.withDefaults()
	if err := node.validate(); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}

	zones := make([]zoneData, 0, len(in.Doc.Zones))
	seen := make(map[string]bool, len(in.Doc.Zones))
	for i := range in.Doc.Zones {
		z := &in.Doc.Zones[i]
		if seen[z.Name] {
			return nil, fmt.Errorf("render: zone %q appears twice in the document", z.Name)
		}
		seen[z.Name] = true
		zd, err := prepareZone(z, in.Certs[z.Name], node)
		if err != nil {
			return nil, fmt.Errorf("render: zone %q: %w", z.Name, err)
		}
		zones = append(zones, zd)
	}
	// The brain sorts, but the output must not depend on that.
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })

	files := make(Files, len(zones)+1)
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "common.conf.tmpl", commonData{Node: node, Zones: zones}); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	files[CommonFile] = append([]byte(nil), buf.Bytes()...)
	for i := range zones {
		buf.Reset()
		if err := tmpl.ExecuteTemplate(&buf, "zone.conf.tmpl", &zones[i]); err != nil {
			return nil, fmt.Errorf("render: zone %q: %w", zones[i].Name, err)
		}
		files[ZoneFile(zones[i].Name)] = append([]byte(nil), buf.Bytes()...)
	}
	return files, nil
}

// prepareZone validates one zone and resolves its policy into template facts.
func prepareZone(z *edgedoc.Zone, cert Cert, node Node) (zoneData, error) {
	if !zoneNameRe.MatchString(z.Name) {
		return zoneData{}, fmt.Errorf("name %q is not a lower-case hostname", z.Name)
	}
	if len(z.Origins) == 0 {
		return zoneData{}, errors.New("no origins")
	}
	origins := make([]string, 0, len(z.Origins))
	for _, o := range z.Origins {
		if !originRe.MatchString(o) {
			return zoneData{}, fmt.Errorf("origin %q is not a canonical host:port", o)
		}
		origins = append(origins, o)
	}
	d := zoneData{
		Name:           z.Name,
		ID:             zoneID(z.Name),
		Origins:        origins,
		OriginUpstream: "kapkan_origin_" + zoneID(z.Name),
		CommonFile:     CommonFile,
		Node:           node,
	}

	switch z.TLS.MinVersion {
	case edgedoc.TLS12:
		d.SSLProtocols = "TLSv1.2 TLSv1.3"
		d.SSLCiphers = sslCiphersTLS12
	case edgedoc.TLS13:
		d.SSLProtocols = "TLSv1.3"
	default:
		return zoneData{}, fmt.Errorf("tls.min_version %q is not %q or %q", z.TLS.MinVersion, edgedoc.TLS12, edgedoc.TLS13)
	}
	if z.TLS.H3 {
		return zoneData{}, errors.New("tls.h3 is not supported by this renderer (HTTP/3 is a later milestone)")
	}

	switch z.Policy.Mode {
	case edgedoc.ModeDecide:
		d.Decide = true
	case edgedoc.ModeNone:
	default:
		return zoneData{}, fmt.Errorf("policy.mode %q is not %q or %q", z.Policy.Mode, edgedoc.ModeDecide, edgedoc.ModeNone)
	}
	switch z.Policy.FailureMode {
	case edgedoc.FailOpen:
		d.FailOpen = true
	case edgedoc.FailClosed:
	default:
		return zoneData{}, fmt.Errorf("policy.failure_mode %q is not %q or %q", z.Policy.FailureMode, edgedoc.FailOpen, edgedoc.FailClosed)
	}
	if z.Policy.Challenge != edgedoc.ChallengeOff {
		return zoneData{}, fmt.Errorf("policy.challenge %q is not supported by this renderer (only %q)", z.Policy.Challenge, edgedoc.ChallengeOff)
	}
	d.RPS = z.Policy.Rate.RPS
	// One second of burst, absorbed without delay: a page load's parallel
	// fetches must not trip a limit meant for floods.
	d.Burst = z.Policy.Rate.RPS
	d.Concurrency = z.Policy.Rate.Concurrency

	if cert.Fullchain != "" || cert.Key != "" {
		if cert.Fullchain == "" || cert.Key == "" {
			return zoneData{}, errors.New("certificate needs both fullchain and key paths")
		}
		if err := safeAbsPath(cert.Fullchain); err != nil {
			return zoneData{}, fmt.Errorf("certificate fullchain: %w", err)
		}
		if err := safeAbsPath(cert.Key); err != nil {
			return zoneData{}, fmt.Errorf("certificate key: %w", err)
		}
		d.HasCert = true
		d.Cert = cert
	}
	if z.ExtraDirectivesFile != "" {
		if err := safeAbsPath(z.ExtraDirectivesFile); err != nil {
			return zoneData{}, fmt.Errorf("extra_directives_file: %w", err)
		}
		d.ExtraDirectivesFile = z.ExtraDirectivesFile
	}
	return d, nil
}

// zoneID maps a zone name onto [a-z0-9_] plus a short hash, so two names that
// differ only in punctuation (a.b vs a-b) cannot collide.
func zoneID(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	sum := sha256.Sum256([]byte(name))
	return b.String() + "_" + hex.EncodeToString(sum[:3])
}
