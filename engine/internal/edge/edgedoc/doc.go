// Package edgedoc is the wire contract between the brain and an edge node: the
// zone document that GET /api/v1/edge/zones serves and that `kapkan edge`
// renders into its terminator (edge-spec §2.3, milestones E3.1/E3.2).
//
// It is a LEAF package — encoding/json and the standard library, nothing of
// Kapkan's — because both ends import it: the api package on the brain side
// (which aliases these types under its Edge* names) and the renderer on the
// node side. Neither may drag the other's dependency tree along: the api
// package go:embeds the console and reaches the engine, the renderer must stay
// small enough to be reasoned about as "the thing that writes nginx config".
//
// THE JSON CONTRACT IS FROZEN HERE at Version 1: docs and the agent are written
// against these key names. The document must be deterministic — same zones
// file, same bytes — because the brain's ETag is a hash of the encoding, so
// nothing volatile may be added. Extension is by ADDING omitempty fields, never
// by renaming or retyping; a node tolerates keys it does not know (a newer
// brain) and refuses only a version it does not know (Decode).
package edgedoc

import (
	"encoding/json"
	"fmt"
	"time"
)

// Version is the document shape version. A node refuses a version it does not
// know rather than guessing at fields.
const Version = 1

// Zone policy vocabulary — the exact strings the zones file, this document and
// the renderer agree on. config.Zone* alias these so there is ONE definition;
// a typo cannot be accepted on the brain and refused on the node.
const (
	ModeDecide = "decide"
	ModeNone   = "none"

	FailOpen   = "open"
	FailClosed = "closed"

	// policy.challenge: off (no proof-of-work rung), manual (every request
	// without a clearance is challenged), auto (the node's rollups decide when
	// a source or the whole zone is challenged). E4; the zones file accepts
	// only off until the decision service can act on the others.
	ChallengeOff    = "off"
	ChallengeManual = "manual"
	ChallengeAuto   = "auto"

	TLS12 = "1.2"
	TLS13 = "1.3"
)

// Doc is the versioned document served to edge nodes.
type Doc struct {
	Version int `json:"version"`
	// Zones is every zone this brain serves, sorted by name. Always present
	// (empty array, not null), so an agent ranges over it without a check.
	Zones []Zone `json:"zones"`
	// ACMEChallenges is the HTTP-01 challenge table fanned out to every node so
	// any of them can answer a CA's validation request (edge-spec §3). Always
	// present; populated by the issuance coordinator (a later E3 step), empty
	// until then. Sorted by (zone, token) for determinism.
	ACMEChallenges []Challenge `json:"acme_challenges"`
	// IssuanceGrants is the set of currently granted issuance slots (edge-spec
	// §3: the brain serialises issuance per zone). Always present; populated by
	// the same later step, empty until then.
	IssuanceGrants []Grant `json:"issuance_grants"`
}

// Zone is one zone as the node must render and enforce it. The vocabulary is
// the zones file's (config.Zone) so a tenant reading the two sees the same
// words; the shape is flattened where the file nests for editing.
type Zone struct {
	Name    string   `json:"name"`
	Origins []string `json:"origins"`
	TLS     TLS      `json:"tls"`
	// ACMEDirectory is the zone's CA directory override; empty means the node
	// default.
	ACMEDirectory string `json:"acme_directory,omitempty"`
	// ACMEFallback is the CA directory the node turns to after repeated
	// failures with the primary (edge-spec §3: the LE duplicate-certificate
	// ceiling); empty means the node default fallback. Added in E3.4 — an
	// omitempty extension, per the rule above.
	ACMEFallback        string `json:"acme_fallback,omitempty"`
	Policy              Policy `json:"policy"`
	ExtraDirectivesFile string `json:"extra_directives_file,omitempty"`
	// ClearanceKeys are the zone's live proof-of-work clearance keys (E4:
	// edge-spec §5), the current epoch's and the previous one's, sorted by
	// NotBefore. A node verifies a clearance cookie with any of them and
	// issues under the newest; a node that receives none (an older brain)
	// mints an ephemeral key valid on itself alone. Added in E4.1 — an
	// omitempty extension; the secrets make the document sensitive, which is
	// why a node caches it 0600.
	ClearanceKeys []ClearanceKey `json:"clearance_keys,omitempty"`
}

// ClearanceKey is one clearance key: an opaque ID (the brain's epoch), the
// 32-byte secret as base64url without padding, and the window in which
// clearances signed with it are honoured.
type ClearanceKey struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// TLS mirrors config.ZoneTLS.
type TLS struct {
	MinVersion string `json:"min_version"`
	H3         bool   `json:"h3,omitempty"`
}

// Policy mirrors config.ZonePolicy — always fully resolved (no empty strings):
// the node never applies a default of its own.
type Policy struct {
	Mode        string `json:"mode"`
	FailureMode string `json:"failure_mode"`
	Challenge   string `json:"challenge"`
	Rate        Rate   `json:"rate"`
}

// Rate mirrors config.ZoneRate; 0 (omitted) means unlimited.
type Rate struct {
	RPS         uint64 `json:"rps,omitempty"`
	Concurrency uint64 `json:"concurrency,omitempty"`
}

// Challenge is one fanned-out HTTP-01 challenge: the node serves
// KeyAuthorization at /.well-known/acme-challenge/<Token> for Zone until
// ExpiresAt.
type Challenge struct {
	Zone             string    `json:"zone"`
	Token            string    `json:"token"`
	KeyAuthorization string    `json:"key_authorization"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// Grant is one issuance slot: Node may issue for Zone until ExpiresAt.
type Grant struct {
	Zone      string    `json:"zone"`
	Node      string    `json:"node"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Empty is the document with nothing to serve: valid, and what a brain with no
// edge block answers.
func Empty() Doc {
	return Doc{
		Version:        Version,
		Zones:          []Zone{},
		ACMEChallenges: []Challenge{},
		IssuanceGrants: []Grant{},
	}
}

// Decode parses a document the way a node must: the version is checked before
// any other field is trusted, unknown keys are tolerated (a newer brain adds
// omitempty fields), and the three arrays are non-nil afterwards even if the
// body carried null, so callers range over them without a check.
func Decode(body []byte) (*Doc, error) {
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("edge document: %w", err)
	}
	if probe.Version != Version {
		return nil, fmt.Errorf("edge document version %d is not supported by this node (it speaks version %d); upgrade the older side", probe.Version, Version)
	}
	d := &Doc{}
	if err := json.Unmarshal(body, d); err != nil {
		return nil, fmt.Errorf("edge document: %w", err)
	}
	if d.Zones == nil {
		d.Zones = []Zone{}
	}
	if d.ACMEChallenges == nil {
		d.ACMEChallenges = []Challenge{}
	}
	if d.IssuanceGrants == nil {
		d.IssuanceGrants = []Grant{}
	}
	return d, nil
}
