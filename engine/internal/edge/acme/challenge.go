// Package acme issues and renews a node's certificates (edge-spec §3,
// milestone E3.4): one ACME account per CA directory, one certificate per
// zone, keys generated on the node and never leaving it.
//
// PER NODE, not per fleet. Every node runs its own client against the zone's
// CA (golang.org/x/crypto/acme — small, and the ordering is ours), so a
// compromised node exposes its own keys and nothing else, and a node with the
// brain gone keeps renewing (edge-spec §2.4: "ACME renewals continue
// autonomously"). The price is the CA's duplicate-certificate ceiling — Let's
// Encrypt allows about five identical certificates a week — which is why the
// brain coordinates issuance: a node asks for a per-zone SLOT before it
// orders, and turns to a per-zone FALLBACK directory after repeated failures.
// Both are advisory: a slot the brain does not answer is a slot the node
// takes for itself after a bounded wait, because a node must never fail to
// renew for want of the brain.
//
// HTTP-01, FANNED OUT. A CA validates by fetching
// /.well-known/acme-challenge/<token> from the zone's name, which the
// operator's DNS points at ANY node — not necessarily the one ordering. So
// the ordering node publishes token → keyAuthorization to the brain, the brain
// fans it out inside the zone document (edgedoc.Doc.ACMEChallenges), and every
// node's ChallengeServer answers from the union of its own pending table and
// the fanned-out one — over the unix socket the renderer already routes the
// ACME location to. No webroot files, no new transport.
//
// ON DISK, under StateDir (0700): acme/<hash of directory URL>.key holds an
// account key per CA; certs/<zone>/{privkey.pem (0600), fullchain.pem,
// meta.json}. Files are written whole and renamed into place; meta.json is
// written last and is the marker that a certificate is complete. Nothing
// here ever reads a key back into a report or an API response — Inventory
// carries paths and public metadata only.
//
// RENEWAL. A certificate is renewed when less than RenewBefore (30 days) of
// its lifetime remains — day 60 of a 90-day certificate — with a per-zone
// jitter of up to a day so a fleet does not renew in lockstep; a failed
// attempt backs off exponentially (one hour to a day) and after
// fallbackAfter consecutive failures the next attempt uses the fallback CA.
// The metric kapkan_edge_cert_not_after_seconds{zone} carries the alarm.
package acme

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// tokenRe is an ACME token: base64url without padding (RFC 8555 §8.3 requires
// at least 128 bits of entropy; CAs use 32+ characters).
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

// ChallengeTTL bounds how long a published challenge is answered: a CA
// validates within seconds of Accept, and a token that outlives its order is
// only surface for confusion.
const ChallengeTTL = 10 * time.Minute

type challengeKey struct {
	zone, token string
}

type challengeEntry struct {
	keyAuth string
	until   time.Time
}

// ChallengeTable is what the ChallengeServer answers from: this node's own
// pending challenges plus the ones the brain fanned out for the fleet.
type ChallengeTable struct {
	mu     sync.Mutex
	local  map[challengeKey]challengeEntry
	fanned map[challengeKey]challengeEntry
	now    func() time.Time
}

// NewChallengeTable returns an empty table; now may be nil.
func NewChallengeTable(now func() time.Time) *ChallengeTable {
	if now == nil {
		now = time.Now
	}
	return &ChallengeTable{local: make(map[challengeKey]challengeEntry), fanned: make(map[challengeKey]challengeEntry), now: now}
}

// Add records one of this node's pending challenges.
func (t *ChallengeTable) Add(zone, token, keyAuth string, ttl time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.local[challengeKey{zone, token}] = challengeEntry{keyAuth: keyAuth, until: t.now().Add(ttl)}
	t.sweepLocked()
}

// Remove forgets one of this node's challenges (the order finished).
func (t *ChallengeTable) Remove(zone, token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.local, challengeKey{zone, token})
}

// SetFanned replaces the fleet-wide challenges with the document's.
func (t *ChallengeTable) SetFanned(challenges []edgedoc.Challenge) {
	fanned := make(map[challengeKey]challengeEntry, len(challenges))
	for _, c := range challenges {
		if !tokenRe.MatchString(c.Token) || c.Zone == "" || c.KeyAuthorization == "" {
			continue
		}
		fanned[challengeKey{c.Zone, c.Token}] = challengeEntry{keyAuth: c.KeyAuthorization, until: c.ExpiresAt}
	}
	t.mu.Lock()
	t.fanned = fanned
	t.mu.Unlock()
}

// Lookup returns the key authorization for a live challenge of zone, this
// node's own first.
func (t *ChallengeTable) Lookup(zone, token string) (string, bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	k := challengeKey{zone, token}
	if e, ok := t.local[k]; ok && now.Before(e.until) {
		return e.keyAuth, true
	}
	if e, ok := t.fanned[k]; ok && now.Before(e.until) {
		return e.keyAuth, true
	}
	return "", false
}

// Pending lists this node's live challenges, for the report and for tests.
func (t *ChallengeTable) Pending() []edgedoc.Challenge {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]edgedoc.Challenge, 0, len(t.local))
	for k, e := range t.local {
		if now.Before(e.until) {
			out = append(out, edgedoc.Challenge{Zone: k.zone, Token: k.token, KeyAuthorization: e.keyAuth, ExpiresAt: e.until})
		}
	}
	return out
}

func (t *ChallengeTable) sweepLocked() {
	now := t.now()
	for k, e := range t.local {
		if !now.Before(e.until) {
			delete(t.local, k)
		}
	}
}

const challengePrefix = "/.well-known/acme-challenge/"

// Handler answers HTTP-01 validation requests the terminator proxies to this
// node: GET or HEAD of the token path, the zone from X-Kapkan-Zone (the
// renderer sets it) or, failing that, the Host header.
func (t *ChallengeTable) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, ok := strings.CutPrefix(r.URL.Path, challengePrefix)
		if !ok || !tokenRe.MatchString(token) {
			http.NotFound(w, r)
			return
		}
		zone := r.Header.Get("X-Kapkan-Zone")
		if zone == "" {
			zone = strings.ToLower(r.Host)
			if h, _, ok := strings.Cut(zone, ":"); ok {
				zone = h
			}
		}
		keyAuth, ok := t.Lookup(zone, token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(keyAuth))
	})
}
