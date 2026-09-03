package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultDirectory is Let's Encrypt production — the one definition, shared
	// with the configuration's validation through edgedoc.
	DefaultDirectory = edgedoc.DefaultACMEDirectory
	// DefaultRenewBefore renews when this much of the lifetime remains: day
	// 60 of a 90-day certificate (edge-spec §2.4). For a shorter certificate
	// the threshold is a third of its lifetime instead.
	DefaultRenewBefore = 30 * 24 * time.Hour
	// DefaultCheckEvery is how often Run looks at every zone.
	DefaultCheckEvery = time.Hour
	// renewJitterMax spreads a fleet's renewals over up to a day; the jitter
	// is per (node, zone) and never more than a quarter of the renew window.
	renewJitterMax = 24 * time.Hour
	// fallbackAfter consecutive failures with the primary CA turn the next
	// attempt to the fallback directory.
	fallbackAfter = 3
	// Backoff between failed attempts for one zone.
	backoffMin = time.Hour
	backoffMax = 24 * time.Hour
)

// Budgets of one attempt; variables so tests can shrink them.
var (
	// issueTimeout bounds one order end to end — the ACME exchange only; the
	// slot wait has its own budget.
	issueTimeout = 5 * time.Minute
	// slotWait bounds how long a node waits for the brain to grant a slot
	// before proceeding on its own (the slot is advisory).
	slotWait = 15 * time.Minute
)

// SlotClient asks the brain for a per-zone issuance slot (edge-spec §3). The
// slot is advisory: errors and refusals are logged, waited on, and eventually
// overridden — a node must renew with the brain gone.
type SlotClient interface {
	// Acquire asks for the slot. granted=false with retryAfter means "not
	// now, another node holds it".
	Acquire(ctx context.Context, zone string) (granted bool, retryAfter time.Duration, err error)
	// Release gives the slot back after the order finished, either way.
	Release(ctx context.Context, zone string) error
}

// ChallengePublisher hands a pending HTTP-01 challenge to the brain for
// fan-out to every node. Best-effort: with the brain gone, only this node
// answers, which suffices when DNS points the CA here.
type ChallengePublisher interface {
	Publish(ctx context.Context, zone, token, keyAuthorization string) error
}

// EAB is an External Account Binding: the credentials a CA such as ZeroSSL or
// Google Trust Services requires to create an ACME account. HMACKey is the
// CA's base64url-encoded key.
type EAB struct {
	KID     string
	HMACKey string
}

// Options configures a Manager.
type Options struct {
	// StateDir is the node's state directory (edge-spec §3): keys and
	// certificates live under it, 0600/0700.
	StateDir string
	// NodeName seeds the per-node renewal jitter so a fleet does not renew
	// in lockstep; "" is allowed (the jitter is then per zone only).
	NodeName string
	// Directory is the default CA; "" means DefaultDirectory. A zone's own
	// acme.directory overrides it.
	Directory string
	// Fallback is the default fallback CA ("" for none); a zone's own
	// acme.fallback overrides it.
	Fallback string
	// Contact is the account contact list ("mailto:..."), optional.
	Contact []string
	// EAB holds External Account Binding credentials per directory URL, for
	// CAs that require one.
	EAB map[string]EAB
	// HTTPClient talks to the CA; nil means a 30 s client. Tests inject one
	// that trusts their CA.
	HTTPClient *http.Client
	// Slots and Publish are the brain-side coordination; either may be nil.
	Slots   SlotClient
	Publish ChallengePublisher
	// Challenges is the table the ChallengeServer answers from. Required.
	Challenges *ChallengeTable
	// OnCertificate runs after a certificate was written for zone — the hook
	// that re-renders and reloads the terminator (the slow path, §2.2).
	OnCertificate func(zone string)
	// RenewBefore, CheckEvery: 0 means the defaults.
	RenewBefore time.Duration
	CheckEvery  time.Duration
	// Now is the clock; nil means time.Now. Tests inject one.
	Now    func() time.Time
	Logger *slog.Logger
}

// Manager issues and renews certificates for the zones it is given.
type Manager struct {
	opts  Options
	store *store
	log   *slog.Logger
	now   func() time.Time

	// wake carries at most one pending request for an immediate Run pass.
	wake chan struct{}

	mu       sync.Mutex
	certs    map[string]Cert
	failures map[string]*zoneFailures
	ordering map[string]bool
}

type zoneFailures struct {
	consecutive  int
	nextAttempt  time.Time
	usedFallback bool
}

// New prepares the state directory and loads the inventory. A zone whose
// files are unusable is logged and skipped, not fatal: the other zones renew.
func New(opts Options) (*Manager, error) {
	if opts.Challenges == nil {
		return nil, errors.New("acme: Options.Challenges is required")
	}
	if opts.Directory == "" {
		opts.Directory = DefaultDirectory
	}
	if opts.RenewBefore <= 0 {
		opts.RenewBefore = DefaultRenewBefore
	}
	if opts.CheckEvery <= 0 {
		opts.CheckEvery = DefaultCheckEvery
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	for dir, eab := range opts.EAB {
		if eab.KID == "" || eab.HMACKey == "" {
			return nil, fmt.Errorf("acme: EAB for %s needs both kid and hmac key", dir)
		}
		if _, err := base64.RawURLEncoding.DecodeString(eab.HMACKey); err != nil {
			return nil, fmt.Errorf("acme: EAB for %s: hmac key is not base64url: %w", dir, err)
		}
	}
	st, err := newStore(opts.StateDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{opts: opts, store: st, log: opts.Logger.With("component", "edge-acme"), now: opts.Now, wake: make(chan struct{}, 1),
		certs: make(map[string]Cert), failures: make(map[string]*zoneFailures), ordering: make(map[string]bool)}
	inv, broken, err := st.inventory()
	if err != nil {
		return nil, err
	}
	for _, c := range inv {
		m.certs[c.Zone] = c
		metrics.EdgeCertNotAfter.WithLabelValues(c.Zone).Set(float64(c.NotAfter.Unix()))
	}
	for _, b := range broken {
		m.log.Error("certificate set on disk is unusable; the zone will be issued afresh", "zone", b.zone, "err", b.err)
	}
	return m, nil
}

// Inventory lists the certificates this node holds, sorted by zone.
func (m *Manager) Inventory() []Cert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Cert, 0, len(m.certs))
	for _, c := range m.certs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Zone < out[j].Zone })
	return out
}

// Cert returns the certificate held for zone.
func (m *Manager) Cert(zone string) (Cert, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certs[zone]
	return c, ok
}

// Due reports whether zone needs an order now: no certificate, or less than
// the renew window — RenewBefore, or a third of the certificate's lifetime
// when that is shorter — minus this (node, zone)'s jitter of its lifetime left.
func (m *Manager) Due(zone string) bool {
	c, ok := m.Cert(zone)
	if !ok {
		return true
	}
	return !m.now().Before(m.renewAt(c))
}

// renewAt is the instant a certificate becomes due.
func (m *Manager) renewAt(c Cert) time.Time {
	window := m.opts.RenewBefore
	if life := c.NotAfter.Sub(c.NotBefore); life > 0 && life/3 < window {
		window = life / 3
	}
	j := jitter(m.opts.NodeName, c.Zone)
	if j > window/4 {
		j = window / 4
	}
	return c.NotAfter.Add(-window + j)
}

// jitter is a stable offset in [0, renewJitterMax) per (node, zone): the same
// zone on two nodes renews at different moments, and two zones on one node
// do too.
func jitter(node, zone string) time.Duration {
	var h uint64 = 1469598103934665603
	for _, s := range []string{node, "\x00", zone} {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= 1099511628211
		}
	}
	return time.Duration(h % uint64(renewJitterMax))
}

// Ensure orders a certificate for zone if one is due. It returns the
// certificate now held and whether this call issued it. A refusal to attempt
// (backoff after failures, or an order already in flight for the zone) is not
// an error.
func (m *Manager) Ensure(ctx context.Context, zone edgedoc.Zone) (Cert, bool, error) {
	if err := checkZoneName(zone.Name); err != nil {
		return Cert{}, false, err
	}
	if !m.Due(zone.Name) {
		c, _ := m.Cert(zone.Name)
		return c, false, nil
	}
	m.mu.Lock()
	if m.ordering[zone.Name] {
		m.mu.Unlock()
		c, _ := m.Cert(zone.Name)
		return c, false, nil
	}
	if f := m.failures[zone.Name]; f != nil && m.now().Before(f.nextAttempt) {
		m.mu.Unlock()
		c, _ := m.Cert(zone.Name)
		return c, false, nil
	}
	m.ordering[zone.Name] = true
	prev, had := m.certs[zone.Name]
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.ordering, zone.Name)
		m.mu.Unlock()
	}()

	directory, usingFallback := m.directoryFor(zone)
	c, info, err := m.issue(ctx, zone.Name, directory, prev, had)
	if err != nil && ctx.Err() != nil {
		// The caller gave up; no verdict on the CA or the order.
		return prev, false, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		f := m.failures[zone.Name]
		if f == nil {
			f = &zoneFailures{}
			m.failures[zone.Name] = f
		}
		if info.publishFailed {
			// With the brain unreachable only this node answered the challenge;
			// under a shared VIP that fails by chance, not by the CA's fault.
			// Retry soon and do not let it push the zone onto the fallback CA.
			f.nextAttempt = m.now().Add(backoffMin)
		} else {
			f.consecutive++
			f.usedFallback = usingFallback
			f.nextAttempt = m.now().Add(backoff(f.consecutive))
		}
		metrics.EdgeACMEAttemptsTotal.WithLabelValues(zone.Name, "failed").Inc()
		m.log.Error("certificate order failed", "zone", zone.Name, "directory", directory, "attempt", f.consecutive, "next", f.nextAttempt, "publish_failed", info.publishFailed, "err", err)
		return prev, false, fmt.Errorf("acme: %s: %w", zone.Name, err)
	}
	delete(m.failures, zone.Name)
	m.certs[zone.Name] = c
	metrics.EdgeCertNotAfter.WithLabelValues(zone.Name).Set(float64(c.NotAfter.Unix()))
	result := "issued"
	if had {
		result = "renewed"
	}
	metrics.EdgeACMEAttemptsTotal.WithLabelValues(zone.Name, result).Inc()
	if usingFallback {
		metrics.EdgeACMEAttemptsTotal.WithLabelValues(zone.Name, "fallback").Inc()
	}
	m.log.Info("certificate "+result, "zone", zone.Name, "directory", directory, "serial", c.Serial, "not_after", c.NotAfter, "issuer", c.Issuer, "renew_at", m.renewAt(c))
	if m.opts.OnCertificate != nil {
		m.mu.Unlock()
		m.opts.OnCertificate(zone.Name)
		m.mu.Lock()
	}
	return c, true, nil
}

// directoryFor picks the CA for this attempt: the primary, or the fallback
// after fallbackAfter consecutive failures (alternating from then on). A
// success from either clears the failure state, so the following renewal
// tries the primary first.
func (m *Manager) directoryFor(zone edgedoc.Zone) (string, bool) {
	primary := zone.ACMEDirectory
	if primary == "" {
		primary = m.opts.Directory
	}
	fallback := zone.ACMEFallback
	if fallback == "" {
		fallback = m.opts.Fallback
	}
	m.mu.Lock()
	f := m.failures[zone.Name]
	m.mu.Unlock()
	if fallback == "" || f == nil || f.consecutive < fallbackAfter {
		return primary, false
	}
	// Alternate: the attempt after a fallback failure tries the primary again.
	if f.usedFallback {
		return primary, false
	}
	return fallback, true
}

func backoff(consecutive int) time.Duration {
	d := backoffMin
	for i := 1; i < consecutive && d < backoffMax; i++ {
		d *= 2
	}
	if d > backoffMax {
		d = backoffMax
	}
	return d
}

// issueInfo is what an attempt learned besides its outcome.
type issueInfo struct {
	publishFailed bool
}

// issue runs one ACME order for zone against directory. The slot is taken
// under its own budget (slotWait) before the order's clock (issueTimeout)
// starts, so a contested slot never turns into a counted CA failure.
func (m *Manager) issue(ctx context.Context, zone, directory string, prev Cert, had bool) (Cert, issueInfo, error) {
	var info issueInfo
	accountKey, err := m.store.accountKey(directory)
	if err != nil {
		return Cert{}, info, err
	}
	client := &xacme.Client{Key: accountKey, DirectoryURL: directory, HTTPClient: m.opts.HTTPClient, UserAgent: "kapkan-edge",
		// x/crypto/acme retries any 429 or 5xx with backoff until the context
		// ends — for a CA rate limit (the LE duplicate-certificate ceiling,
		// edge-spec §3) that would spin for the whole order timeout. A rate
		// limit is not transient within one order: give up at once and let the
		// Manager's own backoff (and the fallback CA) take over; retry a
		// transient 5xx or bad nonce a few times, briefly.
		RetryBackoff: func(n int, _ *http.Request, res *http.Response) time.Duration {
			if res != nil && res.StatusCode == http.StatusTooManyRequests {
				return -1
			}
			if n > 3 {
				return -1
			}
			return time.Duration(n) * time.Second
		},
	}

	slotCtx, cancelSlot := context.WithTimeout(ctx, slotWait)
	released := m.acquireSlot(slotCtx, zone)
	cancelSlot()
	defer released()
	if ctx.Err() != nil {
		return Cert{}, info, ctx.Err()
	}

	octx, cancel := context.WithTimeout(ctx, issueTimeout)
	defer cancel()
	acct := &xacme.Account{Contact: m.opts.Contact}
	if eab, ok := m.opts.EAB[directory]; ok {
		hmacKey, _ := base64.RawURLEncoding.DecodeString(eab.HMACKey)
		acct.ExternalAccountBinding = &xacme.ExternalAccountBinding{KID: eab.KID, Key: hmacKey}
	}
	if _, err := client.Register(octx, acct, xacme.AcceptTOS); err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return Cert{}, info, fmt.Errorf("register: %w", err)
	}
	order, err := client.AuthorizeOrder(octx, xacme.DomainIDs(zone))
	if err != nil {
		return Cert{}, info, fmt.Errorf("new order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(octx, authzURL)
		if err != nil {
			return Cert{}, info, fmt.Errorf("authorization: %w", err)
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return Cert{}, info, errors.New("authorization offers no http-01 challenge")
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return Cert{}, info, err
		}
		m.opts.Challenges.Add(zone, chal.Token, keyAuth, ChallengeTTL)
		defer m.opts.Challenges.Remove(zone, chal.Token)
		if m.opts.Publish != nil {
			if err := m.opts.Publish.Publish(octx, zone, chal.Token, keyAuth); err != nil {
				// This node still answers; only the other nodes will not.
				info.publishFailed = true
				m.log.Warn("challenge fan-out failed; only this node answers it", "zone", zone, "err", err)
			}
		}
		if _, err := client.Accept(octx, chal); err != nil {
			return Cert{}, info, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(octx, authz.URI); err != nil {
			return Cert{}, info, fmt.Errorf("validation: %w", err)
		}
	}
	if _, err := client.WaitOrder(octx, order.URI); err != nil {
		return Cert{}, info, fmt.Errorf("order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Cert{}, info, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{zone}}, key)
	if err != nil {
		return Cert{}, info, err
	}
	chain, _, err := client.CreateOrderCert(octx, order.FinalizeURL, csr, true)
	if err != nil {
		return Cert{}, info, fmt.Errorf("finalize: %w", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return Cert{}, info, fmt.Errorf("leaf: %w", err)
	}
	if err := checkLeaf(leaf, key, zone, m.now(), prev, had); err != nil {
		return Cert{}, info, err
	}
	c, err := m.store.save(zone, key, chain, directory, m.now())
	return c, info, err
}

// checkLeaf refuses a certificate that is not the one this order asked for.
func checkLeaf(leaf *x509.Certificate, key *ecdsa.PrivateKey, zone string, now time.Time, prev Cert, had bool) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("issued certificate does not carry the key this order generated")
	}
	if err := leaf.VerifyHostname(zone); err != nil {
		return fmt.Errorf("issued certificate does not cover %s: %w", zone, err)
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() == 0 {
		return errors.New("issued certificate has no serial number")
	}
	if !leaf.NotAfter.After(now) {
		return fmt.Errorf("issued certificate already expired at %s", leaf.NotAfter)
	}
	if had && !leaf.NotAfter.After(prev.NotAfter) {
		return fmt.Errorf("issued certificate expires at %s, no later than the one held (%s)", leaf.NotAfter, prev.NotAfter)
	}
	return nil
}

// acquireSlot asks the brain for the zone's slot, waiting as told until ctx
// (the slot budget) ends, then proceeds regardless. It returns the release
// function.
func (m *Manager) acquireSlot(ctx context.Context, zone string) func() {
	if m.opts.Slots == nil {
		return func() {}
	}
	for {
		granted, retryAfter, err := m.opts.Slots.Acquire(ctx, zone)
		if err != nil {
			if ctx.Err() != nil {
				m.log.Warn("issuance slot not granted within the wait; proceeding", "zone", zone, "waited", slotWait)
			} else {
				m.log.Warn("issuance slot unavailable; proceeding without it", "zone", zone, "err", err)
			}
			return func() {}
		}
		if granted {
			return func() {
				rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := m.opts.Slots.Release(rctx, zone); err != nil {
					m.log.Warn("issuance slot release failed", "zone", zone, "err", err)
				}
			}
		}
		if retryAfter <= 0 {
			retryAfter = 30 * time.Second
		}
		m.log.Info("issuance slot held by another node; waiting", "zone", zone, "retry_after", retryAfter)
		t := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			t.Stop()
			m.log.Warn("issuance slot not granted within the wait; proceeding", "zone", zone, "waited", slotWait)
			return func() {}
		case <-t.C:
		}
	}
}

// Wake asks Run for a pass now — the node calls it when a new document
// arrives, so a fresh node's first certificates, or a zone added later, are
// ordered at once instead of at the next CheckEvery tick. Safe to call from
// any goroutine and at any rate: a pass over zones already current or in
// backoff is a no-op.
func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Run keeps every zone's certificate current until ctx is done: a pass at
// start, then one every CheckEvery or on Wake. zones returns the current
// zone list (the agent's copy of the document); a zone that disappears is
// left alone (its files stay, its renewals stop) and its expiry gauge is
// dropped.
func (m *Manager) Run(ctx context.Context, zones func() []edgedoc.Zone) error {
	t := time.NewTicker(m.opts.CheckEvery)
	defer t.Stop()
	for {
		current := zones()
		want := make(map[string]bool, len(current))
		for _, z := range current {
			want[z.Name] = true
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, _, err := m.Ensure(ctx, z); err != nil && ctx.Err() == nil {
				// Logged inside Ensure; the loop goes on to the next zone.
				continue
			}
		}
		for _, c := range m.Inventory() {
			if !want[c.Zone] {
				metrics.EdgeCertNotAfter.DeleteLabelValues(c.Zone)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		case <-m.wake:
		}
	}
}
