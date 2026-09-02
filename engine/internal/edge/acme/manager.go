package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sort"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultDirectory is Let's Encrypt production.
	DefaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	// DefaultRenewBefore renews when this much of the lifetime remains: day
	// 60 of a 90-day certificate (edge-spec §2.4).
	DefaultRenewBefore = 30 * 24 * time.Hour
	// DefaultCheckEvery is how often Run looks at every zone.
	DefaultCheckEvery = time.Hour
	// renewJitterMax spreads a fleet's renewals over up to a day.
	renewJitterMax = 24 * time.Hour
	// issueTimeout bounds one order end to end.
	issueTimeout = 5 * time.Minute
	// slotWait bounds how long a node waits for the brain to grant a slot
	// before proceeding on its own (the slot is advisory).
	slotWait = 15 * time.Minute
	// fallbackAfter consecutive failures with the primary CA turn the next
	// attempt to the fallback directory.
	fallbackAfter = 3
	// Backoff between failed attempts for one zone.
	backoffMin = time.Hour
	backoffMax = 24 * time.Hour
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

// Options configures a Manager.
type Options struct {
	// StateDir is the node's state directory (edge-spec §3): keys and
	// certificates live under it, 0600/0700.
	StateDir string
	// Directory is the default CA; "" means DefaultDirectory. A zone's own
	// acme.directory overrides it.
	Directory string
	// Fallback is the default fallback CA ("" for none); a zone's own
	// acme.fallback overrides it.
	Fallback string
	// Contact is the account contact list ("mailto:..."), optional.
	Contact []string
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

	mu       sync.Mutex
	certs    map[string]Cert
	failures map[string]*zoneFailures
}

type zoneFailures struct {
	consecutive  int
	nextAttempt  time.Time
	usedFallback bool
}

// New prepares the state directory and loads the inventory.
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
	st, err := newStore(opts.StateDir)
	if err != nil {
		return nil, err
	}
	inv, err := st.inventory()
	if err != nil {
		return nil, err
	}
	m := &Manager{opts: opts, store: st, log: opts.Logger.With("component", "edge-acme"), now: opts.Now,
		certs: make(map[string]Cert, len(inv)), failures: make(map[string]*zoneFailures)}
	for _, c := range inv {
		m.certs[c.Zone] = c
		metrics.EdgeCertNotAfter.WithLabelValues(c.Zone).Set(float64(c.NotAfter.Unix()))
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
// RenewBefore (minus this zone's jitter) of its lifetime left.
func (m *Manager) Due(zone string) bool {
	c, ok := m.Cert(zone)
	if !ok {
		return true
	}
	return m.now().Add(m.opts.RenewBefore - jitter(zone)).After(c.NotAfter)
}

// jitter is a stable per-zone offset in [0, renewJitterMax) so a fleet's
// renewals for the same zone still spread by node… (the zone name is the
// same on every node, so the spread across a fleet comes from issuance times
// differing; the jitter mainly avoids lockstep across zones on one node).
func jitter(zone string) time.Duration {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(zone); i++ {
		h ^= uint64(zone[i])
		h *= 1099511628211
	}
	return time.Duration(h % uint64(renewJitterMax))
}

// Ensure orders a certificate for zone if one is due. It returns the
// certificate now held and whether this call issued it. A refusal to attempt
// (backoff after failures) is not an error.
func (m *Manager) Ensure(ctx context.Context, zone edgedoc.Zone) (Cert, bool, error) {
	if !m.Due(zone.Name) {
		c, _ := m.Cert(zone.Name)
		return c, false, nil
	}
	m.mu.Lock()
	f := m.failures[zone.Name]
	if f != nil && m.now().Before(f.nextAttempt) {
		m.mu.Unlock()
		c, _ := m.Cert(zone.Name)
		return c, false, nil
	}
	m.mu.Unlock()

	directory, usingFallback := m.directoryFor(zone)
	ctx, cancel := context.WithTimeout(ctx, issueTimeout)
	defer cancel()
	c, err := m.issue(ctx, zone.Name, directory)
	m.mu.Lock()
	defer m.mu.Unlock()
	had := false
	if _, ok := m.certs[zone.Name]; ok {
		had = true
	}
	if err != nil {
		f := m.failures[zone.Name]
		if f == nil {
			f = &zoneFailures{}
			m.failures[zone.Name] = f
		}
		f.consecutive++
		f.usedFallback = usingFallback
		f.nextAttempt = m.now().Add(backoff(f.consecutive))
		metrics.EdgeACMEAttemptsTotal.WithLabelValues(zone.Name, "failed").Inc()
		m.log.Error("certificate order failed", "zone", zone.Name, "directory", directory, "attempt", f.consecutive, "next", f.nextAttempt, "err", err)
		prev := m.certs[zone.Name]
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
	m.log.Info("certificate "+result, "zone", zone.Name, "directory", directory, "not_after", c.NotAfter, "issuer", c.Issuer)
	if m.opts.OnCertificate != nil {
		m.mu.Unlock()
		m.opts.OnCertificate(zone.Name)
		m.mu.Lock()
	}
	return c, true, nil
}

// directoryFor picks the CA for this attempt: the primary, or the fallback
// after fallbackAfter consecutive failures (alternating from then on).
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

// issue runs one ACME order for zone against directory.
func (m *Manager) issue(ctx context.Context, zone, directory string) (Cert, error) {
	accountKey, err := m.store.accountKey(directory)
	if err != nil {
		return Cert{}, err
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
	if _, err := client.Register(ctx, &xacme.Account{Contact: m.opts.Contact}, xacme.AcceptTOS); err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return Cert{}, fmt.Errorf("register: %w", err)
	}

	released := m.acquireSlot(ctx, zone)
	defer released()

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(zone))
	if err != nil {
		return Cert{}, fmt.Errorf("new order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return Cert{}, fmt.Errorf("authorization: %w", err)
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
			return Cert{}, errors.New("authorization offers no http-01 challenge")
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return Cert{}, err
		}
		m.opts.Challenges.Add(zone, chal.Token, keyAuth, ChallengeTTL)
		defer m.opts.Challenges.Remove(zone, chal.Token)
		if m.opts.Publish != nil {
			if err := m.opts.Publish.Publish(ctx, zone, chal.Token, keyAuth); err != nil {
				// This node still answers; only the other nodes will not.
				m.log.Warn("challenge fan-out failed; only this node answers it", "zone", zone, "err", err)
			}
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			return Cert{}, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return Cert{}, fmt.Errorf("validation: %w", err)
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return Cert{}, fmt.Errorf("order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Cert{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{zone}}, key)
	if err != nil {
		return Cert{}, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return Cert{}, fmt.Errorf("finalize: %w", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return Cert{}, fmt.Errorf("leaf: %w", err)
	}
	if err := leaf.VerifyHostname(zone); err != nil {
		return Cert{}, fmt.Errorf("issued certificate does not cover %s: %w", zone, err)
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.Cmp(big.NewInt(0)) == 0 {
		return Cert{}, errors.New("issued certificate has no serial number")
	}
	return m.store.save(zone, key, chain, directory, m.now())
}

// acquireSlot asks the brain for the zone's slot, waiting as told up to
// slotWait, then proceeds regardless. It returns the release function.
func (m *Manager) acquireSlot(ctx context.Context, zone string) func() {
	if m.opts.Slots == nil {
		return func() {}
	}
	deadline := m.now().Add(slotWait)
	for {
		granted, retryAfter, err := m.opts.Slots.Acquire(ctx, zone)
		if err != nil {
			m.log.Warn("issuance slot unavailable; proceeding without it", "zone", zone, "err", err)
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
		if m.now().Add(retryAfter).After(deadline) {
			m.log.Warn("issuance slot not granted within the wait; proceeding", "zone", zone, "waited", slotWait)
			return func() {}
		}
		m.log.Info("issuance slot held by another node; waiting", "zone", zone, "retry_after", retryAfter)
		t := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			t.Stop()
			return func() {}
		case <-t.C:
		}
	}
}

// Run keeps every zone's certificate current until ctx is done: a pass at
// start, then one every CheckEvery. zones returns the current zone list (the
// agent's copy of the document); a zone that disappears is left alone (its
// files stay, its renewals stop).
func (m *Manager) Run(ctx context.Context, zones func() []edgedoc.Zone) error {
	t := time.NewTicker(m.opts.CheckEvery)
	defer t.Stop()
	for {
		for _, z := range zones() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, _, err := m.Ensure(ctx, z); err != nil && ctx.Err() == nil {
				// Logged inside Ensure; the loop goes on to the next zone.
				continue
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
