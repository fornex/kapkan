// Package scrub is the scrub-node agent: the loop behind `kapkan scrub`.
//
// A scrub node has no detection engine and no BGP. The brain diverts a
// victim's traffic toward this box and serves the rule table at
// GET /api/v1/dataplane/rules; this agent long-polls that endpoint — the poll
// itself is the node's liveness signal — and keeps the local XDP data plane
// enforcing exactly what the document says. It NEVER invents rules: the
// charter sentence governs here too — the data plane executes decisions made
// elsewhere, and its default verdict is PASS.
//
// The failure model is inherited from the document's design rather than
// re-implemented: every installed rule carries its own in-kernel deadline
// (mirrored from the ban's expires_at), so a brain that dies leaves rules that
// age out on their own, and an agent that dies leaves a datapath that keeps
// enforcing until they do. The agent's job on top of that is only
// reconciliation: install what the document adds or changes, withdraw what it
// drops, refresh what it extends.
package scrub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/buildinfo"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// Backend installs and removes one victim's rules in the local data plane
// (*dataplane.Installer is the real one, a fake is the tests'). It is the
// mitigator's two-method seam plus Victims, which the agent needs and the
// mitigator does not: an agent restarted over a kept pin set must reconcile
// KERNEL reality, not its own empty memory — the rules a previous run
// installed are still enforcing, and the ones the brain's document no longer
// lists (or a now-LIVE node must not enforce, like a watch-only run's dry_run
// entries) have to be withdrawable.
type Backend interface {
	Install(victim netip.Prefix, rules dataplane.DynamicRules) error
	Withdraw(victim netip.Prefix) error
	// Victims enumerates every victim with dynamic rules in the kernel,
	// including sets adopted from a previous process.
	Victims() ([]netip.Prefix, error)
}

// Status supplies the advisory half of the node's self-report: the effective
// XDP mode and the datapath's real drop totals. Optional — a nil Status
// reports only what the agent itself knows (version, dry-run, rules ETag).
type Status func() (xdpMode string, droppedPackets, droppedBytes uint64)

// Options configures an Agent.
type Options struct {
	// BaseURL is the brain's API base (no path), Token the agent bearer, Node
	// the identity presented on every poll (?node=...).
	BaseURL string
	Token   string
	Node    string
	// DryRun is the NODE's watch-only flag. It rides every report, and it is
	// what permits installing the brain's dry_run entries: a watch-only
	// datapath counts them without dropping, which is the trial window working
	// end to end. A LIVE node must skip them instead — the frozen contract on
	// the rules document says a node must never enforce a dry-run entry.
	DryRun  bool
	Backend Backend
	Status  Status
	Log     *slog.Logger
	// ReportInterval is the advisory self-report cadence (default 10s).
	ReportInterval time.Duration
	// PollTimeout bounds one long-poll round trip. It must EXCEED the server's
	// documented 30s hold, or every held poll would be cut off client-side and
	// read as an error. Default 45s.
	PollTimeout time.Duration
	// BackoffMin/BackoffMax bound the error backoff (defaults 1s/30s).
	BackoffMin, BackoffMax time.Duration
	// Now is the clock (tests); nil means time.Now.
	Now func() time.Time
}

// Agent runs the poll and report loops.
type Agent struct {
	opt    Options
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	// mu guards etag, the one field BOTH loops touch: the poll loop writes it
	// after every 200 and the report loop reads it into each self-report.
	mu   sync.Mutex
	etag string

	// installed maps each victim this agent has rules in the kernel for to a
	// fingerprint of what was installed, so an unchanged entry is not
	// re-written every cycle while a moved expiry (the brain refreshing the
	// TTL mid-attack) IS — the reinstall is what renews the in-kernel
	// deadline, mirroring the brain's own renewal loop. Touched only by the
	// poll goroutine. seeded flips after the first reconcile has folded the
	// KERNEL's adopted victim set in (see apply).
	installed map[netip.Prefix]string
	seeded    bool
}

func (a *Agent) setETag(v string) { a.mu.Lock(); a.etag = v; a.mu.Unlock() }
func (a *Agent) getETag() string  { a.mu.Lock(); defer a.mu.Unlock(); return a.etag }

// New builds an Agent. Backend, BaseURL, Token and Node are required.
func New(opt Options) (*Agent, error) {
	if opt.Backend == nil {
		return nil, fmt.Errorf("scrub: a Backend is required")
	}
	if opt.BaseURL == "" || opt.Token == "" || opt.Node == "" {
		return nil, fmt.Errorf("scrub: BaseURL, Token and Node are all required")
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	if opt.ReportInterval <= 0 {
		opt.ReportInterval = 10 * time.Second
	}
	if opt.PollTimeout <= 0 {
		opt.PollTimeout = 45 * time.Second
	}
	if opt.BackoffMin <= 0 {
		opt.BackoffMin = time.Second
	}
	if opt.BackoffMax < opt.BackoffMin {
		opt.BackoffMax = 30 * time.Second
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	return &Agent{
		opt: opt,
		client: &http.Client{
			Timeout: opt.PollTimeout,
			// Never follow redirects: a redirect would silently re-send the
			// bearer token wherever Location points and would break the
			// long-poll semantics anyway. The brain never redirects; anything
			// that does is a middlebox worth failing loudly on.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log:       opt.Log.With("component", "scrub"),
		now:       now,
		installed: make(map[netip.Prefix]string),
	}, nil
}

// Run polls until ctx is cancelled. The report loop rides alongside.
func (a *Agent) Run(ctx context.Context) {
	go a.reportLoop(ctx)
	backoff := a.opt.BackoffMin
	for ctx.Err() == nil {
		ok := a.pollOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if ok {
			backoff = a.opt.BackoffMin
			continue // a healthy long-poll IS the pacing; re-poll immediately
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > a.opt.BackoffMax {
			backoff = a.opt.BackoffMax
		}
	}
}

// pollOnce performs one rules poll and reconciles on a 200. It reports whether
// the round trip was healthy (200/304); everything else backs off.
func (a *Agent) pollOnce(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.opt.BaseURL+"/api/v1/dataplane/rules?node="+url.QueryEscape(a.opt.Node), nil)
	if err != nil {
		a.log.Error("building the poll request failed", "err", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+a.opt.Token)
	if et := a.getETag(); et != "" {
		req.Header.Set("If-None-Match", et)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return true // shutdown, not a brain failure
		}
		a.log.Warn("rules poll failed; the kernel keeps enforcing the last rules until their own deadlines",
			"err", err)
		return false
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var doc api.RuleDoc
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc); err != nil {
			a.log.Error("rules document did not parse; keeping the last rules", "err", err)
			return false
		}
		if doc.Version != 1 {
			// A version this agent does not know could carry semantics it
			// would enforce wrongly. Refusing loudly and keeping the last
			// rules (which still age out in-kernel) is the fail-safe answer.
			a.log.Error("rules document version is not one this agent understands; upgrade kapkan on this node",
				"got", doc.Version)
			return false
		}
		a.apply(doc)
		et := resp.Header.Get("ETag")
		if et == "" {
			// Without an ETag the next poll cannot long-poll and would get an
			// instant 200 — a full-speed busy loop against the brain. The
			// server always sets one; a middlebox stripping it is a
			// misconfiguration worth a backoff and a loud line.
			a.log.Warn("rules response carried no ETag (a proxy stripping it?); backing off instead of busy-polling")
			return false
		}
		a.setETag(et)
		return true
	case http.StatusNotModified:
		return true
	case http.StatusUnauthorized, http.StatusForbidden:
		a.log.Error("the brain refused this node's credentials; check the agent token and its role",
			"status", resp.StatusCode)
		return false
	case http.StatusNotFound:
		a.log.Error("the brain does not know this node name — controller.name must equal a scrubbing.nodes[] entry",
			"node", a.opt.Node)
		return false
	default:
		a.log.Warn("unexpected rules poll status", "status", resp.StatusCode)
		return false
	}
}

// apply reconciles the local kernel with one rules document: install what is
// new or changed, withdraw what is gone. Per-victim failures are logged and
// retried on the next cycle rather than aborting the rest — one victim's bad
// rule set must not strand every other victim's protection.
func (a *Agent) apply(doc api.RuleDoc) {
	// The FIRST reconcile folds the kernel's adopted victim set in. An agent
	// restarted over a kept pin set (on_exit: keep, the default) inherits a
	// datapath that is still enforcing its previous run's rules, and process
	// memory alone cannot see them. Seeding them under a sentinel that equals
	// no fingerprint makes the document the authority in one pass: entries it
	// still lists are re-installed fresh, and entries it dropped — or a
	// now-LIVE node must not enforce, like a watch-only run's dry_run sets —
	// fall through to the withdraw sweep below.
	if !a.seeded {
		if victims, err := a.opt.Backend.Victims(); err != nil {
			a.log.Warn("could not enumerate adopted kernel rules; stale rule sets will lapse at their own in-kernel deadlines",
				"err", err)
		} else {
			for _, p := range victims {
				if _, ok := a.installed[p]; !ok {
					a.installed[p] = "adopted"
				}
			}
		}
		a.seeded = true
	}

	now := a.now()
	want := make(map[netip.Prefix]string, len(doc.Bans))
	for _, b := range doc.Bans {
		// THE DRY-RUN CONTRACT (frozen with the document's shape): a node must
		// never drop or rate-limit for a dry_run entry. A watch-only node
		// installs it — its whole datapath counts without dropping, which is
		// what makes the trial window observable end to end — and a LIVE node
		// skips it.
		if b.DryRun && !a.opt.DryRun {
			continue
		}
		ttl := b.ExpiresAt.Sub(now)
		if ttl <= 0 {
			// A LIVE document listing a ban this node computes as expired is
			// the clock-skew signature: with the node's clock ahead of the
			// brain's by more than the remaining TTL, every entry would be
			// skipped and the node would pass everything while being counted
			// alive. Said loudly, never swallowed.
			a.log.Error("document lists a ban this node computes as already expired — check clock sync (NTP) between node and brain",
				"victim", b.Prefix.String(), "expires_at", b.ExpiresAt.UTC().Format(time.RFC3339))
			continue
		}
		if len(b.FlowSpec) == 0 {
			// Nothing to narrow by: the ban diverts traffic here but carries
			// no rules yet. Default verdict is PASS by charter; there is
			// nothing to install.
			continue
		}
		fp := fingerprint(b)
		want[b.Prefix] = fp
		if a.installed[b.Prefix] == fp {
			continue
		}
		rules, err := mitigate.CompileDataplaneRules(b.FlowSpec, ttl)
		if err != nil {
			// Refusal is the safe answer (see dpencode.go): enforcing a rule
			// that means something different from the brain's record is worse
			// than leaving this victim to the default PASS.
			a.log.Error("refusing this victim's rules; they do not compile to the kernel schema",
				"victim", b.Prefix.String(), "err", err)
			continue
		}
		if err := a.opt.Backend.Install(b.Prefix, rules); err != nil {
			a.log.Error("installing rules failed; retrying next cycle",
				"victim", b.Prefix.String(), "err", err)
			continue
		}
		a.installed[b.Prefix] = fp
		a.log.Info("installed rules", "victim", b.Prefix.String(), "rules", len(b.FlowSpec),
			"ttl", ttl.Truncate(time.Second).String())
	}
	for p := range a.installed {
		if _, keep := want[p]; keep {
			continue
		}
		if err := a.opt.Backend.Withdraw(p); err != nil {
			// Logged and dropped from tracking anyway: the rules carry their
			// own in-kernel deadline, so a failed withdraw lapses rather than
			// lasting forever — the same call the mitigator makes.
			a.log.Error("withdrawing rules failed; they will lapse at their in-kernel deadline",
				"victim", p.String(), "err", err)
		} else {
			a.log.Info("withdrew rules", "victim", p.String())
		}
		delete(a.installed, p)
	}
}

// fingerprint identifies one entry's installed content. The expiry is part of
// it ON PURPOSE: the brain moving expires_at is a TTL refresh, and the
// reinstall it triggers is what renews the rules' in-kernel deadline.
func fingerprint(b api.RuleDocBan) string {
	rules, _ := json.Marshal(b.FlowSpec)
	return b.ExpiresAt.UTC().Format(time.RFC3339) + "|" + fmt.Sprintf("%t|", b.DryRun) + string(rules)
}

// reportLoop posts the advisory self-report on a fixed cadence. Best-effort by
// design — a report is never load-bearing (the poll is the liveness signal),
// so failures are logged at Warn and never affect the poll loop.
func (a *Agent) reportLoop(ctx context.Context) {
	t := time.NewTicker(a.opt.ReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.reportOnce(ctx)
		}
	}
}

func (a *Agent) reportOnce(ctx context.Context) {
	rep := api.NodeReport{
		Version:   buildinfo.Version(),
		DryRun:    a.opt.DryRun,
		RulesETag: a.getETag(),
	}
	if a.opt.Status != nil {
		mode, pkts, bytes_ := a.opt.Status()
		rep.XDPMode = mode
		rep.DroppedPackets = pkts
		rep.DroppedBytes = bytes_
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.opt.BaseURL+"/api/v1/dataplane/nodes/"+url.PathEscape(a.opt.Node)+"/report",
		bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.opt.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			a.log.Warn("self-report failed (advisory only; the poll is the liveness signal)", "err", err)
		}
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		a.log.Warn("self-report refused", "status", resp.StatusCode)
	}
}
