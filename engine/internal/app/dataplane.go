package app

// Wiring the XDP data plane into the daemon: starting it, hot-reloading its
// static policy, and reporting what it is doing to /metrics, /healthz and
// /api/v1/status.
//
// A THIRD THING USED TO LIVE HERE and is worth recording, because its absence is
// now load-bearing: a startup REFUSAL for a ladder containing `action:
// dataplane` that the mitigator had no backend for. Such a rung resolved to the
// empty method and was announced as an alert-only stage — the ban recorded, the
// notification sent, the metrics moved, and the traffic forwarded. The refusal
// was written as a function of mitigate.SupportsDataplane() precisely so that
// the change adding the backend would retire it without anyone having to
// remember it existed. That change has landed, SupportsDataplane() is true, and
// the guard has been deleted rather than left as dead code that reads like an
// active safety net. What replaced it is stronger than a startup check: the rung
// now installs, and an install that fails degrades to the configured fallback
// with FellBackFrom set, so the failure is visible per ban instead of per boot.
//
// The tripwire that keeps the silent alert-only bug from coming back is
// mitigate.TestSupportsDataplaneMatchesStageView, which fails if stageView stops
// returning a real method for the action.

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// startDataplane builds and attaches the data plane, or returns nil when it is
// not configured.
//
// Failure is fatal to startup, unlike GeoIP next door in New. The asymmetry is
// deliberate and is argued in internal/dataplane/probe_linux.go: a GeoIP
// database that will not open costs an attack some attribution, while a data
// plane that is not there means the operator's configured drop is not happening
// and nothing says so.
func startDataplane(cfg *config.Config, log *slog.Logger) (*dataplane.Manager, error) {
	if !cfg.DataplaneEnabled() {
		return nil, nil
	}
	opts, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	opts.Log = log
	m, err := dataplane.Open(opts)
	if err != nil {
		return nil, err
	}
	if h := m.Health(); h.Degraded {
		log.Warn("the XDP data plane started DEGRADED", "detail", h.Summary())
	} else {
		log.Info("XDP data plane up", "detail", h.Summary())
	}
	return m, nil
}

// ApplyReload pushes a freshly loaded configuration into the components that
// cannot simply re-read the store on their next tick.
//
// Today that is the data plane alone: its static policy lives in kernel maps, so
// a reload has to be WRITTEN somewhere rather than observed. Everything else in
// kapkan calls store.Get() per evaluation and picks up a new config for free.
//
// It never fails the reload. config.Store.Reload has already accepted the file
// and swapped it in — refusing here would leave the process running with a
// configuration the store says is current and the kernel says is not, which is
// worse than a loud failure to apply one part of it. The restart-required cases
// are rejected by the store before this is reached.
func (a *App) ApplyReload(cfg *config.Config) {
	if a.Dataplane == nil {
		if cfg.DataplaneEnabled() {
			a.log.Warn("dataplane.enabled was turned on in the configuration file, but attaching " +
				"an XDP program cannot be done at runtime; restart kapkan to apply it")
		}
		return
	}
	if !cfg.DataplaneEnabled() {
		a.log.Warn("dataplane.enabled was turned off in the configuration file; the XDP program " +
			"stays attached and enforcing until kapkan is restarted. Restart to detach it")
		return
	}
	opts, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		a.log.Error("could not translate the reloaded configuration for the data plane; "+
			"the kernel keeps the previous static policy", "err", err)
		return
	}
	opts.Log = a.log
	rep, err := a.Dataplane.Reload(opts)
	if err != nil {
		a.log.Error("data-plane static policy reload FAILED; the kernel keeps the previous policy "+
			"(dynamic rules are unaffected either way)", "err", err)
		return
	}
	a.log.Info("data-plane static policy reloaded", "detail", rep.Summary())
	// A reload changes the static rule count and the live generation, and the
	// scraper would otherwise publish the old ones for up to a tick. Cheap, and
	// it keeps /metrics and /api/v1/status from disagreeing with the log line
	// that was just written.
	a.dpReport.refresh()
}

/* ========================================================================= */
/* The reporter: one Stats() read feeding /metrics, /api/v1/status, /healthz  */
/* ========================================================================= */

// dataplaneReporter adapts *dataplane.Manager to api.DataplaneReporter and owns
// the periodic scrape that feeds the Prometheus collectors.
//
// It exists in internal/app because this is the only package that may import
// both sides: internal/api deliberately does not know internal/dataplane (see
// api/dataplane.go for why), so the translation has to live somewhere that does.
//
// One Stats() call per tick serves all three consumers. That is deliberate:
// /metrics and /api/v1/status showing different rule counts for the same instant
// is the kind of discrepancy an operator spends an afternoon on, and sharing the
// read makes it impossible rather than unlikely.
type dataplaneReporter struct {
	m   *dataplane.Manager
	log *slog.Logger
	// snap is the most recent successful Stats(). Read by request goroutines,
	// written only by refresh; atomic.Pointer rather than a mutex because a
	// reader never needs to see a half-updated snapshot, only a whole old one.
	snap atomic.Pointer[dataplane.Snapshot]
	// lastErr is the most recent Stats() failure, "" once one succeeds again.
	lastErr atomic.Pointer[string]
	// dynRules is the mitigator-installed rule count, published by the ban
	// counter scraper on ITS cadence (5s) rather than this one (1s). Kept as an
	// atomic here, instead of read from the scraper on demand, so a request
	// goroutine never touches the scraper's unsynchronised state.
	dynRules atomic.Int64
}

// newDataplaneReporter builds the reporter and takes the first reading, so
// /api/v1/status is complete from the first request rather than reporting zero
// rules for the first second of the process's life.
func newDataplaneReporter(m *dataplane.Manager, log *slog.Logger) *dataplaneReporter {
	r := &dataplaneReporter{m: m, log: log}
	r.refresh()
	return r
}

// refresh takes one reading and publishes it to the collectors and the cache.
func (r *dataplaneReporter) refresh() {
	if r == nil || r.m == nil {
		return
	}
	snap, err := r.m.Stats()
	if err != nil {
		msg := err.Error()
		r.lastErr.Store(&msg)
		return
	}
	r.lastErr.Store(nil)
	r.snap.Store(&snap)
	r.publish(snap)
}

// publish writes one snapshot into the Prometheus collectors.
//
// The verdict split is the load-bearing part. kapkan_stats mixes terminal
// verdicts with OBSERVATIONS that are bumped alongside one (a dry-run rewrite
// bumps both dryrun_would_drop and the pass it was rewritten to), so putting
// them in one metric would make sum(rate(packets_total)) over-count exactly the
// packets an operator most wants counted correctly. IsObservation is the
// kernel-side contract for which is which, and this is the one place it is
// consulted on the userspace side.
func (r *dataplaneReporter) publish(snap dataplane.Snapshot) {
	for s := dataplane.Stat(0); s < dataplane.StatMax; s++ {
		c := snap.Counters[s]
		if s.IsObservation() {
			metrics.AddDataplaneObservation(s.String(), c.Pkts)
			continue
		}
		metrics.AddDataplaneVerdict(s.String(), c.Pkts, c.Bytes)
	}
	metrics.DataplanePolicyGeneration.Set(float64(snap.Generation))
	for _, mp := range snap.Maps {
		metrics.DataplaneMapEntries.WithLabelValues(mp.Name).Set(float64(mp.MaxEntries))
		metrics.DataplaneMapBytes.WithLabelValues(mp.Name).Set(float64(mp.Bytes))
	}
	// rules{mode} counts what the kernel is enforcing, filed under what the
	// DATAPATH is doing with it — which is why the metric is a total by mode and
	// not named for statics. The mitigator's dynamic rules now join it, measured
	// by the ban counter scraper on its own cadence, so the gauge answers "how
	// many rules is this box actually running" rather than "how many did the
	// operator write".
	metrics.SetDataplaneRules(int(snap.StaticCount)+int(r.dynRules.Load()), r.m.EffectiveDryRun())
}

// scrape runs refresh on kapkan's existing 1 Hz cadence — the same tick the
// engine evaluates thresholds on and the mitigator sweeps ladders on. Reusing it
// rather than adding a dataplane.metrics_interval knob is the point: an operator
// correlating a drop_rl spike against a pps threshold crossing should not have to
// reason about two different sample rates.
//
// Cost per tick is one per-CPU read of a 21-entry array, one map lookup, and one
// Info() per map — tens of cheap syscalls a second, against a datapath doing
// millions of packets in the same second.
func (r *dataplaneReporter) scrape(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh()
		}
	}
}

// DataplaneSummary implements api.DataplaneReporter. Health() is a mutex and a
// struct copy with no bpf(2) in it, which is what lets /healthz stay cheap enough
// for a supervisor to poll hard.
func (r *dataplaneReporter) DataplaneSummary() string {
	return r.m.Health().Summary()
}

// DataplaneStatus implements api.DataplaneReporter, translating the dataplane
// package's types into the API's frozen contract.
//
// Attachment state comes from a LIVE Health() call and the counters from the
// cached snapshot. That asymmetry is intentional: "is eth1 filtering right now"
// is the question a human asks during an incident and it must not be a second
// stale, while a packet counter one tick behind is indistinguishable from a fresh
// one at any polling rate a console uses.
func (r *dataplaneReporter) DataplaneStatus() api.DataplaneStatus {
	h := r.m.Health()
	out := api.DataplaneStatus{
		Enabled:  h.Enabled,
		DryRun:   r.m.EffectiveDryRun(),
		Degraded: h.Degraded,
		Adopted:  h.Adopted,
		// The mitigator's rules, as MEASURED by the ban counter scraper — the
		// count of kapkan_rule_stats entries it could actually read, not the
		// number of rules something meant to install. A rule that failed to
		// install, or whose in-kernel deadline lapsed while userspace was wedged,
		// is not counted here, which is the point of measuring rather than
		// tallying intent.
		DynamicRules: int(r.dynRules.Load()),
	}
	modes := map[string]bool{}
	for _, i := range h.Interfaces {
		out.Configured++
		if i.Attached {
			out.Attached++
			modes[i.Mode] = true
		}
		out.Interfaces = append(out.Interfaces, api.DataplaneInterface{
			Name: i.Name, Index: i.Index, Mode: i.Mode, Attached: i.Attached,
			Attempts: i.Attempts, LastError: i.LastError,
		})
	}
	// One mode is a mode; two is "mixed". A single scalar that just reported the
	// first interface's mode would hide a box where eth0 is native and eth1 fell
	// back to generic — a tenfold capacity difference on half the traffic.
	switch len(modes) {
	case 0: // nothing attached
	case 1:
		for m := range modes {
			out.Mode = m
		}
	default:
		out.Mode = "mixed"
	}
	if out.Interfaces == nil {
		out.Interfaces = []api.DataplaneInterface{}
	}
	for _, c := range h.Conditions {
		out.Conditions = append(out.Conditions, api.DataplaneCondition{
			Kind: string(c.Kind), Interface: c.Interface, Message: c.Message,
			Since: c.Since.UTC().Format(time.RFC3339),
		})
	}
	if snap := r.snap.Load(); snap != nil {
		out.StaticRules = int(snap.StaticCount)
		out.Generation = int(snap.Generation)
		out.MapSchemaVersion = int(snap.SchemaVersion)
		out.MapBytes = int64(snap.MapBytes)
		out.Verdicts = make(map[string]api.DataplaneCounter, len(snap.Verdicts))
		for name, c := range snap.Verdicts {
			out.Verdicts[name] = api.DataplaneCounter{Packets: c.Pkts, Bytes: c.Bytes}
		}
	}
	// Say so when the counters are unreadable, rather than serving zeros that
	// look like an idle datapath.
	if e := r.lastErr.Load(); e != nil {
		out.Error = *e
	}
	return out
}
