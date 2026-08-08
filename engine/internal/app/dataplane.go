package app

// Wiring the XDP data plane into the daemon, and the one refusal that keeps a
// half-finished feature from lying to an operator.
//
// Two separate things live here and they are easy to confuse:
//
//  1. STARTING THE DATA PLANE, when dataplane.enabled is true. Static policy
//     (allowlist, protected list, static rules, rate-limit profiles) is installed
//     and enforced in the kernel from this moment, and it hot-reloads.
//
//  2. REFUSING TO START when a resolved escalation ladder contains
//     `action: dataplane` and this build cannot execute that rung. That is a
//     different question from whether the data plane is up: the program can be
//     attached and enforcing every static rule the operator wrote, and a ladder
//     rung that says "drop this attack in the kernel" would still do nothing.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// checkDataplaneLadder refuses to start when a resolved ladder uses
// `action: dataplane` and the mitigator has no backend for it.
//
// WHY A REFUSAL AND NOT A WARNING. The failure this prevents is silent by
// construction: mitigate.stageView has no case for the action, so the rung
// resolves to the empty method and is announced as "alert-only stage (no route
// announced)". Nothing about the running system distinguishes it from a ladder
// the operator deliberately configured as alert-only — the ban is recorded, the
// notification fires, the metrics move — while the traffic the operator asked to
// drop in the kernel is forwarded.
//
// Four options were on the table:
//
//   - Warn and continue. The warning is emitted at startup; the consequence
//     arrives during an attack, hours or weeks later, and nobody correlates the
//     two. It would also be inconsistent with the layer directly above:
//     config.requireDataplane already REFUSES a ladder that names this action
//     while the dataplane block is missing or disabled, for exactly the same
//     reason ("the mitigator would have nowhere to install its rules and would
//     silently fall back on every attack"). Warning here would mean the same
//     mistake is fatal one layer up and cosmetic one layer down.
//
//   - Make the rung fail at announce time. applyStageLocked would then reject
//     the ban, and the victim would get NO mitigation at all — strictly worse
//     than alert-only at the moment it matters.
//
//   - Fall back to blackhole, the way flowspec and divert do. Wrong direction on
//     the ladder: dataplane is the MILDEST rung (escalationSeverity: dataplane=1,
//     flowspec=2, divert=3, blackhole=4), so this would blackhole a customer the
//     operator wanted surgically filtered. Worse than either of the above.
//
//   - Refuse at startup. The operator finds out at a moment of their choosing,
//     the supervisor reports it, and the message names the one line to change.
//     This one.
//
// The check is a function of mitigate.SupportsDataplane, so the change that adds
// the stageView case and the backend removes this refusal without anyone having
// to remember it exists.
func checkDataplaneLadder(cfg *config.Config) error {
	if mitigate.SupportsDataplane() {
		return nil
	}
	groups := groupsUsingDataplane(cfg)
	if len(groups) == 0 {
		return nil
	}
	// One line, no trailing punctuation: this is returned as an error and ends
	// up in a slog field, where embedded newlines render as literal \n and make
	// the most important message the daemon can print harder to read, not
	// easier. (staticcheck ST1005 says the same thing.)
	return fmt.Errorf(
		"escalation ladder uses %q, which this build cannot execute: the mitigator has no "+
			"data-plane backend yet, so such a rung would be announced as an ALERT-ONLY stage — "+
			"the attack would be recorded and notified but the traffic would NOT be dropped; "+
			"affected group(s): %s; change those rungs to %q, %q or %q "+
			"(dataplane.static_rules and dataplane.allowlist are unaffected and keep working)",
		config.EscalateDataplane, strings.Join(groups, ", "),
		config.EscalateNone, config.EscalateFlowSpec, config.EscalateBlackhole)
}

// groupsUsingDataplane lists the resolved groups whose ladder contains the
// dataplane action.
//
// It reads Config.Groups, the RESOLVED ladders, rather than the YAML: a group
// that inherits the global escalation has no escalation block of its own, and
// reading the YAML would miss exactly the case where an operator set the action
// once at the top and it applies everywhere.
func groupsUsingDataplane(cfg *config.Config) []string {
	seen := map[string]bool{}
	for _, g := range cfg.Groups {
		for _, s := range g.Escalation {
			if s.Action == config.EscalateDataplane {
				seen[g.Name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

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
	// DATAPATH is doing with it. Today that is the static rules only; the
	// mitigator's dynamic rules join the same gauge when the data-plane backend
	// lands, which is why the metric is a total by mode and not named for statics.
	metrics.SetDataplaneRules(int(snap.StaticCount), r.m.EffectiveDryRun())
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
		Enabled:      h.Enabled,
		DryRun:       r.m.EffectiveDryRun(),
		Degraded:     h.Degraded,
		Adopted:      h.Adopted,
		DynamicRules: 0, // no data-plane mitigation backend yet; see
		// checkDataplaneLadder. Reported as an explicit zero so a console
		// written now does not have to special-case the field appearing later.
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
