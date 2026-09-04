package rollup

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultWindow is the aggregation window. Ten seconds is short enough
	// that a flood shows up before the second poll and long enough that a
	// rate computed from it means something.
	DefaultWindow = 10 * time.Second
	// DefaultMaxPairs bounds the sources measured per zone per window; the
	// exporter's figure, for the same reason (a /64 rotates — though a source
	// here is already a /64, see edgedoc.SourceKey).
	DefaultMaxPairs = 64 << 10
	// DefaultTopSources is how many sources a window's stats name.
	DefaultTopSources = 20
)

// SourceStats is one source's window in one zone. Src is the accounting key
// (edgedoc.SourceKey), not a client address.
type SourceStats struct {
	Src      netip.Addr
	Requests uint64
	// Decided counts requests the decision service answered (200 or 403):
	// the denominator of the flood rule. :80 traffic, ACME hits and
	// undecided requests are requests, not decisions.
	Decided uint64
	// Denied counts requests the decision service refused, split by why:
	// DeniedRate is a client over its ceiling (rate or concurrency) — the
	// evidence of a flood; DeniedTable is a source the verdict table already
	// refuses — not new evidence of anything.
	Denied      uint64
	DeniedRate  uint64
	DeniedTable uint64
	// WouldDenyRate counts dry-run denials for rate/concurrency: a 200 the
	// decision service marked would-deny. Flood evidence in watch-only mode.
	WouldDenyRate uint64
	// Challenged counts requests sent to the clearance page (a 401 decision);
	// Cleared those that passed the rung with a valid clearance;
	// WouldChallenge the dry-run challenges (a 200 marked would-challenge) —
	// the "who would be challenged" set.
	Challenged     uint64
	Cleared        uint64
	WouldChallenge uint64
	// Errors4xx/5xx are origin (or terminator) statuses of decided or
	// non-deciding requests — the decider's own 403s and undecided requests
	// excluded, since neither says anything about the source.
	Errors4xx uint64
	Errors5xx uint64
	// RPS is Requests over the window's REAL elapsed time — never the nominal
	// window length, which would inflate every rate by a stalled reader's
	// stall factor.
	RPS float64
}

// WindowStats is one zone's closed window.
type WindowStats struct {
	Zone     string
	Start    time.Time
	Elapsed  time.Duration
	Requests uint64
	Decided  uint64
	Denied   uint64
	// Undecided counts requests the decision service could not answer (its
	// socket down or slow), passed or refused by the zone's failure_mode.
	Undecided uint64
	// Challenged counts requests sent to the clearance page; WouldChallenge
	// the dry-run ones (answered as allow, marked would-challenge).
	Challenged     uint64
	WouldChallenge uint64
	Status2xx      uint64
	Status3xx      uint64
	Status4xx      uint64
	Status5xx      uint64
	Bytes          uint64
	RPS            float64
	// Sources is the top-N by requests for OnWindow (the report); OnWindowFull
	// receives every source. SourcesTotal is how many there were.
	Sources      []SourceStats
	SourcesTotal int
	// Overflow reports that the zone's pair cap was hit: SourcesTotal is
	// then a floor and unnamed sources were counted in the zone totals only.
	Overflow bool
}

type zoneWindow struct {
	stats   WindowStats
	sources map[netip.Addr]*SourceStats
}

// Aggregator folds records into fixed windows per zone and hands each closed
// window to OnWindow (top-N sources, for the report) and OnWindowFull (every
// source, for the rules). Safe for concurrent use; Observe is cheap.
type Aggregator struct {
	// Window is the window length; 0 means DefaultWindow.
	Window time.Duration
	// MaxPairs bounds the sources measured per ZONE per window; 0 means
	// DefaultMaxPairs. Per zone, so one tenant's flood cannot empty another's
	// window.
	MaxPairs int
	// TopSources bounds WindowStats.Sources for OnWindow; 0 means
	// DefaultTopSources.
	TopSources int
	// OnWindow receives each zone's stats (top-N sources) when a window
	// closes, on the goroutine that closed it (an Observe or a Tick).
	OnWindow func(WindowStats)
	// OnWindowFull receives the same stats with EVERY source — the rules must
	// see the 21st offender too.
	OnWindowFull func(WindowStats)
	// OnRecord receives every record of a known zone before aggregation (the
	// decider's Complete is wired here).
	OnRecord func(Record)
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu    sync.Mutex
	start time.Time
	zones map[string]*zoneWindow
	known map[string]bool
}

func (a *Aggregator) window() time.Duration {
	if a.Window <= 0 {
		return DefaultWindow
	}
	return a.Window
}

func (a *Aggregator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// SetZones names the zones the document has. Records for any other zone —
// a forged line, or one from a zone removed since — are counted and dropped
// rather than aggregated, so the log stream cannot allocate windows at will.
// Until it is called, every zone is accepted.
func (a *Aggregator) SetZones(names []string) {
	known := make(map[string]bool, len(names))
	for _, n := range names {
		known[n] = true
	}
	a.mu.Lock()
	a.known = known
	a.mu.Unlock()
}

// Observe folds one record in, closing the current window first if it is
// over.
func (a *Aggregator) Observe(r Record) {
	now := a.now()
	a.mu.Lock()
	if a.known != nil && !a.known[r.Zone] {
		a.mu.Unlock()
		metrics.EdgeLogRecordsTotal.WithLabelValues("unknown_zone").Inc()
		return
	}
	a.mu.Unlock()
	if a.OnRecord != nil {
		a.OnRecord(r)
	}
	a.mu.Lock()
	closedTop, closedFull := a.rollIfDue(now)
	if a.zones == nil {
		a.zones = make(map[string]*zoneWindow)
		a.start = now
	}
	zw := a.zones[r.Zone]
	if zw == nil {
		zw = &zoneWindow{stats: WindowStats{Zone: r.Zone, Start: a.start}, sources: make(map[netip.Addr]*SourceStats)}
		a.zones[r.Zone] = zw
	}
	zs := &zw.stats
	zs.Requests++
	zs.Bytes += r.Bytes
	switch r.Status / 100 {
	case 2:
		zs.Status2xx++
	case 3:
		zs.Status3xx++
	case 4:
		zs.Status4xx++
	case 5:
		zs.Status5xx++
	}
	decided := r.Decided()
	denied := r.Decision == "403"
	challenged := r.Challenged()
	rateReason := r.Reason == "rate" || r.Reason == "concurrency"
	wouldDeny := r.WouldDenyReason()
	wouldChallenge := r.WouldChallengeReason() != ""
	if decided {
		zs.Decided++
	}
	if denied {
		zs.Denied++
	}
	if challenged {
		zs.Challenged++
	}
	if wouldChallenge {
		zs.WouldChallenge++
	}
	if r.Undecided() {
		zs.Undecided++
	}
	key := edgedoc.SourceKey(r.Src)
	ss := zw.sources[key]
	if ss == nil {
		max := a.MaxPairs
		if max <= 0 {
			max = DefaultMaxPairs
		}
		if len(zw.sources) >= max {
			zs.Overflow = true
		} else {
			ss = &SourceStats{Src: key}
			zw.sources[key] = ss
		}
	}
	if ss != nil {
		ss.Requests++
		if decided {
			ss.Decided++
		}
		if r.Cleared() {
			ss.Cleared++
		}
		switch {
		case denied:
			ss.Denied++
			if rateReason {
				ss.DeniedRate++
			} else {
				ss.DeniedTable++
			}
		case challenged:
			ss.Challenged++
		case wouldDeny == "rate" || wouldDeny == "concurrency":
			ss.WouldDenyRate++
		case wouldChallenge:
			ss.WouldChallenge++
		case r.Undecided():
			// Says nothing about the source.
		case r.Status >= 500:
			ss.Errors5xx++
		case r.Status >= 400:
			ss.Errors4xx++
		}
	}
	a.mu.Unlock()
	a.emit(closedTop, closedFull)
}

// Tick closes the window if it is due even when no record arrives, so an
// idle zone's window is reported (and a flood that stopped is seen to stop).
// Call it from a timer at least once per window.
func (a *Aggregator) Tick() {
	a.mu.Lock()
	closedTop, closedFull := a.rollIfDue(a.now())
	a.mu.Unlock()
	a.emit(closedTop, closedFull)
}

// rollIfDue closes the current window when it has run its length, returning
// the closed zones' stats: with the sources truncated to TopSources, and in
// full. Caller holds a.mu.
func (a *Aggregator) rollIfDue(now time.Time) (top, full []WindowStats) {
	if a.zones == nil || now.Sub(a.start) < a.window() {
		return nil, nil
	}
	elapsed := now.Sub(a.start)
	limit := a.TopSources
	if limit <= 0 {
		limit = DefaultTopSources
	}
	for _, zw := range a.zones {
		st := zw.stats
		st.Elapsed = elapsed
		st.RPS = float64(st.Requests) / elapsed.Seconds()
		st.SourcesTotal = len(zw.sources)
		st.Sources = make([]SourceStats, 0, len(zw.sources))
		for _, s := range zw.sources {
			s.RPS = float64(s.Requests) / elapsed.Seconds()
			st.Sources = append(st.Sources, *s)
		}
		sort.Slice(st.Sources, func(i, j int) bool {
			if st.Sources[i].Requests != st.Sources[j].Requests {
				return st.Sources[i].Requests > st.Sources[j].Requests
			}
			return st.Sources[i].Src.Less(st.Sources[j].Src)
		})
		full = append(full, st)
		truncated := st
		if len(truncated.Sources) > limit {
			truncated.Sources = truncated.Sources[:limit]
		}
		top = append(top, truncated)
	}
	sort.Slice(full, func(i, j int) bool { return full[i].Zone < full[j].Zone })
	sort.Slice(top, func(i, j int) bool { return top[i].Zone < top[j].Zone })
	// A fresh map, not clear(): the old one is referenced by nothing and the
	// allocator reclaims it; clear() would keep a flood's bucket count.
	a.zones = make(map[string]*zoneWindow)
	a.start = now
	return top, full
}

func (a *Aggregator) emit(top, full []WindowStats) {
	if a.OnWindowFull != nil {
		for _, w := range full {
			a.OnWindowFull(w)
		}
	}
	if a.OnWindow != nil {
		for _, w := range top {
			a.OnWindow(w)
		}
	}
}
