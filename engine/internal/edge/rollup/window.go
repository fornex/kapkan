package rollup

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultWindow is the aggregation window. Ten seconds is short enough
	// that a flood shows up before the second poll and long enough that a
	// rate computed from it means something.
	DefaultWindow = 10 * time.Second
	// DefaultMaxPairs bounds the (zone, source) pairs measured per window; the
	// exporter's figure, for the same reason (an IPv6 /64 rotates addresses).
	DefaultMaxPairs = 64 << 10
	// DefaultTopSources is how many sources a window's stats name.
	DefaultTopSources = 20
)

// SourceStats is one source's window in one zone.
type SourceStats struct {
	Src      netip.Addr
	Requests uint64
	// Denied counts requests the decision service refused (decision 403).
	Denied uint64
	// Errors4xx/5xx are origin (or terminator) statuses, excluding the
	// decider's own 403s.
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
	Denied   uint64
	// Undecided counts requests the decision service could not answer (its
	// socket down or slow), passed or refused by the zone's failure_mode.
	Undecided uint64
	Status2xx uint64
	Status3xx uint64
	Status4xx uint64
	Status5xx uint64
	Bytes     uint64
	RPS       float64
	// Sources is the top-N by requests; SourcesTotal how many there were.
	Sources      []SourceStats
	SourcesTotal int
	// Overflow reports that the per-window pair cap was hit: SourcesTotal is
	// then a floor and unnamed sources were counted in the zone totals only.
	Overflow bool
}

type zoneWindow struct {
	stats   WindowStats
	sources map[netip.Addr]*SourceStats
}

// Aggregator folds records into fixed windows per zone and hands each closed
// window to OnWindow. Safe for concurrent use; Observe is cheap (a map update).
type Aggregator struct {
	// Window is the window length; 0 means DefaultWindow.
	Window time.Duration
	// MaxPairs bounds the sources measured per window across zones; 0 means
	// DefaultMaxPairs.
	MaxPairs int
	// TopSources bounds WindowStats.Sources; 0 means DefaultTopSources.
	TopSources int
	// OnWindow receives each zone's stats when a window closes, on the
	// goroutine that closed it (an Observe or a Tick).
	OnWindow func(WindowStats)
	// OnRecord receives every record before aggregation (the decider's
	// Complete is wired here).
	OnRecord func(Record)
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu    sync.Mutex
	start time.Time
	zones map[string]*zoneWindow
	pairs int
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

// Observe folds one record in, closing the current window first if it is
// over.
func (a *Aggregator) Observe(r Record) {
	if a.OnRecord != nil {
		a.OnRecord(r)
	}
	now := a.now()
	a.mu.Lock()
	closed := a.rollIfDue(now)
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
	denied := r.Decision == "403"
	if denied {
		zs.Denied++
	}
	if len(r.Decision) == 3 && r.Decision[0] == '5' {
		zs.Undecided++
	}
	ss := zw.sources[r.Src]
	if ss == nil {
		max := a.MaxPairs
		if max <= 0 {
			max = DefaultMaxPairs
		}
		if a.pairs >= max {
			zs.Overflow = true
		} else {
			ss = &SourceStats{Src: r.Src}
			zw.sources[r.Src] = ss
			a.pairs++
		}
	}
	if ss != nil {
		ss.Requests++
		switch {
		case denied:
			ss.Denied++
		case r.Status >= 500:
			ss.Errors5xx++
		case r.Status >= 400:
			ss.Errors4xx++
		}
	}
	a.mu.Unlock()
	a.emit(closed)
}

// Tick closes the window if it is due even when no record arrives, so an
// idle zone's window is reported (and a flood that stopped is seen to stop).
// Call it from a timer at least once per window.
func (a *Aggregator) Tick() {
	a.mu.Lock()
	closed := a.rollIfDue(a.now())
	a.mu.Unlock()
	a.emit(closed)
}

// rollIfDue closes the current window when it has run its length, returning
// the closed zones' stats. Caller holds a.mu.
func (a *Aggregator) rollIfDue(now time.Time) []WindowStats {
	if a.zones == nil || now.Sub(a.start) < a.window() {
		return nil
	}
	elapsed := now.Sub(a.start)
	top := a.TopSources
	if top <= 0 {
		top = DefaultTopSources
	}
	out := make([]WindowStats, 0, len(a.zones))
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
		if len(st.Sources) > top {
			st.Sources = st.Sources[:top]
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Zone < out[j].Zone })
	// A fresh map, not clear(): the old one is referenced by nothing and the
	// allocator reclaims it; clear() would keep a flood's bucket count.
	a.zones = make(map[string]*zoneWindow)
	a.start = now
	a.pairs = 0
	return out
}

func (a *Aggregator) emit(closed []WindowStats) {
	if a.OnWindow == nil {
		return
	}
	for _, w := range closed {
		a.OnWindow(w)
	}
}
