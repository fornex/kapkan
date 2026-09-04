package decide

import (
	"net/netip"
	"time"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

// entry is one verdict: a deny with its reason, a challenge with its reason,
// or a mark.
type entry struct {
	deny      bool
	challenge bool
	reason    string
	mark      string
	until     time.Time
}

// table holds deny, challenge and mark verdicts per (zone, source), with ""
// as the every-zone wildcard. The three kinds live in separate maps, so a
// weaker verdict can never displace a stronger one and precedence is by
// STRENGTH, not by scope: any live deny (zone or every-zone) denies;
// otherwise any live challenge; otherwise the zone mark, then the every-zone
// mark. Bounded; expired entries are dropped on sweep and, paced, on a full
// insert.
type table struct {
	denies     map[key]entry
	challenges map[key]entry
	marks      map[key]entry
	max        int
	lastSweep  time.Time
}

func newTable(max int) *table {
	return &table{denies: make(map[key]entry), challenges: make(map[key]entry), marks: make(map[key]entry), max: max}
}

func live(m map[key]entry, k key, now time.Time) (entry, bool) {
	e, ok := m[k]
	if !ok {
		return entry{}, false
	}
	if !now.Before(e.until) {
		delete(m, k)
		return entry{}, false
	}
	return e, true
}

// lookup returns the strongest live verdict for k, or nil.
func (t *table) lookup(k key, now time.Time) *entry {
	wild := key{src: k.src}
	for _, m := range [...]map[key]entry{t.denies, t.challenges, t.marks} {
		if e, ok := live(m, k, now); ok {
			return &e
		}
		if k.zone != "" {
			if e, ok := live(m, wild, now); ok {
				return &e
			}
		}
	}
	return nil
}

// setDeny installs or replaces k's deny.
func (t *table) setDeny(k key, reason string, until, now time.Time) bool {
	if !t.room(t.denies, k, now) {
		return false
	}
	t.denies[k] = entry{deny: true, reason: reason, until: until}
	t.gauge()
	return true
}

// setChallenge installs or replaces k's challenge.
func (t *table) setChallenge(k key, reason string, until, now time.Time) bool {
	if !t.room(t.challenges, k, now) {
		return false
	}
	t.challenges[k] = entry{challenge: true, reason: reason, until: until}
	t.gauge()
	return true
}

// setMark installs or replaces k's mark.
func (t *table) setMark(k key, mark string, until, now time.Time) bool {
	if !t.room(t.marks, k, now) {
		return false
	}
	t.marks[k] = entry{mark: mark, until: until}
	t.gauge()
	return true
}

// room makes sure m can take k: an existing key always can; a new one needs
// the combined size under max, after a paced sweep of expired entries. A
// full table refuses rather than evict a live verdict at random.
func (t *table) room(m map[key]entry, k key, now time.Time) bool {
	if _, exists := m[k]; exists {
		return true
	}
	if t.len() < t.max {
		return true
	}
	if now.Sub(t.lastSweep) >= fullSweepEvery {
		t.sweep(now, nil)
	}
	return t.len() < t.max
}

func (t *table) clear(k key) {
	delete(t.denies, k)
	delete(t.challenges, k)
	delete(t.marks, k)
	t.gauge()
}

// sweep drops expired entries and, when zones is given, entries of zones no
// longer configured (the every-zone wildcard is kept).
func (t *table) sweep(now time.Time, zones map[string]*zoneState) {
	t.lastSweep = now
	for _, m := range []map[key]entry{t.denies, t.challenges, t.marks} {
		for k, e := range m {
			if !now.Before(e.until) {
				delete(m, k)
				continue
			}
			if zones != nil && k.zone != "" {
				if _, ok := zones[k.zone]; !ok {
					delete(m, k)
				}
			}
		}
	}
	t.gauge()
}

func (t *table) len() int {
	return len(t.denies) + len(t.challenges) + len(t.marks)
}

func (t *table) gauge() {
	metrics.EdgeVerdictTableEntries.Set(float64(t.len()))
}

// VerdictEntry is one live verdict, for the report. Source is the accounting
// key (an IPv4 address or an IPv6 /64), not a client address. Exactly one of
// Deny, Challenge or a non-empty Mark describes it.
type VerdictEntry struct {
	Zone      string
	Source    netip.Addr
	Deny      bool
	Challenge bool
	Reason    string
	Mark      string
	Until     time.Time
}

// Verdicts snapshots the live verdict table.
func (s *Service) Verdicts() []VerdictEntry {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]VerdictEntry, 0, s.table.len())
	for k, e := range s.table.denies {
		if now.Before(e.until) {
			out = append(out, VerdictEntry{Zone: k.zone, Source: k.src, Deny: true, Reason: e.reason, Until: e.until})
		}
	}
	for k, e := range s.table.challenges {
		if now.Before(e.until) {
			out = append(out, VerdictEntry{Zone: k.zone, Source: k.src, Challenge: true, Reason: e.reason, Until: e.until})
		}
	}
	for k, e := range s.table.marks {
		if now.Before(e.until) {
			out = append(out, VerdictEntry{Zone: k.zone, Source: k.src, Mark: e.mark, Until: e.until})
		}
	}
	return out
}
