package decide

import (
	"net/netip"
	"time"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

// entry is one verdict: a deny with its reason, or a mark.
type entry struct {
	deny   bool
	reason string
	mark   string
	until  time.Time
}

// table holds deny/mark verdicts per (zone, source), with "" as the
// every-zone wildcard. Bounded; expired entries are dropped on sweep and on
// a full insert.
type table struct {
	entries map[key]entry
	max     int
}

func newTable(max int) *table {
	return &table{entries: make(map[key]entry), max: max}
}

// lookup returns the live verdict for k: the zone-specific entry first, then
// the every-zone one; nil when neither exists or both have expired.
func (t *table) lookup(k key, now time.Time) *entry {
	if e, ok := t.entries[k]; ok {
		if now.Before(e.until) {
			return &e
		}
		delete(t.entries, k)
	}
	if k.zone != "" {
		wild := key{src: k.src}
		if e, ok := t.entries[wild]; ok {
			if now.Before(e.until) {
				return &e
			}
			delete(t.entries, wild)
		}
	}
	return nil
}

// set installs or replaces k's verdict. When the table is full it drops
// expired entries first; if still full it refuses (false) rather than evict a
// live verdict at random.
func (t *table) set(k key, e entry, now time.Time) bool {
	if _, exists := t.entries[k]; !exists && len(t.entries) >= t.max {
		t.sweep(now)
		if len(t.entries) >= t.max {
			return false
		}
	}
	t.entries[k] = e
	metrics.EdgeVerdictTableEntries.Set(float64(len(t.entries)))
	return true
}

func (t *table) clear(k key) {
	delete(t.entries, k)
	metrics.EdgeVerdictTableEntries.Set(float64(len(t.entries)))
}

func (t *table) sweep(now time.Time) {
	for k, e := range t.entries {
		if !now.Before(e.until) {
			delete(t.entries, k)
		}
	}
	metrics.EdgeVerdictTableEntries.Set(float64(len(t.entries)))
}

func (t *table) len() int {
	return len(t.entries)
}

// VerdictEntry is one live verdict, for the report.
type VerdictEntry struct {
	Zone   string
	Source netip.Addr
	Deny   bool
	Reason string
	Mark   string
	Until  time.Time
}

// Verdicts snapshots the live verdict table.
func (s *Service) Verdicts() []VerdictEntry {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]VerdictEntry, 0, len(s.table.entries))
	for k, e := range s.table.entries {
		if now.Before(e.until) {
			out = append(out, VerdictEntry{Zone: k.zone, Source: k.src, Deny: e.deny, Reason: e.reason, Mark: e.mark, Until: e.until})
		}
	}
	return out
}
