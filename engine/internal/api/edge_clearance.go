package api

// The brain's half of the edge's proof-of-work rung (edge-spec §5; milestone
// E4.1): the CLEARANCE KEYRING. A node challenges a client with a puzzle and,
// once solved, hands it a cookie signed with the zone's clearance key; every
// node of the fleet must verify that cookie, so the key travels to all of them
// in the zone document. The brain holds one fleet MASTER per epoch and derives
// each zone's key from it with HKDF (clearance.DeriveZoneKey), so nothing is
// stored per zone and the document stays deterministic — the ETag moves
// exactly when an epoch begins or ends, never because a key was re-drawn.
//
// Epochs are UTC days: the key that starts at midnight is honoured for 48 h,
// so a cookie issued just before a rotation still verifies on the day after
// (two keys live per zone; nodes issue under the newest). The masters are
// persisted to edge.state_file when one is configured (0600, written whole);
// without it a brain restart re-keys the fleet and every cleared visitor
// solves a puzzle once more — nodes keep verifying with the keys they cached
// until the new document lands.
//
// The document therefore carries SECRETS: an agent-token holder can mint
// clearances for any zone (a bypass of the rung, never of the rate). The
// node caches the document 0600 for that reason, and the runbook rotates the
// state file's epoch together with the agent token.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

const (
	// clearanceEpoch is how often the fleet master rotates; clearanceKeyLife
	// is how long a key stays honoured after its epoch began (two epochs
	// live), so a cookie's TTL must stay well under the difference.
	clearanceEpoch   = 24 * time.Hour
	clearanceKeyLife = 2 * clearanceEpoch
)

// clearanceMaster is one epoch's fleet master.
type clearanceMaster struct {
	ID        string    `json:"id"`
	Master    []byte    `json:"master"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// clearanceState is the persisted shape.
type clearanceState struct {
	Masters []clearanceMaster `json:"masters"`
}

// clearanceKeyring holds the live masters and derives the document's keys.
type clearanceKeyring struct {
	mu      sync.Mutex
	masters []clearanceMaster
	path    string // "" = memory only
	loaded  bool
	log     *slog.Logger
	changed atomic.Pointer[chan struct{}]
	// newSecret and now are seams for tests.
	newSecret func() ([]byte, error)
	now       func() time.Time
}

func newClearanceKeyring(log *slog.Logger) *clearanceKeyring {
	if log == nil {
		log = slog.Default()
	}
	return &clearanceKeyring{log: log.With("component", "edge-clearance"), newSecret: clearance.NewSecret, now: time.Now}
}

// Changed returns a channel closed on the next rotation — the Store.Changed
// idiom the zones long-poll already selects on.
func (k *clearanceKeyring) Changed() <-chan struct{} {
	for {
		if p := k.changed.Load(); p != nil {
			return *p
		}
		ch := make(chan struct{})
		if k.changed.CompareAndSwap(nil, &ch) {
			return ch
		}
	}
}

func (k *clearanceKeyring) notify() {
	if p := k.changed.Swap(nil); p != nil {
		close(*p)
	}
}

// setPath points the keyring at edge.state_file; the file is read once, when
// the path is first seen (a reload may set it), and written on every rotation.
func (k *clearanceKeyring) setPath(path string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if path == k.path && (k.loaded || path == "") {
		return
	}
	k.path, k.loaded = path, true
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		k.log.Error("clearance state file unreadable; starting with fresh keys", "path", path, "err", err)
		return
	}
	var st clearanceState
	if err := json.Unmarshal(raw, &st); err != nil {
		k.log.Error("clearance state file is not valid JSON; starting with fresh keys", "path", path, "err", err)
		return
	}
	var kept []clearanceMaster
	for _, m := range st.Masters {
		if len(m.Master) == clearance.SecretLen && m.ID != "" && m.NotAfter.After(m.NotBefore) {
			kept = append(kept, m)
		}
	}
	k.masters = kept
	k.log.Info("clearance keys loaded", "path", path, "epochs", len(kept))
}

// epochStart is the UTC midnight an instant belongs to.
func epochStart(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func epochID(start time.Time) string { return "c" + start.UTC().Format("20060102") }

// ensureLocked makes the current epoch's master exist and drops masters past
// their life. It reports whether anything changed.
func (k *clearanceKeyring) ensureLocked(now time.Time) (bool, error) {
	changed := false
	live := k.masters[:0]
	for _, m := range k.masters {
		if now.Before(m.NotAfter) {
			live = append(live, m)
		} else {
			changed = true
		}
	}
	k.masters = live
	start := epochStart(now)
	id := epochID(start)
	have := false
	for _, m := range k.masters {
		if m.ID == id {
			have = true
			break
		}
	}
	if !have {
		secret, err := k.newSecret()
		if err != nil {
			return changed, fmt.Errorf("drawing a clearance master: %w", err)
		}
		k.masters = append(k.masters, clearanceMaster{ID: id, Master: secret, NotBefore: start, NotAfter: start.Add(clearanceKeyLife)})
		changed = true
	}
	sort.Slice(k.masters, func(i, j int) bool { return k.masters[i].NotBefore.Before(k.masters[j].NotBefore) })
	if changed && k.path != "" {
		if err := k.saveLocked(); err != nil {
			k.log.Error("persisting clearance keys failed; a restart will re-key the fleet", "path", k.path, "err", err)
		}
	}
	return changed, nil
}

func (k *clearanceKeyring) saveLocked() error {
	raw, err := json.MarshalIndent(clearanceState{Masters: k.masters}, "", "  ")
	if err != nil {
		return err
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, k.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(k.path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// fill adds every zone's live clearance keys to the document. Deterministic
// for one set of masters: the same zones yield the same bytes.
func (k *clearanceKeyring) fill(doc *edgedoc.Doc, now time.Time) {
	k.mu.Lock()
	changed, err := k.ensureLocked(now)
	masters := make([]clearanceMaster, len(k.masters))
	copy(masters, k.masters)
	k.mu.Unlock()
	if err != nil {
		k.log.Error("clearance keyring unavailable; the document carries no clearance keys", "err", err)
		return
	}
	if changed {
		k.notify()
	}
	for i := range doc.Zones {
		z := &doc.Zones[i]
		z.ClearanceKeys = z.ClearanceKeys[:0]
		for _, m := range masters {
			secret, err := clearance.DeriveZoneKey(m.Master, z.Name)
			if err != nil {
				continue
			}
			z.ClearanceKeys = append(z.ClearanceKeys, edgedoc.ClearanceKey{
				ID: m.ID, Secret: base64.RawURLEncoding.EncodeToString(secret), NotBefore: m.NotBefore, NotAfter: m.NotAfter,
			})
		}
	}
}

// untilNextChange is how long the current key set stays as it is: until the
// next UTC midnight (a new epoch) or the earliest expiry, whichever comes
// first — what a parked poll must wake for.
func (k *clearanceKeyring) untilNextChange(now time.Time) time.Duration {
	next := epochStart(now).Add(clearanceEpoch)
	k.mu.Lock()
	for _, m := range k.masters {
		if m.NotAfter.After(now) && m.NotAfter.Before(next) {
			next = m.NotAfter
		}
	}
	k.mu.Unlock()
	d := next.Sub(now)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// clearanceKeysFor decodes a zone's keys as a node would — for the tests
// here; the node-side decoder lives with the decision service (E4.2).
func clearanceKeysFor(doc *edgedoc.Doc, zone string) []clearance.Key {
	for _, z := range doc.Zones {
		if z.Name != zone {
			continue
		}
		out := make([]clearance.Key, 0, len(z.ClearanceKeys))
		for _, ck := range z.ClearanceKeys {
			secret, err := base64.RawURLEncoding.DecodeString(ck.Secret)
			if err != nil {
				continue
			}
			out = append(out, clearance.Key{ID: ck.ID, Secret: secret, NotBefore: ck.NotBefore, NotAfter: ck.NotAfter})
		}
		return out
	}
	return nil
}
