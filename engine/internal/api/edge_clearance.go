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
// persisted to edge.state_file when one is configured (0600, fsynced, renamed
// into place): without it a brain restart re-keys the fleet and every cleared
// visitor solves a puzzle once more — nodes keep verifying with the keys they
// cached until the new document lands. The file is written as soon as memory
// holds a master the file lacks (a path adopted by a reload mid-day, a save
// that failed), not only at midnight; a file that does not carry this file's
// own kind tag is never overwritten, so a mistyped path cannot destroy an
// operator's file — not the zones file, not the ban state, not a node's cache
// (the last two are JSON with a version of their own).
//
// The document therefore carries SECRETS: an agent-token holder can mint
// clearances for any zone (a bypass of the rung, never of the rate). The
// node caches the document 0600 for that reason. Re-keying after a compromise
// is manual until E4.2's operator endpoint: stop the brain, delete the state
// file, start it — the next document carries fresh keys, and edge-spec §9
// (risk 6) rotates the agent token in the same runbook.

import (
	"bytes"
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
	// clearanceStateKind marks the state file as ours: a file without it is
	// somebody else's and is left alone. A bare version number would not do
	// — the ban state and a node's document cache are JSON with "version": 1
	// too. clearanceStateVersion is this file's own shape version.
	clearanceStateKind    = "kapkan-edge-clearance"
	clearanceStateVersion = 1
)

// clearanceMaster is one epoch's fleet master.
type clearanceMaster struct {
	ID        string    `json:"id"`
	Master    []byte    `json:"master"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

func (m clearanceMaster) valid() bool {
	return len(m.Master) == clearance.SecretLen && m.ID != "" && m.NotAfter.After(m.NotBefore)
}

// clearanceState is the persisted shape.
type clearanceState struct {
	Kind    string            `json:"kind"`
	Version int               `json:"version"`
	Masters []clearanceMaster `json:"masters"`
}

// ours reports whether decoded content is a clearance state file: the kind
// tag, the version and the masters key all present.
func (st clearanceState) ours() bool {
	return st.Kind == clearanceStateKind && st.Version == clearanceStateVersion && st.Masters != nil
}

// clearanceKeyring holds the live masters and derives the document's keys.
type clearanceKeyring struct {
	mu      sync.Mutex
	masters []clearanceMaster
	// path is edge.state_file ("" = memory only); loaded says it was looked
	// at; unusable says its content is not ours and must not be overwritten.
	path     string
	loaded   bool
	unusable bool
	// dirty: memory holds masters the file does not — retried on every
	// snapshot until a save succeeds. saveFailed rate-limits the error log.
	dirty      bool
	saveFailed bool
	log        *slog.Logger
	changed    atomic.Pointer[chan struct{}]
}

func newClearanceKeyring(log *slog.Logger) *clearanceKeyring {
	if log == nil {
		log = slog.Default()
	}
	return &clearanceKeyring{log: log.With("component", "edge-clearance")}
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

// setPath points the keyring at edge.state_file. The file is read once per
// path (a reload may set or change it): its masters are MERGED with the ones
// in memory — memory wins on a duplicate ID, those are the keys nodes already
// hold — and whatever memory holds that the file lacks is written at once.
func (k *clearanceKeyring) setPath(path string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if path == k.path && k.loaded {
		return
	}
	k.path, k.loaded, k.unusable, k.dirty, k.saveFailed = path, true, false, false, false
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	inFile := map[string]bool{}
	switch {
	case errors.Is(err, os.ErrNotExist), err == nil && len(bytes.TrimSpace(raw)) == 0:
		// Absent, or the empty husk a crash between create and rename can
		// leave behind: ours to write.
	case err != nil:
		k.unusable = true
		k.log.Error("clearance state file unreadable; keys stay in memory (a restart re-keys the fleet) until the file is fixed and the brain restarted", "path", path, "err", err)
		return
	default:
		var st clearanceState
		if err := json.Unmarshal(raw, &st); err != nil || !st.ours() {
			k.unusable = true
			k.log.Error("edge.state_file is not a clearance state file; refusing to overwrite it, keys stay in memory (a restart re-keys the fleet) — fix the path or remove the file, then restart", "path", path)
			return
		}
		for _, m := range st.Masters {
			if !m.valid() {
				continue
			}
			inFile[m.ID] = true
			if have, ok := k.getLocked(m.ID); !ok {
				k.masters = append(k.masters, m)
			} else if !bytes.Equal(have.Master, m.Master) {
				// The same epoch, a different master (an older install's
				// file, a restored backup): memory's is the one nodes hold,
				// so the file must be brought up to date.
				k.dirty = true
			}
		}
		k.log.Info("clearance keys loaded", "path", path, "epochs", len(st.Masters))
	}
	for _, m := range k.masters {
		if !inFile[m.ID] {
			k.dirty = true
		}
	}
	k.sortLocked()
	k.flushLocked()
}

func (k *clearanceKeyring) hasLocked(id string) bool {
	_, ok := k.getLocked(id)
	return ok
}

func (k *clearanceKeyring) getLocked(id string) (clearanceMaster, bool) {
	for _, m := range k.masters {
		if m.ID == id {
			return m, true
		}
	}
	return clearanceMaster{}, false
}

func (k *clearanceKeyring) sortLocked() {
	sort.Slice(k.masters, func(i, j int) bool { return k.masters[i].NotBefore.Before(k.masters[j].NotBefore) })
}

// epochStart is the UTC midnight an instant belongs to.
func epochStart(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func epochID(start time.Time) string { return "c" + start.UTC().Format("20060102") }

// ensureLocked makes the current epoch's master exist and drops masters past
// their life. It reports whether the set changed.
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
	if id := epochID(start); !k.hasLocked(id) {
		secret, err := clearance.NewSecret()
		if err != nil {
			return changed, fmt.Errorf("drawing a clearance master: %w", err)
		}
		k.masters = append(k.masters, clearanceMaster{ID: id, Master: secret, NotBefore: start, NotAfter: start.Add(clearanceKeyLife)})
		changed = true
	}
	if changed {
		k.sortLocked()
		k.dirty = true
	}
	k.flushLocked()
	return changed, nil
}

// flushLocked writes the masters when memory is ahead of the file. A failure
// is logged once per streak and retried on every snapshot.
func (k *clearanceKeyring) flushLocked() {
	if !k.dirty || k.path == "" || k.unusable {
		return
	}
	if err := k.saveLocked(); err != nil {
		if !k.saveFailed {
			k.log.Error("persisting clearance keys failed; retrying on every snapshot — until it succeeds a restart re-keys the fleet", "path", k.path, "err", err)
			k.saveFailed = true
		}
		return
	}
	if k.saveFailed {
		k.log.Info("clearance keys persisted", "path", k.path)
	}
	k.dirty, k.saveFailed = false, false
}

// saveLocked writes the state durably: a 0600 temp file beside the path,
// fsynced, renamed over the path, directory fsynced — so a crash leaves
// either the old file or the new one, never a torn or empty husk. The temp
// name is FIXED (<path>.tmp): writes are serialised by the mutex, so a unique
// name would buy nothing, and a crash mid-write then leaves at most one
// husk, which the next write truncates and replaces rather than adding a
// second file of key material beside it.
func (k *clearanceKeyring) saveLocked() error {
	raw, err := json.MarshalIndent(clearanceState{Kind: clearanceStateKind, Version: clearanceStateVersion, Masters: k.masters}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(k.path)
	tmp := k.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, k.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
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
