package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/render"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// Steering is the node's steering configuration (edge.yaml steering:).
type Steering struct {
	Enabled bool
	// Config is the damping (config.EdgeSteering.SteerConfig).
	Config steer.Config
	// VIPs are the steered addresses, unmapped and zone-less, in edge.yaml's
	// order; empty means the node's implicit target (steer.NodeTarget).
	VIPs []netip.Addr
	// Proc and Prober read the kernel and probe :443. Their zero values are
	// the host's /proc and the production probe; tests replace them.
	Proc   steer.Proc
	Prober steer.Prober
	// JoinRetry spaces the first entry's handshakes of a zone that has not
	// passed yet (steer.Joiner.Retry); 0 is steer's default (10 s). Tests
	// shorten it; edge.yaml has no key for it.
	JoinRetry time.Duration
}

// SteerAnswer is GET /steer's body, and one entry of SteeringStatus.Targets
// (which alone fills Readers). It is the verdict as Verdict.AsOf gives it at
// the request. Times are UTC. Never zone names, prefixes or brain data.
type SteerAnswer struct {
	Target   string        `json:"target"` // steer.NodeKey or the VIP's key
	Verdict  steer.State   `json:"verdict"`
	Reason   steer.Reason  `json:"reason"`
	Since    time.Time     `json:"since,omitzero"`
	RejoinAt time.Time     `json:"rejoin_at,omitzero"`
	Warning  steer.Reason  `json:"warning,omitempty"`
	At       time.Time     `json:"at,omitzero"` // when the verdict was evaluated
	HoldDown SteerHoldDown `json:"hold_down"`
	Inputs   *SteerInputs  `json:"inputs,omitempty"` // nil before the first tick
	Readers  []SteerReader `json:"readers,omitempty"`
}

// SteerHoldDown is a target's ladder (steer.Saved); E7.4's flaps is Level.
type SteerHoldDown struct {
	Level int       `json:"level"`
	Until time.Time `json:"until,omitzero"`
}

// SteerInputs is the tick's steer.Inputs, named for the wire.
type SteerInputs struct {
	Triggers SteerTriggers `json:"triggers"`
	Probe    steer.Class   `json:"probe"`
	Gates    SteerGates    `json:"gates"`
	Drain    *SteerDrain   `json:"drain,omitempty"` // set while triggers.drained
	Report   SteerReport   `json:"report"`
}

// SteerTriggers is the tick's steer.Triggers, named for the wire.
type SteerTriggers struct {
	Refused bool `json:"refused"`
	NotTLS  bool `json:"not_tls"`
	Unbound bool `json:"unbound"`
	Drained bool `json:"drained"`
}

// SteerGates is the tick's steer.Gates, named for the wire.
type SteerGates struct {
	GenerationLive bool `json:"generation_live"`
	Zones          int  `json:"zones"` // a count, never names
	DrainKnown     bool `json:"drain_known"`
}

// SteerDrain is a drain in force: Reason is the drain file's free text (""
// for a bare touch; "new_node" for the first entry), cut to 256 bytes at a
// rune boundary with "…" appended when longer: a hand-written drain file may
// hold up to steer's 1 MiB read bound, and E7.4 copies this into a report the
// brain refuses above 64 KiB.
type SteerDrain struct {
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since,omitzero"`
}

// SteerReport is the tick's steer.Report. The three errors are cut to 512
// bytes, as SteerDrain.Reason is to 256.
type SteerReport struct {
	Terminator  steer.PIDState `json:"terminator"`
	Frozen      bool           `json:"frozen,omitempty"`
	Listening   steer.Tri      `json:"listening"`
	LogProgress steer.Tri      `json:"log_progress"`
	ProbeError  string         `json:"probe_error,omitempty"`
	ProcError   string         `json:"proc_error,omitempty"`
	DrainError  string         `json:"drain_error,omitempty"`
}

// SteerReader is one reader of a target's verdict, as GET /steer's
// ?consumer=NAME&dry=… named it: the name's latest read, and what that read
// was served.
type SteerReader struct {
	Consumer string    `json:"consumer"`
	Dry      bool      `json:"dry"`
	At       time.Time `json:"at"`
	// Verdict and Since are the answer the read was served (SteerAnswer's,
	// after AsOf). -wait counts a read only when they are the target's
	// current verdict and since: this episode, not a read that happened after
	// the change and was served the snapshot before it.
	Verdict steer.State `json:"verdict"`
	Since   time.Time   `json:"since,omitzero"`
}

// SteeringStatus is /healthz's steering object. Reading it stamps nothing.
// Every list in it is bounded (64 targets, 8 readers each, 10 missing zones)
// and every string too, yet the whole object is /healthz's, never a
// report's: at those bounds, every target with its inputs and readers, it is
// several times the 64 KiB the brain accepts in a report. E7.4 copies a
// subset of it, field for field: enabled, drained, targets → vips (target →
// address, verdict, reason, since, rejoin_at, hold_down.level → flaps),
// consumed_at, and consumer's name and dry. Inputs, readers, first_entry,
// at and interval_seconds stay on /healthz.
type SteeringStatus struct {
	Enabled         bool             `json:"enabled"`
	IntervalSeconds int              `json:"interval_seconds,omitempty"`
	At              time.Time        `json:"at,omitzero"`           // the last tick
	Drained         *SteerDrain      `json:"drained,omitempty"`     // node-wide: the operator's node drain, or new_node
	FirstEntry      *SteerFirstEntry `json:"first_entry,omitempty"` // while not known done
	Targets         []SteerAnswer    `json:"targets,omitempty"`     // config order, Readers filled
	ConsumedAt      time.Time        `json:"consumed_at,omitzero"`  // the latest read of any target
	Consumer        *SteerReader     `json:"consumer,omitempty"`    // who made it
}

// SteerFirstEntry is the first entry's progress (steer.FirstEntry), bounded
// for the wire.
type SteerFirstEntry struct {
	Pending steer.Tri `json:"pending"`
	Zones   int       `json:"zones"`
	Ready   int       `json:"ready"`
	// Missing names the first 10 zones not yet ready, sorted; MissingCount
	// counts them all (a new node may carry thousands).
	Missing      []string `json:"missing,omitempty"`
	MissingCount int      `json:"missing_count,omitempty"`
}

// ResetRequestFile is the operator's request to forget hold-downs,
// written into state_dir/steering by `kapkan edge -s reset-holddown`. The
// sampler takes it by renaming it to ResetRequestFile+".taken" — so a take
// and the CLI's cancel never both succeed — applies it, saves state.json and
// removes the taken file.
const ResetRequestFile = "reset-holddown"

// ResetRequest is the body of ResetRequestFile.
type ResetRequest struct {
	All  bool      `json:"all,omitempty"`  // every target
	Keys []string  `json:"keys,omitempty"` // else these target keys
	At   time.Time `json:"at"`
}

// WriteResetRequest writes req as dir/ResetRequestFile atomically (CreateTemp
// in dir, write, chmod 0644, fsync, rename, best-effort dir fsync), replacing
// a pending one. dir must exist. It is never created here: steer.Store
// creates it 0755 itself, and a directory made under an operator's umask
// could hide the drains from an unprivileged -steer.
func WriteResetRequest(dir string, req ResetRequest) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("edge: hold-down reset request: %w", err)
	}
	// The temporary name never matches ResetRequestFile, so the sampler can
	// only ever take a whole request: the rename below is what publishes it.
	f, err := os.CreateTemp(dir, "."+ResetRequestFile+".*.tmp")
	if err != nil {
		return fmt.Errorf("edge: hold-down reset request: %w", err)
	}
	_, err = f.Write(append(raw, '\n'))
	if err == nil {
		// CreateTemp makes it 0600; the request is no secret, and an operator
		// looking at a stuck one should not need root to read it.
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(dir, ResetRequestFile))
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("edge: hold-down reset request: %w", err)
	}
	steerSyncDir(dir)
	return nil
}

// ResetRequestPending reports whether dir/ResetRequestFile still exists.
func ResetRequestPending(dir string) (bool, error) {
	_, err := os.Lstat(filepath.Join(dir, ResetRequestFile))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, fmt.Errorf("edge: hold-down reset request: %w", err)
}

// CancelResetRequest removes a pending request. taken is true when it was
// already gone, because the daemon took it.
func CancelResetRequest(dir string) (taken bool, err error) {
	// The daemon takes a request by renaming it away, so exactly one of the
	// rename and this removal finds the file: a request is either taken or
	// cancelled, never both.
	err = os.Remove(filepath.Join(dir, ResetRequestFile))
	switch {
	case err == nil:
		// A cancel lost to a crash would bring the request back for the next
		// start to apply, long after the operator was told nothing was reset.
		steerSyncDir(dir)
		return false, nil
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	}
	return false, fmt.Errorf("edge: hold-down reset request: %w", err)
}

// ConfRoot is the applier's root under a state_dir (the -steer generation
// gate): filepath.Join(stateDir, "conf"). New uses it too.
func ConfRoot(stateDir string) string {
	return filepath.Join(stateDir, "conf")
}

// LiveZones counts the live generation's zone files
// (ConfRoot/live/render.ZoneFilePrefix*.conf). The CLI's no_zones gate reads
// these because every user may read them, and zones.json is 0600.
func LiveZones(stateDir string) (int, error) {
	// `live` is the applier's symlink to the generation it installed last;
	// reading the directory through it lists that generation's files.
	entries, err := os.ReadDir(filepath.Join(ConfRoot(stateDir), "live"))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if name := e.Name(); strings.HasPrefix(name, render.ZoneFilePrefix) && strings.HasSuffix(name, ".conf") {
			n++
		}
	}
	return n, nil
}

// steerSyncDir makes a rename or a removal in dir durable. Best-effort, as in
// steer's Store: some filesystems refuse fsync on a directory, and the file
// itself was synced already.
func steerSyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
