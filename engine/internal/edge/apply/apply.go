// Package apply installs a rendered configuration behind the terminator's own
// test — the reload gate of edge-spec §2.4: "a failing candidate is never
// installed, the old config keeps serving, the failure is a report field".
//
// THE LAYOUT. Under Root, each install is a numbered generation directory,
// gen-000001, gen-000002, …, holding the rendered files, a manifest with their
// content hash, and two markers written as the generation earns them:
// .kapkan-tested once `nginx -t` passed, .kapkan-reloaded once the terminator
// was told to load it. A symlink named `live` points at the generation nginx
// includes (the operator's nginx.conf says `include <Root>/live/*.conf;` — the
// glob never matches the dot-files). A generation is written whole into a
// temporary directory and renamed into place, and the symlink is replaced with
// a rename, so a reader — nginx re-reading its config on reload, an operator
// looking — sees either the old generation or the new one, never a
// half-written directory. Numbers come from what is on disk, so they keep
// increasing across restarts and are never reused; the manifest and markers
// let a fresh process know what is live, and how far it got, without
// re-rendering.
//
// THE GATE, and why it is swap-test-swap-back. nginx can only test the
// configuration it would actually load, and that configuration includes
// `live/*.conf`, so the candidate is pointed to by `live` BEFORE `nginx -t`
// runs and pointed away again if the test fails. In between, `live` names an
// untested generation. That matters if nginx were to (re)start in exactly
// that window — kept as short as the test itself — and it matters if THIS
// process dies in it: the tested marker is what tells the next process that
// the live generation was never verified, so Apply refuses to trust it (the
// idempotence check needs the marker) and Recover, run at startup, tests it
// before anything else. A candidate that passes is marked tested and reloaded
// into; one that fails is moved aside as failed-N (kept for the operator to
// read) and `live` goes back to the previous tested generation — or, when the
// previous link was not one of ours, to exactly what it pointed at before. The
// rename-based swap-back is the same operation as the swap, so it cannot fail
// in a way the swap could not.
//
// IDEMPOTENCE AND PACE. A render whose bytes equal the live, tested
// generation's is not a change: no directory, no test — a brain that re-sends
// an unchanged document does not cost a reload storm (edge-spec §2.2). One
// exception: a generation that passed its test but never reached the
// terminator (a reload that failed, or a crash between test and reload) is
// reloaded on that path, so a missed reload is retried on the next poll rather
// than on the next edit. Applies are also spaced at least MinInterval apart,
// counted from the last ATTEMPT, so a document that fails the test on every
// poll cannot hammer `nginx -t`. Root is locked (flock) for the duration of an
// Apply, so two processes over one directory — the daemon and a one-shot
// debug run — cannot pick the same generation number.
//
// The Tester and Reloader are interfaces so this logic is tested without an
// nginx, and so `nginx -s reload` versus SIGHUP versus `systemctl reload` is a
// deployment choice made where the process is wired up, not here.
package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultMinInterval spaces applies. One second is far above what a human
	// zone edit produces and far below anything an operator would notice.
	DefaultMinInterval = time.Second
	// DefaultKeep is how many passed generations stay on disk besides the live
	// one — enough to diff "what changed" by hand after an incident.
	DefaultKeep = 3

	liveLink       = "live"
	lockFile       = ".kapkan-lock"
	manifestFile   = ".kapkan-manifest"
	testedMarker   = ".kapkan-tested"
	reloadedMarker = ".kapkan-reloaded"
	genPrefix      = "gen-"
	failedPrefix   = "failed-"
)

// ErrTestFailed wraps a Tester failure: the candidate was never installed and
// the previous generation is still live. Result.TestError carries the message;
// the tester's own error is wrapped too, for errors.Is.
var ErrTestFailed = errors.New("candidate configuration failed the terminator's test")

// failedZoneRe finds the zone file nginx blamed: `… in /…/kapkan_zone_<name>.conf:12`.
var failedZoneRe = regexp.MustCompile(`kapkan_zone_([a-z0-9.-]+)\.conf:[0-9]+`)

// Tester runs the terminator's configuration test (`nginx -t`) against what
// `live` currently points to.
type Tester interface {
	Test(ctx context.Context) error
}

// Reloader makes the running terminator load the live generation.
type Reloader interface {
	Reload(ctx context.Context) error
}

// Applier installs generations under Root. Safe for concurrent use; applies
// are serialised within the process by a mutex and across processes by a lock
// file in Root.
type Applier struct {
	// Root is the configuration directory (absolute). Created if missing.
	Root     string
	Tester   Tester
	Reloader Reloader
	// MinInterval spaces applies; 0 means DefaultMinInterval.
	MinInterval time.Duration
	// Keep is how many passed generations to retain besides the live one; 0
	// means DefaultKeep.
	Keep int

	mu          sync.Mutex
	lastAttempt time.Time
}

// Result is what one Apply (or Recover) did, in the terms the node's report
// uses (EdgeReportTerminator: generation, test_ok, test_error).
type Result struct {
	// Generation is the generation that is live after the call: the new one
	// when the test passed, the restored one (0 if none) when it did not.
	Generation uint64
	// Hash is the candidate's content hash.
	Hash string
	// Changed is false when the candidate equalled the live generation and
	// nothing was written or tested.
	Changed bool
	// TestOK reports whether the live generation passed the test — true on the
	// unchanged path too, because what is live did pass.
	TestOK bool
	// TestError is the tester's message when TestOK is false.
	TestError string
	// FailedZone is the zone whose file the tester blamed, parsed from its
	// "in <file>:<line>" message; "" when it named the common file or nothing.
	FailedZone string
	// Reloaded reports whether the terminator was told to load the generation
	// during this call.
	Reloaded bool
}

// Hash is the content hash Apply compares against the live generation's:
// every file, name-ordered, with names and lengths mixed in.
func Hash(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		_, _ = h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// liveState is what the `live` symlink and its generation say.
type liveState struct {
	// exists: `live` is a symlink to something (target is its raw value).
	exists bool
	target string
	// gen is the parsed generation number, 0 when target is not one of ours.
	gen uint64
	// hash is the manifest's content hash, "" when unreadable.
	hash     string
	tested   bool
	reloaded bool
	// ok: a generation of ours with a readable manifest that passed its test —
	// the only state the idempotence check may trust.
	ok bool
}

// Live reports the generation currently pointed to by `live` and its content
// hash; ok is false when nothing is live, when the link is not a kapkan
// generation, or when that generation never passed its test.
func (a *Applier) Live() (gen uint64, hash string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.readLive()
	return st.gen, st.hash, st.ok
}

// Apply installs files as a new generation if they differ from the live one,
// tests, and reloads. See the package doc for the sequence and its guarantees.
func (a *Applier) Apply(ctx context.Context, files map[string][]byte) (Result, error) {
	if err := a.checkWired(); err != nil {
		return Result{}, err
	}
	if len(files) == 0 {
		return Result{}, errors.New("apply: nothing to install (a render always yields at least the common file)")
	}
	for name := range files {
		if err := checkFileName(name); err != nil {
			return Result{}, fmt.Errorf("apply: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	unlock, err := a.lockRoot()
	if err != nil {
		return Result{}, fmt.Errorf("apply: %w", err)
	}
	defer unlock()

	hash := Hash(files)
	live := a.readLive()
	if live.ok && live.hash == hash {
		res := Result{Generation: live.gen, Hash: hash, TestOK: true}
		if !live.reloaded {
			// Tested, never loaded: a failed reload, or a crash between the
			// two. Retry now, not when the document next changes.
			if err := a.Reloader.Reload(ctx); err != nil {
				return res, fmt.Errorf("apply: generation %d is live and tested, but reload failed: %w", live.gen, err)
			}
			_ = a.mark(live.target, reloadedMarker)
			res.Reloaded = true
		}
		return res, nil
	}

	if err := a.waitInterval(ctx); err != nil {
		return Result{}, err
	}
	a.lastAttempt = time.Now()

	next, err := a.nextGeneration()
	if err != nil {
		return Result{}, fmt.Errorf("apply: %w", err)
	}
	genName := genPrefix + formatGen(next)
	dir := filepath.Join(a.Root, genName)
	if err := writeGeneration(dir, files, hash); err != nil {
		return Result{}, fmt.Errorf("apply: %w", err)
	}
	if err := a.pointLive(genName); err != nil {
		_ = os.RemoveAll(dir)
		return Result{}, fmt.Errorf("apply: %w", err)
	}

	if err := a.Tester.Test(ctx); err != nil {
		// Swap back first — the running terminator must never see the failed
		// candidate on a restart — then deal with the evidence.
		nowLive, restoreErr := a.restore(live)
		res := Result{Generation: nowLive, Hash: hash, Changed: true, TestError: err.Error(), FailedZone: failedZone(err.Error())}
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The caller gave up, the test did not finish: no verdict on the
			// candidate, so it is not kept as a failure.
			_ = os.RemoveAll(dir)
			return res, ctxErr
		}
		_ = os.Rename(dir, filepath.Join(a.Root, failedPrefix+formatGen(next)))
		a.prune(a.readLive().target)
		if restoreErr != nil {
			return res, fmt.Errorf("%w: %w; and restoring the previous generation failed: %v", ErrTestFailed, err, restoreErr)
		}
		return res, fmt.Errorf("%w: %w", ErrTestFailed, err)
	}
	if err := a.mark(genName, testedMarker); err != nil {
		// Live and tested, but the next process could not know that; better
		// to report it than to reload on a state we cannot record.
		return Result{Generation: next, Hash: hash, Changed: true, TestOK: true},
			fmt.Errorf("apply: generation %d passed its test, but recording that failed: %w", next, err)
	}

	res := Result{Generation: next, Hash: hash, Changed: true, TestOK: true}
	a.prune(genName)
	if err := a.Reloader.Reload(ctx); err != nil {
		// The generation is valid and live on disk; the terminator simply did
		// not pick it up. The next Apply retries the reload (unchanged path).
		return res, fmt.Errorf("apply: generation %d installed and tested, but reload failed: %w", next, err)
	}
	_ = a.mark(genName, reloadedMarker)
	res.Reloaded = true
	return res, nil
}

// Recover settles what a previous process may have left behind and should run
// once at startup, before the first Apply: a `live` generation without the
// tested marker (the process died between the swap and the test) is tested
// now — marked on a pass, or moved aside as failed-N with `live` pointed back
// at the newest tested generation on a failure — and a half-written
// generation directory is removed. Result.Changed reports whether anything
// had to be done; a passing generation that was never reloaded is left for
// Apply's unchanged path to reload.
func (a *Applier) Recover(ctx context.Context) (Result, error) {
	if err := a.checkWired(); err != nil {
		return Result{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	unlock, err := a.lockRoot()
	if err != nil {
		return Result{}, fmt.Errorf("recover: %w", err)
	}
	defer unlock()

	a.removeTemporaries()
	live := a.readLive()
	if !live.exists || live.gen == 0 || live.tested {
		return Result{Generation: live.gen, Hash: live.hash, TestOK: live.ok}, nil
	}
	dir := filepath.Join(a.Root, live.target)
	if err := a.Tester.Test(ctx); err != nil {
		nowLive, restoreErr := a.restore(liveState{})
		res := Result{Generation: nowLive, Hash: live.hash, Changed: true, TestError: err.Error(), FailedZone: failedZone(err.Error())}
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Undo nothing else: the generation stays where it was for the
			// next Recover to judge.
			_ = a.pointLive(live.target)
			return res, ctxErr
		}
		_ = os.Rename(dir, filepath.Join(a.Root, failedPrefix+formatGen(live.gen)))
		if restoreErr != nil {
			return res, fmt.Errorf("%w: %w; and restoring the previous generation failed: %v", ErrTestFailed, err, restoreErr)
		}
		return res, fmt.Errorf("%w: %w", ErrTestFailed, err)
	}
	if err := a.mark(live.target, testedMarker); err != nil {
		return Result{Generation: live.gen, Hash: live.hash, Changed: true, TestOK: true},
			fmt.Errorf("recover: generation %d passed its test, but recording that failed: %w", live.gen, err)
	}
	return Result{Generation: live.gen, Hash: live.hash, Changed: true, TestOK: true}, nil
}

func (a *Applier) checkWired() error {
	if a.Root == "" || !filepath.IsAbs(a.Root) {
		return fmt.Errorf("apply: root %q must be an absolute path", a.Root)
	}
	if a.Tester == nil {
		return errors.New("apply: no tester configured; a configuration is never installed untested")
	}
	if a.Reloader == nil {
		return errors.New("apply: no reloader configured")
	}
	return nil
}

// checkFileName admits plain file names only: no separators, no dot-names
// (which would hide from the include glob, or collide with the markers).
func checkFileName(name string) error {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("file name %q must be a plain name", name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("file name %q must not start with a dot", name)
	}
	return nil
}

// lockRoot creates Root and takes an exclusive advisory lock on a file in it,
// so two Applier values — in one process or two — never interleave.
func (a *Applier) lockRoot() (func(), error) {
	if err := os.MkdirAll(a.Root, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(a.Root, lockFile), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", lockFile, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func (a *Applier) waitInterval(ctx context.Context) error {
	interval := a.MinInterval
	if interval <= 0 {
		interval = DefaultMinInterval
	}
	if a.lastAttempt.IsZero() {
		return nil
	}
	wait := interval - time.Since(a.lastAttempt)
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *Applier) readLive() liveState {
	target, err := os.Readlink(filepath.Join(a.Root, liveLink))
	if err != nil {
		return liveState{}
	}
	st := liveState{exists: true, target: target}
	gen, ok := parseGen(target, genPrefix)
	if !ok {
		return st
	}
	st.gen = gen
	dir := filepath.Join(a.Root, target)
	if h, err := readManifest(dir); err == nil {
		st.hash = h
	}
	st.tested = fileExists(filepath.Join(dir, testedMarker))
	st.reloaded = fileExists(filepath.Join(dir, reloadedMarker))
	st.ok = st.hash != "" && st.tested
	return st
}

// restore points `live` back after a failed test: at the previous generation
// when it was a tested one of ours; else at the newest tested generation on
// disk; else at exactly what the link named before (an untested generation or
// a foreign target is still what the operator had); else it removes the link.
// It returns the generation now live (0 when none of ours).
func (a *Applier) restore(prev liveState) (uint64, error) {
	if prev.ok {
		return prev.gen, a.pointLive(prev.target)
	}
	if name, gen := a.newestTested(); name != "" {
		return gen, a.pointLive(name)
	}
	if prev.exists {
		return prev.gen, a.pointLive(prev.target)
	}
	if err := os.Remove(filepath.Join(a.Root, liveLink)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	return 0, nil
}

// newestTested finds the highest-numbered generation carrying the tested
// marker; "" when there is none.
func (a *Applier) newestTested() (string, uint64) {
	entries, err := os.ReadDir(a.Root)
	if err != nil {
		return "", 0
	}
	var best uint64
	for _, e := range entries {
		n, ok := parseGen(e.Name(), genPrefix)
		if ok && n > best && fileExists(filepath.Join(a.Root, e.Name(), testedMarker)) {
			best = n
		}
	}
	if best == 0 {
		return "", 0
	}
	return genPrefix + formatGen(best), best
}

// nextGeneration is one above the highest number on disk, passed or failed, so
// a number is never reused while a directory bearing it may still exist.
func (a *Applier) nextGeneration() (uint64, error) {
	entries, err := os.ReadDir(a.Root)
	if err != nil {
		return 0, err
	}
	var max uint64
	for _, e := range entries {
		for _, prefix := range []string{genPrefix, failedPrefix} {
			if n, ok := parseGen(strings.TrimSuffix(e.Name(), ".tmp"), prefix); ok && n > max {
				max = n
			}
		}
	}
	return max + 1, nil
}

// removeTemporaries deletes half-written generation directories a crashed
// process left behind.
func (a *Applier) removeTemporaries() {
	entries, err := os.ReadDir(a.Root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), genPrefix) && strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.RemoveAll(filepath.Join(a.Root, e.Name()))
		}
	}
}

// pointLive atomically retargets the `live` symlink. An operator who created
// `live` by hand as a DIRECTORY (to make nginx's wildcard include compile
// before the first render) would otherwise wedge every install forever — a
// rename cannot replace a directory with a symlink — so an empty directory is
// removed and a populated one is refused with a message that says what to do.
func (a *Applier) pointLive(target string) error {
	live := filepath.Join(a.Root, liveLink)
	if fi, err := os.Lstat(live); err == nil && fi.IsDir() {
		entries, err := os.ReadDir(live)
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			return fmt.Errorf("%s is a directory with %d entries, not the symlink kapkan manages; move its contents away and remove it", live, len(entries))
		}
		if err := os.Remove(live); err != nil {
			return err
		}
	}
	tmp := filepath.Join(a.Root, liveLink+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, live); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(a.Root)
	return nil
}

// mark records a milestone for a generation (tested, reloaded).
func (a *Applier) mark(gen, marker string) error {
	return writeSynced(filepath.Join(a.Root, gen, marker), []byte("ok\n"))
}

// prune removes passed generations beyond Keep (never the one named keep) and
// every failed generation but the newest.
func (a *Applier) prune(keep string) {
	entries, err := os.ReadDir(a.Root)
	if err != nil {
		return
	}
	limit := a.Keep
	if limit <= 0 {
		limit = DefaultKeep
	}
	var gens, failed []uint64
	for _, e := range entries {
		if n, ok := parseGen(e.Name(), genPrefix); ok {
			gens = append(gens, n)
		} else if n, ok := parseGen(e.Name(), failedPrefix); ok {
			failed = append(failed, n)
		}
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i] > gens[j] })
	sort.Slice(failed, func(i, j int) bool { return failed[i] > failed[j] })
	kept := 0
	for _, n := range gens {
		name := genPrefix + formatGen(n)
		if name == keep {
			continue
		}
		if kept < limit {
			kept++
			continue
		}
		_ = os.RemoveAll(filepath.Join(a.Root, name))
	}
	for i, n := range failed {
		if i == 0 {
			continue
		}
		_ = os.RemoveAll(filepath.Join(a.Root, failedPrefix+formatGen(n)))
	}
}

// writeGeneration writes the files and manifest into dir.tmp, fsyncs them and
// renames the directory into place.
func writeGeneration(dir string, files map[string][]byte, hash string) error {
	tmp := dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := writeSynced(filepath.Join(tmp, n), files[n]); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}
	manifest := fmt.Sprintf("hash %s\nfiles %d\n", hash, len(files))
	if err := writeSynced(filepath.Join(tmp, manifestFile), []byte(manifest)); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	syncDir(filepath.Dir(dir))
	return nil
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir makes a rename durable. Best-effort: some filesystems refuse fsync
// on a directory, and durability of the symlink is not what the gate protects.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

func readManifest(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if h, ok := strings.CutPrefix(line, "hash "); ok {
			return strings.TrimSpace(h), nil
		}
	}
	return "", errors.New("manifest has no hash line")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// failedZone extracts the zone a tester message blamed, if it named a zone file.
func failedZone(msg string) string {
	if m := failedZoneRe.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	return ""
}

func formatGen(n uint64) string {
	return fmt.Sprintf("%06d", n)
}

func parseGen(name, prefix string) (uint64, bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" || strings.ContainsAny(rest, "./") {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}
