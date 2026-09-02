// Package apply installs a rendered configuration behind the terminator's own
// test — the reload gate of edge-spec §2.4: "a failing candidate is never
// installed, the old config keeps serving, the failure is a report field".
//
// THE LAYOUT. Under Root, each install is a numbered generation directory,
// gen-000001, gen-000002, …, holding the rendered files plus a manifest with
// their content hash; a symlink named `live` points at the generation nginx
// includes (the operator's nginx.conf says `include <Root>/live/*.conf;`). A
// generation is written whole into a temporary directory and renamed into
// place, and the symlink is replaced with a rename, so a reader — nginx
// re-reading its config on reload, an operator looking — sees either the old
// generation or the new one, never a half-written directory. The numbers come
// from what is on disk, so they keep increasing across restarts, and the
// manifest lets a fresh process know what is live without re-rendering.
//
// THE GATE, and why it is swap-test-swap-back. nginx can only test the
// configuration it would actually load, and that configuration includes
// `live/*.conf`, so the candidate is pointed to by `live` BEFORE `nginx -t`
// runs and pointed away again if the test fails. In the milliseconds between,
// `live` names an untested generation, which matters only if nginx were to
// (re)start in exactly that window — a window this package keeps as short as
// the test itself and never widens with a reload. A candidate that passes is
// reloaded into; one that fails is moved aside as failed-N (kept for the
// operator to read) and the previous generation stays live, exactly as it
// was. The rename-based swap-back is the same operation as the swap, so it
// cannot fail in a way the swap could not.
//
// IDEMPOTENCE AND PACE. A render whose bytes equal the live generation's is
// not a change: no directory, no test, no reload — a brain that re-sends an
// unchanged document does not cost a reload storm (edge-spec §2.2). Applies
// are also spaced at least MinInterval apart, counted from the last ATTEMPT,
// so a document that fails the test on every poll cannot hammer `nginx -t`.
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMinInterval spaces applies. One second is far above what a human
	// zone edit produces and far below anything an operator would notice.
	DefaultMinInterval = time.Second
	// DefaultKeep is how many passed generations stay on disk besides the live
	// one — enough to diff "what changed" by hand after an incident.
	DefaultKeep = 3

	liveLink     = "live"
	manifestFile = ".kapkan-manifest"
	genPrefix    = "gen-"
	failedPrefix = "failed-"
)

// ErrTestFailed wraps a Tester failure: the candidate was never installed and
// the previous generation is still live. Result.TestError carries the message.
var ErrTestFailed = errors.New("candidate configuration failed the terminator's test")

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
// are serialised.
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

// Result is what one Apply did, in the terms the node's report uses
// (EdgeReportTerminator: generation, test_ok, test_error).
type Result struct {
	// Generation is the generation that is live after the call: the new one
	// when the test passed, the previous one (0 if none) when it did not.
	Generation uint64
	// Hash is the candidate's content hash.
	Hash string
	// Changed is false when the candidate equalled the live generation and
	// nothing was written, tested or reloaded.
	Changed bool
	// TestOK reports whether the live generation passed the test — true on the
	// unchanged path too, because what is live did pass.
	TestOK bool
	// TestError is the tester's message when TestOK is false.
	TestError string
	// Reloaded reports whether the terminator was told to load the generation.
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

// liveState is what the `live` symlink and its manifest say.
type liveState struct {
	ok     bool
	gen    uint64
	target string
	hash   string
}

// Live reports the generation currently pointed to by `live` and its content
// hash; ok is false when nothing is live or the manifest is unreadable.
func (a *Applier) Live() (gen uint64, hash string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.readLive()
	return st.gen, st.hash, st.ok
}

// Apply installs files as a new generation if they differ from the live one,
// tests, and reloads. See the package doc for the sequence and its guarantees.
func (a *Applier) Apply(ctx context.Context, files map[string][]byte) (Result, error) {
	if a.Root == "" || !filepath.IsAbs(a.Root) {
		return Result{}, fmt.Errorf("apply: root %q must be an absolute path", a.Root)
	}
	if a.Tester == nil {
		return Result{}, errors.New("apply: no tester configured; a configuration is never installed untested")
	}
	if a.Reloader == nil {
		return Result{}, errors.New("apply: no reloader configured")
	}
	if len(files) == 0 {
		return Result{}, errors.New("apply: nothing to install (a render always yields at least the common file)")
	}
	for name := range files {
		if err := checkFileName(name); err != nil {
			return Result{}, fmt.Errorf("apply: %w", err)
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if err := os.MkdirAll(a.Root, 0o755); err != nil {
		return Result{}, fmt.Errorf("apply: %w", err)
	}
	hash := Hash(files)
	live := a.readLive()
	if live.ok && live.hash == hash {
		return Result{Generation: live.gen, Hash: hash, TestOK: true}, nil
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
	if err := writeGeneration(filepath.Join(a.Root, genName), files, hash); err != nil {
		return Result{}, fmt.Errorf("apply: %w", err)
	}
	if err := a.pointLive(genName); err != nil {
		_ = os.RemoveAll(filepath.Join(a.Root, genName))
		return Result{}, fmt.Errorf("apply: %w", err)
	}

	if err := a.Tester.Test(ctx); err != nil {
		// Swap back first — the running terminator must never see the failed
		// candidate on a restart — then move the evidence aside.
		var swapErr error
		if live.ok {
			swapErr = a.pointLive(live.target)
		} else {
			swapErr = os.Remove(filepath.Join(a.Root, liveLink))
		}
		_ = os.Rename(filepath.Join(a.Root, genName), filepath.Join(a.Root, failedPrefix+formatGen(next)))
		a.prune(live.target)
		res := Result{Generation: live.gen, Hash: hash, Changed: true, TestError: err.Error()}
		if swapErr != nil {
			return res, fmt.Errorf("%w: %s; and restoring the previous generation failed: %v", ErrTestFailed, err.Error(), swapErr)
		}
		return res, fmt.Errorf("%w: %s", ErrTestFailed, err.Error())
	}

	res := Result{Generation: next, Hash: hash, Changed: true, TestOK: true}
	a.prune(genName)
	if err := a.Reloader.Reload(ctx); err != nil {
		// The generation is valid and live on disk; the terminator simply did
		// not pick it up yet. The next reload or start will.
		return res, fmt.Errorf("apply: generation %d installed and tested, but reload failed: %w", next, err)
	}
	res.Reloaded = true
	return res, nil
}

// checkFileName admits plain file names only: no separators, no dot-names
// (which would hide from the include glob, or collide with the manifest).
func checkFileName(name string) error {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("file name %q must be a plain name", name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("file name %q must not start with a dot", name)
	}
	return nil
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
	gen, ok := parseGen(target, genPrefix)
	if !ok {
		return liveState{}
	}
	hash, err := readManifest(filepath.Join(a.Root, target))
	if err != nil {
		return liveState{}
	}
	return liveState{ok: true, gen: gen, target: target, hash: hash}
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
			if n, ok := parseGen(e.Name(), prefix); ok && n > max {
				max = n
			}
		}
	}
	return max + 1, nil
}

// pointLive atomically retargets the `live` symlink.
func (a *Applier) pointLive(target string) error {
	tmp := filepath.Join(a.Root, liveLink+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(a.Root, liveLink)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(a.Root)
	return nil
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
