//go:build !linux

package dataplane

// The non-Linux Manager: a real type with a real Open that always refuses.
//
// This is not a courtesy for macOS developers, it is what keeps internal/app's
// wiring honest. If the data plane were behind a build tag in app.go, the
// darwin developer loop and every unit test that constructs an App would compile
// a DIFFERENT program from the one that ships — and the one place a mistake
// costs most is the wiring that decides whether an operator's configured drop is
// delivered. With a stub, app.go has exactly one code path on every host: call
// Open, and handle the error.
//
// Note what is deliberately absent: Maps(). The map set is the generated
// kapkanXDPMaps, whose helpers need bpf(2), and there is nothing a caller could
// do with it here. A caller that needs it is Linux-only by construction.

import (
	"fmt"
	"runtime"
)

// Manager is the non-Linux placeholder. It is never non-nil: Open is the only
// constructor and it always fails.
type Manager struct{}

// Open always fails with ErrUnsupported, naming the platform.
//
// eBPF is a Linux kernel facility; there is no XDP on darwin, windows or wasm and
// no partial version of it to degrade to. config.validate() accepts a dataplane
// block on any host — it has to, because it compiles to wasm for the kapkan.io
// config builder, where the operator is editing a config for a Linux box from a
// browser — so the refusal belongs here, at the moment something tries to attach.
func Open(opts Options) (*Manager, error) {
	return nil, fmt.Errorf("%w (this binary is %s/%s); set dataplane.enabled: false "+
		"or run kapkan on Linux 5.15 or newer", ErrUnsupported, runtime.GOOS, runtime.GOARCH)
}

// Health reports a disabled data plane. Safe on a nil receiver so a caller can
// render health without knowing which build it is in.
func (m *Manager) Health() Health { return Health{} }

// Stats always fails.
func (m *Manager) Stats() (Snapshot, error) { return Snapshot{}, ErrUnsupported }

// Reload always fails.
func (m *Manager) Reload(Options) (ReloadReport, error) { return ReloadReport{}, ErrUnsupported }

// Reconcile does nothing.
func (m *Manager) Reconcile() {}

// Sizing reports the zero sizing.
func (m *Manager) Sizing() MapSizing { return MapSizing{} }

// EffectiveDryRun reports false: there is no datapath here to rewrite a verdict,
// so claiming dry-run would be as wrong as claiming enforcement.
func (m *Manager) EffectiveDryRun() bool { return false }

// ProfileID never resolves.
func (m *Manager) ProfileID(string) (uint32, bool) { return 0, false }

// Close does nothing.
func (m *Manager) Close(string) error { return nil }
