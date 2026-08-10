//go:build !linux

package dataplane

// The non-Linux Installer, for the same reason manager_stub.go exists: so that
// internal/app has ONE code path on every host.
//
// The mitigator's data-plane backend is wired in app.New, which is compiled and
// unit-tested on the macOS development host. If NewInstaller only existed on
// Linux, that wiring would have to sit behind a build tag, and the darwin
// developer loop would compile a different program from the one that ships —
// in exactly the place that decides whether an operator's configured drop is
// delivered.
//
// Every method refuses, and refuses LOUDLY rather than silently succeeding: a
// no-op Install would tell the mitigator its rules are in the kernel when there
// is no kernel, and the ban would record an enforcing mitigation that does not
// exist. An error makes the mitigator fall back to its configured method
// (blackhole), which is the honest answer. In practice this is unreachable —
// Open() has already failed on this platform, so app never constructs an
// Installer — but "unreachable" is not a property to rely on for a safety
// behaviour.

import (
	"log/slog"
	"net/netip"
)

// Installer is the non-Linux placeholder.
type Installer struct{}

// NewInstaller returns an Installer that always refuses.
func NewInstaller(*Manager, *slog.Logger) *Installer { return &Installer{} }

// Install always fails with ErrUnsupported.
func (i *Installer) Install(netip.Prefix, DynamicRules) error { return ErrUnsupported }

// Withdraw always fails with ErrUnsupported.
func (i *Installer) Withdraw(netip.Prefix) error { return ErrUnsupported }

// Counters reports that nothing is installed, rather than failing.
//
// It is the one method here that does NOT refuse loudly, and the asymmetry is
// the point. Install and Withdraw are asked to change enforcement, so a silent
// success would be a lie about whether an operator's drop is happening. This is
// asked "how much did your rules catch", and the truthful answer on a host with
// no data plane is "there are no rules of mine here" — which is exactly what
// ok=false means to every caller. Returning an error instead would make the
// scrape loop log a failure once per interval, forever, on a machine where
// nothing is wrong.
func (i *Installer) Counters(netip.Prefix) (VictimCounters, bool, error) {
	return VictimCounters{}, false, nil
}
