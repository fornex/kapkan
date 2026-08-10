//go:build linux

package dataplane

// THE PRIVILEGE GATE for the Linux-only half of this package.
//
// These files are tagged `//go:build linux`, which on the macOS development
// host means they do not exist: `make test` never compiles them, so nothing in
// the local loop can tell you how they behave on a machine that HAS a kernel
// but not the right to program it. CI is exactly that machine — the ordinary
// `build & test (race)` job runs on ubuntu as a non-root user with no CAP_BPF —
// and without this file the whole suite compiled there and died on the first
// syscall.
//
// The gate answers one question once per process — may this process program the
// kernel? — and it answers it by DOING the cheap half rather than by reading
// capability bits alone, because the capability bits are not the only input
// (kernel.unprivileged_bpf_disabled, LSM hooks and seccomp filters all get a
// say). See probeBPF for what it does and for the measurement that shows why
// half of it is not enough.
//
// TWO THINGS THIS GATE IS DESIGNED NOT TO DO.
//
//  1. It does not skip more than it must. A skipped suite is a green job that
//     checked nothing, which is strictly worse than the red one it replaced:
//     ~125 tests silently becoming ~125 skips would retire every guarantee this
//     branch makes while the badge stayed green. So the gate is applied at the
//     points where a test actually reaches for the kernel — loadObjects,
//     testOptions/mustOpen, bpffsRoot, ivBpffs — and NOT to the tests that need
//     no privilege at all. Those keep running unprivileged, on every host, and
//     that is deliberate: see the list in the package's CI notes below.
//
//  2. It does not paper over a real failure. The probe creates a MAP. No
//     program is loaded, so the verifier is never invoked, so the probe cannot
//     produce a verifier verdict and cannot mistake one for a missing
//     privilege. That distinction is the whole reason skipIfUnprivileged (in
//     smoke_linux_test.go) is narrow — EPERM skips, EACCES does not, because
//     EACCES is what the kernel returns when the verifier REJECTS a program —
//     and this file leaves that discipline exactly where it was. A probe
//     failure that is not one of the recognised "you may not do this here"
//     errnos is a FATAL error, not a skip.
//
// THE TRIPWIRE. `KAPKAN_DATAPLANE=require` turns every skip in this package
// into a failure, and is set by the two paths whose entire job is to run these
// tests against a real kernel: `make dataplane-test` and the CI `XDP data
// plane` job (plus the kernel-matrix guest, which sets it in vminit.sh). Same
// knob, same reasoning, as KAPKAN_BLOCKRATE=require on the pcap suite and
// KAPKAN_BPF_DRIFT=require on the object drift gate: a gate that quietly
// degrades to a skip when the environment shifts — a runner image without
// bpffs, a capability set trimmed one bit too far — keeps reporting green
// while measuring nothing. On top of that, TestMain refuses to report success
// under `require` if implausibly few tests made it through the gate, so an
// all-skip run cannot read as a pass even if some future change stops calling
// skipOrFail on the way out.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// requireEnv names the knob that turns this package's environment skips into
// failures.
const requireEnv = "KAPKAN_DATAPLANE"

func kernelRequired() bool { return os.Getenv(requireEnv) == "require" }

// skipOrFail skips on a host that cannot run the kernel half — an unprivileged
// CI runner, a container with no bpffs — unless KAPKAN_DATAPLANE=require, in
// which case it FAILS.
//
// Every environment skip in this package goes through here. That is the point:
// there is one place to look to find out what this suite is allowed to decline
// to test, and one switch that takes the permission away.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if kernelRequired() {
		t.Fatalf(requireEnv+"=require: "+format, args...)
	}
	t.Skipf(format, args...)
}

/* ------------------------------------------------------------ the probe */

var bpfProbe struct {
	sync.Once
	err error
}

// probeBPF asks the two questions that between them decide whether this process
// can run the kernel half, in the order in which they can be answered cheaply.
//
// 1. CAN I CALL bpf(2) AT ALL? Measured by creating and immediately closing a
// one-entry array map — the cheapest thing the syscall will do, and no program,
// so the verifier is never involved and nothing here can fail for a reason that
// is about kapkan_xdp.c.
//
// 2. DO I HOLD WHAT LOADING AN XDP PROGRAM NEEDS? Question 1 alone is not
// enough, and finding that out is what this gate cost: on Docker Desktop's
// LinuxKit kernel /proc/sys/kernel/unprivileged_bpf_disabled is 0, so a process
// with CapEff=0x0 creates that array map quite happily — and then every test
// failed anyway, because loading an XDP program additionally needs CAP_NET_ADMIN
// (program type) and CAP_PERFMON (the verifier's allow_ptr_leaks IS
// perfmon_capable(), and the parser subtracts data_end - data). On Ubuntu, where
// unprivileged_bpf_disabled is 2, question 1 does catch it — so a gate built on
// question 1 alone would have looked correct in CI and been wrong on the
// developer's own machine.
//
// checkCapabilities is PRODUCTION's answer to question 2, not a second opinion
// written for the tests, which is deliberate twice over: it is the exact check
// Manager.Open performs, so the gate skips precisely when Open would refuse; and
// its correctness is independently pinned by TestCapabilityProbeAgreesWithReality,
// which is NOT gated and which fails if the check ever refuses a process that can
// in fact load the program. Without that test this would be a gate marking its
// own homework.
func probeBPF() error {
	// Kernels below 5.11 charge map memory against RLIMIT_MEMLOCK. Production
	// does this too (see loadObjects); doing it here keeps the probe's answer
	// the same as the answer the real load would get.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove the memlock rlimit: %w", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kapkan_capprobe",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return err
	}
	if err := m.Close(); err != nil {
		return err
	}
	return checkCapabilities()
}

// bpfRefused reports whether err means "this host will not let this process use
// bpf(2)", as opposed to "something is broken".
//
// EACCES is in this list and is NOT a contradiction of skipIfUnprivileged's
// EPERM-only rule. That rule exists because a *program load* reports a verifier
// rejection as EACCES. probeBPF loads no program; an EACCES from a bare map
// creation comes from an LSM hook (SELinux, Landlock, a seccomp filter), which
// is an environment fact, not a bug in the program.
//
// ErrMissingCapability is the answer to probeBPF's second question and means the
// same thing: the process is short a capability Manager.Open requires. Note what
// is NOT here — a *ebpf.VerifierError, or anything else checkCapabilities might
// return if reading /proc/self/status broke. Those reach requireBPF's t.Fatalf.
func bpfRefused(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, ErrMissingCapability)
}

// requireBPF skips (or, under KAPKAN_DATAPLANE=require, fails) unless this
// process may use bpf(2). The probe runs once per process and the answer is
// cached: it is a syscall pair, but it is also the thing 125 tests would
// otherwise each rediscover.
func requireBPF(t *testing.T) {
	t.Helper()
	bpfProbe.Do(func() { bpfProbe.err = probeBPF() })
	if bpfProbe.err == nil {
		admit(t)
		return
	}
	if !bpfRefused(bpfProbe.err) {
		t.Fatalf("the bpf(2) capability probe failed for a reason that is not a missing "+
			"privilege: %v\nThat is a broken host or a broken probe. Skipping on it would hide "+
			"whatever it is, so this is a failure on purpose", bpfProbe.err)
	}
	skipOrFail(t, "this process cannot program the kernel here: %v\nRun `make dataplane-test` "+
		"for the privileged-container loop", bpfProbe.err)
}

// RequireBPF, BpffsRoot and SkipOrFail are the gate as seen by the external
// dataplane_test package, which holds the two end-to-end tests and cannot reach
// unexported identifiers. They are declared in an internal test file, so they
// exist only in the test binary and add nothing to the shipped package.
//
// Deliberately NOT named with a Test prefix: `go test` would take that for a
// test function and run it.
func RequireBPF(t *testing.T) {
	t.Helper()
	requireBPF(t)
}

func BpffsRoot(t *testing.T) string {
	t.Helper()
	return bpffsRoot(t)
}

func SkipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	skipOrFail(t, format, args...)
}

/* -------------------------------------------------------- usable bpffs */

// usableBpffs reports whether path is a bpffs THIS PROCESS CAN CREATE PINS IN.
//
// Both halves are load-bearing, and the second one is the half that was
// missing. On a GitHub runner /sys/fs/bpf is already a bpffs — systemd mounts
// it — so a magic check alone says "yes" and every subsequent mkdir fails with
// EACCES, because the mount is root-owned mode 0700 and the CI job that runs
// these tests deliberately holds three capabilities and no more (none of them
// CAP_DAC_OVERRIDE). Probing with a real mkdir is the only answer that matches
// what the tests are about to do.
func usableBpffs(path string) error {
	magic, at, err := statfsType(path)
	if err != nil {
		return err
	}
	if magic != bpfFSMagic {
		return fmt.Errorf("%s is not on a bpffs (statfs of %s reports magic %#x)", path, at, magic)
	}
	probe := filepath.Join(path, fmt.Sprintf("kapkan-writable-probe-%d", os.Getpid()))
	_ = os.Remove(probe)
	if err := os.Mkdir(probe, 0o700); err != nil {
		return fmt.Errorf("%s is a bpffs but this process cannot create pins in it: %w", path, err)
	}
	return os.Remove(probe)
}

/* ------------------------------------------------------------ tripwire */

// admitted records the TOP-LEVEL test names that got through the gate, so
// TestMain can tell a run that exercised the kernel from one that exercised
// nothing. Top-level rather than per-subtest so the floor below does not move
// every time a table gains a row.
var admitted sync.Map

func admit(t *testing.T) {
	name := t.Name()
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}
	admitted.Store(name, struct{}{})
}

// minKernelTests is the floor for a full `require` run: fewer than this many
// distinct tests reaching the kernel means the suite is no longer testing what
// it claims to.
//
// A full privileged run currently admits 112 top-level tests (measured under
// `make dataplane-test`). The floor is set well below that on purpose. It is a
// tripwire, not a target: the failure it exists to catch is wholesale — a build
// tag that stopped matching, a gate that grew too broad, a helper that began
// skipping unconditionally — and every one of those takes the number to
// somewhere near zero, not to 79. A floor that had to be edited each time a
// test was added would get edited without thought and stop meaning anything,
// and a floor that can produce a false red on an enforcement job is a floor
// somebody will delete.
const minKernelTests = 80

func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if msg := allSkipTripwire(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
			code = 1
		}
	}
	os.Exit(code)
}

// allSkipTripwire returns a non-empty message when a run that was REQUIRED to
// exercise the kernel did not exercise enough of it.
//
// Only under `require`, and only for an unfiltered run: `go test -run
// TestOneThing` legitimately admits one test, and a floor that fired on that
// would make the knob unusable for debugging, which is how knobs get turned off.
func allSkipTripwire() string {
	if !kernelRequired() {
		return ""
	}
	if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" {
		return ""
	}
	n := 0
	admitted.Range(func(any, any) bool { n++; return true })
	if n >= minKernelTests {
		return ""
	}
	return fmt.Sprintf("%s=require: only %d tests reached the kernel, want at least %d.\n"+
		"Every test reported PASS, but almost none of them touched bpf(2) — this run proved "+
		"nothing about the data plane. Look for a privilege gate that has become too broad, or "+
		"for build tags that stopped matching.", requireEnv, n, minKernelTests)
}
