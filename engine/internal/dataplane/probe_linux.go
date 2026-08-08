//go:build linux

package dataplane

// Pre-flight: does this kernel and this process have what the data plane needs?
//
// EVERY CHECK HERE FAILS HARD. That is a deliberate departure from how kapkan
// treats its other optional components — a GeoIP database that will not open is
// a warning and the detector runs without attribution — and the difference is
// the consequence of being wrong. A missing .mmdb costs an attack some
// attribution. A data plane that is not there means the operator configured a
// drop, saw no error, and is not dropping. There is no useful degraded mode for
// "the filter is absent": either the packets are being filtered or the operator
// needs to know immediately, at a time of their choosing, not during an attack.
//
// Every message names the version or the capability, because the whole value of
// a startup refusal is that it is actionable. "dataplane: failed to start" would
// be worse than the silence it replaces.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// Kernel floor. 5.15 is the project's supported floor and the reason
// bpf/kapkan_xdp.c is compiled -mcpu=v2 and unrolls its rule scan instead of
// using bpf_loop (5.17+). Below it the program does not merely run slowly, it
// does not load.
const (
	minKernelMajor = 5
	minKernelMinor = 15
)

// bpfFSMagic is BPF_FS_MAGIC from include/uapi/linux/magic.h. Pins can only
// live on a bpffs, and a pin_path that is an ordinary directory is the single
// most likely misconfiguration (an operator who did not mount bpffs, or a
// systemd unit with ProtectKernelTunables=yes, which mounts /sys/fs/bpf
// read-only — see deploy/dataplane-operations.md §1).
const bpfFSMagic = 0xcafe4a11

// Capability bit numbers from include/uapi/linux/capability.h. CAP_BPF and
// CAP_PERFMON are above 31, which is why they need the second u32 of the
// capability set and why SELinux puts them in the capability2 class.
const (
	capNetAdmin = 12
	capSysAdmin = 21
	capPerfmon  = 38
	capBPF      = 39
)

// kernelVersion reads the running kernel's major.minor from
// /proc/sys/kernel/osrelease.
//
// Deliberately not uname(2) via x/sys: golang.org/x/sys is an indirect
// dependency here and promoting it to a direct one to read two integers is a
// bad trade. osrelease is the same string uname reports and has been stable
// since forever.
func kernelVersion() (major, minor int, raw string, err error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return 0, 0, "", fmt.Errorf("read kernel version: %w", err)
	}
	raw = strings.TrimSpace(string(b))
	// "6.12.76-linuxkit", "5.15.0-91-generic", "6.1.0-rc4+" — take the leading
	// two dot-separated integers and ignore everything from the first
	// non-digit.
	fields := strings.SplitN(raw, ".", 3)
	if len(fields) < 2 {
		return 0, 0, raw, fmt.Errorf("cannot parse kernel version %q", raw)
	}
	if major, err = strconv.Atoi(leadingDigits(fields[0])); err != nil {
		return 0, 0, raw, fmt.Errorf("cannot parse kernel major in %q", raw)
	}
	if minor, err = strconv.Atoi(leadingDigits(fields[1])); err != nil {
		return 0, 0, raw, fmt.Errorf("cannot parse kernel minor in %q", raw)
	}
	return major, minor, raw, nil
}

func leadingDigits(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

// checkKernel refuses a kernel below the floor.
func checkKernel() (string, error) {
	major, minor, raw, err := kernelVersion()
	if err != nil {
		return "", err
	}
	if major < minKernelMajor || (major == minKernelMajor && minor < minKernelMinor) {
		return raw, fmt.Errorf("%w: running %s, the XDP data plane needs %d.%d or newer "+
			"(the program is built -mcpu=v2 for exactly this floor). Set dataplane.enabled: false "+
			"and use a ladder of flowspec/blackhole instead, or upgrade the kernel",
			ErrKernelTooOld, raw, minKernelMajor, minKernelMinor)
	}
	return raw, nil
}

// effectiveCaps reads CapEff from /proc/self/status.
func effectiveCaps() (uint64, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/status: %w", err)
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		v, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parse CapEff %q: %w", strings.TrimSpace(v), err)
		}
		return caps, nil
	}
	return 0, errors.New("no CapEff line in /proc/self/status")
}

// checkCapabilities refuses unless the process holds the exact three the
// program needs. Each was measured one at a time (varying one capability,
// holding the rest constant) and the table is in
// deploy/dataplane-operations.md §1; the messages below name the same symptom an
// operator would otherwise have to look up there.
//
// CAP_SYS_ADMIN substitutes for any of them, because the kernel's own checks are
// written that way (`!capable(CAP_NET_ADMIN) && !capable(CAP_SYS_ADMIN)`), not
// because running with it is a good idea.
func checkCapabilities() error {
	caps, err := effectiveCaps()
	if err != nil {
		// Not a refusal: /proc could be unmounted in an exotic sandbox, and the
		// real checks below (feature probes) will fail with the kernel's own
		// error anyway. Losing the good message is not worth refusing to start.
		return nil
	}
	has := func(bit uint) bool { return caps&(1<<bit) != 0 || caps&(1<<capSysAdmin) != 0 }

	for _, c := range []struct {
		bit     uint
		name    string
		symptom string
	}{
		{capBPF, "CAP_BPF",
			"without it bpf(2) itself is refused and map creation fails with " +
				"\"map create: operation not permitted\""},
		{capNetAdmin, "CAP_NET_ADMIN",
			"XDP is a net-admin program type, so without it the load fails with " +
				"\"load program: operation not permitted\" and no interface can be attached"},
		{capPerfmon, "CAP_PERFMON",
			"the verifier's allow_ptr_leaks IS perfmon_capable(), and kapkan_xdp.c subtracts " +
				"data_end - data to get the frame length, so without it the program is REJECTED " +
				"with \"R7 pointer -= pointer prohibited\" — which reads like a kapkan bug and is not one"},
	} {
		if !has(c.bit) {
			return fmt.Errorf("%w: %s. %s.\n"+
				"The process needs exactly CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON (not CAP_SYS_ADMIN). "+
				"For a systemd unit add:\n"+
				"    AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON\n"+
				"    CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON\n"+
				"    SystemCallFilter=@system-service bpf\n"+
				"See engine/deploy/dataplane-operations.md §1. Effective capabilities are %#016x.",
				ErrMissingCapability, c.name, c.symptom, caps)
		}
	}
	return nil
}

// checkFeatures asks the kernel whether it supports the program type and the
// two map types that are least likely to be present on a stripped-down build.
//
// These probes each load a tiny program or map, so they run after the capability
// check: without CAP_BPF they would fail with EPERM and blame the feature.
func checkFeatures() error {
	if err := features.HaveProgramType(ebpf.XDP); err != nil {
		return fmt.Errorf("dataplane: this kernel does not support XDP programs: %w "+
			"(CONFIG_XDP_SOCKETS/CONFIG_BPF_SYSCALL)", err)
	}
	for _, mt := range []struct {
		t    ebpf.MapType
		what string
	}{
		{ebpf.LPMTrie, "prefix lists (allowlist, protected list, victim lookup)"},
		{ebpf.LRUHash, "per-source token buckets"},
		{ebpf.PerCPUHash, "per-rule counters"},
	} {
		if err := features.HaveMapType(mt.t); err != nil {
			return fmt.Errorf("dataplane: this kernel does not support %v, needed for %s: %w",
				mt.t, mt.what, err)
		}
	}
	return nil
}

// statfsType returns the filesystem magic of the deepest existing ancestor of
// path, along with the ancestor it actually looked at.
func statfsType(path string) (magic int64, at string, err error) {
	at = path
	for {
		var st syscall.Statfs_t
		err := syscall.Statfs(at, &st)
		if err == nil {
			return int64(st.Type), at, nil
		}
		if !errors.Is(err, syscall.ENOENT) {
			return 0, at, fmt.Errorf("statfs %s: %w", at, err)
		}
		parent := parentDir(at)
		if parent == at {
			return 0, at, fmt.Errorf("statfs %s: no existing ancestor", path)
		}
		at = parent
	}
}

// parentDir is filepath.Dir without importing path/filepath for one call, and
// without its willingness to turn "/" into "/" forever unnoticed — the caller
// uses the fixed point as its loop termination.
func parentDir(p string) string {
	p = strings.TrimSuffix(p, "/")
	i := strings.LastIndexByte(p, '/')
	switch {
	case i < 0:
		return p
	case i == 0:
		return "/"
	default:
		return p[:i]
	}
}

// checkBPFFS refuses a pin path that is not on a bpffs.
func checkBPFFS(pinPath string) error {
	magic, at, err := statfsType(pinPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPinPathUnsafe, err)
	}
	if magic != bpfFSMagic {
		return fmt.Errorf("%w: %s is on filesystem type %#x, not bpffs (%#x). "+
			"Mount one with `mount -t bpf bpffs %s` (systemd normally does this for "+
			"/sys/fs/bpf), and if the unit sets ProtectKernelTunables=yes, remove it — "+
			"systemd mounts /sys/fs/bpf read-only under that option, so no pin can be "+
			"created. See engine/deploy/dataplane-operations.md §1",
			ErrPinPathUnsafe, at, uint64(magic), uint64(bpfFSMagic), at)
	}
	return nil
}

// preflight runs every check that must pass before the manager touches an
// operator's pins, in the order that produces the most useful error: kernel
// first (nothing else can be fixed if that is wrong), then capabilities (the
// most common failure and the one with the least obvious symptom), then kernel
// features, then the pin filesystem.
func preflight(pinPath string) (kernel string, err error) {
	if kernel, err = checkKernel(); err != nil {
		return kernel, err
	}
	if err := checkCapabilities(); err != nil {
		return kernel, err
	}
	if err := checkFeatures(); err != nil {
		return kernel, err
	}
	return kernel, checkBPFFS(pinPath)
}
