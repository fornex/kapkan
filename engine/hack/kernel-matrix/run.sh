#!/usr/bin/env bash
# Kernel matrix for the XDP data plane.
#
# WHY THIS EXISTS
# ---------------
# engine/deploy/dataplane-operations.md, config.example.yaml and the manager's
# own error string all promise Linux 5.15. Until this harness, that floor was
# REASONED — read off the commit that gave global BPF functions pointer
# arguments (e5069b9c23b3, v5.13) — and never executed. The whole point of the
# global-function shape is that it took the verifier from 97.9% of its budget
# to single digits, so if an older verifier rejected it the program would have
# to be restructured and the support matrix would be wrong. A reasoned floor is
# a claim; this makes it a measurement.
#
# WHAT IT DOES
# ------------
# For each kernel in the matrix: pull the matching cilium/little-vm-helper
# kernel image, boot it under QEMU on a purpose-built initramfs whose only
# userspace is a static busybox and the cross-compiled data-plane test binary,
# and run that suite against that kernel.
#
# The guest kernels come from quay.io/lvh-images/kernel-images, the images the
# Cilium project uses for exactly this. They are published for both amd64 and
# arm64, which is what makes the loop work on an Apple Silicon laptop as well
# as on an x86 CI runner.
#
# ACCELERATION
# ------------
# On a Linux runner with /dev/kvm this runs at native speed. On macOS it does
# not: Docker Desktop's LinuxKit VM exposes no /dev/kvm and no nested virt, so
# the guest runs under QEMU TCG inside the container. That is slower — the
# suite takes tens of minutes rather than one — but it is the same kernel, the
# same object and the same verifier, so the answers are the same. Boot itself
# is a few seconds either way.
#
# USAGE
#   ./run.sh                          # the full matrix, host architecture
#   KERNELS="5.15" ./run.sh           # one kernel
#   MATRIX_ARCH=arm64 ./run.sh        # arm64 guests instead of amd64
#   JOBS=4 ./run.sh                   # all four kernels at once
#   TESTFLAGS="-test.v -test.run TestProgramSize" ./run.sh
#   LVH_TAG=main ./run.sh             # against lvh's current tip, not the pin
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # engine/

KERNELS=${KERNELS:-"5.15 6.1 6.6 6.12"}
LVH_REPO=${LVH_REPO:-quay.io/lvh-images/kernel-images}
# PINNED, not `main`. lvh republishes `<version>-main` on a schedule, so that
# tag silently moves to a newer point release. This job exists to make a
# support claim; a kernel that changes under it turns an unrelated PR red and,
# worse, means the last green run and the current one tested different things.
# Bumping this is a deliberate commit, exactly as with the clang pin in CI.
#
# 20260803.013611 == 5.15.213, 6.1.180, 6.6.147, 6.12.100.
LVH_TAG=${LVH_TAG:-20260803.013611}
# -test.timeout has to clear the SLOWEST case, which is not CI. Without
# hardware virtualisation (Docker Desktop on macOS exposes no /dev/kvm) guests
# run under TCG, and the suite on 5.15 took over an hour there — Go's timeout
# fired mid-test and panicked, so the run reported rc=2 with 138 of 148 tests
# passed and zero failures. That reads like a kernel incompatibility and is
# nothing of the sort. CI has /dev/kvm and finishes in a fraction of the time;
# this number exists for the laptop.
TESTFLAGS=${TESTFLAGS:-"-test.v -test.count=1 -test.timeout 180m"}
IMAGE=${IMAGE:-kapkan-kernel-matrix:local}
# Wall-clock guard per kernel. A guest that wedges before /init prints
# KAPKAN_VM_DONE would otherwise hang the job forever.
DEADLINE=${DEADLINE:-12000}
JOBS=${JOBS:-1}

HARNESS=$PWD/hack/kernel-matrix

# Guest architecture. Kapkan supports amd64 and arm64 and the committed object
# is arch-neutral BPF bytecode (bpf2go builds -target bpfel only), so the
# verifier answer should not depend on this — but "should not" is what this
# harness exists to stop saying, and the JIT and the map implementations behind
# it are per-arch. Both are worth running.
#
# The default follows `uname -m`, which on macOS reports the architecture of
# the CURRENT PROCESS: an Intel-Homebrew bash under Rosetta says x86_64 even on
# Apple Silicon. That is harmless — GOARCH, the Docker platform and the QEMU
# binary are all derived from this one value, so they always agree — but set
# MATRIX_ARCH to be explicit.
case "${MATRIX_ARCH:-$(uname -m)}" in
arm64 | aarch64) GOARCH=arm64; PLATFORM=linux/arm64 ;;
x86_64 | amd64)  GOARCH=amd64; PLATFORM=linux/amd64 ;;
*) echo "unsupported architecture ${MATRIX_ARCH:-$(uname -m)}" >&2; exit 2 ;;
esac
echo "==> guest architecture: $GOARCH (docker platform $PLATFORM)"

# Everything scratch is keyed by architecture: a cached vmlinuz for 5.15/amd64
# must never be booted by an arm64 QEMU because the directory name matched.
WORK=$PWD/.kernel-matrix/$GOARCH  # cache + logs; gitignored

mkdir -p "$WORK/kernels" "$WORK/logs" "$WORK/payload"

echo "==> harness image ($PLATFORM)"
docker build --platform "$PLATFORM" -t "$IMAGE" "$HARNESS" >/dev/null
mkdir -p "$WORK/harness"
cp "$HARNESS/vminit.sh" "$HARNESS/boot.sh" "$WORK/harness/"

# ---------------------------------------------------------------- kernels
# Only vmlinuz is extracted. The 340MB vmlinux next to it is debug symbols;
# BTF is compiled into the bootable image (CONFIG_DEBUG_INFO_BTF=y) and the
# guest exposes it at /sys/kernel/btf/vmlinux, which is what cilium/ebpf reads.
for v in $KERNELS; do
	if [ -f "$WORK/kernels/$v/vmlinuz" ]; then
		echo "==> kernel $v (cached)"
		continue
	fi
	echo "==> kernel $v (pulling $LVH_REPO:$v-$LVH_TAG)"
	docker pull -q --platform "$PLATFORM" "$LVH_REPO:$v-$LVH_TAG" >/dev/null
	docker run --rm --platform "$PLATFORM" --entrypoint sh \
		-v "$WORK/kernels:/out" "$LVH_REPO:$v-$LVH_TAG" -c '
			set -e
			d=$(ls /data/kernels | head -1)
			mkdir -p "/out/'"$v"'"
			cp /data/kernels/$d/boot/vmlinuz-* "/out/'"$v"'/vmlinuz"
			cp /data/kernels/$d/boot/config-*  "/out/'"$v"'/config"
		'
done

# ---------------------------------------------------------------- payload
# The suite reads three things by relative path from its own package
# directory — ../../bpf/kapkan_xdp.c, ../../bpf/include/kapkan_maps.h and
# ../../internal/config/config.go — so the initramfs mirrors just enough of the
# tree for those to resolve, and the guest runs with that directory as cwd.
echo "==> building the data-plane test binary (linux/$GOARCH)"
rm -rf "$WORK/payload"
mkdir -p "$WORK/payload/engine/internal/dataplane" "$WORK/payload/engine/internal/config"
GOOS=linux GOARCH=$GOARCH CGO_ENABLED=0 \
	go test -c -o "$WORK/payload/dataplane.test" ./internal/dataplane/
cp -R bpf "$WORK/payload/engine/bpf"
cp internal/config/config.go "$WORK/payload/engine/internal/config/"
cp internal/dataplane/*.go internal/dataplane/*.o "$WORK/payload/engine/internal/dataplane/"

# ---------------------------------------------------------------- run
# macOS still ships bash 3.2, so this stays 3.2-compatible: no `wait -n`, no
# associative arrays. JOBS>1 launches the whole matrix at once and waits.
KVM_DEVICE=""
if [ -e /dev/kvm ]; then
	KVM_DEVICE="--device=/dev/kvm"
	echo "==> /dev/kvm present: guests run accelerated"
else
	echo "==> no /dev/kvm: guests run under QEMU TCG (slower, same verifier)"
fi

# The watchdog POLLS rather than sleeping for the whole deadline, and its
# output goes to /dev/null. Both matter, and the second one is not cosmetic: a
# `sleep $DEADLINE` left behind after the run inherits this script's stdout and
# holds the pipe open, so `run.sh | tee` sits there for another 90 minutes with
# the work long finished. Polling also means the watchdog reaps itself the
# moment the container exits, instead of surviving as an orphan.
one() {
	# Three statements, not one: within a single `local` the earlier
	# assignments are not reliably visible to the later ones (SC2318).
	local v=$1
	local log=$WORK/logs/$v.log
	local name=kapkan-matrix-$$-${v//./_}
	(
		waited=0
		while [ "$waited" -lt "$DEADLINE" ]; do
			sleep 5
			waited=$((waited + 5))
			# Grace period: `docker run` has not necessarily created the
			# container yet, and "not there" in the first minute means "not
			# started", not "finished". Without this the watchdog disarms
			# itself immediately.
			[ "$waited" -lt 60 ] && continue
			docker ps -q --filter "name=^${name}$" | grep -q . || exit 0
		done
		echo "KAPKAN_HARNESS deadline ${DEADLINE}s exceeded, killing $name" >> "$log"
		docker kill "$name"
	) >/dev/null 2>&1 &
	local guard=$!
	docker run --rm --platform "$PLATFORM" --name "$name" \
		$KVM_DEVICE \
		-e KAPKAN_FLAGS="$TESTFLAGS" \
		-e KAPKAN_RUNS="dataplane.test /engine/internal/dataplane" \
		-e KAPKAN_VM_SMP="${VM_SMP:-2}" \
		-e KAPKAN_VM_MEM="${VM_MEM:-3072}" \
		-v "$WORK:/work" -w /work "$IMAGE" \
		bash /work/harness/boot.sh "$v" > "$log" 2>&1 || true
	kill "$guard" 2>/dev/null || true
	wait "$guard" 2>/dev/null || true
	echo "==> $v finished: $log"
}

for v in $KERNELS; do
	if [ "$JOBS" -gt 1 ]; then one "$v" & else one "$v"; fi
done
wait

# ---------------------------------------------------------------- verdict
echo
printf '%-8s %-12s %-5s %-10s %-9s %s\n' KERNEL RELEASE BTF PROCESSED TESTS RESULT
rc=0
for v in $KERNELS; do
	log=$WORK/logs/$v.log
	# A container that never started leaves no log at all. Report it rather
	# than dying in the sed below with `set -e` and no verdict table.
	if [ ! -f "$log" ]; then
		printf '%-8s %-12s %-5s %-10s %-9s %s\n' \
			"$v" "?" "?" "n/a" "0p/0f" "NO-LOG"
		rc=1
		continue
	fi
	rel=$(sed -n 's/^KAPKAN_VM_KERNEL=\([^ ]*\).*/\1/p' "$log" | head -1)
	btf=$(sed -n 's/^KAPKAN_VM_BTF=\([a-z]*\).*/\1/p' "$log" | head -1)
	proc=$(sed -n 's/.*verifier processed \([0-9]*\) insns.*/\1/p' "$log" | head -1)
	pass=$(grep -c '^--- PASS' "$log" || true)
	fail=$(grep -c '^--- FAIL' "$log" || true)
	code=$(sed -n 's/^KAPKAN_VM_RC=dataplane.test \([0-9]*\).*/\1/p' "$log" | head -1)
	verdict=FAIL
	if ! grep -q '^KAPKAN_VM_DONE=1' "$log"; then
		verdict="NO-BOOT/HUNG"
	elif [ "$code" = "0" ]; then
		verdict=PASS
	fi
	[ "$verdict" = PASS ] || rc=1
	printf '%-8s %-12s %-5s %-10s %-9s %s\n' \
		"$v" "${rel:-?}" "${btf:-?}" "${proc:-n/a}" "${pass:-0}p/${fail:-0}f" "$verdict"
done
exit $rc
