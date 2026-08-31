#!/bin/bash
# Runs INSIDE the harness container. Builds an initramfs out of /work/payload
# and boots /work/kernels/$1/vmlinuz on it.
#
# Guest console goes to this script's stdout; the driver captures it.
set -euo pipefail

VER=${1:?usage: boot.sh <kernel-version-dir>}
ARCH=$(uname -m)
KDIR=/work/kernels/$VER
ROOT=/tmp/initramfs

rm -rf "$ROOT"
mkdir -p "$ROOT"/{bin,sbin,proc,sys,dev,tmp,root}
cp /bin/busybox.static "$ROOT/bin/busybox"
cp -a /work/payload/. "$ROOT/"
cp /work/harness/vminit.sh "$ROOT/init"
chmod +x "$ROOT/init"

{
	echo "FLAGS=\"${KAPKAN_FLAGS:--test.v}\""
	echo "RUNS=\"${KAPKAN_RUNS:?KAPKAN_RUNS must name at least one binary}\""
} > "$ROOT/run.conf"

# -1 rather than -9: this is a 60MB tree of already-incompressible Go binaries,
# and the difference is seconds of CPU for a few percent of RAM.
( cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1 > /tmp/initramfs.cpio.gz )

echo "KAPKAN_HARNESS kernel_dir=$VER host_arch=$ARCH initramfs_bytes=$(stat -c %s /tmp/initramfs.cpio.gz)"
cat "$ROOT/run.conf"

# panic=-1 with -no-reboot: a guest panic exits QEMU immediately instead of
# hanging the job until the driver's timeout.
COMMON="earlyprintk=serial panic=-1 rdinit=/init"

case "$ARCH" in
aarch64 | arm64)
	BIN=qemu-system-aarch64
	APPEND="console=ttyAMA0 $COMMON"
	# No KVM on Apple Silicon under Docker Desktop (no /dev/kvm in the
	# LinuxKit VM, and no nested virt exposed), so this is TCG. It is still
	# fast enough: -cpu max on an M-series host boots 5.15 in ~3 seconds.
	MACH=(-machine virt -cpu max)
	;;
x86_64 | amd64)
	BIN=qemu-system-x86_64
	APPEND="console=ttyS0 $COMMON"
	if [ -e /dev/kvm ]; then
		# shellcheck disable=SC2054  # q35,accel=kvm is one QEMU argument.
		MACH=(-machine q35,accel=kvm -cpu host)
	else
		MACH=(-machine q35 -cpu max)
	fi
	;;
*)
	echo "KAPKAN_HARNESS unsupported host arch $ARCH" >&2
	exit 2
	;;
esac

exec "$BIN" "${MACH[@]}" \
	-smp "${KAPKAN_VM_SMP:-2}" \
	-m "${KAPKAN_VM_MEM:-4096}" \
	-nographic -no-reboot \
	-kernel "$KDIR/vmlinuz" \
	-initrd /tmp/initramfs.cpio.gz \
	-append "$APPEND"
