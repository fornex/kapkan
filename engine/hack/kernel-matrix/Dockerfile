# The kernel-matrix harness: a QEMU that runs guest kernels, and the pieces
# needed to build an initramfs around a Go test binary.
#
# Deliberately NOT privileged at runtime. QEMU in TCG mode needs no host
# capabilities at all, and with /dev/kvm passed in it needs only that device.
# This matters because the thing under test is a program that loads into a
# kernel: if the harness itself had CAP_SYS_ADMIN on the host, a "pass" would
# be ambiguous about which kernel actually accepted it.
#
# busybox-static, not the image's own busybox: alpine's is linked against musl,
# and the initramfs has no libc in it.
FROM alpine:3.20

RUN apk add --no-cache \
	qemu-system-aarch64 \
	qemu-system-x86_64 \
	busybox-static \
	cpio \
	gzip \
	bash
