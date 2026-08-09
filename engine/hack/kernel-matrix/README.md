# Kernel matrix

Boots real Linux kernels under QEMU and runs `internal/dataplane`'s suite on
each one.

## Why

`engine/deploy/dataplane-operations.md`, `config.example.yaml` and
`manager_stub.go`'s error string all promise **Linux 5.15**. That floor was
originally *reasoned*: pointer arguments to global (non-inlined) BPF functions
landed in v5.13 (`e5069b9c23b3`), and that construct is what took the verifier
from 97.9% of its complexity budget to single digits. A reasoned floor is a
claim about a kernel nobody had run. This harness turns it into a measurement.

It also catches the class of bug that only exists below the newest kernel — a
`bpf_prog_info` field that does not exist yet, a map flavour that behaves
differently, a helper that is not there. The first thing it found was exactly
that: `TestProgramSize` read `bpf_prog_info.verified_insns`, which was added in
**5.16**, so the test failed on the floor the project documents.

## Running it

```sh
cd engine
./hack/kernel-matrix/run.sh                    # 5.15, 6.1, 6.6, 6.12
KERNELS="5.15" ./hack/kernel-matrix/run.sh     # one kernel
MATRIX_ARCH=arm64 ./hack/kernel-matrix/run.sh  # arm64 guests
JOBS=4 ./hack/kernel-matrix/run.sh             # all four at once
TESTFLAGS="-test.v -test.run TestProgramSize" ./hack/kernel-matrix/run.sh
```

or `make dataplane-matrix` from `engine/`. It prints a verdict table:

```
KERNEL   RELEASE      BTF   PROCESSED  TESTS     RESULT
5.15     5.15.213     yes   75216      148p/0f   PASS
```

Logs land in `engine/.kernel-matrix/<arch>/logs/<version>.log` (gitignored) and
guest kernels are cached alongside them. The `<arch>` level is not decoration:
a cached 5.15 `vmlinuz` for amd64 must never be booted by an arm64 QEMU because
the version directory matched.

## How it works

1. **Kernels** come from `quay.io/lvh-images/kernel-images`, the images the
   Cilium project publishes for its own BPF CI. They are multi-arch, which is
   what lets this run on an Apple Silicon laptop as well as on an x86 runner.
   Only `vmlinuz` is extracted; BTF is compiled into it
   (`CONFIG_DEBUG_INFO_BTF=y`) and the guest exposes it at
   `/sys/kernel/btf/vmlinux`.

   The tag is **pinned** (`LVH_TAG`), not `-main`: lvh moves `-main` to newer
   point releases on a schedule, and a job that makes a support claim must not
   change what it tested without a commit saying so. `LVH_TAG=main ./run.sh`
   checks against the current tip on purpose.
2. **Guest userspace** is an initramfs built from scratch: a static busybox,
   the cross-compiled `dataplane.test`, and the three repository files the
   drift tests read by relative path (`bpf/kapkan_xdp.c`,
   `bpf/include/kapkan_maps.h`, `internal/config/config.go`). No distribution,
   no package manager, nothing that could differ between kernels.
3. **QEMU** runs inside a container so the toolchain is pinned and the host
   needs nothing but Docker. The container is **not** privileged — QEMU needs
   no host capability. That matters: the harness must not be able to influence
   whether the guest kernel accepts the program.

## Speed, and the honest caveat

With `/dev/kvm` (a Linux CI runner) the guests are accelerated and the suite
takes a couple of minutes. On macOS there is no `/dev/kvm` — Docker Desktop's
LinuxKit VM exposes neither the device nor nested virtualisation — so the guest
runs under QEMU TCG. Boot is still ~3 seconds, but the suite takes tens of
minutes because loading the object with a full instruction-level verifier log
is CPU-bound.

It is the same kernel, the same object and the same verifier either way, so the
answers are identical; only the wall clock differs.

## What it does not cover

Least privilege. The matrix guests run as root with every capability, on
purpose: this harness answers "does this *kernel* accept the program", so
capability is deliberately removed as a variable. The CI job that runs the same
binary under `setpriv --ambient-caps=+bpf,+net_admin,+perfmon` on the runner's
own kernel is what keeps the three-capability claim honest.
