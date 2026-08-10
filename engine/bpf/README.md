# engine/bpf — Kapkan's XDP data plane (kernel side)

## Charter

The data plane **executes decisions made elsewhere**. It never classifies, and
its default verdict is always `XDP_PASS`. Every early exit, every parse failure
and every map miss passes the packet and bumps a counter. Malformed frames pass
unless `dataplane.drop_malformed` is set. There is no default-deny anywhere, and
no rule-presence-flips-the-default behaviour.

The corollary worth stating plainly: the failure mode of this data plane is a
wire, not a black hole. Every error path in `kapkan_xdp.c` forwards — a missing
config, a victim whose policy block has gone, a profile a rule names but
userspace never wrote, an LRU that refuses a bucket, a null pointer the
verifier makes us check. All of them pass and count.

`kapkan_xdp.c` implements the full six-step packet path: the parser, all five
precedence levels, the per-source token bucket, rule expiry, the double-buffer
generation flip and dry run.

## Packet-path precedence (normative)

1. src allowlist → PASS (`kapkan_allow4/6`)
2. dst protected list → PASS (`kapkan_protect4/6`, the `protected_whitelist` mirror)
3. static rules → first match wins
4. dynamic src rules → source-flood / source-anchored entries
5. dynamic dst rules → per-victim, bounded scan of ≤8 rules, first match wins
6. default → PASS, counted

Steps 1 and 2 are different axes: `dataplane.allowlist` is a **source** list,
`protected_whitelist` is a **destination** list. Both must be enforced in the
kernel — see the comment block at the top of `kapkan_xdp.c`.

### Steps 4 and 5 share one trie

`kapkan_victims4/6` is not "the list of destinations" — it is *the set of
prefixes that have a policy block*, and it is consulted on **both** axes.
`mitigate.FlowSpecRule` anchors a rule on either end: an incoming attack yields
`Dst=victim` (found at step 5), an outgoing flood from a compromised host
yields `Src=victim` (step 4), and a source-anchored rule yields both. Reaching
a block by the "wrong" axis cannot produce a wrong verdict, because
`kapkan_rule_match()` re-checks both prefixes against the packet before a rule
may fire; the trie only narrows the candidate set.

### IPv4-mapped IPv6 is NOT normalised

An IPv6 packet sourced from `::ffff:a.b.c.d` is matched against IPv6 rules
only. It is never rewritten to the IPv4 address and never tested against
`kapkan_allow4` / `kapkan_protect4` / `kapkan_victims4`. They are different
packets on the wire, the IR keeps the families apart (RFC 8956 gives IPv6
FlowSpec its own AFI, and `sourceAnchoredRules()` skips a source whose family
differs from the victim's), and normalising would fail dangerously — an
operator's IPv4 *drop* rule would silently begin dropping IPv6 nobody named.

## Layout

```
engine/bpf/
  kapkan_xdp.c              the XDP program: parser, accounting, verdict
  include/
    kapkan_bpf.h            single entry point; fixes the include order
    kapkan_kern.h           hand-written minimal kernel UAPI (types, map/XDP enums, xdp_md)
    kapkan_proto.h          hand-written wire formats (eth/vlan/ip/ipv6/tcp/udp/icmp)
    kapkan_maps.h           FREEZE POINT F6 — the map set and every struct layout
    bpf_helpers.h           vendored from libbpf
    bpf_helper_defs.h       vendored from libbpf
    bpf_endian.h            vendored from libbpf
    LICENSE.LGPL-2.1        for the vendored headers
    LICENSE.BSD-2-Clause    for the vendored headers (libbpf's copyright)
  LICENSE.BSD-2-Clause      for Kapkan's own BPF sources
  LICENSE.GPL-2.0           for Kapkan's own BPF sources
```

Every `.c`/`.h` Kapkan wrote carries
`// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)`, and the program
declares `char _license[] SEC("license") = "Dual BSD/GPL";`.

Why dual: GPL-only helpers and *all* kfuncs refuse to load into a program whose
license string is not GPL-compatible. Declaring the dual license now keeps that
door open without a later relicense. It does not make the Kapkan binary GPL —
the object is loaded **into the kernel** by `bpf(2)`, not linked into the Go
program. Same arrangement Cilium and loxilb use.

## Vendored header provenance

All three come from **libbpf v1.7.0**, tag commit
`f5dcbae736e5d7f83a35718e01be1a8e3010fa39`, fetched from
`https://github.com/libbpf/libbpf/archive/refs/tags/v1.7.0.tar.gz`.

| File | Upstream path | SHA-256 of the vendored copy |
|---|---|---|
| `include/bpf_helpers.h` | `src/bpf_helpers.h` | `04575f99655917175eef6f44ecc50c081f4e4bfe9b1242d5ecc82f2a57cb3865` |
| `include/bpf_helper_defs.h` | `src/bpf_helper_defs.h` | `ebcd44514b37cbd4459b5b637dcb39a43d9adee94496c3afe2ee5219b5c8a3a5` |
| `include/bpf_endian.h` | `src/bpf_endian.h` | `64b77c97b089ca06203d0451407844fe93933b4e36e7315a294745fa29d058fb` |

All three are `SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)`; we take
them under BSD-2-Clause. Verify a copy with:

```
shasum -a 256 include/bpf_helpers.h include/bpf_helper_defs.h include/bpf_endian.h
```

### What is vendored vs hand-written, and why

**Vendored:** the libbpf helper declarations and endian macros. They are
generated from the kernel's `bpf.h`, gain new helpers every release, and a
hand-rolled copy rots silently into wrong signatures. Take upstream's.

**Hand-written:** `kapkan_kern.h` and `kapkan_proto.h`. Their contents are
either wire formats frozen by an RFC/IEEE spec (`ethhdr`, `iphdr`, `ipv6hdr`,
`tcphdr`, `udphdr`, `icmphdr`) or UAPI ABI the kernel can never renumber
(`BPF_MAP_TYPE_*`, `enum xdp_action`, `struct xdp_md`). Those are stable by
construction, so ~350 lines of local definitions beat the alternatives:

- We have no Linux UAPI headers on the macOS build host at all.
- `vmlinux.h` generated from BTF is ~3 MB *and architecture-specific* — the CI
  container is arm64 while the deployment targets are amd64 — so it is the
  wrong thing to commit.

`kapkan_bpf.h` exists only to fix the include order: `bpf_helper_defs.h`
assumes `__u32`/`__u64` and a pile of kernel struct names already exist, so
`kapkan_kern.h` must precede it.

## Build

The object and the generated Go bindings are **committed**. clang is a
contributor/CI dependency, never an operator one: `make build` and `make test`
work on a box with nothing but Go.

Regenerate after touching any `.c`/`.h` here:

```
cd engine && make dataplane-sync
```

That runs `bpf2go` with the compiler that works on macOS. The exact invocation
it performs is:

```
/usr/local/opt/llvm@21/bin/clang -target bpf -O2 -g -Wall -Werror -mcpu=v2 \
    -Iengine/bpf/include -c kapkan_xdp.c -o kapkan_xdp.o
```

- Apple's clang has **no** bpf target; `brew install llvm@21` provides one.
- `-mcpu=v2` holds the kernel floor at 5.15. `v3` emits jump-32 and
  zero-extension instructions that older verifiers reject.
- `-g` is required: it is what produces the BTF that BTF-defined maps and
  `bpf2go`'s Go type generation both need. `bpf2go` strips DWARF afterwards and
  keeps `.BTF`.

## Test

"It compiles" means nothing here; the verifier is the whole risk. Kernel-side
tests need Linux and live in four files under `engine/internal/dataplane/`:

| File | What it covers |
|---|---|
| `smoke_linux_test.go` | Load, the parser's packet shapes, program size. |
| `maps_linux_test.go` | The Go map-population helpers: `RuleSpec.Encode` and `ProfileSpec.Encode` against F6 byte for byte, and the double-buffer bookkeeping. Pure Go apart from the generation tests, so it also runs under `make test` on CI. |
| `packetpath_linux_test.go` | The six precedence levels, rule matching, expiry, the generation flip, dry run and the token bucket. |
| `pktmatrix_linux_test.go` | The table-driven matrix: the precedence ladder in order, every field of the rule IR, the wire shapes (VLAN, QinQ, IPv4 options, fragments, truncation), dry-run/live counter parity, the empty-policy baseline and the per-source limiter under many sources. Frames come from `pkg/pktgen`; every case asserts the verdict **and** the exact set of counters that moved. |

They run with:

```
cd engine && make dataplane-test    # correctness
cd engine && make dataplane-bench   # capacity
cd engine && make dataplane-matrix  # the same suite on 5.15 / 6.1 / 6.6 / 6.12
```

On macOS the first two cross-compile the test binary for `linux/arm64` and run
it in a privileged container (Docker Desktop's VM kernel is 6.12 and ships
`/sys/kernel/btf/vmlinux`). `make test` on macOS skips those cases and runs only
the checks that need no kernel — the C↔Go drift gate and the map set in the
committed ELF.

On **Linux without the privilege** — CI's ordinary test job, or any contributor
running `make test` as a normal user — the kernel-side files do compile, and
they skip through one shared gate rather than failing: see
`engine/internal/dataplane/kernelgate_linux_test.go` for what it probes and,
more importantly, for what it deliberately does *not* gate. Two environment
variables go with it:

| Variable | Effect |
|---|---|
| `KAPKAN_DATAPLANE=require` | Turns every environment skip in `internal/dataplane` (and `internal/app`'s data-plane test) into a **failure**, and makes the suite refuse to report success if implausibly few tests reached the kernel. Set by `make dataplane-test`, by the CI `XDP data plane` job and by the kernel-matrix guest — the three paths that exist to run these tests for real. |
| `KAPKAN_BPFFS` | Where the suite may create pins. Needed wherever `/sys/fs/bpf` is a bpffs the test user cannot write to, which is the case on a GitHub runner: it is root-owned mode 0700 and the job holds `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON` and no `CAP_DAC_OVERRIDE`. Same variable the pcap block-rate suite uses. |

`dataplane-matrix` is the one that tests the **documented floor** rather than
whatever kernel the host happens to run: it boots each kernel under QEMU on a
purpose-built initramfs and runs the whole suite there. See
`engine/hack/kernel-matrix/README.md`.

## Verifier-risk register

Each of these is also called out in a comment at the point it applies.

| Risk | Mitigation |
|---|---|
| IPv6 extension-header walk | Bounded loop, ≤8, bounds check *inside* the loop via `kapkan_pull()`; hitting the cap PASSES and bumps `pass_exthdr_cap`. The redundant "is it a known L4 protocol" pre-check was **removed**: the "not a TLV extension header → break" test already caught every L4 protocol and `IPPROTO_NONE`, and the duplication cost six extra comparisons per unrolled iteration. |
| The ≤8 policy scan | `#pragma unroll`'d. A runtime-count loop over a map value would need `bpf_loop()` (5.17+) and breaks the 5.15 floor. |
| The ≤256 static scan | The one scan whose trip count is *not* a compile-time constant. Written as a **rolled** bounded loop with a constant ceiling plus a runtime `static_count` break — verifier-supported since 5.3. Unrolling 256 copies of the matcher is not viable. Runtime cost is proportional to `static_count`, not to the ceiling; only the verifier pays for the ceiling. |
| Token bucket | No division by a runtime value. `kapkan_profile` carries precomputed `pkt_per_ns_q32` / `byte_per_ns_q32`; the datapath multiplies only. Overflow is *proven*, not promised: `delta` is clamped to 2^32 ns and each Q32 rate to 2^32−1, so the product is strictly below 2^64 no matter what userspace writes into the map. |
| Map-in-map inner lookups | Avoided entirely — double buffering uses index arithmetic in one flat array, so there is one lookup and one NULL check. See the DOUBLE BUFFERING comment in `kapkan_maps.h` for the three candidates and why this one won. |
| Global-function pointer args | A global function's pointer arguments arrive as `PTR_TO_MEM_OR_NULL`; the verifier rejects the first dereference without an explicit NULL test, because it checks the body in isolation. `kapkan_decide()` and `kapkan_rule_match()` both test and both fail open. |
| Unaligned wide loads | Address operands are a `union kapkan_addr` (alignment 8), never a bare `__u8 addr[16]` parameter (alignment 1). With alignment 1 clang cannot emit a 64-bit load and reassembles each word from eight byte loads plus shifts — see the measurements below. `_Static_assert`s in `kapkan_xdp.c` fail the build if an F6 edit ever moves `kapkan_rule.src`/`.dst` off an 8-byte boundary. |
| Program size / complexity | Watched by `TestProgramSize`, which fails if the verifier processes more than half the 1M budget. |

### Function shape is a verifier decision

The single most expensive thing in this program is not any instruction, it is
the *multiplication* of (distinct parser states) × (scan iterations) × (paths
through the matcher). Measured end to end on the 6.12 test kernel, whole
program, full packet path:

| Revision | ELF instructions | Verifier processed | % of 1M budget |
|---|---|---|---|
| Everything `__always_inline` | 8,040 | 979,105 | 97.9% |
| Aligned address loads (`union kapkan_addr`) | 1,949 | 702,682 | 70.3% |
| Branchless `kapkan_rule_match()` | 1,979 | 822,035 | 82.2% |
| `kapkan_decide()` made **global** | 1,952 | 275,639 | 27.6% |
| `kapkan_rule_match()` made **global** | 1,935 | 82,422 | 8.2% |
| First-fragment L4 parsing fixed (see below) | **1,871** | **119,701** | **12.0%** |

The last row is the only one where the count went *up* while the program got
*smaller*, and it is worth understanding before someone tries to "reclaim" it.
`kapkan_parse_l4()` used to return early on `pkt->is_frag`, which skipped the
whole L4 parse for fragments — cheap for the verifier precisely because it was
skipping work it should have been doing. It also skipped it for FIRST
fragments, which do carry the L4 header, so every port and TCP-flag rule missed
the leading fragment of every fragmented flood. Removing the guard deletes 64
instructions and adds a real path through the parser for fragmented traffic.
12.0% of the budget is the honest price of parsing packets the data plane is
supposed to be able to match.

Two lessons worth keeping:

- **`global`, not `static`, is the lever.** A static subprogram is verified
  along every path that reaches it; a global one is verified *exactly once*,
  standalone. Only that breaks the multiplication. Pointer arguments to global
  functions landed in 5.13 (`e5069b9c23b3`), below the 5.15 floor — and this
  is no longer only a citation: see the kernel matrix below, where a real
  5.15 verifier accepts the program.
- **Branchless is not automatically cheaper.** Removing the matcher's early
  exits *raised* the count on its own (70.3% → 82.2%), because every call then
  runs the full body and carries more live state into the loop. It only paid
  off once the function was global and verified once — then the single-path
  body is exactly what you want. Measure, do not assume.

### Kernel matrix — the floor, measured

`make dataplane-matrix` boots each kernel under QEMU and runs the whole
`internal/dataplane` suite on it. Kernels come from `quay.io/lvh-images`
(Cilium's BPF CI images); the harness is `engine/hack/kernel-matrix`.

| Kernel | Guest release | Loads | Verifier processed | % of 1M budget | Suite |
|---|---|---|---|---|---|
| 5.15 (the floor) | 5.15.213 | yes | 75,216 | 7.5% | pass |
| 6.1 | 6.1.180 | yes | 75,216 | 7.5% | pass |
| 6.6 | 6.6.147 | yes | 74,633 | 7.5% | pass |
| 6.12 | 6.12.100 | yes | 118,003 | 11.8% | pass |

Program tag is `c71769b19e70b058` on every row. The instruction counts and the
tag are identical on **arm64 and amd64 guests** of the same kernels — expected,
since the committed object is arch-neutral bytecode, but now checked rather
than assumed. The `Suite` column is the amd64 run; CI runs amd64, and
`MATRIX_ARCH=arm64 ./run.sh` runs the same thing on arm64 guests.

Two things this settles:

- **The 5.15 floor is real, not inferred.** The global-function shape that the
  budget depends on is accepted by a 5.15 verifier.
- **Older is cheaper here, not riskier.** The intuition that an older verifier
  would be closer to the limit is backwards for this program: 5.15 through 6.6
  process ~75k, and 6.12 processes ~118k. The headroom to watch is on the
  *newest* kernel, which is where `TestProgramSize`'s tripwire already runs.

One portability trap the matrix found, worth knowing before writing any test
that reads program metadata: `bpf_prog_info.verified_insns` was added in
**5.16** (`aba64c7da983`). On 5.15 it reads back as zero, so
`ProgramInfo.VerifiedInstructions()` reports "unavailable" and anything that
insists on it fails on the exact kernel the project supports. The portable
source for that number is the verifier's own trailing
`processed N insns (limit 1000000)` line, which every kernel in the matrix
emits; `TestProgramSize` parses that and treats `bpf_prog_info` as a
cross-check.

### Runtime cost

From `make dataplane-bench`, which drives the kernel's own `BPF_PROG_TEST_RUN`
repeat loop. These were taken in the Docker Desktop VM on arm64, where
absolute figures swing 20-30% run to run — **the scaling with rule count is the
part that transfers, not the constants.**

| Path | ns/op (approx.) |
|---|---|
| No rules installed (idle) | 60-80 |
| 1 static rule examined | ~90 |
| 16 statics examined | ~180 |
| 64 statics examined | ~480 |
| 256 statics examined | ~1,650 |
| Victim policy, full 8-rule scan, drop | 105-150 |
| Static rate-limit rule, token bucket | 75-110 |

The static-scan row is the stable, reproducible one: **~6.2 ns per static rule
examined**, on every packet, and it is linear.

**Operator guidance:** static rules are evaluated linearly and unconditionally.
A handful is free; 256 of them is roughly 600 Kpps and will not hold a 10G line
of small packets. Dynamic per-victim rules do NOT have this shape — they cost
one LPM lookup plus a bounded 8-rule scan no matter how many victims are under
mitigation at once, which is why an attack response installs policy blocks
rather than statics.

## Freeze point F6

`include/kapkan_maps.h` is the contract. Map **names**, struct **field order**
and enum **values** are frozen; the Go mirror is
`engine/internal/dataplane/contract.go` and `TestContractMatchesC` fails the
build if the two drift. Appending a field to the tail of a struct or an
enumerator to the end of an enum is compatible; anything else needs a
`KAPKAN_MAP_SCHEMA_VERSION` bump, which makes the next binary recreate the pins
instead of adopting them.
