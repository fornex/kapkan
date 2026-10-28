# Running the XDP data plane in production

> Lives in `engine/deploy/` rather than `engine/docs/` deliberately: `engine/docs/`
> is git-excluded in this repo, so a document placed there is local-only. This one
> has to travel with the systemd unit it talks about. Its user-facing half feeds
> `docs/en/deployment.mdx` when the feature ships.

Operational notes for `dataplane.*`: what privileges the kapkan process needs,
how much memory the BPF maps cost, what SELinux and AppArmor do to it, and the
one traffic shape that gets past every rule (section 6 — read it before you go
live).

Everything marked **measured** was run for this document on kernel
`6.12.76-linuxkit` (aarch64, 14 CPUs, the Docker Desktop VM) against the
committed `kapkanxdp_bpfel.o`. Everything marked **cited** could not be tested
on that kernel and carries a source. Nothing here is inferred from what ought to
be true.

---

## 1. Capabilities

**kapkan needs exactly three: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`.**
Not `CAP_SYS_ADMIN`. All three are required; none is optional.

**Measured** — capability sets varied one at a time, everything else held
constant, running the data-plane test suite (load + `BPF_PROG_TEST_RUN`):

| capability set | result |
|---|---|
| none | `map create: operation not permitted` (EPERM) |
| `CAP_BPF` | maps create; `load program: operation not permitted` (EPERM) |
| `CAP_BPF` + `CAP_PERFMON` | same — `load program` EPERM |
| `CAP_BPF` + `CAP_NET_ADMIN` | reaches the verifier, then **rejected**: `R7 pointer -= pointer prohibited` (EACCES) |
| `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` | **passes**, as uid 1000, `CapEff: 000000c000001000` |

Why each one:

- **`CAP_BPF`** gates `bpf(2)` itself. `map_create` for an LPM trie or an LRU
  hash requires it — the unprivileged carve-out covers only a few map types for
  socket filters, and none of kapkan's fourteen maps qualify.

- **`CAP_NET_ADMIN`** gates the *program type*. `is_net_admin_prog_type()` in
  `kernel/bpf/syscall.c` lists `BPF_PROG_TYPE_XDP`, and `bpf_prog_load()`
  refuses without it:

  ```c
  if (is_net_admin_prog_type(type) && !capable(CAP_NET_ADMIN) && !capable(CAP_SYS_ADMIN))
          return -EPERM;
  ```

  Identical in v5.15 (`syscall.c:2206`) and v6.8 (`syscall.c:2639`) — this is not
  a 6.x-only requirement. Attaching to an interface needs it too, either way you
  attach.

- **`CAP_PERFMON`** is the surprising one, and it is **not** discretionary. The
  verifier's `allow_ptr_leaks` flag *is* `perfmon_capable()`:

  ```c
  /* include/linux/bpf.h, identical in v5.15 and v6.8 */
  static inline bool bpf_allow_ptr_leaks(void) { return perfmon_capable(); }
  /* kernel/bpf/verifier.c */
  env->allow_ptr_leaks = bpf_allow_ptr_leaks();
  ```

  and subtracting one pointer from another is gated on exactly that flag
  (`verifier.c:13775` in v6.8):

  ```c
  if (opcode == BPF_SUB && env->allow_ptr_leaks) { mark_reg_unknown(...); return 0; }
  verbose(env, "R%d pointer %s pointer prohibited\n", ...);
  return -EACCES;
  ```

  `kapkan_xdp.c` computes `data_end - data` to get the frame length, so without
  `CAP_PERFMON` the program **does not load at all**. Note the error class: this
  comes back as **EACCES**, not EPERM, and it arrives as a verifier log. An
  operator who reads "verifier rejected the program" as a kapkan bug will chase
  the wrong thing; the fix is a capability, not a patch.

**`BPF_PROG_TEST_RUN` needs nothing further.** `bpf_prog_test_run()` has no
`capable()` check of its own in either v5.15 or v6.8 — authorisation is the
program fd you already hold. (**Measured**: the suite passes under the three
caps; **cited**: `kernel/bpf/syscall.c:4085` in v6.8.)

**5.15 vs 6.x**: no difference for kapkan. `CAP_BPF` and `CAP_PERFMON` were
split out of `CAP_SYS_ADMIN` in 5.8, below the project's 5.15 floor, and all
three gates above are byte-identical between the v5.15 and v6.8 trees. On a
kernel older than 5.8 there is no split and the process needs `CAP_SYS_ADMIN`,
but that is below the supported floor anyway.

**The floor itself is tested, not asserted.** `make dataplane-matrix` (and the
`kernel floor` CI job) boots 5.15, 6.1, 6.6 and 6.12 under QEMU and runs the
whole data-plane suite on each. The program loads on all four with the same
program tag, and the verifier processes 75,216 instructions on 5.15 against a
1,000,000 limit — 7.5%. See `engine/bpf/README.md` for the table and
`engine/hack/kernel-matrix/README.md` for the harness.

One consequence to expect on a 5.15 host: the startup line
`data plane pre-flight passed ... verified_insns=0` and the
`verified_instructions` field of `kapkan dataplane status` are **zero because
the kernel does not report the number**, not because nothing was verified.
`bpf_prog_info.verified_insns` was added in 5.16.

**Attach works under the same three.** **Measured**: with only
`CAP_BPF,CAP_NET_ADMIN,CAP_PERFMON` as ambient capabilities on a non-root uid,
`link.AttachXDP` to a veth succeeded in **both** `XDP_FLAGS_DRV_MODE` (native)
and `XDP_FLAGS_SKB_MODE` (generic) — so `dataplane.xdp_mode: auto|native|generic`
needs no extra privilege in any of its three settings.

### Ubuntu's sysctl

Ubuntu builds with `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`, which sets
`kernel.unprivileged_bpf_disabled=2` (**cited**: [Ubuntu kernel-team patch
marking it enforced][ubuntu-unpriv], [LKDDB][lkddb]). This does **not** affect
kapkan: the check is `!bpf_capable()`, and a process holding `CAP_BPF` is
`bpf_capable()` regardless of the sysctl. It only means that dropping
capabilities entirely and hoping is not an option — there is no unprivileged
fallback path.

### systemd unit

**The shipped `kapkan.service` does NOT grant any of this, and a drop-in next to
it does: `deploy/kapkan-dataplane.conf`.**

```
install -D -m 0644 kapkan-dataplane.conf \
    /etc/systemd/system/kapkan.service.d/10-dataplane.conf
systemctl daemon-reload && systemctl restart kapkan
```

Why a drop-in rather than an edit to the unit everyone gets: every line in it
relaxes the shipped hardening, and a kapkan that mitigates through BGP alone —
blackhole, flowspec, divert — touches no BPF, no bpffs and no netlink. Handing
`CAP_BPF` and `CAP_PERFMON` to those hosts buys nothing and widens what a
compromised daemon can do. The privileges are opt-in by the same switch the
feature is: one config flag, one drop-in, installed together.

A host with `dataplane.enabled: true` and no drop-in **fails at startup** and
says why (see the triage table). That is deliberate — an operator who configured
in-kernel drops must not get a daemon that came up without them.

The drop-in, in full:

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
ProtectKernelTunables=false
ReadWritePaths=/sys/fs/bpf
RestrictAddressFamilies=AF_NETLINK
MemoryAccounting=yes
LimitMEMLOCK=infinity
# MemoryMax=<map footprint + receive queues + heap + headroom; see section 2>
```

**Measured, end to end, on systemd 255 (Ubuntu 24.04, kernel 6.12.76-linuxkit),
installing the shipped unit exactly as an operator would.** Each relaxation was
then removed on its own to check it was actually load-bearing:

| unit | result |
|---|---|
| shipped `kapkan.service`, no drop-in | **fails**: `missing capability: CAP_BPF … Effective capabilities are 0x0000000000000000` |
| drop-in minus `ProtectKernelTunables=false` | **fails**: `create pin directory /sys/fs/bpf/kapkan: read-only file system` |
| drop-in minus `RestrictAddressFamilies=AF_NETLINK` | **fails**: `could not attach to any of the configured interfaces ([lo]): interface "lo" does not exist` |
| the full drop-in | **works**: `data plane attached interface=lo mode=generic`, `/healthz` → `dataplane: ok (1/1 interfaces attached)`, as uid 997 with `CapEff: 000000c000001000` |

That third row is the one worth remembering, because the error lies. Resolving
an interface name to an ifindex is an `AF_NETLINK` socket, and a blocked socket
comes back through `net.InterfaceByName` as "no such interface" — so a unit
missing one line reports a NIC that is plainly there as absent. Nothing in the
message points at systemd.

The rest, checked rather than assumed:

- **`SystemCallFilter`** — **measured** on systemd 255:
  `systemd-analyze syscall-filter @system-service | grep -w bpf` returns
  nothing; `bpf` appears only in `@privileged` (and `@known`). A unit hardened
  with the recommended `SystemCallFilter=@system-service` and nothing else gets
  EPERM — or rather ENOSYS/SIGSYS — on the very first `bpf(2)`. The shipped unit
  sets **no** syscall filter, so the drop-in does not need to fix one; if you add
  one of your own it must read `SystemCallFilter=@system-service bpf`.

- **`ProtectKernelTunables=yes`** — **cited**, systemd v255
  `src/core/namespace.c`:

  ```c
  static const MountEntry protect_kernel_tunables_sys_table[] = {
          { "/sys",                MOUNT_READ_ONLY,           false },
          { "/sys/fs/bpf",         MOUNT_READ_ONLY,           true  },
          ...
  ```

  `/sys/fs/bpf` is explicitly listed read-only, so with this setting kapkan
  cannot create pins under `dataplane.pin_path` (default
  `/sys/fs/bpf/kapkan`) — which means no `on_exit: keep`, no policy surviving a
  restart, and a failure at startup rather than at the moment it matters.
  `ReadWritePaths=` does not rescue it: the path is mounted read-only by the
  same protection, so the option itself has to go. **Measured** above.

- **`ProtectSystem=strict`** is fine on its own: it leaves `/dev`, `/proc` and
  `/sys` writable and defers those to the `Protect*` options above (**cited**:
  systemd.exec(5)). `ReadWritePaths=/sys/fs/bpf` is belt and braces.

- **`on_exit: keep` survives `systemctl restart` under this unit.** **Measured**:
  the second process logged `data plane adopted the existing attachment on lo`
  and `re-installed static policy over the adopted data plane`, so the gap
  between the two processes forwards nothing.

---

## 2. Map memory and the cgroup

Since **5.11**, BPF map memory is no longer charged against `RLIMIT_MEMLOCK`.
It is allocated with `__GFP_ACCOUNT` and charged to the **memory cgroup of the
process that created the map** (**cited**: Roman Gushchin's "switch to
memcg-based memory accounting" series, [LWN][lwn-memcg], [v9
posting][memcg-v9]). For a systemd unit, that cgroup is the unit's own — so
`MemoryMax=` counts kapkan's BPF maps, and a limit that was fine before the
data plane existed will now OOM the unit at load time.

**Measured**, loading the committed object with stock `dataplane.limits` on a
14-CPU host, reading `/proc/self/fdinfo/<map fd>`:

| map | type | max entries | bytes |
|---|---|---:|---:|
| `kapkan_rl_src6` | LRU hash | 1,048,576 | 134,219,008 |
| `kapkan_rl_src4` | LRU hash | 1,048,576 | 109,053,184 |
| `kapkan_rule_stats` | per-CPU hash | 8,192 | 2,491,648 |
| `kapkan_policies` | array | 1,024 | 532,744 |
| `kapkan_statics` | array | 512 | 33,032 |
| `kapkan_profiles` | array | 256 | 16,648 |
| `kapkan_stats` | per-CPU array | 21 | 5,136 |
| `kapkan_allow4/6`, `kapkan_protect4/6`, `kapkan_victims4/6` | LPM trie | 65,536 each | 0 |
| **total** | | | **246,351,696 (234.9 MiB)** |

The cgroup agrees: `memory.current` moved from 31,293,440 to 277,123,072 across
`ebpf.NewCollection()` — a delta of **234.4 MiB**, charged in one step at load.
(Two runs against two builds of the object gave 233.2 and 234.4 MiB; the map
footprint itself was byte-identical both times, as freeze point F6 requires.)

What an operator needs to take from that table:

- **Two maps are 94% of the cost.** `kapkan_rl_src4` and `kapkan_rl_src6` are
  sized from `dataplane.limits.max_ratelimit_sources`, default `1<<20`. LRU
  hashes are always pre-allocated — `BPF_F_NO_PREALLOC` is not permitted for
  them — so this is paid in full at startup whether or not a single source is
  ever rate-limited. Measured per-entry cost: **104 B** (v4, 16-byte key) and
  **128 B** (v6, 40-byte key). Halving `max_ratelimit_sources` halves ~232 MiB
  of the 235.

  **This is now a knob that works.** The loader rewrites `max_entries` on the
  object before the maps are created; until it existed, `dataplane.limits` was
  validated and then discarded, so lowering the limit changed nothing.
  **Measured** on the same kernel, one process each:

  | limits | `kapkan_rl_src4/6` entries | total footprint |
  |---|---:|---:|
  | defaults | 1,048,576 | 245,352,272 B (**234.0 MiB**) |
  | `max_dynamic_rules: 256`, `max_static_rules: 32`, `max_ratelimit_sources: 65536` | 65,536 | 15,372,624 B (**14.7 MiB**) |

  The other two limits barely move the total (`kapkan_policies` and
  `kapkan_statics` are half a megabyte between them at the defaults) — they
  exist to bound how many rules can be installed, not to save memory. Only
  `max_ratelimit_sources` is worth tuning for a small box.

  Two derived sizes are worth knowing because neither is spelled in the config:
  `kapkan_rule_stats` is created at `max_dynamic_rules + 2 x max_static_rules`
  rather than its compiled-in 8192, and `kapkan_statics` is created at twice
  `max_static_rules` per generation — a static rule with no `match.src` has no
  address family, and the datapath is family-strict, so such a rule compiles to
  one kernel rule per family.

- **The LPM tries cost nothing up front** and grow per insert, so an allowlist
  of 20 prefixes costs about what 20 prefixes should. Their `max_entries` of
  65,536 is a ceiling, not a reservation.

- **Per-CPU maps scale with core count, not with load.** `kapkan_rule_stats` is
  304 B/entry on this 14-CPU host (a 16-byte counter × 14, plus overhead); the
  same map on a 128-core box is roughly nine times larger — call it 22 MiB
  instead of 2.4 MiB. Size `MemoryMax=` on the target machine, not on the test
  one.

- **The telemetry listeners' receive queues are the other large item, and they
  are only charged under load.** A listener queues datagrams for its decode
  workers while they are behind, and every queued datagram pins one of
  goflow2's pooled 9000-byte receive buffers (Go's 9472-byte size class),
  whatever the datagram's real size. **Measured** in a 1 GiB cgroup (kernel
  7.0.14-linuxkit, THP `always`), one listener whose decode workers were
  blocked, under a loopback flood of 1324-byte sFlow datagrams:

  | queue | result |
  |---|---|
  | 65,536 datagrams | full at +628 MiB of `memory.current` — **10,049 B per datagram** — after which every further datagram was dropped and counted |
  | 1,000,000 (the old fixed size) | **OOM-killed 0.7 s** into the flood, ~100,000 datagrams queued, `kapkan_ingest_dropped_flows_total` still **0** |

  The second row is why `listen.queue` exists: the saturation counter was
  never going to move before the kernel killed the process. The default is
  16,384 datagrams, ~157 MiB per listener, both listeners ~314 MiB. Budget
  `listen.queue × 10 KB` per listener, and remember that a quiet week's
  `memory.peak` never saw a full queue.

- **A practical starting point** for the default limits is `MemoryMax=1G` on a
  ≤16-core box: ~235 MiB of maps, ~314 MiB for two full receive queues at the
  default `listen.queue`, plus the Go heap, plus room for the LPM tries under a
  large allowlist. Leave `MemoryAccounting=yes` on and watch `memory.peak` for
  a week before tightening it — and tighten it to the peak plus the queues,
  not to the peak.

- **`LimitMEMLOCK=infinity` is still worth setting** even though 5.11+ ignores
  it for maps: it costs nothing, and it is what keeps the unit working if kapkan
  is ever run on an older kernel. The Go side calls
  `rlimit.RemoveMemlock()`, which is a no-op on kernels that do memcg
  accounting.

- The `memlock:` field in map fdinfo (the numbers in the table) is a footprint
  *estimate* the kernel retains for tooling. On 5.11+ it is not a limit and
  nothing is checked against `RLIMIT_MEMLOCK`. It is still the most convenient
  way to size a unit, which is why it is used here — and it matched the cgroup
  delta to within 1%.

---

## 3. SELinux (RHEL, Rocky, Alma)

The kernel exposes an SELinux object class `bpf` with permissions
`map_create`, `map_read`, `map_write`, `prog_load` and `prog_run`. Under
`enforcing`, a domain needs all five for what kapkan does.

**This bites even without a custom domain.** A systemd service on RHEL runs as
`unconfined_service_t` by default, and the shipped policy does **not** grant
that domain the `bpf` class — multiple vendors document the identical AVC
(**cited**: [Trend Micro][selinux-tm], [Cisco][selinux-cisco],
[Broadcom][selinux-cb]):

```
avc: denied { map_create } for pid=... comm="kapkan" \
  scontext=system_u:system_r:unconfined_service_t:s0 tclass=bpf
```

"unconfined" is a misnomer here — it means unconfined for the *classic* object
classes, not for `bpf`. So yes, a policy snippet is needed on RHEL:

```te
module kapkan_bpf 1.0;

require {
    type unconfined_service_t;
    class bpf { map_create map_read map_write prog_load prog_run };
    class capability2 { bpf perfmon };
}

allow unconfined_service_t self:bpf { map_create map_read map_write prog_load prog_run };
allow unconfined_service_t self:capability2 { bpf perfmon };
```

```
checkmodule -M -m -o kapkan_bpf.mod kapkan_bpf.te
semodule_package -o kapkan_bpf.pp -m kapkan_bpf.mod
semodule -i kapkan_bpf.pp
```

Note the second `allow`: `CAP_BPF` and `CAP_PERFMON` live in the `capability2`
class (they are capability bits above 31), so granting them in the unit file is
necessary but not sufficient under SELinux. `CAP_NET_ADMIN` is in the classic
`capability` class and is already granted to `unconfined_service_t`.

Untested here — this VM has no SELinux. Diagnose on the target with
`ausearch -m avc -ts recent` and confirm with `setenforce 0`; if the failure
disappears, it is policy, not kapkan.

## 4. AppArmor (Ubuntu 24.04)

Ubuntu 24.04 ships AppArmor 4.0.1, whose policy language mediates both new
capabilities. **Measured**: `apparmor_parser -Q` accepts a profile containing
`capability bpf,`, `capability perfmon,` and `capability net_admin,` — they are
real, distinct rules, not aliases of `capability sys_admin`.

The practical consequence is narrow: **a service run from a normal systemd unit
is unconfined by AppArmor and nothing happens.** Ubuntu ships no profile for
kapkan and does not auto-confine arbitrary binaries. There is no policy snippet
to write and no default-enforcing rule to work around.

It matters in exactly two situations:

1. Someone writes a profile for `/usr/bin/kapkan` (or attaches one via
   `AppArmorProfile=` in the unit). It must then contain, at minimum:

   ```
   capability bpf,
   capability perfmon,
   capability net_admin,
   /sys/fs/bpf/kapkan/** rw,
   ```

2. kapkan runs inside a container. Docker drops `CAP_BPF`, `CAP_PERFMON` and
   `CAP_NET_ADMIN` from the default bounding set, so they must be added back:

   ```
   docker run --cap-add=BPF --cap-add=PERFMON --cap-add=NET_ADMIN ...
   ```

   The default **seccomp** profile does not need loosening, contrary to a lot of
   folklore. **Measured** on Docker 29.4: with those three `--cap-add` flags and
   the stock profile, the program loads and the full suite passes;
   `--security-opt seccomp=unconfined` changes nothing. Moby's
   `profiles/seccomp/default.json` allows `bpf` for `CAP_SYS_ADMIN` *and*
   separately for `CAP_BPF`, which is why. Do not reach for
   `seccomp=unconfined` or `--privileged`; neither is required, and both give up
   far more than the three capabilities.

Ubuntu 24.04's other well-known AppArmor change —
`kernel.apparmor_restrict_unprivileged_userns=1` — does not apply: kapkan
creates no user namespaces.

---

## 5. Measured drops on a ban

Every ban whose method is `dataplane` carries what the kernel actually counted
for its rules. It is a nested `dataplane` object on the ban, and it reaches
`/api/v1/bans`, `/api/v1/attacks` and the console's bans table and attack
drawer. A ban with no rules in this box's maps — every blackhole, flowspec,
divert, alert-only and dry-run ban — **omits the object entirely**, so those
payloads are byte-for-byte what they were before this existed.

```json
"dataplane": {
  "packets": 400,
  "bytes": 192800,
  "rules": [ { "id": 0, "packets": 400, "bytes": 192800 } ],
  "policy_id": 0,
  "measured_at": "2026-08-08T19:32:47Z",
  "stale": false
}
```

Four things about it that are not obvious from the shape:

- **`packets`/`bytes` are the ban's LIFETIME totals, not the raw counter.** The
  kernel's counters restart in normal operation — a re-install recreates the
  `kapkan_rule_stats` entries at zero, and a restart that could not adopt the
  pins starts with empty maps. kapkan accumulates deltas across those events, so
  the number only ever goes up for the life of the ban. It is also persisted in
  `ban.state_file`, which is what carries it across a restart.

- **`rules` joins to the ban's `flowspec` array BY INDEX.** `rules[i]` is what
  `flowspec[i]` caught. The counters carry no match of their own precisely so
  the two cannot drift into disagreeing about which rule a number belongs to.
  The array may be **shorter** than `flowspec` (a counter already reaped); a
  missing entry means *unknown*, not zero.

- **`stale: true` means the last reading is old, not that traffic stopped.**
  Counters are scraped every 5 seconds; past three intervals the last good
  values are kept and flagged. They are deliberately not replaced with zeros —
  a datapath whose counters cannot be read has not stopped dropping packets, and
  zero is the one answer an operator would act on and be wrong.

- **`policy_id` is never persisted.** It is an allocation against a map set that
  may have been resized or rebuilt while the process was down; after a restart it
  is absent until the first scrape re-derives it.

The same numbers are on `/metrics` as `kapkan_dataplane_packets_total` by
verdict, and `/api/v1/status`'s `dataplane.dynamic_rules` is the count of
mitigator rules whose counters could actually be read — measured, not tallied
from intent.

---

## 6. IPv6 extension headers: the one way traffic bypasses every rule

**A packet carrying 8 or more IPv6 extension headers is forwarded without a
single rule being evaluated.** Not "the rules ran and none matched" — the rules
never run. Your allow-list, your static drops, the mitigator's rules and every
rate limit are skipped together. It costs an attacker 64 bytes of padding.

This is the datapath's only blind spot, it is deliberate, and it is not going to
be closed by dropping the packet. What follows is how it works, how to see it,
and what to do when you do.

### The mechanism

`kapkan_parse()` walks the IPv6 header chain in a bounded loop:
`KAPKAN_MAX_EXT_HDRS` iterations, unrolled, with the `data_end` bound re-checked
inside the body. The bound is what makes the program verify — an unbounded walk
is rejected outright on 5.15, and the loop's cost multiplies into every rule-scan
path the verifier explores downstream.

Falling off the end of that loop is the cap. The parser returns
`KAPKAN_PARSE_EXTHDR_CAP`, the program counts `pass_exthdr_cap` and returns
`XDP_PASS` **immediately** — before the victim lookup, before the allow-list,
before the rule scan. Nothing downstream of the parser sees the packet at all.

### The threshold, measured

**Measured** on `6.12.76-linuxkit` against the committed `kapkanxdp_bpfel.o`,
by `TestIPv6ExtHdrCapBoundary` (`engine/internal/dataplane/exthdrcap_linux_test.go`).
The test installs two static drop rules for the victim — one matching on
protocol and port, one matching the destination address alone — and sweeps the
header count:

| extension headers | verdict | counter | rules consulted |
|---|---|---|---|
| 0 – 7 | `XDP_DROP` | `drop_static` | yes, normally |
| 8 and above | `XDP_PASS` | `pass_exthdr_cap` | **none** |

The destination-only rule is what makes the second row mean something: it matches
*any* IPv6 packet to that address, and it does not fire.

Eight minimum-length headers is **64 bytes** — less than the IPv6 header they
follow, and cheaper than the TCP header they hide. Header *type* does not matter:
hop-by-hop options, destination options, routing and mobility headers all count
toward the same cap, and `TestIPv6ExtHdrCapCostsSixtyFourBytes` pins the
hop-by-hop case specifically because it is the cheapest chain to build.

The boundary is asserted from **both** sides on purpose. A future change that
lowered the cap to 4 for a verifier-budget win would still pass any test that
only checked "a long chain is passed", while quietly quadrupling the window.

### Why it is passed and not dropped

Because the charter's default verdict is PASS, and a parse limit must never
become a default-deny.

The same header chain can arrive from a legitimate host. Dropping on "my parser
gave up" would mean a packet shape nobody rejected is blackholed by an
implementation budget — and the failure would be silent, permanent, and
attributable to nothing an operator configured. A filter that fails open and says
so is recoverable. One that fails closed on a parser detail is not.

So the packet goes through, and **being seen is the entire mitigation.**

### How you find out

Three places, all fed by the same kernel counter:

- **Prometheus.** `kapkan_dataplane_filter_bypass_packets_total{reason="ipv6_exthdr_cap"}`
  (and `..._bytes_total`). The series is published even at zero, so you can tell a
  quiet alarm from an alarm that was never wired up. The threshold is zero:

  ```yaml
  - alert: KapkanFilterBypassed
    expr: sum(rate(kapkan_dataplane_filter_bypass_packets_total[5m])) > 0
    for: 2m
    labels: { severity: critical }
    annotations:
      summary: "Packets are passing Kapkan's data plane with no rule evaluated"
  ```

  This duplicates `kapkan_dataplane_packets_total{verdict="pass_exthdr_cap"}` on
  purpose — an alert rule should name the thing it means, not a parser statistic.
  It is a second view of one series, not extra traffic. Do not add the two.

- **`kapkan dataplane status`.** A block directly under the verdict line, above
  the pin path, and a marker on the counter row itself. Absent entirely when the
  counter is zero, so its presence *is* the signal. `-json` carries the same thing
  as `.filter_bypass[]` — `jq -e '.filter_bypass | length > 0'` is the check.

- **The console.** An alert-role banner at the top of Overview, a second one on
  the XDP data plane card in Settings, and the `pass_exthdr_cap` verdict badge
  coloured as an alarm rather than as one statistic among twenty. Admin-only, like
  the rest of the data-plane block.

### What to do when the counter moves

**Any** movement is worth looking at. No legitimate traffic chains eight
extension headers — not tunnels, not IPsec, not Mobile IPv6. A non-zero value is
either somebody probing your parser or an attack already routing around your
filter, and the two look identical until you check the source.

1. **Confirm the scale.** Compare `filter_bypass_packets_total` against
   `kapkan_dataplane_packets_total`. A few packets an hour is reconnaissance; a
   sustained rate is the attack that reconnaissance was for. The bytes counter
   separates the two faster than the packet counter does.
2. **Find the source.** The datapath does not record it — the packet never
   reached the victim lookup. Use flow telemetry (your sFlow/NetFlow exporters, or
   `tcpdump 'ip6[6] == 0 or ip6[6] == 60'` on the ingress interface) to identify
   the sources and destinations.
3. **Filter it upstream.** This is the real remedy. An edge router ACL that drops
   or rate-limits IPv6 packets by extension-header count enforces at a place with
   a full parser, and it costs nothing on normal traffic. On most platforms the
   knob is an IPv6 extension-header / hop-by-hop filter in the ingress ACL.
4. **If you cannot filter upstream, alert and investigate.** Keep the Prometheus
   alert on. Do not raise `KAPKAN_MAX_EXT_HDRS` hoping to parse further: the cap
   exists because the verifier budget is finite, raising it moves the window
   rather than closing it, and the same attacker adds one more header.

### What will not help

- **Turning on `drop_malformed`.** It does not apply. These packets are not
  malformed — they parse correctly for as far as the parser goes, and
  `drop_malformed` governs `pass_malformed`/`drop_malformed`, a different counter
  and a different branch.
- **Adding a rule.** There is no rule that catches this, because rule evaluation
  is exactly what is being skipped. A destination-only catch-all does not fire;
  that is measured above.

---

## 7. Quick triage

| symptom | cause |
|---|---|
| `map create: operation not permitted` | no `CAP_BPF` |
| `missing capability: CAP_BPF … Effective capabilities are 0x0` under systemd | the data-plane drop-in is not installed. `install -D -m 0644 kapkan-dataplane.conf /etc/systemd/system/kapkan.service.d/10-dataplane.conf`, then `systemctl daemon-reload && systemctl restart kapkan` |
| `interface "eth0" does not exist` for a NIC that plainly does | the unit's `RestrictAddressFamilies=` has no `AF_NETLINK`. Resolving a name to an ifindex is a netlink socket, and a blocked one surfaces as "no such interface". Install the drop-in |
| `load program: operation not permitted` | no `CAP_NET_ADMIN` (XDP is a net-admin program type) |
| verifier log ending `pointer -= pointer prohibited` | no `CAP_PERFMON` — **not** a kapkan bug |
| SIGSYS / ENOSYS on the first `bpf(2)` | `SystemCallFilter=` without `bpf` |
| `avc: denied ... tclass=bpf` | SELinux; see section 3 |
| `create pin directory /sys/fs/bpf/kapkan: read-only file system` | `ProtectKernelTunables=yes` is still in force; the drop-in sets it to `false` and `ReadWritePaths=` cannot substitute for that |
| unit OOM-killed at startup | `MemoryMax=` below the ~235 MiB of maps; see section 2 |
| unit OOM-killed under a telemetry burst, `kapkan_ingest_dropped_flows_total` still 0 | `MemoryMax=` leaves no room for the receive queues, `listen.queue` × ~10 KB per listener; see section 2 |
| `pin path is not safe to use: ... is on filesystem type 0x…, not bpffs` | `pin_path` is an ordinary directory: bpffs is not mounted, or the unit made `/sys/fs/bpf` read-only |
| `pin path is not safe to use: ... is mode 0777` / `owned by uid N` | the pin directory is writable by, or owned by, somebody else. A local user who can write it can pre-create a program kapkan would ADOPT, so this is a refusal to start. `chown` it to the kapkan user and `chmod 0700` |
| `kernel too old: running X, the XDP data plane needs 5.15 or newer` | below the supported floor; set `dataplane.enabled: false` and use a flowspec/blackhole ladder |
| `another XDP program already owns this interface's hook` | something else is attached (Cilium, a leftover `ip link set xdp`). `ip -details link show <if>` or `bpftool net` |
| `this driver has no native XDP support` | `xdp_mode: native` on a device without driver XDP. `auto` falls back to the generic path and records that it did; `native` fails on purpose, because it costs ~10x less CPU per packet and silently giving up that difference is not a favour |
| startup log: `REJECTED the existing pinned data plane and rebuilt it` | this binary's BPF object, map layout or `dataplane.limits` differ from the pinned ones, so they could not be adopted. Expected after an upgrade that changes `bpf/`; the cost is that dynamic rules from the previous process are gone and active attacks are re-mitigated on their next detection interval |
| `/healthz` says `dataplane: DEGRADED (n/m interfaces attached)` | at least one configured interface has no live XDP attachment. Alert on `kapkan_dataplane_degraded`; the status code stays 200 because a restart cannot conjure a missing NIC |
| a `dataplane` ban shows `fell_back_from: dataplane` and a blackhole route | the install failed and the ban degraded to its configured fallback, which is louder and safer than going unmitigated. The reason is in the log next to it — usually `ErrNoPolicySlots` (raise `dataplane.limits.max_dynamic_rules`) or `ErrNoProfileSlots` (more than 64 distinct live rate-limit rates) |
| `pass_exthdr_cap` is non-zero, or `kapkan dataplane status` prints a FILTER BYPASSED block | packets carrying 8+ IPv6 extension headers are being forwarded with **no rule evaluated**. Not a parser statistic — treat it as possible evasion. See section 6 |
| a ban's `dataplane.stale` is true in `/api/v1/bans` | the per-rule counters could not be read for more than three scrape intervals. The numbers shown are the last good ones, NOT zeros — the rules are still installed and still dropping; it is the *reading* that failed. Check the log for `reading in-kernel drop counters failed` |

---

## Sources

- [LWN: bpf — switch to memcg-based memory accounting][lwn-memcg] and the
  [v9 patch series][memcg-v9] (kernel 5.11)
- [Ubuntu kernel-team: mark `CONFIG_BPF_UNPRIV_DEFAULT_OFF` enforced][ubuntu-unpriv];
  [LKDDB entry][lkddb]
- systemd v255 `src/core/namespace.c` (`protect_kernel_tunables_sys_table`) and
  systemd.exec(5) for `ProtectSystem=strict`
- Linux v5.15 / v6.8: `include/linux/bpf.h` (`bpf_allow_ptr_leaks`),
  `kernel/bpf/syscall.c` (`is_net_admin_prog_type`, `bpf_prog_test_run`),
  `kernel/bpf/verifier.c` (`allow_ptr_leaks`, pointer-subtraction gate)
- [moby `profiles/seccomp/default.json`][moby-seccomp] — `bpf` is allowed for
  `CAP_BPF`, not only `CAP_SYS_ADMIN`
- SELinux `bpf` class denials under `unconfined_service_t`:
  [Trend Micro KA-0014560][selinux-tm], [Cisco 220545][selinux-cisco],
  [Broadcom 292463][selinux-cb]

[lwn-memcg]: https://lwn.net/Articles/829307/
[memcg-v9]: https://lore.kernel.org/bpf/20201201215900.3569844-33-guro@fb.com/
[ubuntu-unpriv]: https://patchwork.ozlabs.org/project/ubuntu-kernel/patch/20210901174435.497412-1-cascardo@canonical.com/
[lkddb]: https://cateee.net/lkddb/web-lkddb/BPF_UNPRIV_DEFAULT_OFF.html
[moby-seccomp]: https://github.com/moby/profiles/blob/main/seccomp/default.json
[selinux-tm]: https://success.trendmicro.com/en-US/solution/KA-0014560
[selinux-cisco]: https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint-private-cloud/220545-resolve-linux-connector-selinux-policy-f.html
[selinux-cb]: https://knowledge.broadcom.com/external/article/292463
