# Running the XDP data plane in production

> Lives in `engine/deploy/` rather than `engine/docs/` deliberately: `engine/docs/`
> is git-excluded in this repo, so a document placed there is local-only. This one
> has to travel with the systemd unit it talks about. Its user-facing half feeds
> `https://kapkan.io/docs/deployment` when the feature ships.

Operational notes for `dataplane.*`: what privileges the kapkan process needs,
how much memory the BPF maps cost, and what SELinux and AppArmor do to it.

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

```ini
[Service]
# The three, and only the three. CapabilityBoundingSet caps what the process
# could ever regain; AmbientCapabilities is what it actually starts with, so
# this works with User= set to a non-root account.
User=kapkan
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
NoNewPrivileges=yes

# bpf(2) is in systemd's @privileged group and NOT in @system-service, so the
# usual hardening line silently blocks every BPF syscall. Add it back by name.
SystemCallFilter=@system-service bpf

# Pre-5.11 kernels charge map memory against RLIMIT_MEMLOCK. Harmless on 5.11+.
LimitMEMLOCK=infinity

# See section 2 — the maps are charged to this unit's memory cgroup at load.
MemoryAccounting=yes
# MemoryMax=<at least map footprint + heap + headroom; see the table below>

# Do NOT set these:
#   ProtectKernelTunables=yes   -> mounts /sys AND /sys/fs/bpf read-only
#   PrivateNetwork=yes          -> private sysfs and no host interfaces
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf
```

Three of those lines are load-bearing and each was checked rather than assumed:

- **`SystemCallFilter`** — **measured** on systemd 255 (Ubuntu 24.04):
  `systemd-analyze syscall-filter @system-service | grep -w bpf` returns
  nothing; `bpf` appears only in `@privileged` (and `@known`). A unit hardened
  with the recommended `SystemCallFilter=@system-service` and nothing else gets
  EPERM — or rather ENOSYS/SIGSYS — on the very first `bpf(2)`.

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

- **`ProtectSystem=strict`** is fine on its own: it leaves `/dev`, `/proc` and
  `/sys` writable and defers those to the `Protect*` options above (**cited**:
  systemd.exec(5)). `ReadWritePaths=/sys/fs/bpf` is belt and braces.

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

- **A practical starting point** for the default limits is `MemoryMax=512M` on a
  ≤16-core box: ~235 MiB of maps, plus the Go heap, plus room for the LPM tries
  under a large allowlist. Leave `MemoryAccounting=yes` on and watch
  `memory.peak` for a week before tightening it.

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

## 5. Quick triage

| symptom | cause |
|---|---|
| `map create: operation not permitted` | no `CAP_BPF` |
| `load program: operation not permitted` | no `CAP_NET_ADMIN` (XDP is a net-admin program type) |
| verifier log ending `pointer -= pointer prohibited` | no `CAP_PERFMON` — **not** a kapkan bug |
| SIGSYS / ENOSYS on the first `bpf(2)` | `SystemCallFilter=` without `bpf` |
| `avc: denied ... tclass=bpf` | SELinux; see section 3 |
| pin creation fails, `/sys/fs/bpf` read-only | `ProtectKernelTunables=yes` |
| unit OOM-killed at startup | `MemoryMax=` below the ~235 MiB of maps; see section 2 |
| `pin path is not safe to use: ... is on filesystem type 0x…, not bpffs` | `pin_path` is an ordinary directory: bpffs is not mounted, or the unit made `/sys/fs/bpf` read-only |
| `pin path is not safe to use: ... is mode 0777` / `owned by uid N` | the pin directory is writable by, or owned by, somebody else. A local user who can write it can pre-create a program kapkan would ADOPT, so this is a refusal to start. `chown` it to the kapkan user and `chmod 0700` |
| `kernel too old: running X, the XDP data plane needs 5.15 or newer` | below the supported floor; set `dataplane.enabled: false` and use a flowspec/blackhole ladder |
| `another XDP program already owns this interface's hook` | something else is attached (Cilium, a leftover `ip link set xdp`). `ip -details link show <if>` or `bpftool net` |
| `this driver has no native XDP support` | `xdp_mode: native` on a device without driver XDP. `auto` falls back to the generic path and records that it did; `native` fails on purpose, because it costs ~10x less CPU per packet and silently giving up that difference is not a favour |
| startup log: `REJECTED the existing pinned data plane and rebuilt it` | this binary's BPF object, map layout or `dataplane.limits` differ from the pinned ones, so they could not be adopted. Expected after an upgrade that changes `bpf/`; the cost is that dynamic rules from the previous process are gone and active attacks are re-mitigated on their next detection interval |
| `/healthz` says `dataplane: DEGRADED (n/m interfaces attached)` | at least one configured interface has no live XDP attachment. Alert on `kapkan_dataplane_degraded`; the status code stays 200 because a restart cannot conjure a missing NIC |
| startup refused: `escalation ladder uses "dataplane", which this build cannot execute` | this release has no mitigator backend for in-kernel drops yet. The rung would be announced as an alert-only stage, so kapkan refuses rather than run a configuration whose drop is not a drop. Use `flowspec`/`blackhole`/`none`; `static_rules` and `allowlist` are unaffected |

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
