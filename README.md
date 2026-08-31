# Kapkan

**Free, open-source DDoS detection and mitigation for ISPs and hosting providers.**

> **This repository is a monorepo.** Four independently-developable folders:
> `engine/` — the Go engine + REST API (documented below); `console/` — the operator-console UI
> (embedded into the binary); `site/` — the kapkan.io marketing + docs site; `docs/` — the
> user-facing documentation. `make build` (root) produces a **single binary** with the console
> `go:embed`'d — see the root `Makefile`. The rest of this README documents the engine.

Kapkan is a single Go binary that ingests flow telemetry (NetFlow v5/v9, IPFIX, sFlow v5)
from your routers, detects volumetric attacks against the prefixes you protect in seconds,
and mitigates them automatically — BGP RTBH (remotely-triggered blackhole), surgical BGP
FlowSpec rules, diversion to a scrubbing node, or drops in this box's own in-kernel XDP
data plane — with a web API, Prometheus metrics, and Telegram/webhook notifications. It is
a free replacement for the features commercial flow-DDoS products charge for.

It is **dry-run by default**: until you explicitly flip the switch, every would-be blackhole
is logged and exposed via the API but never announced to your routers.

The full user documentation — every config key, the deployment guides, the data plane and
the network-integration lab — lives at **[kapkan.io/docs](https://kapkan.io/docs)**
(English, Russian, German, French, Spanish). This README is the engine's own reference.

## Features

- **Ingest** sFlow v5, NetFlow v5/v9 and IPFIX over UDP via [goflow2](https://github.com/netsampler/goflow2), in library mode (no sidecar).
- **Detect** per-destination volumetric attacks using sampling-corrected pps / Mbps / flows-per-second thresholds over a sliding window. ≥20M flows/sec/core on the hot path. Diffuse subnet-spread floods are caught by [carpet-bomb detection](#carpet-bomb-detection).
- **Mitigate** four ways, individually or as an [escalation ladder](#escalation-ladders): drop locally in an in-kernel **[XDP data plane](#in-kernel-data-plane-xdp)**; announce **BGP FlowSpec** rules (RFC 8955/8956) that drop only the attack vector, IPv4 and IPv6 at parity; **divert** the victim to a scrubbing node; or announce `/32` and `/128` **blackhole** routes — all through an embedded [GoBGP](https://github.com/osrg/gobgp) speaker.
- **Scrub** with your own nodes: a second box running [`kapkan scrub`](#managed-scrubbing-nodes) takes the diverted traffic, is told exactly what to drop, and filters it in its own kernel — same binary, no second product.
- **Safe by construction** — see [Safety model](#safety-model).
- **Classify** each attack from its flow sample and per-protocol rates — amplification (NTP/DNS/CLDAP/memcached/SSDP/chargen), SYN/UDP/TCP/ICMP/fragment floods — with the inferred vector in events, notifications and the API.
- **Observe** through a REST API, Prometheus `/metrics`, an embedded operator console, and Telegram, Slack, email, webhook and exec-hook notifications.

## Quickstart

No build step — grab a prebuilt, signed release (see [Install](#install) to verify it first):

```sh
# Download and unpack a release (linux amd64/arm64) — or `apt install ./kapkan_*.deb`.
VER=v1.6.0
curl -fLO "https://github.com/fornex/kapkan/releases/download/$VER/kapkan_${VER#v}_linux_amd64.tar.gz"
tar xzf "kapkan_${VER#v}_linux_amd64.tar.gz"   # yields ./kapkan and ./deploy/

# Run in dry-run with the bundled example config (text logs).
./kapkan -config deploy/config.example.yaml -log-format text
```

(Building from source instead? See [Development](#development).)

Point your routers' flow exporters at the configured ports (sFlow `:6343`, NetFlow/IPFIX
`:2055`), then watch:

```sh
curl -s localhost:8080/api/v1/status | jq
curl -s localhost:8080/api/v1/attacks | jq
curl -s localhost:8080/metrics | grep kapkan_
```

No router handy? Generate synthetic attack traffic with the `pkg/flowgen` package (used
throughout the tests) to validate detection end-to-end.

## Configuration

Configuration is a single YAML file (see [`configs/dev.yaml`](engine/configs/dev.yaml) for
development and [`deploy/config.example.yaml`](engine/deploy/config.example.yaml) for
production). `kapkan -check-config <path>` validates one without starting the daemon, and
`kapkan -dump-schema` prints the machine-readable JSON schema. The main keys — the complete
reference, key by key, is [kapkan.io/docs/configuration](https://kapkan.io/docs/configuration):

| Key | Meaning |
| --- | --- |
| `dry_run` | When true (default), blackholes are logged and tracked but **never announced**. |
| `listen.sflow` / `listen.netflow` | UDP listen addresses. NetFlow v5/v9 and IPFIX share the netflow socket. At least one is required. |
| `sampling.default_rate` | Sampling rate used when an exporter does not report its own (must be ≥ 1). |
| `sampling.boundary[]` | Optional per-exporter boundary interfaces (`exporter`, `external_ifindexes`, `egress_sampling`). Telemetry from several vantage points counts the same packet once per exporter that sees it; naming the edge interfaces makes kapkan count traffic only where it crosses your border. `sampling.boundary_debug: true` temporarily emits a per-exporter/per-interface byte breakdown to find those ifIndexes. |
| `flow_sources` | Optional allowlist of exporter addresses. Telemetry arrives over unauthenticated UDP, so the source address is spoofable: with this list set, only listed exporters get their own `exporter` metric label and everything else buckets under `other`, bounding metric cardinality. Does not affect detection. |
| `networks` | Protected prefixes. Detection applies **only** to destinations inside these; they must not overlap. |
| `protected_whitelist` | Addresses that are **never** banned, regardless of traffic. |
| `thresholds.pps` / `.mbps` / `.flows_per_sec` | Per-destination thresholds, after sampling correction. All must be > 0. |
| `thresholds.tcp_pps` / `udp_pps` / `icmp_pps` / `tcp_syn_pps` / `frag_pps` (+ `_mbps` each) | Optional per-protocol thresholds; 0/absent disables. Any crossed threshold triggers (OR). `tcp_syn` counts pure SYNs (SYN set, ACK clear); `frag` counts non-first IP fragments. |
| `thresholds_outgoing` | Optional. Enables detection of attacks **originated by** protected hosts (compromised machines). Same keys as `thresholds`, at least one must be set; absent, outgoing traffic is not even counted. |
| `hostgroups[]` | Optional named prefix groups with their own thresholds and mitigation policy (see [Hostgroups](#hostgroups)). Each group may also set `thresholds_outgoing` and a `tenant` label (see [Multi-tenancy](#multi-tenancy)). |
| `tenant` | Optional tenant label for the implicit global/fallback group (top level). See [Multi-tenancy](#multi-tenancy). |
| `samples.enabled` / `buffer_flows` / `flows_per_attack` | Traffic buffer for attack samples (defaults: on / 65536 / 20). Recent flows are buffered continuously so the moment a threshold trips, the attack's dominant sources, ports and protocols are already attached to the event, the notification and the API — no post-detection capture delay. Sizing changes require a restart. |
| `geoip.enabled` / `asn_database` / `country_database` | Optional GeoIP/ASN attribution of attack-sample sources against MaxMind GeoLite2 (or GeoIP2) `.mmdb` files. Both databases are optional and independent. When an ASN database is loaded the sample, API and dashboard carry a **per-ASN top-talkers** breakdown ("from which AS"); a country database stamps each sampled source with its country. Database-path changes require a restart. Default off. |
| `baseline` | Continuous learned per-host thresholds (see [Baselines](#baselines)). Optional; per-hostgroup overridable. |
| `carpet` | Optional carpet-bomb detection: aggregate rates per supernet with a fan-out gate (see [Carpet-bomb detection](#carpet-bomb-detection)). Alert-only unless `carpet.mitigation` is set. |
| `mitigation` | Default mitigation method for every group: `blackhole` (default), `flowspec`, `divert` or `dataplane`. Per-hostgroup overridable; superseded by `escalation` when that is present. |
| `escalation[]` | An [escalation ladder](#escalation-ladders) — `after_seconds` + `action` rungs that step the response up while an attack persists. |
| `flowspec.action` / `rate_mbps` | FlowSpec rule action: `discard`, or `rate_limit` with a ceiling (see [FlowSpec](#flowspec-surgical-mitigation)). |
| `scrubbing` | Diversion target(s): the scalar `next_hop`/`next_hop6`/`community`/`local_pref` of a scrubbing center, plus `nodes[]` / `node_selection` / `on_all_nodes_lost` / `stale_after_seconds` for [managed scrubbing nodes](#managed-scrubbing-nodes). Per-hostgroup overridable. |
| `dataplane` | The [in-kernel XDP data plane](#in-kernel-data-plane-xdp): `interfaces`, `xdp_mode`, `pin_path`, `on_exit`, `drop_malformed`, `allowlist`, `ratelimit_profiles[]`, `static_rules[]`, `limits`, and the off-path `fingerprint` plane (JA4 source-blocking). Absent = off. |
| `ban.ttl_seconds` | Every announcement auto-withdraws after this. No permanent bans. |
| `ban.unban_hysteresis_seconds` | Traffic must stay below threshold this long before withdrawing, to prevent flapping. |
| `ban.max_active_bans` | Hard cap on simultaneous bans; new bans past the cap are refused. |
| `ban.max_banned_fraction` / `max_bans_per_window` + `ban_window_seconds` | Blast-radius guards: cap the share of your own address space that may be blackholed at once (per address family), and the rate of new bans. Both default to 0 = off. See [Safety model](#safety-model). |
| `ban.fallback` | What happens when a peer rejects a `flowspec`/`divert` announce: `blackhole` (default — degrade rather than leave the victim undefended) or `none` (reject the ban). |
| `ban.state_file` | Writable path where active bans are persisted and re-announced on startup, so an upgrade does not drop mitigation (see [Upgrading](#upgrading)). Empty = off; an unwritable path degrades to no persistence, never a startup failure. |
| `bgp.local_asn` / `router_id` / `next_hop` / `next_hop6` / `community` | BGP identity, blackhole next-hops (v4/v6) and RTBH community (`ASN:value`). `router_id` must be IPv4. Optional `communities` (list, overrides `community`) and `local_pref`; both overridable per hostgroup via a group `bgp:` block. |
| `bgp.neighbors[]` | eBGP peers: `address`, `remote_asn` (and optional `port` for testing). |
| `notify.telegram.token_env` / `chat_id` | Telegram bot: the token is read from the named **environment variable**, never the file. |
| `notify.webhook.url` | Optional generic JSON POST target for attack start/end. Payload documented in [`docs/callback-schema.json`](docs/callback-schema.json) (versioned via `schema_version`). |
| `notify.slack.webhook_url` | Optional Slack incoming webhook. |
| `notify.email.smtp_host` / `from` / `to[]` / `username_env` / `password_env` / `require_tls` | Optional SMTP notifications. Credentials come from environment variables. STARTTLS is used when the server offers it and **required** when credentials are configured or `require_tls` is set; plaintext delivery to a non-loopback host is loudly logged. |
| `notify.exec.command` / `timeout_seconds` / `format` | Optional hook executed on every attack event, no shell. The command must exist and be executable at config load. On timeout (default 10s) the hook's whole process group is killed. The hook receives a **minimal environment** (PATH/HOME/TZ/LANG/USER/TMPDIR) — the daemon's secrets are not inherited. `format` selects the convention: `kapkan` (default — event name as `argv[1]`, payload JSON on stdin, same schema as the webhook) or `fastnetmon` (see below). |
| `api.listen` | REST API + metrics listen address. |
| `api.token_env` / `api.tokens` | API auth: a single operator token (`token_env`) or a role-based `tokens` list (`viewer`/`operator`/`agent`, each with an optional `tenant` scope); secrets come from the named env vars. See [Authentication](#authentication) and [Multi-tenancy](#multi-tenancy). |
| `api.dashboard` | Serve the embedded operator console on the API listener. Default true; false leaves only the JSON API and metrics. |
| `storage.clickhouse` | Optional attack/traffic history in ClickHouse (see [Storage](#storage-optional)). Absent = kapkan runs entirely on live data. |
| `update_check` | Opt-in check for a newer release (`enabled`, `interval_seconds`, `channel`, `url`, `notify`). **Off by default — kapkan never phones home.** When on it transmits only the HTTP request itself, never node identity, config or attack data. |

Sampling: every rate is multiplied by the exporter's sampling rate (from the flow packet
when present, else `sampling.default_rate`) so thresholds are expressed in real,
unsampled traffic units.

### Hostgroups

Group prefixes under a shared policy instead of one global threshold set:

```yaml
hostgroups:
  - name: web                    # tighter per-host limits for this /26
    networks: ["203.0.113.0/26"]
    thresholds: { pps: 20000, mbps: 500, flows_per_sec: 10000 }
  - name: customers-no-rtbh      # detect and notify, but never auto-blackhole
    networks: ["203.0.113.64/26"]
    ban: false
  - name: dns-pool               # alert on the pool's TOTAL traffic
    networks: ["203.0.113.128/26"]
    calculation: total
    thresholds: { pps: 300000, mbps: 4000, flows_per_sec: 150000 }
```

Rules:

- A host is owned by the group with the **most specific (longest) matching prefix**;
  hosts matched by no group fall back to the implicit `global` group carrying the
  top-level `thresholds`. Group prefixes must lie inside `networks`.
- `thresholds` is optional — omitted, the group inherits the global thresholds.
- `ban: false` keeps detection and notifications but disables automatic RTBH for the
  group's hosts (manual bans still work).
- `calculation: total` evaluates the **sum** of the group's traffic instead of each
  host: attacks are reported for the group as a whole (`scope: "group"` in events,
  notifications and the API) and never trigger automatic bans — there is no single
  host to blackhole. `calculation: per_host` (the default) evaluates each host.
- Hostgroups hot-reload with the rest of the config.

### Outgoing detection

```yaml
thresholds_outgoing:
  pps: 50000
  udp_pps: 20000
```

With a `thresholds_outgoing` block (global or per hostgroup), kapkan also watches traffic
**leaving** protected hosts and reports `direction: "outgoing"` attacks — the signature of
a compromised machine inside your network. A host attacked and attacking at the same time
holds two independent attack records but shares one RTBH route; the route is withdrawn
only when the last of the two attacks ends. Without the block, outgoing traffic is not
counted at all (zero hot-path cost).

Note that an RTBH blackhole is destination-based: banning an outgoing attacker kills
traffic *to* the host (taking it offline, which usually stops the abuse), and stops the
outbound flood itself only where the edge also drops sources in blackholed prefixes
(e.g. uRPF). Set `ban: false` on the hostgroup if you only want the alert.

### Baselines

```yaml
baseline:
  factor: 3              # attack = traffic above learned_normal × factor
  half_life_seconds: 3600
  warmup_seconds: 600
  floor: { pps: 5000, mbps: 50, flows_per_sec: 2000 }
```

With a `baseline` block kapkan continuously learns every host's normal traffic level
(EWMA per host, per direction; per-group totals for `calculation: total` groups) and
tightens the effective thresholds to `learned_normal × factor` — so a host that
normally does 10k pps is flagged at 30k instead of waiting for the global 80k. This is
the "stop tuning thresholds by hand" mode: FastNetMon's automated baseline is an
offline calculator you run and copy numbers from; kapkan's is online and follows your
traffic continuously.

The static thresholds stay as guards, and the design is poisoning-aware:

- **Ceiling**: traffic above the static thresholds always triggers — a poisoned or
  fast-grown baseline can never raise the bar above what you configured.
- **Floor**: the effective threshold never drops below `floor` — quiet hosts don't
  become hair-triggers.
- **Frozen under attack**: attack traffic (including the hysteresis tail) never trains
  the baseline.
- **Clamped learning**: outside attacks, each sample is capped at `baseline × factor`,
  so a slow attacker ramp raises the baseline by at most `2^(factor−1)` per half-life
  (e.g. 4× per hour at the defaults factor 3 / half-life 3600s — hours to reach the
  static ceiling from a normal level, and never past it). Aggressive settings (large
  factor, short half-life) shrink that window: pick them deliberately.
- **Learning only on real traffic**: a direction with no traffic in the window never
  trains its baseline (so an incoming-only host keeps its static outgoing threshold,
  and an empty `total` group never warms up to a zero baseline).
- **Warm-up**: a freshly observed host is protected by static thresholds only for
  `warmup_seconds`, counted from its first real traffic. Note the warm-up traffic
  itself trains the initial baseline — a host that is *already* under a sub-static
  flood when kapkan first sees it learns that flood as "normal" (bounded by the static
  ceiling); there is no clean reference for a host attacked from first sight. An
  evicted (long-quiet) host re-warms up when it returns. Set `warmup_seconds` to at
  least a few multiples of `half_life_seconds` so the baseline converges before it
  gates.

Learned levels are visible per host in the API (`baseline` / `baseline_out` in the
hosts snapshot). Hostgroups inherit the global block or override it wholesale
(`baseline: { enabled: false }` opts a group out).

### Carpet-bomb detection

A carpet bomb spreads the flood across a whole subnet so no single host ever crosses its
threshold — the classic way to stay under a per-host detector while saturating the link
all the same. With a `carpet` block kapkan also folds per-host rates into their supernet
and evaluates the aggregate:

```yaml
carpet:
  aggregation_prefix_v4: 24  # fold per /24 (default)
  aggregation_prefix_v6: 48  # and per /48 (default)
  min_hosts: 10              # fan-out gate (default 10, minimum 2)
  thresholds:                # AGGREGATE volume over the whole prefix
    pps: 2000000
    mbps: 20000
  # mitigation: flowspec     # optional; alert-only by default
  # max_active_prefix_bans: 10
```

`min_hosts` is the fan-out gate: at least that many distinct destinations in the prefix
must carry traffic in the window, so one heavy host — already caught per-host — is never
re-reported as a carpet bomb. Set the aggregate thresholds well above the per-host ones;
they sum the whole prefix. A carpet attack carries `scope: "prefix"`, the aggregation CIDR
in `prefix` and its fan-out in `hosts`, alongside the usual sample and classification.

Mitigation is **opt-in** and separate from host bans: `carpet.mitigation` accepts
`flowspec` (vector-narrowed rules across the prefix), `dataplane` (the same rule installed
locally, see below) or `blackhole` (drops the entire prefix — the heavy hammer). `divert`
is deliberately not offered: steering a whole /24 into a scrubbing center is a routing
decision an operator makes deliberately, not one a detector should make automatically.
Any method **refuses** a prefix that contains a `protected_whitelist` address — the
whitelist guarantee is absolute and a prefix-wide mitigation cannot exempt one member — and
the alert still fires. Carpet bans have their own cap, `max_active_prefix_bans` (default
10), so host bans and prefix bans can never starve each other.

### In-kernel data plane (XDP)

RTBH, FlowSpec and diversion are all *requests*: they ask a peer to drop or redirect, and
depend on that peer being willing and able. The data plane instead drops the packets
itself — kapkan loads an XDP program into the kernel of the box it runs on and writes the
rules the detector already builds for FlowSpec into kernel maps. Nothing propagates, and no
peer has to accept anything:

```yaml
dataplane:
  interfaces: [eth0]            # NICs to attach to (at least one; restart to change)
  xdp_mode: auto                # auto (native, fall back to generic) | native | generic
  pin_path: /sys/fs/bpf/kapkan  # pinned policy survives a restart of this process
  on_exit: keep                 # keep enforcing on shutdown, or `detach`
  drop_malformed: false         # unparseable frames pass and are counted

  allowlist:                    # SOURCE prefixes that always pass, checked first
    - "192.0.2.0/24"

  ratelimit_profiles:           # named ceilings, referenced by static rules
    - { name: icmp_cap, mbps: 10 }
    - { name: handshake_cap, pps: 20 }
    - { name: quic_handshake_cap, pps: 20 }

  static_rules:                 # always-on operator policy, first match wins
    - name: cap_tls_handshakes  # per-source ceiling on new TLS handshakes
      match: { proto: tcp, dst_port: 443, payload: tls_client_hello }
      action: ratelimit
      profile: handshake_cap
    - name: cap_quic_handshakes # ...and its own ceiling for QUIC/HTTP-3
      match: { proto: udp, dst_port: 443, payload: quic_initial }
      action: ratelimit
      profile: quic_handshake_cap
    - name: drop_chargen
      match: { proto: udp, src_port: 19 }
      action: drop
    - name: cap_icmp
      match: { proto: icmp }
      action: ratelimit
      profile: icmp_cap

mitigation: dataplane           # or a `dataplane` rung in an escalation ladder
```

**The one question that decides whether this applies to you:** the filter can only drop
packets that *reach the machine kapkan runs on*. It helps when kapkan sits in the traffic
path — a Linux border router, a bump-in-the-wire box, the attacked host itself, or a
scrubbing node. In the classic off-path deployment (a VM that receives NetFlow and speaks
BGP back), no attack traffic crosses that VM and there is nothing for it to drop; keep
using RTBH and FlowSpec there. And an XDP filter runs on packets that already arrived, so
it cannot un-saturate an upstream link — that is what the router-based rungs are for.

The data plane is a mitigation *method* like the others and inherits the whole safety
model: dry-run, whitelists, TTLs and the ban caps apply unchanged, because it plugs in at
the same point — only the last step differs. Its default verdict is always PASS: it
executes decisions made by the detector, it never classifies traffic. Severity across the
ladder runs `none < dataplane < flowspec < divert < blackhole`.

`allowlist` (source prefixes that always pass) is a different axis from
`protected_whitelist` (destinations that are never banned); both are enforced in the
kernel. `limits.max_dynamic_rules` (default 4096) caps the mitigator's rules and must be at
least `ban.max_active_bans × 8`, since a ban contributes up to 8 rules.

`static_rules` are **first match wins**, so a rule an earlier one already covers — or one
whose sources the allowlist admits before any rule is reached — can never fire. Kapkan
reports those on every apply rather than rejecting the config: a WARN line, the reload
report, the `policy_shadowed` condition on `/healthz`, the
`dataplane_shadowed_static_rules` metric, and a WARNING from `kapkan -check-config`.

Rules also arrive from **outside** the detector: `POST /api/v1/dataplane/sources` lets
whoever already terminates a victim's traffic (an nginx, a log exporter, an operator) hand
kapkan a source to drop, scoped to that victim, with a mandatory TTL — HTTP awareness
without kapkan parsing HTTP. The ban guarantees hold unabridged: bounded TTLs carried into
the kernel per rule, accounting against `max_dynamic_rules`, dry-run honoured, one audited
event per call including refusals, tenant scoping via the victim, and state-file
persistence. A block anchors the kernel policy at the SOURCE, so one source holds at most
8 victims and distinct sources get only the slots left after every ban could claim its own
— blocks are refused before a ban is ever starved. An allowlisted source, a protected
victim or an absent data plane are errors, not silent no-ops, because the datapath would
pass those packets before reaching any rule. The binary ships the reference caller:
`kapkan nginx-exporter` tails an nginx JSON access log, measures per-source request rates
per window, and posts the verdicts to this channel — a supported component, and the embryo
of the future edge role. Full contract:
[kapkan.io/docs/dataplane](https://kapkan.io/docs/dataplane#source-blocks-from-your-own-stack).

A `ratelimit` action is enforced **per source address** — each source gets its own token
bucket, which is the one thing BGP FlowSpec structurally cannot express, since its
traffic-rate caps an aggregate that attackers and legitimate clients then compete for.
`match.payload` narrows a rule to the shape of a handshake, one value per transport:
`tls_client_hello` matches TCP segments opening a TLS ClientHello — a **TLS handshake
flood**, which a SYN-flags rule cannot see because those connections are established — and
`quic_initial` matches UDP datagrams opening a QUIC v1 Initial, the packet every
QUIC/HTTP-3 handshake starts with. Both are read from fixed offsets with no reassembly and
no decryption: a split ClientHello, a QUIC v2 or version-negotiation packet, and anything
too short to decide do not match and are forwarded. Requirements,
capabilities, tuning and the measured block rates are in the
[data-plane guide](https://kapkan.io/docs/dataplane); `kapkan dataplane status` reports
whether the kernel is actually filtering, and works with the daemon stopped.

Beyond matching a handshake's *shape*, the data plane can fingerprint the *client* behind
it. With `dataplane.fingerprint.enabled: true` the kernel copies a sampled prefix of each
TLS ClientHello and QUIC v1 Initial **off-path** to userspace — a per-CPU sampler caps the
copy rate so the plane never becomes its own DoS — where kapkan computes the client's
**JA4** and source-blocks any whose JA4 is on `ja4_blocklist` (QUIC Initials are decrypted
with keys derived from their connection ID; no completed handshake needed). A JA4 block
acts on the **claimed** source and the trigger is spoofable, so it draws from a separate,
smaller budget than operator blocks — a crafted-JA4 flood can never starve them — and is
written to the audit trail with `source: "auto"`. Contract:
[kapkan.io/docs/fingerprinting](https://kapkan.io/docs/fingerprinting).

### FlowSpec (surgical mitigation)

RTBH blackholing takes the whole victim offline — it trades the attack for an outage.
BGP FlowSpec (RFC 8955 for IPv4, RFC 8956 for IPv6) instead distributes a rule that drops
only the matching attack traffic, so the victim keeps serving everything else.

```yaml
mitigation: flowspec            # default method for all groups (default: blackhole)
flowspec:
  action: discard               # or rate_limit
  rate_mbps: 100                # required for rate_limit
hostgroups:
  - name: web
    networks: ["203.0.113.0/26"]
    mitigation: blackhole       # per-group override
```

On an attack, kapkan derives a **minimal rule set** (≤8) from the attack's classification
and flow sample, matching the victim as destination plus the vector:

| Attack | Generated FlowSpec match |
| --- | --- |
| NTP/DNS/CLDAP/memcached/SSDP/chargen amplification | `dst=victim, proto=udp, src-port=<reflected port>` |
| SYN flood | `dst=victim, proto=tcp, tcp-flags=SYN` |
| Fragment flood | `dst=victim, fragment` |
| ICMP / UDP / TCP flood | `dst=victim, proto=<icmp/udp/tcp>` |
| mixed / unknown | `dst=victim` (plus a rule per dominant reflector port in the sample) |

For an **outgoing** attack (a compromised host flooding outward) the rule instead matches
the host as **source** (RFC 8955/8956 source-prefix), so it actually drops the outbound
flood — unlike a destination-based RTBH blackhole, which only kills traffic *to* the host.

Two caveats worth knowing: the `tcp-flags` match for SYN floods is a bitmask that also
matches SYN-ACK, so a `discard` action drops the victim's outbound-initiated connections too
— prefer `rate_limit` for TCP vectors. And `max_active_bans` caps *bans*, not rules: a
FlowSpec ban can carry up to 8 rules, so N bans can mean up to 8N rules in your upstream's
RIB — watch the `mitigate_flowspec_rules` metric against your routers' FlowSpec route limit.

Rules carry a traffic-rate extended community: `discard` (rate 0) or a `rate_limit`
ceiling. Everything is **dry-run-first** — the generated rules appear in `/api/v1/attacks`
(`method`, `flowspec`) and `/api/v1/bans` and the notifications before you ever set
`dry_run: false`, so you can confirm them against your upstream's FlowSpec support. The
victim is always matched as a `/32` (v4) or `/128` (v6) — **IPv6 FlowSpec is at full parity
with IPv4**, where FastNetMon's own roadmap still lists IPv6 FlowSpec as unsupported.

FlowSpec rides the same BGP neighbors as RTBH (the FlowSpec AFI/SAFI is advertised
additively; a peer that doesn't support it simply won't negotiate it). It is not valid for
`calculation: total` groups (no single victim prefix to match). Rules share the same TTL,
hysteresis, and `max_active_bans` lifecycle as blackhole bans.

### Escalation ladders

A single `mitigation` method fires the same response the instant an attack is detected.
An escalation ladder instead steps the response up the longer an attack persists —
declaratively, where FastNetMon makes you write a callback script:

```yaml
escalation:                         # supersedes `mitigation` when present
  - { after_seconds: 0,   action: none }       # alert only at first
  - { after_seconds: 15,  action: dataplane }  # still under attack after 15s → drop in-kernel
  - { after_seconds: 30,  action: flowspec }   # still under attack after 30s → surgical drop
  - { after_seconds: 90,  action: divert }     # still under attack after 90s → scrub
  - { after_seconds: 300, action: blackhole }  # still under attack after 300s → blackhole
flowspec:
  action: discard
scrubbing:
  next_hop: "192.0.2.100"   # scrubbing center; see "Traffic diversion" below
  community: "65000:200"
```

Each rung's `after_seconds` is measured from the attack's start; a rung applies once that
much time has elapsed **and the attack is still active** (no end event yet — i.e. traffic
is still above threshold through the unban hysteresis). Climbing to a rung is
**make-before-break**: the new rung is announced first and the previous one is withdrawn
only after that succeeds, so the victim is never momentarily unprotected mid-switch; if the
announce fails the ban holds the working rung and retries on the next tick. (The one
exception is `divert → blackhole`: both ride the same host-route NLRI, so the blackhole
re-announce atomically replaces the divert route — no withdraw, no gap.) A ladder may only
hold or strengthen the response (`none` < `dataplane` < `flowspec` < `divert` <
`blackhole`) — de-escalating between rungs is a config error. `dataplane` sits just above
alert-only because it announces nothing and touches only traffic arriving on this box's
NIC; `divert` sits below `blackhole` because it keeps the victim reachable. If several
rungs come due at once (a long-running attack, or the daemon catching up after a pause) the
ban jumps straight to the highest due rung and never announces the rungs it skips. The
first rung must be at `0s`; `action` is `none` (alert only), `dataplane`, `flowspec`,
`divert`, or `blackhole`.

The ladder is per-hostgroup overridable and shares the rest of the ban lifecycle: TTL
auto-withdrawal, the `max_active_bans` cap, whitelist-never, and dry-run (which advances
the ladder and logs each rung but never announces). When no `escalation` block is set, the
single `mitigation` method behaves exactly as a one-rung ladder at `0s` — full backward
compatibility. The current rung and method are visible per ban in `/api/v1/bans`.

### Per-hostgroup BGP attributes

The global `bgp` block sets the default blackhole next-hops and RTBH community. A hostgroup
can override any of them so different customers signal their own upstreams — where
FastNetMon ties you to one community set:

```yaml
bgp:
  next_hop: "192.0.2.1"
  community: "65000:666"        # the default RTBH community
  # communities: ["65000:666", "65000:777"]   # or a full set (overrides `community`)
  # local_pref: 100                            # optional LOCAL_PREF for iBGP peers

hostgroups:
  - name: customer-a
    networks: ["203.0.113.64/26"]
    bgp:
      communities: ["65000:100", "65001:200"]  # customer-A's own blackhole signal
      next_hop: "192.0.2.50"                    # and discard next-hop
      local_pref: 250
```

Each field left unset inherits the global `bgp` value, so a group can override just its
community while sharing the global next-hop. `local_pref` (default 0 = omit) attaches a
`LOCAL_PREF` path attribute, which is meaningful to iBGP peers. The resolved attributes are
**frozen on each ban when it is created**: a config reload changes only future bans, never
the route a live ban already announced. The per-ban `next_hop`, `community`, and `local_pref`
are visible in `/api/v1/bans` and in the `route` field. FlowSpec rungs are unaffected (their
action lives in a traffic-rate extended community, configured via the `flowspec` block).

### Traffic diversion (scrubbing)

A blackhole completes the attacker's job — it drops *all* of the victim's traffic. The
`divert` action instead announces the victim's host route toward a **scrubbing center**
(its BGP next-hop, plus an optional divert community) so the traffic is cleaned and
reinjected rather than dropped. It is the natural rung between `flowspec` (surgical drops)
and `blackhole` (last resort):

```yaml
scrubbing:
  next_hop: "192.0.2.100"      # scrubbing center BGP next-hop (v4); required to divert
  next_hop6: "100::100"        # required when IPv6 space is protected
  community: "65000:200"       # optional divert community (the next-hop does the rerouting)
  # communities: ["65000:200", "65000:201"]   # or a full set
  local_pref: 200              # often raised so the divert route wins selection

mitigation: divert             # or use `divert` as an escalation rung (above)
```

Diversion reuses the host-route machinery: the route is withdrawn on attack end / TTL like
any ban, and the scrubbing attributes are **frozen per ban** exactly like the blackhole
ones. Hostgroups override the target with their own `scrubbing:` block (same shape as the
per-group `bgp:` block) — different customers, different scrubbers. Reinjection of cleaned
traffic (GRE, a VRF, a separate routing context) is the scrubber's job, outside kapkan's
BGP signaling. Total groups cannot divert (no single victim route); an inherited divert
stage degrades to blackhole there, an explicit one is a config error.

#### Managed scrubbing nodes

The scalar `next_hop` diverts toward **one** scrubber you operate or a provider runs, and
kapkan's part ends at the announcement. A **managed scrubbing node** is kapkan's own
scrubber: a box running the `kapkan scrub` role that receives the diverted traffic, drops
the attack in its in-kernel [data plane](#in-kernel-data-plane-xdp) and reinjects the rest.
Kapkan announces the victim toward the node **and** tells the node exactly what to drop —
the same rules the detector generated for FlowSpec — so it filters the attack vector rather
than every packet to the victim. Same binary, no second product:

```yaml
scrubbing:
  next_hop: "192.0.2.100"        # still valid: the one-node case / catch-all target
  node_selection: affinity       # affinity (default); least_loaded and ecmp parse but
                                 #   are not implemented yet and warn + use affinity
  on_all_nodes_lost: withdraw    # withdraw (default) | blackhole | flowspec
  stale_after_seconds: 15        # a node unheard-from this long counts as lost
  nodes:
    - name: scrub-fra1           # must equal the node's controller.name
      next_hop: "192.0.2.10"     # the node's IPv4 BGP next-hop (required)
      next_hop6: "2001:db8::10"  # required to divert IPv6 victims to this node
      capacity_mbps: 10000       # shown in the console; used by least_loaded
      hostgroups: [game-servers] # this node serves only these groups (empty = any)
    - name: scrub-ams1
      next_hop: "192.0.2.11"
```

On the node itself, everything role-specific lives in its own file — the daemon's
`config.yaml` is deliberately **not** read:

```yaml
# /etc/kapkan/scrub.yaml — then: kapkan scrub
dry_run: true                              # the remote-role default: counts, drops nothing
controller:
  url: "https://kapkan.example.net:8443"   # the brain's API base
  token_env: KAPKAN_AGENT_TOKEN            # an `agent`-role token (required)
  name: scrub-fra1                         # must equal a scrubbing.nodes[] name
dataplane:
  interfaces: [eth0]                       # the dirty side: diverted traffic arrives here
  pin_path: /sys/fs/bpf/kapkan
```

Three properties are worth knowing before you deploy this:

- **Liveness is the poll, never the report.** A node is alive because it keeps long-polling
  the brain for rules. Its self-report (load, drop counts, version — shown in the console's
  Nodes view) is *advisory*: a compromised node token could inflate a report, but it can
  never keep a dead node attracting diverted traffic, because nothing acts on the report.
  For a *silent* death (power loss, a partition — nothing sends a FIN) the real detection
  bound is `stale_after_seconds` **plus** the long-poll hold the node may be parked in (the
  channel contract is ≤30 s) — size it against your blackhole tolerance with that sum in
  mind.
- **The node choice is frozen per ban** and survives node loss. It is made once at ban time
  (preferring nodes that are actually polling) so a reload reordering the list never moves
  a victim mid-attack. When a node goes stale the sweep re-announces its victims toward a
  surviving eligible node make-before-break; the old node coming back does not pull them
  home. Only when *no* eligible node survives does `on_all_nodes_lost` apply.
- **The agent role is off the privilege ladder.** A node's token reaches exactly two routes
  (the rule channel and its own self-report) and nothing else — not attacks, bans or audit
  — because it lives on a remote, often less-guarded box. See [Authentication](#authentication).

Getting the diverted traffic *to* a node and the clean traffic back out — L2 insertion,
GRE/IPIP with MSS clamping, the return path and the asymmetric-routing traps — is your
network's job, covered in the
[network-integration guide](https://kapkan.io/docs/network-integration).

### Going live

1. Run in dry-run and confirm in the logs / `/api/v1/attacks` that detection fires on the
   right prefixes and the would-be routes (`route` field) are correct.
2. Confirm BGP sessions reach `ESTABLISHED` (logged as `bgp peer state`). Peering happens
   even in dry-run, so you can validate connectivity before announcing anything.
3. Set `dry_run: false` and reload (`SIGHUP` or `POST /api/v1/config/reload`).

## Command line

`kapkan [flags]` runs the daemon; `kapkan [flags] <command> [args]` runs a command and
exits. Global flags come **before** the command, the command's own flags after it. A flag
that exits on its own (`-version`, `-check-config`, `-dump-schema`, `-check-update`, `-s`)
cannot be combined with a command — kapkan refuses the combination rather than silently
honouring one of them.

| Flag | Default | Description |
| --- | --- | --- |
| `-config <path>` | `configs/dev.yaml` | Path to the YAML config file. |
| `-log-format <fmt>` | `json` | `json` (for log collectors) or `text` (human-readable). Logs always go to stderr. |
| `-log-level <lvl>` | `info` | `debug`, `info`, `warn` or `error`. |
| `-check-config <path>` | — | Parse and validate that config — including cross-field rules a static schema cannot express — print the resolved result, and exit `0` valid / `1` invalid. Drops straight into CI or a pre-deploy gate. A valid config may still print a `WARNING` — today, a static rule that can never fire — without changing the exit code. |
| `-dump-schema` | `false` | Print the config's JSON schema to stdout and exit. |
| `-version` | `false` | Print the build version and exit (also on `/api/v1/status` and the `kapkan_build_info` metric — zero egress). |
| `-check-update` | `false` | Run the update check once and exit: `0` up to date, `10` newer release available, `1` error. Works regardless of the `update_check` setting. |
| `-pid-file <path>` | `/run/kapkan/kapkan.pid` | Where the daemon writes its pid on start; read by `-s`. A write failure is non-fatal. |
| `-s <signal>` | — | Signal the running daemon and exit: `reload` (SIGHUP), `stop` / `quit` (SIGTERM) — nginx-style local control that needs no API token and works when the API is down. |

```sh
kapkan dataplane status    # is the kernel actually filtering? read-only; works with the daemon stopped
kapkan scrub               # run the scrub-node role (its own -config, default /etc/kapkan/scrub.yaml)
kapkan help                # the synopsis, commands and flag defaults
```

`dataplane status` is the diagnostic to reach for during an incident: it opens the pinned
program and maps **read-only** (the descriptors carry `BPF_F_RDONLY`, so the *kernel*
refuses a write through them) and never loads, attaches, detaches or rebuilds anything —
unlike starting the daemon, which adopts-or-rebuilds the pin set and can discard the very
rules you are diagnosing. With the default `on_exit: keep` the kernel keeps enforcing with
no kapkan process at all, and this command reads the pins directly to say so. It leads with
the verdict and the remedy, then the detail (attached interfaces and the mode actually in
force, kernel and map-schema versions, rule counts, per-map occupancy, the dry-run flag,
the verdict counters), and exits `0` only when `enforcing` — `10` not filtering but nothing
broken, `11` something must be fixed first, `1` could not answer (usually permissions),
`2` usage. Add `-json` for the machine-readable form.

## REST API

All endpoints are served on `api.listen`.

| Method & path | Description |
| --- | --- |
| `GET /api/v1/status` | Mode, uptime, protected networks, thresholds, hostgroups, active attack/ban counts. |
| `GET /api/v1/attacks` | Currently active attacks plus the last 100 that ended (with samples and classification). |
| `GET /api/v1/hosts` | Tracked-host snapshot: per-direction rates, learned baselines, attack state (top-talkers data). |
| `GET /api/v1/bans` | All bans, active and historical. |
| `GET /api/v1/traffic` | Persisted per-host rate history (the Traffic/Reports view). Returns `available: false` — not an error — when [storage](#storage-optional) is disabled. |
| `GET /api/v1/audit` | Operator-attributed audit trail: who banned/unbanned/reloaded, when, and the outcome. Tenant-scoped server-side. Also `available: false` without storage. |
| `POST /api/v1/ban` | Manually ban an address: `{"ip":"203.0.113.66"}`. Respects the whitelist, the cap, and the `networks` scope. |
| `POST /api/v1/unban` | Manually withdraw a ban: `{"ip":"203.0.113.66"}`. |
| `POST /api/v1/config/reload` | Re-read the config file (same as `SIGHUP`). |
| `POST /api/v1/dataplane/sources` | Drop a source in the XDP data plane, scoped to one victim, with a **mandatory** TTL (1s-24h): `{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":600}`. For whoever already terminates the victim's traffic. `operator` only — `agent` is denied. |
| `POST /api/v1/dataplane/sources/unblock` | Remove one source block immediately (same `victim`/`source` body). |
| `GET /api/v1/dataplane/rules` | The rule table a [scrub node](#managed-scrubbing-nodes) enforces, as a long poll (ETag'd). **`agent` or `operator` only** — not viewer. |
| `POST /api/v1/dataplane/nodes/{name}/report` | A scrub node's self-report (load, drop counts, version). Advisory by contract, never liveness. `agent` or `operator`. |
| `GET /api/v1/dataplane/nodes` | Scrub-node inventory for the console's Nodes view: configured nodes, whether each is polling, its frozen ban count and its last self-report. Viewer rank, unscoped tokens only. |
| `GET /metrics` | Prometheus metrics. Unauthenticated. |
| `GET /healthz` | Readiness probe: `503` until every component is up, `200` after. Unauthenticated (it leaks nothing) so an updater or supervisor can gate on it; the body also summarises the data plane's state. |

Manual bans honour every safety rule: a whitelisted target returns `409` and is never
announced; a target outside the configured `networks` returns `409`; exceeding
`max_active_bans` returns `409`. POST endpoints require `Content-Type: application/json`.
The `GET` routes need the **viewer** role; the mutating routes (`ban`, `unban`,
`config/reload`, and both `dataplane/sources` routes) need the **operator** role; the two
scrub-node routes are granted by explicit membership to `agent` (and `operator`, so a human
can curl what an agent sees) — see [Authentication](#authentication).

### Dashboard

A self-contained web console (no build step, no external assets — embedded in the binary via
`go:embed`) is served on the same `api.listen` address at `/`. It polls the API and shows
the live mode, active and recent attacks with their classification and flow samples, top
talkers with learned baselines, the ban table, hostgroups, traffic history and a read-only
settings view — plus manual ban/unban and config-reload controls. A **Nodes** view appears
when the config carries managed [scrubbing nodes](#managed-scrubbing-nodes): which are
polling, how many bans each is holding, and each node's last self-report. It works fully on
live data alone (no database required), the free answer to FastNetMon's per-user paid
LiveView. Set `api.dashboard: false` to serve only the JSON API and metrics.

### Authentication

By default the API and dashboard are **unauthenticated** — safe only because the default
`api.listen` binds to `127.0.0.1`. **Before exposing the listener beyond localhost, set a
token.** The shorthand is one operator token:

```yaml
api:
  listen: "0.0.0.0:8080"
  token_env: "KAPKAN_API_TOKEN"   # token read from this env var, never the file
```

For role-based access use `tokens` instead — each names the env var holding its secret and
a role: **viewer** (read-only: status, attacks, hosts, bans, traffic, audit), **operator**
(read plus manual ban/unban and config reload), or **agent** (a scrub node's credential):

```yaml
api:
  listen: "0.0.0.0:8080"
  tokens:
    - { name: dashboard, token_env: "KAPKAN_API_RO", role: viewer }
    - { name: automation, token_env: "KAPKAN_API_RW", role: operator }
    - { name: scrub-fra1, token_env: "KAPKAN_AGENT_FRA1", role: agent }
```

The **agent** role sits deliberately **off** the privilege ladder — below viewer, not above
it. An agent token lives on a remote scrubbing node, often a less-guarded box, and must not
become a read-everything key if that box is compromised, so it is granted its two routes
(`GET /api/v1/dataplane/rules` and its own `POST …/report`) by explicit membership rather
than by rank. It reads no attacks, no bans, no audit, no status.

`token_env` and `tokens` are mutually exclusive; `token_env` is exactly a single operator
token. Every `/api/v1` request must carry `Authorization: Bearer <token>`; the presented
token is matched constant-time against every configured secret (an empty/unset env var
never matches — fail closed), and the highest matching role applies. A read with a viewer
token works; a mutation with a viewer token returns `403`; an unknown token returns `401`.
Tokens are read from the environment per request, so rotating a secret or changing the set
takes effect on reload without a restart. The dashboard prompts for a token and keeps it in
`sessionStorage`. `/metrics` and the static UI shell stay open (the data behind the UI does
not). POST endpoints also require the JSON content type, which — together with the token
living in a header — blocks cross-site request forgery.

## Multi-tenancy

One kapkan instance can serve many customers (an MSP/IDC use case) and give each a token
that sees and touches **only their own** attacks, bans and hosts. A tenant is just an
optional label on a hostgroup — no new top-level object:

```yaml
tenant: "house"                 # optional: label the global/fallback group

hostgroups:
  - name: custA-web
    tenant: "customerA"         # this group belongs to customerA
    networks: ["203.0.113.0/26"]
  - name: custA-dns
    tenant: "customerA"         # a tenant can span several groups
    networks: ["203.0.113.64/26"]
  - name: custB
    tenant: "customerB"
    networks: ["198.51.100.0/24"]
  - name: shared-infra          # no tenant → visible only to admin tokens
    networks: ["192.0.2.0/24"]

api:
  tokens:
    - { name: admin,    token_env: KAPKAN_ADMIN, role: operator }                    # unscoped: all tenants
    - { name: a-portal, token_env: KAPKAN_A,     role: viewer,   tenant: "customerA" }
    - { name: b-ops,    token_env: KAPKAN_B,     role: operator, tenant: "customerB" }
```

"Which tenant owns this IP" is answered by the **same** longest-prefix hostgroup lookup the
engine and mitigator already use, so there is one source of truth and the detection hot path
is untouched. A token's optional `tenant` scopes it; an unscoped token is an admin that sees
everything (the default, fully back-compatible). Enforcement is **default-deny for scoped
tokens** at a single choke point:

- **Reads** (`/status`, `/attacks`, `/hosts`, `/bans`) return only rows whose owning group
  carries the caller's tenant. `/status` is rebuilt per scope — a tenant never learns
  another's prefixes, thresholds or BGP posture. Unlabeled groups are admin-only.
- **Mutations**: a scoped operator may `ban`/`unban` only within its own prefixes; an
  out-of-tenant target returns a uniform `403` whether or not a ban exists (no cross-tenant
  probing). `config/reload` is admin-only (it rewrites every tenant's policy and the token
  set itself).
- A bearer that matches tokens of **different** tenants at the same role (a reused secret) is
  refused — a misconfiguration never silently widens access.

`/metrics` is **not** tenant-scoped (it stays an admin/operator scrape surface); the
dashboard shell is shared but every data call it makes is filtered by the pasted token. No
tenant configured anywhere = single-tenant behavior, unchanged.

## Metrics

Prometheus metrics under the `kapkan_` namespace, on `/metrics`. The families, with the
full table (labels, values and what to alert on) at
[kapkan.io/docs/metrics](https://kapkan.io/docs/metrics):

- **Ingest** — `ingest_flows_total` (by protocol), `ingest_packets_total` (by
  exporter/protocol), `ingest_decode_errors_total`, `ingest_dropped_flows_total`.
- **Engine** — `engine_active_attacks`, `engine_attacks_total`,
  `engine_process_latency_seconds`, `engine_tracked_hosts`, `engine_events_dropped_total`
  (by `kind` — should sit at zero), and `engine_boundary_debug_bytes_total` while
  `sampling.boundary_debug` is on.
- **Mitigation** — `mitigate_announced_routes` and `mitigate_flowspec_rules` (by
  `real`/`dry_run` mode), `mitigate_dataplane_bans` / `mitigate_dataplane_rules` for the
  local XDP rung, `mitigate_source_blocks` (by mode) and `mitigate_source_blocks_rejected_total`
  (by `reason` — a rising `source_allowlisted` or `slots_full` means an integration is asking
  for blocks that can never take effect), `mitigate_bans_rejected_total` (by `reason`: `max_active_bans`,
  `blast_radius_fraction`, `blast_radius_rate`, `max_active_prefix_bans`), and
  `mitigate_fallback_total` (by `from`/`to` — a non-zero `from="flowspec"` series flags
  upstreams that do not honour FlowSpec).
- **Data plane** — `dataplane_degraded` (**the single series to alert on**),
  `dataplane_xdp_mode` (by interface and `native`/`generic`), `dataplane_attach_errors_total`,
  `dataplane_reattach_total`, `dataplane_pins_rebuilt`,
  `dataplane_shadowed_static_rules` (config static rules that can never fire, because the
  allowlist or an earlier rule already takes every packet they select — `0` is the only
  healthy value), `dataplane_rules`,
  `dataplane_packets_total` / `dataplane_bytes_total` (by terminal verdict),
  `dataplane_observations_total`, `dataplane_map_entries` / `dataplane_map_bytes`,
  `dataplane_policy_generation` / `dataplane_policy_apply_seconds`, and
  `dataplane_filter_bypass_packets_total` / `_bytes_total` — an alarm, not a statistic:
  packets forwarded without a single rule being evaluated. Alert on any non-zero rate.
- **Delivery and build** — `notify_notifications_total` (by channel/result),
  `storage_rows_total` (by table and `written`/`dropped`/`error`), `build_info` (the
  `node_exporter` idiom — query fleet drift with `count by (version)(kapkan_build_info)`,
  zero phone-home), and `update_available` when the opt-in update check finds a release.

## Storage (optional)

Point kapkan at a ClickHouse server to keep attack and traffic history — the answer to
"what hit us last Tuesday":

```yaml
storage:
  clickhouse:
    url: "http://127.0.0.1:8123"   # empty/absent disables persistence
    database: "kapkan"             # created if absent
    username_env: "KAPKAN_CH_USER" # optional; credentials come from the env
    password_env: "KAPKAN_CH_PASS"
    ttl_days: 7                    # rows auto-expire (per-row TTL)
```

kapkan talks to ClickHouse's **HTTP interface** with the standard library — no driver
dependency; the only external dependency is the ClickHouse server itself. On start it
creates three MergeTree tables (idempotently): `attack_events` (every start/end with type,
direction, rates, sample top-sources, top-ASNs when GeoIP is enabled, ban state),
`traffic` (periodic per-host rate and baseline snapshots), and `audit_events` (who did
what, with which role and tenant, to which target, and how it turned out — served back on
`/api/v1/audit`). All three carry a `ttl_days` TTL so retention is bounded without
operator intervention.

Persistence is **best-effort and never blocks detection**: rows go onto a bounded queue
(`queue_size`) with a non-blocking send and are flushed in batches (`batch_size` /
`flush_interval_seconds`); a slow or down ClickHouse drops rows (counted in
`storage_rows_total{result="dropped"}`) rather than stalling the engine. Without the block,
kapkan runs entirely in-process on live data.

> Note: per-ASN top-talkers are persisted on `attack_events` (in the `top_asns` column) when
> GeoIP is enabled; the `traffic` table itself still persists per-host snapshots only, and
> per-hostgroup totals are not yet snapshotted — a candidate for a follow-up.

## Migrating from FastNetMon

Already running FastNetMon? Keep your existing notify scripts. Set the exec hook to the
FastNetMon convention and kapkan invokes them exactly the way FastNetMon's `notify_script`
does — argv `<ip> <direction> <pps> <action>`, with a plain-text attack summary on stdin:

```yaml
notify:
  exec:
    command: "/usr/local/bin/notify_about_attack.sh"
    format: fastnetmon
```

`action` is `ban`, `unban`, or `attack_details`, matching FastNetMon. The mapping:

| kapkan event | `action` |
| --- | --- |
| attack started, host blackholed/diverted | `ban` |
| attack started, alert-only (no ban) | `attack_details` |
| attack ended, a ban was withdrawn | `unban` |
| **any event while `dry_run` is true** | `attack_details` |

That last row is the safety rule that matters: in dry-run kapkan announces nothing, so it
**never** emits `ban`/`unban` to your script — only the informational `attack_details` — so a
FastNetMon ban script cannot firewall a host you are only validating. Group-scoped (total)
attacks have no single host and are skipped in this mode. The default `format: kapkan`
(event name + JSON payload) is unchanged.

## Safety model

These rules are enforced in code and covered by tests; they are non-negotiable:

1. **Dry-run by default.** Announcements happen only when `dry_run: false` is set explicitly. An absent `dry_run` key is treated as `true`.
2. **No permanent bans.** Every announcement carries a TTL and is auto-withdrawn — even if the attack is still ongoing.
3. **Unban hysteresis.** A ban is withdrawn only after traffic stays below threshold for `unban_hysteresis_seconds`, preventing announce/withdraw flapping.
4. **Hard ban cap.** Past `max_active_bans` simultaneous bans, new bans are refused and alerted — kapkan will never blackhole half your network.
5. **Whitelist is absolute.** Addresses in `protected_whitelist` are never announced, by detection or manual request — and a prefix-wide carpet mitigation that would cover a whitelisted address is refused outright rather than exempting one member.
6. **Scoped detection.** Only destinations inside `networks` are ever acted on; other traffic is counted in metrics but never triggers a ban.
7. **Bounded blast radius.** `ban.max_banned_fraction` caps the share of your own address space that may be blackholed simultaneously (per address family) and `ban.max_bans_per_window` caps the *rate* of new bans — the two failure modes a simple count cap cannot see: a poisoned baseline or a spoofed-source storm driving many individually-legal bans. Both are off by default; refusals are counted in `kapkan_mitigate_bans_rejected_total`.

Every method inherits these — the [data plane](#in-kernel-data-plane-xdp) plugs in at the
same point as a BGP announcement, so dry-run, whitelists, TTLs and the caps apply to an
in-kernel drop exactly as they do to a route.

## Install

Every release ships prebuilt and signed for `linux/amd64` and `linux/arm64` — no
build toolchain needed. The simplest path is a native package:

```sh
VER=v1.6.0
# Debian / Ubuntu — sets up the kapkan user, /etc/kapkan and the systemd unit.
curl -fLO "https://github.com/fornex/kapkan/releases/download/$VER/kapkan_${VER#v}_linux_amd64.deb"
sudo apt install "./kapkan_${VER#v}_linux_amd64.deb"
# RHEL / Fedora: sudo dnf install ./kapkan_<ver>_linux_amd64.rpm
```

Prefer a tarball? Download it from
[Releases](https://github.com/fornex/kapkan/releases), verify, and extract. Each
release ships `checksums.txt` with a cosign-keyless signature; verifying is two
commands (authenticity then integrity):

```sh
VER=v1.6.0   # the release you want
base="https://github.com/fornex/kapkan/releases/download/$VER"
curl -fLO "$base/kapkan_${VER#v}_linux_amd64.tar.gz"   # archive names drop the leading "v"
curl -fLO "$base/checksums.txt" -O "$base/checksums.txt.sig" -O "$base/checksums.txt.pem"

# 1) authenticity — signature over checksums.txt, pinned to this repo's release tag
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig --certificate checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/fornex/kapkan/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# 2) integrity — hash of the archive (shasum -a 256 -c on macOS)
sha256sum -c checksums.txt --ignore-missing

tar xzf "kapkan_${VER#v}_linux_amd64.tar.gz"   # yields ./kapkan and ./deploy/
./kapkan -version
```

(Building from source instead? See [Development](#development); `make build`
stamps the version the same way.)

## Deployment

A hardened systemd unit and a production config example ship in the release
archive's `deploy/` (and live in [`engine/deploy/`](engine/deploy/) in this repo):

```sh
sudo install -m 0755 kapkan /usr/local/bin/kapkan
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kapkan
sudo install -d -o kapkan -g kapkan /etc/kapkan
sudo install -m 0640 -o kapkan -g kapkan deploy/config.example.yaml /etc/kapkan/config.yaml
echo 'KAPKAN_TG_TOKEN=123456:abc' | sudo install -m 0600 /dev/stdin /etc/kapkan/kapkan.env
sudo install -m 0644 deploy/kapkan.service /etc/systemd/system/kapkan.service
sudo systemctl daemon-reload && sudo systemctl enable --now kapkan
sudo systemctl reload kapkan   # SIGHUP: hot-reload config
```

## Upgrading

`deploy/update.sh` performs a safe, signed upgrade on the host:

```sh
sudo deploy/update.sh v1.6.0   # or: sudo deploy/update.sh   (latest stable)
```

It verifies the download (cosign signature over `checksums.txt`, then the
SHA-256), **preflights the new binary against the live config as the `kapkan`
user with the env file loaded** (so schema drift, files the daemon can't read,
or missing secrets are caught *before* any swap — the running daemon is left
untouched on failure), snapshots the config, swaps the binary atomically
(keeping the previous one at `…/kapkan.old`), restarts, and **rolls back both the
binary and the config if `/healthz` does not report ready** within the deadline.

Active mitigation survives the restart: BGP Graceful Restart has the peer retain
kapkan's routes across the gap, and persisted bans are re-announced on startup
before End-of-RIB (set `ban.state_file`), so there is no need to wait for zero
active bans. The `/healthz` endpoint (unauthenticated, `503` until fully started)
is the readiness signal; the unit's `StartLimit*` turns a bad binary into a
`failed` state the script can detect rather than a restart loop.

You can also check for a newer release at any time:

```sh
kapkan -version        # the running version
kapkan -check-update   # exit 10 if a newer release exists (0 = up to date)
```

## Development

From the repo root (the root Makefile delegates to `engine/`):

```sh
make build   # the single binary, with the console embedded
make test    # go test -race -count=1
make schema  # regenerate docs/config-schema.json from the Config struct
make site    # build the static kapkan.io site (docs/ -> site/frontend)
```

Inside `engine/` there are a few more, including the ones that need a Linux kernel:

```sh
make -C engine lint            # golangci-lint, run for GOOS=linux AND darwin
make -C engine bench           # engine hot-path benchmarks
make -C engine dataplane-test  # the XDP suite, in a privileged container
make -C engine blockrate       # replay the 18 attack captures end to end
```

Tests use synthetic NetFlow/sFlow datagrams built by `pkg/flowgen` (real wire format) and an
in-process GoBGP peer; no real routers are ever contacted. The end-to-end test in
`internal/app` replays an NTP-amplification flood over a real UDP socket against a dry-run
instance and asserts the attack and its (auto-expiring) virtual ban appear in the API. The
data-plane suites go further: they compile the detector's rules into real kernel maps and
replay captured attack frames through the program, so every published block rate is a
measurement rather than a claim.

## Architecture

Paths below are relative to `engine/`:

```
cmd/kapkan/          main, flag parsing, signals, the dataplane/scrub commands
cmd/kapkan-validate/ the same config validator compiled to WASM, so the kapkan.io
                     config builder can show engine-exact errors in the browser
internal/app/        wiring of all components; end-to-end test
internal/config/     YAML load, validation, JSON schema, SIGHUP hot-reload
internal/flow/       the normalized flow record: the hot path's contract
internal/ingest/     goflow2 library-mode ingestion -> normalized Flow
internal/engine/     sharded per-host counters, sliding window, threshold eval
internal/mitigate/   embedded GoBGP: RTBH/FlowSpec/divert announce+withdraw, the
                     escalation ladder, scrub-node selection, TTL, caps, dry-run
internal/dataplane/  the XDP program and its maps: load, pin, attach, rule installs
internal/scrub/      the scrub-node agent behind `kapkan scrub` (rule long-poll)
internal/blockrate/  the eighteen attack captures behind every block-rate claim
internal/storage/    optional ClickHouse persistence (attack, traffic, audit rows)
internal/geoip/      MaxMind ASN/country attribution of attack samples
internal/update/     the opt-in "is there a newer release" check
internal/notify/     Telegram, Slack, email, webhook and exec-hook notifications
internal/api/        REST API, embedded console, Prometheus metrics
pkg/flowgen/         synthetic NetFlow/sFlow generator for tests and load
pkg/pktgen/          synthetic attack frames for the data-plane suite
```

Data flow: `ingest → engine (hot path) → [mitigate, notify, api]`, where `mitigate`
either announces through GoBGP or writes rules into `dataplane` — the same decision,
a different executor.

## License

Apache 2.0.
