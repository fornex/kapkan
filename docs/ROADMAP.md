# Kapkan Roadmap — Competing with FastNetMon Advanced

Based on a full read of the FastNetMon Advanced documentation (fastnetmon.com/docs-fnm-advanced, June 2026).
This document refines the phase plan in CLAUDE.md into concrete, prioritized feature work.

## 1. Competitive thesis

FastNetMon Advanced is a mature, fast, proprietary C++ product. We will not out-feature it
in a year. We win by attacking its structural weaknesses:

| FNM Advanced weakness | Kapkan answer |
|---|---|
| Paid license, per-user paid web UI (LiveView) | Everything free, Apache 2.0, UI included |
| Heavy stack: MongoDB/FerretDB + ClickHouse + InfluxDB + separate web API service | Single Go binary; ClickHouse is the only optional external dep |
| HA = run two copies, deduplicate alerts yourself in callback scripts | Built-in instance coordination / dedup out of the box |
| Config via `fcli set` + `commit`, opaque state in MongoDB | Declarative YAML in git + REST API; config is a file you can diff |
| FlowSpec has no IPv6 support (their own roadmap admits it) | Target IPv6 FlowSpec at parity with IPv4 from day one of Phase 3 |
| Closed source, closed parser | Open source; community-auditable detection logic |

Rule of thumb for every feature below: **match the capability, not the implementation.**

## 2. Where we are (MVP, shipped)

Ingest (sFlow v5, NetFlow v5/v9, IPFIX via goflow2) → sharded engine with global per-host
thresholds (pps / mbps / flows) → RTBH via gobgp with dry-run, TTL, hysteresis, max-bans cap →
Telegram + webhook → REST API (status, attacks, ban/unban, reload) → Prometheus metrics.

## 3. What FastNetMon Advanced has that we don't (gap inventory)

**Detection**
- Per-protocol thresholds: TCP / UDP / ICMP / TCP-SYN, each in pps and mbps; IP fragments
- Independent incoming **and outgoing** direction thresholds
- Hostgroups: networks grouped under shared policy; two calculation methods
  (per-host and total-for-the-group), per-direction settings, built-in `global_total` fallback group
- Flexible thresholds: up to 16 custom rules matching protocol, src/dst ports, packet size,
  TCP flags, TTL, fragmentation — each with its own counters and thresholds
- Automated baselines: compute weekly traffic peaks from stored metrics at global / host /
  prefix / hostgroup level, recommend thresholds (peak × 2–3)
- Connection tracking: per-host unique 5-tuple (or 3-tuple) flow rate counters
- Traffic buffer: ring buffer of recent flows so that the moment a threshold trips, the attack
  sample is already available — saves 15–90 s versus capturing after detection
- Attack analysis: capture ~20 flows (or 500 mirrored packets) per attack, derive dominant
  vectors, attach human-readable sample to notifications

**Mitigation**
- BGP FlowSpec (RFC 8955): auto-generated rules (5–10 per attack) matching prefix, ports,
  protocol, TCP flags, fragmentation, packet length; actions discard / rate-limit / redirect;
  per-hostgroup enablement; vendor-compat toggles (field exclusion, port stripping)
- IPv6 blackhole; selective blackhole; per-hostgroup BGP communities/next-hops
- Traffic diversion to scrubbing centers (Cloudflare Magic Transit, Path.net, F5, Radware)
- Escalation scripting (e.g. blackhole if FlowSpec didn't reduce traffic)
- Country lockdown, automated BGP feed injection, remote (source-IP) attacker blocking

**Storage & reporting**
- ClickHouse metric tables: total / per-network / per-host / per-ASN / per-interface /
  per-hostgroup, top talkers, attack events; default 7-day TTL
- Full raw flow persistence (`fastnetmon.traffic`) for forensics and SQL reporting
- Grafana dashboards; ASN peering reports; discarded traffic monitoring

**Management & integrations**
- REST API covering full config CRUD (networks, hostgroups, thresholds), all counters
  (host / network / ASN / total), blackhole + FlowSpec management, schema reflection
- LiveView web UI (paid add-on): dashboard, attacks, auth with roles
- Email, Slack, Telegram, MongoDB logging, callback scripts with documented JSON schema
  (`alert_scope` field distinguishes per-host vs hostgroup events)
- `fcli` CLI with commit model

**Scale & deployment**
- 3M flows/s claimed per instance; multi-PoP; HA via independent instances
- Port mirror / SPAN capture (AF_PACKET, AF_XDP), XDP host filter, BMP, Docker/VM/ARM64 images

## 4. Phased plan

### Phase 1.5 — Detection parity (extends current MVP, no new external deps)

Goal: a FNM Community user switching to Kapkan loses nothing and gains FNM-Advanced-grade
detection. All in-memory, all in the existing engine.

1. **Per-protocol counters and thresholds.** Extend `engine` buckets with tcp/udp/icmp/tcp-syn
   pps+bps and fragment counters. Config grows `thresholds.tcp_pps`, `thresholds.udp_mbps`, etc.
   Multiple thresholds OR-ed, like FNM. Hot path stays allocation-free — fixed arrays indexed
   by metric enum, benchmarks gate the change.
2. **Direction split.** Every counter kept for incoming and outgoing independently; outgoing
   detection catches compromised hosts inside the network (FNM sells this hard).
3. **Hostgroups.** Named groups of prefixes with their own threshold set and mitigation policy;
   longest-prefix-match lookup table built at config load (no per-flow allocation); calculation
   methods `per_host` and `total`; implicit `global` group as fallback. This is the single most
   important structural feature — everything later (per-group FlowSpec, baselines, API) hangs off it.
4. **Traffic buffer + attack samples.** Small per-shard ring of recent flow records; on detection,
   snapshot matching flows into the attack event. Notifications and API show top ports/protocols/
   sources immediately. This is the foundation for Phase 2 classification and Phase 3 FlowSpec
   rule generation — build it early.
5. **Callback exec hook.** `notify.exec` script receiving documented JSON on ban/unban
   (publish the JSON schema in repo, versioned). Brings FNM's callback-script ecosystem over.
6. **Email + Slack notifiers.** Trivial after webhook; closes the notification gap entirely.

### Phase 2 — See: storage, UI, classification, baselines (per CLAUDE.md)

Goal: kill LiveView's value proposition. FNM charges per-user for a UI that needs MongoDB —
we ship a free dashboard embedded in the binary.

1. **ClickHouse metrics export (optional).** Async batched writers for per-host / per-network /
   per-hostgroup / per-ASN / total tables, configurable TTL (default 7d, like FNM). Engine never
   blocks on storage — drop-and-count on backpressure.
2. **Raw flow persistence (optional).** `kapkan.traffic` table for forensics; sampled or full.
3. **React dashboard, embedded via `go:embed`.** Served by the existing API server: traffic
   graphs, active/historical attacks with samples, top talkers, hostgroup view, ban management,
   dry-run announcement preview. Works in degraded mode without ClickHouse (live data only).
   Auth: local users + API tokens; roles admin/viewer.
4. **Attack classification.** Using traffic-buffer samples: amplification (src ports 123/53/389/
   11211 + size signatures), SYN flood, UDP flood, ICMP flood, fragments. Attack type lands in
   events, notifications, UI, and storage.
5. **EWMA dynamic baselines.** Per-host/per-hostgroup learned baselines with multiplier
   (`baseline.factor`, default ×3) as an alternative to static thresholds. FNM's "automated
   baseline" is an offline calculator that prints suggested numbers — ours is continuous and
   online. Static thresholds remain as floor/ceiling guards.
6. **API v1 completion.** Counter endpoints (host/network/hostgroup/total, top-N), config CRUD
   for networks/hostgroups/thresholds with validation + atomic apply, attack history. OpenAPI spec
   published — FNM has no machine-readable schema; reflection endpoints are their substitute.
7. **Grafana dashboards** shipped in `deploy/grafana/` for those who prefer Grafana over our UI.

### Phase 3 — Act: FlowSpec and surgical mitigation (per CLAUDE.md)

Goal: surgical drops instead of blackholing the victim. FNM's FlowSpec is its strongest
Advanced-only feature; their IPv6 gap is our opening.

1. **FlowSpec rule generation (RFC 8955/8956).** From traffic-buffer samples, greedy cover:
   propose minimal rule set (≤10/attack) matching dst prefix + protocol + ports + flags +
   packet size; actions discard and rate-limit. Always dry-run-first: rules visible in UI/API
   before `dry_run: false`. IPv4 **and IPv6** at parity.
2. **Vendor compatibility toggles.** Per-peer flags to exclude fields (fragmentation, TCP flags,
   packet length) — mirrors FNM's Arista/Extreme workarounds; validate against gobgp encoding.
3. **Escalation policies.** Per-hostgroup ladder: notify → FlowSpec → RTBH if traffic stays
   above threshold N seconds after rule install. Declarative in YAML, no scripting required
   (scripting hook still available via exec callback).
4. **Traffic diversion / scrubbing.** Announce victim prefix with configurable next-hop +
   communities toward a scrubbing path; generic mechanism first, named integrations
   (Magic Transit etc.) as config presets, not code.
5. **Selective blackhole & per-hostgroup BGP attributes.** Communities, next-hop, peer set
   per hostgroup.
6. **Multi-tenant API.** Scoped tokens: a tenant sees/manages only its hostgroups. Foundation
   for hosting-panel integration (billing hooks stay in Phase 3 per CLAUDE.md).

### Phase 4 — Scale: HA, capture modes, ecosystem

Goal: credible at ISP scale; out-of-the-box answers where FNM says "write a script".

1. **Performance: 1M+ flows/s per instance.** Profile-guided: batch ingest decode, per-shard
   worker pinning, optional parallel evaluation tick. Published reproducible benchmarks
   (`pkg/flowgen` replay harness) — FNM publishes marketing numbers, we publish `make bench`.
2. **HA with built-in dedup.** FNM's model (independent instances, dedupe yourself) is fine —
   we ship the missing piece: instances gossip active bans (or share state via the API),
   so notifications and announcements deduplicate without user scripting.
3. **Connection tracking (opt-in).** Per-host unique-flow counters, honest about sampling:
   refuse to enable with sampled telemetry instead of producing garbage numbers (FNM documents
   the same limitation but lets you foot-gun).
4. **Port mirror capture (AF_PACKET, then AF_XDP).** New `ingest` source for SPAN deployments;
   unlocks payload-aware classification later.
5. **BMP ingestion** for route visibility; **eBPF/XDP local filter** as a mitigation backend for
   on-host deployments (drop matching attack signatures without BGP).
6. **Packaging.** Docker images (amd64/arm64), deb/rpm, systemd units, one-line installer,
   config converter from FastNetMon Community config — make migration a 10-minute job.

## 5. Deliberate non-goals

- **InfluxDB support** — deprecated even by FNM; ClickHouse + Prometheus only.
- **MongoDB/FerretDB** — no document store; config is YAML, runtime state is in-process,
  history is ClickHouse.
- **Per-vendor router guides as code** — vendor quirks live in docs and config presets,
  never in detection/mitigation logic.
- **Proprietary cloud telemetry (AWS/GCP VPC flow logs)** — revisit only on user demand.

## 6. Success criteria per phase

- **1.5:** synthetic UDP/SYN/amplification floods detected with correct vector attribution in
  ≤3 s; per-hostgroup policies; ≥200k flows/s sustained on 8 cores with per-protocol counters on.
- **2:** a hosting provider can run Kapkan + ClickHouse and answer "what hit us last Tuesday"
  from the bundled UI; baselines reduce manual threshold tuning to zero for 80% of hosts.
- **3:** an amplification attack is mitigated by FlowSpec rate-limit without blackholing the
  victim, end-to-end in dry-run integration tests against in-process gobgp.
- **4:** two-instance HA produces exactly one notification and one (deduplicated) announcement
  per attack; 1M flows/s benchmark reproducible from `make bench`.
