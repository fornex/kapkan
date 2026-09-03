# Changelog

All notable changes to kapkan are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and releases use
[Semantic Versioning](https://semver.org/):

- **MAJOR** — a breaking config or API change: a removed/renamed required field,
  validation that rejects a previously-valid config, or a breaking `/api/v1`
  change. The committed `docs/config-schema.json` drift gate makes config-surface
  changes objective.
- **MINOR** — new features and new *optional* config.
- **PATCH** — fixes with no config-surface change.

Each release lists, in this order: `### BREAKING` (if any) → `### Config changes`
(added / required / removed / tightened keys, each with a one-line migration
note) → `### Security` → `### Added` → `### Fixed`. The `### Security` heading is
the machine-readable marker the update check uses to flag a release as
security-relevant.

## [Unreleased]

### Config changes

- **Added** `edge` block (optional): `edge.zones_file` (absolute path to the tenant-owned
  zones file, required when the block is present), `edge.nodes[].name` and
  `edge.stale_after_seconds` (default 15). A config without an `edge` block behaves exactly
  as before; the zones file is loaded and validated alongside `kapkan.yaml` and a broken one
  keeps the previous zones on reload.

### Added

- Edge track, E3.1 — the zone model (`zones.yaml`: origins, TLS floor, ACME directory,
  per-request policy) and the brain-side edge channel: `GET /api/v1/edge/zones` (held
  long-poll on a content-hash ETag, woken by a successful reload), `POST
  /api/v1/edge/nodes/{name}/report` and `GET /api/v1/edge/nodes` (inventory with liveness).
  Unscoped tokens only; a node's poll is its liveness, a report never is.
- Edge track, E3.2 — the nginx/Angie renderer (`internal/edge/render`: one shared file plus
  one per zone, embedded templates, `auth_request`-based decision gate that fails open — with
  the failure absorbed inside the subrequest, so keepalive survives — or closed per zone, a
  kapkan-owned catch-all that refuses unknown Host/SNI traffic, WebSocket upgrade relay, ACME
  challenge routing, JSON access log over a unix socket; `policy.rate` is deliberately not
  rendered — it is the decision service's, so a rate change is never a reload) and the
  generation applier (`internal/edge/apply`: numbered generations behind a `live` symlink,
  `nginx -t` gating every install, swap-back on failure, durable tested/reloaded markers with
  startup `Recover`, idempotent by content hash, paced, flock'ed). CI now renders every fixture
  zone set and runs it on nginx 1.22, nginx stable and Angie, `nginx -t` first and then live
  requests through it. Known limitation: nginx before 1.29.2 applies the node-wide TLS floor
  (the lowest `tls.min_version` on the node) to every zone; Angie and nginx ≥ 1.29.2 honour
  per-zone floors. No `kapkan edge` command yet (E3.5).
- Edge track, E3.3 — the per-node decision service (`internal/edge/decide`: answers nginx's
  `auth_request` over a unix socket with 200/403, an optional `X-Kapkan-Mark` and, on a denial,
  `X-Kapkan-Reason`; enforces the zone's `policy.rate` per source key — an IPv4 address or an
  IPv6 /64 — with a token bucket for rps and an approximate, self-correcting in-flight count for
  concurrency, per-zone quotas of a bounded node table; a bounded deny/mark verdict table with
  TTLs where a deny always outranks a mark; dry-run answers every deny as an allow marked
  `would-deny:<reason>`; never consults the brain) and the access-log rollups
  (`internal/edge/rollup`: the terminator's JSON log over a unix datagram socket → per-zone,
  per-source windows with real-elapsed rates; a flood rule promotes a source that keeps pushing
  through its rate ceiling to a deny with escalating TTL — a source already denied is never
  re-escalated — and an error-share rule marks scanners). The renderer forwards none of the
  client's headers to the decision, answers a rate/concurrency denial as 429 with `Retry-After`
  and a table denial as 403, and logs `port`, `decision`, `reason` and `mark`. Edge unix sockets
  default to 0660 with a configurable group. `make bench` reports the single-client
  `BenchmarkDecideOverUnixSocket` round trip (p50/p99) and the parallel throughput.
- Edge track, E3.4 — per-node ACME (`internal/edge/acme`, on `golang.org/x/crypto/acme`, the
  repository's eighth direct dependency): one account key per CA directory and one certificate
  per zone, keys generated on the node and kept `0600` under its state directory as whole
  certificate sets behind a `current` link — one rename switches, the pair is verified on load;
  HTTP-01 only; renewal from day 60 of 90 (a third of the lifetime for shorter certificates)
  with per-node, per-zone jitter, exponential backoff on failure and a fallback CA after three
  consecutive failures; External Account Binding per directory for CAs that require one; the
  certificate's serial reaches the rendered zone file so a renewal is a new, `nginx -t`-tested
  generation; the challenge answerer on the unix socket the renderer
  routes `/.well-known/acme-challenge/` to, serving this node's pending challenges and the ones
  the brain fans out. Brain side: an in-memory issuance coordinator — per-zone slots with a
  10-minute lease (`POST /api/v1/edge/nodes/{name}/acme/slot`) and challenge fan-out through
  the zones document (`POST …/acme/challenges`; only the slot holder may publish, a live
  challenge is never overwritten, 16 live per node), both waking parked long-polls, both
  logged. Both are advisory to the node: it waits up to 15 minutes for a slot on its own budget
  and renews with the brain gone. The zones file gained `acme.fallback`
  (per-zone fallback directory) and the zone document `acme_fallback`. Metrics
  `kapkan_edge_cert_not_after_seconds{zone}` (the T−30 d alarm) and
  `kapkan_edge_acme_attempts_total`. `kapkan edge` wiring is E3.5.
- Edge track, E3.5 — the `kapkan edge` role (`internal/edge/node`, `cmd/kapkan edge`, its own
  `edge.yaml`: `controller`, `state_dir`, `sockets_dir`, `socket_group`, `terminator`
  {binary, main_conf, reload: exec|signal|command}, `acme` {directory, fallback, contact, `eab[]`
  — External Account Binding per directory, the HMAC key read from an environment variable like
  the token}, `status_listen`; `dry_run` defaults to TRUE like every remote role). It brings the
  three unix sockets up first, probes the terminator
  and recovers an untested generation, starts from the last document cached on disk (so a node
  reboots into service with the brain gone and its first poll can answer 304), then long-polls
  `GET /api/v1/edge/zones`. A new document takes the fast path first — decision-service zones,
  rollup zone set, fanned-out challenges — and is rendered and applied only when its bytes
  change what the terminator serves, so a rate change never reloads; an issued certificate
  re-renders. It self-reports every 10 s (version, dry-run, rendered ETag, terminator kind and
  version, generation and test result, certificates), and serves `/healthz` + `/metrics` on
  `status_listen` when set. `internal/edge/poll` is the long-poll generalised over the document.
  A `-check` flag validates `edge.yaml` and exits. Ships `deploy/edge.example.yaml` and
  `deploy/kapkan-edge.service`.

## [1.7.0] - 2026-09-02

### Config changes

- **Added** `dataplane.static_rules[].match.payload`, with two values:
  `tls_client_hello` matches a TCP segment opening a TLS ClientHello and
  requires `proto: tcp`; `quic_initial` matches a UDP datagram opening a QUIC
  v1 Initial and requires `proto: udp`. Optional and absent by default; a
  config that does not use it behaves exactly as before.

- **Added** `dataplane.fingerprint`, the off-path fingerprint plane (see
  *Added* below): `enabled` (off by default; requires `dataplane.enabled: true`
  or the config is rejected; **restart-required**), `sample_pps` (handshake
  copies per second per CPU, default `1000`; **restart-required**),
  `block_ttl_seconds` (default `300`, must be within `1..86400`; hot-reloads)
  and `ja4_blocklist` (exact-match `a_b_c` JA4 fingerprints, duplicates
  rejected; hot-reloads). Absent by default; a config without it behaves
  exactly as before.

### Added

- **The fingerprint plane: source-block clients by their JA4, off-path.** With
  `dataplane.fingerprint.enabled: true` the kernel copies a bounded, sampled
  prefix of each TLS ClientHello and QUIC v1 Initial to a ring buffer; userspace
  computes the client's JA4 (plus SNI and ALPN) with a pure-Go parser and, when
  that JA4 is on `ja4_blocklist`, installs a TTL'd source block on the existing
  XDP path — the same per-source drop `POST /api/v1/dataplane/sources` installs.
  The kernel copies, userspace classifies, enforcement is the source-block path
  you already have; nothing is announced to any peer. QUIC v1 Initials are
  decrypted with keys derived from the Destination Connection ID — public
  inputs, so an off-path copy is enough — and carry transport `q` in their JA4.
  A per-CPU token-bucket sampler (`sample_pps`) caps copy volume so the plane
  can never become its own DoS under a handshake flood, and parsing fails open:
  a truncated snapshot, a handshake spanning datagrams, a QUIC version other
  than v1, or anything that does not parse is simply not fingerprinted — never
  misclassified.

  Stated up front, because it governs how a blocklist must be read: **a JA4
  block acts on the *claimed* source, and the trigger is spoofable.** A
  ClientHello is recognised by a stateless fixed-offset match with no completed
  handshake behind it, so a single spoofed packet carrying a crafted,
  blocklisted JA4 source-blocks whatever address it claims. Read
  `ja4_blocklist` as "block this fingerprint's claimed sources", never "these
  hosts are bad". To bound the collateral, fingerprint blocks draw from a
  separate, smaller budget — half the source-anchor pool — so a crafted-JA4
  flood can fill only its own reservation and never starves operator/API
  source blocks; every fingerprint block is TTL'd and honours dry-run. Each is
  written to the audit trail as a `source_block` with `source: "auto"`
  (engine-initiated, no operator/role/tenant; successes only, so a flood cannot
  spam the store). Observability: `kapkan_fingerprint_events_total{result}` for
  the reader, and the `fp_emitted` / `fp_throttled` / `fp_ring_full` kinds on
  `kapkan_dataplane_observations_total` for the in-kernel sampler. The config
  builder renders the new keys, and the docs gained a dedicated
  [Fingerprint plane (JA4)](https://kapkan.io/docs/fingerprinting) page in all
  five locales. Requires the data plane (Linux 5.15+).

- **`kapkan nginx-exporter` — the reference feeder for the source-block
  channel**, and a supported component rather than an example. It tails an
  nginx access log in a two-line documented JSON `log_format`, measures each
  source's request rate (and optionally its 4xx/5xx share) against a victim
  per window, and posts verdicts to `POST /api/v1/dataplane/sources` — so an
  HTTP flood that nginx can see becomes an in-kernel drop that nginx never
  has to serve again, with no Kapkan code parsing HTTP.

  Grounding, stated up front: it is a fixed operator-written threshold, not a
  detector (no baselines) and not a WAF (it reads source, destination and
  status — never request content). It is an ordinary API caller: every
  guarantee — TTL bounds, tenant scope, dry-run, the allowlist/whitelist
  refusals, auditing — is enforced brain-side and cannot be bypassed from
  here. It starts at the log's end (history is not evidence), follows
  logrotate (a create-new rotation is drained to the old file's last line at
  the switch; `copytruncate` has an inherent one-poll detection window —
  both bounds stated in the docs), computes rates against the *real* elapsed
  time so a stalled loop can never inflate a steady client into a "flood",
  caps the per-window measurement map so a source-rotating IPv6 attacker
  cannot balloon its memory, refreshes a still-hot source before its TTL
  lapses (enforced: `-ttl` ≥ 2×`-window`), and `-observe` runs the full loop
  posting nothing — the trial mode against a live brain. Its token is a full
  operator credential for its tenant — scope it accordingly and put a remote
  brain behind TLS; the docs also spell out why `src` must stay the socket's
  `$remote_addr`, never a header-derived address.

- **QUIC handshake matching in the data plane.** `payload: quic_initial` is
  the UDP twin of `tls_client_hello`: it narrows a static rule to datagrams
  opening a **QUIC v1 Initial** — the packet every QUIC/HTTP-3 handshake
  starts with and the shape a QUIC handshake flood is made of — so those
  handshakes can be metered per source with the same `ratelimit` profiles:

  ```yaml
  ratelimit_profiles:
    - { name: quic_handshake_cap, pps: 20 }
  static_rules:
    - name: cap_quic_handshakes
      match: { proto: udp, dst_port: 443, payload: quic_initial }
      action: ratelimit
      profile: quic_handshake_cap
  ```

  Give it its own profile rather than sharing the TLS rule's: the per-source
  token bucket is keyed `{victim, source, profile}`, so rules naming one
  profile draw down one shared budget per source, while separate profiles
  meter independently.

  Only the handshake is metered: established QUIC connections use the short
  header and never match, so a client mid-download is not competing with new
  handshakes for the ceiling.

  **Bounds, stated rather than buried.** The Initial is recognized from five
  bytes at fixed offsets (long-header form + Initial type, version 1) and the
  data plane decrypts nothing. Version negotiation and QUIC v2 do not match;
  anything too short to decide is forwarded — under-match and forward, as
  everywhere. There is deliberately **no minimum-size test** despite the RFC's
  1200-byte floor for client Initials: the rule must meter everything the
  victim's QUIC stack has to parse, and runt "Initials" are what an attacker
  would craft to duck a size gate. Unlike a ClientHello — which can only
  arrive on a completed TCP handshake — an Initial is the connection's first
  packet, so **sources can be spoofed**; a per-source ceiling still caps each
  address, but rotating sources moves load to the token-bucket LRU, so size
  `limits.max_ratelimit_sources` accordingly.

- **The source-block API: `POST /api/v1/dataplane/sources`.** Whoever already
  terminates a victim's traffic — an nginx in front of it, a log exporter, an
  operator — can hand Kapkan a source to drop in the XDP data plane, scoped to
  that victim and with a mandatory TTL. This is HTTP awareness without parsing
  HTTP: the decision is made where requests are visible, the enforcement
  happens in the kernel. `POST /api/v1/dataplane/sources/unblock` removes a
  pair immediately, so a mistaken block is an undo away rather than a TTL away.

  The ban guarantees apply unabridged: TTLs are bounded (1s–24h, refresh to
  extend — no permanent entries), each blocked source is accounted against
  `dataplane.limits.max_dynamic_rules`, dry-run is honoured (the pair is
  recorded, audited and reported; nothing reaches a map), every call — including
  every refusal — writes one operator-attributed audit event, and tenant-scoped
  tokens may only aim at victims inside their own tenant. Refusals are loud
  rather than silent: a source inside `dataplane.allowlist` (the datapath would
  pass it before any rule), a victim inside `protected_whitelist` (the datapath
  passes its traffic before any rule), a source inside your own `networks`, and
  a deployment with no data plane are all errors. Blocks survive a restart via
  the existing `ban.state_file`, each pair expiring in-kernel exactly on its own
  deadline even if the process never comes back. Operator role required; the
  audit trail gains `source_block`/`source_unblock` actions and the API two
  gauges (`kapkan_mitigate_source_blocks`,
  `kapkan_mitigate_source_blocks_rejected_total`).

  One source can be blocked for up to 8 victims at a time (its pairs share one
  policy block), and the cap is per source, not per tenant — in a multi-tenant
  deployment, tenants blocking the same attacker share those 8 slots (a
  per-tenant split is a fleet-milestone question, once tokens bind to nodes).
  Distinct blocked sources are capped at the policy slots left after every ban
  — host and carpet — could claim its own, so a burst of blocks can never
  starve a ban into its blackhole fallback: the budget is
  `max_dynamic_rules/8 − ban.max_active_bans − carpet.max_active_prefix_bans`.
  At the defaults that leaves plenty; raise
  `dataplane.limits.max_dynamic_rules` if you need more concurrent blocks.

- **TLS handshake matching in the data plane.** A static rule can now narrow on
  the shape of a TLS handshake, so a **TLS handshake flood** — connections that
  complete the TCP handshake, start a ClientHello and go no further — can be
  metered per source:

  ```yaml
  ratelimit_profiles:
    - { name: handshake_cap, pps: 20 }
  static_rules:
    - name: cap_tls_handshakes
      match: { proto: tcp, dst_port: 443, payload: tls_client_hello }
      action: ratelimit
      profile: handshake_cap
  ```

  This is the vector per-source buckets suit best: a ClientHello can only arrive
  on a completed TCP handshake, so the sources are real addresses rather than
  spoofed ones. Established connections are untouched — the rule matches the
  handshake, not the traffic that follows it.

  **Bounds, stated rather than buried.** The record is read from a fixed offset
  and the data plane never reassembles a stream, so a ClientHello split across
  segments does not match and is forwarded, like anything else the parser cannot
  decide. It is TCP-only, which is why `proto: tcp` is required rather than
  inferred, and it does **not** cover HTTP/3, whose handshake is encrypted inside
  QUIC on UDP. Kapkan matches the shape of a handshake, never its contents; no
  part of the data plane reads HTTP inside an established TLS session.

  There is deliberately **no detector-side `tls_handshake_flood` vector**:
  detection runs on sampled flow telemetry, which does not carry payload bytes.
  This is an operator-written rule that is always on, not something a ban turns
  on during an attack — so it is also not part of the measured block-rate table,
  which covers detector-driven mitigation. Its coverage is the kernel packet-path
  suite: a real ClientHello matches, with or without TCP options; a bare ACK,
  application data, a ServerHello, an SSLv2-era version and a payload too short
  to decide all pass; a first fragment carrying one still matches while a later
  fragment does not; and the per-source bucket admits a burst then denies.

- **Unreachable static rules are now reported.** Data-plane `static_rules` are
  first match wins, so a rule whose match set is contained by an earlier one can
  never fire — and nothing said so: its counter in `kapkan dataplane status`
  stayed at zero, which is exactly what a healthy rule looks like when its
  traffic has not arrived. Every apply (startup and reload) now names such rules
  in the reload report and a `WARN` log line, raises the existing
  `policy_shadowed` health condition, and publishes the new
  `kapkan_dataplane_shadowed_static_rules` gauge (`0` is the only healthy value).
  `kapkan -check-config` prints the same finding as a `WARNING`, so it is
  catchable in CI before deployment. This extends the allowlist-shadowing
  analysis that already existed to the rule-versus-rule axis; both report through
  the same field. **Reported, not rejected**: a dead rule enforces nothing, so
  refusing the config would trade a defect that costs zero packets for a daemon
  that will not start, and rejecting a previously-valid config is a MAJOR change
  by the policy above.

## [1.6.0] - 2026-08-14

### Security

- **Built with Go 1.26.6**, which fixes six reachable standard-library advisories
  (`net/url`, `html/template`, `crypto/tls`, `net/http` ×2, `encoding/asn1`) —
  GO-2026-5026, -5972, -6089, -6090, -6091, -6218. No code change; the toolchain
  floor in `engine/go.mod` moves from 1.26.5 to 1.26.6.

The scrub-node release: Kapkan can now run its own managed scrubbing nodes.
A box running `kapkan scrub` receives diverted traffic, drops the attack in its
own XDP data plane, and reinjects the rest — Kapkan diverts the victim toward it
over BGP and tells it exactly what to drop. New: the `agent` token role, the
scrub-node rule channel and node inventory API, the console Nodes view, frozen
node selection with re-announce on node loss, and a lab-verified network
integration guide. No breaking change; deployments without `scrubbing.nodes[]`
are unaffected.

### Config changes

- **Tightened** the divert-target check: a group whose ladder diverts must now
  have the scalar `scrubbing.next_hop` **or a `scrubbing.nodes[]` entry that
  actually serves that group** (matching its `hostgroups` restriction, per
  address family). Previously a node restricted to *other* groups satisfied
  the check, and victims outside those groups diverted to an empty next-hop —
  an announce every peer rejects, silently degrading them to the blackhole
  fallback instead of scrubbing them. Migration: either add the group to the
  node's `hostgroups`, add an unrestricted node, or set the scalar
  `next_hop`/`next_hop6` as the catch-all target.
- **Added** `agent` as a value for `api.tokens[].role` — a scrub node's
  credential. It sits *off* the privilege ladder, below `viewer`: an agent
  token may read `GET /api/v1/dataplane/rules` (and, in an upcoming release,
  report its node's state) and nothing else — not attacks, not bans, not audit.
  The token lives on a remote scrub box, and a compromise there must not become
  a read-everything key. An agent token cannot be tenant-scoped: the rules feed
  is deployment-wide (per-node scoping arrives with the fleet milestone), and
  validation rejects the combination rather than promising a scoping nothing
  enforces.

### Added

- **`kapkan scrub` — the scrub-node role, in the same binary.** A box that
  receives diverted traffic now runs `kapkan scrub -config scrub.yaml`: no
  detection, no BGP, no listeners — it long-polls the brain's rules document
  (the poll doubles as its liveness signal), compiles each ban's rules through
  the *same* encoder the brain's own in-kernel rung uses, and keeps the local
  XDP data plane enforcing them. Every installed rule carries the ban's
  mirrored TTL as its in-kernel deadline, so a dead brain leaves rules that
  age out on their own and a dead agent leaves a datapath that keeps
  enforcing until they do. The node never invents rules and never enforces a
  `dry_run` entry while live; its own `dry_run` **defaults to true** (the
  remote-role safety default — set `dry_run: false` explicitly to go live).
  `scrub.yaml` carries the controller (URL, token env, node name) and the
  same `dataplane:` block as `kapkan.yaml`, validated by the same code; the
  agent posts its advisory self-report every `report_interval_seconds`
  (default 10). A node stopped with the default `on_exit: keep` leaves the
  pinned program filtering.
- **The console gained a Nodes view, and bans a node column.** A new
  `GET /api/v1/dataplane/nodes` (viewer rank, unscoped tokens only — the
  inventory names next-hops and hostgroups, which is topology) joins what the
  brain knows about each managed scrubbing node — poll liveness, last poll,
  how many divert bans are frozen to it — with the node's own advisory report
  (load, drops, version, XDP mode, node-side dry-run), rendered as claims and
  visually attributed as such. `/api/v1/status` gains a `nodes_total` count
  for every role, which is what shows or hides the node affordances: a
  deployment without `scrubbing.nodes[]` sees neither the view nor the extra
  bans column, and its tables are byte-identical to before. Active and
  historical bans now display the frozen `node`.
- **Divert bans now pick a managed scrubbing node and survive its death.** When
  `scrubbing.nodes[]` is configured, a divert ban chooses a node at ban time —
  affinity order, preferring nodes that are actually polling — and **freezes**
  the choice like its BGP attributes, so a victim's traffic never hops between
  scrub sites because a reload reordered a list. The frozen choice appears on
  the ban as `node` and survives a restart. When the node stops polling
  (`stale_after_seconds`, default 15), the victim is **re-announced toward a
  surviving node** — make-before-break on the same host route — and only when
  no node survives does `on_all_nodes_lost` run: `withdraw` (default: stop
  attracting traffic toward a dead box), `blackhole`, or `flowspec` (rules are
  generated at ban time for this, while the attack sample still exists). A
  node the brain has never seen — after a restart, or just added by reload —
  gets one appearance window (`stale_after` plus a poll cycle) before it may
  be judged lost, so a routine node rollout or a brain restart never fires the
  last-resort policy against healthy configs; a node that *was* polling is
  judged strictly by `stale_after`. A ban degraded by node loss comes back
  from the state file on its degraded method, never on the divert rung (which
  would re-attract traffic to the still-dead node). Bans on the unmanaged
  scalar `next_hop` are never judged at all, and a target whitelisted mid-ban
  is withdrawn rather than degraded. `node_selection` modes beyond `affinity`
  are not implemented yet and log a warning at startup.
- **`POST /api/v1/dataplane/nodes/{name}/report` — a scrub node's self-report.**
  Version, XDP mode, node-side dry-run, load and drop totals, stored in memory
  for the console's upcoming Nodes view. Reports are **advisory by contract**:
  every field is what the node *claims*, and none of it feeds a decision — above
  all, a report is never a liveness signal, so a compromised agent token cannot
  keep a dead node "up" and attracting diverted traffic by posting reports.
  Liveness is the rules poll and only the rules poll: an agent identifies
  itself with `?node=<name>` on `GET /api/v1/dataplane/rules`, and the brain
  tracks who is asking (a node mid-hold counts as present). An unknown name is
  refused (404) so a typo'd `controller.name` fails loudly instead of polling
  into the void, and naming a node at all requires a real API token (403 in
  token-less open mode) — presence must not be forgeable by an unauthenticated
  request. Reports for nodes
  absent from `scrubbing.nodes[]` are refused (404), bodies over 64 KiB
  likewise (413); the route takes the same `agent`-or-unscoped-`operator`
  credentials as the rules feed.
- **`GET /api/v1/dataplane/rules` — the scrub-node channel.** A versioned,
  deterministic document of every active diverted victim (prefix, narrowing
  rules, mirrored TTL, dry-run flag), served with a content-hash `ETag`. A
  request whose `If-None-Match` names the current document is held until the ban
  table changes (or up to 30 s, then `304`), so a box running the upcoming
  `kapkan scrub` role follows rule changes with sub-second latency over plain
  HTTP polling. Holds are capped — 4 per token, 8 overall, `429` beyond — and a
  graceful shutdown releases every held poll immediately instead of stalling
  behind it. The endpoint is restricted to unscoped tokens — the dedicated
  `agent` role (see Config changes above) or an unscoped operator — because the
  document deliberately spans all tenants (per-node scoping is the fleet
  milestone). Reverse proxies in front of the API need read timeouts
  above 30 s (the long-poll hold) — nginx `proxy_read_timeout 60s` or higher.

### Fixed

- **Release artifacts now ship the BPF data plane's license texts.** The
  compiled XDP object is embedded in the binary and loaded into the kernel, so
  the dual BSD/GPL texts for Kapkan's own BPF sources and the vendored libbpf
  headers' texts now travel with every release — under `licenses/bpf/` in the
  tarballs and `/usr/share/doc/kapkan/bpf/` in the `.deb`/`.rpm`. The kernel
  support matrix (5.15 / 6.1 / 6.6 / 6.12) is now **release-blocking**: a tag
  does not publish unless the XDP suite loads and passes on every supported
  kernel floor, checked on the exact released commit.
- **A divert ban toward a managed scrubbing node now carries the attack's
  narrowing rules — before, a scrub node dropped nothing.** The scrub node
  pulls each diverted ban from `/api/v1/dataplane/rules` and enforces its
  `flowspec` rule set in its own XDP data plane, but a divert-only ladder never
  generated those rules (they were made only for `flowspec`/`dataplane` rungs),
  so the node received an empty set, applied its charter default of PASS, and
  passed the attack straight through to the victim it was diverting to protect.
  Divert bans that target a managed node — or whose `on_all_nodes_lost` is
  `flowspec` — now generate the rules, and the group's `flowspec.action`
  resolves for them (a divert group previously left it empty, so even the
  generated rules would not compile). Surfaced by the network-integration lab
  (`engine/scripts/labnet/`), which runs the full attack → detect → divert →
  scrub → drop loop on a real kernel. No config change; an unmanaged scalar
  `scrubbing.next_hop` (a third-party scrubber) is unaffected — it decides its
  own policy.

## [1.5.0] - 2026-08-11

A metrics and reporting release: the in-kernel mitigation rung gets gauges of its
own, and two numbers that were quietly wrong — one gauge, one API field — now say
what they claim to. No config change; nothing needs editing on upgrade.

### Added

- **Two gauges for the in-kernel rung**, which the announced-route metric could
  not represent. `kapkan_mitigate_dataplane_bans{mode}` counts bans on the local
  XDP rung and `kapkan_mitigate_dataplane_rules{mode}` the rules they installed,
  both labelled by the ban's frozen dry-run flag. They stay separate from the
  datapath's own `kapkan_dataplane_rules` deliberately: one is what the mitigator
  intended, the other what the kernel actually holds, and a divergence between
  them under `mode="real"` is a fault worth seeing rather than summing away.
  Under dry-run the intent gauge counts while the measured one stays at zero —
  permanently and benignly, since a dry-run ban never reaches the installer.

### Fixed

- **`/api/v1/attacks` reported the weakest second of an attack's life.** The
  record carried the measurement frozen at the instant of detection, and
  detection fires on the first sliding window to cross a threshold — necessarily
  the window holding the least data. A sustained attack therefore reported a
  fifth of its real rate, or a tenth when the exporter's first datagram landed
  mid-second, for its entire duration, and contradicted `/api/v1/hosts` about the
  same host at the same moment. Active attacks now carry the engine's live
  measurement; `metric` and `threshold` stay frozen at detection, because the
  engine judges an attack's end against the thresholds captured at its start.
  Mitigation is unaffected — the ban decision always ran on the live windowed
  rates and never read the frozen number — but anyone who tuned thresholds from
  the attack view, the console's attack panel or a Telegram/webhook payload was
  reading a figure roughly 5x too low.
- **`kapkan_mitigate_announced_routes` counted bans that announce nothing.**
  Every ban with a non-empty method was counted, including the `dataplane` rung,
  which installs into this box's own NIC and asks no peer for anything — so it
  inflated a gauge whose name is a claim about the RIB. It now counts only the
  rungs that ask a peer to enforce something: blackhole, divert and flowspec.
  Dashboards and alerts built on this gauge will see it drop by the number of
  data-plane bans, which is the correction, not a regression.

## [1.4.0] - 2026-08-10

Kapkan can now drop attack packets itself, in the Linux kernel, instead of only
announcing BGP routes for someone else's router to act on. The feature is
opt-in: without a `dataplane:` block the binary behaves exactly as before, and
no existing deployment changes behaviour on upgrade.

### Config changes

- **Added** `dataplane:` — the whole optional block: `enabled`, `interfaces`,
  `xdp_mode` (`auto` | `native` | `generic`), `pin_path`, `on_exit`
  (`keep` | `detach`), `drop_malformed`, `allowlist`, `ratelimit_profiles[]`,
  `static_rules[]` and `limits`. Absent means the data plane does not exist.
- **Added** `dataplane` as a value for `mitigation`, for `escalation[].action`
  and for `carpet.mitigation`. Ladder severity is now
  `none < dataplane < flowspec < divert < blackhole`, so a `dataplane` rung may
  follow an alert-only rung but never `flowspec`, `divert` or `blackhole`.
- **Added** `scrubbing.nodes[]` (`name`, `next_hop`, `next_hop6`,
  `capacity_mbps`, `hostgroups`), `scrubbing.node_selection` and
  `scrubbing.on_all_nodes_lost`. The scalar `scrubbing.next_hop` stays valid and
  is the one-node form; nothing to migrate. Multi-node is schema-only in this
  release — the node role itself is not shipped yet.
- **Tightened** a `dataplane` rung, or `carpet.mitigation: dataplane`, is
  rejected at startup unless a `dataplane` block exists with `enabled: true`.
  A configured drop that silently is not a drop is the failure this prevents.
- **Tightened** `dataplane.limits.max_dynamic_rules` must be at least
  `ban.max_active_bans * 8`. The defaults sit exactly on that boundary at 512
  active bans.

### Security

- Go 1.26.5 (was 1.26.4) — `crypto/tls`, Encrypted Client Hello privacy leak
  (GO-2026-5856).
- gRPC 1.82.1 (was 1.79.3, pulled in by gobgp) — xDS RBAC authorization engine
  and HTTP/2 server transport (GO-2026-6061).

### Added

- **In-kernel mitigation.** A detection installs XDP rules directly into kernel
  maps: the same rules that would have been announced as FlowSpec, compiled to a
  second encoder instead of BGP NLRI. Requires Linux 5.15+ with BTF, `CAP_BPF`
  and `CAP_NET_ADMIN`, and a writable bpffs. Nothing needs a compiler on the box.
- **Per-source rate limiting**, which BGP FlowSpec structurally cannot express:
  each attacking source gets its own token bucket, so a limit of *N* holds every
  individual source to *N* rather than letting attackers and legitimate clients
  compete for one aggregate ceiling.
- **Rules expire inside the kernel.** Every generated rule carries its own
  deadline and the program treats an expired rule as absent, so a killed or hung
  Kapkan cannot leave a victim's legitimate traffic dropped. Sustained attacks
  renew the deadline while they last.
- **Safety is inherited, not reimplemented.** The backend sits below the existing
  announcer seam, so dry-run (still the default), the absolute
  `protected_whitelist`, TTLs, hysteresis, blast-radius caps, fallback to
  blackhole and ban rehydration across restarts all apply unchanged. The
  whitelist is enforced in the kernel too, on both the source and destination
  axes, so a protected host inside a carpet-banned prefix keeps receiving traffic.
- **`kapkan dataplane status`** — a strictly read-only inspector that works with
  the daemon stopped, which is when an operator needs it. Reports attached
  interfaces, attach mode, rule counts, map pressure and per-verdict counters.
  `kapkan` gained subcommand dispatch; every existing flag invocation is
  unchanged.
- **Measured, not asserted.** Eighteen attack captures run end to end on every
  change: 100% of attack traffic dropped on seventeen of them, 98.5% on the
  per-source rate-limit capture, zero legitimate frames dropped and zero
  allowlisted frames dropped in all eighteen. The full suite also runs on real
  5.15, 6.1, 6.6 and 6.12 kernels in CI.
- **A documented limitation, surfaced rather than buried.** An IPv6 packet
  carrying more than eight extension headers is forwarded **without any rule
  being evaluated** — the parser's budget is bounded, and a parse limit that
  dropped packets would be a default-deny hiding inside a parser. No legitimate
  traffic chains eight, so it is counted as
  `kapkan_dataplane_filter_bypass_packets_total{reason="ipv6_exthdr_cap"}` and
  called out in the console and the CLI. Alert on it.
- New documentation page **In-kernel data plane**, in all five languages, plus a
  `kapkan-dataplane.conf` systemd drop-in in the packages. The packaged unit
  deliberately does not grant `CAP_BPF` by default — install the drop-in on the
  boxes that run a data plane.
- Prometheus: `kapkan_dataplane_*` — attach mode, per-verdict packets and bytes,
  map entries and bytes, policy generation, attach errors, apply latency and the
  filter-bypass counters. Per-ban measured drops are on `/api/v1/bans` rather
  than `/metrics`, which is unauthenticated.

### Fixed

- `dataplane.limits` was documented as requiring `max_dynamic_rules` to *exceed*
  `ban.max_active_bans * 8` in the config-builder overlay and the example config,
  while validation accepts equality. All copies now say "at least".

## [1.3.1] - 2026-06-28

### Fixed

- Operator console: clicking a host row in **Hosts** now opens the per-protocol
  breakdown panel. The DOM-morph applied inline styles via `setAttribute('style')`,
  which the dashboard's strict CSP (`style-src 'self'`) blocks, so the panel's
  show/hide never took effect; styles are now applied through the CSSOM.
- Console assets are served with `Cache-Control: no-cache` and a content-hash
  ETag, so a redeployed binary's updated UI reaches the browser instead of a
  stale cached copy lingering after an upgrade.
- Per-protocol cells for a host with no traffic on a protocol now read `0 pps`
  instead of `NaN pps`.

## [1.3.0] - 2026-06-26

### Added

- Operator console: a **top-hosts-by-bandwidth** table (ranked by mbps) above the
  existing top-hosts-by-pps table, plus an **aggregate ingress/egress pps** card
  summarizing total packet rate, placed directly beneath the bandwidth card.

### Fixed

- The operator console is now usable on mobile: a responsive layout for narrow
  viewports, with filter-dropdown chevrons given breathing room from the right edge.
- Top-hosts tables rank by throughput with a stable sort, so equal-rate hosts no
  longer reorder between refreshes.
- Outgoing-attack remote endpoints are labeled as destinations rather than sources.
- Sustained attacks: the ban TTL is refreshed while an attack is ongoing so the
  mitigation is not withdrawn mid-attack, AttackOngoing heartbeats are isolated
  from one another, and the carpet-bombing whitelist is tightened — with a new
  `events_dropped` drop metric.

## [1.2.1] - 2026-06-24

### Fixed

- sFlow samples are no longer counted as flows: `flows_per_sec` was effectively a
  duplicate of `pps` for sFlow exporters (which carry no flow records). It is now
  NetFlow/IPFIX-only and reports 0 for sFlow.

## [1.2.0] - 2026-06-24

### Added

- Process control: `kapkan -s reload|stop|quit` (nginx-style) signals a running
  daemon via its pid file — `reload` hot-reloads the config (SIGHUP), `stop`/`quit`
  shut it down. A new `-pid-file` flag (default `/run/kapkan/kapkan.pid`) is
  written on start and read by `-s`.

## [1.1.0] - 2026-06-24

### Config changes

- Added `sampling.boundary` (optional, per-exporter interface-boundary counting)
  and `sampling.boundary_debug`. Existing configs validate unchanged — absent
  means every sample is counted, the prior behavior.

### Added

- Interface-boundary counting (`sampling.boundary`): deduplicates a flow observed
  at more than one sampling vantage point — redundant exporters (MLAG pairs),
  ingress+egress sampling (Arista `sflow sample output`), and transit/peer-links —
  which otherwise over-counts `pps`/`mbps`/`flows_per_sec` by a constant factor.
  Classify each exporter's external (uplink/border) interfaces and a flow is
  counted only when it crosses the boundary; `egress_sampling` halves the rate for
  exporters that also sample on egress. `sampling.boundary_debug` exports the
  `kapkan_engine_boundary_debug_bytes_total` metric (bytes per exporter and
  interface) to help identify the external interfaces. Opt-in: exporters without a
  `boundary` entry keep counting every sample.
- Prebuilt `.deb` and `.rpm` packages for `linux` `amd64`/`arm64`, built by
  GoReleaser alongside the existing tarballs and covered by the same
  `checksums.txt` + cosign signature. `apt install ./kapkan_*.deb` (or the
  matching `.rpm`) installs the binary to `/usr/local/bin/kapkan`, creates the
  unprivileged `kapkan` user, lays out `/etc/kapkan` with a dry-run `config.yaml`
  seeded from the example, creates the writable state directory, and installs the
  hardened systemd unit — left stopped so the operator reviews the config first.
  Upgrades keep the edited config; `apt purge` removes config, state and the user.
- The release tarball now also bundles `deploy/update.sh`, matching what the
  upgrading docs reference.

## [1.0.0] - 2026-06-23

### Added

- Build version stamping: a `kapkan -version` flag, the `version` field in
  `/api/v1/status` and the console, and link-time injection via
  `internal/buildinfo` (release builds stamp the real tag).
- BGP Graceful Restart (`bgp.graceful_restart`, enabled by default): a peer that
  supports it retains kapkan's mitigation routes across a restart instead of
  flushing them. On shutdown kapkan signals an Administrative Reset rather than a
  Hard Reset so retention applies.
- Ban persistence and rehydration (`ban.state_file`, opt-in): active bans are
  persisted and re-announced on startup — paired with Graceful Restart this keeps
  mitigation up across an upgrade restart instead of dropping it until the engine
  re-detects.
- Release pipeline: signed, multi-arch (`linux/amd64`, `linux/arm64`) GitHub
  Releases via GoReleaser, with `checksums.txt`, cosign-keyless signatures, and
  SLSA build provenance; a govulncheck release gate.

### Config changes

- Added `bgp.graceful_restart` (`enabled` default `true`, `restart_seconds`,
  `long_lived`, `long_lived_stale_seconds`). Existing configs validate unchanged.
- Added `ban.state_file` (empty default = disabled). Existing configs validate
  unchanged. The systemd unit now provides a writable `StateDirectory=kapkan`.
