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
  `ban.max_active_bans * 8` in the config builder and the example config,
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
