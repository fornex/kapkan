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
