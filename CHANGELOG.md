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
