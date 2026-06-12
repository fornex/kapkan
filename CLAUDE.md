# Kapkan — Open-Source DDoS Detection & Mitigation

## What this is

A free, open-source (Apache 2.0) replacement for FastNetMon Community Edition, built for ISPs and hosting providers. It ingests flow telemetry (NetFlow/IPFIX/sFlow) from routers, detects volumetric DDoS attacks against monitored prefixes in 1–3 seconds, and triggers automated BGP mitigation (RTBH blackhole now, FlowSpec later).

Design goal: everything FastNetMon Advanced charges for — web UI, REST API, attack classification, dynamic baselines, notifications — free and in a single Go binary.

## Architecture (single binary, modular internals)

```
cmd/kapkan/            — main, wiring, graceful shutdown
internal/config/       — YAML config, validation, SIGHUP hot-reload
internal/ingest/       — flow ingestion via netsampler/goflow2 v2 (library mode)
                         protocols: sFlow v5, NetFlow v5/v9, IPFIX
internal/engine/       — detection core: sharded per-host counters,
                         sliding windows, threshold evaluation
internal/mitigate/     — BGP via osrg/gobgp v3 (library mode): RTBH announce/withdraw
internal/notify/       — Telegram + generic webhook (Slack/email in later phases)
internal/api/          — REST API: status, active attacks, manual ban/unban, metrics
pkg/flowgen/           — synthetic flow generator for tests and load benchmarks
```

Data flow: `ingest → engine (hot path) → [mitigate, notify, api]`. ClickHouse storage and the React dashboard are **Phase 2** — do not add them to the MVP.

## Critical safety rules (non-negotiable)

1. `dry_run: true` is the default. In dry-run, every would-be BGP announcement is logged and exposed via API but **never sent**. BGP announcements happen only when config explicitly sets `dry_run: false`.
2. Every blackhole announcement has a TTL (`ban.ttl_seconds`) and is auto-withdrawn. No permanent bans ever.
3. Unban hysteresis: withdraw only after traffic stays below threshold for `unban_hysteresis_seconds`, to prevent announce/withdraw flapping.
4. Hard cap `ban.max_active_bans` on simultaneous announcements. If exceeded, alert loudly and refuse new bans — never blackhole half the network.
5. IPs in `protected_whitelist` (routers, NS, own infrastructure) must NEVER be banned, regardless of traffic.
6. Detection only triggers for IPs inside configured `networks` prefixes. Traffic to unknown destinations is counted in metrics but never acted on.

## Tech stack & conventions

- Go 1.22+, Go modules. Key deps: `netsampler/goflow2/v2`, `osrg/gobgp/v3`, `prometheus/client_golang`, `gopkg.in/yaml.v3`. Stdlib `net/http` + `log/slog`. Avoid heavy frameworks.
- Standard Go project layout. No global mutable state; dependencies passed explicitly; `context.Context` for cancellation everywhere.
- Hot path (per-flow processing) is performance-critical: target ≥200k flows/sec on 8 cores. Use sharded maps (e.g. 256 shards keyed by IP hash) with atomic counters; avoid allocations per flow; pre-allocate buffers. Add `go test -bench` benchmarks for the engine and run them before claiming any hot-path change is done.
- Structured logging via `slog` (JSON in prod, text in dev). Prometheus metrics on `/metrics`: flows/sec per protocol, per-exporter packet counters, active attacks, announced routes, engine processing latency.
- Table-driven tests. `golangci-lint` must pass. Every exported symbol documented.
- Errors: wrap with `fmt.Errorf("...: %w", err)`; the process must survive malformed flow packets (log + counter, never panic).

## Testing policy

- Unit tests use synthetic flow datagrams built by `pkg/flowgen` (encode real NetFlow v9 / sFlow v5 wire format), including attack patterns: UDP flood, SYN flood, NTP/DNS/CLDAP amplification (source ports 123/53/389, characteristic packet sizes).
- Integration test: start engine in dry-run, replay a synthetic attack at an IP inside `networks`, assert detection fires within 3 simulated seconds and the would-be RTBH announcement appears in the API.
- BGP tests use gobgp's in-process server. NEVER test against real routers from CI.
- Respect sampling: all rate math must multiply by the exporter's sampling rate (from flow packet headers when available, config fallback otherwise).

## Commands

```
make build      # build single static binary
make test       # go test ./...
make lint       # golangci-lint run
make bench      # engine benchmarks
make run-dev    # run with configs/dev.yaml (dry-run, text logs)
```

## Roadmap context (do not implement ahead of the current milestone)

- **MVP (now):** ingest, static thresholds, RTBH via gobgp, Telegram/webhook, REST API, dry-run.
- **Phase 2:** ClickHouse flow storage, React dashboard, attack classification, EWMA dynamic baselines per host.
- **Phase 3:** BGP FlowSpec rules (RFC 8955) for surgical drops, multi-tenant API, billing-panel integration.

---

# Karpathy Skills — Coding Principles

> Imported verbatim from https://github.com/forrestchang/andrej-karpathy-skills (`CLAUDE.md`).
> Behavioral guidelines to reduce common LLM coding mistakes. They complement — do not replace — the project rules above. **Tradeoff:** these bias toward caution over speed; for trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
