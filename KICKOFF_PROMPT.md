# Kickoff prompt for Claude Code (paste as the first message)

Read CLAUDE.md first — it defines the architecture, safety rules, and conventions. Then build the MVP described below. Work milestone by milestone; after each milestone run `make test && make lint`, fix everything, and give me a short summary before moving on.

## Goal

Working MVP of Kapkan: a single Go binary that ingests sFlow/NetFlow/IPFIX, detects volumetric attacks against configured prefixes using static thresholds, and (in dry-run by default) announces RTBH blackhole routes via embedded GoBGP, with Telegram/webhook notifications and a REST API.

## Reference config (configs/dev.yaml — create it, the loader must support exactly this shape)

```yaml
dry_run: true

listen:
  sflow: ":6343"
  netflow: ":2055"   # NetFlow v5/v9 + IPFIX on the same socket

sampling:
  default_rate: 1000   # used when the exporter does not report its rate

networks:              # prefixes we protect; detection applies only to these
  - "203.0.113.0/24"
  - "2001:db8::/32"

protected_whitelist:   # never ban these, ever
  - "203.0.113.1"

thresholds:            # per destination host, after sampling correction
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000

ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50

bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"          # blackhole next-hop
  community: "65000:666"          # RTBH community
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000

notify:
  telegram:
    token_env: "KAPKAN_TG_TOKEN"  # read token from env, never from file
    chat_id: "-1001234567890"
  webhook:
    url: ""                       # optional generic JSON POST

api:
  listen: "127.0.0.1:8080"
```

## Milestones

**M1 — Skeleton + ingest.**
Project layout per CLAUDE.md, Makefile, golangci-lint config, config loader with validation (reject overlapping nonsense, bad CIDRs, zero thresholds). Ingest via goflow2 v2 in library mode producing a normalized internal `Flow` struct (src/dst IP, proto, ports, bytes, packets, TCP flags, sampling rate, exporter). Prometheus metrics for flows/sec per protocol and decode errors. Acceptance: `make run-dev` starts, decodes synthetic sFlow and NetFlow v9 packets from pkg/flowgen in tests.

**M2 — Detection engine.**
Sharded per-destination-host counters with 1-second buckets and a sliding window (configurable, default 5s). Threshold evaluation once per second: pps / mbps / flows_per_sec, sampling-corrected. Emits `AttackStarted` / `AttackEnded` events on a channel; respects networks, whitelist, hysteresis. Acceptance: unit tests for window math and hysteresis; benchmark proving ≥200k flows/sec on the dev machine; integration test where a flowgen UDP-flood pattern triggers `AttackStarted` within 3 simulated seconds.

**M3 — Mitigation (gobgp, dry-run first).**
Embedded gobgp server: peer with configured neighbors, announce /32 (or /128) blackhole with next-hop + community on `AttackStarted`, withdraw on `AttackEnded` or TTL expiry — but only when `dry_run: false`. In dry-run, log the exact route that would be announced and track it as a virtual ban. Enforce max_active_bans. Acceptance: tests against an in-process gobgp peer verify announce/withdraw lifecycle, TTL expiry, and that dry-run never sends.

**M4 — Notifications + REST API.**
Telegram + webhook notifications on attack start/end (target IP, trigger metric, observed rate, ban state, dry-run flag). REST API: `GET /api/v1/status`, `GET /api/v1/attacks` (active + last 100), `POST /api/v1/ban` and `/unban` (manual, respects whitelist), `GET /metrics`, `POST /api/v1/config/reload`. Acceptance: httptest-based API tests; notification payloads unit-tested with a fake HTTP server.

**M5 — End-to-end + docs.**
Full e2e test: start the binary in dry-run with dev config, replay an NTP-amplification pattern from flowgen over real UDP sockets, assert the attack appears in `/api/v1/attacks` and a virtual ban is created and later expires. Write README.md (quickstart, config reference, systemd unit example) and a `deploy/` dir with the unit file. Final pass: `make test lint bench` all green.

## Rules of engagement

- Do not implement ClickHouse, dashboards, FlowSpec, or baselining — MVP only.
- If a goflow2 or gobgp API differs from what you expect, read the actual package source in the module cache instead of guessing.
- Ask me before adding any dependency not listed in CLAUDE.md.
- Commit after each milestone with a conventional-commit message.
