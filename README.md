# Kapkan

**Free, open-source DDoS detection and RTBH mitigation for ISPs and hosting providers.**

Kapkan is a single Go binary that ingests flow telemetry (NetFlow v5/v9, IPFIX, sFlow v5)
from your routers, detects volumetric attacks against the prefixes you protect in seconds,
and triggers automated BGP RTBH (remotely-triggered blackhole) mitigation — with a web API,
Prometheus metrics, and Telegram/webhook notifications. It is a free replacement for the
features commercial flow-DDoS products charge for.

It is **dry-run by default**: until you explicitly flip the switch, every would-be blackhole
is logged and exposed via the API but never announced to your routers.

> Status: MVP. ClickHouse storage, a React dashboard, attack classification, dynamic
> baselines and BGP FlowSpec are on the roadmap but not in this release.

## Features

- **Ingest** sFlow v5, NetFlow v5/v9 and IPFIX over UDP via [goflow2](https://github.com/netsampler/goflow2), in library mode (no sidecar).
- **Detect** per-destination volumetric attacks using sampling-corrected pps / Mbps / flows-per-second thresholds over a sliding window. ≥20M flows/sec/core on the hot path.
- **Mitigate** by announcing `/32` and `/128` blackhole routes via an embedded [GoBGP](https://github.com/osrg/gobgp) speaker, with your RTBH community and discard next-hop.
- **Safe by construction** — see [Safety model](#safety-model).
- **Classify** each attack from its flow sample and per-protocol rates — amplification (NTP/DNS/CLDAP/memcached/SSDP/chargen), SYN/UDP/TCP/ICMP/fragment floods — with the inferred vector in events, notifications and the API.
- **Observe** through a REST API, Prometheus `/metrics`, and Telegram, Slack, email, webhook and exec-hook notifications.

## Quickstart

```sh
# Build the static binary (Go 1.22+).
make build

# Run in dry-run with the development config (text logs).
make run-dev
# or: ./kapkan -config configs/dev.yaml -log-format text
```

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

Configuration is a single YAML file (see [`configs/dev.yaml`](configs/dev.yaml) for
development and [`deploy/config.example.yaml`](deploy/config.example.yaml) for production).
The full schema:

| Key | Meaning |
| --- | --- |
| `dry_run` | When true (default), blackholes are logged and tracked but **never announced**. |
| `listen.sflow` / `listen.netflow` | UDP listen addresses. NetFlow v5/v9 and IPFIX share the netflow socket. At least one is required. |
| `sampling.default_rate` | Sampling rate used when an exporter does not report its own (must be ≥ 1). |
| `networks` | Protected prefixes. Detection applies **only** to destinations inside these; they must not overlap. |
| `protected_whitelist` | Addresses that are **never** banned, regardless of traffic. |
| `thresholds.pps` / `.mbps` / `.flows_per_sec` | Per-destination thresholds, after sampling correction. All must be > 0. |
| `thresholds.tcp_pps` / `udp_pps` / `icmp_pps` / `tcp_syn_pps` / `frag_pps` (+ `_mbps` each) | Optional per-protocol thresholds; 0/absent disables. Any crossed threshold triggers (OR). `tcp_syn` counts pure SYNs (SYN set, ACK clear); `frag` counts non-first IP fragments. |
| `thresholds_outgoing` | Optional. Enables detection of attacks **originated by** protected hosts (compromised machines). Same keys as `thresholds`, at least one must be set; absent, outgoing traffic is not even counted. |
| `hostgroups[]` | Optional named prefix groups with their own thresholds and mitigation policy (see [Hostgroups](#hostgroups)). Each group may also set `thresholds_outgoing`. |
| `samples.enabled` / `buffer_flows` / `flows_per_attack` | Traffic buffer for attack samples (defaults: on / 65536 / 20). Recent flows are buffered continuously so the moment a threshold trips, the attack's dominant sources, ports and protocols are already attached to the event, the notification and the API — no post-detection capture delay. Sizing changes require a restart. |
| `baseline` | Continuous learned per-host thresholds (see [Baselines](#baselines)). Optional; per-hostgroup overridable. |
| `ban.ttl_seconds` | Every announcement auto-withdraws after this. No permanent bans. |
| `ban.unban_hysteresis_seconds` | Traffic must stay below threshold this long before withdrawing, to prevent flapping. |
| `ban.max_active_bans` | Hard cap on simultaneous bans; new bans past the cap are refused. |
| `bgp.local_asn` / `router_id` / `next_hop` / `next_hop6` / `community` | BGP identity, blackhole next-hops (v4/v6) and RTBH community (`ASN:value`). `router_id` must be IPv4. |
| `bgp.neighbors[]` | eBGP peers: `address`, `remote_asn` (and optional `port` for testing). |
| `notify.telegram.token_env` / `chat_id` | Telegram bot: the token is read from the named **environment variable**, never the file. |
| `notify.webhook.url` | Optional generic JSON POST target for attack start/end. Payload documented in [`docs/callback-schema.json`](docs/callback-schema.json) (versioned via `schema_version`). |
| `notify.slack.webhook_url` | Optional Slack incoming webhook. |
| `notify.email.smtp_host` / `from` / `to[]` / `username_env` / `password_env` / `require_tls` | Optional SMTP notifications. Credentials come from environment variables. STARTTLS is used when the server offers it and **required** when credentials are configured or `require_tls` is set; plaintext delivery to a non-loopback host is loudly logged. |
| `notify.exec.command` / `timeout_seconds` | Optional hook executed on every attack event: payload JSON on stdin, event name as `argv[1]`, no shell. The command must exist and be executable at config load. On timeout (default 10s) the hook's whole process group is killed. The hook receives a **minimal environment** (PATH/HOME/TZ/LANG/USER/TMPDIR) — the daemon's secrets are not inherited. Same schema as the webhook. |
| `api.listen` | REST API + metrics listen address. |

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

### Going live

1. Run in dry-run and confirm in the logs / `/api/v1/attacks` that detection fires on the
   right prefixes and the would-be routes (`route` field) are correct.
2. Confirm BGP sessions reach `ESTABLISHED` (logged as `bgp peer state`). Peering happens
   even in dry-run, so you can validate connectivity before announcing anything.
3. Set `dry_run: false` and reload (`SIGHUP` or `POST /api/v1/config/reload`).

## REST API

All endpoints are served on `api.listen`.

| Method & path | Description |
| --- | --- |
| `GET /api/v1/status` | Mode, uptime, protected networks, thresholds, active attack/ban counts. |
| `GET /api/v1/attacks` | Currently active attacks plus the last 100 that ended. |
| `POST /api/v1/ban` | Manually ban an address: `{"ip":"203.0.113.66"}`. Respects the whitelist, the cap, and the `networks` scope. |
| `POST /api/v1/unban` | Manually withdraw a ban: `{"ip":"203.0.113.66"}`. |
| `POST /api/v1/config/reload` | Re-read the config file (same as `SIGHUP`). |
| `GET /metrics` | Prometheus metrics. |

Manual bans honour every safety rule: a whitelisted target returns `409` and is never
announced; a target outside the configured `networks` returns `409`; exceeding
`max_active_bans` returns `409`.

## Metrics

Prometheus metrics under the `kapkan_` namespace, including: `ingest_flows_total` (by
protocol), `ingest_packets_total` (by exporter/protocol), `ingest_decode_errors_total`,
`engine_active_attacks`, `engine_attacks_total`, `engine_process_latency_seconds`,
`engine_tracked_hosts`, `mitigate_announced_routes` (by `real`/`dry_run` mode),
`mitigate_bans_rejected_total`, and `notify_notifications_total` (by channel/result).

## Safety model

These rules are enforced in code and covered by tests; they are non-negotiable:

1. **Dry-run by default.** Announcements happen only when `dry_run: false` is set explicitly. An absent `dry_run` key is treated as `true`.
2. **No permanent bans.** Every announcement carries a TTL and is auto-withdrawn — even if the attack is still ongoing.
3. **Unban hysteresis.** A ban is withdrawn only after traffic stays below threshold for `unban_hysteresis_seconds`, preventing announce/withdraw flapping.
4. **Hard ban cap.** Past `max_active_bans` simultaneous bans, new bans are refused and alerted — kapkan will never blackhole half your network.
5. **Whitelist is absolute.** Addresses in `protected_whitelist` are never announced, by detection or manual request.
6. **Scoped detection.** Only destinations inside `networks` are ever acted on; other traffic is counted in metrics but never triggers a ban.

## Deployment

A hardened systemd unit and a production config example live in [`deploy/`](deploy/):

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

## Development

```sh
make test   # go test -race ./...
make lint   # golangci-lint run
make bench  # engine hot-path benchmarks
make build  # static binary
```

Tests use synthetic NetFlow/sFlow datagrams built by `pkg/flowgen` (real wire format) and an
in-process GoBGP peer; no real routers are ever contacted. The end-to-end test in
`internal/app` replays an NTP-amplification flood over a real UDP socket against a dry-run
instance and asserts the attack and its (auto-expiring) virtual ban appear in the API.

## Architecture

```
cmd/kapkan/        main, flag parsing, signal handling
internal/app/      wiring of all components; end-to-end test
internal/config/   YAML load, validation, SIGHUP hot-reload
internal/ingest/   goflow2 library-mode ingestion -> normalized Flow
internal/engine/   sharded per-host counters, sliding window, threshold eval
internal/mitigate/ embedded GoBGP: RTBH announce/withdraw, TTL, caps, dry-run
internal/notify/   Telegram + webhook notifications
internal/api/      REST API + Prometheus metrics
pkg/flowgen/       synthetic NetFlow/sFlow generator for tests and load
```

Data flow: `ingest → engine (hot path) → [mitigate, notify, api]`.

## License

Apache 2.0.
