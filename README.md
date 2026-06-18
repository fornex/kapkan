# Kapkan

**Free, open-source DDoS detection and RTBH mitigation for ISPs and hosting providers.**

> **This repository is a monorepo.** Four independently-developable folders:
> `engine/` — the Go engine + REST API (documented below); `console/` — the operator-console UI
> (embedded into the binary); `site/` — the kapkan.io marketing + docs site; `docs/` — the
> user-facing documentation. `make build` (root) produces a **single binary** with the console
> `go:embed`'d — see the root `Makefile`. The rest of this README documents the engine.

Kapkan is a single Go binary that ingests flow telemetry (NetFlow v5/v9, IPFIX, sFlow v5)
from your routers, detects volumetric attacks against the prefixes you protect in seconds,
and triggers automated BGP RTBH (remotely-triggered blackhole) mitigation — with a web API,
Prometheus metrics, and Telegram/webhook notifications. It is a free replacement for the
features commercial flow-DDoS products charge for.

It is **dry-run by default**: until you explicitly flip the switch, every would-be blackhole
is logged and exposed via the API but never announced to your routers.

## Features

- **Ingest** sFlow v5, NetFlow v5/v9 and IPFIX over UDP via [goflow2](https://github.com/netsampler/goflow2), in library mode (no sidecar).
- **Detect** per-destination volumetric attacks using sampling-corrected pps / Mbps / flows-per-second thresholds over a sliding window. ≥20M flows/sec/core on the hot path.
- **Mitigate** by announcing `/32` and `/128` blackhole routes via an embedded [GoBGP](https://github.com/osrg/gobgp) speaker, or — surgically — **BGP FlowSpec** rules (RFC 8955/8956) that drop only the attack vector and spare the victim's other traffic, IPv4 and IPv6 at parity.
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
| `hostgroups[]` | Optional named prefix groups with their own thresholds and mitigation policy (see [Hostgroups](#hostgroups)). Each group may also set `thresholds_outgoing` and a `tenant` label (see [Multi-tenancy](#multi-tenancy)). |
| `tenant` | Optional tenant label for the implicit global/fallback group (top level). See [Multi-tenancy](#multi-tenancy). |
| `samples.enabled` / `buffer_flows` / `flows_per_attack` | Traffic buffer for attack samples (defaults: on / 65536 / 20). Recent flows are buffered continuously so the moment a threshold trips, the attack's dominant sources, ports and protocols are already attached to the event, the notification and the API — no post-detection capture delay. Sizing changes require a restart. |
| `geoip.enabled` / `asn_database` / `country_database` | Optional GeoIP/ASN attribution of attack-sample sources against MaxMind GeoLite2 (or GeoIP2) `.mmdb` files. Both databases are optional and independent. When an ASN database is loaded the sample, API and dashboard carry a **per-ASN top-talkers** breakdown ("from which AS"); a country database stamps each sampled source with its country. Database-path changes require a restart. Default off. |
| `baseline` | Continuous learned per-host thresholds (see [Baselines](#baselines)). Optional; per-hostgroup overridable. |
| `ban.ttl_seconds` | Every announcement auto-withdraws after this. No permanent bans. |
| `ban.unban_hysteresis_seconds` | Traffic must stay below threshold this long before withdrawing, to prevent flapping. |
| `ban.max_active_bans` | Hard cap on simultaneous bans; new bans past the cap are refused. |
| `bgp.local_asn` / `router_id` / `next_hop` / `next_hop6` / `community` | BGP identity, blackhole next-hops (v4/v6) and RTBH community (`ASN:value`). `router_id` must be IPv4. Optional `communities` (list, overrides `community`) and `local_pref`; both overridable per hostgroup via a group `bgp:` block. |
| `bgp.neighbors[]` | eBGP peers: `address`, `remote_asn` (and optional `port` for testing). |
| `notify.telegram.token_env` / `chat_id` | Telegram bot: the token is read from the named **environment variable**, never the file. |
| `notify.webhook.url` | Optional generic JSON POST target for attack start/end. Payload documented in [`docs/callback-schema.json`](docs/callback-schema.json) (versioned via `schema_version`). |
| `notify.slack.webhook_url` | Optional Slack incoming webhook. |
| `notify.email.smtp_host` / `from` / `to[]` / `username_env` / `password_env` / `require_tls` | Optional SMTP notifications. Credentials come from environment variables. STARTTLS is used when the server offers it and **required** when credentials are configured or `require_tls` is set; plaintext delivery to a non-loopback host is loudly logged. |
| `notify.exec.command` / `timeout_seconds` / `format` | Optional hook executed on every attack event, no shell. The command must exist and be executable at config load. On timeout (default 10s) the hook's whole process group is killed. The hook receives a **minimal environment** (PATH/HOME/TZ/LANG/USER/TMPDIR) — the daemon's secrets are not inherited. `format` selects the convention: `kapkan` (default — event name as `argv[1]`, payload JSON on stdin, same schema as the webhook) or `fastnetmon` (see below). |
| `api.listen` | REST API + metrics listen address. |
| `api.token_env` / `api.tokens` | API auth: a single operator token (`token_env`) or a role-based `tokens` list (`viewer`/`operator`, each with an optional `tenant` scope); secrets come from the named env vars. See Authentication and [Multi-tenancy](#multi-tenancy). |

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
hold or strengthen the response (`none` < `flowspec` < `divert` < `blackhole`) —
de-escalating between rungs is a config error. If several rungs come due at once (a
long-running attack, or the daemon catching up after a pause) the ban jumps straight to the
highest due rung and never announces the rungs it skips. The first rung must be at `0s`;
`action` is `none` (alert only), `flowspec`, `divert`, or `blackhole`.

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
| `GET /api/v1/status` | Mode, uptime, protected networks, thresholds, hostgroups, active attack/ban counts. |
| `GET /api/v1/attacks` | Currently active attacks plus the last 100 that ended (with samples and classification). |
| `GET /api/v1/hosts` | Tracked-host snapshot: per-direction rates, learned baselines, attack state (top-talkers data). |
| `GET /api/v1/bans` | All bans, active and historical. |
| `POST /api/v1/ban` | Manually ban an address: `{"ip":"203.0.113.66"}`. Respects the whitelist, the cap, and the `networks` scope. |
| `POST /api/v1/unban` | Manually withdraw a ban: `{"ip":"203.0.113.66"}`. |
| `POST /api/v1/config/reload` | Re-read the config file (same as `SIGHUP`). |
| `GET /metrics` | Prometheus metrics. |

Manual bans honour every safety rule: a whitelisted target returns `409` and is never
announced; a target outside the configured `networks` returns `409`; exceeding
`max_active_bans` returns `409`. POST endpoints require `Content-Type: application/json`.
The `GET` routes need the **viewer** role; the mutating routes (`ban`, `unban`,
`config/reload`) need the **operator** role (see Authentication).

### Dashboard

A self-contained web UI (no build step, no external assets — embedded in the binary via
`go:embed`) is served on the same `api.listen` address at `/`. It polls the API and shows
the live mode, active and recent attacks with their classification and flow samples,
top talkers with learned baselines, hostgroups, and the ban table — plus manual ban/unban
and config-reload controls. It works fully on live data alone (no database required), the
free answer to FastNetMon's per-user paid LiveView. Set `api.dashboard: false` to serve
only the JSON API and metrics.

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
a role: **viewer** (read-only: status, attacks, hosts, bans, metrics) or **operator**
(read plus manual ban/unban and config reload):

```yaml
api:
  listen: "0.0.0.0:8080"
  tokens:
    - { name: dashboard, token_env: "KAPKAN_API_RO", role: viewer }
    - { name: automation, token_env: "KAPKAN_API_RW", role: operator }
```

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

Prometheus metrics under the `kapkan_` namespace, including: `ingest_flows_total` (by
protocol), `ingest_packets_total` (by exporter/protocol), `ingest_decode_errors_total`,
`engine_active_attacks`, `engine_attacks_total`, `engine_process_latency_seconds`,
`engine_tracked_hosts`, `mitigate_announced_routes` (by `real`/`dry_run` mode),
`mitigate_flowspec_rules` (by mode), `mitigate_bans_rejected_total`,
`notify_notifications_total` (by channel/result), and `storage_rows_total` (by table and
`written`/`dropped`/`error`).

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
creates two MergeTree tables (idempotently): `attack_events` (every start/end with type,
direction, rates, sample top-sources, top-ASNs when GeoIP is enabled, ban state) and
`traffic` (periodic per-host rate and baseline snapshots). Both carry a `ttl_days` TTL so
retention is bounded without operator intervention.

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
