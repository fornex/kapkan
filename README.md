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

The same binary also runs the boxes around it. [`kapkan scrub`](#managed-scrubbing-nodes)
turns a Linux box into a managed scrubbing node that filters diverted traffic in its own
kernel; [`kapkan edge`](#edge-nodes) turns a box running nginx or Angie into a managed HTTPS
front for your websites — certificates, configuration and per-request decisions (a rate
ceiling, a proof-of-work challenge, a block) all made on the node. Flow detection stays
volumetric; at the edge Kapkan enforces the per-request policy you write, keyed by source and
never by request content — it is not a WAF — and it never forwards a client's bytes: nginx
terminates and proxies.

It is **dry-run by default**: until you explicitly flip the switch, every would-be blackhole
is logged and exposed via the API but never announced to your routers, and the in-kernel data
plane, if you run one, installs no ban or source block — only the rules your own config sets
there run, counting what they would drop and passing it. The remote roles start the same way,
each on its own switch: a scrub node drops nothing and an edge node refuses nothing it decides —
it marks what it would refuse for the origin — until its own file says `dry_run: false`, and
even then a zone's proof-of-work challenge only previews until that zone turns it on. A zone
set to `failure_mode: closed` still answers `503` whenever the decision service cannot be
reached, dry-run or not.

The full user documentation — every config key, the deployment guides, the data plane, the
edge and the network-integration lab — lives at **[kapkan.io/docs](https://kapkan.io/docs)**
(English, Russian, German, French, Spanish). This README is the engine's own reference.

## Features

- **Ingest** sFlow v5, NetFlow v5/v9 and IPFIX over UDP via [goflow2](https://github.com/netsampler/goflow2), in library mode (no sidecar).
- **Detect** per-destination volumetric attacks using sampling-corrected pps / Mbps / flows-per-second thresholds over a sliding window — optionally per protocol, against [learned per-host baselines](#baselines), and for [attacks your own hosts send](#outgoing-detection). Flows-per-second counts NetFlow/IPFIX records only, so it never fires on sFlow; diffuse subnet-spread floods are caught by [carpet-bomb detection](#carpet-bomb-detection). The per-flow fold is allocation-free: `make -C engine bench` times it at about 10M flows/sec on one Apple M3 Max core and 24M on eight — pre-built flows, no socket or decoder — and every hot-path change must clear ≥200k flows/sec on 8 cores there ([how it works](https://kapkan.io/docs/how-it-works#performance)).
- **Mitigate** four ways, individually or as an [escalation ladder](#escalation-ladders): drop locally in an in-kernel **[XDP data plane](#in-kernel-data-plane-xdp)**, which announces nothing; or, through an embedded [GoBGP](https://github.com/osrg/gobgp) speaker, announce **BGP FlowSpec** rules (RFC 8955/8956) that drop only the attack vector, IPv4 and IPv6 at parity, **divert** the victim to a scrubbing node, or announce `/32` and `/128` **blackhole** routes. The data plane also runs your own always-on rules with a token bucket per source — one can match the TLS ClientHello or the QUIC v1 Initial, so a handshake flood is metered per source.
- **Fingerprint** TLS and QUIC clients by [JA4](https://kapkan.io/docs/fingerprinting), off-path (off by default; needs the data plane): the kernel copies a sampled prefix of each ClientHello and QUIC v1 Initial, userspace computes the JA4 and source-blocks any on `ja4_blocklist`. The trigger is spoofable, so a JA4 block acts on the *claimed* source — TTL'd, dry-run-aware and drawn from its own smaller budget, so a crafted-JA4 flood can never starve operator blocks.
- **Enforce** an application-layer decision made elsewhere: whatever already terminates a victim's traffic hands Kapkan a source to drop in-kernel through [`POST /api/v1/dataplane/sources`](https://kapkan.io/docs/dataplane#source-blocks-from-your-own-stack) — scoped to that victim, with a mandatory TTL, every ban guarantee intact — and `kapkan nginx-exporter`, the reference caller, turns an nginx JSON access log into per-source verdicts.
- **Scrub** with your own nodes: a second box running [`kapkan scrub`](#managed-scrubbing-nodes) takes the diverted traffic, is told exactly what to drop, and filters it in its own kernel — same binary, no second product.
- **Front** your websites with [`kapkan edge`](#edge-nodes): a box running nginx or Angie becomes a managed HTTPS front — certificates issued on the node (ACME HTTP-01; keys never leave the box; no wildcards), configuration tested with `nginx -t` before every reload so a broken edit never goes live, HTTP/3 per zone where the node's build has the module, and requests decided on the node against each zone's per-source rate ceiling and verdict table, failing open by default. The brain distributes policy, never verdicts, so a node keeps serving from its cached document with the brain gone — and Kapkan never forwards a client's bytes.
- **Challenge** before blocking: a zone's [proof-of-work rung](https://kapkan.io/docs/edge#the-proof-of-work-rung) serves a challenged client a page instead of the origin — seconds of CPU for a browser, a timed ticket without JavaScript — and the clearance it earns holds on every node serving the zone. In `auto` a flooding source is challenged before it is denied, and the whole zone once its admitted rate on a node reaches `auto.zone_rps`. In an incident an operator's [lever](https://kapkan.io/docs/edge#the-lever), from the API or the console, holds a zone under challenge for 60 s to 24 h — no reload, ending on time with or without the brain.
- **Scale out** behind your own routing: [place zones on nodes](https://kapkan.io/docs/edge#placing-zones-on-nodes) along the hostgroups you already have, bind each node's `agent` token to that node (`api.tokens[].node`), and put several nodes behind one [anycast or ECMP address](https://kapkan.io/docs/edge-anycast). Your network announces and withdraws that address — Kapkan never steers a zone's traffic — and every rate ceiling, verdict table and TLS session cache stays per node, while clearances, the zones file and the lever are the fleet's.
- **Share** one instance among customers: a `tenant` label on a hostgroup — or on an edge zone, for a customer with hostnames and no prefixes — scopes an API token to that customer's attacks, bans, hosts, audit trail, zones, edge history and lever, default-deny and with no cross-tenant existence oracle ([multi-tenancy](#multi-tenancy)). The scoping is the API's: notifications and `/metrics` stay deployment-wide.
- **Persist** (optional) attack, traffic, audit and edge history in [ClickHouse](#storage-optional) 21.4+ — for the edge, each zone's ten-second windows per node, its telling sources (denied, challenged or would-have-been; ordinary visitors are never stored) and the fleet's node events. Best-effort by contract: a slow or down ClickHouse costs rows, never detection.
- **Safe by construction** — see [Safety model](#safety-model).
- **Classify** each attack from its flow sample and per-protocol rates — amplification (NTP/DNS/CLDAP/memcached/SSDP/chargen), SYN/UDP/TCP/ICMP/fragment floods — with the inferred vector in events, notifications and the API.
- **Observe** through a REST API, Prometheus `/metrics`, an embedded operator console, and Telegram, Slack, email, webhook and exec-hook notifications.

## Quickstart

No build step — grab a prebuilt, signed release (see [Install](#install) to verify it first):

```sh
# Download and unpack a release (linux amd64/arm64) — or `apt install ./kapkan_*.deb`.
VER=v1.8.0
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

No router handy? `pkg/flowgen` is a test package, not a command in the binary: from a source
checkout, `make -C engine console-sync && cd engine && go test ./internal/app -run TestEndToEndNTPAmplification -v`
replays a synthetic NTP-amplification flood against a dry-run instance and checks that the
attack and its virtual ban reach the API.

## Configuration

Configuration is a single YAML file (see [`configs/dev.yaml`](engine/configs/dev.yaml) for
development and [`deploy/config.example.yaml`](engine/deploy/config.example.yaml) for
production) — plus, only when it has an `edge` block, the [zones file](#edge-nodes) that block
names. `kapkan -check-config <path>` validates both without starting the daemon, and
`kapkan -dump-schema` / `-dump-zones-schema` print their machine-readable JSON schemas. The
remote roles never read this file: a [scrub node](#managed-scrubbing-nodes) and an
[edge node](#edge-nodes) each carry their own. The main keys — the complete reference, key by
key, is [kapkan.io/docs/configuration](https://kapkan.io/docs/configuration):

| Key | Meaning |
| --- | --- |
| `dry_run` | When true (default), blackholes are logged and tracked but **never announced**. `kapkan scrub` and `kapkan edge` nodes carry their own `dry_run`, also on by default. The brain's flag still travels with each ban to a scrub node — a live scrub node never drops for a ban made in dry-run — and never reaches an edge node (see [Going live](#going-live)). |
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
| `flowspec.action` / `rate_mbps` / `source_anchored` / `min_source_concentration` | FlowSpec rule action: `discard`, or `rate_limit` with a ceiling (see [FlowSpec](#flowspec-surgical-mitigation)). `source_anchored: true` (default off) pins the attack sample's dominant sources as well as the victim, so only the attackers are dropped — but only when those sources cover at least `min_source_concentration` of the sample; a diffuse attack keeps the victim-anchored rule. Per-hostgroup overridable. |
| `scrubbing` | Diversion target(s): the scalar `next_hop`/`next_hop6`/`community`/`local_pref` of a scrubbing center, plus `nodes[]` / `node_selection` / `on_all_nodes_lost` / `stale_after_seconds` for [managed scrubbing nodes](#managed-scrubbing-nodes). Per-hostgroup overridable. |
| `dataplane` | The [in-kernel XDP data plane](#in-kernel-data-plane-xdp): `interfaces`, `xdp_mode`, `pin_path`, `on_exit`, `drop_malformed`, `allowlist`, `ratelimit_profiles[]`, `static_rules[]`, `limits`, and the off-path [`fingerprint`](https://kapkan.io/docs/fingerprinting) plane (JA4 source-blocking). Absent = off; `enabled: false` switches a written block off, and whatever needs it — a `dataplane` rung or method, `fingerprint.enabled` — is then refused. The attachment (`enabled`, `interfaces`, `xdp_mode`, `pin_path`, `on_exit`), `limits` and `fingerprint.enabled` / `sample_pps` are fixed at startup — a reload that changes them is refused; the policy (`allowlist`, `ratelimit_profiles`, `static_rules`) and `fingerprint.ja4_blocklist` / `block_ttl_seconds` hot-reload. |
| `edge` | Serve [edge nodes](#edge-nodes) — boxes running `kapkan edge` that turn their nginx/Angie into a managed HTTPS front: `zones_file` (absolute path of the tenant-owned [zones file](https://kapkan.io/docs/zones) — loaded and validated with this one, and a broken one fails the whole load, so a reload keeps the previous zones live), `nodes[].name` (each must equal a node's `controller.name`), `nodes[].hostgroups` (optional placement scope: the hostgroups whose zones the node serves, the literal `global` for zones that name none; empty = `global` alone), `stale_after_seconds`, and `state_file` (optional: where the brain keeps the fleet's clearance-signing keys, written `0600`, so a restart does not send every cleared visitor back to the challenge). Absent = off. |
| `ban.ttl_seconds` | Every ban's expiry. A detection window that still sees the attack refreshes it, so a sustained flood stays mitigated; a ban nothing refreshes any more auto-withdraws within it. No permanent bans. |
| `ban.unban_hysteresis_seconds` | Traffic must stay below threshold this long before withdrawing, to prevent flapping. |
| `ban.max_active_bans` | Hard cap on simultaneous bans; new bans past the cap are refused. |
| `ban.max_banned_fraction` / `max_bans_per_window` + `ban_window_seconds` | Blast-radius guards: cap the share of your own address space that may be blackholed at once (per address family), and the rate of new bans. Both default to 0 = off. See [Safety model](#safety-model). |
| `ban.fallback` | What happens when a peer rejects a `flowspec`/`divert` announce: `blackhole` (default — degrade rather than leave the victim undefended) or `none` (reject the ban). |
| `ban.state_file` | Writable path where active bans are persisted and re-announced on startup, so an upgrade does not drop mitigation (see [Upgrading](#upgrading)). Empty = off; an unwritable path degrades to no persistence, never a startup failure. |
| `bgp.local_asn` / `router_id` / `next_hop` / `next_hop6` / `community` | BGP identity, blackhole next-hops (v4/v6) and RTBH community (`ASN:value`). `router_id` must be IPv4. Optional `communities` (list, overrides `community`) and `local_pref`; both overridable per hostgroup via a group `bgp:` block. |
| `bgp.neighbors[]` | eBGP peers: `address`, `remote_asn` (and optional `port` for testing). |
| `bgp.graceful_restart` | BGP Graceful Restart, **on by default**: a peer that supports it keeps kapkan's mitigation routes, as stale, while the session is down — an upgrade, a crash — instead of flushing them. `enabled: false` opts out; `restart_seconds`, and `long_lived` with `long_lived_stale_seconds` (LLGR), bound how long they linger if kapkan does not come back. Pairs with `ban.state_file` (see [Upgrading](#upgrading)). |
| `notify.telegram.token_env` / `chat_id` | Telegram bot: the token is read from the named **environment variable**, never the file. |
| `notify.webhook.url` | Optional generic JSON POST target for attack start/end. Payload documented in [`docs/callback-schema.json`](docs/callback-schema.json) (versioned via `schema_version`). |
| `notify.slack.webhook_url` | Optional Slack incoming webhook. |
| `notify.email.smtp_host` / `from` / `to[]` / `username_env` / `password_env` / `require_tls` | Optional SMTP notifications. Credentials come from environment variables. STARTTLS is used when the server offers it and **required** when credentials are configured or `require_tls` is set; plaintext delivery to a non-loopback host is loudly logged. |
| `notify.exec.command` / `timeout_seconds` / `format` | Optional hook executed on every attack event, no shell. The command must exist and be executable at config load. On timeout (default 10s) the hook's whole process group is killed. The hook receives a **minimal environment** (PATH/HOME/TZ/LANG/USER/TMPDIR) — the daemon's secrets are not inherited. `format` selects the convention: `kapkan` (default — event name as `argv[1]`, payload JSON on stdin, same schema as the webhook) or `fastnetmon` (see below). |
| `api.listen` | REST API + metrics listen address. |
| `api.token_env` / `api.tokens` | API auth: a single operator token (`token_env`) or a role-based `tokens` list (`viewer`/`operator`/`agent`); secrets come from the named env vars. A `viewer` or `operator` token may carry a `tenant` scope (one a hostgroup or a zone uses); an `agent` token may not, and takes `node` instead — exactly one `edge.nodes[]` or `scrubbing.nodes[]` name, the only node it may then act as. Unbound, an agent token can act as **any** node: it keeps working, named by `-check-config`, the log and the edge inventory, and becomes a config error once any edge node has a placement scope. See [Authentication](#authentication) and [Multi-tenancy](#multi-tenancy). |
| `api.dashboard` | Serve the embedded operator console on the API listener. Default true; false leaves only the JSON API and metrics. |
| `storage.clickhouse` | Optional history in ClickHouse — attacks, traffic, the audit trail and the edge nodes' windows and events — under one switch and one `ttl_days` (see [Storage](#storage-optional)). Absent = kapkan runs entirely on live data, and the history routes answer `available: false`. |
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
per window, and posts the verdicts to this channel — a supported component beside the
[edge role](https://kapkan.io/docs/edge), which makes those decisions on the node itself. Full contract:
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
- **The agent role is off the privilege ladder.** A node's token reaches only the node routes
  (here, the rule channel and its own self-report) and nothing else — not attacks, bans or
  audit — because it lives on a remote, often less-guarded box. Bind it to its node
  (`node: scrub-fra1` on its `api.tokens` entry): unbound, it may poll and report as any node,
  scrubbing or edge. And give the node an `agent` token, never an operator one — only an
  agent's poll counts as liveness, so a node polling on an operator token reads as lost and its
  victims fail over as if it were. See [Authentication](#authentication).

Getting the diverted traffic *to* a node and the clean traffic back out — L2 insertion,
GRE/IPIP with MSS clamping, the return path and the asymmetric-routing traps — is your
network's job, covered in the
[network-integration guide](https://kapkan.io/docs/network-integration).

### Edge nodes

RTBH, FlowSpec, diversion and the data plane all act on packets; none of them ever sees an
HTTP request. An **edge node** does: a box running the `kapkan edge` role beside its own nginx
or Angie, which Kapkan turns into a managed HTTPS front — certificates issued on the box,
configuration generated and tested (`nginx -t`) before every reload, and a local decision
service that lets each request through, holds it to a per-source rate ceiling, asks it to solve
a proof-of-work challenge, or blocks it. Kapkan **never forwards a client's bytes**: nginx
terminates TLS and proxies to your origins, Kapkan decides. Three files, each owned by whoever
changes it — the brain's `edge` block only joins the other two:

```yaml
# /etc/kapkan/config.yaml (the brain)
edge:
  zones_file: /etc/kapkan/zones.yaml   # absolute; required when the block is present
  nodes:
    - name: edge-1                     # must equal the node's controller.name
api:
  tokens:
    - { name: edge-1, token_env: KAPKAN_EDGE_1_TOKEN, role: agent, node: edge-1 }
```

```yaml
# /etc/kapkan/zones.yaml — the sites: tenant data, kept out of the operator's file
zones:
  - name: shop.example.com
    origins: ["10.0.0.10:8080"]
    policy: { mode: decide, rate: { rps: 50, concurrency: 20 } }
```

```yaml
# /etc/kapkan/edge.yaml on the node — then: kapkan edge
dry_run: true                            # the remote-role default: marks, refuses nothing
controller:
  url: "https://kapkan.example.net:8443" # the brain's API base
  token_env: KAPKAN_EDGE_TOKEN           # the node's agent token (required)
  name: edge-1                           # must equal an edge.nodes[] name
socket_group: nginx                      # the terminator's worker group
terminator:
  binary: nginx                          # or angie
  main_conf: /etc/nginx/nginx.conf       # its http {} includes kapkan's live generation
```

The zones file is loaded and validated with the configuration — on start, on every reload and
by `kapkan -check-config` — and one that does not read or validate fails the whole load, so a
reload keeps the previous zones live. A zone may name an owner (`tenant`, the
[Multi-tenancy](#multi-tenancy) axis) and a placement (`hostgroup`: served by the nodes whose
`edge.nodes[].hostgroups` list it; a zone that names none is `global`, and `global` is all a
node without a scope serves). The brain's API speaks plain HTTP, so the `https` URL a scrub or
edge node polls needs a TLS-terminating proxy in front of `api.listen`, with a read timeout
longer than the poll's hold. Four things are worth knowing before you deploy this:

- **The brain distributes policy, never verdicts.** Every per-request decision is made on the
  node, which keeps serving its last document and certificates from disk — and renewing — while
  the brain is down. A zone's rate or challenge mode, or a pulled
  [lever](https://kapkan.io/docs/edge#the-lever), applies without reloading nginx; a zone added
  or removed, an origin, the TLS settings or a new certificate is a new generation, tested
  before it is installed.
- **Watch-only is the node's and the zone's, not the brain's.** The brain's `dry_run` never
  reaches an edge node. A node refuses nothing it decides until its own `dry_run: false` — a
  would-be refusal reaches the origin marked `X-Kapkan-Mark: would-deny:<reason>` — a zone stays
  watch-only everywhere with `policy.dry_run: true`, and the challenge only previews until the
  zone sets `policy.challenge_options.dry_run: false`. `failure_mode: closed` is not a decision:
  such a zone answers `503` while the decision service is unreachable, watch-only or not.
- **The agent token issues certificates — bind it.** Besides polling, a node's `agent` token
  coordinates ACME issuance for the zones it serves: give every node its own, bound with
  `node`, so a stolen one speaks for that node alone. Once any node has a placement scope, an
  unbound agent token is a config error.
- **Kapkan renders configuration; it never steers traffic.** DNS, or an
  [anycast/ECMP address](https://kapkan.io/docs/edge-anycast) the nodes share, brings clients
  to a node — your network's job — and a zone's certificate cannot be issued until its name
  resolves to a node that serves it.

Installing a node end to end is [kapkan.io/docs/edge-install](https://kapkan.io/docs/edge-install);
every zones key is in [kapkan.io/docs/zones](https://kapkan.io/docs/zones), every `edge.yaml` key
in [kapkan.io/docs/cli](https://kapkan.io/docs/cli#edge), and the role — the challenge ladder,
the lever, HTTP/3, shared addresses, what fails how — in
[kapkan.io/docs/edge](https://kapkan.io/docs/edge). The annotated node file and its unit are
[`engine/deploy/edge.example.yaml`](engine/deploy/edge.example.yaml) and
[`engine/deploy/kapkan-edge.service`](engine/deploy/kapkan-edge.service); releases after 1.8.0
carry them in the archive's `deploy/` and, from a package, in `/usr/share/kapkan/`.

### Going live

1. Run in dry-run and confirm in the logs / `/api/v1/attacks` that detection fires on the
   right prefixes and the would-be routes (`route` field) are correct.
2. Confirm BGP sessions reach `ESTABLISHED` (logged as `bgp peer state`). Peering happens
   even in dry-run, so you can validate connectivity before announcing anything.
3. Set `dry_run: false` and reload (`SIGHUP` or `POST /api/v1/config/reload`).
4. Take the remote roles live on their own. Step 3 governs this daemon; a
   [scrub node](#managed-scrubbing-nodes) and an [edge node](#edge-nodes) each start watch-only
   from their own file and go live there, with `dry_run: false` on the node. A scrub node still
   never drops for a ban the brain marks dry-run; an edge node never consults the brain's
   `dry_run` at all — a zone can stay watch-only with `policy.dry_run`, and its challenge
   previews until `policy.challenge_options.dry_run: false`.

## Command line

`kapkan [flags]` runs the daemon; `kapkan [flags] <command> [args]` runs a command instead —
`dataplane status` and `help` answer and exit, the roles `scrub`, `edge` and `nginx-exporter`
run until stopped. Global flags come **before** the command, the command's own flags after it
(`kapkan -config /etc/kapkan/config.yaml dataplane status -json`). The roles take nothing from
the daemon's command line: a global `-config`, `-log-format` or `-log-level` in front of one is
refused (exit `2`) rather than pointing a node at the daemon's file — give the role its own,
after the command. A flag that exits on its own (`-version`, `-check-config`, `-dump-schema`,
`-dump-zones-schema`, `-check-update`, `-s`) cannot be combined with a command — kapkan refuses
the combination rather than silently honouring one of them. Every flag, default and exit code:
[kapkan.io/docs/cli](https://kapkan.io/docs/cli).

| Flag | Default | Description |
| --- | --- | --- |
| `-config <path>` | `configs/dev.yaml` | Path to the YAML config file. The default is the repo's development config, resolved against the working directory — on a host pass the real path (the shipped unit passes `/etc/kapkan/config.yaml`), also to `-check-update` and `dataplane status`, which read it. |
| `-log-format <fmt>` | `json` | `json` (for log collectors) or `text` (human-readable). Logs always go to stderr. |
| `-log-level <lvl>` | `info` | `debug`, `info`, `warn` or `error`. |
| `-check-config <path>` | — | Parse and validate that config — including cross-field rules a static schema cannot express, and the [zones file](#edge-nodes) its `edge.zones_file` names — print the resolved result (with an `edge` block, each node's scope, zones placed and bound token), and exit `0` valid / `1` invalid. Drops straight into CI or a pre-deploy gate. A valid config may still print a `WARNING` without changing the exit code — a static rule that can never fire, an `agent` token bound to no node, a zone no edge node's scope covers. The daemon's file only: an edge node checks its `edge.yaml` with `kapkan edge -check`, and a `scrub.yaml` is validated when `kapkan scrub` starts. |
| `-dump-schema` | `false` | Print the config's JSON schema to stdout and exit. |
| `-dump-zones-schema` | `false` | Print the JSON schema of the [zones file](https://kapkan.io/docs/zones) an edge brain serves (`edge.zones_file`) to stdout and exit. |
| `-version` | `false` | Print the build version and exit (also on `/api/v1/status` and the `kapkan_build_info` metric — zero egress). |
| `-check-update` | `false` | Run the update check once and exit: `0` up to date, `10` newer release available, `1` error. Works regardless of the `update_check` setting, but loads the config for its `channel` / `url` — without `-config` it reads the development default and exits `1` on a host. |
| `-pid-file <path>` | `/run/kapkan/kapkan.pid` | Where the daemon writes its pid on start; read by `-s`. A write failure is non-fatal. |
| `-s <signal>` | — | Signal the running daemon and exit: `reload` (SIGHUP), `stop` / `quit` (SIGTERM) — nginx-style local control that needs no API token and works when the API is down. The daemon only: the `scrub`, `edge` and `nginx-exporter` roles write no pid file and have no reload — restart one to change its configuration. |

```sh
kapkan dataplane status    # is the kernel actually filtering? read-only; works with the daemon stopped
kapkan scrub               # run the scrub-node role (its own -config, default /etc/kapkan/scrub.yaml)
kapkan edge                # run the edge-node role (its own -config, default /etc/kapkan/edge.yaml)
kapkan edge -check         # validate edge.yaml and what it names on this box, then exit
kapkan nginx-exporter      # tail an nginx JSON access log into the source-block channel (-log required)
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
`2` usage. Add `-json` for the machine-readable form. The pins it reads are
`dataplane.pin_path` from the file the global `-config` names — the default
`configs/dev.yaml` is not there on a host, so pass the real one before the command — else
`/sys/fs/bpf/kapkan` when that file has no `dataplane` block or cannot be read. A `dataplane`
block with `enabled: false` resolves to an empty path, where no pins can be found, so pass
`-pin-path <dir>` there; it overrides all of these, and the report always says which path it
read and why.

`edge`, like `scrub`, defaults to dry-run, and neither starts while the variable its
`controller.token_env` names is empty. `kapkan edge -check` is the edge node's pre-flight: it
validates `edge.yaml` and what it names on this box and exits `0` / `1` — a `socket_group` that
does not exist or a malformed EAB key fails it, while an unset token, an absent terminator
binary or `main_conf` only warn, since the check may run before the unit's environment file or
nginx is in place — and, with the binary on `PATH`, prints what the terminator's `-V` reports
and the node's HTTP/3 readiness, all on stderr. `nginx-exporter` posts with an **operator**
token (`-token-env`, default `KAPKAN_API_TOKEN`); `-observe` only logs its verdicts and needs
none. The roles' flags and every `edge.yaml` key:
[kapkan.io/docs/cli](https://kapkan.io/docs/cli#edge).

## REST API

All endpoints are served on `api.listen`.

| Method & path | Description |
| --- | --- |
| `GET /api/v1/status` | Mode, uptime, protected networks, thresholds, hostgroups, active attack/ban counts. |
| `GET /api/v1/attacks` | Currently active attacks plus the last 100 that ended (with samples and classification). |
| `GET /api/v1/hosts` | Tracked-host snapshot: per-direction rates, learned baselines, attack state (top-talkers data). |
| `GET /api/v1/bans` | All bans, active and historical. |
| `GET /api/v1/traffic` | Persisted per-host rate history (the Traffic/Reports view). Returns `available: false` — not an error — when [storage](#storage-optional) is disabled. |
| `GET /api/v1/audit` | Operator-attributed audit trail: who banned/unbanned, blocked/unblocked a source, pulled or cleared an edge lever, or reloaded — when, and the outcome — plus the fingerprint plane's automatic source blocks (`source: "auto"`). Tenant-scoped server-side. Also `available: false` without storage. |
| `POST /api/v1/ban` | Manually ban an address: `{"ip":"203.0.113.66"}`. Respects the whitelist, the cap, and the `networks` scope. |
| `POST /api/v1/unban` | Manually withdraw a ban: `{"ip":"203.0.113.66"}`. |
| `POST /api/v1/config/reload` | Re-read the config file (same as `SIGHUP`). |
| `POST /api/v1/dataplane/sources` | Drop a source in the XDP data plane, scoped to one victim, with a **mandatory** TTL (1s-24h): `{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":600}`. For whoever already terminates the victim's traffic. `operator` only — `agent` is denied. |
| `POST /api/v1/dataplane/sources/unblock` | Remove one source block immediately (same `victim`/`source` body). |
| `GET /api/v1/dataplane/rules` | The rule table a [scrub node](#managed-scrubbing-nodes) enforces, as a long poll (ETag'd); with `?node=<name>` the poll is that node's liveness signal. **`agent` or unscoped `operator` only** — not viewer; a node-bound token polls only as its node. |
| `POST /api/v1/dataplane/nodes/{name}/report` | A scrub node's self-report (load, drop counts, version). Advisory by contract, never liveness. `agent` or unscoped `operator`; a node-bound token reports only as its node. |
| `GET /api/v1/dataplane/nodes` | Scrub-node inventory for the console's Scrubbing nodes view: configured nodes, whether each is polling, its frozen ban count and its last self-report. Viewer rank, unscoped tokens only. |
| `GET /api/v1/edge/zones` | The zone document an [edge node](#edge-nodes) renders, as a long poll (ETag'd): the zones its placement covers — every zone for a bare `GET` — with origins, TLS floor and policy, plus the live ACME grants and challenges, the rung's signing keys and any lever. With `?node=<name>` the poll is that node's liveness signal. **`agent` or unscoped `operator` only** — not viewer; a node-bound token polls only as its node. |
| `POST /api/v1/edge/nodes/{name}/report` | An edge node's self-report: version, terminator and live generation, certificates (metadata only) and each deciding zone's last ten-second window with its telling sources. Advisory by contract, never liveness; with [storage](#storage-optional) it also feeds the edge history. `agent` or unscoped `operator`; a node-bound token reports only as its node. |
| `POST /api/v1/edge/nodes/{name}/acme/slot` (and `…/acme/challenges`) | The issuance coordinator, advisory and in memory: one node at a time orders a zone's certificate, and the slot holder's pending HTTP-01 challenge is fanned out to every node serving the zone. Only for zones the node's placement covers — any other is `404 unknown zone`, the answer a nonexistent zone gets; a `{"release": true}` touches only the caller's own grant and answers `204` for any zone name. `agent` or unscoped `operator`; a node-bound token only as its node. |
| `GET /api/v1/edge/nodes` | Edge-node inventory for the console's Edge nodes view: liveness from the poll, placement scope and zones placed, the agent tokens bound to each node and the one that last polled as it, its last self-report — and `unbound_agent_tokens`, scrubbing-node tokens included. Viewer rank, unscoped tokens only. |
| `GET /api/v1/edge/zones/status` | Every zone of the zones file merged with the alive nodes' reports — fleet rate, the challenge mode the nodes apply, watch-only nodes, certificates, placement, the lever in force — and the **would-be set**: who would be challenged, to read before a rung goes live. Viewer rank; a tenant-scoped token sees exactly its own zones. |
| `POST /api/v1/edge/zones/{name}/challenge` (and `DELETE`) | [The lever](https://kapkan.io/docs/edge#the-lever): set a zone's rung to `manual` or `auto` with a **mandatory** TTL (60s-24h), whatever its `policy.challenge` says — `{"mode":"manual","ttl_seconds":1800,"reason":"…"}` — or clear it (`DELETE`, or `mode: off`); a zone in `policy.mode: none` is `409`, since nothing challenges there. Every node ends it on time, brain or no brain; it lives in the brain's memory, so a brain restart drops it. Audited. `operator` rank; a tenant-scoped operator on its own zones only — any other zone is `404 unknown zone`, exactly what a nonexistent one answers. |
| `GET /api/v1/edge/history` | A zone's [edge history](https://kapkan.io/docs/storage#edge-history) summed into buckets over a range (`zone`, `from`/`to`, `step`; `node=` for unscoped tokens only). Viewer rank; a tenant-scoped token reads its own zones, and any other — nonexistent included — is one uniform `403`. `available: false`, not an error, without storage. |
| `GET /api/v1/edge/history/sources` | The zone's telling sources over the range: who was denied, challenged, or would have been. Same scope and storage rules as `edge/history`. |
| `GET /api/v1/edge/events` | The transitions the brain saw in the edge fleet — a node lost or back, a generation refused, a certificate issued or gone, a zone-wide challenge — newest first. Viewer rank, unscoped tokens only (the events name nodes). `available: false` without storage. |
| `GET /metrics` | Prometheus metrics. Unauthenticated. |
| `GET /healthz` | Readiness probe: `503` until every component is up, `200` after. Unauthenticated (it leaks nothing) so an updater or supervisor can gate on it; the body also summarises the data plane's state. |

Manual bans honour every safety rule: a whitelisted target returns `409` and is never
announced; a target outside the configured `networks` returns `409`; exceeding
`max_active_bans` returns `409`. POST endpoints require `Content-Type: application/json`.
The `GET` routes need the **viewer** role; the mutating routes (`ban`, `unban`,
`config/reload`, both `dataplane/sources` routes and the edge lever) need the **operator**
role. The six node routes — the scrub channel's rules poll and report, the edge channel's
zones poll, report and two ACME calls — are granted by explicit membership to `agent` and to
an unscoped `operator` (so a human can curl what an agent sees), which is why
`dataplane/rules` and `edge/zones` are `GET`s a viewer cannot read; a node-bound agent token
acts only as its own node. Whatever spans the deployment — `config/reload`, both node
channels, both node inventories, `edge/events` — refuses a tenant-scoped token with `403`;
the edge zone status, history and lever admit one for its own zones. See
[Authentication](#authentication), [Multi-tenancy](#multi-tenancy) and the edge channel's
full contract at [kapkan.io/docs/api](https://kapkan.io/docs/api#the-edge-channel).

### Dashboard

A self-contained web console (no build step, no external assets — embedded in the binary via
`go:embed`) is served on the same `api.listen` address at `/`. It polls the API and shows
the live mode, active and recent attacks with their classification and flow samples, top
talkers with learned baselines, the ban table, hostgroups, traffic history and a read-only
settings view — plus manual ban/unban and config-reload controls. A **Scrubbing nodes** view
appears when the config carries managed [scrubbing nodes](#managed-scrubbing-nodes): which
are polling, how many bans each is holding, and each node's last self-report. With
[edge nodes](#edge-nodes) configured, two more appear: **Edge** — every zone of the zones file
with its fleet-wide rate, challenge state and placement (an unserved zone is flagged), the
**Who would be challenged** panel to read before a rung goes live, the lever for operators,
and each zone's history and the fleet's events from storage — and **Edge nodes**, the fleet's
inventory: liveness from the poll, the agent tokens bound to each node and the one that last
polled as it, placement, and each node's reported version, terminator, HTTP/3 readiness and
certificates, with a banner naming any unbound agent token. A tenant-scoped token sees only
its own zones on Edge; both node inventories and the fleet's events are for unscoped tokens.
It works fully on live data alone (no database required — only the history panels read
[storage](#storage-optional)), the free answer to FastNetMon's per-user paid LiveView. Set
`api.dashboard: false` to serve only the JSON API and metrics.

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
a role: **viewer** (read-only: status, attacks, hosts, bans, traffic, audit, the edge zone
status and history — the node inventories and edge events for unscoped tokens only),
**operator** (read plus manual ban/unban, source blocks, the edge lever and config reload),
or **agent** (a scrubbing or edge node's credential, bound to that node with `node`):

```yaml
api:
  listen: "0.0.0.0:8080"
  tokens:
    - { name: dashboard,  token_env: "KAPKAN_API_RO",     role: viewer }
    - { name: automation, token_env: "KAPKAN_API_RW",     role: operator }
    - { name: scrub-fra1, token_env: "KAPKAN_AGENT_FRA1", role: agent, node: scrub-fra1 } # a scrubbing.nodes[] name
    - { name: edge-fra1,  token_env: "KAPKAN_EDGE_FRA1",  role: agent, node: edge-fra1 }  # an edge.nodes[] name
```

The **agent** role sits deliberately **off** the privilege ladder — below viewer, not above
it. An agent token lives on a remote node, often a less-guarded box, and must not become a
read-everything key if that box is compromised, so it is granted the node routes — the scrub
channel's rules poll and report, the edge channel's zones poll, report and two ACME calls —
by explicit membership rather than by rank. It reads no attacks, no bans, no audit, no
status, and it cannot carry a `tenant` (a validation error: what it reads spans every
tenant).

**Bind every agent token to its node.** `node` names exactly one `edge.nodes[]` or
`scrubbing.nodes[]` entry — a name in both lists is refused as ambiguous, and several tokens
may bind one node, which is how a secret is rotated without a gap. The brain then refuses
the token wherever a node names itself — the polls' `?node=`, the reports, the ACME calls —
when the name is another node's, and on a poll that names none: a uniform `403` that never
names the bound node, decided before any presence is stamped, report stored or slot granted,
shown to you as one log warning a minute per token and in
`kapkan_api_node_binding_refused_total`, never as an audit row. **Unbound, an agent token is a
fleet-wide credential on both channels**: it may poll, report and coordinate ACME as any
node, and its bare zones poll returns every zone with the rung's signing keys. It keeps
working so a fleet migrates one node at a time, and it is named until bound — by
`-check-config` (a `WARNING`), in the log at start and on every reload, and as
`unbound_agent_tokens` in the edge inventory — but once any edge node has a placement scope
(`edge.nodes[].hostgroups`) it is a validation error. Presence is stamped by agent tokens
only: an operator's `?node=X` previews X's document without making X look alive. Contract:
[kapkan.io/docs/authentication](https://kapkan.io/docs/authentication#binding-an-agent-token-to-its-node).

`token_env` and `tokens` are mutually exclusive; `token_env` is exactly a single operator
token. Every `/api/v1` request must carry `Authorization: Bearer <token>`; the presented
token is matched constant-time against every configured secret (an empty/unset env var
never matches — fail closed). Give every token its own secret: one that matches tokens of
different role, tenant or node binding is refused with `401` (logged as `ambiguous API
token`) rather than resolved to either. A read with a viewer token works; a mutation with a
viewer token returns `403`; an unknown token returns `401`.
Tokens are read from the environment per request, so rotating a secret or changing the set
takes effect on reload without a restart. The dashboard prompts for a token and keeps it in
`sessionStorage`. `/metrics` and the static UI shell stay open (the data behind the UI does
not). POST endpoints also require the JSON content type, which — together with the token
living in a header — blocks cross-site request forgery.

## Multi-tenancy

One kapkan instance can serve many customers (an MSP/IDC use case) and give each a token
that sees and touches **only their own** attacks, bans and hosts — and, on an edge brain,
zones. A tenant is just an optional label on a hostgroup, or on a zone (`zones[].tenant` in
the [zones file](https://kapkan.io/docs/zones): a customer may own hostnames and no
prefixes) — no new top-level object:

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
is untouched. "Which tenant owns this zone" is the zone's own label in the live zones file —
never inherited from the hostgroup that places it; a zone whose `tenant` contradicts the
hostgroup it names (`global` excepted) fails the reload and the previous zones stay live. A
token's optional `tenant` scopes it — a tenant no hostgroup or zone uses is rejected at load —
and an unscoped token is an admin that sees everything (the default, fully back-compatible).
Enforcement is **default-deny for scoped tokens** at a single choke point:

- **Reads** (`/status`, `/attacks`, `/hosts`, `/bans`) return only rows whose owning group
  carries the caller's tenant; `/audit` returns only its own tenant's actions, and
  `/traffic` refuses an out-of-tenant host. `/status` is rebuilt per scope — a tenant never
  learns another's prefixes, thresholds or BGP posture. Unlabeled groups are admin-only.
- **Mutations**: a scoped operator may `ban`/`unban`, and block a source for a victim, only
  within its own prefixes; an out-of-tenant target returns a uniform `403` whether or not a
  ban exists (no cross-tenant probing). `config/reload` is admin-only (it rewrites every
  tenant's policy and the token set itself).
- **Edge zones**: a scoped token's `GET /api/v1/edge/zones/status` holds only its own zones —
  no other tenant's hostname in any row, would-be set or HTTP/3 list — it reads only their
  history and telling sources, and a scoped operator pulls the lever only on them. **No
  existence oracle**: a zone it does not own — another tenant's, unlabelled, or gone from the
  file — answers exactly as a nonexistent one (the lever's `404 unknown zone`, decided before
  the body is read; the history reads' one uniform `403`). The operator still sees it: each
  refusal counts in `kapkan_api_zone_refused_total` and is logged once a minute per token,
  with no audit row. A tenant may see the names of the nodes its zones are served on; the
  zones document, node reports, ACME coordination, both node inventories, the per-node
  history filter and the fleet's events stay unscoped.
- A bearer that matches tokens of **different** role, tenant or node binding (a reused
  secret) is refused with `401` — a misconfiguration never silently widens access.

`/metrics` is **not** tenant-scoped (it stays an admin/operator scrape surface), and neither
are notifications; the dashboard shell is shared but every data call it makes is filtered by
the pasted token. An `agent` token cannot carry a `tenant` at all: what narrows one is
topology — its `node` and that node's placement — never ownership. No tenant configured
anywhere = single-tenant behavior, unchanged.

## Metrics

Prometheus metrics under the `kapkan_` namespace, on `/metrics` — the brain's on `api.listen`,
an [edge node](#edge-nodes)'s on its own `status_listen` (only when that is set); a scrub node
exports none, its counters ride its report. Both endpoints are unauthenticated. One binary
registers every series, so the brain's and a node's `/metrics` each carry the other's
label-less ones at a constant `0` — the brain an `edge_h3_ready`, a node an
`engine_active_attacks`: read a family from the role that owns it. The families, with the full
table (labels, values and what to alert on) at
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
- **Fingerprint plane** — `fingerprint_events_total` (by `result`: `classified`, `blocked`,
  `would_block` in dry-run, `suppressed`, `block_error` — a rising `block_error` is the one
  worth an alert: blocks the source-block guards refused, a full JA4 budget among them, which
  also counts as `mitigate_source_blocks_rejected_total{reason="fp_budget_full"}`); the
  in-kernel copy sampler reports as
  `dataplane_observations_total{kind="fp_emitted"|"fp_throttled"|"fp_ring_full"}` — a sustained
  `fp_ring_full` means the reader cannot drain the ring.
- **Edge nodes** (each node's own `/metrics`) — `edge_decisions_total` (by zone and result;
  `would_deny` / `would_challenge` are a dry run's evidence), `edge_challenge_active` (a
  zone-wide challenge in force), `edge_clearance_total` (the challenge page's outcomes),
  `edge_verdict_table_entries`, `edge_requests_total` (by zone and protocol — the `h3` share),
  `edge_h3_ready`, `edge_log_records_total`, `edge_inflight_resets_total` (a steady rate means
  access-log datagrams are lost before they reach the node), `edge_acme_attempts_total`, and
  `edge_cert_not_after_seconds` — **the certificate alarm**: alert when a zone's expiry is under
  30 days away. The `zone` label is bounded by the zones document: a name it does not have never
  opens a series. A node exports no `build_info`; its version is in its report on
  `GET /api/v1/edge/nodes`.
- **Token refusals and edge history** (the brain) — `edge_history_dropped_total` (by `reason`:
  report parts the [edge history](#storage-optional) skipped, counted while storage is on),
  `api_node_binding_refused_total` (an `agent` token bound to one node naming another) and
  `api_zone_refused_total` (a tenant-scoped token naming a zone outside its tenant), both by
  `route` — a rising count is a misconfigured or leaked token, which the brain's log names once
  a minute.
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
dependency; the only external dependency is the ClickHouse server itself, **21.4 or newer**
(the `clickhouse-server` package Debian and Ubuntu ship is 18.16 from 2018 and does not
work — install from clickhouse.com; an older server is named in one `ERROR` line at start).
On start it creates six MergeTree tables (idempotently): `attack_events` (every start/end with type,
direction, rates, sample top-sources, top-ASNs when GeoIP is enabled, ban state),
`traffic` (periodic per-host rate and baseline snapshots), `audit_events` (who did
what, with which role and tenant, to which target, and how it turned out — served back on
`/api/v1/audit`), and the edge history — `edge_windows` (one row per edge node, zone and
closed ten-second window), `edge_sources` (only the telling sources of each window: denied,
challenged, would-deny, would-challenge) and `edge_events` (the transitions the brain saw).
All six carry a `ttl_days` TTL so retention is bounded without operator intervention.

The edge history is written from the nodes' advisory reports, so every row is a node's claim —
the brain sums it and never acts on it. It has no tenant column (ownership is read from the live
zones file at query time, so relabelling a zone leaves no stale rows), and `edge_sources` keeps
at most 20 sources per node, zone and window, never an ordinary visitor. It is read back on
`GET /api/v1/edge/history` and `…/edge/history/sources` (a tenant-scoped token sees its own
zones only) and `GET /api/v1/edge/events` (unscoped tokens only); report parts it cannot use are
counted in `edge_history_dropped_total{reason}`. Contract:
[kapkan.io/docs/storage](https://kapkan.io/docs/storage#edge-history).

One ClickHouse credential (`username_env` / `password_env`) both writes and reads. It needs
`CREATE` on the first start, and again on the first start of a release that adds tables —
1.8.0 added the three `edge_*` — and `INSERT` and `SELECT` in between: the history reads behind
`/api/v1/traffic`, `/api/v1/audit`, `/api/v1/edge/history`, `…/edge/history/sources` and
`/api/v1/edge/events` run under it and answer `502` without `SELECT`. A release that adds columns needs `ALTER` once. Schema
init attempts every statement, so an upgrade under a credential without `CREATE` keeps the
three core tables writing but gets no edge history until one start runs with `CREATE` rights
(or the tables are created by hand); the refusals it logs on every start are harmless once the
tables exist.

Persistence is **best-effort and never blocks detection**: rows go onto a bounded queue
(`queue_size`) with a non-blocking send and are flushed in batches (`batch_size` /
`flush_interval_seconds`); a clean stop flushes what is already queued. Rows ClickHouse cannot
take are lost, never held — a server that is **down** refuses each insert at once and counts it
under `storage_rows_total{result="error"}`; one that **stalls** (holds the connection, or sits
behind a network that drops packets) makes each batch wait out its send timeout, also counted
as `error`, while the rows behind it fill the queue and, once it is full, count
`result="dropped"` — and the engine keeps running either way. The `storage` block is read at start: a reload that changes it
is refused. Without the block, kapkan runs entirely in-process on live data.

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
2. **No permanent bans.** Every ban carries a TTL. Each detection window that still sees the attack refreshes it — never past one fresh TTL from now — so a sustained flood stays mitigated; once the attack ends the ban comes down, and one nothing refreshes any more (a lost end event, a manual ban) lapses within one TTL. No code path produces a route without an expiry, and a data-plane rule carries its deadline into the kernel, where it lapses even with kapkan gone.
3. **Unban hysteresis.** A ban is withdrawn only after traffic stays below threshold for `unban_hysteresis_seconds`, preventing announce/withdraw flapping.
4. **Hard ban cap.** Past `max_active_bans` simultaneous bans, new bans are refused and alerted — kapkan will never blackhole half your network.
5. **Whitelist is absolute.** Addresses in `protected_whitelist` are never announced, by detection or manual request — and a prefix-wide carpet mitigation that would cover a whitelisted address is refused outright rather than exempting one member.
6. **Scoped detection.** Only destinations inside `networks` are ever acted on; other traffic is counted in metrics but never triggers a ban.
7. **Bounded blast radius.** `ban.max_banned_fraction` caps the share of your own address space that may be blackholed simultaneously (per address family) and `ban.max_bans_per_window` caps the *rate* of new bans — the two failure modes a simple count cap cannot see: a poisoned baseline or a spoofed-source storm driving many individually-legal bans. Both are off by default; refusals are counted in `kapkan_mitigate_bans_rejected_total`.

Every mitigation method inherits these — the [data plane](#in-kernel-data-plane-xdp) plugs in
at the same point as a BGP announcement, so dry-run, whitelists, TTLs and the caps apply to an
in-kernel drop exactly as they do to a route, and a [scrub node](#managed-scrubbing-nodes)
never enforces a ban the brain holds in dry-run. Detail:
[kapkan.io/docs/safety](https://kapkan.io/docs/safety).

The seven govern **bans**. An [edge node](#edge-nodes)'s per-request answers — a `429`, a
`403`, the challenge page — are not bans, and none of the seven reach them, not even `dry_run`:
the brain's flag does not travel to a node or gate the zone lever. The edge role keeps rules of
its own, enforced in code and covered by tests the same way:

8. **Edge nodes watch before they bite.** `kapkan edge` reads `dry_run` from its own `edge.yaml`, absent = `true`: every deny and challenge is answered as an allow marked `would-deny:…` / `would-challenge:…` and counted, never enforced. A zone's `policy.dry_run` and its rung's `challenge_options.dry_run` (default `true`) only add to the node's — a zone can be more watch-only than its node, never less — and under any of the three the lever previews rather than bites.
9. **Edge nodes fail static, and open by default.** Every per-request decision is made on the node; none waits on the brain. With the brain down a node keeps serving its last document and certificates from disk, reboots into service without it, keeps renewing, and clears challenged visitors on a key of its own once the brain's lapse — the rung never becomes a wall. A decision service or clearance page that is down follows the zone's `failure_mode` — `open` by default, so the request passes undecided (`closed` answers `503`) — and a decider whose tables are full passes the request rather than guess.
10. **No reload without a passing test.** Every configuration generation an edge node renders must pass the terminator's own test (`nginx -t`) before kapkan reloads into it. A failing candidate is never installed: the previous generation keeps serving, `/healthz` stays `200` with `converged: false`, and the node retries on its own; a generation a crashed process left untested is tested again before anything trusts it. Rate, rung and lever changes never reload the terminator at all.
11. **Edge verdicts and overrides end on time.** Every deny, challenge and mark in a node's verdict table expires on its own, and the zone lever lasts 60 s to 24 h and lapses at its `until` on every node, brain or no brain — it lives in the brain's memory, so a brain restart ends it early.

## Install

Every release ships prebuilt and signed for `linux/amd64` and `linux/arm64` — no
build toolchain needed. The simplest path is a native package:

```sh
VER=v1.8.0
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
VER=v1.8.0   # the release you want
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
sudo groupadd --system kapkan
sudo useradd --system --gid kapkan --no-create-home --home-dir /var/lib/kapkan --shell /usr/sbin/nologin kapkan
sudo install -d -o kapkan -g kapkan /etc/kapkan
sudo install -m 0640 -o kapkan -g kapkan deploy/config.example.yaml /etc/kapkan/config.yaml
echo "KAPKAN_API_TOKEN=$(openssl rand -hex 32)" | sudo install -m 0600 /dev/stdin /etc/kapkan/kapkan.env   # inert until api.token_env names it
sudo install -m 0644 deploy/kapkan.service /etc/systemd/system/kapkan.service
sudo systemctl daemon-reload && sudo systemctl enable --now kapkan
sudo systemctl reload kapkan   # SIGHUP: hot-reload config
```

The unit is hardened for BGP-only boxes and deliberately does not grant what the XDP data
plane needs: on a host with a `dataplane` block, also install the shipped drop-in, or the
daemon refuses to start and names the cause —
`sudo install -D -m 0644 deploy/kapkan-dataplane.conf /etc/systemd/system/kapkan.service.d/10-dataplane.conf`
(packages keep it at `/usr/share/kapkan/kapkan-dataplane.conf`), then
`sudo systemctl daemon-reload && sudo systemctl restart kapkan`. See
[kapkan.io/docs/dataplane-install](https://kapkan.io/docs/dataplane-install).

An [edge node](#edge-nodes) runs the same binary as `kapkan edge`, under its own unit:
`kapkan-edge.service` (root, `/etc/kapkan/edge.yaml`, the agent token in
`/etc/kapkan/edge.env`, and its own `/var/lib/kapkan-edge` and `/run/kapkan-edge`, so a brain
and an edge can share a host) — [kapkan.io/docs/edge-install](https://kapkan.io/docs/edge-install).

## Upgrading

`deploy/update.sh` (`/usr/share/kapkan/update.sh` from a `.deb`/`.rpm`) performs a safe,
signed upgrade on the host; it needs `cosign` installed:

```sh
sudo deploy/update.sh v1.8.0   # or: sudo deploy/update.sh   (latest stable)
```

It verifies the download (cosign signature over `checksums.txt`, then the
SHA-256), **preflights the new binary against the live config as the `kapkan`
user** (so schema drift or a file the daemon can't read stops the upgrade *before*
any swap — the running daemon is left untouched; a secret the config names but
`kapkan.env` lacks is only a warning, since `-check-config` never reads secret
values), snapshots the config, swaps the binary atomically (keeping the previous
one at `…/kapkan.old`), restarts, and **rolls back both the binary and the config
if `/healthz` does not report ready** within the deadline.

Active mitigation survives the restart: BGP Graceful Restart has the peer retain
kapkan's routes across the gap, and persisted bans are re-announced on startup
before End-of-RIB (set `ban.state_file`), so there is no need to wait for zero
active bans. The `/healthz` endpoint (unauthenticated, `503` until fully started)
is the readiness signal; the unit's `StartLimit*` turns a bad binary into a
`failed` state the script can detect rather than a restart loop.

`update.sh` upgrades the brain only: it preflights `/etc/kapkan/config.yaml` and restarts
`kapkan.service` (as a package upgrade does) — it never checks `edge.yaml` or restarts
`kapkan-edge`. It does replace `/usr/local/bin/kapkan`, which `kapkan-edge.service` runs too:
on a host with both roles, run `kapkan edge -check` and `systemctl restart kapkan-edge` right
after it, or the edge picks up the unchecked binary at its next start. On a scrub or
[edge node](#edge-nodes), swap the binary yourself and restart the role; on an edge node run
`kapkan edge -check` with the new binary first, then `systemctl restart kapkan-edge`. Upgrade the nodes before relying on a feature they enforce —
the brain's edge inventory (`GET /api/v1/edge/nodes`) shows each node's version. While the
brain restarts, edge nodes keep serving their cached document, but two things live only in
its memory: an operator's [challenge lever](https://kapkan.io/docs/edge#the-lever) on a zone
(pull it again), and — unless `edge.state_file` persists them — the proof-of-work clearance
keys, whose loss makes every cleared visitor solve the puzzle again.

You can also check for a newer release at any time:

```sh
kapkan -version                                        # this binary's version (a running daemon's: /api/v1/status)
kapkan -check-update -config /etc/kapkan/config.yaml   # 10 = newer release exists, 0 = up to date, 1 = error
```

## Development

Building needs **Go 1.26.10 or newer** — the `go` line of [`engine/go.mod`](engine/go.mod),
raised with each security release; with the default `GOTOOLCHAIN=auto`, an older Go 1.26
fetches it on the first build. From the repo root (the root Makefile delegates to `engine/`):

```sh
make build   # the single binary, with the console embedded
make test    # go test -race -count=1
make schema  # regenerate docs/config-schema.json and docs/zones-schema.json
make site    # build the static kapkan.io site (docs/ -> site/frontend)
```

Inside `engine/` there are a few more, including the ones that need a Linux kernel:

```sh
make -C engine lint                  # golangci-lint, run for GOOS=linux AND darwin
make -C engine bench                 # engine hot-path and edge decision-service benchmarks
make -C engine dataplane-test        # the XDP suite, in a privileged container
make -C engine blockrate             # replay the 18 attack captures end to end
make -C engine edge-terminator-test  # the edge renderer under real nginx/Angie (Docker)
```

Tests use synthetic NetFlow/sFlow datagrams built by `pkg/flowgen` (real wire format) and an
in-process GoBGP peer; no real routers are ever contacted. The end-to-end test in
`internal/app` replays an NTP-amplification flood over a real UDP socket against a dry-run
instance and asserts the attack and its (auto-expiring) virtual ban appear in the API. The
data-plane suites go further: they compile the detector's rules into real kernel maps and
replay captured attack frames through the program, so every published block rate is a
measurement rather than a claim. The edge renderer's suite does the same for nginx, on nginx
1.22, nginx stable and Angie: every fixture zone set is rendered and checked with `nginx -t`,
and the behavioural ones — a decider open or closed, `mode: none`, no certificate, the TLS
floor, HTTP/3, the challenge and the ACME path — are served live and driven with requests.

## Architecture

Paths below are relative to `engine/`:

```
cmd/kapkan/           main, flag parsing, signals; the dataplane, scrub, edge and
                      nginx-exporter commands
cmd/kapkan-validate/  the config and zones validators compiled to WASM, so the kapkan.io
                      config builder can show engine-exact errors in the browser
internal/app/         wiring of all components; end-to-end test
internal/config/      YAML load, validation, JSON schemas, SIGHUP hot-reload; the zones
                      file and the scrub/edge roles' own config files
internal/flow/        the normalized flow record: the hot path's contract
internal/ingest/      goflow2 library-mode ingestion -> normalized Flow
internal/engine/      sharded per-host counters, sliding window, thresholds and learned
                      baselines, carpet-bomb detection, attack classification
internal/mitigate/    embedded GoBGP: RTBH/FlowSpec/divert announce+withdraw, the
                      escalation ladder, scrub-node selection, source blocks, TTL,
                      caps, dry-run
internal/dataplane/   the XDP program and its maps: load, pin, attach, rule installs
internal/fpplane/     drains the data plane's handshake copies; a blocklisted JA4
                      becomes a source block
internal/fingerprint/ JA4 from a TLS ClientHello or QUIC Initial (pure Go)
internal/scrub/       the scrub-node agent behind `kapkan scrub` (rule long-poll)
internal/edge/        the `kapkan edge` role: zone-document poll, nginx/Angie renderer
                      and `nginx -t`-gated applier, decision service, log rollups,
                      per-node ACME, the clearance page
internal/exporter/    `kapkan nginx-exporter`: access-log rates -> the source-block API
internal/blockrate/   the eighteen attack captures behind every block-rate claim
internal/storage/     optional ClickHouse persistence (attack, traffic, audit and edge
                      history rows)
internal/geoip/       MaxMind ASN/country attribution of attack samples
internal/update/      the opt-in "is there a newer release" check
internal/notify/      Telegram, Slack, email, webhook and exec-hook notifications
internal/api/         REST API, embedded console, /metrics; the scrub and edge node
                      channels (zone document, reports, ACME slots, the lever)
internal/metrics/     the Prometheus collectors behind every /metrics
internal/buildinfo/   the link-time version behind -version and /api/v1/status
internal/logging/     the process-wide slog logger (json or text)
pkg/flowgen/          synthetic NetFlow/sFlow generator for tests and load
pkg/pktgen/           synthetic attack frames for the data-plane suite
```

Data flow: `ingest → engine (hot path) → [mitigate, notify, api]`, where `mitigate`
either announces through GoBGP or writes rules into `dataplane` — the same decision,
a different executor. Source blocks reach the same `mitigate` from two more inputs:
`fpplane` (a blocklisted JA4 from the data plane's handshake copies) and
`POST /api/v1/dataplane/sources` (e.g. `kapkan nginx-exporter`). The remote roles talk
to the brain only through `api`: `kapkan scrub` long-polls the rule table into its own
`dataplane`; `kapkan edge` long-polls the zone document, drives the local nginx/Angie
and answers its per-request decisions — nginx carries the traffic, kapkan never
forwards a byte.

## License

Apache 2.0.
