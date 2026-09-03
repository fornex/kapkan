# Kapkan Edge — orchestrated L7 termination (design spec)

Status: accepted design (2026-08-17), not yet scheduled code. This is the design record for
the **E track**: Kapkan as the protection layer of an operator-built HTTPS edge — certificates,
generated terminator config, per-request decisions, enforcement pushed down into the shipped
XDP data plane. It builds on the scrub-node role and its rules channel (see the
[scrubbing docs](https://kapkan.io/docs/scrubbing)), on the shipped `tls_client_hello` match
axis, and on the planned source-block API. The rationale behind every locked decision is in
the appendix.

---

## 0. TL;DR

Kapkan gains an **edge role**: a Linux box running nginx becomes a managed HTTPS front for a
set of zones — certificates auto-issued, config generated, per-request decisions made locally,
enforcement pushed down into the existing XDP data plane. The goal is the *technical* core of a
Cloudflare-style protection layer that an operator assembles into their own network (their
transit, their anycast, their PoPs); Kapkan supplies the protection loop, not the network.

Decisions, up front (locked 2026-08-17):

- **Kapkan orchestrates a foreign terminator. Kapkan never forwards client bytes.**
  Not an own Go proxy: a public-facing HTTP/TLS/QUIC stack is a permanent CVE liability of a
  different class than the opt-in, kernel-sandboxed, fail-open XDP program, and HTTP/3 done
  right (Retry, address validation, CID routing, 0-RTT policy) is a multi-year project by
  itself. Kapkan's value is the loop *measure per-source → decide with guarantees → enforce at
  the cheapest layer*, not moving bytes.
- **Terminator target: nginx-compatible config; Angie is the recommended build** (config-file
  compatible, adds a status API and richer metrics). Kapkan generates the config and drives
  reloads; it does not require Angie-only features. Envoy/xDS was considered and declined for
  now: heavier runtime, alien to the hosting admins Kapkan targets, and it would pull
  go-control-plane + protobuf service machinery into a 7-direct-dependency engine.
- **Keys: ACME per node — a private key never leaves the box that uses it, and the brain never
  sees it.** The brain coordinates *issuance* (ordering, rate-limit budget, challenge fan-out),
  never key material. Central issuance and keyless-style remote signing are recorded as
  rejected/deferred in the appendix.
- **The fast/slow split is the load-bearing wall.** Terminator config is rendered and reloaded
  only on *slow* changes (zones, certificates, origins). Everything at attack speed — source
  blocks, challenge mode, rate policies — flows through the decision service and the XDP data
  plane, and **never causes a terminator reload**.
- **Fingerprints are taken off-path** (the E2 fingerprint plane), so the terminator choice does
  not need to support JA4/JA3 and a stock nginx package is sufficient.
- **Third role, same binary.** `kapkan edge` joins `kapkan` and `kapkan scrub`. It reuses the
  scrub node's channel (ETag long-poll, `agent` token role, poll-is-liveness) for a second
  document family; it does not get a new transport.

### 0.1 The edge charter

The data-plane charter (*executes decisions made elsewhere; never classifies; default PASS*)
cannot stretch to L7 — a TLS terminator classifies by definition and cannot "pass by default"
what it must first decrypt. The edge plane gets its own charter, and every E-track PR is held
against it:

> **The edge plane measures requests and decides within operator-written policy; enforcement is
> always pushed to the cheapest layer that can express it; per-request decisions are always
> local to the node; the brain distributes policy, never verdicts; and Kapkan never forwards
> client bytes.**

Two corollaries worth spelling out:

1. **No verdict RPC to the brain, ever.** A per-request round trip to the brain turns the
   long-poll channel into a latency bomb and the brain into a single point of failure for
   serving traffic. The brain ships policy documents; the node answers requests alone.
2. **The BPF charter is untouched.** The XDP program still executes decisions made elsewhere —
   "elsewhere" now includes the local `kapkan edge` userspace, exactly as it includes the
   integrated mitigator today. No classification moves into the kernel.

---

## 1. The five-layer picture

Each layer is an order of magnitude more expensive per packet/request than the one above it.
The edge plane's job is to *measure* at layers 4–5 and *push enforcement up* this table:

| # | Layer | Mechanism | Vector it absorbs | Status |
|---|---|---|---|---|
| 1 | Network | BGP/anycast, RTBH, FlowSpec, divert | volumetric floods | shipped |
| 2 | XDP | SYN drop/ratelimit, `tls_client_hello` matching, per-source buckets, allowlist; QUIC Initial (E1), fingerprint blocks (E2) | handshake floods, identified sources | shipped / E1–E2 |
| 3 | Kernel/socket | syncookies (its own design round), backlog, accept-queue sizing | spoofed SYN under the terminator | config + a pending design round |
| 4 | Terminator/L7 | per-{source, zone} rps + concurrency, slowloris timeouts, h2 stream caps | request floods that completed a handshake | **E3–E4** |
| 5 | Challenge | PoW/JS + signed clearance cookie | residential-proxy botnets with real TCP stacks | **E4** |

The hard limit from the data-plane design still holds one level up: an edge node whose uplink
is saturated is not helped by any of this — layers 1–2 (and the operator's network design) are
what keep layers 4–5 reachable.

---

## 2. Architecture

### 2.1 Edge node anatomy

```
┌─────────────────────────────── edge box ────────────────────────────────┐
│  nginx / Angie (systemd unit, operator-installed package)               │
│   · terminates TLS (:443), later h3 — serves zones from rendered conf   │
│   · auth_request → unix socket (protected zones only)                   │
│   · access_log → syslog JSON → unix socket                              │
│                          │            │                                 │
│  kapkan edge (one process, third role of the same binary)               │
│   · policy agent   — long-polls zone doc + challenge doc from brain     │
│   · zone renderer  — templates → conf.d/kapkan_*.conf → nginx -t → HUP  │
│   · ACME manager   — x/crypto/acme, per-node keys, brain-granted slots  │
│   · decision svc   — unix socket; allow/deny/mark, later challenge      │
│   · log aggregator — per-source/per-zone rollups from the syslog stream │
│   · local XDP      — the SAME internal/dataplane manager, in-path       │
│   · reporter       — advisory rollups + health to the brain             │
└─────────────────────────────────────────────────────────────────────────┘
        ▲ GET /api/v1/edge/zones (ETag long-poll = liveness)
        │ POST /api/v1/edge/nodes/{name}/report (advisory, never liveness)
   kapkan brain — zones.yaml, issuance coordinator, detection over L7
   telemetry, ladder decisions, console, audit
```

The terminator is an operator-installed package with its own systemd unit. Kapkan owns files
under a dedicated include directory and drives `nginx -t` + reload; it does not supervise the
process (that is systemd's job) and does not ship nginx.

### 2.2 The fast/slow split (frozen contract)

| Change | Path | Terminator reload? |
|---|---|---|
| zone added/removed, origin changed, TLS policy, h3 toggle | zone doc → renderer | **yes** (validated, rate-limited) |
| certificate issued/renewed | ACME manager → renderer | yes (that is what reloads are for) |
| source blocked/unblocked | policy → local XDP installer | **never** |
| challenge mode on/off per zone | policy → decision service | **never** |
| rate policy tightened under attack | policy → decision service | **never** |
| fingerprint (JA4) block | E2 plane → XDP / decision service | **never** |

If a proposed feature needs a reload at attack speed, the feature is mis-designed — redesign it
onto the decision service or the data plane. This is the contract that keeps reload storms
structurally impossible rather than rate-limited into rarity.

### 2.3 Signals up, policy down

The channel is the one the scrub node already uses, with a second document family:

- **Down:** `GET /api/v1/edge/zones` — a versioned, ETag'd document (zones, per-zone policy,
  challenge keys, ACME challenge tokens in flight). Long-poll ≤30 s; **the poll is the liveness
  signal**, exactly like the scrub node's rules poll. Served to `agent`-role tokens.
- **Up:** `POST /api/v1/edge/nodes/{name}/report` — advisory rollups: per-zone rps, status
  mix, concurrency, top sources with rates, handshake rate, cert expiry, render/reload health.
  Reports are never liveness (the scrub-node rule, kept).
- **Detection:** the rollups feed the engine as a **second metric family** — unsampled,
  request-grade, from an authenticated component. sFlow/NetFlow physically cannot see requests;
  this is the input that makes L7 thresholds/baselines possible. It extends the detection
  engine (new counters, same ladder), it is not a plugin.
- **Enforcement:** brain-side decisions reuse the source-block machinery (the planned
  `POST /api/v1/dataplane/sources`: source-anchored rules with TTL, audited, dry-run-honoring).
  A local decision (node saw a source exceed local policy) installs through the same local
  installer with a TTL and appears in the next report — the brain audits it after the fact; it
  does not pre-approve it.

### 2.4 Failure modes

| Failure | Behavior |
|---|---|
| Brain dies / partition | Node keeps serving: last zone doc + certs are on disk, ACME renewals continue autonomously, challenge policy freezes as-is, XDP dynamic rules age out on in-kernel TTL. Fail-static, indefinitely. |
| nginx dies | systemd restarts it. Kapkan reports the gap (`/healthz` condition + report field); it never supervises or respawns the terminator itself. |
| Decision service dies / times out | Per-zone `failure_mode: open` (default — requests pass undecided, counted) or `closed` (503). Default is open: the edge analog of default-PASS. |
| Renders produce a broken config | `nginx -t` against the candidate file gates every reload; a failing candidate is never installed, the old config keeps serving, the failure is a report field + metric. Mirrors the validate-before-apply gate the config package already enforces (the same validator that ships as `cmd/kapkan-validate`). |
| Cert unrenewable (CA down, attack outlasts retries) | Serve the current cert until expiry; alarm from T−30 d (metric + console badge + notify). With a 90-day cert renewed from day 60, an attack must outlast ~30 days of retries before expiry is threatened. |
| Node dies | Brain sees the poll stop (stale_after, as with scrub nodes) and surfaces it. Traffic steering is the operator's network (anycast withdraw, DNS) in v1 — see "self-steering" in E6 candidates. |

---

## 3. Certificates (per-node ACME)

- **Client:** `golang.org/x/crypto/acme` in `kapkan edge` — small, control over ordering.
  Deliberately **not** Angie's built-in ACME module (would make Angie required rather than
  recommended) and not certmagic (dependency footprint).
- **Keys:** generated on the node, `0600` under `/var/lib/kapkan/edge/`, never in reports,
  never in any API response, redacted from support bundles. Compromise blast radius is one
  node — that asymmetry is *why* per-node was chosen.
- **HTTP-01 under a shared/anycast VIP:** the CA's validation request lands on *any* node, not
  necessarily the requester. The requesting node publishes `token → keyAuthorization` to the
  brain; the brain fans it out inside the zone doc; **every** node serves
  `/.well-known/acme-challenge/` from that shared table. Uses the existing channel, no new
  transport. (Multi-vantage validation makes "allowlist the CA" impossible by design — do not
  attempt it in XDP.)
- **Issuance coordination:** nodes request an issuance slot from the brain
  (per-zone mutex + staggering). This is what respects CA duplicate-certificate limits — with
  per-node certs, N nodes on one zone are N "duplicate" orders, and Let's Encrypt's duplicate
  limit caps a zone's fleet at roughly five first-time issuances a week. The design's answer:
  staggered initial rollout, renewal jitter, and a configurable fallback ACME directory per
  zone (ZeroSSL / Google Trust Services). The ceiling is documented, not hidden.
- **Wildcard = DNS-01 = a DNS-provider integration:** deferred, v1 issues explicit names only.
- **Session resumption across a multi-node PoP:** ticket keys must be shared or resumption
  breaks under anycast; single-node PoPs (v1) skip this. Rotating a shared ticket key via the
  channel is an E5 design item (short-lived keys make transit acceptable; key material still
  never includes certificate keys).

---

## 4. Zones (config UX)

Zones are **tenant data, not operator policy** — they change at a different cadence and by
different hands than `kapkan.yaml`. They live in a separate declarative file on the brain,
referenced as `edge.zones_file`, so the git-diffable config story survives:

```yaml
# zones.yaml — served to edge nodes as a versioned document
zones:
  - name: example.com
    origins: ["10.0.5.10:8443"]        # ACL'd to edge IPs; mTLS later
    tls:
      min_version: "1.2"
      h3: false                        # default off until E5
    acme:
      directory: ""                    # empty = default CA; per-zone fallback
    policy:
      failure_mode: open               # decision-service failure: open|closed
      challenge: off                   # off | manual | auto (E4)
      rate:                            # measured per source, per zone
        rps: 200
        concurrency: 100
```

- Validation follows the config-package discipline (wasm-safe, so the site's config builder
  validates the same bytes): JSON schema + overlay + the config-builder wizard + documentation
  in all five locales — **that schema/docs wave is the long pole of E3**, as it was for the
  data plane.
- Rendering: templates embedded in the binary → `kapkan_*.conf` files. One documented escape
  hatch (`extra_directives_file`, included verbatim, "you own what it breaks"); no template
  override mechanism — that way lies unsupportable config drift.
  *Decided in E3.2 (`internal/edge/render`, `internal/edge/apply`):* the node keeps rendered
  generations under `/var/lib/kapkan/edge/conf/gen-N/` behind a `live` symlink, and the
  operator's `nginx.conf` includes that once — `include /var/lib/kapkan/edge/conf/live/*.conf;`
  inside `http{}`. An install is: write the generation whole, retarget `live`, `nginx -t`, then
  reload — or, on a failed test, retarget back and keep the candidate as `failed-N` for reading.
  A generation records what it earned (`.kapkan-tested`, `.kapkan-reloaded`), so a process that
  died between swap and test cannot leave an untested generation trusted (`Recover` at startup
  tests it) and a failed reload is retried on the next poll. A render whose bytes equal the live
  generation's is skipped (no test, no reload), installs are paced ≥1 s apart counted from the
  last attempt, and the directory is flock'ed across processes. **`policy.rate` is not rendered
  at all** — it is the decision service's to enforce (§2.2), so a rate change never touches the
  terminator. Fail-open is `auth_request` with the failure absorbed inside the subrequest
  (`error_page 5xx =200 /_kapkan/undecided`, so the main request keeps its keepalive and a mark
  is believed only from a real 200); closed answers 503; every allowed request ends in
  `@kapkan_pass` via `try_files`, so there is one origin path, and kapkan owns `X-Kapkan-Zone` /
  `X-Kapkan-Mark` towards the origin. The shared file adds a kapkan catch-all `default_server`
  on :80/:443 (444, `ssl_reject_handshake`) so an unknown Host or SNI is refused rather than served
  by whichever zone sorts first; its `ssl_protocols` is the node-wide floor (lowest
  `tls.min_version`), because **nginx before 1.29.2 applies the default server's protocols to
  every SNI** — per-zone floors hold on nginx ≥ 1.29.2 and Angie only, and the matrix asserts
  which. A zone without a certificate renders only its `:80` listener (ACME challenges via
  GET/HEAD, otherwise 503) — nothing is proxied over cleartext. Hostname origins are resolved once,
  at `nginx -t`; an unresolvable one fails the whole generation (prefer `ip:port`). nginx floor:
  1.22 (`listen … ssl http2`, which nginx ≥ 1.25.1 warns about). CI renders every fixture and runs
  it on nginx 1.22, nginx stable and Angie — `nginx -t` first, then live requests through the
  served render: fail-open with and without a decider, keepalive, WebSocket upgrade, catch-all,
  TLS floor, ACME.
- The brain serves zones to nodes as a versioned ETag'd doc; per-node scoping (which node
  serves which zones) is a fleet concern deferred to E6 with hostgroup-scoped agent tokens.

---

## 5. The decision service

- **Transport:** unix socket, `auth_request` on protected zones, keepalive. The budget is
  measured, not assumed: E3's acceptance includes a benched added-latency number (target:
  tens of µs local), and any public claim waits for that measurement.
- **v1 verdicts (E3):** `allow` / `deny` / `mark` (headers to origin so the origin can make
  its own call). No challenge yet. A denial surfaces as 403, or as 429 through an `error_page`
  mapping in the rendered config — `auth_request` itself honors only 2xx/401/403 from the
  subrequest, and the renderer owns that translation.
- **E4 adds:** `challenge` — redirect to a PoW/JS page served by the node, clearance = signed
  cookie (HMAC, key distributed in the zone doc, rotated; bound to zone + source prefix + TTL;
  a no-JS fallback path is required, accessibility is a review gate, and the cookie must not
  become a cross-zone tracking vector — bind and expire narrowly). Challenge enters the
  escalation ladder as a new rung between rate-limit and block, **dry-run mandatory**: a
  dry-run pass must show who *would* have been challenged before any zone turns it on.
- **Local loop:** the log stream gives per-source rps/status/concurrency; local policy
  thresholds produce local verdicts; sources that stay hostile get promoted to the XDP LRU
  (TTL'd, reported, audited). The expensive layers protect themselves by feeding the cheap one.

An honest positioning sentence that belongs in the docs when this ships: against real
browsers, Cloudflare's challenge works because of a data scale Kapkan will not have. The
challenge rung cuts off cheap bots; the rest is rate policy and origin headroom.

---

## 6. The fingerprint plane (E2 tie-in)

The data plane's parser already finds the ClientHello in the kernel (the `tls_client_hello`
match axis); E2 adds a bounded ring-buffer copy of TLS ClientHellos and QUIC Initials to
userspace, where JA4 + SNI are computed and policy comes back as per-source XDP entries or
decision-service inputs. QUIC Initial decryption is deterministic (keys derive from the DCID
via a published per-version constant) — impractical in eBPF, ~a hundred lines in Go, and
implemented for QUIC v1 in `internal/fingerprint` (its JA4s carry transport `q`). The kernel
copies, userspace classifies: both charters hold. Copy volume under flood is capped (sampled)
— the plane must never become its own DoS.

**A JA4 block is a source block on the CLAIMED source, and the trigger is spoofable.** The
ClientHello is recognised by a stateless fixed-offset match — there is no completed TCP
handshake behind it — so a single spoofed packet carrying a crafted ClientHello whose JA4 an
operator has blocklisted will source-block whatever address the packet claims. That is the
source-block model working as designed (it acts on the address on the wire), but with an
attacker-craftable trigger it means an operator's JA4 blocklist can be turned into a lever to
block a chosen third party's traffic toward the victim. Two consequences follow, and both are
load-bearing: a JA4 blocklist is "block this fingerprint's *claimed* sources", never "these
are bad hosts"; and the fingerprint plane's blocks draw from a **separate, smaller budget**
(half the source-anchor pool) so that such a flood can fill only its own reservation and can
never starve the operator/API source blocks that share the pool. Every fp block is still
TTL'd and dry-run-honouring, so a misfire ages out on its own.

---

## 7. Non-goals

| Not building | Why / what instead |
|---|---|
| CDN / cache | A different product (cache keys, purge, tiered). Nothing here precludes an operator putting a cache behind the edge. |
| Own WAF ruleset | Delegate: document ModSecurity/Coraza as operator add-ons via the escape hatch. Kapkan does availability, not request-content security. |
| Authoritative DNS | Integrate, don't build. v1 has no DNS dependency at all (no DNS-01). |
| Managed CAPTCHA (Turnstile-class) | Needs data scale Kapkan doesn't have. PoW/JS challenge only. |
| ML bot scoring | Same reason. Deterministic signals only: JA4, ASN, rate, path profile. |
| Keyless-style remote signing | Deferred; its own milestone if third-party-owned keys ever become a requirement. |
| Origin tunnel (Cloudflare-Tunnel-class) | A separate product; revisit on demand. v1 origin protection = ACL to edge IPs, mTLS later. |
| Forwarding client bytes through kapkan | **Never** — charter. |

---

## 8. Roadmap

The E track. E1/E2 are deliberately small and independently useful within weeks; E3 is the
headline and the long pole.

- **E1 — Protect your own proxy** *(the shipped `tls_client_hello` axis + the planned
  source-block API, plus two deltas)*: a `quic_initial` payload axis beside `tls_client_hello`
  (long header + Initial type + version at fixed offsets — same six-byte-peek spirit,
  fail-open), and an nginx log exporter — per-source rps and status mix, posted to the
  source-block API — **shipped as a supported component from the start**, so it becomes the
  edge role's embryo rather than a disposable example.
  *Acceptance:* a handshake flood (TLS and QUIC) against a stock nginx is shed in-kernel while
  legitimate handshakes complete; an nginx-reported source is blocked in XDP within ~1 s with
  TTL + audit.
- **E2 — Fingerprint plane, off-path.** Ring-buffer copies → JA4 + SNI in userspace → policy
  back into the per-source LRU. *Acceptance:* a JA4-keyed block policy takes effect with no
  terminator involvement; copy volume stays capped under flood.
- **E3 — Zones, ACME, orchestrated terminator** *(the headline, L)*: zone model + renderer +
  per-node ACME + challenge fan-out + issuance coordinator + decision service (allow/deny/mark)
  + log rollups + the schema/wizard/docs ×5 wave.
  *Acceptance:* a name is served end-to-end through a managed edge with an auto-issued cert;
  the origin answers only to edge IPs; kill the brain — the node serves and renews
  indefinitely; a broken zone edit never reaches a running nginx; the auth_request overhead is
  a measured, in-repo number.
- **E4 — L7 decisions + challenge**: the challenge rung, clearance cookies, dry-run-first,
  ladder integration, console "who would be challenged" view.
  *Acceptance:* an HTTP flood from residential proxies collapses to challenge-passers in
  enforce mode; the same run in dry-run shows the would-be set and touches nothing.
- **E5 — QUIC/HTTP3 in earnest**: per-zone h3 (default off), Retry under load, Initial-rate
  XDP caps, ticket-key rotation for multi-node PoPs, 0-RTT policy, the "kill QUIC" lever
  (drop UDP/443 → clients fall back to TCP — cheap and already expressible as a static rule),
  and an honest doc section on what nginx cannot do (CID-aware ECMP routing) with the
  supported topologies stated.
- **E6 — Fleet + product tail**: multi-tenant zones in console/API, per-node zone scoping via
  hostgroup-scoped agent tokens, analytics tables, deployment guide for operator-built
  anycast. **Candidate needing its own round:** self-steering — an edge node announcing zone
  VIPs via the already-embedded BGP stack and withdrawing on failed health, which is the piece
  that makes "build your own network" concrete. Do not start it casually; it is mitigation
  machinery pointed at service routing.

Dependency notes: E1/E2 need nothing from E3 and ship on the existing data plane. E3 blocks
E4; E5 rides on E3; E6 rides on everything. The SYN-proxy design round is orthogonal and
protects layer 3 of the table in §1.

---

## 9. Risks

1. **Reload storms** → the fast/slow split (§2.2) makes them structural non-events; renders are
   additionally rate-limited and `nginx -t`-gated.
2. **auth_request latency tax** → measured in E3's acceptance, per-zone opt-out
   (`policy: none`), unix socket + keepalive; if the tax can't be held to tens of µs, E4's
   design revisits before challenge ships.
3. **CA rate limits with per-node issuance** → issuance coordinator + documented ~5-node
   ceiling per zone per week on LE + per-zone fallback directory. Small fleets are fine;
   large multi-tenant fleets must plan CA accounts.
4. **Template drift across nginx versions** → pin a minimum nginx version; CI job renders every
   fixture zone set and runs `nginx -t` in containers for the supported matrix (nginx stable,
   Angie current).
5. **Scope creep toward a CDN/WAF** → the charter sentence + §7 table are the review contract,
   exactly as the data-plane charter is for `bpf/`.
6. **Key theft from a node** → per-node blast radius by design; runbook: revoke via ACME,
   reissue, rotate clearance keys; document that the brain holds nothing to steal.
7. **The second metric family bloats the engine** → L7 counters enter through the same
   hostgroup/threshold/baseline machinery, not a parallel engine; review holds that line.

---

## Appendix — decision record (2026-08-17)

**Shape: orchestrate over own-proxy.** An own terminator (stdlib TLS + net/http + quic-go) was
declined for CVE surface class, HTTP/3 engineering depth, and because the differentiated value
is the measure→decide→enforce loop, not byte movement. The chosen shape's cost is accepted
knowingly: no in-handshake fingerprinting (mitigated by the off-path E2 plane) and "one static
binary" becomes "a binary plus a packaged terminator" on edge boxes only.

**A "both via abstraction" option** (nginx *and* Envoy backends behind a renderer contract) was
declined: it doubles E3–E5 and the second backend rots untested.

**An L4-only edge** (SNI routing + XDP, no termination, origins keep their keys) was considered
attractive for a private fleet (~80 % of the protective value, no key custody) but does not
meet the stated goal (an HTTPS edge others can use), and its useful parts (E1/E2) ship anyway
as prerequisites.

**Keys: per-node ACME** over brain-issued distribution (would put private keys on the wire and
a key store + node identity + revocation story in scope) and over keyless remote signing
(maximum safety, maximum cost — deferred until third-party-owned keys are a real requirement).
The chosen cost — CA duplicate-limit ceilings and issuance coordination — is §3's subject.

**Terminator: nginx/Angie** over Envoy. Envoy's xDS (no reloads at all), native ext_authz and
tls_inspector fingerprints were acknowledged; the deciding factors were operator familiarity in
Kapkan's audience, runtime weight, and dependency footprint. Angie is *recommended* (metrics,
status API), never *required*; everything rendered must run on stock nginx.
