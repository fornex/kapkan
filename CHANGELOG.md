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
- **Added** `api.tokens[].node` (optional; `agent` tokens only): binds the token to exactly one
  `edge.nodes[]` or `scrubbing.nodes[]` entry, refused on every node-identified route when another
  node's name is presented. Absent by default: the token keeps acting as any node, named as
  unbound by `-check-config`, the daemon log and the edge inventory; making it required is a
  MAJOR-release item. One behaviour change rides with the release regardless of the key: node
  presence is now stamped only by `agent` tokens, so a node polling on an `operator` token shows as
  lost while it keeps serving — give it an agent token.
- **Added** `edge.nodes[].hostgroups` (optional) and, in the zones file, `zones[].hostgroup`
  (optional): the placement axis. A node serves a zone when the zone's hostgroup (`global` when it
  names none) is in the node's scope (`[global]` when it lists none). Absent everywhere, every node
  serves every zone and the documents are byte-identical to before. Scoping any node requires
  every `agent` token to carry `node`; a `zones[].hostgroup` that is not a hostgroup fails the
  reload (the previous zones stay live).

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
  re-renders (and wakes the ACME manager, so a new zone is issued at once). The slow path is
  serialised and reads its inputs inside the serialisation. The node keeps two ETags: the
  ACCEPTED document (fast path) and the RENDERED one (what the terminator serves) — a document
  the renderer or `nginx -t` refuses leaves the previous generation serving, is reported as such
  (`zones_etag` names the rendered document), and is retried locally on a 1 → 10 min backoff
  until it applies or a newer one arrives; the poll parks on it meanwhile, so the brain sees the
  node alive. `/healthz` is 200 while a tested generation of ours is live (and, with
  `terminator.pid_file` set, the terminator process is alive), with `converged` and the error in
  the body; a refused document does not take a fleet out of its load balancer. It self-reports
  every 10 s (version, dry-run, rendered ETag, terminator kind, version and liveness, generation
  and test result, certificates — cut to the 64 KiB limit with a `certs_truncated` count), and
  serves `/healthz` + `/metrics` on `status_listen` when set. A component that fails to start
  ends the process with its error (systemd restarts it). `internal/edge/poll` is the long-poll
  generalised over the document. `-check` validates `edge.yaml` and what it names on the box
  (socket group, EAB key shape; the terminator binary and secrets as warnings). The role owns
  `/var/lib/kapkan-edge` and `/run/kapkan-edge` (never the brain's directories). Ships
  `deploy/edge.example.yaml` and `deploy/kapkan-edge.service`.
- Edge track, E3.6 — the zones file's JSON schema (`docs/zones-schema.json`, generated by
  `kapkan -dump-zones-schema` / `make -C engine schema` from `zones.go` and pinned by a drift gate
  like the configuration schema; the zone vocabulary's enums and bounds ride along), the
  WebAssembly validator's `kapkanValidateZones()` beside `kapkanValidateConfig()`, and the
  documentation: new pages *Edge nodes*, *Install an edge node* and *Zones reference*, the
  `kapkan edge` section of the CLI reference with every `edge.yaml` key, the brain's `edge` block
  in the configuration reference, *The edge channel* in the API reference, the `kapkan_edge_*`
  series in the metrics reference, a README row — in all five languages.
- Edge track, E3.7 — the E3 acceptance rig `engine/scripts/labnet/edge-e3.sh`: one privileged
  container, a netns per role (brain, edge with stock nginx, origin, Pebble as a real ACME CA
  validating HTTP-01 on the edge's `:80`, a legit client, an attacker), proving issuance through
  the brain's slot and fan-out, dry-run marks then live `429`s, the fast path without a reload,
  the slow path with one, a broken edit that never goes live, kill-brain with a restart from disk
  and a `304` re-sync, rollup promotion to a deny, and the decision's latency. It caught two
  traps, both fixed: a `live` directory created by hand (the install guide's own first draft
  said to) wedged every install with *file exists* — the applier now removes an empty one and
  refuses a populated one by name; and a fresh node's first certificate order was placed before
  the first generation was live, failing its validation and backing off for an hour — the node
  now wakes the ACME manager only after a document is rendered and live, and two seconds after
  a reload (the old workers, which know nothing of a new zone, keep answering for a moment), and
  the manager only ever sees the zones the live generation serves. A third, against the
  real CA: Pebble answers finalize with *processing* and no `Location` header, which leaves
  `x/crypto/acme` polling an empty URL — the manager now polls the order URL it already knows
  and fetches the certificate itself, and finalises where the ready order says to.
- Edge track, E4.1 — the proof-of-work rung's primitives and keys (edge-spec §5; code word
  *clearance*, since the node's ACME machinery already owns "challenge"). A new leaf package
  `internal/edge/clearance` holds the clearance token (`v1.<key>.<kind>.<exp>.<mac>`: an HMAC
  over zone, source key, kind and expiry — not a session, useless on another zone or from
  another source), the stateless hashcash puzzle (its nonce is an HMAC over zone, source key,
  return path and a two-minute bucket — accepted one bucket either side, so fleet clocks may
  differ by seconds — so a node remembers nothing about a challenged client and the answer page
  can only send a client back where the terminator said it came from) and HKDF derivation of
  per-zone keys from one fleet master. The zone document gains `zones[].clearance_keys` (the
  current and the previous UTC-day epoch, each honoured 48 h) and the document's vocabulary
  reserves `manual` and `auto` for `policy.challenge` (the zones file still accepts only `off`
  until E4.2 can act on them); the brain rotates the master at UTC midnight, derives every
  zone's key from it (deterministic, so the ETag moves exactly at the boundary and a parked poll
  wakes for it), and persists the masters to the new optional `edge.state_file` (0600, fsynced,
  written as soon as memory is ahead of the file — never only at midnight — and never over a
  file that does not carry its own kind tag, so a mistyped path cannot destroy the zones file,
  the ban state or a node's cache) so a restart does not re-key the fleet; to re-key deliberately,
  stop the brain, delete the file, start it. The document now carries secrets: a node caches it
  0600 already. No node-side behaviour changes yet — the decision service and the challenge
  page follow in E4.2–E4.4.
- Edge track, E4.2 — the `challenge` verdict and the rendered machinery (edge-spec §5). The
  decision service now answers a third word: **401**, "clear the rung first", with
  `X-Kapkan-Reason: challenge:<why>` (`manual`, `zone:<reason>` while a zone is flipped,
  `table:<reason>` for a source under a challenge verdict). A zone with `policy.challenge:
  manual` challenges every request without a valid clearance; `auto` challenges nobody until the
  node's rollups (E4.4) or the brain (E4.6) name a source or flip the zone — the verdict table
  gained a third kind, deny > challenge > mark, and a challenge that is not in force leaves the
  mark beneath it visible. The clearance cookie `kapkan_clr` is the one client value the
  subrequest carries, alone, in `X-Kapkan-Clearance` — and only when it is shaped like a token
  (a map in the rendered config forwards anything else as nothing: a control byte in a cookie
  would otherwise make the subrequest malformed, a failed decision, and `failure_mode: open`
  would pass the request undecided). It is verified outside the decider's lock against the
  document's keys; every zone also holds a key of the node's own, last, so a zone the brain sent
  no keys for — or whose keys aged out with the brain gone — can still challenge and clear on
  that node instead of walling everyone out. A valid cookie passes with the mark `cleared` /
  `cleared:nojs`; the rate and concurrency ceilings apply to cleared and to challenged requests
  alike, so a flood without cookies is answered with 429s, not with a page per request. The rung
  has its own watch-only switch per zone, `policy.challenge_options.dry_run`, **default true**: a
  challenge is then a 200 marked `would-challenge:<why>`, as it is under the node's dry-run, so a
  zone shows who it would ask before it asks anyone; `challenge_options.exempt_paths` names path
  prefixes never challenged — the one place the edge reads a request path, for an exemption only,
  and it needs nginx's normalised path (`X-Kapkan-Path`, dot segments merged, forwarded only when
  free of control bytes — a decoded one would otherwise make the subrequest malformed) AND the raw
  target to agree, with no dot segment, path parameter, control byte or invalid UTF-8 in either
  and no escape surviving in the normalised form, so `/healthz/../admin`, `/healthz/..;/admin`,
  `/admin/..%2Fhealthz`, the double-encoded `/api/%252e%252e/admin` and the overlong
  `/api/%C0%AE%C0%AE/admin` are all challenged while `/api/items/café` and `/api/coupons/50%25-off`
  stay exempt under `/api/`; the zones file refuses an exempt prefix that no client's request
  could ever match (non-ASCII, spaces, braces, quotes, a path parameter, an escape). The zones
  file accepts the three words and the
  options (schema regenerated). The renderer emits the machinery for EVERY decide-mode zone —
  the cookie and path headers on the subrequest, `error_page 401 = @kapkan_clearance` to a
  named location that proxies the fourth socket (`edge-clearance.sock`, `upstream
  kapkan_clearance`) with the request's own URI and follows `failure_mode` when the page is down
  (nginx needs `recursive_error_pages on` for that second error_page, and it is there), and the
  public `/_kapkan/clearance/` prefix (GET/HEAD/POST, 4 KiB bodies, kapkan's headers plus the
  client's Content-Type and Accept-Language) — so the bytes are the same for `off`, `manual` and
  `auto` and switching the rung is never a reload; a test pins it. The rollup counts
  challenged, cleared and would-challenge per zone and source, and challenge pages do not count
  as origin errors;
  `kapkan_edge_decisions_total` gains `challenge`, `would_challenge`, `allow_cleared`;
  `kapkan_edge_challenge_active{zone}` says whether a zone-wide challenge is on. The node holds
  the fourth socket with a placeholder that answers 503 until E4.3 lands the page itself, so a
  zone switched to challenge on such a node degrades exactly as `failure_mode` says.
- Edge track, E4.3 — the clearance page and the clearance flow (edge-spec §5). The node now
  serves the proof-of-work rung's page itself on the fourth socket (`internal/edge/clearance/page`,
  `go:embed`): on a 401 from the decision service the terminator serves, in place of the origin, a
  **403** `Cache-Control: no-store` HTML page — the puzzle as a data block, one script and one
  stylesheet by content hash, a strict CSP, no images and no third parties — in the visitor's
  language (en/ru/de/fr/es from `Accept-Language`); a non-GET original gets the compact
  `{"error":"challenge_required"}` instead. The browser solves the hashcash in lanes — a few
  Workers started from the page's own script plus a time-sliced lane on the main thread, so a
  visible tab uses its fastest core and a background tab's timer throttling cannot stall the
  search — with its own SHA-256 (WebCrypto's per-call cost, not the hashing, was the bottleneck;
  checked against a known digest before use), asks for a fresh puzzle rather than post a solution
  that outlived the nonce's window, and posts the form to
  `/_kapkan/clearance/answer`, which checks the solution and answers `303` back to the request's
  own path with `Set-Cookie: kapkan_clr=…; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<ttl>`
  — host-only, so a sibling zone can never read it, and bound to zone and source key, so it is
  useless elsewhere. **No JavaScript** is a first-class path, not an afterthought: the page
  carries a timed ticket (redeemable four seconds to two minutes after issue) both as a
  `<noscript>` meta refresh and as a Continue button that stays in place unless the script hides it
  as its first act — JavaScript off, a blocked or broken script and an engine that fails the
  solver's self-check all leave it there, and it comes back beside a solve that runs long —
  and it earns the shorter five-minute `nojs` clearance. Every refusal a browser can meet is a page with the way
  forward — a too-early ticket retries itself, an expired one and a stale or wrong answer lead
  back to the page the visitor came from, the issuance cap says to wait a minute — and the compact
  JSON is kept for clients that post JSON. The page signs with the decision service's own keys
  (the document's newest live key, else the node's) and reads each zone's rung from it, so the
  two halves cannot disagree; clearances are capped at 6 per source and 6000 per zone a minute
  (`429` beyond). Two new zone knobs, `policy.challenge_options.difficulty` (12..22, default 18)
  and `cookie_ttl_seconds` (60..86400, default 1800), reach the document only when set (schema
  regenerated; the published schema admits 0 — the default — or the range, exactly as the
  validator does). `kapkan_edge_clearance_total{zone,result=page|page_json|issued|issued_nojs|
  invalid|rate_limited|unknown_zone|bad_request|error}` counts it. Accessibility as a review
  gate: semantic HTML, a status line announced once (the moving counter is not a live region), a
  non-timed alternative to every timer, both colour schemes at ≥13:1 text contrast, focus
  outlines, reduced-motion honoured.
- Edge track, E4.4 — the local ladder (edge-spec §5: the rung between the ceiling and the block).
  In a zone with `policy.challenge: auto` the rollup's flood rule now **challenges before it
  denies**: a source pushing through its rate ceiling for a window is sent to the rung for five
  minutes (a browser clears it and is rate-limited like anyone; a bot cannot), and a source that
  already had the rung's chance — flooding on while challenged (by name, or with the whole zone),
  having cleared the rung and flooding anyway, or remembered from an earlier promotion — is
  denied, with the doubling TTL as before. The **zone-wide trigger** for the flood no single
  source trips (residential proxies): `challenge_options.auto.zone_rps` (0 = off) flips the
  whole zone to challenge for `auto.hold_seconds` (30..3600, default 300) when the zone's
  **admitted** rate on the node — decided requests the node did not refuse — runs at or over it;
  each window still over extends the hold; the flip lapses on its own. Refused traffic is not
  load: a blocked bot's 403s, a lone flooder's 429s or a plain-HTTP flood never flip the zone or
  keep it flipped. Node-local by design (the fleet-wide view is the brain's). The rules take the
  per-zone rung settings from the document on every new one. Dry-run: the node's `dry_run`
  previews the whole ladder as `would-challenge` / `would-deny` marks; a zone's
  `challenge_options.dry_run` (the default) previews the rung only — the deny that follows a
  second flood window stays the ceiling's and is enforced as before, one window later than in an
  `off` zone because the rung's turn is taken first; under a zone-wide challenge — previewed or
  not — a flooder had the rung with everyone else and is denied at once. In the verdict table a
  deny drops the same source's challenge only when it outlives it — or when the table is full and
  the block needs the room, a challenge beneath a live deny being invisible anyway (a shorter block otherwise leaves the
  challenge beneath it, in force again when the block lapses), and challenges may fill at most half
  of the table, so a rotating botnet's challenges cannot crowd out the denies that must follow; a
  flooder whose challenge the quota refuses is denied instead. The zone-wide trigger measures the
  same admitted load in dry-run as enforcing (a would-deny preview is refused traffic too), so the
  preview shows the flips enforcement would make. Zones schema regenerated.

- Edge track, E4.7 — per-zone dry-run. A zone can now be watch-only on its own: `policy.dry_run:
  true` in the zones file makes the node count and mark that zone's decisions — a deny as an allow
  marked `would-deny:<reason>`, a challenge as `would-challenge:<why>` — and enforce none, while
  its sibling zones on the same node enforce as before. The node's own `dry_run` (edge.yaml) stays
  the floor: a zone can only be MORE watch-only than its node, never less, so the box owner's
  switch is never undone by a tenant's zones file. The rung's own `challenge_options.dry_run` is
  the third layer, for the rung alone. Travels in the document as `policy.dry_run` (omitted when
  false — a document written before E4.7 keeps its bytes and its ETag); zones schema regenerated.
  **Upgrade the nodes before relying on it**: a node older than this release does not know the key
  and enforces the zone under its own `dry_run` — the document is tolerant of unknown keys by
  contract, so the flag is silently absent there; `GET /api/v1/edge/nodes` shows each node's
  version. The per-zone flag in the node's report arrives with the per-zone rollups (E4.5).

- Edge track, E4.5 — signals up: the node's rollups in its report, and "who would be challenged".
  Each self-report now carries a **zones section**: for every decide-mode zone the live generation
  serves, the last closed ten-second window (`rps`, requests, decided, denied, challenged, cleared,
  `would_deny`, `would_challenge`, status classes), whether a zone-wide challenge is in force and
  why, whether the zone is watch-only on that node, and the window's sources — the would-be ones
  first, then the refused and challenged, then the busiest of the rest — with the strongest thing
  the node did to each (`denied` / `challenged` / `would-deny` / `would-challenge` / `cleared` /
  `marked` / `allow`), the zone's challenge mode, and whether a flip bites or previews there. A
  window older than two aggregator windows reads as a quiet zone. A report too big for the brain's
  limit sheds detail a little at a time — the sources that tell nothing first (uncounted: they are
  not in the would-be set), then every zone's list halved, then certificates, then zones — the
  would-be sources it loses counted, so the brain and the console say "partial", never "nobody".
  New **`GET
  /api/v1/edge/zones/status`** (viewer rank, unscoped tokens, like the inventory) merges the alive
  nodes' zones: sums per zone, the zone's mode, the nodes on which it is watch-only or under a
  zone-wide challenge (biting or previewing), how many nodes are alive, and the **would-be set** — the union of sources the nodes previewed a challenge or a deny for,
  with the nodes that saw each, the busiest first, bounded to 20 per node. That set is edge-spec
  §8's "who would have been challenged", for the console and the acceptance rig alike. The
  console gains an **Edge** view (shown when `edge.nodes[]` is configured; `/api/v1/status` now
  carries `edge_nodes_total`): the zones table with a challenge column (off / preview / active with
  its reasons) and a "Who would be challenged" panel, in all five languages. The aggregator's
  bounded view ranks the would-be sources first, then the refused and challenged ones, then the
  busiest of the rest, so a would-be source is never lost to a busier bystander, and counts the
  would-be ones its bound cut — a refused source the bound cut is not in the set and not a
  shortfall; the report carries `rung_dry_run` (the rung previews
  on this node: the node's, the zone's or the rung's own watch-only switch) beside `dry_run`, so
  the status (`rung_watch_only`) and the console tell an enforcing rung from a watching one by
  state, not by guessing from a window's counters; zone entries a node cut from its report reach
  the status as `zones_truncated` and the console says so; shedding the sources that tell nothing
  is not a cut of the would-be set and is not called partial. A marked source's origin errors
  count again (the mark had shadowed them, so the errors rule could not renew the mark it set),
  and a node forgets the kept windows of zones the document no longer has.

- Edge track, E4.6 — the operator's lever on a zone's rung. **`POST
  /api/v1/edge/zones/{name}/challenge`** `{"mode":"manual|auto|off","ttl_seconds":60..86400,"reason":"…"}`
  (operator rank, unscoped tokens) sets the zone's challenge mode for a bounded time, whatever
  the zones file says; **`DELETE`** — or `mode: off` — clears it. The override travels in the zones
  document as `challenge_override {mode, until, reason}` with a fixed `until`, so the document's
  bytes and ETag move exactly when an operator acts (and once more when it lapses); parked polls
  are woken at once and every node applies the effective mode on its fast path — a policy
  change, never a reload — reading the override per decision — the rules too, at each window's close — so it ends on time,
  brain or no brain, and a zone-wide flip made inert by its lapse is retired with it. The response says where the lever bites: the file's mode, the zone's watch-only flags
  (`policy.dry_run`, `challenge_options.dry_run`) and every configured node with its liveness and
  reported `dry_run` — a node that only counts must be seen before the lever is trusted. A zone
  in `mode: none` is refused (409); the reason is at most 200 characters. Audited (`edge_challenge` set / cleared); shown by
  `GET /api/v1/edge/zones/status` as `override`. The brain's own `dry_run` does not gate the lever:
  it is a policy edit; enforcement watch-only lives on the node and the zone. In memory, like the
  ACME coordinator — an incident's tool, re-pulled after a brain restart. A lever on a zone a
  reload has since removed can still be cleared. The node's report carries the mode it APPLIES
  — the lever's, while one is live — so `zones/status` and the console read a zone under a manual
  lever as challenging, not as the file's `off`. **Upgrade the nodes first**: a node older than
  this release does not know `challenge_override`, follows its file, and is still listed by the
  response as a node the lever would bite; `GET /api/v1/edge/nodes` shows each node's version.
- Edge track, E4.8 — the documentation of the rung, in all five languages. *Edge nodes* gains
  *The proof-of-work rung* — the ladder, the clearance page, the lever, the three watch-only
  layers and how to go live one layer at a time — with the failure table and the reading section
  that go with it; the install guide's check and go-live steps, the rung's troubleshooting rows
  and the fourth socket; the zones reference's `policy.dry_run`, `policy.challenge` and
  `challenge_options.*` keys, a full example, and the request table's challenge reasons and
  `cleared` marks; the API reference's `GET /api/v1/edge/zones/status` and the lever, the report's
  zones section and the document's `clearance_keys` and `challenge_override`; the new
  `kapkan_edge_decisions_total` results, `kapkan_edge_challenge_active` and
  `kapkan_edge_clearance_total` in the metrics reference; the console's Edge view on the
  dashboard page; `edge.state_file` and `socket_group` brought up to date.
- Edge track, E4.9 — the E4 acceptance rig `engine/scripts/labnet/edge-e4.sh`: the E3 rig's
  topology (brain, edge with stock nginx, origin, Pebble as a real ACME CA, clients) plus a
  `botnet` netns of 64 sources, a python browser that solves the hashcash and keeps its cookie, a
  no-JS client that follows the timed ticket, and a per-source flooder. Ten arms prove edge-spec
  §8 for E4 on real nginx: the rung's switches never reload; manual enforcement, the cookie's
  binding and expiry; the residential-proxy flood collapsing to challenge-passers (no bot reaches
  the origin after the zone-wide flip, the browser does, a plain client is challenged too); the
  same flood in dry-run touching nothing while the status names who would have been challenged
  and the node's dry-run flooring the zone's; the local ladder (429 → page → 403, a cleared
  flooder denied at once); the no-JS ticket; exempt paths and the JSON refusal for non-GET
  clients; the brain killed mid-challenge (cookies verify, new visitors clear, the node restarts
  from disk with its keys, the returned brain serves the same keys); the lever, audited, lapsing
  on time; and the challenge page's cost (within a tenth of a millisecond of a mode:none 200 at
  p50, every sample checked for its status). 108/108; the first run caught three rig bugs and its
  review ten more weaknesses of the rig, none in the product; the results are recorded in
  edge-spec §8.
- Edge track, E6.1 — an agent token belongs to one node (edge-spec §9 risk 6; milestone E6, fleet).
  `api.tokens[].node` binds an `agent` token to exactly one `edge.nodes[]` or `scrubbing.nodes[]`
  entry (a name present in both lists is refused as ambiguous; several tokens may bind one node for
  a gap-free rotation; `node` on a viewer or operator token is an error). The brain then refuses the
  token on every node-identified route — the zones and rules polls (`?node=`), both self-reports,
  the ACME slot and challenge publication — when another node's name is presented, **before** any
  side effect: no presence stamped, nothing stored, granted or published. The refusal is a uniform
  `403` that never names the bound node, a Warn once a minute per token, and
  `kapkan_api_node_binding_refused_total{route}`. A bound token polling without `?node=` is refused
  too. **Presence is now stamped only by agent tokens**: an operator's `?node=X` returns X's document
  as a preview and moves no liveness (behaviour change — a node configured with an operator token
  shows as lost while it keeps serving). An **unbound** agent token keeps working exactly as before,
  so a fleet migrates one node at a time, and is named in four places until it is bound:
  `kapkan -check-config` (WARNING), the daemon's log at start and on every reload, the edge
  inventory (`unbound_agent_tokens`, and per node `tokens` and `last_token` — the token that last
  polled as it), and the console (a later E6 change). Making an unbound agent token an error is
  scheduled for a MAJOR release; there is deliberately no switch to make it one today. The zones
  document is untouched: a fleet without bindings gets byte-identical documents and ETags, so the
  upgrade reloads nothing. Config surface: `api.tokens[].node` (schema, overlay, config builder).
- Edge track, E6.2 — a zone belongs to a tenant (milestone E6, fleet). `zones[].tenant` is an
  optional ownership label on the hostgroups' tenant axis — never inherited (not from
  kapkan.yaml's top-level `tenant`), never in the document the nodes render (a labelled zones
  file yields byte-identical bytes and ETag, so labelling a fleet's zones reloads nothing). The
  rule "a token's tenant is in use" now counts zones as well as hostgroups, so an **edge-only
  customer** — hostnames, no prefixes — can hold a scoped token; with an `edge` block that check
  runs when the daemon loads both files (`kapkan -check-config`, start, reload), since the
  browser-side validator sees only `kapkan.yaml`; a reload that would orphan a scoped token
  fails as a whole and keeps the previous zones. `GET /api/v1/edge/zones/status` now admits
  **tenant-scoped tokens** and shows them exactly their own zones — no other tenant's hostname in
  any row, would-be set or HTTP/3 list, no `tenant` field — and every zone of the zones file has
  a row (a `mode: none` or unreported zone with `nodes: 0`) carrying the file's `mode` and
  `file_challenge`, the alive nodes' `certs` for it and, for unscoped callers, its `tenant`. A
  scoped operator pulls the lever (`POST`/`DELETE /api/v1/edge/zones/{name}/challenge`) on its
  own zones only; any other zone — another tenant's, unlabelled, or gone from the file — is the
  byte-identical `404 unknown zone`, decided before the body is read, so the lever is no
  cross-tenant existence oracle. Node names stay visible to a tenant; the zones document, both
  reports, the ACME coordination, both inventories and `config/reload` stay unscoped.
  `edge_challenge` joins `GET /api/v1/audit?action=`. Each refusal counts in
  `kapkan_api_zone_refused_total{route}` and is logged once a minute per token — the caller learns
  nothing more, the operator sees a leaked scoped token walking hostnames. Every zone of the file
  that turns h3 on shows `h3.enabled`, with `serving`/`unsupported` from the alive nodes'
  `terminator.h3` — a `mode: none` zone included — and the document sums the nodes'
  `certs_truncated` beside `zones_truncated`. The shipped console renders a zone no alive node
  reports yet with `nodes: 0` and no challenge; the Edge view's cells for those rows are a later E6
  change. Config surface: `zones[].tenant` (zones schema), `api.tokens.tenant` overlay entry marked
  server-verified.
- Edge track, E6.4 — the edge history's storage (milestone E6, analytics). Three ClickHouse
  tables beside the three the brain always had: `edge_windows` (one row per edge node, zone and
  closed ten-second window — the report's counters, response statuses, HTTP/3 requests and the
  rung's state; `ts` is the node's clock as the brain accepted it, `received_at` the brain's; no
  `rps` column — it is `sum(requests)/sum(window_seconds)` — and no tenant column: ownership is
  read from the live zones file), `edge_sources` (only the **telling** sources — denied,
  challenged, would-deny, would-challenge — at most 20 per node, zone and window; visitors are
  never stored) and `edge_events` (the transitions the brain saw). Flat MergeTree with the
  `ttl_days` TTL and `LowCardinality(String)` (never an Enum), created **after** the core tables
  and each logged on its own, so a writer credential from before this release keeps the tables it
  had; the column upgrades are one table-keyed list now. The writer grows
  `WriteEdgeWindows/Sources/Event`, the querier `QueryEdgeHistory/Sources/Events` (`param_*`
  bindings, `readonly=2`, time and row caps, 64-bit integers unquoted). A real-ClickHouse suite
  (`KAPKAN_CLICKHOUSE=require`) runs in CI on a pinned `clickhouse/clickhouse-server:25.8`:
  schema idempotent twice, a dropped column comes back, every table takes rows, a row already
  past `ttl_days` never lands (ClickHouse drops expired rows as the part is written) and
  `OPTIMIZE … FINAL` keeps it so, the read client's INSERT is refused as read-only, the three
  queries answer in shape — the time range applied to the windows, not to the buckets they fall
  into, and the strongest source state won by rank. Schema init now attempts every statement
  and reports the first failure instead of stopping at it, so a credential that may INSERT but
  not CREATE still gets the column upgrades and the new tables tried. No new configuration key:
  storage on means history on, `ttl_days` keeps it. The read API
  follows (E6.6).
- Edge track, E6.5 — the brain writes the edge history (milestone E6, analytics). Every accepted
  node report now becomes rows: one `edge_windows` row per node, zone and closed window for the
  zones the zones file has — a window the node re-sends is written once (six copies of one report
  are one row), one window per zone per report, a window with counters but no close time or for
  an unknown zone is skipped, a quiet zone (no close time, nothing counted) is nothing to write —
  and `edge_sources` rows for its telling sources (denied, challenged, would-deny,
  would-challenge; parsed as an address; at most 20 per window). `ts` is the node's window close
  when it is within ten minutes behind or a minute ahead of the brain's clock; otherwise the
  brain's clock is written and one `clock_skew` event marks the transition (and one the
  recovery); `received_at` is always the brain's. What changed between a node's two reports
  becomes `edge_events` — `version`, `dry_run`, `document_rendered`, `generation_installed`,
  `generation_refused`, `terminator_alive`, `h3_state`, `cert_issued`/`cert_renewed`/`cert_gone`,
  `challenge_started`/`challenge_ended`, `report_truncated` — each once per change, the
  certificate and challenge kinds only for zones the file has, and nothing read as "gone" from a
  report that had to shed its tail; the first report after a brain start is a silent baseline
  (`clock_skew` excepted — it is about the clock, not a transition). A presence ticker (period
  `min(stale_after/2, 5 s)`, never under a second) writes `node_alive`/`node_lost` on every
  transition — `node_lost` stamped at the last poll plus `stale_after`, a node baselined silently
  at its first poll after a start (no restart burst) — and logs the same at INFO whether or not
  storage is on: **a lost edge node now reaches the brain's log.** All of it is map work and
  non-blocking enqueues after the report is stored and before the `204`; the answer never waits
  for storage, a full queue drops and counts. Skipped parts count in
  `kapkan_edge_history_dropped_total{reason}` (`unknown_zone`, `no_at`, `duplicate`,
  `extra_window`, `bad_source`, `source_cap`), while storage is on. Two gates: no node-side
  package (`internal/edge`, `internal/mitigate`) imports `internal/storage` directly (the
  transitive path through the shared report types in `internal/api` is known), and the history's
  row types carry no key material (the report's rule, extended).
- Edge track, E6.6 — the edge history's read API (milestone E6, analytics). Three `viewer`-rank
  endpoints over the tables: `GET /api/v1/edge/history?zone=[&node=]&from&to&step` (a zone's
  windows summed into buckets — `nodes`, `window_seconds`, the counters, `status_2xx..5xx`,
  `h3_requests`; the client derives the rate and the HTTP/3 share), `GET
  /api/v1/edge/history/sources?zone=&from&to[&state=]` (the zone's telling sources over the
  range, the strongest state each, the busiest first, at most 1 001 — *who would have been
  challenged* over a period) and `GET /api/v1/edge/events?[node][zone][kind]&from&to` (the
  transitions, newest first, at most 1 001). The range and step rules are the traffic and audit
  endpoints' — RFC 3339, an hour by default, at most 31 days, at most 5 000 buckets — now shared
  in one place; storage off answers `{available:false}` like `/api/v1/traffic`, a failed query
  `502`. Scope: a tenant-scoped token reads its own zones (ownership from the live zones file) and
  gets one uniform `403` for any zone that is not its own — another tenant's, unlabelled, gone
  from the file or nonexistent — counted in `kapkan_api_zone_refused_total{route="edge_history"}`
  (while storage is on; with it off no zone is looked at); `node=` and `/edge/events` name nodes
  and stay unscoped. Zone names are folded like the file's; `step` is capped at a day, the
  query's own clamp, and `step_seconds` is the step the buckets were built with.
- Edge track, E6.3 — placing zones on nodes (milestone E6, fleet; edge-spec D8/D9). The
  placement axis is the hostgroup Kapkan already has for prefixes: `zones[].hostgroup` places a
  zone (`global` when absent), `edge.nodes[].hostgroups` is a node's scope (`[global]` when
  absent, with `global` a literal a node may list beside its PoP's group), and **a node serves a
  zone when the zone's group is in its scope**. Consequences: a label by itself is strict (it
  takes the zone off every node not listing the group — isolation and the CA's
  duplicate-certificate budget follow the placement by default); a fleet without scopes gets
  byte-identical documents and ETags; **each node now receives its own document** — exactly its
  zones with their issuance grants, fanned-out ACME challenges, clearance keys and levers, and its
  own ETag — while an operator's bare `GET` is still the whole file; a node asking for the slot
  of, or publishing a challenge for, a zone it does not serve gets the byte-identical `404
  unknown zone` of a nonexistent zone, so a stolen bound token issues only for its node's zones
  (edge-spec §9 risk 6 closed with that residual). Ownership and placement are two axes: a zone
  in a labelled hostgroup inherits nothing, and when both carry a tenant they must agree. Scoping
  any node requires every `agent` token to be bound. `GET /api/v1/edge/zones/status` carries each
  file zone's `placement {hostgroup, nodes, alive}` and `unserved`; a node's claims about a zone
  outside its scope are stored but neither merged nor written to the edge history
  (`kapkan_edge_history_dropped_total{reason="outside_scope"}`); `placement.hostgroup` is for
  unscoped tokens (a tenant sees node names, not the operator's grouping); the lever lists the
  zone's nodes; the inventory shows `hostgroups` and `zones_placed`; `kapkan -check-config`
  prints the node → scope → zones matrix with each token binding (or `SHARED`) and warns about a
  zone no node's scope covers, an edge block without nodes included. A node the configuration no
  longer has gets an empty document, and a poll of its parked in a hold across that reload is
  answered `404 unknown edge node` — never the whole file; likewise a token the reload removed
  or rebound ends its parked poll with `401` / `403`, on the edge channel and the scrub channel
  alike. The tenant-agreement rule applies to named hostgroups; the global group is the fleet's
  catch-all, not a tenant's PoP.
  Node side: no change — a zone leaving a node's document is an ordinary slow reload; its
  certificates stay on disk and stop renewing (runbook, not automation). Config surface: both
  schemas, the overlay, docs (zones, configuration, edge *Placing zones on nodes* + Limits,
  edge-install, api, authentication).
- Edge track, E6.7 (history half) — the operator console reads the edge history (milestone E6).
  Clicking a zone's row in the Edge view opens that zone's stored history under the table over
  **1 h / 24 h / 7 d** (`step` 60 / 600 / 3600): requests per second per bucket, "refused or would
  be" (denied + challenged + would-deny + would-challenge, titled **Would be refused** and tagged
  *preview* when the rung bites on no node, because nothing in that series can then be real), an
  HTTP/3 share line only where some bucket actually saw HTTP/3, and the period's totals — nodes
  seen, requests, refusals, 4xx/5xx and the bucket width the engine **actually applied**
  (`step_seconds`, which the brain may raise or cap, not the step asked for). Under it, **Who
  would have been challenged — over {period}** from `/edge/history/sources`, busiest first, with
  the live table's own state badges (now one shared lookup, so a source cannot read differently in
  the two tables, and `denied` / `challenged` — states a ten-second window never carries — have
  their own tones). For unscoped tokens a **Fleet events** card closes the view: the last 24 h of
  `/edge/events`, newest first, the sixteen kinds as a locale enum so a newer kapkan's
  seventeenth renders as its raw name instead of vanishing. Storage off (`available: false`)
  renders the Traffic view's labelled ghost, never an error; a `403` (a tenant on another
  tenant's zone, or on the events at all) hides the element rather than reporting a fault; a zone
  a reload has dropped from the zones file says so instead of showing a failure. All three reads
  are on demand with a ten-second freshness guard and are **not** in the console's three-second
  poll, a late answer for a zone or range the operator has since left is discarded, and the
  storage-off placeholder's noise is now drawn once instead of being re-rolled on every poll
  (which made the Traffic view's ghost twitch as if it were live). 35 strings and the
  sixteen-member `edgeEventKind` enum in all five locales; the dashboard page documents the card.
- Edge track, E5.8 — the acceptance rig, `engine/scripts/labnet/edge-e5.sh` (edge-spec §8, E5): the E4
  rig's netns topology on **Debian 13** — stock nginx 1.26.3 with the HTTP/3 module and curl 8.14.1
  with HTTP3, no third-party repository — with the brain **inside the edge netns** and its XDP data
  plane on the edge's interface in front of nginx's UDP/443, a Pebble CA, `h3probe` and tcpdump as
  witnesses, and a second node whose `nginx -V` is wrapped to hide the module. Arms A–M of the E5
  plan's acceptance table (G, shared ticket keys, is absent — E5.6 was cut): per-zone h3 is one
  install and a rate change installs nothing, curl reaches the zone over HTTP/3 and the origin sees
  it, the TCP answer announces `Alt-Svc` and a client with the cache upgrades, the zone that did not
  ask refuses QUIC; 429 + `Retry-After`, the clearance page, a cleared cookie and a watch-only
  zone's `would-deny` mark all over h3; **Retry** seen by `h3probe` and on the wire (the server's
  first datagram is a long-header Retry shorter than the Initial), the host key unchanged across a
  reload and a restart, `quic.retry: false` observed; the **Initial-rate cap** sheds a 300-Initial
  flood in-kernel — the stack sees none of it — while a legitimate h3 handshake completes during
  it, and the same flood under the brain's dry-run is counted and reaches the stack; 0-RTT provably
  off (no `ssl_early_data`, `ssl_session_tickets off`, early data never accepted,
  `early_data_capable: false` reported); the **kill lever** puts every client back on TCP within a
  second and is previewed under dry-run; h3 survives the brain's death and a node restart from disk;
  the wrapped node degrades to TCP, says why, and the fleet status names it under `unsupported`
  beside the serving node; h3 versus h2 p50 recorded for a `mode: none` and a decide zone; MTU 1200
  breaks h3 cleanly and fast while TCP survives; the `advertise: false` canary announces nothing to
  the browser path while an explicit client is served, then a short `ma`. Test-only; no product
  change. The first runs caught nine rig bugs and none in the product; the data-plane facts the rig
  had to learn — dry-run takes effect at attach and records the would-be verdict beside
  `dryrun_would_drop`, so "not dropped" is proven at the stack (`Udp InDatagrams`) — are in the
  script's comments.
- Edge track, E5.4 (tools) — the two HTTP/3 test clients the E5 arms will be written against.
  `engine/hack/h3client` is stock Debian 13 curl in a container, the ordinary-client half: its
  build ends in `curl -V | grep -q HTTP3`, because `curl --http3` falls back to HTTP/2 rather
  than failing and a point release that dropped HTTP/3 would otherwise leave every h3 arm
  passing over the wrong protocol. `engine/hack/h3probe` is the instrumented half, for the two
  facts curl cannot report: whether the server sent a QUIC **Retry** (read from the connection's
  own qlog trace) and whether a session ticket issued by one node **resumes** on another
  (`-resume` makes a second connection sharing one TLS session cache; `-resume-url` points it at
  a different address). It prints one JSON object — `status`, `alpn`, `proto`, `alt_svc`,
  `retry_seen`, `resumed`, `resume_status`, `error` — and exits 0 even on a failed request, so a
  shell arm parses a refusal as readily as a success. **The product gains no QUIC dependency**
  (E5 decision D10): h3probe is its own Go module, invisible to `go build ./...` and to the
  kapkan binary's module graph, and `internal/edge/render/deps_guard_test.go` fails if a
  `quic-go` requirement ever appears in `engine/go.mod` — or if h3probe stops holding one, so
  the guard cannot pass vacuously. Both tools are test-only; `make h3probe` builds the probe.
- Edge track, E5.4 (arms) — the HTTP/3 clients drive the real-terminator matrix (edge-spec §8,
  E5). `TestRealTerminator` gains `serve/h3/*`: on `nginx:stable` and Angie, stock curl reaches a
  decide zone and a `mode: none` zone over **HTTP/3** (`--http3-only`, status 200, the origin echoes
  the zone); a first request over TCP negotiates h2 and carries `Alt-Svc`, and a second one with
  curl's alt-svc cache is h3 (the browser path); the `advertise: false` canary is reachable by a
  client that asks for h3 explicitly; QUIC to a zone without `tls.h3` is refused while TCP serves
  it; an unknown SNI over QUIC is refused by the catch-all and, under `omit_catch_all`, by the
  QUIC anchor; h3probe sees a **Retry** with the default `quic_retry` and none under
  `quic.retry: false` (the http-level placement takes effect); and, on Linux, the same decisions
  over h3 as over TCP — a 403 denies, a rate denial is 429 + `Retry-After`, a 200's mark reaches
  the origin, a 401 lands on the clearance page, the subrequest carries the kapkan headers, and
  the access log's `proto` is `HTTP/3.0` (what `kapkan_edge_requests_total{protocol="h3"}` counts).
  On `nginx:1.22` the zone that asked is served over TCP, `--http3-only` fails and the rendered
  zone file says why. The clients run in containers on the terminator's Docker bridge
  (`--add-host` per zone), so UDP/443 is never published and the arms behave the same on Docker
  Desktop and a Linux runner; the harness builds the curl image and cross-compiles h3probe once per
  run and fails — never skips — when either cannot be had. Test-only; no product change.
- Edge track, E5.1 — the terminator capability probe and HTTP/3 readiness (edge-spec §8, E5).
  The node now asks its binary `nginx -V` (was `-v`) and learns, beside kind and version, the
  nginx core an Angie build derives from, the TLS library it runs with, whether it was built
  with `--with-http_v3_module` and whether it could do 0-RTT over QUIC (recorded only: 0-RTT
  stays off by policy). `edge.yaml` gains `quic.h3: auto|off` (default `auto`). The report
  carries `terminator.h3 {state, module, tls_library, early_data_capable, advisory}` and
  `/healthz` the same object as `h3`, with `state` `ready`, `no_module`, `node_off` or
  `unknown` (the probe failed — treated as `no_module`: the node never guesses about a binary
  it could not ask); the new gauge `kapkan_edge_h3_ready` is `1` for `ready`. The probe runs
  once, at start, so an upgraded binary is only reported after a restart. `advisory` names a published QUIC advisory whose
  affected range holds the build's nginx core — CVE-2026-40460 (1.25.0–1.30.0: a migrated QUIC
  connection's new streams carry an unverified client address, the accounting key kapkan
  decides on; fixed upstream in 1.30.1 and 1.31.0) or CVE-2026-42530 (1.31.0–1.31.1: a
  use-after-free processing a crafted QUIC session, fixed upstream in 1.31.2) — as advice, never a
  refusal: distributions backport fixes without moving the version (Debian 13's
  `1.26.3-3+deb13u7` carries the first fix and reports `1.26.3`), so the operator checks the
  package changelog or sets `quic.h3: off`. `kapkan edge -check` prints the probe's findings
  and warns on an advisory. Nothing renders QUIC yet — that is E5.2; `tls.h3` is still refused
  by the zones file until E5.3. The real-terminator matrix pins what each image must report
  (`nginx:1.22` without the module, `nginx:stable` and Angie with it).
- Edge track, E5.2 — the renderer speaks QUIC where the terminator can (edge-spec §8, E5). A
  zone with `tls.h3` now renders `listen 443 quic` beside its TCP listeners and announces it
  with `Alt-Svc` — only on a node whose probe found the HTTP/3 module (`render.Node.H3Supported`);
  elsewhere the zone renders byte for byte as `tls.h3: false` plus a comment block, and the
  render reports it (`render.RenderDetailed` → `Info.Degraded`), so a zone is never held hostage
  to one node's package. Everything QUIC needs before SNI names a zone sits at the `http` level
  of the shared file — `quic_retry` (on; node-wide `quic_retry` input) and `quic_host_key` (the
  node's file, default `/var/lib/kapkan-edge/tls/quic_host.key`) — because nginx binds a QUIC
  connection to the address's default server first. The catch-all carries the address's one
  `reuseport` QUIC listener; under `omit_catch_all` a bare QUIC anchor (`server_name _;
  ssl_reject_handshake on`) carries it unless `omit_quic_anchor` says the operator's own server
  does (a second `reuseport` fails `nginx -t`). New document field `tls.h3_options {advertise,
  alt_svc_max_age_seconds}` (nil at the defaults: unchanged bytes and ETag); `advertise: false`
  renders the listener without announcing it. The access log gains `"proto":"$server_protocol"`
  (`HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`) — the shared file changes, so every node
  tests and reloads once on upgrade, as with the earlier log-field additions — and the rollups
  parse it. Not rendered, by decision: `ssl_early_data` (0-RTT off by policy), `quic_bpf`,
  `quic_gso`, `http3`. The QUIC anchor carries `ssl_protocols TLSv1.3` of its own: the UDP
  default server's protocol set governs every QUIC handshake on the address, and an http-level
  `ssl_protocols TLSv1.2;` in an operator's `nginx.conf` would otherwise pass `nginx -t` and fail
  every HTTP/3 handshake silently (verified on nginx 1.28, 1.30 and Angie). Golden fixtures for
  seven HTTP/3 shapes; the real-terminator matrix runs every one through `nginx -t` on all three
  images (TCP-only on `nginx:1.22`, where forcing QUIC is shown to fail on `unknown directive
  "quic_retry"` — the first QUIC token nginx meets, in the shared file) and checks `Alt-Svc` over
  TCP and the `proto` field in the access log.
  The node does not pass its readiness to the renderer yet and `tls.h3` is still refused by the
  zones file — both are E5.3.
- Edge track, E5.7 — the HTTP/3 documentation, in English (the five-locale wave follows). *Edge
  nodes* gains a **`## HTTP/3 (QUIC)`** section: where h3 renders and where it honestly degrades
  (the readiness table), what is node-wide and why (Retry always on, 0-RTT off, the per-node host
  key — nginx fixes them on the address's default server before SNI), the rollout order (nodes
  first, UDP 443 and MTU, the `advertise: false` canary, a short `ma`, rollback), the build
  advisories (CVE-2026-40460/-42530 as advice, since distributions backport), the cap and kill
  levers as data-plane static rules, and the supported topologies with what nginx cannot do — no
  connection migration between nodes and **no TLS session resumption between nodes** (nginx binds
  a session to the node's certificate, and Kapkan's certificates are per node; shared ticket keys
  were investigated in E5 and do not help). *Install an edge node* gains the UDP-443 / `nginx -V`
  / MTU / `TLSv1.3` prerequisites and four HTTP/3 troubleshooting rows; the glossary gains a TLS
  and HTTP/3 table (QUIC, HTTP/3, QUIC Initial, Retry, Alt-Svc, 0-RTT); `edge-spec.md` §2.1 and
  §3 record that cross-node resumption is out, with the reason. No code change.
- Edge track, E5.3 — the switch is real (edge-spec §8, E5). The zones file accepts `tls.h3:
  true` and `tls.h3_options {advertise (default true), alt_svc_max_age_seconds 60..604800
  (default 86400)}` (refused without `h3`); the document carries the options only where they
  depart from the defaults, so a zones file that merely turns h3 on adds one flag and nothing
  else. `edge.yaml` gains `quic.retry` (node-wide `quic_retry`, default on) and
  `quic.omit_anchor` (only with `omit_catch_all`). The node renders QUIC when its readiness is
  `ready` — module present, `quic.h3` not `off`; a failed probe renders none — passes
  `quic.retry` and the host-key path through, and mints the key once at its first start
  (`state_dir/tls/quic_host.key`, 32 random bytes, `0600`, kept across restarts so Retry and
  stateless-reset tokens survive a reload). Zones asking for h3 on a node that cannot are served
  over TCP and named: `terminator.h3.serving` / `unsupported` in the report and `/healthz` (one
  warning per change of the set), plus `terminator.h3.listening` — whether something on the box
  holds UDP 443 while QUIC listeners are rendered, from `/proc/net/udp`. The rollups count HTTP/3
  requests from the log's `proto` field: `zones[].h3_requests` in the report, the counter
  `kapkan_edge_requests_total{zone,protocol=h1|h2|h3|other}` on the node. `GET
  /api/v1/edge/zones/status` gains `h3 {enabled, serving[], unsupported[], requests}` (`enabled`
  is the zones file's word, the lists are the alive nodes'). The zones schema is regenerated.
  Not rendered, still: `ssl_early_data`. Upgrade nodes before zones: a node older than E5
  refuses a document that carries `h3`, stays on its previous generation with
  `converged: false`, and installs nothing more — renewed certificates included — until `h3` is
  removed or the node upgraded; upgrade every node first.
- Edge track, E5.5 — the operator console's Edge view gains an **HTTP/3** column (edge-spec §8,
  E5). It reads the zone's h3 STATE from `GET /api/v1/edge/zones/status`, never a window's
  counters: `off` when the status carries no `h3` for the zone (nobody asks and nobody speaks it —
  and a brain older than E5.3 sends no such field, which renders the same way); `on · 42% · 3/3`
  when every node reporting the zone serves it, the share being the alive nodes' last-window
  HTTP/3 requests over the zone's requests (dropped when the window had none); `on · 2/3 ready`
  in the watch-only treatment when the zone asks and a node cannot, with a tooltip naming each
  such node, the reason from its own `terminator.h3.state` and any advisory its probe raised —
  read from `GET /api/v1/edge/nodes`, which the view now fetches beside the status, since only a
  node's report explains itself (a refused or failed inventory costs the tooltip's detail, never
  the table); and `off · 2 nodes still serving` when the zones file no longer asks for HTTP/3
  while a node still holds a QUIC listener, because a file and a fleet that disagree must not
  read as a finished switch-off. A node reporting the zone that named neither list is said to
  have reported no readiness at all rather than guessed about. Twelve new locale strings and two
  plural keys in all five catalogs; `i18n.plural()` now interpolates `{vars}` as `t()` does, so a
  form carrying a second number keeps its whole phrase, word order included, in the translation.

### Fixed

- Storage: rows enqueued just before shutdown were lost when they filled a batch — the
  size-triggered flush sent on the run context, which the shutdown had just cancelled, so the
  POST failed with `context canceled` and the rows were counted as errors. Every flush now sends
  each table on its own bounded context (10 s); the run context is only the stop signal. Found by
  the new real-ClickHouse suite (E6.4).
- Storage: `GET /api/v1/traffic` applied its time range to the **bucket** a snapshot fell into
  rather than to the snapshot itself — ClickHouse read the `ts BETWEEN` beside the bucket's
  `AS ts` alias as the alias — so the first partly covered bucket lost every point and points
  just past `to` in the last bucket were counted. The range now filters the rows in a subquery,
  and the reads pin the alias rule they are written for (`prefer_column_name_to_alias=0`) so a
  per-user server profile cannot turn a bucketed history into one row per snapshot. Found by the
  E6.4 review on the edge twin of the query.

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
