# Kapkan Operator Console — Integration Plan

Status: ready to execute. Owner: TBD. Source review: 29-agent adversarial review of the
Claude Design handoff, cross-checked against this repo's API source (2026-06-15).

This plan integrates the redesigned operator console (a vanilla HTML/CSS/JS prototype produced
by Claude Design) into the engine's embedded UI at `internal/api/static/`. The design and its
CSP discipline are excellent and verified; the work is **data-contract reconciliation + a few
small server additions + render-loop/a11y hardening**, NOT a re-build. Do **not** port to a
framework: the target is the embedded, build-step-free, strict-CSP static bundle.

---

## 0. TL;DR

The handoff README's "swap the mock for fetch and you're done" is **false**. The mock data layer
diverges from the real API in load-bearing ways (3 confirmed crash/break blockers, ~9 highs). The
clean path is a **thin client-side adapter** that replaces `mock-api.js`, exposing the exact method
names/shapes the UI already consumes while (a) calling the real `/api/v1/*` endpoints, (b) renaming
fields, (c) deriving the few things the API doesn't ship (aggregate, bans active/history split,
escalation reconstruction, rejection log). Plus **one required** server change (expose `role` on
`/status`) and **two optional** ones (escalation on `Attack`; `GET /api/v1/traffic`).

Estimated effort: ~2–4 focused days. Order: data contract → role/auth → embed → render loop → a11y →
strip demo → traffic endpoint → fr/es.

---

## 1. What you're integrating & where

- **Bundle (prototype):** currently in `/tmp/kapkan-design/design_handoff_kapkan_console/` (12 ship
  files + 3 docs). Step 1 is to copy the ship files into `internal/api/static/`.
- **Target:** `internal/api/static/` (today: `index.html`, `app.js`, `style.css`).
- **Server touch points:** `internal/api/dashboard.go` (embed + allowlist), `internal/api/api.go`
  (`/status` role, optional escalation-on-Attack, optional traffic route), `internal/app/app.go:62`
  (`api.New(...)` wiring if the traffic endpoint is added), `internal/storage/storage.go` (add a
  read path for the traffic endpoint).
- **CSP:** already set as an HTTP header by `dashboard.go:54` (`dashboardCSP`, dashboard.go:33) with
  the exact target policy. Nothing to add — just ignore the prototype's commented `<meta>`.

Ship files: `index.html`, `style.css`, `components.css`, `icons.js`, `i18n.js`,
`locales/en.js`, `locales/de.js`, `locales/ru.js`, `components.js`, `views.js`, `views2.js`,
`app.js`. (`design-tokens.css` is a reference duplicate of the `:root` block in `style.css` — do
not ship it. `mock-api.js` is replaced by the adapter.)

---

## 2. Verified-good — keep as-is

- **CSP / constraint compliance (96/100):** zero inline styles/scripts, zero external resources,
  icons inline SVG, all dynamic dimensions via CSSOM, XSS-safe (`textContent` everywhere;
  `innerHTML` only for constant icon strings). It satisfies `dashboardCSP` unchanged.
- **The differentiators are real, not mocked-up:** escalation ladder, posture-first dual-state
  Overview, dry-run dashed-amber treatment, rate-vs-baseline host bars, exact BGP/FlowSpec artifact,
  sample share bars + raw flows, ban timeline, confident empty states. All render correctly (driven
  live through a full calm→attack→mitigate→blackhole→recovery arc).
- **i18n core (78/100):** ~148 string keys all resolve; de/ru 100% parity; correct Russian plural
  forms; full enum-label coverage; `Intl`-bound formatting. Technical tokens kept verbatim.

Do not re-style or re-architect these. The work below is contract + plumbing + hardening.

---

## 3. Strategy — a thin adapter, not a rewrite

The prototype funnels **all** data access through one `window.MockAPI` object. Replace it with
`api.js` exposing the **same method names** and returning the **same shapes the UI already
consumes**, but backed by `fetch('/api/v1/…')`. This isolates the entire contract mismatch in one
file and leaves the verified-good UI code untouched.

The adapter handles three classes of mismatch:
1. **Pure renames** (e.g. group `calculation`→`calc`) — map in the adapter's response shaping.
2. **Derivations** the API doesn't ship — `aggregate()` (sum `/hosts`), bans `{active,history}`
   split, `escalation`/`escalation_step` reconstruction, rejection log.
3. **Auth** — bearer token acquisition (401 → prompt → `sessionStorage`) and `role` sourcing.

Keep the rolling-buffer logic in `app.js` (it already reads through the adapter via `pushBuf()`).

---

## 4. The data contract: real API → UI shape (the crux)

Real shapes verified from source (`internal/api/api.go`, `internal/mitigate/mitigate.go`,
`internal/engine/{events,engine,sample,classify}.go`, `internal/config/config.go`). Enum strings
(attack types ×12, metrics ×13, actions ×4, ban states ×3, scope ×2, direction ×2, method ×3)
**all match** the catalogs — only the data wrapping them diverges.

### 4.1 `GET /api/v1/status`
Real: `{dry_run, uptime_seconds, active_attacks, active_bans, hostgroups:[Group], networks?, thresholds?}`
(api.go:378-391). `networks`/`thresholds` present **only for unscoped admin tokens**.

- UI calls `API.getStatus()`, `API.getHostgroups()`, `API.getNetworks()` — the latter two are **not
  endpoints**. Adapter: cache the `/status` body each poll; `getHostgroups()` → `status.hostgroups`,
  `getNetworks()` → `status.networks || []`.
- **Group field renames** (config.go:362-401) — adapter must map each `Group`:
  | UI expects (mock) | Real JSON tag |
  |---|---|
  | `calc` | `calculation` |
  | `ban_enabled` | `ban` |
  | `next_hop` | `blackhole_next_hop` |
  | `community` | `blackhole_communities` (display string) |
  | `local_pref` | `blackhole_local_pref` |
  | `scrub_next_hop` | `scrub_next_hop` (same) |
  | `baseline:{enabled,window}` | `baseline:{factor,warmup_seconds,floor}` or **omitted** |
- **BLOCKER F3 (Hostgroups crash):** `views2.js:120` does `g.baseline.enabled`. Real `baseline` is
  `*BaselineSettings,omitempty` → **absent when disabled**. Adapter must emit `baseline:null` when
  absent and `{enabled:true, factor, warmup_seconds, floor}` when present; **and** `views2.js:120-121`
  must be changed to render `factor / warmup_seconds / floor` instead of `enabled / window`. (Pure
  adapter renaming is not enough here — the displayed fields differ.)
- `role` is **absent** today — see §6.1 (required server change).

### 4.2 `GET /api/v1/attacks`
Real: `{active:[Attack], recent:[Attack]}` (api.go:420-423). `Attack` (api.go:31-56):
`scope, target, group, tenant?, direction, metric, rate, threshold, rates, active, ban_state?,
method?, route?, flowspec?, dry_run, started_at, ended_at?, sample?, classification?`.

- **BLOCKER F2 — `Attack` has NO `escalation` / `escalation_step`.** These exist only on `Ban`
  (mitigate.go:66-67). The UI reads `a.escalation_step` (app.js:47) and `a.escalation` (views.js:97)
  for the **signature ladder + posture**. Adapter reconstruction (no server change required):
  - Find the matching active ban (`/bans` by `target` + same direction). If found, graft
    `ban.escalation` + `ban.escalation_step` onto the attack.
  - Else (alert-only, no ban yet): use the owning group's ladder
    `status.hostgroups[a.group].escalation` and derive the step as
    `max i where (now - started_at) >= escalation[i].after_seconds` (mirrors the engine's rung
    advancement). This makes the ladder work for the entire arc, including pre-ban alert.
  - (Alternative: add `escalation`/`escalation_step` to `api.Attack` server-side — see §6.2. Cleaner
    but optional given the above works.)
- **HIGH F7 — `peak_rate` does not exist.** Recent table reads `peak_rate`; real recent attacks
  carry `rate` + `rates` (the *last* measurement, not a peak). Adapter: map `peak_rate ← rate`, and
  relabel the column "Last rate" (or wait for `/traffic` history to compute a true peak). Do not
  imply a peak we don't have.
- **HIGH F8/F9 — sample/flowspec shapes:** `SampleFlow.tcp_flags` is a numeric `uint8`
  (sample.go:31), not a string `"flags":"S"`; flows also carry `bytes`, `packets`, `sampling_rate`.
  Real `FlowSpec` rules are structured objects (not `{match:string, action}`). The raw-flows table
  (`views2.js` `rawFlows`) and route display (`components.js` `routeDisplay`) must render the real
  shapes — decode `tcp_flags` to a flag string for display, render structured flowspec match fields.
- `ban_state` is `omitempty` (absent, not `null`) when empty — UI must treat absent == none.
- `classification` is `omitempty` — already guarded in most places; verify no unguarded
  `a.classification.type` deref (correctness review flagged this risk).

### 4.3 `GET /api/v1/hosts`
Real: `{hosts:[HostStat]}` (api.go:436). `HostStat` (engine.go:789-801):
`target, group, rates, rates_out, in_attack, metric?, direction?, baseline?, baseline_out?`.

- **HIGH F6 — outgoing field names:** UI reads `out_rates`/`out_baseline`; real tags are
  **`rates_out`/`baseline_out`**. Adapter rename (breaks the Hosts Outgoing toggle otherwise).
- `baseline`/`baseline_out` are `*Rates,omitempty` (absent until learned) — UI already handles the
  "Learning baseline…" null case; keep `null` when absent.

### 4.4 `GET /api/v1/bans`
Real: `{bans:[Ban]}` — a **flat array** (api.go:449), one entry per banned address, mixed states.
`Ban` (mitigate.go:39-67): `target, prefix(full CIDR), metric?, rate?, threshold?, next_hop,
community, local_pref?, route, state, dry_run, manual, started_at, expires_at, withdrawn_at?,
reason?, method, flowspec?, escalation?, escalation_step`.

- **BLOCKER F1 — shape:** UI consumes `{active, history}` (views.js:269,293). Adapter:
  `getBans()` → fetch `{bans}`, return
  `{ active: bans.filter(b=>b.state==='active'), history: bans.filter(b=>b.state!=='active') }`.
- **Rejections are not in `/bans`.** A rejected manual ban comes back from `POST /api/v1/ban` as
  **HTTP 409** with the `Ban` body (`state:"rejected"`, `reason`) (api.go:484-488); a cross-tenant
  target is **HTTP 403** (api.go:475). The adapter must keep a **client-side rejection log** fed from
  those responses and merge it into `history` so the rejection states render. Map `reason` →
  UI reason key (or display `ban.reason` directly; confirm the exact reason strings in
  `mitigate.go` — the UI currently keys on `whitelisted` / `outside_networks` / `cap`).
- **F12 — `prefix`** is a full CIDR (`"203.0.113.66/32"`), not a `/NN` suffix. Adapter/UI: derive
  the suffix or render the CIDR.
- Note the **Ban BGP fields `next_hop`/`community`/`local_pref` match the mock** — no rename needed
  here (the rename problem is the hostgroup `Group` object in §4.1, a different struct).

### 4.5 `POST /api/v1/ban` · `/unban` · `/config/reload`
- `ban {ip}` → 200 + `Ban`, or **409** + rejected `Ban`, or **403** cross-tenant, or 400 invalid IP.
  Requires `Content-Type: application/json` (api.go:250). Adapter `ban()` returns
  `{ok:true, ban}` on 200, `{ok:false, reason}` on 409 (and appends to the rejection log).
- `unban {ip}` → 200 + `Ban`, or 404 if no such ban.
- `config/reload {}` → `{reloaded, dry_run, thresholds}`. Admin-only (403 for scoped tokens).
- **No `aggregate()`/`currentRung()` endpoints** — both are mock-only. `aggregate()` → sum `rates`
  and `rates_out` across `/hosts` (the prototype already structures it this way). `currentRung()` →
  derive from the active attack's reconstructed `escalation_step`.

---

## 5. Work plan (ordered)

### P0 — Blockers (UI cannot run on the real API without these)
- **P0-1** Write `internal/api/static/api.js` (the adapter) replacing `mock-api.js`: same method
  names, real `fetch`, all renames/derivations from §4, bearer-token handling (§6.1), rejection log.
- **P0-2** Fix `getBans()` `{active,history}` split (§4.4 / F1).
- **P0-3** Fix Hostgroups baseline crash: adapter shape + `views2.js:120-121` render real
  `factor/warmup_seconds/floor` (§4.1 / F3).
- **P0-4** Reconstruct `escalation`/`escalation_step` in the adapter (§4.2 / F2) — or do §6.2.

### P1 — Required for correctness/security
- **P1-1** Role: add `role` to `/status` (§6.1) and source `state.role` from it; remove the demo
  toggle. Treat absent `networks`/`thresholds` as a scoped (non-admin) view.
- **P1-2** Auth: on `401`, prompt for a bearer token, store in `sessionStorage`, attach
  `Authorization: Bearer …` to every fetch (mirrors the behavior the *old* panel had).
- **P1-3** Embed: expand `dashboard.go` (§6.3) — `//go:embed` directive + allowlist for all 12 files
  + the `locales/` subdir, with content types.
- **P1-4** Field renames for Hosts (`rates_out`/`baseline_out`, F6) and the sample/flowspec/flags
  shapes (F8/F9), `peak_rate→rate` (F7).

### P2 — Render-loop hardening (root cause of several correctness/UX findings)
The 3s poll fully tears down and rebuilds the active view **and** the open drawer
(`app.js:255-256` → `K.mount` → `clear`). This causes: Attacks search box losing focus per keystroke
(RC-1), manual-ban input being wiped (RC-2), drawer scroll reset + orphaned confirm popover (D2),
hosts jumping under the cursor (D5), the traffic ghost-chart regenerating random noise (D6), and CSS
width transitions never playing (D1).
- **P2-1** Hot-path in-place updates: keep persistent gauge/bar/counter nodes and update only
  `.style.width`/`textContent` on poll (extend the pattern the 1s `tick()` already uses for
  `[data-bar-start]`). At minimum: diff the active attack by id and skip re-mount when structure is
  unchanged.
- **P2-2** Preserve transient UI across renders: input drafts + focus + selection (Attacks search,
  manual-ban field), drawer scroll position, expanded host rows, open menus, in-flight confirm
  popovers. Don't rebuild inputs/drawer every poll.
- **P2-3** Brand-mark duplication bug: `buildShell()` appends a shield without clearing
  (`app.js:67`), and `buildShell` re-runs on `setLocale`/`setRole` — clear `brandMark` first
  (caught live: 3 stacked shields after 2 locale switches).

### P3 — Accessibility (all confirmed)
- **P3-1** Drawer: add `role="dialog" aria-modal="true"`, move focus in on open, trap focus while
  open, restore to the trigger on close, and make controls `inert`/untabbable while closed
  (A11Y-1, A11Y-2).
- **P3-2** Contrast: `--faint` (≈3.0–3.4:1) is used for meaningful text (table headers, section
  labels, route keys, timeline timestamps, the live countdown) — fails WCAG AA 1.4.3. Darken the
  token or stop using it for content; fix the danger-button label and input placeholder too
  (A11Y-3, A11Y-8, A11Y-9).
- **P3-3** Keyboard: table/host rows are click-only `<tr>`/`<div>` — make them keyboard-operable
  (button semantics or `tabindex` + Enter/Space) (A11Y-5).
- **P3-4** Either implement the documented sortable headers (`aria-sort`) or drop the dead CSS/claim
  (A11Y-4). Switch the new-attack live region to `aria-live="polite"` to avoid interrupting on every
  rung change (A11Y-7).

### P4 — Strip demo scaffolding + i18n cleanup
- **P4-1** Remove the auto-run scenario (`app.js:298`), the demo controls (`buildDemoControls`,
  Simulate/Reset/dry-run toggle), and the `MockAPI` scenario methods.
- **P4-2** Route hardcoded user-visible strings through i18n (I18N-01/02/04/05): demo labels (being
  removed), the locale "soon" badge + tooltips, sidebar/drawer `aria-label`s, Settings "RTBH
  next-hop"/"RTBH community". Remove dead error/loading keys or wire the states (see §7).
- **P4-3** German duration spacing (`22Std 31Min` → `22 Std. 31 Min.`) (I18N-07).

### P5 — Optional / follow-up
- **P5-1** `GET /api/v1/traffic` history endpoint (§6.4) — unlocks the Traffic/Reports view and a
  true `peak_rate`. The frontend chart components already accept time-series arrays.
- **P5-2** fr/es catalogs: copy `locales/en.js`, translate strings + enums (the switcher already
  lists them as "soon"; they fall back to English until shipped) (INT-9).
- **P5-3** Render loading-skeleton + error/reconnect banner states (styled + keyed but never
  rendered today — D3/I18N-03), or remove the dead keys/CSS to drop the over-claim.

---

## 6. Server-side additions (Go)

### 6.1 (REQUIRED) Expose `role` on `/status`
The viewer/operator gate currently has no session source — the server knows the caller role
(`requireRole`, api.go:199-257) but `handleStatus` (api.go:378-391) returns no `role`. You cannot
distinguish viewer from operator client-side (both can GET `/status`; the difference only shows on a
403'd mutation). Add to the `resp` map in `handleStatus`:

```go
resp["role"] = string(c.role)        // "viewer" | "operator"
resp["unscoped"] = c.unscoped()      // admin sees networks/thresholds
if c.tenant != "" { resp["tenant"] = c.tenant }
```

Then `app.js` sources `state.role` from `status.role`, removes the demo toggle, and treats absent
`networks`/`thresholds` as scoped.

### 6.2 (OPTIONAL, cleaner than §4.2 client reconstruction) Escalation on `Attack`
In `RecordAttackStarted` (api.go:97-124), `ban` is already passed in. Copy onto `api.Attack`:

```go
// add to Attack struct:
Escalation     []config.EscalationStage `json:"escalation,omitempty"`
EscalationStep int                      `json:"escalation_step,omitempty"`
// in RecordAttackStarted, when ban != nil:
a.Escalation = ban.Escalation
a.EscalationStep = ban.EscalationStep
```

Caveat: alert-only attacks have no ban, so the client still needs the group-ladder fallback for the
pre-ban stage. Given that, the §4.2 client reconstruction is sufficient on its own; do this only if
you prefer the server to be authoritative.

### 6.3 (REQUIRED) Embed + allowlist (`dashboard.go`)
Expand the `//go:embed` directive (dashboard.go:12) and the `dashboardAssets` allowlist
(dashboard.go:23-27) from 3 entries to all shipped files + the `locales/` subdir:

```go
//go:embed static/index.html static/app.js static/api.js static/style.css static/components.css \
//   static/icons.js static/i18n.js static/components.js static/views.js static/views2.js \
//   static/locales/en.js static/locales/de.js static/locales/ru.js
var dashboardFS embed.FS
```

Add allowlist entries for each (`GET /components.css` → `text/css`, `GET /components.js`/`icons.js`/
`i18n.js`/`api.js`/`views.js`/`views2.js` → `text/javascript`, `GET /locales/en.js` etc.). Keep the
explicit-map approach (no `http.FileServer`) to preserve the zero-path-traversal property. The
per-asset handler already sets the CSP header — no change there.

### 6.4 (OPTIONAL) `GET /api/v1/traffic` over ClickHouse
`storage.Writer` (storage.go) is **write-only** (`WriteAttack`/`WriteTraffic`/`Start`/`Stop`) and is
**not passed to `api.New`** (app.go:62 builds `api.New(store, Engine, mit, log)`; the writer is a
separate `NewWriter`). To add the endpoint:
1. Add `QueryTraffic(ctx, key, from, to, step)` to the storage package: a parameterized
   ClickHouse HTTP `SELECT toStartOfInterval(ts, INTERVAL <step> SECOND) AS b, avg(pps), avg(mbps),
   avg(flows_per_sec), max(in_attack), avg(baseline_pps) FROM traffic WHERE key = {key} AND ts
   BETWEEN {from} AND {to} GROUP BY b ORDER BY b` (validate `key` as a `netip.Addr`).
2. Add a `querier` param to `api.New` and wire the writer/reader in `app.go:62`.
3. Add `read("GET /api/v1/traffic", s.handleTraffic)` returning `{points:[…], events:[…]}` with
   `visibleAddr` tenant scoping. The traffic schema columns match the documented set
   (`ts, scope, key, group, pps, mbps, flows_per_sec, in_attack, baseline_pps`).

---

## 7. Acceptance criteria

- App boots against the real engine with zero console errors; CSP header present, zero violations.
- All seven views render with real data: Overview (calm + under-attack transform), Attacks (+ drawer
  with sample/flows), Bans (active + withdrawn + rejected), Hosts (in/out, baseline), Hostgroups (no
  crash), Traffic (live sparklines; history stub or §6.4), Settings.
- Escalation ladder + posture track a real attack through its rungs (ban-backed or group-derived).
- Manual ban/unban round-trips; rejection (409) and cross-tenant (403) render correct states.
- Viewer token hides all operator affordances; operator token shows them; admin sees
  networks/thresholds.
- Locale switch (en/de/ru) works; technical tokens stay verbatim; no brand-mark duplication.
- Keyboard: drawer traps/restores focus; rows operable; AA contrast on all content text.
- Typing in the Attacks search / manual-ban field is not interrupted by the 3s poll.

---

## 8. Open decisions for you

1. **Escalation source:** client reconstruction (§4.2, zero server change) vs server field (§6.2,
   cleaner). Recommended: start client-side; add the server field later if desired.
2. **Token delivery:** login form storing a bearer in `sessionStorage` (simple, matches old panel)
   vs a same-origin session the Go side translates to a token. Recommended: the prompt-on-401 +
   `sessionStorage` form.
3. **Traffic history (§6.4):** ship now (unlocks Reports + true peak) vs defer behind the stub.
4. **`peak_rate`:** relabel recent "Last rate" until history lands, vs hold the column.
