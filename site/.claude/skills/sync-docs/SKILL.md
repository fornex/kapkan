---
name: sync-docs
description: Sync the kapkan.io documentation site with the Kapkan product repo after the product gains features or changes. Use when the Kapkan product (~/Projects/kapkan) has new commits or features, when the SessionStart docs-sync reminder fires, or when the user asks to update/refresh/sync the docs. Updates English first from the product source, propagates to every locale (ru/de/fr/es) keeping code/keys/links intact, verifies rendering, and advances the sync marker.
---

# Sync Kapkan docs with the product

The documentation site (this repo, `kapkan.io`) documents the **Kapkan product**, a separate
Go repository at `~/Projects/kapkan`. When the product ships features, the docs must follow —
in **all five languages**. This skill is the procedure for that.

## Layout you are working with

- Product (source of truth): `~/Projects/kapkan` — its `README.md`, `configs/`,
  `deploy/config.example.yaml`, `docs/callback-schema.json`, and `internal/**` (Go structs with
  `json:"..."` tags) define what is true.
- Docs content: `frontend/content/docs/<lang>/<slug>.mdx`, where `<lang>` ∈ `en ru de fr es`.
  **English (`en`) is the source; the others are translations.**
- Sidebar structure & order: `frontend/lib/docs-nav.ts` (group keys + slug lists).
- All display titles (sidebar group titles + per-page titles) per locale: `frontend/lib/i18n.ts`.
- Routing: `app/[lang]/docs/[slug]/page.tsx` dynamically imports the MDX; `generateStaticParams`
  enumerates `locales × flatSlugs`, so **a new slug must be added to `docs-nav.ts` AND given a
  title in every locale in `i18n.ts`** or it will 404.
- In-content links are **locale-agnostic**: write `/docs/<slug>`; the `DocLink` component
  (`components/DocLink.tsx`) prefixes the active locale automatically. Never hard-code `/en/docs/...`.
- The sync marker: `.tooling/docs-sync-state.json` holds `synced_commit` — the product commit the
  docs currently reflect.

## Procedure

### 1. Find what changed
```sh
SYNCED=$(sed -n 's/.*"synced_commit"[^"]*"\([^"]*\)".*/\1/p' .tooling/docs-sync-state.json | head -1)
PROD=~/Projects/kapkan
git -C "$PROD" log --oneline "$SYNCED"..HEAD
git -C "$PROD" diff --stat "$SYNCED"..HEAD -- README.md configs deploy docs/callback-schema.json internal
git -C "$PROD" diff "$SYNCED"..HEAD -- README.md deploy/config.example.yaml docs/callback-schema.json
```
Read the changed product files in full. **Trust the README body, configs and Go code — NOT the
stale `> Status: MVP …` line at the top of the product README, which is known to lag reality.**

### 2. Map product changes → doc pages
| Product change | Doc page(s) to update (slug) |
| --- | --- |
| New/changed config key (README config table, `config.example.yaml`, `internal/config`) | `configuration` + the relevant topic page |
| New detection behaviour, per-protocol metric, classification vector | `detection` |
| Hostgroup behaviour | `hostgroups` |
| Baseline behaviour | `baselines` |
| BGP / RTBH / FlowSpec / escalation / per-hostgroup BGP (`internal/mitigate`, `bgp.go`) | `mitigation` (or a dedicated page) |
| Safety rule | `safety` |
| New/changed REST endpoint or response field (`internal/api`, `internal/engine`, `internal/mitigate` json tags) | `api` |
| Dashboard | `dashboard` |
| Auth | `authentication` |
| Notification channel / callback payload (`docs/callback-schema.json`, `internal/notify`) | `notifications` |
| New/renamed Prometheus metric | `metrics` |
| systemd / install / build | `deployment` |
| A shipped feature previously listed as roadmap | remove it from the "What it does not do (yet)" list in `introduction` |

A large new subsystem (e.g. ClickHouse storage, FlowSpec) usually deserves its **own page**, plus
a summary + link from `configuration`, `mitigation`, `metrics`, and `introduction` as relevant.

### 3. Update English first
Edit/create `frontend/content/docs/en/<slug>.mdx`. Follow the existing page conventions exactly:
- Start with `export const metadata = { title, description };` then a blank line, then `# <Title>`.
- GFM markdown; fenced code blocks **with a language tag**; GFM tables.
- Notes via the global `<Callout type="info|warning|danger|success" title="…">…</Callout>` (no import).
- **No** imports, **no** default export, **no** `---` frontmatter.
- In prose, never use raw `{ } < >` — put such tokens in `code spans` or fenced blocks.
- Links: locale-agnostic `[text](/docs/<slug>)`. In-page anchors must match the heading text.
- Document only what the product source establishes; match exact key names, defaults, ports,
  endpoints, field names and metric names. Do not invent.

### 4. New page? wire it up
- Add the slug to the right group in `frontend/lib/docs-nav.ts`.
- Add the page title for **every** locale in `frontend/lib/i18n.ts` (`pageTitles[lang][slug]`).
  Keep the sidebar title identical to the page H1/metadata.title.

### 5. Propagate to ru / de / fr / es
For each changed or new page, produce the translation in each locale at
`frontend/content/docs/<lang>/<slug>.mdx`. Translation rules (identical to the originals):
- Translate prose, table-cell text, `<Callout>` `title=` and body, and `metadata.description`.
- **Do NOT translate / alter:** fenced code block contents (incl. comments), inline code spans,
  config keys, field names, endpoints, env vars, units, link hrefs, the `<Callout type>` value,
  and product/tech names (Kapkan, GoBGP, goflow2, NetFlow, IPFIX, sFlow, BGP, RTBH, FlowSpec,
  Prometheus, ClickHouse, systemd, Telegram, Slack, …). Keep technical terms (dry-run, blackhole,
  flow, hostgroup, pps, Mbps) in English, with a brief native gloss on first use if natural.
- Use the canonical title from `i18n.ts` verbatim for both `metadata.title` and the H1.
- Keep heading levels, table structure and section order identical to the English page.
- **In-page anchor links** (`](#…)`) must point at the slug of the *translated* heading (rehype-slug
  derives anchors from the rendered heading text), so update them when you translate a heading.

When more than a few (lang, page) pairs change, fan out with the **Workflow tool** — one agent per
(lang, page) — using the rules above; see `frontend/` history for the translation workflow shape.

### 6. Verify
```sh
cd frontend
npx tsc --noEmit                                  # types clean
npm run dev -- --port 3099 >/tmp/kapkan-dev.log 2>&1 &   # if not already running
# every affected route in every locale must be 200 with no error overlay:
for lang in en ru de fr es; do for slug in <changed-slugs>; do
  curl -s -o /tmp/r -w "$lang/$slug %{http_code}\n" "http://localhost:3099/$lang/docs/$slug"
  grep -qiE "Build Error|Failed to compile|Unhandled Runtime|is not defined" /tmp/r && echo "  ^ ERROR"
done; done
```
Also confirm each translation's fenced code blocks are byte-identical to the English page
(translators must never touch code). Spot-check the Russian prose for quality.

### 7. Advance the marker & report
Set `synced_commit` in `.tooling/docs-sync-state.json` to the new product HEAD
(`git -C ~/Projects/kapkan rev-parse --short HEAD`) and `synced_at` to today. Summarize what
changed (pages added/updated, in which languages) and suggest committing. The SessionStart hook
(`.tooling/hooks/docs-sync-check.sh`) will then go quiet until the product moves again.

## Notes
- Keep English and translations structurally in lockstep — same sections, same code, same order.
- Prefer dedicated pages for big subsystems over bloating an existing page.
- If you remove or rename a slug, update `docs-nav.ts`, `i18n.ts` (all locales) and any links.
