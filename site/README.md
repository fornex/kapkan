# kapkan.io

Website for [Kapkan](https://github.com/kapkan) — open-source DDoS detection & mitigation.
The product itself lives in a separate repository (`~/Projects/kapkan` locally); this repo
is only the site.

## Layout

```
frontend/   — Next.js (landing, docs; customer portal later)
backend/    — Go API for the site (forms; licensing/billing later)
```

## Development

```
cd frontend && npm run dev          # Next.js dev server on :3000
cd backend && go run ./cmd/server   # API on 127.0.0.1:8090 (KAPKAN_SITE_ADDR to override)
```
