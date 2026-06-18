# Kapkan

Monorepo for the Kapkan project. Four independently-developable folders; the engine and its
console still compile to **one binary** (the console is `go:embed`'d).

```
engine/    Go engine + REST API — `make build` produces a single binary
console/   operator-console UI (HTML/CSS/JS); copied into the engine's embed dir at build
site/      kapkan.io marketing + docs site (Next.js static export)
docs/      canonical user-facing docs (MDX, 5 locales) — rendered by the site
```

## Build

```sh
make build     # one binary (engine + embedded console) → engine/kapkan
make test      # engine test suite
make site      # static site → site/frontend/out  (copies docs/ in first)
```

`make build` copies `console/` into `engine/internal/api/static/` (gitignored) before
`go build`, so the binary embeds the console — same single artifact as before. The engine is a
self-contained Go module under `engine/` (module path `github.com/kapkan-io/kapkan`).

## Develop in parallel

Each folder is independent. Use `git worktree` to work on several at once without interference:

```sh
git worktree add ../kapkan-site site-branch     # hack on site/ in its own checkout
git worktree add ../kapkan-engine engine-branch  # hack on engine/ in another
```

- **Console** previews standalone — serve `console/` as static files (see `.tooling/launch.json`).
- **Docs** are the source of truth under `docs/`; the site copies them in at build, and
  `/sync-docs` keeps them in step with `engine/`.

## Release

The site auto-publishes to https://kapkan.io on change (Stop hook → `site/deploy.sh`); see the
`release` skill. The engine ships as the `make build` binary. CI is `.github/workflows/ci.yml`.
