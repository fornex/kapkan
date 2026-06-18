# Kapkan

The engine and its console compile to **one binary** (the console is `go:embed`'d).

```
engine/    Go engine + REST API — `make build` produces a single binary
console/   operator-console UI (HTML/CSS/JS); copied into the engine's embed dir at build
```

## Build

```sh
make build     # one binary (engine + embedded console) → engine/kapkan
make test      # engine test suite
```

`make build` copies `console/` into `engine/internal/api/static/` (gitignored) before
`go build`, so the binary embeds the console — same single artifact as before. The engine is a
self-contained Go module under `engine/` (module path `github.com/kapkan-io/kapkan`).

## Release

The engine ships as the `make build` binary. CI is `.github/workflows/ci.yml`.
