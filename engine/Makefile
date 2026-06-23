BINARY := kapkan
PKG := ./...

# Version stamping. Injected into internal/buildinfo via -ldflags -X so the
# /api/v1/status version, the console Settings view and `kapkan -version` are
# accurate even though -trimpath drops VCS info from local checkouts. Overridable
# (e.g. the release pipeline passes VERSION=$tag). git commands walk up to the
# repo root, so they work from this subdirectory.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo none)
DATE    ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
BUILDINFO := github.com/kapkan-io/kapkan/internal/buildinfo
LDFLAGS := -s -w \
	-X $(BUILDINFO).version=$(VERSION) \
	-X $(BUILDINFO).commit=$(COMMIT) \
	-X $(BUILDINFO).date=$(DATE)

.PHONY: build test lint bench run-dev clean console-sync schema

# The operator console lives in the monorepo's top-level console/ folder; the Go
# binary go:embeds internal/api/static. Copy console/ there before any compile
# (build AND test compile the api package, which has //go:embed static/...).
console-sync:
	rm -rf internal/api/static
	mkdir -p internal/api/static
	cp -R ../console/. internal/api/static/

build: console-sync
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/kapkan

test: console-sync
	go test -race -count=1 $(PKG)

lint: console-sync
	golangci-lint run

bench: console-sync
	go test -run '^$$' -bench . -benchmem ./internal/engine/...

run-dev: build
	./$(BINARY) -config configs/dev.yaml -log-format text

# Regenerate the committed config schema from the Config struct. The drift gate
# (TestSchemaMatchesGenerated) fails the build until the result is committed.
# Depends on console-sync because cmd/kapkan go:embeds the console at compile.
schema: console-sync
	go run ./cmd/kapkan -dump-schema > ../docs/config-schema.json

clean:
	rm -f $(BINARY)
	rm -rf internal/api/static
