BINARY := kapkan
PKG := ./...

.PHONY: build test lint bench run-dev clean console-sync

# The operator console lives in the monorepo's top-level console/ folder; the Go
# binary go:embeds internal/api/static. Copy console/ there before any compile
# (build AND test compile the api package, which has //go:embed static/...).
console-sync:
	rm -rf internal/api/static
	mkdir -p internal/api/static
	cp -R ../console/. internal/api/static/

build: console-sync
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/kapkan

test: console-sync
	go test -race -count=1 $(PKG)

lint: console-sync
	golangci-lint run

bench: console-sync
	go test -run '^$$' -bench . -benchmem ./internal/engine/...

run-dev: build
	./$(BINARY) -config configs/dev.yaml -log-format text

clean:
	rm -f $(BINARY)
	rm -rf internal/api/static
