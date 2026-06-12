BINARY := kapkan
PKG := ./...

.PHONY: build test lint bench run-dev clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/kapkan

test:
	go test -race -count=1 $(PKG)

lint:
	golangci-lint run

bench:
	go test -run '^$$' -bench . -benchmem ./internal/engine/...

run-dev: build
	./$(BINARY) -config configs/dev.yaml -log-format text

clean:
	rm -f $(BINARY)
