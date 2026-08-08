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

# Toolchain for regenerating the XDP data plane. Apple's clang has no bpf
# target; Homebrew's LLVM does. Override on other hosts (a Linux CI box usually
# just needs BPF_CLANG=clang BPF_STRIP=llvm-strip).
BPF_CLANG ?= /usr/local/opt/llvm@21/bin/clang
BPF_STRIP ?= /usr/local/opt/llvm@21/bin/llvm-strip

# Where the kernel-side smoke tests run. eBPF needs a Linux kernel, so on macOS
# the test binary is cross-compiled and executed in a privileged container.
BPF_TEST_ARCH  ?= arm64
BPF_TEST_IMAGE ?= alpine:3.20

# Iterations for `make dataplane-bench`. The kernel runs the program this many
# times inside one syscall, so it is a fixed count rather than Go's adaptive b.N.
BPF_BENCH_N ?= 300000

.PHONY: build test lint bench run-dev clean console-sync schema \
	dataplane-sync dataplane-test dataplane-bench

# The operator console lives in the repository's top-level console/ folder; the Go
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

# Regenerate the XDP object and its bpf2go bindings from bpf/*.c. Unlike
# console-sync this is deliberately NOT a prerequisite of build/test: the .o and
# the generated .go are committed, so clang is a contributor/CI dependency and
# never an operator one. `make build` must work on a box with nothing but Go.
# Commit the result — TestAllMapsMatchesObject and TestContractMatchesC fail
# until the object and the Go contract agree again.
dataplane-sync:
	@test -x "$(BPF_CLANG)" || { \
		echo "BPF_CLANG=$(BPF_CLANG) not found or not executable."; \
		echo "On macOS: brew install llvm@21 (Apple's clang has no bpf target)."; \
		exit 1; }
	BPF2GO_CC=$(BPF_CLANG) BPF2GO_STRIP=$(BPF_STRIP) go generate ./internal/dataplane/...

# Run the data-plane tests against a real kernel. The verifier is the whole
# risk in BPF work, and it only exists on Linux: `make test` on macOS skips the
# kernel-side cases, so this is the target that actually proves the program
# loads. Needs Docker (Desktop is fine) and runs privileged because loading an
# XDP program and BPF_PROG_TEST_RUN both want CAP_BPF/CAP_SYS_ADMIN. The repo
# root is mounted so the C/Go drift tests can read bpf/include/kapkan_maps.h.
#
# TWO packages, not one. internal/app is here because it owns the last hop —
# turning kapkan_rule_stats into the number on /api/v1/bans — and that hop is
# unreachable on the macOS loop: on a host with no kernel its Linux-only test
# does not even compile in. Everything else in internal/app still runs under
# `make test`; this adds the part that needs a datapath. Depends on console-sync
# because internal/app imports internal/api, which go:embeds the console.
dataplane-test: console-sync
	GOOS=linux GOARCH=$(BPF_TEST_ARCH) CGO_ENABLED=0 \
		go test -c -o .dataplane.test ./internal/dataplane/
	GOOS=linux GOARCH=$(BPF_TEST_ARCH) CGO_ENABLED=0 \
		go test -c -o .app.test ./internal/app/
	docker run --rm --privileged \
		-v "$(CURDIR)/..:/w" -w /w/engine/internal/dataplane \
		$(BPF_TEST_IMAGE) /w/engine/.dataplane.test -test.v
	docker run --rm --privileged \
		-v "$(CURDIR)/..:/w" -w /w/engine/internal/app \
		$(BPF_TEST_IMAGE) /w/engine/.app.test -test.v -test.run 'MeasuredDropsReachTheAPI'
	rm -f .dataplane.test .app.test

# Capacity numbers for the data plane, via the kernel's own PROG_TEST_RUN
# repeat loop. Same container as dataplane-test. The absolute figures depend on
# the host (on macOS this is a VM); the SCALING with rule count is the part
# that transfers.
dataplane-bench:
	GOOS=linux GOARCH=$(BPF_TEST_ARCH) CGO_ENABLED=0 \
		go test -c -o .dataplane.test ./internal/dataplane/
	docker run --rm --privileged \
		-v "$(CURDIR)/..:/w" -w /w/engine/internal/dataplane \
		$(BPF_TEST_IMAGE) /w/engine/.dataplane.test \
		-test.run '^$$' -test.bench . -test.benchtime $(BPF_BENCH_N)x
	rm -f .dataplane.test

clean:
	rm -f $(BINARY) .dataplane.test .app.test
	rm -rf internal/api/static
