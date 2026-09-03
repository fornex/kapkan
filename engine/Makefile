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
	dataplane-sync dataplane-test dataplane-bench dataplane-matrix \
	blockrate blockrate-fixtures edge-terminator-test

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

# GOOS values `make lint` type-checks. BOTH, always, on whichever host you are.
#
# golangci-lint type-checks ONE build configuration per run, so a `//go:build
# linux` file simply does not exist to a run on macOS — and a `//go:build
# !linux` file does not exist to a run on Linux. Neither host lints the whole
# tree, and until now neither did CI: the lint job runs on ubuntu, so
# manager_stub.go, inspect_other.go and installer_other.go had never been linted
# anywhere, and the ~5,000 lines of Linux-only data-plane test code had never
# been linted on the machine that writes them.
#
# That gap is how three findings (two ST1005, one unconvert) in
# internal/dataplane's Linux-only files got past `make lint` on the development
# host and were first reported by CI. Linting both directions costs a second
# type-check pass and removes the whole class.
LINT_GOOS ?= linux darwin

lint: console-sync
	@for goos in $(LINT_GOOS); do \
		echo "==> golangci-lint (GOOS=$$goos)"; \
		GOOS=$$goos golangci-lint run || exit 1; \
	done

# The edge decision service's numbers are here too: BenchmarkDecide (in-process
# floor) and BenchmarkDecideOverUnixSocket (the auth_request round trip edge-spec
# §5 asks to have measured, in µs/decision).
bench: console-sync
	go test -run '^$$' -bench . -benchmem ./internal/engine/... ./internal/edge/...

run-dev: build
	./$(BINARY) -config configs/dev.yaml -log-format text

# Regenerate the committed config schema from the Config struct. The drift gate
# (TestSchemaMatchesGenerated) fails the build until the result is committed.
# Depends on console-sync because cmd/kapkan go:embeds the console at compile.
schema: console-sync
	go run ./cmd/kapkan -dump-schema > ../docs/config-schema.json
	go run ./cmd/kapkan -dump-zones-schema > ../docs/zones-schema.json

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
# KAPKAN_DATAPLANE=require is what stops the skipping from following the tests
# in here. Every environment skip in internal/dataplane goes through one
# skipOrFail (see kernelgate_linux_test.go); under `require` it fails instead,
# and the suite additionally refuses to report success when implausibly few
# tests reached the kernel. Without it, a container that quietly stopped being
# privileged would turn this target into a fast, green no-op. Same knob and same
# reasoning as KAPKAN_BLOCKRATE=require below.
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
		-e KAPKAN_DATAPLANE=require \
		-v "$(CURDIR)/..:/w" -w /w/engine/internal/dataplane \
		$(BPF_TEST_IMAGE) /w/engine/.dataplane.test -test.v
	docker run --rm --privileged \
		-e KAPKAN_DATAPLANE=require \
		-v "$(CURDIR)/..:/w" -w /w/engine/internal/app \
		$(BPF_TEST_IMAGE) /w/engine/.app.test -test.v -test.run 'MeasuredDropsReachTheAPI'
	rm -f .dataplane.test .app.test
	$(MAKE) blockrate

# The pcap block-rate suite: the gate on every public pps/Gbps/percentage
# figure. It is a THIRD package (internal/mitigate) because it is the only one
# that can see the whole chain — detector, classifier, FlowSpec IR, kernel
# encoder, installer — without an import cycle. Same container, same kernel.
#
# -timeout is raised because detection is driven through the engine's REAL
# one-second evaluation loop: the window cannot be faked from outside the
# package, so a few seconds of wall clock is the price of not stubbing the
# detector out of its own regression suite.
blockrate: console-sync
	GOOS=linux GOARCH=$(BPF_TEST_ARCH) CGO_ENABLED=0 \
		go test -c -o .blockrate.test ./internal/mitigate/
	docker run --rm --privileged \
		-v "$(CURDIR)/..:/w" -w /w/engine/internal/mitigate \
		-e KAPKAN_BLOCKRATE=require \
		$(BPF_TEST_IMAGE) /w/engine/.blockrate.test \
		-test.v -test.timeout 10m -test.run 'TestPcapBlockRateSuite'
	rm -f .blockrate.test

# Boot 5.15, 6.1, 6.6 and 6.12 under QEMU and run the data-plane suite on each.
#
# `dataplane-test` above proves the program loads on WHATEVER kernel the host
# happens to run — 6.12 on Docker Desktop, whatever the CI runner ships. This
# target is the one that proves the DOCUMENTED FLOOR: the 5.15 in
# deploy/dataplane-operations.md, config.example.yaml and manager_stub.go's
# error string. See hack/kernel-matrix/README.md for how it works and why the
# macOS loop is slow (no /dev/kvm, so the guests run under TCG).
#
# Not a prerequisite of anything: it pulls ~50MB of guest kernel per version
# and takes tens of minutes without KVM. CI runs it per-kernel in parallel.
dataplane-matrix:
	./hack/kernel-matrix/run.sh

# Regenerate the committed pcap fixtures from the catalog. Like the BPF object,
# they are the artifact of record: committed, reviewed, and byte-compared by
# TestCommittedFixturesMatchTheCatalog on every run, on every host.
blockrate-fixtures:
	go run ./internal/blockrate/cmd/mkfixtures internal/blockrate/testdata

# The edge renderer against a real terminator. Renders every fixture zone set
# under internal/edge/render/testdata, runs the image's `nginx -t` on each, then
# SERVES the render and drives requests through it — the fail-open idiom
# (edge-spec §2.4) is proven here, on the binary, not by reading docs. Needs
# Docker; the decision-service arms need a Linux host (a unix socket does not
# cross a Docker Desktop bind mount) and are skipped on macOS. CI runs the
# three supported images; pass EDGE_TERMINATOR_IMAGE=nginx:1.22 for the floor
# or docker.angie.software/angie:latest for Angie.
EDGE_TERMINATOR_IMAGE ?= nginx:stable
edge-terminator-test:
	KAPKAN_EDGE_TERMINATOR=require KAPKAN_EDGE_TERMINATOR_IMAGE=$(EDGE_TERMINATOR_IMAGE) \
		go test -count=1 -v -run 'TestRealTerminator' ./internal/edge/render/

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
	rm -f $(BINARY) .dataplane.test .app.test .blockrate.test
	rm -rf internal/api/static
