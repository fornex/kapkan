// Package dataplane loads and drives Kapkan's XDP mitigation executor.
//
// The kernel side lives in engine/bpf (see engine/bpf/README.md). This package
// owns the Go half: the generated bindings, the map encoders, and — in later
// revisions — the manager that attaches the program, installs rules and flips
// generations.
//
// # Charter
//
// The data plane EXECUTES decisions made elsewhere. It never classifies, and
// its default verdict is always XDP_PASS. Nothing in this package may
// introduce a default-deny.
//
// # Regenerating
//
// Run `make dataplane-sync` from engine/. It sets BPF2GO_CC and BPF2GO_STRIP
// to the Homebrew LLVM that actually has a bpf target (Apple's clang does not)
// and then runs `go generate`. Do not run `go generate ./internal/dataplane`
// directly unless those variables are already exported — bpf2go defaults to
// plain `clang`, which on macOS is Apple's and will fail with "unknown target
// 'bpf'".
//
// The generated .o and .go are COMMITTED. clang is a contributor/CI
// dependency, never an operator one: `make build` and `make test` must work on
// a machine with nothing but Go installed.
package dataplane

// bpf2go, not "clang + go:embed", and the reasons in order of weight:
//
//  1. It derives Go struct declarations from the object's BTF. The C structs in
//     kapkan_maps.h are freeze point F6 and the Go encoder must agree with them
//     byte for byte; hand-written mirrors are exactly the kind of thing that
//     drifts silently and then drops a customer's traffic. With bpf2go, a field
//     added in C shows up as a compile error in Go on the next regeneration
//     rather than as a misaligned map value at 3am.
//  2. It emits a typed loader (kapkanXDPObjects) with one field per map and per
//     program, so a renamed or deleted map is a Go compile error instead of a
//     nil map at attach time.
//  3. go:embed of a hand-compiled .o gives none of that: it hands you a []byte
//     and you write the same LoadCollectionSpec/AssignTo boilerplate by hand,
//     plus the struct mirrors, plus your own drift gate.
//
// What bpf2go costs us: it insists on compiling the C itself, so the exact
// clang invocation lives here in the -- flags rather than in the Makefile.
// They are kept identical to the line in engine/bpf/README.md, and
// TestObjectCompiledFlagsMatchREADME is not a thing we have — the Makefile is
// the single caller, so there is one place to change.
//
// -target bpfel only: Kapkan's supported deployment targets (amd64, arm64) are
// both little-endian, and a bpfeb object would be dead weight in the binary.
// The generated file's build constraint keeps it out of big-endian builds, and
// the loader returns a clear error there rather than mis-parsing.
//
// -mcpu=v2 holds the kernel floor at 5.15: v3 emits jump-32 and
// zero-extension instructions that older verifiers reject.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -output-stem kapkanxdp -type kapkan_rule -type kapkan_policy_block -type kapkan_profile -type kapkan_bucket -type kapkan_config -type kapkan_counter -type kapkan_lpm_key_v4 -type kapkan_lpm_key_v6 -type kapkan_rl_key_v4 -type kapkan_rl_key_v6 -type kapkan_fp_event kapkanXDP ../../bpf/kapkan_xdp.c -- -I../../bpf/include -O2 -g -Wall -Werror -mcpu=v2
