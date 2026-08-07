//go:build !linux

package dataplane

import "testing"

// Non-Linux stub for smoke_linux_test.go. eBPF is a Linux kernel facility, so
// the kernel-side tests cannot run on the macOS development host — but
// `go test ./...` must still pass there, and a developer who breaks the
// datapath deserves a pointer to the loop that would have caught it rather
// than silence.
//
// The parts of the contract that CAN be checked without a kernel — the C/Go
// drift gate and the map set in the committed ELF — live in contract_test.go
// with no build tag, and do run here.
func TestSmokeRequiresLinux(t *testing.T) {
	t.Skip("XDP smoke tests need a Linux kernel; see the recipe at the top of " +
		"smoke_linux_test.go (cross-compile the test binary, run it in Docker)")
}
