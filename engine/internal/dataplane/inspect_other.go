//go:build !linux

package dataplane

// The non-Linux InspectPins, for the same reason manager_stub.go exists: so the
// one caller — cmd/kapkan's `dataplane status` — has a single code path on every
// host, and so the whole rendering half of that command compiles and is tested
// on the macOS development host.
//
// It refuses rather than returning an empty Inspection. An empty Inspection
// would render as "no pin path: the data plane has never run here", which on a
// Mac is a true sentence with a completely misleading implication.

import (
	"fmt"
	"runtime"
)

// InspectPins always fails with ErrUnsupported, naming the platform.
func InspectPins(dir string) (Inspection, error) {
	return Inspection{PinPath: dir}, fmt.Errorf(
		"%w (this binary is %s/%s), so there are no pinned maps to read; "+
			"run `kapkan dataplane status` on the Linux host itself",
		ErrUnsupported, runtime.GOOS, runtime.GOARCH)
}
