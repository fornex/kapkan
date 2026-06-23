// Package buildinfo exposes the binary's version, set at link time for release
// builds and falling back to the Go build info otherwise. The version drives the
// /api/v1/status "version" field, the console Settings view and the upcoming
// update-availability check, so it must be accurate across every build path:
//
//   - GoReleaser / Makefile inject the real value with
//     -ldflags "-X github.com/kapkan-io/kapkan/internal/buildinfo.version=v1.5.0 ...";
//   - `go install github.com/kapkan-io/kapkan/...@vX.Y.Z` reports its module tag;
//   - a plain `go build` of a checkout reports "(devel)" plus the VCS revision.
//
// -trimpath (used by the release build) does not strip VCS stamping, but a build
// from outside a VCS checkout has none — which is exactly why release builds
// inject the values explicitly rather than relying on the fallback.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Set at link time via -ldflags -X. Left empty for non-release builds, where
// resolved() fills them from debug.ReadBuildInfo().
var (
	version string
	commit  string
	date    string
)

type info struct{ version, commit, date string }

// resolved merges the link-time values with the embedded build info exactly
// once: injected values always win, the module tag fills an unstamped version,
// and the VCS settings fill an unstamped commit/date. Build info is static for
// the process lifetime, so the result is cached.
var resolved = sync.OnceValue(func() info {
	out := info{version: version, commit: commit, date: date}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		if out.version == "" {
			out.version = "unknown"
		}
		return out
	}
	if out.version == "" {
		if out.version = bi.Main.Version; out.version == "" {
			out.version = "(devel)"
		}
	}
	if out.commit == "" || out.date == "" {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if out.commit == "" {
					out.commit = shortRev(s.Value)
				}
			case "vcs.time":
				if out.date == "" {
					out.date = s.Value
				}
			}
		}
	}
	return out
})

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// Version returns the release version (e.g. "v1.5.0"), or "(devel)"/"unknown"
// for an unstamped build.
func Version() string { return resolved().version }

// Commit returns the short VCS revision, or "" when unknown.
func Commit() string { return resolved().commit }

// Date returns the build/commit date, or "" when unknown.
func Date() string { return resolved().date }

// String renders a one-line human version for `kapkan -version`, e.g.
// "v1.5.0 (revision a1b2c3d4e5f6, go1.26.4, linux/amd64)".
func String() string {
	r := resolved()
	parts := make([]string, 0, 3)
	if r.commit != "" {
		parts = append(parts, "revision "+r.commit)
	}
	parts = append(parts, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
	return r.version + " (" + strings.Join(parts, ", ") + ")"
}
