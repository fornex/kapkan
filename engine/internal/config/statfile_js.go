//go:build js

package config

import "os"

// statFile cannot touch a real filesystem in the browser/wasm build, so it
// reports errStatDeferred. The validate() call sites treat that as "verified on
// the server at load", not a validation failure — so a config that only differs
// by an unreachable geoip path or exec hook still validates in the browser, and
// `kapkan -check-config` on the host remains the authoritative file check.
func statFile(path string) (os.FileInfo, error) {
	return nil, errStatDeferred
}
