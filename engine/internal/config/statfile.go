//go:build !js

package config

import "os"

// statFile reports file metadata for the geoip-database and exec-hook checks in
// validate(). On a normal (server) build it is os.Stat. The wasm build replaces
// it with a stub that defers these filesystem checks to the server (see
// statfile_js.go), so the in-browser config builder can validate everything a
// filesystem is not needed for.
func statFile(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
