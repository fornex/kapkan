//go:build !linux

package steer

import "syscall"

// probeFreebind does nothing off Linux: IP_FREEBIND is Linux's, and so are
// the IPv6 AnyIP ranges it is set for (probe_linux.go).
func probeFreebind(string, syscall.RawConn) error { return nil }
