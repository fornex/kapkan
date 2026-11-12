//go:build !linux

package steer

import (
	"errors"
	"net/netip"
)

// procIfaddrs4 is Linux's (proc_ifconf_linux.go). Elsewhere it fails, and a
// Tick asks fib_trie, which such a host does not have either: unknown holds.
func procIfaddrs4() ([]netip.Addr, error) {
	return nil, errors.New("steer: the interface address list (SIOCGIFCONF) is read on Linux only")
}
