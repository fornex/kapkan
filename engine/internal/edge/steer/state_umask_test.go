//go:build unix

package steer

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
)

// TestStoreModesIgnoreTheUmask: the steering directory is 0755 and its files
// 0644 whatever the umask of the process that writes first — an operator's
// `sudo kapkan edge -s drain` under a hardened umask, before the daemon's
// first start, included — so an unprivileged `-steer` (E7.2) sees every
// drain. A directory already there keeps its mode. The umask is the
// process's: no test in this package runs in parallel with this one.
func TestStoreModesIgnoreTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	s := storeNew(t)
	storeMust(t, s.SetDrain(NodeKey, Drain{Reason: "maintenance", Since: storeT0}))
	_, err := s.Birth(storeT0)
	storeMust(t, err)
	storeMust(t, s.SetDrain(storeVIP, Drain{Reason: "maintenance", Since: storeT0}))
	storeModes(t, s.Dir, map[string]fs.FileMode{
		".":                            0o755,
		drainFileName:                  0o644,
		drainFileName + "." + storeVIP: 0o644,
		newNodeFileName:                0o644,
		stateFileName:                  0o644,
	})

	kept := storeNew(t)
	storeMust(t, os.Mkdir(kept.Dir, 0o700))
	storeMust(t, kept.SetDrain(NodeKey, Drain{Reason: "maintenance", Since: storeT0}))
	storeModes(t, kept.Dir, map[string]fs.FileMode{".": 0o700, drainFileName: 0o644})
}
