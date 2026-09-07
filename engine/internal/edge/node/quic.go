package node

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// quicHostKeyLen is the host key's size: 32 random bytes, the same shape
// nginx generates itself when no quic_host_key is set.
const quicHostKeyLen = 32

// ensureQUICHostKey creates the terminator's QUIC host key once — 32 random
// bytes, 0600 under state_dir/tls (0700) — and leaves an existing one alone,
// so the Retry and stateless-reset tokens nginx derives from it survive both
// a reload and a restart of the node. Without a key file nginx would mint a
// fresh random key on every reload, voiding every token handed out — and a
// client that already took one Retry may not accept another (RFC 9000), so
// it would fall back to TCP exactly when the node reloads under load.
// Written whether or not this node renders QUIC: the render names the file
// only when it does, and the bytes cost nothing.
func (n *Node) ensureQUICHostKey() error {
	path := n.files.quicHostKey
	if st, err := os.Stat(path); err == nil {
		if st.Size() == 0 {
			return fmt.Errorf("%s exists and is empty; remove it to have a new key minted", path)
		}
		if st.Mode().Perm() != 0o600 {
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	key := make([]byte, quicHostKeyLen)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	n.log.Info("QUIC host key created", "path", path)
	return nil
}

// udpListeningFn is udpListening, a variable so tests can stand in for /proc.
var udpListeningFn = udpListening

// udpListening reports whether any socket on this box is bound to the UDP
// port, in either address family, from /proc/net/udp and /proc/net/udp6 —
// the local half of "is the QUIC listener up?". nil where neither file can
// be read (not Linux, or /proc not mounted).
func udpListening(port int) *bool {
	readable := false
	found := false
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		readable = true
		sc := bufio.NewScanner(f)
		sc.Scan() // the header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			_, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if p, err := strconv.ParseUint(hexPort, 16, 16); err == nil && int(p) == port {
				found = true
			}
		}
		_ = f.Close()
	}
	if !readable {
		return nil
	}
	return &found
}
