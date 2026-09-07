package node

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
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
// only when it does, and the bytes cost nothing. The write is durable
// (fsync + directory fsync), because the applied configuration names this
// file and nginx refuses a zero-length host key: a torn first mint would
// wedge both nginx and the node until an operator cleared it.
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
	if err := writeSecretFileSynced(path, key); err != nil {
		return err
	}
	n.log.Info("QUIC host key created", "path", path)
	return nil
}

// writeSecretFileSynced writes content to path 0600 durably: a temp file
// opened O_EXCL (so a second process cannot share the .tmp name), written,
// fsynced and renamed into place, then the directory fsynced — so a crash
// leaves either the old file or the whole new one, never a zero-length husk.
func writeSecretFileSynced(path string, content []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(content); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// udpListeningFn is udpListening, a variable so tests can stand in for /proc.
var udpListeningFn = udpListening

// udpListening reports whether any socket on this box is bound to the UDP
// port, in either address family, from /proc/net/udp and /proc/net/udp6 —
// the local half of "is the QUIC listener up?". nil where neither file can
// be read (not Linux, or /proc not mounted).
func udpListening(port int) *bool {
	return udpListeningIn([]string{"/proc/net/udp", "/proc/net/udp6"}, port)
}

// udpListeningIn is udpListening over explicit paths, for tests. nil when no
// path could be read at all; otherwise whether the port appears in any.
func udpListeningIn(paths []string, port int) *bool {
	readable := false
	found := false
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		readable = true
		if udpTableListens(f, port) {
			found = true
		}
		_ = f.Close()
	}
	if !readable {
		return nil
	}
	return &found
}

// udpTableListens scans one /proc/net/udp{,6} table for a local socket on the
// port. The local address is the second column, "<hex addr>:<hex port>".
func udpTableListens(r io.Reader, port int) bool {
	sc := bufio.NewScanner(r)
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
			return true
		}
	}
	return false
}
