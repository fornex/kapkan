// Package unixsock creates the edge's unix sockets the same careful way
// everywhere: a stale socket file is replaced, a socket another live process
// serves is refused rather than stolen, the mode and group are set before
// anyone may connect, and at exit only the file this process created is
// removed — never a successor's.
package unixsock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"
)

// probeTimeout bounds the liveness probe of an existing socket file.
const probeTimeout = 200 * time.Millisecond

// GroupID resolves a group name or numeric id to a gid for Listen; "" means
// -1 (keep the created group).
func GroupID(name string) (int, error) {
	if name == "" {
		return -1, nil
	}
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, fmt.Errorf("socket group %q: %w", name, err)
	}
	return strconv.Atoi(g.Gid)
}

// Listen binds a unix socket at path — network "unix" (stream, returned as a
// net.Listener) or "unixgram" (datagram, returned as a *net.UnixConn) — with
// the given mode and group (gid -1 keeps the created group). The release
// function closes the socket and removes the path if it is still ours.
func Listen(network, path string, mode os.FileMode, gid int) (sock any, release func(), err error) {
	if err := refuseIfServed(network, path); err != nil {
		return nil, nil, err
	}
	_ = os.Remove(path)
	var closer func() error
	switch network {
	case "unix":
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, nil, err
		}
		sock, closer = ln, ln.Close
	case "unixgram":
		conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			return nil, nil, err
		}
		sock, closer = conn, conn.Close
	default:
		return nil, nil, fmt.Errorf("unixsock: unsupported network %q", network)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = closer()
		_ = os.Remove(path)
		return nil, nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = closer()
			_ = os.Remove(path)
			return nil, nil, fmt.Errorf("chown %s to gid %d: %w", path, gid, err)
		}
	}
	ours, err := os.Lstat(path)
	if err != nil {
		_ = closer()
		return nil, nil, err
	}
	release = func() {
		_ = closer()
		// A successor may have replaced the path while we were shutting
		// down; unlink only what is still our socket.
		if cur, err := os.Lstat(path); err == nil && os.SameFile(cur, ours) {
			_ = os.Remove(path)
		}
	}
	return sock, release, nil
}

// refuseIfServed returns an error when a live process serves the socket at
// path. A stale file (nobody listening) passes. For a stream socket a connect
// succeeding means someone is listening; for a datagram socket, connect
// succeeds only when a bound receiver exists.
func refuseIfServed(network, path string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	d := net.Dialer{Timeout: probeTimeout}
	conn, err := d.Dial(network, path)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s is already served by another process; refusing to replace it", path)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return nil
	}
	return nil
}
