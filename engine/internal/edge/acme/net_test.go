package acme

import (
	"context"
	"net"
)

// Small aliases so the unix-socket client in the tests reads plainly.
type netConn = net.Conn

func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
