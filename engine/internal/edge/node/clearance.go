package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/unixsock"
)

// serveClearance holds the fourth socket — the clearance page the renderer
// points every decide-mode zone at (upstream kapkan_clearance) — so that the
// rendered configuration always has something to connect to. Until E4.3
// lands the page itself, it answers 503 with no-store: nginx's
// proxy_intercept_errors turns that into the zone's failure_mode (open →
// the origin, undecided; closed → 503), exactly what a dead page server
// would get, so a zone switched to challenge on a node without the page
// degrades predictably rather than hanging. Same socket contract as the
// decision service: 0660, the terminator's worker group.
func (n *Node) serveClearance(ctx context.Context) error {
	gid, err := unixsock.GroupID(n.opt.SocketGroup)
	if err != nil {
		return fmt.Errorf("clearance socket: %w", err)
	}
	sock, release, err := unixsock.Listen("unix", n.files.clearanceSock, 0o660, gid)
	if err != nil {
		return fmt.Errorf("clearance socket: %w", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "the clearance page is not available on this node", http.StatusServiceUnavailable)
		}),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	n.log.Info("clearance page listening", "socket", n.files.clearanceSock, "mode", "660", "group", n.opt.SocketGroup)
	err = srv.Serve(sock.(net.Listener))
	release()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
