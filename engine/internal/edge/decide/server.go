package decide

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/unixsock"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultSocketMode is owner and group only. Asking for a verdict is NOT
	// side-effect free — it spends the named source's tokens and opens an
	// in-flight slot — so the socket must be reachable by the terminator's
	// worker (its group, via SocketGroup) and by nobody else on the box.
	DefaultSocketMode = 0o660

	headerZone   = "X-Kapkan-Zone"
	headerClient = "X-Kapkan-Client"
	headerMark   = "X-Kapkan-Mark"
	headerReason = "X-Kapkan-Reason"
	decidePath   = "/decide"

	// maxHeaderBytes is what one subrequest may carry. The renderer forwards
	// only its own headers (proxy_pass_request_headers off), so this is
	// generous by an order of magnitude; it must never be below what nginx
	// can send, or a client could push the decision off the contract.
	maxHeaderBytes = 256 << 10
)

// Server answers nginx's auth_request subrequests over a unix socket.
type Server struct {
	Service *Service
	// Path is the socket; the renderer's Node.DecideSocket must name the same.
	Path string
	// Mode is the socket's permission bits; 0 means DefaultSocketMode.
	Mode os.FileMode
	// SocketGroup is the group the socket is chowned to — the terminator's
	// worker group (nginx, www-data, angie) — so that DefaultSocketMode admits
	// it. "" leaves the group as created.
	SocketGroup string
	Logger      *slog.Logger
}

// Handler is the HTTP side of the contract, for tests and for embedding.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != decidePath {
		http.NotFound(w, r)
		return
	}
	zone := r.Header.Get(headerZone)
	src, err := netip.ParseAddr(r.Header.Get(headerClient))
	if zone == "" || err != nil {
		// Off the contract: the renderer always sets both. auth_request turns
		// this into a failed decision, which the zone's failure_mode handles.
		metrics.EdgeDecisionsTotal.WithLabelValues("unknown", "bad_request").Inc()
		http.Error(w, "X-Kapkan-Zone and X-Kapkan-Client are required", http.StatusBadRequest)
		return
	}
	v := s.Service.Decide(zone, src.Unmap())
	if v.Mark != "" {
		w.Header().Set(headerMark, v.Mark)
	}
	if v.Denied() {
		w.Header().Set(headerReason, v.Reason)
	}
	if v.Allow {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

// ListenAndServe serves on the unix socket until ctx is done, then removes
// it. A stale socket file from a dead process is replaced; a socket another
// live process serves is refused, not stolen.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Path == "" {
		return errors.New("decide: no socket path")
	}
	log := s.Logger
	if log == nil {
		log = slog.Default()
	}
	mode := s.Mode
	if mode == 0 {
		mode = DefaultSocketMode
	}
	gid, err := groupID(s.SocketGroup)
	if err != nil {
		return fmt.Errorf("decide: %w", err)
	}
	ln, release, err := unixsock.Listen("unix", s.Path, mode, gid)
	if err != nil {
		return fmt.Errorf("decide: %w", err)
	}
	srv := &http.Server{
		Handler: s.Handler(),
		// nginx's subrequest timeouts are 50/100/200 ms; a header that has not
		// arrived in two seconds is not nginx.
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("decision service listening", "socket", s.Path, "mode", fmt.Sprintf("%o", mode), "group", s.SocketGroup)
	err = srv.Serve(ln.(net.Listener))
	release()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// groupID resolves a group name (or numeric id) to a gid; "" means -1 (keep).
func groupID(name string) (int, error) {
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
