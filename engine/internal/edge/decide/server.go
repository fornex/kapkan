package decide

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultSocketMode lets the terminator's worker user connect. The socket
	// lives in a kapkan-owned runtime directory; anyone who can reach it can
	// ask for verdicts about arbitrary sources, which is not a secret, and
	// cannot change anything.
	DefaultSocketMode = 0o666

	headerZone   = "X-Kapkan-Zone"
	headerClient = "X-Kapkan-Client"
	headerMark   = "X-Kapkan-Mark"
	decidePath   = "/decide"
)

// Server answers nginx's auth_request subrequests over a unix socket.
type Server struct {
	Service *Service
	// Path is the socket; the renderer's Node.DecideSocket must name the same.
	Path string
	// Mode is the socket's permission bits; 0 means DefaultSocketMode.
	Mode   os.FileMode
	Logger *slog.Logger
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
	if v.Allow {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

// ListenAndServe serves on the unix socket until ctx is done, then removes
// it. A stale socket file from a previous process is replaced.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Path == "" {
		return errors.New("decide: no socket path")
	}
	log := s.Logger
	if log == nil {
		log = slog.Default()
	}
	_ = os.Remove(s.Path)
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	mode := s.Mode
	if mode == 0 {
		mode = DefaultSocketMode
	}
	if err := os.Chmod(s.Path, mode); err != nil {
		_ = ln.Close()
		return err
	}
	srv := &http.Server{
		Handler: s.Handler(),
		// nginx's subrequest timeouts are 50/100/200 ms; a header that has not
		// arrived in two seconds is not nginx.
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("decision service listening", "socket", s.Path)
	err = srv.Serve(ln)
	_ = os.Remove(s.Path)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
