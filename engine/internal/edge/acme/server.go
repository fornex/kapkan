package acme

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// DefaultSocketMode lets the terminator's worker user connect; the socket
// answers public challenge tokens and nothing else.
const DefaultSocketMode = 0o666

// ChallengeServer serves the ChallengeTable on the unix socket the renderer's
// Node.ChallengeSocket names (the same shape as the decision service's).
type ChallengeServer struct {
	Table  *ChallengeTable
	Path   string
	Mode   os.FileMode
	Logger *slog.Logger
}

// ListenAndServe serves until ctx is done, then removes the socket. A stale
// socket file from a previous process is replaced.
func (s *ChallengeServer) ListenAndServe(ctx context.Context) error {
	if s.Path == "" {
		return errors.New("acme: no challenge socket path")
	}
	if s.Table == nil {
		return errors.New("acme: no challenge table")
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
		Handler:           s.Table.Handler(),
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
	log.Info("acme challenge answerer listening", "socket", s.Path)
	err = srv.Serve(ln)
	_ = os.Remove(s.Path)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
