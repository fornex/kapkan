package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/unixsock"
)

// DefaultSocketMode lets the terminator's worker connect: the socket answers
// public challenge tokens and nothing else, so it needs no group restriction.
const DefaultSocketMode = 0o666

// ChallengeServer serves the ChallengeTable on the unix socket the renderer's
// Node.ChallengeSocket names (the same shape as the decision service's).
type ChallengeServer struct {
	Table *ChallengeTable
	Path  string
	// Mode is the socket's file mode; 0 means DefaultSocketMode. A
	// group-restricted mode (0660) needs SocketGroup, or the terminator's
	// worker — which runs as a different user under the shipped unit —
	// cannot connect and no challenge is ever answered.
	Mode os.FileMode
	// SocketGroup is the group the socket is chowned to (the terminator's
	// worker group); "" keeps the process's group.
	SocketGroup string
	Logger      *slog.Logger
}

// ListenAndServe serves until ctx is done, then removes the socket. A stale
// socket file from a previous process is replaced; one another process still
// serves is refused.
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
	mode := s.Mode
	if mode == 0 {
		mode = DefaultSocketMode
	}
	gid, err := unixsock.GroupID(s.SocketGroup)
	if err != nil {
		return fmt.Errorf("acme: challenge socket: %w", err)
	}
	if mode&0o006 == 0 && gid < 0 {
		return errors.New("acme: a group-only challenge socket needs a socket group, or the terminator's worker cannot connect")
	}
	sock, release, err := unixsock.Listen("unix", s.Path, mode, gid)
	if err != nil {
		return fmt.Errorf("acme: challenge socket: %w", err)
	}
	ln := sock.(net.Listener)
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
	log.Info("acme challenge answerer listening", "socket", s.Path, "mode", fmt.Sprintf("%o", mode), "group", s.SocketGroup)
	err = srv.Serve(ln)
	release()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
