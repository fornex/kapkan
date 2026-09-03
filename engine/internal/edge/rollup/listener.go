package rollup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/kapkan-io/kapkan/internal/edge/unixsock"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultSocketMode is owner and group only: anyone who can write to this
	// socket can forge access-log lines, and forged lines drive the flood rule
	// into denying a source of the forger's choosing. The terminator's worker
	// group (SocketGroup) is the one writer meant to reach it.
	DefaultSocketMode = 0o660
	// maxDatagram bounds one log line. nginx's syslog transport does not cap
	// an access-log line at any documented size; 64 KiB is well above any
	// request line plus user agent the renderer's format can produce.
	maxDatagram = 64 << 10
	// queueDepth is how many parsed records may wait for Handle before the
	// listener starts dropping (and counting) instead of falling behind on
	// the socket, where the kernel would drop silently.
	queueDepth = 8192
	// minDgramQlen is the net.unix.max_dgram_qlen a node should run with. The
	// kernel default of 10 datagrams means any burst of eleven log lines while
	// the reader is between reads loses one; systemd sets 512 at boot, a
	// container without systemd does not.
	minDgramQlen = 512
)

// Listener receives the terminator's access-log datagrams.
type Listener struct {
	// Path is the unix datagram socket; the renderer's Node.LogSocket must
	// name the same.
	Path string
	// Mode is the socket's permission bits; 0 means DefaultSocketMode.
	Mode os.FileMode
	// SocketGroup is the group the socket is chowned to (the terminator's
	// worker group). "" leaves the group as created.
	SocketGroup string
	// Handle receives every well-formed record of a known zone, in arrival
	// order, on the listener's worker goroutine.
	Handle func(Record)
	Logger *slog.Logger
}

// Run receives until ctx is done, then removes the socket. A stale socket
// file from a dead process is replaced; one a live process serves is refused.
func (l *Listener) Run(ctx context.Context) error {
	if l.Path == "" {
		return errors.New("rollup: no socket path")
	}
	log := l.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "edge-rollup")
	mode := l.Mode
	if mode == 0 {
		mode = DefaultSocketMode
	}
	gid := -1
	if l.SocketGroup != "" {
		g, err := lookupGID(l.SocketGroup)
		if err != nil {
			return fmt.Errorf("rollup: %w", err)
		}
		gid = g
	}
	sock, release, err := unixsock.Listen("unixgram", l.Path, mode, gid)
	if err != nil {
		return fmt.Errorf("rollup: %w", err)
	}
	conn := sock.(*net.UnixConn)
	defer release()
	warnDgramQlen(log)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	log.Info("access-log listener ready", "socket", l.Path, "mode", fmt.Sprintf("%o", mode), "group", l.SocketGroup)

	// Parsing and handling happen off the socket goroutine, behind a bounded
	// queue: the reader must never be the reason the kernel queue fills.
	queue := make(chan Record, queueDepth)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for rec := range queue {
			if l.Handle != nil {
				l.Handle(rec)
			}
		}
	}()

	buf := make([]byte, maxDatagram)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			close(queue)
			<-done
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n == len(buf) {
			// A datagram at least as large as the buffer was truncated by the
			// kernel; its JSON is not trustworthy.
			metrics.EdgeLogRecordsTotal.WithLabelValues("oversized").Inc()
			continue
		}
		rec, err := Parse(buf[:n])
		if err != nil {
			metrics.EdgeLogRecordsTotal.WithLabelValues("malformed").Inc()
			continue
		}
		select {
		case queue <- rec:
			metrics.EdgeLogRecordsTotal.WithLabelValues("ok").Inc()
		default:
			metrics.EdgeLogRecordsTotal.WithLabelValues("dropped").Inc()
		}
	}
}

// warnDgramQlen reads the kernel's unix datagram queue length and warns when
// it is below what a busy terminator needs. Linux only; elsewhere silent.
func warnDgramQlen(log *slog.Logger) {
	if runtime.GOOS != "linux" {
		return
	}
	raw, err := os.ReadFile("/proc/sys/net/unix/max_dgram_qlen")
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return
	}
	if n < minDgramQlen {
		log.Warn("net.unix.max_dgram_qlen is low; access-log datagrams will be dropped under load",
			"value", n, "recommended", minDgramQlen, "sysctl", "net.unix.max_dgram_qlen="+strconv.Itoa(minDgramQlen))
	}
}

func lookupGID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, fmt.Errorf("socket group %q: %w", name, err)
	}
	return strconv.Atoi(g.Gid)
}
