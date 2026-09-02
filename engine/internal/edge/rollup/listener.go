package rollup

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultSocketMode lets the terminator's worker user send to the socket.
	DefaultSocketMode = 0o666
	// DefaultReadBuffer is the receive queue asked of the kernel: a burst of
	// log lines while the reader is busy must not be dropped at once.
	DefaultReadBuffer = 4 << 20
	// maxDatagram bounds one log line. nginx's syslog transport does not cap
	// an access-log line at any documented size; 64 KiB is well above any
	// request line plus user agent the renderer's format can produce.
	maxDatagram = 64 << 10
)

// Listener receives the terminator's access-log datagrams.
type Listener struct {
	// Path is the unix datagram socket; the renderer's Node.LogSocket must
	// name the same.
	Path string
	// Mode is the socket's permission bits; 0 means DefaultSocketMode.
	Mode os.FileMode
	// ReadBuffer is the kernel receive buffer; 0 means DefaultReadBuffer.
	ReadBuffer int
	// Handle receives every well-formed record, in arrival order, on the
	// listener's goroutine.
	Handle func(Record)
	Logger *slog.Logger
}

// Run receives until ctx is done, then removes the socket. A stale socket
// file from a previous process is replaced.
func (l *Listener) Run(ctx context.Context) error {
	if l.Path == "" {
		return errors.New("rollup: no socket path")
	}
	log := l.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "edge-rollup")
	_ = os.Remove(l.Path)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: l.Path, Net: "unixgram"})
	if err != nil {
		return err
	}
	mode := l.Mode
	if mode == 0 {
		mode = DefaultSocketMode
	}
	if err := os.Chmod(l.Path, mode); err != nil {
		_ = conn.Close()
		return err
	}
	rb := l.ReadBuffer
	if rb <= 0 {
		rb = DefaultReadBuffer
	}
	if err := conn.SetReadBuffer(rb); err != nil {
		log.Warn("could not raise the log socket's receive buffer", "err", err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	log.Info("access-log listener ready", "socket", l.Path)

	buf := make([]byte, maxDatagram)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			_ = os.Remove(l.Path)
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
		metrics.EdgeLogRecordsTotal.WithLabelValues("ok").Inc()
		if l.Handle != nil {
			l.Handle(rec)
		}
	}
}
