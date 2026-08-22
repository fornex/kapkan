package exporter

// A deliberately small file tailer. The obvious dependency (a tail library)
// buys inotify at the price of a tree of transitive code in a binary whose
// dependency count is a stated feature; 200ms polling is indistinguishable
// from inotify at the timescales a DDoS verdict works on (whole seconds), and
// the rotation story is simpler to prove correct.
//
// Semantics: start at the END of the file (history is not evidence — a
// verdict must come from live traffic, and replaying an old log through the
// thresholds would re-block sources for attacks that ended hours ago), then
// deliver every complete appended line. Rotation is detected the way
// logrotate actually behaves: the inode changes (create-new) or the size
// shrinks (copytruncate). On rotation the NEW file is read from offset 0 —
// those lines are all fresh traffic.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"time"
)

const tailPollInterval = 200 * time.Millisecond

type tailer struct {
	path string
	f    *os.File
	r    *bufio.Reader
	off  int64
	ch   chan []byte
	// partial buffers an incomplete final line until its newline arrives —
	// nginx writes lines atomically, but the reader can still race the write.
	partial []byte
}

func newTailer(path string) (*tailer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &tailer{path: path, f: f, r: bufio.NewReader(f), off: off}, nil
}

func (t *tailer) close() { _ = t.f.Close() }

// lines returns the channel of complete lines, starting the pump on first
// use. One channel per tailer; Run is the only consumer.
func (t *tailer) lines(ctx context.Context) <-chan []byte {
	if t.ch == nil {
		t.ch = make(chan []byte, 1024)
		go t.pump(ctx)
	}
	return t.ch
}

func (t *tailer) pump(ctx context.Context) {
	defer close(t.ch)
	ticker := time.NewTicker(tailPollInterval)
	defer ticker.Stop()
	for {
		if err := t.drain(ctx); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.maybeReopen()
		}
	}
}

// drain reads everything currently appended, sending complete lines.
func (t *tailer) drain(ctx context.Context) error {
	for {
		chunk, err := t.r.ReadBytes('\n')
		t.off += int64(len(chunk))
		if len(chunk) > 0 && err == nil {
			line := chunk[:len(chunk)-1] // strip '\n'
			if len(t.partial) > 0 {
				line = append(t.partial, line...)
				t.partial = nil
			}
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			out := make([]byte, len(line))
			copy(out, line)
			select {
			case t.ch <- out:
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		// EOF mid-line: keep the fragment for the next drain.
		if len(chunk) > 0 {
			t.partial = append(t.partial, chunk...)
		}
		return nil
	}
}

// maybeReopen detects rotation and swaps to the new file. Errors are
// tolerated silently and retried next tick: a rotation window where the new
// file does not exist yet is ordinary.
//
// THE COPYTRUNCATE BOUND, stated rather than hidden: a truncation is
// detected by the size falling below the consumed offset, so a truncate
// whose file REGROWS past that offset within one poll interval is
// indistinguishable from ordinary growth (same inode, plausible size — the
// bytes are different, but a tailer that checksummed content would not be a
// small tailer). The consequence is bounded and self-healing: the lines
// written before the size caught up are missed, the first read lands
// mid-line and parses as garbage (counted, throttled-logged), and everything
// after flows normally. logrotate's default create-new mode has no such
// window — the inode changes — and is what the deployment docs recommend.
func (t *tailer) maybeReopen() {
	st, err := os.Stat(t.path)
	if err != nil {
		return
	}
	cur, err := t.f.Stat()
	if err == nil && os.SameFile(st, cur) && st.Size() >= t.off {
		return // same file, nothing rewound
	}
	// Rotated (new inode) or truncated (size shrank): reopen from the start —
	// everything in the new file is fresh traffic.
	f, err := os.Open(t.path)
	if err != nil {
		return
	}
	_ = t.f.Close()
	t.f, t.r, t.off, t.partial = f, bufio.NewReader(f), 0, nil
}
