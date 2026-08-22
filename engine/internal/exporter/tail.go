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
	// pumpStarted hands ownership of f to the pump goroutine: after lines()
	// launches it, only the pump may touch f (close() becomes its job too —
	// a deferred close from the consumer racing maybeReopen's swap is a real
	// TSan finding, not a theoretical one).
	pumpStarted bool
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

// close releases the file — but only before the pump exists. Once the pump
// runs, IT owns f (maybeReopen swaps it), and it closes the current f on its
// own way out; a second closer would be the data race this comment replaces.
func (t *tailer) close() {
	if !t.pumpStarted {
		_ = t.f.Close()
	}
}

// lines returns the channel of complete lines, starting the pump on first
// use. One channel per tailer; Run is the only consumer.
func (t *tailer) lines(ctx context.Context) <-chan []byte {
	if t.ch == nil {
		t.ch = make(chan []byte, 1024)
		t.pumpStarted = true
		go t.pump(ctx)
	}
	return t.ch
}

func (t *tailer) pump(ctx context.Context) {
	defer close(t.ch)
	defer func() { _ = t.f.Close() }()
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
			if f := t.detectRotation(); f != nil {
				// FINAL DRAIN of the old fd before the swap: the renamed
				// inode is still fully readable through it, and the lines
				// nginx appended since our last read are evidence like any
				// other. Losing them silently was a reviewed-and-confirmed
				// bug, not a hypothetical.
				if err := t.drain(ctx); err != nil {
					_ = f.Close()
					return
				}
				t.swapTo(f)
			}
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

// detectRotation reports rotation by returning the freshly opened NEW file
// (nil when nothing rotated). Errors are tolerated silently and retried next
// tick: a rotation window where the new file does not exist yet is ordinary.
// The caller drains the OLD fd to EOF before swapping, so a create-new
// rotation loses nothing that reached the old inode before the swap; what it
// can still miss is bounded and honest — lines nginx keeps appending to the
// renamed inode AFTER our swap, until nginx itself reopens on logrotate's
// signal. That gap is logrotate's postrotate latency, typically milliseconds.
//
// THE COPYTRUNCATE BOUND, stated rather than hidden: a truncation is
// detected by the size falling below the consumed offset, so a truncate
// whose file REGROWS past that offset within one poll interval is
// indistinguishable from ordinary growth (same inode, plausible size — the
// bytes are different, but a tailer that checksummed content would not be a
// small tailer). The consequence is bounded and self-healing: the lines
// written before the size caught up are missed, the first read lands
// mid-line and parses as garbage (counted, throttled-logged), and everything
// after flows normally. Prefer logrotate's default create-new mode.
func (t *tailer) detectRotation() *os.File {
	st, err := os.Stat(t.path)
	if err != nil {
		return nil
	}
	cur, err := t.f.Stat()
	if err == nil && os.SameFile(st, cur) && st.Size() >= t.off {
		return nil // same file, nothing rewound
	}
	f, err := os.Open(t.path)
	if err != nil {
		return nil
	}
	return f
}

// swapTo moves the tailer onto the new file, from its start — everything in
// it is fresh traffic. The partial from the old file is dropped: its
// terminating newline lives in an inode nobody reads anymore, and gluing it
// to the new file's first line would fabricate a request that never happened.
func (t *tailer) swapTo(f *os.File) {
	_ = t.f.Close()
	t.f, t.r, t.off, t.partial = f, bufio.NewReader(f), 0, nil
}
