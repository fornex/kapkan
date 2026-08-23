// Package fpplane is the userspace half of the E2 fingerprint plane: it drains
// the datapath's copy ring (kapkan_fp_events), computes JA4 for each captured
// handshake, and source-blocks a client whose JA4 is on the operator's
// blocklist. The kernel COPIES; this package CLASSIFIES; enforcement is the
// existing source-block path (mitigate.BlockSource → an XDP source block). It
// never forwards or holds client bytes beyond the sampled handshake prefix.
//
// Off-path and fail-open: a dead or slow reader simply stops classifying —
// nothing here is on the packet's verdict path, and a full ring drops copies in
// the kernel rather than stalling traffic. Every enforcement action is a TTL'd,
// audited source block, so a misfire ages out on its own.
package fpplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/fingerprint"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// Blocker enforces a classified verdict at the cheapest layer — an XDP source
// block. It is exactly mitigate.Mitigator.BlockSource minus the returned record,
// so the daemon adapts the mitigator to it without this package importing
// mitigate. An error (allowlisted/protected source, full policy block, absent
// data plane) is logged and counted, never fatal.
type Blocker func(victim, source netip.Addr, ttl time.Duration, reason string) error

// Policy is the hot-reloadable half the reader consults per matched event: the
// JA4 set to block and the lifetime of a block. The daemon rebuilds it from the
// live config, so editing the blocklist takes effect on the next handshake with
// no restart.
type Policy struct {
	// Blocklist maps a JA4 string to nothing; membership means "source-block".
	Blocklist map[string]struct{}
	// TTL is how long a JA4-triggered source block lives before it must refresh.
	TTL time.Duration
}

// Reader drains one fingerprint ring and enforces the JA4 blocklist.
type Reader struct {
	rd     *ringbuf.Reader
	block  Blocker
	policy func() Policy
	log    *slog.Logger
}

// New opens a ring reader over the fingerprint events map. policy is called once
// per classified handshake and must be cheap and safe for concurrent use with
// config reloads; block enforces a match.
func New(ring *ebpf.Map, block Blocker, policy func() Policy, log *slog.Logger) (*Reader, error) {
	if ring == nil {
		return nil, errors.New("fpplane: nil fingerprint ring map")
	}
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		return nil, fmt.Errorf("fpplane: open ring reader: %w", err)
	}
	return &Reader{rd: rd, block: block, policy: policy, log: log}, nil
}

// Run drains the ring until Close is called (or ctx is cancelled). It blocks, so
// the daemon runs it in a goroutine. Read errors other than a closed ring are
// transient and logged; the loop continues.
func (r *Reader) Run(ctx context.Context) {
	for {
		rec, err := r.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			r.log.Warn("fingerprint ring read error", "err", err)
			continue
		}
		r.handle(rec.RawSample)
	}
}

// Close unblocks Run and releases the reader.
func (r *Reader) Close() error { return r.rd.Close() }

// handle classifies one ring record and enforces a blocklist match.
func (r *Reader) handle(raw []byte) {
	ev, ok := dataplane.DecodeFPEvent(raw)
	if !ok {
		metrics.FingerprintEventsTotal.WithLabelValues("malformed").Inc()
		return
	}
	switch ev.Axis {
	case dataplane.MatchTLSClientHello:
		r.classifyTLS(&ev)
	case dataplane.MatchQUICInitial:
		// QUIC Initial decryption (deterministic keys from the DCID) is the next
		// E2 sub-PR; for now the copy is counted and dropped.
		metrics.FingerprintEventsTotal.WithLabelValues("quic_skipped").Inc()
	default:
		metrics.FingerprintEventsTotal.WithLabelValues("unknown_axis").Inc()
	}
}

// classifyTLS computes JA4 for a captured ClientHello and blocks the source when
// its JA4 is on the blocklist.
func (r *Reader) classifyTLS(ev *dataplane.FPEvent) {
	res, err := fingerprint.TLSClientHello(ev.Payload())
	if err != nil {
		// Truncated by the snapshot, or not actually a ClientHello: fail open.
		metrics.FingerprintEventsTotal.WithLabelValues("unparsed").Inc()
		return
	}
	metrics.FingerprintEventsTotal.WithLabelValues("classified").Inc()

	pol := r.policy()
	if _, blocked := pol.Blocklist[res.JA4]; !blocked {
		return
	}
	victim, source := ev.VictimAddr(), ev.SourceAddr()
	if err := r.block(victim, source, pol.TTL, "ja4:"+res.JA4); err != nil {
		// BlockSource refuses an allowlisted/protected/in-networks source and a
		// full policy block. That is expected policy, not a bug: count and move on.
		metrics.FingerprintEventsTotal.WithLabelValues("block_error").Inc()
		r.log.Warn("fingerprint source block refused",
			"ja4", res.JA4, "source", source.String(), "victim", victim.String(), "err", err)
		return
	}
	metrics.FingerprintEventsTotal.WithLabelValues("blocked").Inc()
	r.log.Info("source blocked on JA4 fingerprint",
		"ja4", res.JA4, "sni", res.SNI, "source", source.String(),
		"victim", victim.String(), "ttl", pol.TTL.Round(time.Second).String())
}
