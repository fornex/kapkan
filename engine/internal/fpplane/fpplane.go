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
// audited source block, so a misfire ages out on its own. A per-event recover
// makes even a parser bug on crafted bytes a dropped event, not a daemon crash.
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
// block — and reports whether the install was a DRY RUN. It is
// mitigate.Mitigator.BlockSource adapted to fpplane's contract; an error
// (allowlisted/protected source, full block, absent data plane) is counted and
// logged, never fatal.
//
// THREAT-MODEL NOTE. The kernel recognises a ClientHello by a stateless
// fixed-offset match — no completed TCP handshake — so a spoofed single packet
// carrying a crafted, blocklisted-JA4 ClientHello makes this block the CLAIMED
// source. That is the source-block model working as designed (it blocks the
// address on the wire), but with an attacker-craftable trigger it can block a
// chosen third party's traffic toward the victim. Operators must read a JA4
// blocklist as "block this fingerprint's claimed sources". See edge-spec §6.
// To bound the collateral, fp blocks draw from a separate, smaller budget than
// operator/API blocks (mitigate.BlockSourceFingerprint), so a crafted-JA4 flood
// cannot starve operator source blocks.
type Blocker func(victim, source netip.Addr, ttl time.Duration, reason string) (dryRun bool, err error)

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
	now    func() time.Time

	// recent dedups repeated action on the same source→victim. The copy path is
	// upstream of the source-block drop in the datapath, so an already-blocked
	// source keeps producing sampled copies; without this the reader would
	// re-block (a mitigator lock + map write) and re-log on every one. Keyed
	// source→victim to a re-action deadline. Only Run touches it, one goroutine,
	// so no lock.
	recent map[string]time.Time
}

const (
	// recentCap bounds the dedup map against a spoofed-source flood (many
	// distinct sources). At the cap, expired entries are pruned; if still full,
	// the map resets — a few redundant re-blocks, never unbounded memory.
	recentCap = 1 << 16
	// maxCooldown caps the re-action interval so even a very long TTL refreshes.
	maxCooldown = 60 * time.Second
	// maxReadBackoff caps the Run error backoff.
	maxReadBackoff = time.Second
)

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
	return &Reader{
		rd:     rd,
		block:  block,
		policy: policy,
		log:    log,
		now:    time.Now,
		recent: make(map[string]time.Time),
	}, nil
}

// Run drains the ring until Close is called (or ctx is cancelled). It blocks, so
// the daemon runs it in a goroutine.
func (r *Reader) Run(ctx context.Context) {
	var consecErr int
	for {
		rec, err := r.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			// A persistent (non-closed) Read error — e.g. a wedged ring position —
			// must not spin the loop at 100% CPU or flood the log. Back off, and
			// log only the first of a run.
			consecErr++
			if consecErr == 1 {
				r.log.Warn("fingerprint ring read error; backing off", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(readBackoff(consecErr)):
			}
			continue
		}
		consecErr = 0
		r.handle(rec.RawSample)
	}
}

// readBackoff grows 10ms per consecutive error, capped at maxReadBackoff.
func readBackoff(n int) time.Duration {
	d := time.Duration(n) * 10 * time.Millisecond
	if d > maxReadBackoff {
		return maxReadBackoff
	}
	return d
}

// Close unblocks Run and releases the reader.
func (r *Reader) Close() error { return r.rd.Close() }

// handle classifies one ring record and enforces a blocklist match. The recover
// upholds the fail-open charter: a parser bug on attacker-controlled bytes
// degrades to a dropped event + a counter, never a daemon-wide crash.
func (r *Reader) handle(raw []byte) {
	defer func() {
		if p := recover(); p != nil {
			metrics.FingerprintEventsTotal.WithLabelValues("panic").Inc()
			r.log.Error("recovered from a panic classifying a fingerprint event", "panic", p)
		}
	}()

	ev, ok := dataplane.DecodeFPEvent(raw)
	if !ok {
		metrics.FingerprintEventsTotal.WithLabelValues("malformed").Inc()
		return
	}
	switch ev.Axis {
	case dataplane.MatchTLSClientHello:
		r.classify(&ev, fingerprint.TLSClientHello)
	case dataplane.MatchQUICInitial:
		// A QUIC v1 Initial is decrypted with keys derived from its Destination
		// Connection ID (public inputs), so an off-path copy is enough to recover
		// and fingerprint the ClientHello it carries.
		r.classify(&ev, fingerprint.QUICInitial)
	default:
		metrics.FingerprintEventsTotal.WithLabelValues("unknown_axis").Inc()
	}
}

// classify computes JA4 from a captured handshake and blocks the source when its
// JA4 is on the blocklist. parse turns the axis's raw bytes — a TLS ClientHello
// record or a QUIC Initial datagram — into a Result; every step after the parse
// (the blocklist match, dedup, and source-anchored block) is identical for TLS
// and QUIC, since the fingerprint and the enforcement action are the same.
func (r *Reader) classify(ev *dataplane.FPEvent, parse func([]byte) (fingerprint.Result, error)) {
	res, err := parse(ev.Payload())
	if err != nil {
		// Truncated by the snapshot, not actually a handshake, or (QUIC) an
		// undecryptable/unsupported packet: fail open.
		metrics.FingerprintEventsTotal.WithLabelValues("unparsed").Inc()
		return
	}
	metrics.FingerprintEventsTotal.WithLabelValues("classified").Inc()

	pol := r.policy()
	if _, blocked := pol.Blocklist[res.JA4]; !blocked {
		return
	}
	victim, source := ev.VictimAddr(), ev.SourceAddr()
	key := source.String() + "\x00" + victim.String()
	if r.suppressed(key) {
		// Already actioned this source→victim within its cooldown; the block is
		// live and will be refreshed when the cooldown lapses. Skip the redundant
		// install + log.
		metrics.FingerprintEventsTotal.WithLabelValues("suppressed").Inc()
		return
	}

	dryRun, err := r.block(victim, source, pol.TTL, "ja4:"+res.JA4)
	if err != nil {
		// BlockSource refuses an allowlisted/protected/in-networks source and a
		// full policy block. Expected policy, not a bug, and potentially frequent
		// under a flood — count it and log at Debug rather than Warn per event.
		metrics.FingerprintEventsTotal.WithLabelValues("block_error").Inc()
		r.log.Debug("fingerprint source block refused",
			"ja4", res.JA4, "source", source.String(), "victim", victim.String(), "err", err)
		return
	}
	r.remember(key, pol.TTL)
	if dryRun {
		metrics.FingerprintEventsTotal.WithLabelValues("would_block").Inc()
		r.log.Info("DRY-RUN: would source-block on JA4 (nothing installed)",
			"ja4", res.JA4, "source", source.String(), "victim", victim.String())
		return
	}
	metrics.FingerprintEventsTotal.WithLabelValues("blocked").Inc()
	r.log.Info("source blocked on JA4 fingerprint",
		"ja4", res.JA4, "source", source.String(), "victim", victim.String(),
		"ttl", pol.TTL.Round(time.Second).String())
	// SNI is the visited hostname (client-identifying with the source IP), so it
	// stays at Debug rather than default-level logs.
	r.log.Debug("blocked handshake detail", "ja4", res.JA4, "sni", res.SNI)
}

// suppressed reports whether this source→victim was actioned within its cooldown.
func (r *Reader) suppressed(key string) bool {
	dl, ok := r.recent[key]
	return ok && r.now().Before(dl)
}

// remember records that source→victim was just actioned, for a cooldown of
// TTL/2 (floored at 1s, capped at maxCooldown) so a persistent offender is
// refreshed before its block expires without re-blocking on every sampled copy.
func (r *Reader) remember(key string, ttl time.Duration) {
	cd := ttl / 2
	if cd > maxCooldown {
		cd = maxCooldown
	}
	if cd < time.Second {
		cd = time.Second
	}
	now := r.now()
	if len(r.recent) >= recentCap {
		for k, dl := range r.recent {
			if now.After(dl) {
				delete(r.recent, k)
			}
		}
		if len(r.recent) >= recentCap {
			r.recent = make(map[string]time.Time, recentCap)
		}
	}
	r.recent[key] = now.Add(cd)
}
