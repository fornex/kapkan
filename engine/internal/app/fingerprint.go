package app

// Wiring the E2 fingerprint plane into the daemon. This is where the two halves
// meet: the data-plane Manager owns the copy ring, the Mitigator owns the
// source-block enforcement, and the reader joins them — drain the ring, compute
// JA4, and block a client whose JA4 is on the operator's list. The kernel
// COPIES; userspace CLASSIFIES; enforcement is the existing source-block path.

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/fpplane"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/internal/storage"
)

// startFingerprintReader builds the fingerprint-plane reader, or returns nil
// when the plane is not enabled (no data plane, or dataplane.fingerprint off).
//
// It is a construction step, not a goroutine: Start launches Run, and Stop
// closes the reader before the data-plane maps it reads are closed.
func startFingerprintReader(dp *dataplane.Manager, mit *mitigate.Mitigator, store *config.Store, audit storage.Writer, log *slog.Logger) (*fpplane.Reader, error) {
	if dp == nil {
		return nil, nil
	}
	cfg := store.Get()
	if cfg.Dataplane == nil || !cfg.DataplaneCfg.FingerprintEnabled {
		return nil, nil
	}
	// The Blocker adapts the mitigator's BlockSource to fpplane's contract,
	// forwarding the block's frozen dry-run flag so the reader reports
	// would-block vs blocked correctly. This keeps fpplane from importing mitigate.
	inner := fpplane.Blocker(func(victim, source netip.Addr, ttl time.Duration, reason string) (bool, error) {
		// BlockSourceFingerprint (not BlockSource) so the block draws from the
		// fingerprint plane's separate, smaller anchor budget — a spoofable JA4
		// trigger must never starve operator/API source blocks.
		sb, err := mit.BlockSourceFingerprint(victim, source, ttl, reason)
		if err != nil {
			return false, err
		}
		return sb.DryRun, nil
	})
	policy := func() fpplane.Policy { return fingerprintPolicy(store.Get()) }
	return fpplane.New(dp.FingerprintRing(), auditingBlocker(inner, audit), policy, log.With("component", "fingerprint"))
}

// auditingBlocker wraps a Blocker so a SUCCESSFUL reader-initiated block writes an
// audit record with source="auto" — the engine, not an operator, took the action,
// so there is no caller/token/tenant (the operator path stamps those in the API
// layer). Only successes are audited (dry-run included, marked DryRun): the reader
// dedups repeats within the block's cooldown, so audit volume is bounded, whereas
// a refusal is not deduped — auditing refusals would let a spoofed-JA4 flood spam
// the audit store, so refusals are left to metrics and logs. The writer is
// no-op when storage is disabled, so this is free in that case.
func auditingBlocker(inner fpplane.Blocker, audit storage.Writer) fpplane.Blocker {
	return func(victim, source netip.Addr, ttl time.Duration, reason string) (bool, error) {
		dryRun, err := inner(victim, source, ttl, reason)
		if err != nil {
			return false, err
		}
		if audit != nil {
			var dr uint8
			if dryRun {
				dr = 1
			}
			audit.WriteAudit(storage.AuditRow{
				EventTime:  time.Now().UTC().Format("2006-01-02 15:04:05"),
				Action:     "source_block",
				Result:     "blocked",
				Target:     source.String() + "->" + victim.String(),
				TargetType: "source",
				Reason:     reason,
				Source:     "auto",
				DryRun:     dr,
			})
		}
		return dryRun, nil
	}
}

// fingerprintPolicy resolves the live JA4 blocklist and block TTL from the
// current configuration. It is called per classified handshake, so an edit to
// dataplane.fingerprint.ja4_blocklist takes effect on the next handshake with no
// restart (the enable flag and sampler rate are restart-required; the blocklist
// and TTL hot-reload).
func fingerprintPolicy(cfg *config.Config) fpplane.Policy {
	if cfg.Dataplane == nil {
		return fpplane.Policy{}
	}
	fp := cfg.Dataplane.Fingerprint
	set := make(map[string]struct{}, len(fp.JA4Blocklist))
	for _, j := range fp.JA4Blocklist {
		set[j] = struct{}{}
	}
	return fpplane.Policy{
		Blocklist: set,
		TTL:       time.Duration(fp.BlockTTLSeconds) * time.Second,
	}
}
