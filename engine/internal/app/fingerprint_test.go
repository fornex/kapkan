package app

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/storage"
)

// fakeAuditWriter records audit rows; every other Writer method is a no-op.
type fakeAuditWriter struct{ rows []storage.AuditRow }

func (f *fakeAuditWriter) WriteAttack(storage.AttackRow)     {}
func (f *fakeAuditWriter) WriteTraffic([]storage.TrafficRow) {}
func (f *fakeAuditWriter) WriteAudit(r storage.AuditRow)     { f.rows = append(f.rows, r) }
func (f *fakeAuditWriter) Start(context.Context)             {}
func (f *fakeAuditWriter) Stop()                             {}

var (
	fpTestSource = netip.MustParseAddr("198.51.100.7")
	fpTestVictim = netip.MustParseAddr("203.0.113.9")
)

// TestAuditingBlockerAuditsSuccessfulBlock: a successful reader block writes one
// audit row attributed to the engine (source="auto"), with the source-block
// shape the operator path uses.
func TestAuditingBlockerAuditsSuccessfulBlock(t *testing.T) {
	aw := &fakeAuditWriter{}
	block := auditingBlocker(func(victim, source netip.Addr, ttl time.Duration, reason string) (bool, error) {
		return false, nil // installed, not dry-run
	}, aw)

	dryRun, err := block(fpTestVictim, fpTestSource, time.Minute, "ja4:t13d1516h2_8daaf6152771_e5627efa2ab1")
	if err != nil || dryRun {
		t.Fatalf("block returned dryRun=%v err=%v, want false,nil", dryRun, err)
	}
	if len(aw.rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(aw.rows))
	}
	r := aw.rows[0]
	if r.Action != "source_block" || r.Result != "blocked" || r.TargetType != "source" {
		t.Errorf("action/result/type = %q/%q/%q, want source_block/blocked/source", r.Action, r.Result, r.TargetType)
	}
	if r.Source != "auto" {
		t.Errorf("source = %q, want auto (engine-initiated, not api)", r.Source)
	}
	if r.Operator != "" || r.Role != "" || r.Tenant != "" {
		t.Errorf("caller fields set (%q/%q/%q), want empty for an auto block", r.Operator, r.Role, r.Tenant)
	}
	if want := "198.51.100.7->203.0.113.9"; r.Target != want {
		t.Errorf("target = %q, want %q", r.Target, want)
	}
	if r.Reason != "ja4:t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("reason = %q, want the ja4 reason", r.Reason)
	}
	if r.DryRun != 0 {
		t.Errorf("dry_run = %d, want 0", r.DryRun)
	}
	if r.EventTime == "" {
		t.Errorf("event_time empty")
	}
}

// TestAuditingBlockerMarksDryRun: a dry-run block is still audited (Result
// "blocked") but flagged DryRun, and the wrapper propagates dryRun=true.
func TestAuditingBlockerMarksDryRun(t *testing.T) {
	aw := &fakeAuditWriter{}
	block := auditingBlocker(func(netip.Addr, netip.Addr, time.Duration, string) (bool, error) {
		return true, nil // dry-run
	}, aw)

	dryRun, err := block(fpTestVictim, fpTestSource, time.Minute, "ja4:x")
	if err != nil || !dryRun {
		t.Fatalf("block returned dryRun=%v err=%v, want true,nil", dryRun, err)
	}
	if len(aw.rows) != 1 || aw.rows[0].DryRun != 1 {
		t.Fatalf("want 1 audit row with DryRun=1, got %+v", aw.rows)
	}
}

// TestAuditingBlockerSkipsAuditOnRefusal: a refused block writes NO audit row
// (refusals are not deduped; auditing them would let a flood spam the store) and
// the error propagates.
func TestAuditingBlockerSkipsAuditOnRefusal(t *testing.T) {
	aw := &fakeAuditWriter{}
	sentinel := errors.New("refused")
	block := auditingBlocker(func(netip.Addr, netip.Addr, time.Duration, string) (bool, error) {
		return false, sentinel
	}, aw)

	if _, err := block(fpTestVictim, fpTestSource, time.Minute, "ja4:x"); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the sentinel", err)
	}
	if len(aw.rows) != 0 {
		t.Errorf("audit rows = %d, want 0 on a refused block", len(aw.rows))
	}
}

// TestAuditingBlockerNilWriterIsSafe: a nil audit writer must not panic (a
// defensive guard, though app wiring always passes the no-op writer).
func TestAuditingBlockerNilWriterIsSafe(t *testing.T) {
	block := auditingBlocker(func(netip.Addr, netip.Addr, time.Duration, string) (bool, error) {
		return false, nil
	}, nil)
	if _, err := block(fpTestVictim, fpTestSource, time.Minute, "ja4:x"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}
