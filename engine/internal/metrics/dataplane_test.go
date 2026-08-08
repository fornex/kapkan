package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The data-plane counters are the one part of this package with state in it, and
// the state exists because two counter models have to be bridged: the kernel's
// per-CPU arrays can only be read ABSOLUTELY, and a Prometheus counter can only
// be INCREMENTED. Getting the bridge wrong is not a cosmetic bug — it either
// fabricates a traffic spike at every restart or silently swallows real drops —
// and neither is visible by reading the code, so it is tested.

// TestVerdictDeltaSeedsAndAccumulates covers the whole state machine: the seed,
// a normal delta, a no-op re-read, and a decrease.
func TestVerdictDeltaSeedsAndAccumulates(t *testing.T) {
	ResetDataplaneCounterBaseline()
	DataplanePacketsTotal.Reset()
	DataplaneBytesTotal.Reset()

	// 1. FIRST READ PUBLISHES NOTHING. This is the restart case. An adopted pin
	// set carries the previous process's lifetime totals, so adding the first
	// absolute read into a fresh counter would draw a spike as wide as the
	// previous process's whole life and make rate() lie for a scrape interval.
	AddDataplaneVerdict("drop_static", 1_000_000, 64_000_000)
	if got := testutil.ToFloat64(DataplanePacketsTotal.WithLabelValues("drop_static")); got != 0 {
		t.Errorf("first read published %v, want 0 — an adopted counter must not spike at startup", got)
	}

	// 2. A NORMAL ADVANCE publishes the difference, not the absolute value.
	AddDataplaneVerdict("drop_static", 1_000_500, 64_032_000)
	if got := testutil.ToFloat64(DataplanePacketsTotal.WithLabelValues("drop_static")); got != 500 {
		t.Errorf("packets = %v, want 500", got)
	}
	if got := testutil.ToFloat64(DataplaneBytesTotal.WithLabelValues("drop_static")); got != 32_000 {
		t.Errorf("bytes = %v, want 32000", got)
	}

	// 3. AN IDLE DATAPATH does not move the counter.
	AddDataplaneVerdict("drop_static", 1_000_500, 64_032_000)
	if got := testutil.ToFloat64(DataplanePacketsTotal.WithLabelValues("drop_static")); got != 500 {
		t.Errorf("packets after an unchanged read = %v, want 500", got)
	}

	// 4. A DECREASE re-seeds instead of panicking. prometheus.Counter.Add panics
	// on a negative argument, so a counter reset under us (a map recreated) would
	// otherwise take the daemon down over a metric — the process would die
	// BECAUSE it was being observed.
	AddDataplaneVerdict("drop_static", 7, 448)
	if got := testutil.ToFloat64(DataplanePacketsTotal.WithLabelValues("drop_static")); got != 500 {
		t.Errorf("packets after a reset = %v, want 500 (held, not decremented)", got)
	}
	// ...and it resumes from the new baseline rather than staying stuck.
	AddDataplaneVerdict("drop_static", 10, 640)
	if got := testutil.ToFloat64(DataplanePacketsTotal.WithLabelValues("drop_static")); got != 503 {
		t.Errorf("packets after resuming = %v, want 503", got)
	}
}

// TestObservationsAreASeparateFamily is the over-counting guard.
//
// kapkan_stats bumps an observation counter ALONGSIDE a terminal verdict for the
// same packet: a dry-run rewrite increments both dryrun_would_drop and the pass
// it was rewritten to. If both families shared a metric name, the obvious query
// — sum(rate(kapkan_dataplane_packets_total[1m])) — would count that packet
// twice. Separate names make the sum exactly "packets through the datapath".
func TestObservationsAreASeparateFamily(t *testing.T) {
	ResetDataplaneCounterBaseline()
	DataplanePacketsTotal.Reset()
	DataplaneObservationsTotal.Reset()

	// One packet, dry-run: the datapath counted a terminal pass AND the
	// observation that it would have dropped it.
	AddDataplaneVerdict("pass_default", 0, 0)
	AddDataplaneObservation("dryrun_would_drop", 0)
	AddDataplaneVerdict("pass_default", 1, 64)
	AddDataplaneObservation("dryrun_would_drop", 1)

	if got := testutil.ToFloat64(DataplanePacketsTotal.WithLabelValues("pass_default")); got != 1 {
		t.Errorf("packets_total{verdict=pass_default} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(DataplaneObservationsTotal.WithLabelValues("dryrun_would_drop")); got != 1 {
		t.Errorf("observations_total{kind=dryrun_would_drop} = %v, want 1", got)
	}
	// The guarantee: one packet in, one packet counted under packets_total.
	if got := testutil.CollectAndCount(DataplanePacketsTotal); got != 1 {
		t.Errorf("packets_total has %d series, want 1 — an observation leaked into it", got)
	}
}

// TestSetDataplaneRulesZeroesTheOtherMode mirrors mitigate's gauge contract. A
// bare Set on the mode in force would leave the other reading its last value, so
// a data plane that switched out of dry-run would report its rules under BOTH
// modes — a dashboard panel showing simulated and real enforcement at once.
func TestSetDataplaneRulesZeroesTheOtherMode(t *testing.T) {
	DataplaneRules.Reset()

	SetDataplaneRules(12, true)
	if got := testutil.ToFloat64(DataplaneRules.WithLabelValues("dry_run")); got != 12 {
		t.Errorf("rules{dry_run} = %v, want 12", got)
	}
	if got := testutil.ToFloat64(DataplaneRules.WithLabelValues("real")); got != 0 {
		t.Errorf("rules{real} = %v, want 0", got)
	}

	// dry_run off: the count moves, and the old series must go to zero.
	SetDataplaneRules(12, false)
	if got := testutil.ToFloat64(DataplaneRules.WithLabelValues("real")); got != 12 {
		t.Errorf("rules{real} = %v, want 12", got)
	}
	if got := testutil.ToFloat64(DataplaneRules.WithLabelValues("dry_run")); got != 0 {
		t.Errorf("rules{dry_run} = %v, want 0 — a stale series claims both modes at once", got)
	}
}

// TestSetDataplaneAttachedZeroesTheOtherMode is the same argument for xdp_mode.
// Under xdp_mode: auto a NIC can come back on the generic path after a flap, and
// a stale native series would show one interface attached twice.
func TestSetDataplaneAttachedZeroesTheOtherMode(t *testing.T) {
	DataplaneXDPMode.Reset()

	SetDataplaneAttached("eth0", "native", true)
	if got := testutil.ToFloat64(DataplaneXDPMode.WithLabelValues("eth0", "native")); got != 1 {
		t.Errorf("xdp_mode{native} = %v, want 1", got)
	}

	// Flapped, came back generic.
	SetDataplaneAttached("eth0", "generic", true)
	if got := testutil.ToFloat64(DataplaneXDPMode.WithLabelValues("eth0", "generic")); got != 1 {
		t.Errorf("xdp_mode{generic} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(DataplaneXDPMode.WithLabelValues("eth0", "native")); got != 0 {
		t.Errorf("xdp_mode{native} = %v, want 0 after falling back to generic", got)
	}

	// Detached: BOTH read zero. That is the difference between "filtering on the
	// generic path" and "not filtering", and it must not be inferrable only from
	// the degraded gauge.
	SetDataplaneAttached("eth0", "generic", false)
	for _, mode := range []string{"native", "generic"} {
		if got := testutil.ToFloat64(DataplaneXDPMode.WithLabelValues("eth0", mode)); got != 0 {
			t.Errorf("xdp_mode{%s} = %v after detaching, want 0", mode, got)
		}
	}
}
