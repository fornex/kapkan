//go:build linux

package dataplane

// Reading back what a victim's installed rules caught.
//
// It is a separate file from installer_linux.go on purpose: everything there
// WRITES, and the allocators it owns are the delicate part. This only reads, and
// the only Installer state it touches is the policy-id binding — under the same
// lock, in the same order (installer.mu -> manager.mu), so a scrape can never
// observe a half-finished install.

import (
	"fmt"
	"net/netip"
)

// Counters returns the per-rule counters for victim's installed block.
//
// The bool is false when THIS PROCESS has nothing installed for victim: a ban
// that fell back to a blackhole, one whose method is not dataplane, or an
// adopted victim from a previous process that has not been rehydrated yet. That
// is not an error and must not be reported as zero drops — "no rules here" and
// "rules here that caught nothing" are different facts, and only the first one
// means the numbers are not about this ban at all.
//
// COST, because this runs on a timer against every live ban: one bpf(2) lookup
// per installed rule, at most RulesPerPolicy (8) per victim, each a per-CPU read
// summed in userspace. At the default ban.max_active_bans and the interval
// app.dataplaneReporter uses, that is a few hundred syscalls per scrape against
// a datapath doing millions of packets between scrapes.
func (i *Installer) Counters(victim netip.Prefix) (VictimCounters, bool, error) {
	if !victim.IsValid() {
		return VictimCounters{}, false, fmt.Errorf("dataplane: counters: invalid victim prefix")
	}
	i.mu.Lock()
	defer i.mu.Unlock()

	policyID, ok := i.policyOf[victim]
	if !ok {
		return VictimCounters{}, false, nil
	}
	out := VictimCounters{PolicyID: policyID}
	err := i.mgr.WithMaps(func(maps *Maps, _ uint32) error {
		for n := 0; n < RulesPerPolicy; n++ {
			c, exists, err := ReadRuleStats(maps, DynamicRuleID(policyID, n))
			if err != nil {
				return err
			}
			// STOP at the first gap rather than skipping it. The ids are
			// contiguous from 0 by construction, so a gap means the block ends
			// there; carrying on and appending later slots would silently shift
			// every counter one position left and mis-attribute it to the wrong
			// FlowSpec rule — a wrong number that looks right.
			if !exists {
				break
			}
			out.Rules = append(out.Rules, c)
		}
		return nil
	})
	if err != nil {
		return VictimCounters{}, false, err
	}
	return out, true, nil
}
