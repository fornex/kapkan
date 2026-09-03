package edgedoc

import "net/netip"

// SourceKeyPrefixV6 is the IPv6 prefix length a source is accounted under.
// A /64 is the smallest allocation an end user gets and the block privacy
// extensions rotate within, so it is the unit an attacker cannot multiply for
// free; the E4 clearance cookie binds to the same prefix.
const SourceKeyPrefixV6 = 64

// SourceKey is the address a source is accounted under, on every table of the
// node — rate buckets, in-flight counters, verdicts, rollup windows: an IPv4
// address as it is (IPv4-mapped forms unmapped), an IPv6 address by its /64.
// One key, shared by the decision service and the rollup, so a verdict the
// rollup asks for lands on the bucket the decider consults.
func SourceKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if !a.Is6() {
		return a
	}
	return netip.PrefixFrom(a, SourceKeyPrefixV6).Masked().Addr()
}
