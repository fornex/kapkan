package dataplane

// The bpf2go-generated types, under readable names.
//
// This file is UNTAGGED while maps_linux.go is Linux-only, and the split is
// narrower than it looks: the generated bindings in kapkanxdp_bpfel.go carry an
// ARCHITECTURE constraint, not an OS one (every little-endian target, including
// darwin/amd64 and darwin/arm64), so the types themselves exist everywhere. Only
// WRITING to a map needs bpf(2), which is why the helpers stayed behind.
//
// They live apart from those helpers for one concrete reason: Snapshot in
// health.go reports a Counter per verdict, and health.go has to compile on the
// macOS development host where /healthz and the console renderers are built and
// tested. An alias that existed only on Linux would have forced the public
// snapshot type to name the unexported generated identifier instead.
//
// THE STRUCT DEFINITIONS ARE STILL NOT HAND-WRITTEN. Everything below is an
// ALIAS to a BTF-derived type, not a definition, so it cannot drift from the
// object: a field added in C becomes a Go compile error on the next
// `make dataplane-sync`, which is the whole reason bpf2go is used at all.

// Aliases for the bpf2go-generated types. The generated names carry the
// object's stem twice (kapkanXDPKapkanRule) and are unexported; these are the
// names the rest of the package uses. They are ALIASES, not definitions, so
// they cannot drift from the BTF-derived originals.
type (
	// Objects is the loaded program plus its whole map set.
	Objects = kapkanXDPObjects
	// Maps is the loaded map set on its own.
	Maps = kapkanXDPMaps
	// Rule is one encoded match rule: struct kapkan_rule.
	Rule = kapkanXDPKapkanRule
	// PolicyBlock is one victim's whole rule set: struct kapkan_policy_block.
	PolicyBlock = kapkanXDPKapkanPolicyBlock
	// Profile is a rate-limit ceiling with its precomputed reciprocals.
	Profile = kapkanXDPKapkanProfile
	// Bucket is one token bucket: struct kapkan_bucket.
	Bucket = kapkanXDPKapkanBucket
	// Config is kapkan_cfg[0]: struct kapkan_config.
	Config = kapkanXDPKapkanConfig
	// Counter is one {pkts, bytes} pair.
	Counter = kapkanXDPKapkanCounter
	// LPMKeyV4 and LPMKeyV6 key the prefix tries.
	LPMKeyV4 = kapkanXDPKapkanLpmKeyV4
	// LPMKeyV6 keys the IPv6 prefix tries.
	LPMKeyV6 = kapkanXDPKapkanLpmKeyV6
	// RLKeyV4 and RLKeyV6 key the token-bucket LRUs.
	RLKeyV4 = kapkanXDPKapkanRlKeyV4
	// RLKeyV6 keys the IPv6 token-bucket LRU.
	RLKeyV6 = kapkanXDPKapkanRlKeyV6
	// FPEvent is one fingerprint-plane copy: struct kapkan_fp_event. The
	// ring-buffer reader decodes records into this. Data holds SnapLen bytes of
	// captured L4 payload (up to FPSnapLen); the rest is stale and must be
	// ignored.
	FPEvent = kapkanXDPKapkanFpEvent
)

// MapSet returns the loaded maps, so a caller holding Objects can pass them to
// the helpers below without naming the generated embedded field.
func (o *Objects) MapSet() *Maps { return &o.kapkanXDPMaps }
