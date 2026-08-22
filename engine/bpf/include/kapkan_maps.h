// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * kapkan_maps.h — FREEZE POINT F6.
 *
 * Everything downstream keys off this file: the Go encoder in
 * internal/dataplane, the manager that flips generations, every test, and the
 * bpf2go-generated bindings (which are derived from this file's BTF). Map
 * NAMES, struct FIELD ORDER and enum VALUES are contract. Adding a field to
 * the tail of a struct or an enumerator to the end of an enum is a compatible
 * change; anything else is a map_schema_version bump.
 *
 * ==========================================================================
 * CHARTER
 * ==========================================================================
 * The data plane EXECUTES decisions made elsewhere. It never classifies, and
 * its default verdict is ALWAYS XDP_PASS. Every early exit, every parse
 * failure and every map miss passes the packet and bumps a counter. Malformed
 * frames pass unless cfg.drop_malformed is set. There is no default-deny
 * anywhere, and no rule-presence-flips-the-default behaviour.
 */
#ifndef KAPKAN_MAPS_H
#define KAPKAN_MAPS_H

#include "kapkan_bpf.h"

/*
 * KAPKAN_MAP_SCHEMA_VERSION is load-bearing. It is written into
 * kapkan_cfg[0].map_schema_version at attach. A future binary that finds a
 * pinned program ADOPTS it only when this constant matches what is pinned;
 * otherwise it tears the pins down and recreates them, because the layouts
 * below would be reinterpreted wrongly. Go mirrors this as
 * dataplane.MapSchemaVersion and a test asserts the two are equal.
 *
 * 1 -> 2 (E2, the off-path fingerprint plane): added the kapkan_fp_events
 * ring buffer and the kapkan_fp_sampler per-CPU state, and appended the fp_*
 * fields to struct kapkan_config. New maps and a changed kapkan_config layout
 * are both reasons a previous process's pins must be rebuilt rather than
 * adopted, so the stamp moves even though the program tag would already force
 * a rebuild on any .c edit (tryAdopt checks the tag first). Appending to the
 * TAIL of kapkan_config is otherwise a compatible change; the map additions
 * are what make this a version bump.
 */
#define KAPKAN_MAP_SCHEMA_VERSION 2

/*
 * KAPKAN_RULES_PER_POLICY mirrors config.maxDataplaneRulesPerBan (= 8). One
 * ban installs at most this many match rules, so one victim's whole rule set
 * fits in a single policy block and the datapath needs exactly ONE map lookup
 * to get all of it.
 *
 * VERIFIER RISK: the scan over these rules must be `#pragma unroll`ed. A
 * runtime-count loop over a map value needs bpf_loop(), which is 5.17+, and
 * Kapkan's floor is 5.15. Eight unrolled iterations is also why the rule
 * struct is kept to 64 bytes: the verifier walks every iteration.
 */
#define KAPKAN_RULES_PER_POLICY 8

/*
 * KAPKAN_GENERATIONS is the double-buffer depth. See the DOUBLE BUFFERING
 * note above kapkan_policies.
 */
#define KAPKAN_GENERATIONS 2

/*
 * Default map sizings, matching config.DataplaneLimits defaults.
 *
 * THESE ARE DEFAULTS, NOT SIZES. The loader in internal/dataplane REWRITES
 * max_entries from the resolved dataplane.limits on the CollectionSpec before
 * the maps are created (see limits.go: Limits.MapSizing and applySizing), so
 * what an operator gets is what they configured and these values are only what
 * they get when they configure nothing. That matters most for
 * KAPKAN_MAX_RL_SOURCES: the two LRU hashes it sizes are 94% of a measured
 * 234.9 MiB, charged to the unit's memory cgroup in one step at load, so an
 * operator lowering it to fit a small box has to actually get a smaller map.
 *
 * Three of them are the same number in three files — here, dataplane's
 * DefaultMax* in contract.go, and config's defaultMax* — and both edges are
 * gated: TestContractMatchesC reads this header, TestDefaultLimitsMatchConfig
 * reads config.go.
 *
 * KAPKAN_MAX_STATIC_RULES is the count of rules AS THE OPERATOR WRITES THEM.
 * kapkan_statics is created larger than KAPKAN_GENERATIONS x this: a config rule
 * that names no source prefix has no address family, and since the datapath
 * tests KAPKAN_RF_IPV6 against the packet unconditionally, such a rule is
 * compiled to one kernel rule per family (dataplane.StaticExpansion).
 *
 * KAPKAN_MAX_RULE_STATS is a default the loader always replaces, with the real
 * bound on live rule ids (max_dynamic_rules + the expanded static count).
 *
 * KAPKAN_MAX_PREFIXES is deliberately NOT rewritten: an LPM_TRIE allocates
 * nothing up front and grows per insert (measured: 0 bytes at max_entries
 * 65536), so it is a ceiling rather than a reservation and there is nothing to
 * save by lowering it.
 */
#define KAPKAN_MAX_DYNAMIC_RULES	4096 /* config default */
#define KAPKAN_MAX_POLICIES		(KAPKAN_MAX_DYNAMIC_RULES / KAPKAN_RULES_PER_POLICY)
#define KAPKAN_MAX_STATIC_RULES		256      /* config default */
#define KAPKAN_MAX_RL_SOURCES		(1 << 20) /* config default */
#define KAPKAN_MAX_PROFILES		256
#define KAPKAN_MAX_PREFIXES		65536
#define KAPKAN_MAX_RULE_STATS		8192

/*
 * The fingerprint plane (E2). See "THE FINGERPRINT PLANE" below and §6 of the
 * edge spec: the datapath COPIES a bounded, sampled prefix of TLS ClientHello
 * and QUIC Initial payloads into a ring buffer, and userspace CLASSIFIES it
 * (JA4 + SNI). The kernel never classifies — the copy is pure observation and
 * can NEVER change a packet's verdict.
 *
 * KAPKAN_FP_SNAP_LEN is the per-event capture ceiling, in bytes of L4 payload.
 * It is sized to hold a whole QUIC v1 Initial datagram's payload (RFC 9000
 * floors a client Initial at 1200 bytes) so QUIC decryption in userspace has
 * the bytes it needs; a first-segment TLS ClientHello is far smaller and is
 * captured whole. It MUST stay a multiple of 64: the datapath copies in fixed
 * 64-byte blocks so the verifier proves every access without a byte loop (see
 * kapkan_fp_emit).
 *
 * KAPKAN_FP_RING_BYTES is the ring's byte size (power of two, page-aligned).
 * A full ring simply drops the copy and counts KAPKAN_STAT_FP_RING_FULL; it
 * never applies backpressure to the datapath, so the plane cannot become its
 * own DoS. Together with the in-kernel sampler (kapkan_fp_sampler) this is what
 * caps copy volume under flood.
 */
#define KAPKAN_FP_SNAP_LEN		1536
#define KAPKAN_FP_RING_BYTES		(1 << 20)

/* ======================================================================== */
/* Actions and rule flags                                                    */
/* ======================================================================== */

/* Rule action. Mirrors config.StaticAction* and mitigate.FlowSpecRule.Action. */
enum kapkan_action {
	KAPKAN_ACT_PASS		= 0, /* explicit admit; stops evaluation */
	KAPKAN_ACT_DROP		= 1,
	KAPKAN_ACT_RATELIMIT	= 2, /* consult profile; admit iff tokens remain */
};

/*
 * Rule flag bits. "any" is expressed with an explicit bit rather than a
 * zero-valued field, because 0 is a legal value for several of these
 * (protocol 0 is IPv6 hop-by-hop; TCP flags 0 is a NULL scan, which is
 * precisely a thing an operator wants to match).
 */
enum kapkan_rule_flag {
	KAPKAN_RF_VALID		= 1 << 0, /* clear => empty slot, skip */
	KAPKAN_RF_SRC_ANY	= 1 << 1,
	KAPKAN_RF_DST_ANY	= 1 << 2,
	KAPKAN_RF_PROTO_ANY	= 1 << 3,
	KAPKAN_RF_SPORT_ANY	= 1 << 4,
	KAPKAN_RF_DPORT_ANY	= 1 << 5,
	KAPKAN_RF_FRAGMENT	= 1 << 6, /* match only fragmented packets */
	KAPKAN_RF_IPV6		= 1 << 7, /* address family of src/dst prefixes */
};

/*
 * Extended match bits, in kapkan_rule.match_ext.
 *
 * WHY A SECOND BYTE. `flags` above is full — all eight bits are spoken for —
 * and widening it would move every field after it. match_ext was the struct's
 * _pad0, so the layout is byte-for-byte what it was: same size, same offsets,
 * same alignment. A zero here means "no extended predicate", which is exactly
 * what every rule an older userspace wrote already contains.
 *
 * NO MapSchemaVersion BUMP IS OWED FOR ADDING A BIT HERE, and the reasoning is
 * worth writing down because the defensive reflex is to bump anyway and tear
 * down every operator's pins for nothing. tryAdopt() compares the PROGRAM TAG
 * of the pinned program against the one this binary loads, and any edit to
 * kapkan_xdp.c changes that tag. So a binary that understands a new bit never
 * meets a program that does not: the whole pin set is rebuilt, and the rules
 * are re-encoded from config and from ban rehydration on the way. The version
 * stamp is for LAYOUT changes, which this is not.
 *
 * THIS AXIS IS STATIC-RULE ONLY. It is the first thing in kapkan_rule with no
 * mitigate.FlowSpecRule counterpart, because FlowSpec cannot express a payload
 * predicate at all (RFC 8955 has no component for it). A dynamic rule that set
 * one would select different packets through the BPF encoder than through the
 * NLRI encoder while claiming to be the same rule — so dpencode.go must never
 * emit it, and a test holds that line rather than a comment.
 */
enum kapkan_match_ext {
	/*
	 * The TCP payload begins a TLS handshake record carrying a
	 * ClientHello. Set by the parser from three bytes at fixed offsets;
	 * see kapkan_parse_l4(). Clear for everything else INCLUDING a
	 * ClientHello this program could not see (truncated capture, a
	 * segment-split record), because the parser fails open like the rest
	 * of the file.
	 */
	KAPKAN_MX_TLS_CLIENT_HELLO = 1 << 0,

	/*
	 * The UDP payload opens a QUIC v1 Initial: long-header form + the QUIC
	 * fixed bit with the Initial packet type, then version 0x00000001 —
	 * five bytes at fixed offsets; see kapkan_parse_l4(). Clear for
	 * everything else, INCLUDING version negotiation (version 0), QUIC v2
	 * (a different version constant that also renumbers the Initial type;
	 * negligible deployment, revisit when that changes), and any Initial
	 * this program could not read — the parser fails open like the rest of
	 * the file. This is the UDP twin of the bit above: the handshake
	 * packet a server must parse and answer, matchable so a handshake
	 * flood is meterable per source.
	 */
	KAPKAN_MX_QUIC_INITIAL = 1 << 1,
};

/* ======================================================================== */
/* struct kapkan_rule — the in-kernel form of mitigate.FlowSpecRule           */
/* ======================================================================== */
/*
 * Field-for-field correspondence with mitigate.FlowSpecRule (which is frozen
 * and must not be edited):
 *
 *   FlowSpecRule.Dst   netip.Prefix -> dst[16] + dst_prefixlen (+ RF_IPV6)
 *   FlowSpecRule.Src   netip.Prefix -> src[16] + src_prefixlen
 *   FlowSpecRule.Proto uint8        -> proto     (unset => RF_PROTO_ANY)
 *   FlowSpecRule.SrcPort uint16     -> sport     (unset => RF_SPORT_ANY)
 *   FlowSpecRule.DstPort uint16     -> dport     (unset => RF_DPORT_ANY)
 *   FlowSpecRule.TCPFlags uint8     -> tcp_flags + tcp_flags_mask
 *   FlowSpecRule.Fragment bool      -> RF_FRAGMENT
 *   FlowSpecRule.Action             -> action
 *   FlowSpecRule.RateBytes float64  -> profile
 *
 * match_ext is the one member with NO FlowSpecRule counterpart — see
 * enum kapkan_match_ext. Static rules only.
 *
 * RateBytes does not appear directly: the datapath must not carry a float and
 * must not divide by a runtime value, so userspace INTERNS each distinct rate
 * into a kapkan_profile with ns_per_* precomputed and stores the profile id.
 *
 * TCPFlags gets two bytes because FlowSpecRule documents bitmask semantics
 * ("SYN also matches SYN-ACK"): the datapath tests
 * (observed & tcp_flags_mask) == tcp_flags, so userspace can express both
 * "these bits set" and "exactly these bits" without a second rule kind.
 *
 * expires_at_ns is compared against bpf_ktime_get_boot_ns(). AN EXPIRED RULE
 * IS TREATED AS ABSENT — the packet falls through to the next precedence
 * level and ultimately to PASS. This is the fail-safe that makes a dead
 * userspace harmless: if the manager crashes, every dynamic rule ages out on
 * its own and the box reverts to forwarding. It is not optional. 0 means
 * "never expires" and is only ever used for static (operator) rules, which
 * come from the config file and cannot be stranded by a crash.
 *
 * Layout is exactly 64 bytes (one cache line) and every member is naturally
 * aligned, so no implicit padding exists for the Go encoder to disagree about.
 */
struct kapkan_rule {
	__u64 expires_at_ns; /* boot-clock ns; 0 = never. Expired == absent.  */
	__u32 rule_id;	     /* stable id, key of kapkan_rule_stats           */
	__u32 profile;	     /* kapkan_profiles index; only for ACT_RATELIMIT */
	__u8 src[16];	     /* source prefix, network order; v4 in [0..3]    */
	__u8 dst[16];	     /* dest prefix, network order; v4 in [0..3]      */
	__u8 src_prefixlen;
	__u8 dst_prefixlen;
	__u8 action;	     /* enum kapkan_action                            */
	__u8 proto;
	__u8 tcp_flags;	     /* expected bits, after masking                  */
	__u8 tcp_flags_mask; /* 0 => do not test flags                        */
	__u8 flags;	     /* enum kapkan_rule_flag bitset                  */
	__u8 match_ext;	     /* enum kapkan_match_ext bitset; 0 = no extras   */
	__u16 sport;	     /* host order                                    */
	__u16 dport;	     /* host order                                    */
	__u32 _pad1;
};

/*
 * A victim's whole rule set, fetched with one lookup. n_rules bounds the
 * unrolled scan; slots beyond it have RF_VALID clear anyway, so a torn read
 * can only ever under-match (fail open), never over-match.
 */
struct kapkan_policy_block {
	__u32 n_rules;
	__u32 _pad;
	struct kapkan_rule rules[KAPKAN_RULES_PER_POLICY];
};

/* ======================================================================== */
/* Rate limiting                                                             */
/* ======================================================================== */
/*
 * VERIFIER / DATAPATH RISK: no division by a runtime value in the datapath.
 * A BPF division is legal but the divisor must be proven non-zero, which costs
 * a branch per packet, and on some targets it is a slow multi-cycle insn.
 * So userspace precomputes the reciprocals here and the datapath does
 * multiply-and-shift only:
 *
 *   tokens += (now_ns - last_ns) / ns_per_pkt     <-- WRONG, runtime divide
 *   tokens += (now_ns - last_ns) * pkt_per_ns_q32 >> 32   <-- what we do
 *
 * Both spellings are stored: ns_per_* documents the intent and is used by
 * userspace for sanity checks and console display; the datapath uses the
 * _q32 reciprocals.
 */
struct kapkan_profile {
	__u64 rate_pps;	    /* config RateLimitProfile.PPS; 0 = no pps cap  */
	__u64 burst_pps;    /* bucket depth, packets                        */
	__u64 rate_bps;	    /* BYTES/s, derived from Mbps; 0 = no byte cap  */
	__u64 burst_bps;    /* bucket depth, bytes                          */
	__u64 ns_per_pkt;   /* 1e9 / rate_pps, precomputed (documentation)  */
	__u64 ns_per_byte;  /* 1e9 / rate_bps, precomputed (documentation)  */
	__u64 pkt_per_ns_q32; /* (rate_pps << 32) / 1e9 — datapath uses this */
	__u64 byte_per_ns_q32; /* (rate_bps << 32) / 1e9 — datapath uses this */
};

/*
 * One token bucket. Both counters live in the same value so a single LRU
 * lookup serves a rule that caps pps and Mbps at once; whichever empties
 * first denies the packet, per config.RateLimitProfile's documented
 * semantics.
 */
struct kapkan_bucket {
	__u64 last_ns;
	__u64 tokens_pkt_q32;
	__u64 tokens_byte_q32;
};

/*
 * Token-bucket keys. The victim is part of the key so one attacker hammering
 * two protected prefixes gets one budget per victim, not a shared one. The
 * profile is part of the key so two rules with different ceilings do not
 * drain each other's bucket.
 */
struct kapkan_rl_key_v4 {
	__be32 victim;
	__be32 src;
	__u32 profile;
	__u32 _pad;
};

struct kapkan_rl_key_v6 {
	__u8 victim[16];
	__u8 src[16];
	__u32 profile;
	__u32 _pad;
};

/* ======================================================================== */
/* LPM keys                                                                  */
/* ======================================================================== */
/*
 * BPF_MAP_TYPE_LPM_TRIE requires prefixlen (in BITS, host order) as the first
 * u32 of the key, followed by the value bytes in network order.
 */
struct kapkan_lpm_key_v4 {
	__u32 prefixlen;
	__u8 addr[4];
};

struct kapkan_lpm_key_v6 {
	__u32 prefixlen;
	__u8 addr[16];
};

/* ======================================================================== */
/* Global config                                                             */
/* ======================================================================== */
/*
 * DRY RUN: dry_run rewrites a DROP verdict to PASS at the very LAST moment,
 * AFTER kapkan_stats and kapkan_rule_stats have been bumped, so an operator
 * sees exactly what would have been dropped. The accounting is never skipped.
 * A dry-run drop additionally bumps KAPKAN_STAT_DRYRUN_WOULD_DROP so the
 * console can show the counterfactual as one number.
 *
 * NAMING: the struct is kapkan_config, not kapkan_cfg, because the MAP is
 * named kapkan_cfg (that name is contract) and BTF puts map variables and
 * struct types in one namespace — bpf2go refuses to generate a Go type when a
 * struct and a variable share a name. The map name is what the contract
 * freezes, so the struct is the one that gives way.
 */
struct kapkan_config {
	__u32 generation;	  /* 0 or 1: which half of the double buffer  */
	__u32 map_schema_version; /* == KAPKAN_MAP_SCHEMA_VERSION            */
	__u32 policy_stride;	  /* entries per generation in kapkan_policies */
	__u32 static_stride;	  /* entries per generation in kapkan_statics  */
	__u32 static_count;	  /* live statics in the active generation     */
	__u32 flags;		  /* reserved                                  */
	__u8 dry_run;
	__u8 drop_malformed;	  /* config Dataplane.DropMalformed            */
	__u8 fp_enabled;	  /* fingerprint plane on (E2)                 */
	__u8 _pad[5];
	/*
	 * Fingerprint-plane copy sampler, appended at the tail (schema 2). These
	 * gate ONLY the observation ring, never a verdict, so a torn read of them
	 * across a reload can at worst mis-sample a copy or two — it can never
	 * drop or admit a packet. The math mirrors kapkan_profile exactly: a
	 * per-CPU token bucket refilled by (elapsed_ns * fp_rate_per_ns_q32) in
	 * Q32, with fp_burst as the depth in packets. Userspace precomputes the
	 * reciprocal; the datapath never divides. The bucket is a zero-initialised
	 * PERCPU_ARRAY the datapath only reads (unlike kapkan_rl_admit, nothing
	 * seeds it with a full burst); its first packet reaches the cap purely via
	 * the clock-delta refill. So fp_rate_per_ns_q32 == 0 means it never refills
	 * and copies NOTHING — the safe direction for a copy channel.
	 */
	__u64 fp_burst;		  /* sampler bucket depth, packets             */
	__u64 fp_rate_per_ns_q32; /* copies/ns in Q32, precomputed by userspace */
};

/* ======================================================================== */
/* Counters                                                                  */
/* ======================================================================== */

struct kapkan_counter {
	__u64 pkts;
	__u64 bytes;
};

/*
 * Verdict/reason enum, the index space of kapkan_stats. Append only: the
 * console and the /api/v1 surface render these by index.
 *
 * TWO KINDS OF COUNTER LIVE HERE, and anything that sums them needs to know
 * which is which:
 *
 *   TERMINAL — exactly one is bumped on every packet, naming the branch that
 *       decided it. These partition the traffic: their sum IS the packet
 *       count. Everything below except the four observation counters.
 *
 *   OBSERVATION — bumped on the way past, and therefore CO-OCCURRING with a
 *       terminal counter for the same packet. There are seven (Stat.IsObservation
 *       in contract.go is the authority, and a test pins the two together):
 *         PASS_FRAG_NOPORTS   saw a non-first fragment (which is then
 *                             evaluated normally, and may well be dropped by
 *                             a rule — the name predates the rule engine and
 *                             is kept because the value is contract)
 *         PASS_RULE_EXPIRED   a rule matched but had aged out; the scan
 *                             continued past it
 *         DRYRUN_WOULD_DROP   a drop was rewritten to a pass
 *         ERR_POLICY_MISSING  a victim resolved to a policy block that is not
 *                             there; the packet fell through
 *         FP_EMITTED          a fingerprint copy was written to the ring
 *         FP_THROTTLED        the sampler denied a fingerprint copy
 *         FP_RING_FULL        the ring was full, so a copy was skipped
 *       and one near-miss worth naming because it looks like it belongs here:
 *         ERR_CFG_MISSING     is TERMINAL, not observational — it returns
 *                             XDP_PASS immediately rather than falling through
 *
 * Adding up every index to cross-check against an interface counter therefore
 * over-counts by the number of observations. The Go side documents the same
 * split on dataplane.Stat.
 */
enum kapkan_stat {
	KAPKAN_STAT_PASS_DEFAULT	= 0,  /* fell through every rule (6)  */
	KAPKAN_STAT_PASS_NOT_IP		= 1,  /* ARP, LLDP, ... not our job   */
	KAPKAN_STAT_PASS_MALFORMED	= 2,  /* unparseable, drop_malformed=0 */
	KAPKAN_STAT_DROP_MALFORMED	= 3,  /* unparseable, drop_malformed=1 */
	KAPKAN_STAT_PASS_VLAN_DEPTH	= 4,  /* more tags than we walk       */
	KAPKAN_STAT_PASS_EXTHDR_CAP	= 5,  /* hit the IPv6 ext-hdr cap     */
	KAPKAN_STAT_PASS_FRAG_NOPORTS	= 6,  /* non-first fragment, no L4    */
	KAPKAN_STAT_PASS_ALLOW_SRC	= 7,  /* precedence 1                 */
	KAPKAN_STAT_PASS_PROTECT_DST	= 8,  /* precedence 2                 */
	KAPKAN_STAT_PASS_STATIC		= 9,  /* precedence 3, action=pass    */
	KAPKAN_STAT_DROP_STATIC		= 10, /* precedence 3, action=drop    */
	KAPKAN_STAT_PASS_DYN_SRC	= 11, /* precedence 4, action=pass    */
	KAPKAN_STAT_DROP_DYN_SRC	= 12, /* precedence 4, action=drop    */
	KAPKAN_STAT_PASS_DYN_DST	= 13, /* precedence 5, action=pass    */
	KAPKAN_STAT_DROP_DYN_DST	= 14, /* precedence 5, action=drop    */
	KAPKAN_STAT_PASS_RL_ADMIT	= 15, /* ratelimit, tokens remained   */
	KAPKAN_STAT_DROP_RL		= 16, /* ratelimit, bucket empty      */
	KAPKAN_STAT_PASS_RULE_EXPIRED	= 17, /* matched a rule past its TTL  */
	KAPKAN_STAT_DRYRUN_WOULD_DROP	= 18, /* drop rewritten to pass       */
	KAPKAN_STAT_ERR_CFG_MISSING	= 19, /* kapkan_cfg[0] lookup failed  */
	KAPKAN_STAT_ERR_POLICY_MISSING	= 20, /* victim hit, policy block gone */
	/*
	 * The fingerprint plane (E2). All three are OBSERVATION counters: they are
	 * bumped on the copy channel as a packet goes past and CO-OCCUR with
	 * whatever terminal verdict the packet later gets, so they must NOT be
	 * summed into the packet count. FP_THROTTLED climbing while FP_EMITTED
	 * plateaus is the visible proof that the sampler is capping copy volume
	 * under flood; FP_RING_FULL is userspace-drain backpressure, not a drop.
	 */
	KAPKAN_STAT_FP_EMITTED		= 21, /* a copy was written to the ring */
	KAPKAN_STAT_FP_THROTTLED	= 22, /* sampler denied the copy        */
	KAPKAN_STAT_FP_RING_FULL	= 23, /* ring full, copy skipped        */
	KAPKAN_STAT__MAX		= 24,
};

/* ======================================================================== */
/* THE MAPS                                                                  */
/* ======================================================================== */

/*
 * Precedence 1 — SOURCE allowlist (config Dataplane.Allowlist).
 * Precedence 2 — DESTINATION protected list (the protected_whitelist mirror).
 *
 * These are two different axes and both must live in the kernel. The
 * allowlist answers "this sender is never to be touched"; the protected list
 * answers "this victim is never to be banned". Without the DST map in the
 * kernel, a rehydrated rule from a previous process, or a rule installed in
 * the same instant the operator adds a prefix to protected_whitelist, can drop
 * traffic to a protected prefix until the userspace sweep notices on its next
 * 1 Hz tick. One second of dropping a customer's traffic is not acceptable, so
 * the check is in the datapath.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct kapkan_lpm_key_v4);
	__type(value, __u8);
	__uint(max_entries, KAPKAN_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} kapkan_allow4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct kapkan_lpm_key_v6);
	__type(value, __u8);
	__uint(max_entries, KAPKAN_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} kapkan_allow6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct kapkan_lpm_key_v4);
	__type(value, __u8);
	__uint(max_entries, KAPKAN_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} kapkan_protect4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct kapkan_lpm_key_v6);
	__type(value, __u8);
	__uint(max_entries, KAPKAN_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} kapkan_protect6 SEC(".maps");

/*
 * Precedence 5 — victim lookup. Longest-prefix match on the DESTINATION gives
 * a policy id, which indexes kapkan_policies. Split from the policy blocks so
 * that re-pointing a victim at a freshly built block is a single map update.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct kapkan_lpm_key_v4);
	__type(value, __u32);
	__uint(max_entries, KAPKAN_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} kapkan_victims4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct kapkan_lpm_key_v6);
	__type(value, __u32);
	__uint(max_entries, KAPKAN_MAX_PREFIXES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} kapkan_victims6 SEC(".maps");

/*
 * ==========================================================================
 * DOUBLE BUFFERING — kapkan_policies and kapkan_statics
 * ==========================================================================
 * Requirement: policy is replaceable with zero packet loss, and a packet must
 * observe either the whole old rule set or the whole new one, never a mix.
 * Userspace builds the INACTIVE generation completely, then flips the single
 * u32 kapkan_cfg[0].generation. The flip is one 4-byte store; a packet reads
 * generation once at the top of the program and uses that value for every
 * subsequent lookup, so it is consistent for its whole traversal.
 *
 * ENCODING CHOSEN: index arithmetic in ONE flat array,
 *
 *     idx = generation * cfg->policy_stride + policy_id
 *
 * The three candidates and why this one wins:
 *
 *   (a) Two sibling maps selected by `if (gen) lookup(A) else lookup(B)`.
 *       Simplest to read, worst for the verifier: the unrolled 8-rule scan
 *       sits downstream of the branch, so the verifier walks BOTH arms and
 *       the instruction budget for the hot path roughly doubles. With an
 *       unrolled scan already being the expensive part, this was the first
 *       one out.
 *
 *   (b) ARRAY_OF_MAPS with the generation as the outer index. Clean model,
 *       but the inner lookup returns a pointer the verifier cannot prove
 *       non-NULL, so it costs a SECOND null check and a second dependent
 *       load on every packet — and userspace has to keep inner map fds alive
 *       and swap them, which is materially more code in the manager for no
 *       datapath benefit.
 *
 *   (c) Index arithmetic (this one). One map, one lookup, one null check.
 *       Verifier cost is a single 32-bit multiply-add; the ARRAY lookup
 *       helper bounds-checks the index itself and returns NULL when it is out
 *       of range, so an out-of-range stride can only ever fail open (the
 *       null check bumps ERR_POLICY_MISSING and passes). The stride is a
 *       runtime value from kapkan_cfg — a multiply by a runtime value is
 *       fine, it is only DIVISION we must keep out of the datapath.
 *
 * Cost paid: max_entries is KAPKAN_GENERATIONS x stride, i.e. the maps are
 * twice the size an operator's limits imply. That is the price of a lossless
 * flip and it is stated in the docs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct kapkan_policy_block);
	__uint(max_entries, KAPKAN_GENERATIONS * KAPKAN_MAX_POLICIES);
} kapkan_policies SEC(".maps");

/*
 * Precedence 3 — operator static rules, first match wins, also double
 * buffered so a config reload is lossless.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct kapkan_rule);
	__uint(max_entries, KAPKAN_GENERATIONS * KAPKAN_MAX_STATIC_RULES);
} kapkan_statics SEC(".maps");

/*
 * Token buckets, keyed by {victim, src, profile}. LRU because the source set
 * is attacker-controlled and unbounded: under a spoofed flood the map fills
 * instantly, and eviction of a cold bucket is exactly the right failure mode
 * (the evicted source starts again with a full bucket, i.e. it fails OPEN,
 * consistent with the charter).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct kapkan_rl_key_v4);
	__type(value, struct kapkan_bucket);
	__uint(max_entries, KAPKAN_MAX_RL_SOURCES);
} kapkan_rl_src4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct kapkan_rl_key_v6);
	__type(value, struct kapkan_bucket);
	__uint(max_entries, KAPKAN_MAX_RL_SOURCES);
} kapkan_rl_src6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct kapkan_profile);
	__uint(max_entries, KAPKAN_MAX_PROFILES);
} kapkan_profiles SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct kapkan_config);
	__uint(max_entries, 1);
} kapkan_cfg SEC(".maps");

/*
 * PERCPU so the hot path is a plain increment with no atomics and no cache
 * line ping-pong across RX queues. Userspace sums the per-CPU values.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct kapkan_counter);
	__uint(max_entries, KAPKAN_STAT__MAX);
} kapkan_stats SEC(".maps");

/*
 * Per-rule accounting, keyed by kapkan_rule.rule_id widened to u64 so the key
 * space can later carry a generation or a victim tag without a schema bump.
 * PERCPU_HASH for the same reason as above. Entries are created by userspace
 * when a rule is installed, so a datapath miss is not an error path we need
 * to handle beyond "skip the per-rule bump".
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u64);
	__type(value, struct kapkan_counter);
	__uint(max_entries, KAPKAN_MAX_RULE_STATS);
} kapkan_rule_stats SEC(".maps");

/* ======================================================================== */
/* THE FINGERPRINT PLANE (E2)                                                 */
/* ======================================================================== */
/*
 * OFF-PATH BY CONSTRUCTION. The datapath already recognises the SHAPE of a TLS
 * ClientHello and a QUIC v1 Initial at fixed offsets (see kapkan_parse_l4 and
 * enum kapkan_match_ext). This plane adds one thing: a bounded, sampled COPY of
 * those payloads to userspace, where JA4 + SNI are computed and a per-source
 * policy comes back through the SAME source-block path E1 already built
 * (mitigate.BlockSource -> the victims trie). The kernel copies; userspace
 * classifies. Both the BPF charter (never classify) and the edge charter hold.
 *
 * THE COPY CANNOT BECOME A DoS, and that is enforced two ways: an in-kernel
 * per-CPU token bucket (kapkan_fp_sampler) caps copies to a configured rate
 * regardless of packet rate, and a full ring drops the copy rather than
 * stalling the datapath. A lost copy costs nothing — userspace simply does not
 * fingerprint that handshake — which is why the sampler's failure direction is
 * the OPPOSITE of the charter's default-PASS: on any doubt it declines to copy.
 */

/*
 * One fingerprint event: metadata plus a captured prefix of the L4 payload.
 * data[] begins at the TLS record (TCP) or the QUIC long header (UDP), i.e. at
 * kapkan_pkt.fp_off, so userspace parses the handshake without re-walking L2/L3.
 * snap_len is how many bytes were actually captured (a 64-byte-granular prefix,
 * possibly less than the frame carried); userspace classifies what it got and
 * fails open on truncation. No __u64 members, so the struct's alignment is 4 and
 * the Go decoder (bpf2go) sees exactly this layout.
 */
struct kapkan_fp_event {
	__u8 src[16];	/* network order; v4 left-aligned in [0..3] */
	__u8 dst[16];	/* network order; v4 left-aligned in [0..3] */
	__u16 sport;	/* host order */
	__u16 dport;	/* host order */
	__u8 is_v6;
	__u8 proto;	/* IPPROTO_TCP or IPPROTO_UDP */
	__u8 axis;	/* enum kapkan_match_ext: which payload opened this */
	__u8 _pad;
	__u32 pkt_len;	/* full frame length, for context */
	__u32 snap_len;	/* bytes captured in data[]; <= KAPKAN_FP_SNAP_LEN */
	__u32 _pad2;
	__u8 data[KAPKAN_FP_SNAP_LEN];
};

/* Per-CPU copy sampler. See the fp_* fields of kapkan_config for the math. */
struct kapkan_fp_sampler {
	__u64 last_ns;
	__u64 tokens_q32;
};

/*
 * The copy channel. A single MPSC ring buffer (5.8+, below Kapkan's 5.15
 * floor). Typeless by design — bpf_ringbuf_reserve returns raw space that the
 * datapath fills with a struct kapkan_fp_event; bpf2go still emits the Go type
 * because the program references it. The reader is a userspace ringbuf.Reader.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, KAPKAN_FP_RING_BYTES);
} kapkan_fp_events SEC(".maps");

/*
 * The sampler's per-CPU state, one entry. PERCPU so the hot gate is a plain
 * lookup with no atomics; the aggregate copy ceiling is therefore the
 * configured rate times the CPU count, a hard constant independent of packet
 * rate, which is all the DoS bound requires.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct kapkan_fp_sampler);
	__uint(max_entries, 1);
} kapkan_fp_sampler SEC(".maps");

/* ======================================================================== */
/* Shared helpers                                                            */
/* ======================================================================== */

/* Bump one verdict/reason counter. Never fails: an out-of-range index is a
 * programming error, and the null check keeps the verifier happy either way. */
static __always_inline void kapkan_count(__u32 stat, __u64 bytes)
{
	struct kapkan_counter *c = bpf_map_lookup_elem(&kapkan_stats, &stat);

	if (!c)
		return;
	c->pkts += 1;
	c->bytes += bytes;
}

#endif /* KAPKAN_MAPS_H */
