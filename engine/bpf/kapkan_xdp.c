// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * kapkan_xdp.c — Kapkan's in-kernel mitigation executor.
 *
 * ==========================================================================
 * CHARTER (governs every line in this file)
 * ==========================================================================
 * The data plane EXECUTES decisions made elsewhere. It never classifies, and
 * its default verdict is ALWAYS XDP_PASS. Every early exit, every parse
 * failure and every map miss passes the packet and bumps a counter. Malformed
 * frames pass unless cfg.drop_malformed is set. There is no default-deny
 * anywhere, and no rule-presence-flips-the-default behaviour.
 *
 * ==========================================================================
 * PACKET-PATH PRECEDENCE (normative)
 * ==========================================================================
 *   1. src allowlist        -> PASS            (kapkan_allow4/6)
 *   2. dst protected list   -> PASS            (kapkan_protect4/6 — the
 *                                               protected_whitelist mirror)
 *   3. static rules         -> first match wins
 *   4. dynamic src rules    -> source-flood / source-anchored entries
 *   5. dynamic dst rules    -> per-victim, bounded scan of <=8 rules,
 *                              first match wins
 *   6. default              -> PASS, counted
 *
 * Steps 1 and 2 are BOTH needed and are different things: dataplane.allowlist
 * is a SOURCE list; protected_whitelist is a DESTINATION list ("never ban this
 * victim"). Without the dst map in the kernel, a rehydrated or racing rule can
 * drop traffic to a protected prefix that the userspace sweep would only catch
 * on its next 1 Hz tick.
 *
 * ==========================================================================
 * WHERE EACH PRECEDENCE STEP LIVES
 * ==========================================================================
 *   1  kapkan_allow4/6    LPM on pkt.src            — see (1) in the body
 *   2  kapkan_protect4/6  LPM on pkt.dst            — see (2)
 *   3  kapkan_statics     bounded scan of static_count rules
 *   4  kapkan_victims4/6  LPM on pkt.SRC -> policy block, unrolled <=8 scan
 *   5  kapkan_victims4/6  LPM on pkt.DST -> policy block, unrolled <=8 scan
 *   6  fall through, count KAPKAN_STAT_PASS_DEFAULT, XDP_PASS
 *
 * Steps 4 and 5 share ONE trie. kapkan_victims4/6 is not "the list of
 * destinations" — it is "the set of prefixes that have a policy block", and it
 * is consulted on both axes because mitigate.FlowSpecRule anchors a rule on
 * either end: an INCOMING attack yields Dst=victim (found at step 5), an
 * OUTGOING one from a compromised host yields Src=victim (step 4), and a
 * source-anchored rule yields BOTH (found at 5, and harmlessly also reachable
 * at 4). Reaching a block by the "wrong" axis can never produce a wrong
 * verdict, because kapkan_rule_match() re-checks BOTH prefixes against the
 * packet before the rule may fire — the trie only ever narrows the candidates.
 *
 * ==========================================================================
 * IPv4-MAPPED IPv6 (::ffff:a.b.c.d) — WE DO NOT NORMALISE. Deliberate.
 * ==========================================================================
 * An IPv6 packet whose source is ::ffff:198.51.100.7 is matched against IPv6
 * rules only; it is never rewritten to the IPv4 address and never tested
 * against kapkan_allow4/kapkan_protect4/kapkan_victims4. Three reasons:
 *
 *   - They are different packets. The L3 header, the MTU, the ECMP hash and
 *     the upstream forwarding decision all differ; the data plane's job is to
 *     execute a decision about traffic on a wire, not about an abstract host.
 *   - The IR already keeps the families apart. mitigate.FlowSpecRule carries
 *     netip.Prefix values with a definite family, RFC 8956 gives IPv6 FlowSpec
 *     its own AFI, and sourceAnchoredRules() explicitly skips a source whose
 *     family differs from the victim's. Normalising here would make the kernel
 *     disagree with the BGP encoder about what a rule means.
 *   - It fails in the dangerous direction. Normalising would let an operator's
 *     IPv4 DROP rule silently start dropping IPv6 traffic nobody named.
 *
 * In practice ::ffff:0:0/96 is not routable on the wire (RFC 4291 reserves it
 * for a host's own socket API), so this costs nothing real. An operator who
 * wants both families covered writes both prefixes, exactly as they must for
 * every other tool in the path.
 */

#include "kapkan_bpf.h"
#include "kapkan_maps.h"

/*
 * VERIFIER RISK — IPv6 extension headers. The walk must be a bounded loop with
 * the bounds check INSIDE the loop, and hitting the cap must PASS. Eight is
 * generous for real traffic and small enough that the unrolled/verified path
 * stays cheap; a packet that chains more than eight extension headers is
 * either an attack shape we cannot classify or a bug, and per the charter we
 * forward it and count it (KAPKAN_STAT_PASS_EXTHDR_CAP).
 */
#define KAPKAN_MAX_EXT_HDRS 8

/*
 * One VLAN tag is walked. QinQ (a second tag) is counted and passed rather
 * than parsed: on the deployments Kapkan targets the scrubber sees at most one
 * tag, and each extra level is more verifier state on the hot path for traffic
 * we would not be able to attribute to a victim anyway.
 */
#define KAPKAN_MAX_VLAN_TAGS 1

/*
 * ==========================================================================
 * FUNCTION SHAPE IS A VERIFIER DECISION HERE, NOT A STYLE ONE
 * ==========================================================================
 * Three spellings are used deliberately, and the difference between them was
 * worth ~900,000 verifier instructions. Measured on a 6.12 kernel, whole
 * program, from the same test that prints the number on every run:
 *
 *   everything __always_inline ................. 979,105  (97.9% of budget)
 *   decision helpers as static subprograms ..... 822,035  (82.2%)
 *   + kapkan_decide() global ................... 275,639  (27.6%)
 *   + kapkan_rule_match() global ................ 82,422  ( 8.2%)
 *
 * Those four are one experiment, run against the program as it stood when the
 * shapes were chosen; they are a RATIO, and the ratio is what the rule below
 * rests on. The absolute figure moves whenever the program does — the TLS
 * ClientHello peek in kapkan_parse_l4() took it to 108,601 (10.9%), and the
 * QUIC Initial peek to 112,423 (11.2%), because a bounded read inside an
 * __always_inline parser is paid once per parser path and there are many.
 * TestProgramSize prints the current number on every run; read it there
 * rather than trusting this comment, and if a change ever puts the program
 * near the budget, re-read the rule before optimising anything else.
 *
 * THE FLOOR KERNEL IS NOT THE WORST CASE, which is worth knowing before
 * anyone budgets headroom for it: the same object measures 89,610 (9.0%) on
 * 5.15 and 108,601 (10.9%) on 6.12. The intuition that an older verifier must
 * process more is wrong here — the two walk different numbers of paths — so
 * "it fits on 6.12" has been the binding constraint, not "it fits on 5.15".
 * Both are measured by the kernel matrix (hack/kernel-matrix/run.sh); neither
 * is inferred from the other.
 *
 * The rule that produced those numbers:
 *
 *   __always_inline  — for tiny leaf helpers (bounds-checked pulls, mask
 *       arithmetic). One copy per call site is fine when the body is a handful
 *       of straight-line instructions, and a call would cost more than it
 *       saves.
 *
 *   __kapkan_subprog (static noinline) — for bodies with real size that are
 *       called from a FEW places. Emits one copy, so the instruction count
 *       stops multiplying, but the verifier still walks the body along every
 *       path that reaches it. Good enough off the hot scan.
 *
 *   GLOBAL (no `static`) — for the two functions on the hot scan:
 *       kapkan_decide() and kapkan_rule_match(). A global function is verified
 *       EXACTLY ONCE, standalone, and its callers are then only checked for
 *       argument validity. This is the only construct that breaks the
 *       multiplication of (parser paths) x (scan iterations) x (body paths),
 *       which is what was eating the budget: the static scan runs up to 256
 *       times, and without this the verifier re-walked the matcher on every
 *       iteration of every distinct parser path.
 *
 * The cost of `global` is that pointer arguments arrive as PTR_TO_MEM_OR_NULL
 * and must be null-checked inside the callee (the verifier is not looking at
 * the call sites when it checks the body). Both global functions do that
 * explicitly, and both returns are the fail-open answer.
 *
 * Kernel floor: BPF-to-BPF calls are 4.16+, pointer arguments to global
 * functions are 5.13+ (e5069b9c23b3, "bpf: Support pointers in global func
 * args"). Kapkan's floor is 5.15, so both are safely below it.
 *
 * Five arguments, maximum: the BPF calling convention passes arguments in
 * r1-r5 and clang rejects a sixth outright with "stack arguments are not
 * supported". That is why the frame length and the timestamp ride in
 * struct kapkan_pkt and the two counter ids are packed with KAPKAN_STATS().
 */
#define __kapkan_subprog static __attribute__((noinline))

/*
 * Parsed packet, in host order where it matters for rule matching. This is a
 * FILE-LOCAL struct, not part of freeze point F6 — nothing in userspace sees
 * it, so it is free to carry whatever the decision path finds convenient.
 *
 * `len` and `now` live here rather than in the argument lists for a hard
 * reason: the BPF calling convention passes arguments in r1-r5, so a
 * subprogram takes AT MOST FIVE, and clang rejects a sixth outright with
 * "stack arguments are not supported". Both values are invariant for the whole
 * traversal, which makes the context struct their natural home anyway — and it
 * guarantees every expiry check and every token bucket on the packet's path
 * agrees on the same instant.
 */
/*
 * ==========================================================================
 * WHY ADDRESSES ARE A UNION AND NOT `__u8 addr[16]`
 * ==========================================================================
 * This is worth 700,000 verifier instructions, so it gets a comment.
 *
 * The obvious spelling, `kapkan_pfx_match(const __u8 a[16], ...)`, decays the
 * parameter to a `const __u8 *` — alignment ONE. clang then cannot emit a
 * 64-bit load for `__builtin_memcpy(&w, a, 8)`; it emits eight byte loads plus
 * seven shift/OR pairs to reassemble each word. At four words per IPv6 compare
 * and up to two compares per rule across a 256-rule scan, that reassembly WAS
 * the program: the verifier log showed `r5 = *(u8 *)(r2 +6); r5 <<= 8; ...`
 * repeated until it hit "BPF program is too large. Processed 1000001 insn".
 *
 * A union whose widest member is a __u64 carries alignment 8, so the same
 * compare becomes two loads and two ANDs. The alignment is REAL, not asserted
 * into existence: the kernel gives every map value 8-byte alignment,
 * struct kapkan_rule is 64 bytes with src at offset 16 and dst at 32, and a
 * policy block puts rules[] at offset 8 — every one of those is a multiple of
 * 8. The _Static_asserts below fail the build if a future edit to F6 breaks
 * that, rather than letting the loads silently go unaligned.
 */
union kapkan_addr {
	__u8 b[16];
	__u32 w32[4];
	__u64 w64[2];
};

_Static_assert(sizeof(union kapkan_addr) == 16, "address view must be 16 bytes");
_Static_assert(_Alignof(union kapkan_addr) == 8, "address view must be 8-aligned");
_Static_assert(__builtin_offsetof(struct kapkan_rule, src) % 8 == 0,
	       "kapkan_rule.src must be 8-aligned for the wide prefix compare");
_Static_assert(__builtin_offsetof(struct kapkan_rule, dst) % 8 == 0,
	       "kapkan_rule.dst must be 8-aligned for the wide prefix compare");
_Static_assert(__builtin_offsetof(struct kapkan_policy_block, rules) % 8 == 0,
	       "policy block rules[] must be 8-aligned");
_Static_assert(sizeof(struct kapkan_rule) % 8 == 0,
	       "kapkan_rule must be a multiple of 8 so every slot stays aligned");

/*
 * Flag-bit positions are load-bearing constants, not just names.
 *
 * kapkan_rule_match() reads them as bare shift amounts — (f >> 7) for IPV6,
 * (f >> 6) for FRAGMENT, kapkan_test_mask(f, 3) for PROTO_ANY and so on —
 * because a shift by a literal is one instruction and the verifier's budget on
 * an unrolled 8-rule scan is not free. The cost of that is that reordering
 * enum kapkan_rule_flag would compile clean under -Wall -Werror and silently
 * change what every rule matches: no crash, no log line, just the wrong
 * packets dropped. The drift gate cannot catch it either, since it rebuilds
 * the object and would happily follow the change.
 *
 * So pin each literal to its enumerator here. If you renumber the enum, the
 * build stops until you fix the datapath to agree. The Go side has the mirror
 * of this in contract_test.go.
 */
_Static_assert(KAPKAN_RF_VALID == 1u << 0, "RF_VALID must be bit 0: the empty-slot test is (f & RF_VALID) ^ 1");
_Static_assert(KAPKAN_RF_SRC_ANY == 1u << 1, "RF_SRC_ANY must be bit 1: kapkan_test_mask(f, 1)");
_Static_assert(KAPKAN_RF_DST_ANY == 1u << 2, "RF_DST_ANY must be bit 2: kapkan_test_mask(f, 2)");
_Static_assert(KAPKAN_RF_PROTO_ANY == 1u << 3, "RF_PROTO_ANY must be bit 3: kapkan_test_mask(f, 3)");
_Static_assert(KAPKAN_RF_SPORT_ANY == 1u << 4, "RF_SPORT_ANY must be bit 4: kapkan_test_mask(f, 4)");
_Static_assert(KAPKAN_RF_DPORT_ANY == 1u << 5, "RF_DPORT_ANY must be bit 5: kapkan_test_mask(f, 5)");
_Static_assert(KAPKAN_RF_FRAGMENT == 1u << 6, "RF_FRAGMENT must be bit 6: read as (f >> 6) & 1");
_Static_assert(KAPKAN_RF_IPV6 == 1u << 7, "RF_IPV6 must be bit 7: read as (f >> 7) & 1");
_Static_assert(KAPKAN_MX_TLS_CLIENT_HELLO == 1u << 0,
	       "MX_TLS_CLIENT_HELLO must be bit 0: its match term gates without a shift");
_Static_assert(KAPKAN_MX_QUIC_INITIAL == 1u << 1,
	       "MX_QUIC_INITIAL must be bit 1: its match term reads (match_ext >> 1) & 1");
_Static_assert(KAPKAN_FP_SNAP_LEN % 64 == 0,
	       "fingerprint snapshot must be a multiple of 64: kapkan_fp_emit copies in 64-byte blocks");

struct kapkan_pkt {
	union kapkan_addr src; /* network order; v4 left-aligned in [0..3] */
	union kapkan_addr dst; /* network order; v4 left-aligned in [0..3] */
	__u64 len;	 /* frame length, for every counter          */
	__u64 now;	 /* boot-clock ns, read once per packet      */
	__u16 sport;	 /* host order; 0 when there are no ports    */
	__u16 dport;	 /* host order; 0 when there are no ports    */
	__u8 proto;	 /* final L4 protocol after any ext-hdr walk */
	__u8 tcp_flags;	 /* raw TCP flag byte; 0 when not TCP        */
	__u8 is_v6;
	__u8 is_frag;
	__u8 have_ports;
	__u8 is_tls_chello;   /* TCP payload opens a TLS ClientHello     */
	__u8 is_quic_initial; /* UDP payload opens a QUIC v1 Initial     */
	__u32 fp_off;	 /* frame offset of the L4 payload to copy for the
			  * fingerprint plane; only meaningful when one of the
			  * two bits above is set. See kapkan_fp_emit.        */
};

/*
 * The pass/drop counter pair a precedence level reports under, packed into one
 * u32 for the same five-argument reason. Both are small enum values.
 */
#define KAPKAN_STATS(pass, drop) ((__u32)(pass) | ((__u32)(drop) << 16))
#define KAPKAN_STATS_PASS(v)	 ((v) & 0xFFFF)
#define KAPKAN_STATS_DROP(v)	 ((v) >> 16)

/*
 * Bounds-checked read of `sz` bytes at *off, advancing *off on success.
 * Returns NULL when the packet is too short. Every single packet access in
 * this file goes through this helper: the verifier requires the data_end
 * comparison to dominate the dereference, and funnelling it through one
 * __always_inline helper is what keeps that provable at every call site.
 */
static __always_inline void *kapkan_pull(void *data, void *data_end,
					 __u32 *off, __u32 sz)
{
	void *p = data + *off;

	/* The (p + sz) > data_end form is the one the verifier reasons about
	 * best; comparing offsets against a computed length is not. */
	if (p + sz > data_end)
		return NULL;
	*off += sz;
	return p;
}

/* Copy an IPv4 address into the left-aligned 16-byte slot rule matching uses.
 * Two aligned 64-bit stores plus one 32-bit store, no memcpy loop. */
static __always_inline void kapkan_set_v4(union kapkan_addr *out, __be32 addr)
{
	out->w64[0] = 0;
	out->w64[1] = 0;
	out->w32[0] = addr;
}

/*
 * Parse the L4 ports and TCP flags. Only TCP and UDP carry ports; everything
 * else (ICMP, ESP, GRE, ...) leaves have_ports clear, and a rule that names a
 * port simply will not match it.
 *
 * PRECONDITION: the packet has an L4 header at *off. Both callers guarantee it
 * by returning KAPKAN_PARSE_OK before they get here when it does not — the
 * IPv4 path on (frag_off & IP_OFFSET), the IPv6 path on a fragment header
 * whose offset field is non-zero. In both cases have_ports is left clear and a
 * rule naming a port cannot match, while a rule naming only
 * KAPKAN_RF_FRAGMENT still can.
 *
 * DO NOT re-test pkt->is_frag here. That bit is set for a FIRST fragment too
 * (IPv4 MF with offset 0, or an IPv6 fragment header at offset 0), and a first
 * fragment does carry the whole L4 header. Skipping it would mean every
 * port-, TCP-flag- or protocol-with-ports rule silently missed the leading
 * fragment of every fragmented flood — and fragmented UDP amplification is one
 * of the commoner shapes this data plane exists to shed. It would also
 * mis-report those packets under KAPKAN_STAT_PASS_FRAG_NOPORTS, whose whole
 * meaning is "there was no L4 header here".
 */
static __always_inline int kapkan_parse_l4(void *data, void *data_end,
					   __u32 *off, struct kapkan_pkt *pkt)
{
	if (pkt->proto == IPPROTO_TCP) {
		struct tcphdr *th = kapkan_pull(data, data_end, off, sizeof(*th));
		__u32 dataoff, payload_off, hlen;
		__u8 *rec;

		if (!th)
			return -1;
		pkt->sport = bpf_ntohs(th->source);
		pkt->dport = bpf_ntohs(th->dest);
		/* Reassemble the flag byte in its wire order (CWR..FIN) so the
		 * value matches what an operator writes and what
		 * mitigate.FlowSpecRule.TCPFlags carries. */
		pkt->tcp_flags = (__u8)(th->fin | (th->syn << 1) |
					(th->rst << 2) | (th->psh << 3) |
					(th->ack << 4) | (th->urg << 5) |
					(th->ece << 6) | (th->cwr << 7));
		pkt->have_ports = 1;

		/*
		 * TLS ClientHello peek — KAPKAN_MX_TLS_CLIENT_HELLO.
		 *
		 * Six bytes at fixed offsets, and that is the whole feature:
		 *
		 *   [0]     0x16  TLS record type "handshake"
		 *   [1]     0x03  record-layer major version (every TLS to date,
		 *                 including 1.3, which keeps 0x03xx here for
		 *                 middlebox compatibility)
		 *   [2..4]        minor version + record length, not tested
		 *   [5]     0x01  handshake type "client_hello"
		 *
		 * NO REASSEMBLY, and that bound is deliberate rather than
		 * regrettable. A record split across segments, a ClientHello
		 * that does not start the segment, a capture truncated before
		 * byte six: all of them leave the bit CLEAR and the packet is
		 * ordinary TCP. The failure direction is the one this whole
		 * file is built on — a rule under-matches and the packet is
		 * forwarded, never the reverse.
		 *
		 * The offset must come from th->doff (TCP options are common on
		 * the first data segment, so assuming 20 would miss most real
		 * traffic), and doff is attacker-controlled: range-check it
		 * BEFORE it becomes an offset. Below 5 it is malformed and the
		 * peek is skipped; the 4-bit field cannot exceed 15, so the
		 * upper end needs no test and kapkan_pull's bounds check covers
		 * the frame anyway.
		 */
		hlen = (__u32)th->doff * 4;
		if (hlen < sizeof(*th))
			return 0;
		payload_off = *off - (__u32)sizeof(*th) + hlen;
		dataoff = payload_off;
		rec = kapkan_pull(data, data_end, &dataoff, 6);
		if (rec && rec[0] == 0x16 && rec[1] == 0x03 && rec[5] == 0x01) {
			pkt->is_tls_chello = 1;
			/* Where the fingerprint plane copies from: the TLS record
			 * start, i.e. the TCP payload. payload_off is the offset
			 * before kapkan_pull advanced dataoff past the 6-byte peek. */
			pkt->fp_off = payload_off;
		}
		return 0;
	}

	if (pkt->proto == IPPROTO_UDP) {
		struct udphdr *uh = kapkan_pull(data, data_end, off, sizeof(*uh));
		__u32 qoff;
		__u8 *q;

		if (!uh)
			return -1;
		pkt->sport = bpf_ntohs(uh->source);
		pkt->dport = bpf_ntohs(uh->dest);
		pkt->have_ports = 1;

		/*
		 * QUIC v1 Initial peek — KAPKAN_MX_QUIC_INITIAL, the UDP twin of
		 * the TLS peek above. Five bytes at fixed offsets, and that is
		 * the whole feature:
		 *
		 *   [0]    0xC0..0xCF  long-header form (bit 7) + the QUIC fixed
		 *                      bit (bit 6) + packet type Initial (bits
		 *                      5-4 zero); the low four bits are
		 *                      reserved/PN-length and are not tested
		 *   [1..4] 0x00000001  QUIC version 1
		 *
		 * What deliberately does NOT match: version negotiation (version
		 * 0), QUIC v2 (0x6b3343cf, which also renumbers Initial), and
		 * anything shorter than five bytes — all leave the bit CLEAR and
		 * the packet is ordinary UDP. Under-match and forward, never the
		 * reverse.
		 *
		 * RFC 9000 requires a client Initial to arrive in a >=1200-byte
		 * datagram, and that floor is deliberately NOT tested here: a
		 * rule on this bit must meter everything the victim's QUIC stack
		 * has to parse, and a flood of runt Initials is exactly the
		 * traffic an attacker would craft to slip under a size gate.
		 * Unlike the TCP arm there is no header-length arithmetic — the
		 * payload starts right after the 8-byte UDP header, so there is
		 * nothing attacker-controlled between *off and the peek.
		 */
		qoff = *off;
		q = kapkan_pull(data, data_end, &qoff, 5);
		if (q && (q[0] & 0xF0) == 0xC0 && q[1] == 0x00 &&
		    q[2] == 0x00 && q[3] == 0x00 && q[4] == 0x01) {
			pkt->is_quic_initial = 1;
			/* The fingerprint plane copies from the QUIC long header,
			 * i.e. the UDP payload at *off (before kapkan_pull moved
			 * qoff past the 5-byte peek). */
			pkt->fp_off = *off;
		}
		return 0;
	}

	return 0;
}

/* Parse result codes. Anything negative means "could not parse". */
#define KAPKAN_PARSE_OK		0
#define KAPKAN_PARSE_NOT_IP	1  /* ARP/LLDP/...: not ours, pass          */
#define KAPKAN_PARSE_VLAN_DEPTH	2  /* more tags than we walk                */
#define KAPKAN_PARSE_EXTHDR_CAP	3  /* hit KAPKAN_MAX_EXT_HDRS               */
#define KAPKAN_PARSE_MALFORMED	-1 /* truncated: subject to drop_malformed  */

static __always_inline int kapkan_parse(void *data, void *data_end,
					struct kapkan_pkt *pkt)
{
	struct ethhdr *eth;
	__u32 off = 0;
	__u16 proto;
	int i;

	__builtin_memset(pkt, 0, sizeof(*pkt));

	eth = kapkan_pull(data, data_end, &off, sizeof(*eth));
	if (!eth)
		return KAPKAN_PARSE_MALFORMED;
	proto = bpf_ntohs(eth->h_proto);

	/* One VLAN tag. Written as a bounded loop so raising
	 * KAPKAN_MAX_VLAN_TAGS is a one-line change; unrolled because the
	 * trip count is a compile-time constant. */
#pragma unroll
	for (i = 0; i < KAPKAN_MAX_VLAN_TAGS; i++) {
		struct vlan_hdr *vh;

		if (proto != ETH_P_8021Q && proto != ETH_P_8021AD)
			break;
		vh = kapkan_pull(data, data_end, &off, sizeof(*vh));
		if (!vh)
			return KAPKAN_PARSE_MALFORMED;
		proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
	}
	if (proto == ETH_P_8021Q || proto == ETH_P_8021AD)
		return KAPKAN_PARSE_VLAN_DEPTH;

	if (proto == ETH_P_IP) {
		struct iphdr *iph = kapkan_pull(data, data_end, &off, sizeof(*iph));
		__u32 ihl_bytes;
		__u16 frag;

		if (!iph)
			return KAPKAN_PARSE_MALFORMED;
		if (iph->version != 4)
			return KAPKAN_PARSE_MALFORMED;

		/* ihl is 4 bits so it is at most 15; the verifier still needs
		 * the explicit floor check because ihl < 5 is a malformed
		 * header that would make ihl_bytes underflow the fixed part. */
		if (iph->ihl < 5)
			return KAPKAN_PARSE_MALFORMED;
		ihl_bytes = (__u32)iph->ihl * 4;
		if (ihl_bytes > sizeof(*iph)) {
			/* Skip IPv4 options. The bound is proven: ihl <= 15 so
			 * this is at most 40 bytes. */
			__u32 optlen = ihl_bytes - (__u32)sizeof(*iph);

			if (optlen > 40)
				return KAPKAN_PARSE_MALFORMED;
			if (!kapkan_pull(data, data_end, &off, optlen))
				return KAPKAN_PARSE_MALFORMED;
		}

		kapkan_set_v4(&pkt->src, iph->saddr);
		kapkan_set_v4(&pkt->dst, iph->daddr);
		pkt->proto = iph->protocol;

		/* Fragmented iff MF is set or the offset is non-zero. A
		 * non-first fragment (offset != 0) has no L4 header. */
		frag = bpf_ntohs(iph->frag_off);
		if (frag & (IP_MF | IP_OFFSET))
			pkt->is_frag = 1;
		if (frag & IP_OFFSET) {
			/* No ports to read; leave have_ports clear. */
			return KAPKAN_PARSE_OK;
		}

		if (kapkan_parse_l4(data, data_end, &off, pkt) < 0)
			return KAPKAN_PARSE_MALFORMED;
		return KAPKAN_PARSE_OK;
	}

	if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = kapkan_pull(data, data_end, &off, sizeof(*ip6));
		__u8 nexthdr;

		if (!ip6)
			return KAPKAN_PARSE_MALFORMED;

		__builtin_memcpy(pkt->src.b, &ip6->saddr, 16);
		__builtin_memcpy(pkt->dst.b, &ip6->daddr, 16);
		pkt->is_v6 = 1;
		nexthdr = ip6->nexthdr;

		/*
		 * VERIFIER RISK — the extension-header walk. Rules that make
		 * this verify on a 5.15 kernel:
		 *   - the trip count is the compile-time constant
		 *     KAPKAN_MAX_EXT_HDRS, so the loop unrolls and no
		 *     bpf_loop() (5.17+) is needed;
		 *   - every header read goes through kapkan_pull(), so the
		 *     data_end bound is re-checked INSIDE the loop body, not
		 *     hoisted;
		 *   - the per-header advance is derived from an 8-bit field
		 *     and clamped, so the offset cannot be pushed out of range
		 *     by a crafted hdrlen;
		 *   - falling off the end of the loop (the cap) PASSES.
		 */
#pragma unroll
		for (i = 0; i < KAPKAN_MAX_EXT_HDRS; i++) {
			struct ipv6_opt_hdr *oh;
			__u32 hdrlen;

			if (nexthdr == IPPROTO_FRAGMENT) {
				struct ipv6_frag_hdr *fh =
					kapkan_pull(data, data_end, &off, sizeof(*fh));

				if (!fh)
					return KAPKAN_PARSE_MALFORMED;
				pkt->is_frag = 1;
				/* Offset lives in the top 13 bits. A non-first
				 * fragment carries no L4 header. */
				if (bpf_ntohs(fh->frag_off) & 0xFFF8) {
					pkt->proto = fh->nexthdr;
					return KAPKAN_PARSE_OK;
				}
				nexthdr = fh->nexthdr;
				continue;
			}

			if (nexthdr == IPPROTO_AH) {
				struct ip_auth_hdr *ah =
					kapkan_pull(data, data_end, &off, sizeof(*ah));

				if (!ah)
					return KAPKAN_PARSE_MALFORMED;
				/* AH measures in 4-octet units, minus 2, and
				 * we have already consumed 12 bytes. */
				hdrlen = ((__u32)ah->hdrlen + 2) * 4;
				if (hdrlen < sizeof(*ah))
					return KAPKAN_PARSE_MALFORMED;
				hdrlen -= (__u32)sizeof(*ah);
				if (hdrlen > 0xFF)
					return KAPKAN_PARSE_MALFORMED;
				if (hdrlen &&
				    !kapkan_pull(data, data_end, &off, hdrlen))
					return KAPKAN_PARSE_MALFORMED;
				nexthdr = ah->nexthdr;
				continue;
			}

			/*
			 * The four TLV-shaped extension headers, which all
			 * measure their length the same way. ANYTHING else
			 * ends the walk: every L4 protocol (TCP, UDP, ICMPv6,
			 * ESP, GRE, ...) and IPPROTO_NONE alike.
			 *
			 * This single test used to be preceded by an explicit
			 * "is it one of the five common L4 protocols" break and
			 * an IPPROTO_NONE early return. Both were REDUNDANT —
			 * this condition already caught them — and both were
			 * expensive in a way that is invisible until you
			 * measure: six extra comparisons and an extra exit
			 * path, in an unrolled 8-iteration loop, multiply into
			 * every path the rule scans downstream are verified
			 * along. Deleting them cut the verifier's processed
			 * count by roughly a third. IPPROTO_NONE now simply
			 * falls out of the loop as pkt->proto, and
			 * kapkan_parse_l4() ignores it because it is neither
			 * TCP nor UDP — same behaviour, a third of the cost.
			 */
			if (nexthdr != IPPROTO_HOPOPTS &&
			    nexthdr != IPPROTO_ROUTING &&
			    nexthdr != IPPROTO_DSTOPTS &&
			    nexthdr != IPPROTO_MH)
				break;

			oh = kapkan_pull(data, data_end, &off, sizeof(*oh));
			if (!oh)
				return KAPKAN_PARSE_MALFORMED;
			/* hdrlen counts 8-octet units NOT including the first
			 * 8; we have consumed 2, so skip the remaining 6 plus
			 * 8 per unit. Bounded by 255*8+6 = 2046. */
			hdrlen = ((__u32)oh->hdrlen * 8) + 6;
			if (!kapkan_pull(data, data_end, &off, hdrlen))
				return KAPKAN_PARSE_MALFORMED;
			nexthdr = oh->nexthdr;
		}

		/* Hitting the cap means `i` ran to the end without a break.
		 * Per the charter: forward and count. */
		if (i == KAPKAN_MAX_EXT_HDRS)
			return KAPKAN_PARSE_EXTHDR_CAP;

		pkt->proto = nexthdr;
		if (kapkan_parse_l4(data, data_end, &off, pkt) < 0)
			return KAPKAN_PARSE_MALFORMED;
		return KAPKAN_PARSE_OK;
	}

	return KAPKAN_PARSE_NOT_IP;
}

/* ======================================================================== */
/* Prefix matching                                                           */
/* ======================================================================== */
/*
 * A rule stores its prefix as raw network-order bytes plus a bit length, and
 * the packet's addresses are held the same way, so a match is "do the top
 * `bits` bits agree".
 *
 * Both helpers return the MISMATCHING BITS rather than a boolean, so the
 * caller can OR them into an accumulator instead of branching on each one.
 * See the note above kapkan_rule_match() for why that matters so much.
 *
 * The mask is built in NETWORK byte order (one byteswap of a shifted word) and
 * ANDed against the raw, unswapped address words: swapping the mask once is
 * cheaper than swapping both operands, and it stays exact at every length.
 *
 * Shift safety: C and BPF both leave a shift of >= the word width undefined,
 * and the verifier will not reason about it for us. Each helper clamps its
 * length ONCE and then shifts a wider type, so no shift count can reach the
 * width of the value being shifted. A prefix length out of range for its
 * family is a userspace encoding bug; clamping makes it match LESS, never
 * more, which is the safe direction.
 */

/*
 * IPv4. bits is clamped to 32, then the mask is derived by shifting a 64-bit
 * word so that a /0 (shift of 32) is still a defined operation and yields the
 * correct empty mask.
 */
static __always_inline __u32 kapkan_pfx_bad_v4(const union kapkan_addr *addr,
					       const union kapkan_addr *pfx,
					       __u32 bits)
{
	__u32 m;

	if (bits > 32)
		bits = 32;
	m = (__u32)((~0ULL << (32 - bits)) & 0xFFFFFFFFULL);
	return (addr->w32[0] ^ pfx->w32[0]) & __builtin_bswap32(m);
}

/*
 * IPv6, as two 64-bit halves. The /0 and /64 edges are the awkward ones: a
 * 64-bit word cannot be shifted by 64, so the high half is masked by shifting
 * in two steps (<< (63 - bits) then << 1), which is defined for every bits in
 * [0, 63], and the >= 64 case skips the shift entirely because the whole word
 * must then match.
 */
static __always_inline __u64 kapkan_pfx_bad_v6(const union kapkan_addr *addr,
					       const union kapkan_addr *pfx,
					       __u32 bits)
{
	__u64 mhi, mlo;
	__u32 lo;

	if (bits > 128)
		bits = 128;

	if (bits >= 64) {
		mhi = ~0ULL;
		lo = bits - 64;			/* 0..64 */
		mlo = lo >= 64 ? ~0ULL
				: __builtin_bswap64((~0ULL << (63 - lo)) << 1);
	} else {
		mhi = __builtin_bswap64((~0ULL << (63 - bits)) << 1);
		mlo = 0;
	}

	return ((addr->w64[0] ^ pfx->w64[0]) & mhi) |
	       ((addr->w64[1] ^ pfx->w64[1]) & mlo);
}

/*
 * All-ones when a field must be tested, zero when the rule says "any".
 * `any_shift` is the bit position of the matching KAPKAN_RF_*_ANY flag.
 *
 * The subtraction is the whole trick: (flag & 1) is 1 for "any", and 1 - 1 is
 * 0, so the field's comparison gets masked away; it is 0 when the field must
 * be tested, and 0 - 1 underflows to all-ones, so the comparison survives.
 * No branch either way.
 */
static __always_inline __u64 kapkan_test_mask(__u32 flags, __u32 any_shift)
{
	return (__u64)((flags >> any_shift) & 1) - 1;
}

/* ======================================================================== */
/* Rule matching                                                             */
/* ======================================================================== */
/*
 * Does this rule describe this packet? Field-for-field the same predicate the
 * BGP encoder builds in mitigate.flowSpecNLRI(), so a rule handed to a
 * FlowSpec peer and the same rule handed to this data plane select the same
 * packets.
 *
 * ==========================================================================
 * THIS FUNCTION IS GLOBAL, AND BRANCHLESS. Both, and in that order.
 * ==========================================================================
 * It is called from the body of a scan the verifier must walk up to 256 times,
 * so its shape dominates the complexity budget.
 *
 * GLOBAL (note the missing `static`) is the load-bearing half: a global
 * function is verified exactly once instead of on every path that reaches it.
 * That alone took the whole program from 275,639 processed instructions to
 * 82,422 — both figures from the experiment in the header comment, which also
 * says why the absolute number has moved since.
 *
 * BRANCHLESS is the supporting half, and it is worth being honest about the
 * measurement: folding the early-exit ladder into one accumulator made things
 * WORSE on its own (702,682 -> 822,035), because every call then executes the
 * full body and carries more live state into the loop. It only pays once the
 * function is global and that single path is verified a single time. Anyone
 * tempted to "simplify" this back into a readable ladder should re-measure
 * both changes together, not one at a time.
 *
 * The enabling observation for the branchless form is that BPF has no
 * set-on-condition instruction — every `!=` becomes a jump — but equality can
 * be written as XOR, which is pure arithmetic:
 *
 *      a != b            ->   (a ^ b)          nonzero iff they differ
 *      "field is any"    ->   & kapkan_test_mask(...)
 *      "prefix mismatch" ->   the masked XOR itself
 *
 * OR those together and the rule matches iff the accumulator is zero. Only the
 * address-family split and the final test remain as branches.
 *
 * ==========================================================================
 * TCP FLAGS — the semantics that must not drift.
 * ==========================================================================
 * RFC 8955 type 9 with the bitmask operator's MATCH bit set (gobgp's
 * BITMASK_FLAG_OP_MATCH, which is what flowSpecNLRI emits for
 * FlowSpecRule.TCPFlags) means "every bit in the value is set in the packet",
 * NOT "the packet's flag byte equals the value". That is exactly why
 * FlowSpecRule documents "SYN also matches SYN-ACK": a SYN-flood rule carries
 * 0x02, and 0x12 (SYN|ACK) & 0x02 == 0x02, so it hits. The kernel spells the
 * same thing as (observed & mask) == expected, with userspace setting
 * mask == expected == TCPFlags for the FlowSpec case. The extra mask byte also
 * lets an operator write an EXACT match (mask 0xFF) for a NULL scan, which
 * FlowSpec's bitmask alone cannot express.
 *
 * FRAGMENTS are matchable, never automatic. KAPKAN_RF_FRAGMENT set means "only
 * fragmented packets"; clear means the rule is indifferent, matching fragments
 * and whole datagrams alike — which mirrors FlowSpec, where an absent type-12
 * component means "any". Nothing in this file drops a packet for the sole
 * reason that it is a fragment.
 */
int kapkan_rule_match(const struct kapkan_rule *r,
		      const struct kapkan_pkt *pkt)
{
	const union kapkan_addr *rsrc, *rdst;
	__u32 f, tfm, v6, noports, nz;
	__u64 bad = 0;
	__u64 msrc, mdst;

	if (!r || !pkt)
		return 0;

	f = r->flags;
	tfm = r->tcp_flags_mask;
	v6 = pkt->is_v6;
	/* "no ports here": 1 when the packet carries no L4 header at all. */
	noports = (__u32)pkt->have_ports ^ 1;

	/* Empty slot. RF_VALID clear => never matches. */
	bad |= (f & KAPKAN_RF_VALID) ^ 1;

	/* Address family: the rule's RF_IPV6 bit must equal the packet's.
	 * A v4 rule never matches a v6 packet or vice versa — see the
	 * IPv4-mapped-IPv6 note at the top of this file. */
	bad |= ((f >> 7) & 1) ^ v6;

	/* RF_FRAGMENT set => the packet must be a fragment. Clear => the rule
	 * is indifferent, so the term vanishes. */
	bad |= ((f >> 6) & 1) & ((__u32)pkt->is_frag ^ 1);

	/* MX_TLS_CLIENT_HELLO, same shape: set => the packet must be one.
	 * Clear => the term vanishes, which is why every rule written before
	 * this bit existed keeps matching exactly what it used to. */
	bad |= (__u32)(r->match_ext & KAPKAN_MX_TLS_CLIENT_HELLO) &
	       ((__u32)pkt->is_tls_chello ^ 1);

	/* MX_QUIC_INITIAL, one bit up. The shift collapses the flag to 0/1
	 * before it can gate the term — bit 1's raw value is 2, and `2 & 1`
	 * would erase the term no matter what the packet is. The TLS term
	 * above skips the shift only because its flag IS bit 0; the
	 * _Static_asserts at the top of this file hold both in place. */
	bad |= (__u32)((r->match_ext >> 1) & 1) &
	       ((__u32)pkt->is_quic_initial ^ 1);

	bad |= ((__u32)r->proto ^ (__u32)pkt->proto) &
	       kapkan_test_mask(f, 3); /* RF_PROTO_ANY */

	/* A rule that names a port cannot match a packet with no L4 header
	 * (a non-first fragment), hence the `noports` term rather than a
	 * comparison against the zeroed sport/dport. */
	bad |= (((__u32)r->sport ^ (__u32)pkt->sport) | noports) &
	       kapkan_test_mask(f, 4); /* RF_SPORT_ANY */
	bad |= (((__u32)r->dport ^ (__u32)pkt->dport) | noports) &
	       kapkan_test_mask(f, 5); /* RF_DPORT_ANY */

	/* tcp_flags_mask == 0 means "do not test flags" (see kapkan_maps.h).
	 * `nz` is that test without a branch: for tfm in [0,255],
	 * (tfm + 255) >> 8 is 0 exactly when tfm is 0, and 1 otherwise, and
	 * negating that 0/1 gives the all-ones-or-zero mask. */
	nz = (tfm + 0xFF) >> 8;
	bad |= ((((__u32)pkt->tcp_flags & tfm) ^ (__u32)r->tcp_flags) |
		((__u32)pkt->proto ^ IPPROTO_TCP) | noports) &
	       (__u64)(0 - (__u64)nz);

	/* The casts are sound by the _Static_asserts at the top of this file:
	 * kapkan_rule.src/.dst sit at 8-aligned offsets of an 8-aligned map
	 * value, so the wide view never produces an unaligned load. */
	rsrc = (const union kapkan_addr *)r->src;
	rdst = (const union kapkan_addr *)r->dst;

	msrc = kapkan_test_mask(f, 1); /* RF_SRC_ANY */
	mdst = kapkan_test_mask(f, 2); /* RF_DST_ANY */

	/* The one remaining branch besides the final test: the two families
	 * read different widths, and folding them together would cost more
	 * than it saves. */
	if (v6) {
		bad |= kapkan_pfx_bad_v6(&pkt->src, rsrc, r->src_prefixlen) & msrc;
		bad |= kapkan_pfx_bad_v6(&pkt->dst, rdst, r->dst_prefixlen) & mdst;
	} else {
		bad |= kapkan_pfx_bad_v4(&pkt->src, rsrc, r->src_prefixlen) & msrc;
		bad |= kapkan_pfx_bad_v4(&pkt->dst, rdst, r->dst_prefixlen) & mdst;
	}

	return bad == 0;
}

/* ======================================================================== */
/* Token bucket                                                              */
/* ======================================================================== */
/*
 * The per-source rate limiter. This is the one capability BGP FlowSpec
 * structurally cannot express: FlowSpec's traffic-rate community caps an
 * AGGREGATE, so "cap every source at N pps" would need one rule per source.
 * Here the bucket is keyed {anchor, source, profile}, so a single rule caps
 * each attacker independently and a flood of a million sources costs a million
 * cheap LRU entries instead of a million rules.
 *
 * NO RUNTIME DIVISION. Refill is (elapsed_ns * tokens_per_ns) in Q32 fixed
 * point, with tokens_per_ns precomputed by userspace into the profile. The
 * datapath does one multiply and one shift-free compare.
 *
 * OVERFLOW IS PROVEN HERE, NOT PROMISED BY USERSPACE. kapkan_profiles is a map
 * an operator's manager writes, so this code treats its contents as untrusted:
 * `delta` is clamped to 2^32 ns and each Q32 rate is clamped to 2^32-1, so the
 * product is strictly below 2^64 and cannot wrap however the map is filled.
 *
 * APPROXIMATIONS, all deliberate and all in the fail-open direction:
 *   - Read-modify-write on the bucket is NOT atomic. Two CPUs handling the
 *     same source in the same instant can each see the pre-decrement value and
 *     both admit. The error is bounded by the CPU count per refill interval,
 *     which against a flood is noise; the alternative is a contended
 *     cmpxchg on a line that every RX queue touches.
 *   - Clamping `delta` at ~4.295 s means a bucket idle for longer refills by
 *     4.295 s worth of rate rather than jumping straight to full. Invisible
 *     for any profile whose burst is under 4.295 s of its own rate, which is
 *     every sane DDoS ceiling; the error under-credits an idle source, so the
 *     limiter is momentarily stricter, never looser.
 *   - A clock that runs backwards (b->last_ns > now) makes `delta` underflow
 *     to a huge unsigned value, which the same clamp turns into a full refill.
 *     Fails open, per the charter.
 */

/* Clamp for the refill interval: 2^32 ns ~= 4.295 s. Paired with the Q32 rate
 * clamp below, this is what makes the multiply provably wrap-free. */
#define KAPKAN_RL_REFILL_CAP_NS	(1ULL << 32)
#define KAPKAN_Q32_MAX		0xFFFFFFFFULL

/*
 * Returns 1 to admit the packet, 0 to deny it. Every failure to look something
 * up admits: an unknown profile, a bucket the LRU refused to create, a profile
 * that caps nothing. The charter has no default-deny, and that includes here.
 */
__kapkan_subprog int kapkan_rl_admit(const struct kapkan_pkt *pkt,
				     const union kapkan_addr *anchor,
				     __u32 profile_id)
{
	struct kapkan_profile *prof;
	struct kapkan_bucket *b = NULL;
	struct kapkan_bucket fresh = {};
	__u64 delta, tp, tb, cap, q, need;
	__u64 now = pkt->now;
	__u64 len = pkt->len;
	int admit = 1;

	prof = bpf_map_lookup_elem(&kapkan_profiles, &profile_id);
	if (!prof)
		return 1; /* rule names a profile userspace never wrote */
	if (!prof->rate_pps && !prof->rate_bps)
		return 1; /* profile caps neither packets nor bytes */

	fresh.last_ns = now;
	fresh.tokens_pkt_q32 = prof->burst_pps << 32;
	fresh.tokens_byte_q32 = prof->burst_bps << 32;

	/*
	 * The two families duplicate only the key construction; the token
	 * arithmetic below exists once. On a miss we insert a FULL bucket and
	 * re-look-it-up, so a brand-new source starts with its whole burst
	 * (fail open) and the arithmetic path is identical for new and
	 * established sources. The extra lookup costs one map access on the
	 * first packet of a flow and nothing thereafter.
	 */
	if (pkt->is_v6) {
		struct kapkan_rl_key_v6 k = {};

		__builtin_memcpy(k.victim, anchor->b, 16);
		__builtin_memcpy(k.src, pkt->src.b, 16);
		k.profile = profile_id;
		b = bpf_map_lookup_elem(&kapkan_rl_src6, &k);
		if (!b) {
			bpf_map_update_elem(&kapkan_rl_src6, &k, &fresh, BPF_ANY);
			b = bpf_map_lookup_elem(&kapkan_rl_src6, &k);
		}
	} else {
		struct kapkan_rl_key_v4 k = {};

		k.victim = anchor->w32[0];
		k.src = pkt->src.w32[0];
		k.profile = profile_id;
		b = bpf_map_lookup_elem(&kapkan_rl_src4, &k);
		if (!b) {
			bpf_map_update_elem(&kapkan_rl_src4, &k, &fresh, BPF_ANY);
			b = bpf_map_lookup_elem(&kapkan_rl_src4, &k);
		}
	}
	/* VERIFIER: a map lookup returns a pointer the verifier cannot prove
	 * non-NULL, and the LRU may legitimately refuse the insert under
	 * pressure. Explicit check, and the miss admits. */
	if (!b)
		return 1;

	delta = now - b->last_ns;
	if (delta > KAPKAN_RL_REFILL_CAP_NS)
		delta = KAPKAN_RL_REFILL_CAP_NS;
	b->last_ns = now;

	tp = b->tokens_pkt_q32;
	tb = b->tokens_byte_q32;

	/*
	 * Two phases. Both ceilings are refilled and tested BEFORE either is
	 * consumed, so a packet the byte ceiling denies does not silently eat a
	 * packet token — "whichever is hit first admits nothing" has to mean
	 * the packet costs nothing either.
	 */
	if (prof->rate_pps) {
		q = prof->pkt_per_ns_q32;
		if (q > KAPKAN_Q32_MAX)
			q = KAPKAN_Q32_MAX;
		cap = prof->burst_pps;
		if (cap > KAPKAN_Q32_MAX)
			cap = KAPKAN_Q32_MAX;
		cap <<= 32;

		tp += delta * q; /* < 2^32 * 2^32 == 2^64: cannot wrap */
		if (tp > cap)
			tp = cap;
		if (tp < (1ULL << 32))
			admit = 0;
	}
	if (prof->rate_bps) {
		q = prof->byte_per_ns_q32;
		if (q > KAPKAN_Q32_MAX)
			q = KAPKAN_Q32_MAX;
		cap = prof->burst_bps;
		if (cap > KAPKAN_Q32_MAX)
			cap = KAPKAN_Q32_MAX;
		cap <<= 32;

		tb += delta * q;
		if (tb > cap)
			tb = cap;
		need = len << 32; /* len is a frame size: << 32 cannot wrap */
		if (tb < need)
			admit = 0;
	}

	if (admit) {
		if (prof->rate_pps)
			tp -= 1ULL << 32;
		if (prof->rate_bps)
			tb -= len << 32;
	}

	b->tokens_pkt_q32 = tp;
	b->tokens_byte_q32 = tb;
	return admit;
}

/* ======================================================================== */
/* The fingerprint plane (E2)                                                 */
/* ======================================================================== */
/*
 * Off-path observation, never a verdict. Both helpers below run only for a
 * packet the parser recognised as a TLS ClientHello or a QUIC Initial, only
 * when cfg->fp_enabled, and only AFTER the allowlist/protected checks have let
 * the packet through — an allowlisted source can never be source-blocked, so
 * fingerprinting it would be wasted copy. Nothing here can change what
 * kapkan_xdp_filter returns.
 */

/*
 * The copy sampler: a per-CPU token bucket, arithmetically identical to
 * kapkan_rl_admit's, that caps how many copies this CPU emits per second. It is
 * what makes the plane immune to becoming its own DoS: copy volume is bounded by
 * the configured rate, not by packet rate.
 *
 * ITS FAILURE DIRECTION IS THE OPPOSITE OF THE REST OF THE FILE. Everywhere
 * else a lookup miss PASSES the packet (fail open). Here a miss returns 0 = "do
 * not copy" (fail closed), because a lost copy costs nothing — userspace simply
 * does not fingerprint that one handshake — while a copy emitted on a failed
 * lookup would be an uncapped copy, which is the exact attack surface the
 * sampler exists to remove. Returns 1 to copy, 0 to skip.
 */
static __always_inline int kapkan_fp_sample(const struct kapkan_config *cfg, __u64 now)
{
	__u32 zero = 0;
	struct kapkan_fp_sampler *s;
	__u64 delta, tok, cap, q;

	s = bpf_map_lookup_elem(&kapkan_fp_sampler, &zero);
	if (!s)
		return 0; /* fail closed — see the note above */

	delta = now - s->last_ns;
	if (delta > KAPKAN_RL_REFILL_CAP_NS)
		delta = KAPKAN_RL_REFILL_CAP_NS;
	s->last_ns = now;

	q = cfg->fp_rate_per_ns_q32;
	if (q > KAPKAN_Q32_MAX)
		q = KAPKAN_Q32_MAX;
	cap = cfg->fp_burst;
	if (cap > KAPKAN_Q32_MAX)
		cap = KAPKAN_Q32_MAX;
	cap <<= 32;

	tok = s->tokens_q32 + delta * q; /* < 2^32 * 2^32 == 2^64: cannot wrap */
	if (tok > cap)
		tok = cap;
	if (tok < (1ULL << 32)) {
		s->tokens_q32 = tok;
		return 0;
	}
	s->tokens_q32 = tok - (1ULL << 32);
	return 1;
}

/*
 * The largest L4-payload offset the copy will start from. A recognised
 * ClientHello/Initial sits a few dozen bytes into the frame (Ethernet + VLAN +
 * IP(+ext hdrs) + TCP/UDP); this ceiling exists only so the verifier can treat
 * `data + off` as a BOUNDED variable-offset packet pointer. A packet whose
 * payload begins past it is not one we can usefully fingerprint, so it is
 * skipped rather than copied from the wrong place.
 */
#define KAPKAN_FP_MAX_OFF 2048

/*
 * Copy the recognised handshake into the ring. Reserve a fixed-size record,
 * fill the metadata, then copy a prefix of the L4 payload in fixed 64-byte
 * blocks.
 *
 * THE COPY ADVANCES ONE PACKET POINTER, and that is a verifier requirement, not
 * a style choice. The payload starts at a RUNTIME offset (fp_off, from the TCP
 * header length), so `data + off` is a variable-offset packet pointer. Two rules
 * make the loop verify on the 5.15 floor:
 *   - `off` is bounded first (the KAPKAN_FP_MAX_OFF guard), or the verifier
 *     cannot reason about `data + off` at all;
 *   - a single pointer `p` is ADVANCED by 64 each block and re-checked against
 *     data_end, rather than re-deriving `data + off + i*64` each iteration.
 *     Re-deriving resets the proven readable range to zero and the verifier
 *     rejects the access ("invalid access to packet ... r=0") — which is exactly
 *     what the first cut of this did.
 * Each block is a constant-length __builtin_memcpy at a compile-time dst offset,
 * so no byte loop is needed and the instruction budget stays small. A block that
 * would run past data_end stops the copy; snap_len records the 64-byte-granular
 * prefix captured, and userspace fingerprints what it got and fails open.
 *
 * __always_inline with a single call site, so the copy is emitted once and the
 * packet pointers stay direct (a global function cannot take PTR_TO_PACKET).
 */
static __always_inline void kapkan_fp_emit(void *data, void *data_end,
					   const struct kapkan_pkt *pkt)
{
	struct kapkan_fp_event *e;
	__u32 off = pkt->fp_off;
	__u32 snap = 0;
	unsigned char *p;
	int i;

	/* The caller already gates on fp_off <= KAPKAN_FP_MAX_OFF, so this never
	 * fires at runtime; it stays because it is what bounds `off` for the
	 * verifier (data + off below must be a bounded variable-offset pointer) and
	 * it keeps kapkan_fp_emit safe if ever called from a second site. */
	if (off > KAPKAN_FP_MAX_OFF)
		return;

	e = bpf_ringbuf_reserve(&kapkan_fp_events, sizeof(*e), 0);
	if (!e) {
		kapkan_count(KAPKAN_STAT_FP_RING_FULL, pkt->len);
		return;
	}

	__builtin_memcpy(e->src, pkt->src.b, 16);
	__builtin_memcpy(e->dst, pkt->dst.b, 16);
	e->sport = pkt->sport;
	e->dport = pkt->dport;
	e->is_v6 = pkt->is_v6;
	e->proto = pkt->proto;
	e->axis = pkt->is_tls_chello ? KAPKAN_MX_TLS_CLIENT_HELLO
				     : KAPKAN_MX_QUIC_INITIAL;
	e->_pad = 0;
	e->pkt_len = (__u32)pkt->len;
	e->_pad2 = 0;

	p = (unsigned char *)data + off;
#pragma unroll
	for (i = 0; i < KAPKAN_FP_SNAP_LEN / 64; i++) {
		if (p + 64 > (unsigned char *)data_end)
			break;
		__builtin_memcpy(&e->data[i * 64], p, 64);
		p += 64;
		snap += 64;
	}
	e->snap_len = snap;

	bpf_ringbuf_submit(e, 0);
	kapkan_count(KAPKAN_STAT_FP_EMITTED, pkt->len);
}

/*
 * BTF ANCHOR for struct kapkan_fp_event. A BPF_MAP_TYPE_RINGBUF is typeless —
 * nothing declares the record as a map key or value — so clang emits the map
 * but NOT the struct into the object's BTF, and bpf2go's `-type kapkan_fp_event`
 * would fail to generate the Go decoder (verified: the type is absent from .BTF
 * without this). A global (external-linkage) function names the type in its
 * prototype, which forces the full definition into BTF exactly as the prototypes
 * of kapkan_decide()/kapkan_rule_match() anchor struct kapkan_pkt. It is never
 * called, so it is never linked into the loaded program and never verified; it
 * exists only so the record type survives into BTF for the userspace reader.
 */
__attribute__((used)) int kapkan_fp_event_btf_anchor(const struct kapkan_fp_event *e)
{
	return e != NULL;
}

/* ======================================================================== */
/* Applying a matched rule                                                   */
/* ======================================================================== */

/* Scan outcomes. NOMATCH falls through to the next precedence level. */
#define KAPKAN_DEC_NOMATCH	0
#define KAPKAN_DEC_PASS		1
#define KAPKAN_DEC_DROP		2

/*
 * Turn a matched rule into a decision, doing ALL the accounting on the way.
 * The dry-run rewrite deliberately does not happen here — see kapkan_finish().
 */
__kapkan_subprog int kapkan_apply(const struct kapkan_rule *r,
				  const struct kapkan_pkt *pkt,
				  const union kapkan_addr *anchor, __u32 stats)
{
	struct kapkan_counter *rc;
	__u64 len = pkt->len;
	__u64 rid = r->rule_id;

	/* Per-rule accounting. Userspace creates the entry when it installs
	 * the rule, so a miss just means "not instrumented" and is not an
	 * error path. */
	rc = bpf_map_lookup_elem(&kapkan_rule_stats, &rid);
	if (rc) {
		rc->pkts += 1;
		rc->bytes += len;
	}

	if (r->action == KAPKAN_ACT_DROP) {
		kapkan_count(KAPKAN_STATS_DROP(stats), len);
		return KAPKAN_DEC_DROP;
	}
	if (r->action == KAPKAN_ACT_RATELIMIT) {
		/* The rate-limit outcome is its own counter pair rather than
		 * the precedence level's: an operator needs to see how much a
		 * ceiling actually shed, and which level installed it is
		 * already visible from kapkan_rule_stats. */
		if (kapkan_rl_admit(pkt, anchor, r->profile)) {
			kapkan_count(KAPKAN_STAT_PASS_RL_ADMIT, len);
			return KAPKAN_DEC_PASS;
		}
		kapkan_count(KAPKAN_STAT_DROP_RL, len);
		return KAPKAN_DEC_DROP;
	}

	kapkan_count(KAPKAN_STATS_PASS(stats), len);
	return KAPKAN_DEC_PASS;
}

/*
 * Is this rule live? EXPIRED == ABSENT, and the counter fires only for a rule
 * that WOULD have matched, which is why the caller tests the match first: a
 * policy block full of stale slots must not spam the counter on every packet.
 *
 * This is the fail-safe that makes a dead userspace harmless. If the manager
 * crashes mid-attack, every dynamic rule ages out on its own boot-clock
 * deadline and the box reverts to being a wire. 0 means "never expires" and is
 * reserved for statics, which come from the config file and cannot be
 * stranded by a crash.
 */
static __always_inline int kapkan_rule_expired(const struct kapkan_rule *r,
					       __u64 now)
{
	return r->expires_at_ns != 0 && r->expires_at_ns <= now;
}

/* ======================================================================== */
/* Precedence 4 and 5 — the per-victim policy scan                           */
/* ======================================================================== */
/*
 * One LPM lookup on `anchor` gives a policy id; one array lookup gives that
 * victim's WHOLE rule set (that is why a block holds KAPKAN_RULES_PER_POLICY
 * rules inline rather than being a list); then an unrolled scan, first match
 * wins.
 *
 * VERIFIER: the scan is #pragma unroll'd because a runtime trip count over a
 * map value would need bpf_loop(), which is 5.17+ and below Kapkan's 5.15
 * floor. Eight iterations is the compile-time constant
 * KAPKAN_RULES_PER_POLICY, which is itself config.maxDataplaneRulesPerBan, so
 * the bound is a contract rather than a guess.
 *
 * DOUBLE BUFFERING: the block index is generation * policy_stride + id, both
 * read from the single kapkan_cfg snapshot the caller took at entry. A
 * generation flip is therefore one u32 store that this packet either saw or
 * did not; it can never read half of each set. The ARRAY lookup helper
 * bounds-checks the computed index itself and returns NULL when it is out of
 * range, so even a garbage stride can only fail open.
 */
__kapkan_subprog int kapkan_scan_policy(const struct kapkan_pkt *pkt,
					const union kapkan_addr *anchor,
					const struct kapkan_config *cfg,
					__u32 stats)
{
	struct kapkan_policy_block *pol;
	__u64 len = pkt->len;
	__u32 *policy_id;
	__u32 idx;
	int i;

	if (pkt->is_v6) {
		struct kapkan_lpm_key_v6 k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, anchor->b, 16);
		policy_id = bpf_map_lookup_elem(&kapkan_victims6, &k);
	} else {
		struct kapkan_lpm_key_v4 k = { .prefixlen = 32 };

		__builtin_memcpy(k.addr, &anchor->w32[0], 4);
		policy_id = bpf_map_lookup_elem(&kapkan_victims4, &k);
	}
	if (!policy_id)
		return KAPKAN_DEC_NOMATCH; /* no policy for this prefix */

	idx = cfg->generation * cfg->policy_stride + *policy_id;
	pol = bpf_map_lookup_elem(&kapkan_policies, &idx);
	if (!pol) {
		/* The trie pointed at a block that is not there: userspace is
		 * mid-update or has a bug. Count it loudly and fall through to
		 * the next precedence level rather than inventing a verdict. */
		kapkan_count(KAPKAN_STAT_ERR_POLICY_MISSING, len);
		return KAPKAN_DEC_NOMATCH;
	}

#pragma unroll
	for (i = 0; i < KAPKAN_RULES_PER_POLICY; i++) {
		const struct kapkan_rule *r = &pol->rules[i];

		/* n_rules bounds the live prefix of the block. Slots past it
		 * have RF_VALID clear anyway, so a torn read can only ever
		 * under-match — it fails open, never open-fires. */
		if ((__u32)i >= pol->n_rules)
			break;
		if (!kapkan_rule_match(r, pkt))
			continue;
		if (kapkan_rule_expired(r, pkt->now)) {
			kapkan_count(KAPKAN_STAT_PASS_RULE_EXPIRED, len);
			continue; /* expired == absent: keep looking */
		}
		return kapkan_apply(r, pkt, anchor, stats);
	}
	return KAPKAN_DEC_NOMATCH;
}

/*
 * Fold a decision into an XDP verdict. THE DRY-RUN REWRITE LIVES HERE AND
 * NOWHERE ELSE, at the very last moment, long after kapkan_stats and
 * kapkan_rule_stats have been bumped. That ordering is the whole point of
 * dry run: an operator staging a policy must be able to read off exactly which
 * rules fired and exactly how much traffic they would have shed, which is
 * impossible if the accounting is short-circuited along with the drop.
 */
static __always_inline int kapkan_finish(int decision,
					 const struct kapkan_config *cfg,
					 __u64 len)
{
	if (decision != KAPKAN_DEC_DROP)
		return XDP_PASS;
	if (cfg->dry_run) {
		kapkan_count(KAPKAN_STAT_DRYRUN_WOULD_DROP, len);
		return XDP_PASS;
	}
	return XDP_DROP;
}

/* ======================================================================== */
/* The decision engine — precedence 3, 4 and 5                               */
/* ======================================================================== */
/*
 * ==========================================================================
 * THIS IS A GLOBAL FUNCTION, AND THAT IS THE WHOLE POINT
 * ==========================================================================
 * Note the missing `static`. A static subprogram is verified along every path
 * that reaches it; a GLOBAL one is verified EXACTLY ONCE, standalone, with its
 * arguments taken on trust as PTR_TO_MEM of the declared struct size. The
 * verifier then only checks, at each call site, that the pointers really do
 * address at least that much initialised memory.
 *
 * That distinction is worth about half a million instructions here. The parser
 * above produces roughly twenty distinct verifier states (the unrolled IPv6
 * extension-header walk, the fragment cases, the two families), and the static
 * scan below is a 256-iteration loop. Verified per-path, the two multiply:
 * 20 x 256 x ~120 instructions, measured at ~2,478 processed instructions per
 * single static rule and 822,035 in total — 82% of the budget, with the
 * rate limiter and both policy scans still to pay for. Verified once, the loop
 * costs what it actually is.
 *
 * Kernel floor: pointer arguments to global functions landed in 5.13
 * (e5069b9c23b3, "bpf: Support pointers in global func args"), below Kapkan's
 * 5.15 floor. Both arguments satisfy the rule that makes them legal: `pkt`
 * points at a fully initialised stack object (kapkan_parse memsets it before
 * anything else), and `cfg` at a kapkan_cfg map value whose size IS
 * sizeof(struct kapkan_config).
 *
 * Returns a KAPKAN_DEC_* code. It deliberately does NOT return an XDP verdict:
 * the dry-run rewrite belongs at the very end of the program, after all the
 * accounting, and keeping that in one place (kapkan_finish) is what stops a
 * future edit from quietly making dry run lose a counter.
 */
int kapkan_decide(struct kapkan_pkt *pkt, struct kapkan_config *cfg)
{
	__u32 n_static, base;
	int dec, i;

	/*
	 * VERIFIER: a global function's pointer arguments arrive as
	 * PTR_TO_MEM_OR_NULL — the verifier reports them literally as
	 * `mem_or_null(sz=64)` and `mem_or_null(sz=32)` and refuses the first
	 * dereference without this test. It cannot see that both call sites
	 * already null-checked, precisely because it is verifying this
	 * function in isolation, which is the property we wanted.
	 *
	 * Newer kernels can annotate the arguments __arg_nonnull and skip
	 * this; that annotation postdates the 5.15 floor, and the branch is
	 * two instructions on a path that runs once per packet. Returning
	 * NOMATCH means the packet falls through to PASS, per the charter.
	 */
	if (!pkt || !cfg)
		return KAPKAN_DEC_NOMATCH;

	/*
	 * ---------------------------------------------------------------
	 * (3) STATIC rules, first match wins.
	 *
	 * VERIFIER: this is the one scan whose trip count is NOT a compile-time
	 * constant — an operator may configure up to KAPKAN_MAX_STATIC_RULES of
	 * them. It is written as a bounded loop with a constant ceiling AND a
	 * runtime `static_count` break, which the verifier has handled natively
	 * since 5.3 (below our 5.15 floor) via state pruning on the back edge.
	 * It is deliberately NOT unrolled: 256 copies of the match predicate
	 * would blow both the instruction count and the complexity budget,
	 * whereas the rolled form lets the verifier prune once the per-iteration
	 * state stabilises.
	 *
	 * Statics carry expires_at_ns == 0 (never) because they come from the
	 * config file, but the expiry test still runs — an operator CAN set a
	 * deadline, and a uniform rule lifecycle is worth more than the branch.
	 * ---------------------------------------------------------------
	 */
	n_static = cfg->static_count;
	if (n_static > KAPKAN_MAX_STATIC_RULES)
		n_static = KAPKAN_MAX_STATIC_RULES;
	base = cfg->generation * cfg->static_stride;

	for (i = 0; i < KAPKAN_MAX_STATIC_RULES; i++) {
		const struct kapkan_rule *r;
		__u32 key;

		if ((__u32)i >= n_static)
			break;
		key = base + (__u32)i;
		r = bpf_map_lookup_elem(&kapkan_statics, &key);
		if (!r)
			break; /* index out of range: nothing further to scan */
		if (!kapkan_rule_match(r, pkt))
			continue;
		if (kapkan_rule_expired(r, pkt->now)) {
			kapkan_count(KAPKAN_STAT_PASS_RULE_EXPIRED, pkt->len);
			continue;
		}
		/* A static rate-limit anchors its buckets on the destination:
		 * "cap each source at N pps towards this prefix". */
		return kapkan_apply(r, pkt, &pkt->dst,
				    KAPKAN_STATS(KAPKAN_STAT_PASS_STATIC,
						 KAPKAN_STAT_DROP_STATIC));
	}

	/*
	 * ---------------------------------------------------------------
	 * (4) DYNAMIC SOURCE rules. The policy trie keyed by the packet's
	 * SOURCE, which is where an OUTGOING attack lands: mitigate anchors a
	 * compromised host's outbound flood on Src, not Dst. Buckets anchor on
	 * the source too, so a rate-limited outgoing rule caps that host.
	 * ---------------------------------------------------------------
	 */
	dec = kapkan_scan_policy(pkt, &pkt->src, cfg,
				 KAPKAN_STATS(KAPKAN_STAT_PASS_DYN_SRC,
					      KAPKAN_STAT_DROP_DYN_SRC));
	if (dec != KAPKAN_DEC_NOMATCH)
		return dec;

	/*
	 * ---------------------------------------------------------------
	 * (5) DYNAMIC DESTINATION rules — the common case, an incoming attack
	 * on a protected victim. Anchors on the destination for both the trie
	 * lookup and the token buckets, so one rate-limit rule gives every
	 * attacker its own independent budget against that victim.
	 * ---------------------------------------------------------------
	 */
	dec = kapkan_scan_policy(pkt, &pkt->dst, cfg,
				 KAPKAN_STATS(KAPKAN_STAT_PASS_DYN_DST,
					      KAPKAN_STAT_DROP_DYN_DST));
	if (dec != KAPKAN_DEC_NOMATCH)
		return dec;

	return KAPKAN_DEC_NOMATCH;
}

SEC("xdp")
int kapkan_xdp_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 len = (__u64)(data_end - data);
	struct kapkan_pkt pkt;
	struct kapkan_config *cfg;
	__u32 zero = 0;
	int rc, dec;

	/*
	 * Read the config ONCE, at the top. Everything downstream — the
	 * generation used for both double-buffered maps, dry_run,
	 * drop_malformed — comes from this single snapshot, which is what
	 * makes a generation flip atomic from the packet's point of view: a
	 * packet cannot read generation 0 for the statics and generation 1
	 * for the policies.
	 *
	 * A missing config means the manager has not finished attaching. Per
	 * the charter that is a PASS, not a drop.
	 */
	cfg = bpf_map_lookup_elem(&kapkan_cfg, &zero);
	if (!cfg) {
		kapkan_count(KAPKAN_STAT_ERR_CFG_MISSING, len);
		return XDP_PASS;
	}

	rc = kapkan_parse(data, data_end, &pkt);
	switch (rc) {
	case KAPKAN_PARSE_OK:
		break;
	case KAPKAN_PARSE_NOT_IP:
		kapkan_count(KAPKAN_STAT_PASS_NOT_IP, len);
		return XDP_PASS;
	case KAPKAN_PARSE_VLAN_DEPTH:
		kapkan_count(KAPKAN_STAT_PASS_VLAN_DEPTH, len);
		return XDP_PASS;
	case KAPKAN_PARSE_EXTHDR_CAP:
		kapkan_count(KAPKAN_STAT_PASS_EXTHDR_CAP, len);
		return XDP_PASS;
	default:
		/*
		 * The only place in the program where an unparsed packet can
		 * be dropped, and only because the operator asked for it.
		 * Note the accounting happens before the dry-run rewrite, as
		 * everywhere else.
		 */
		if (cfg->drop_malformed) {
			kapkan_count(KAPKAN_STAT_DROP_MALFORMED, len);
			if (cfg->dry_run) {
				kapkan_count(KAPKAN_STAT_DRYRUN_WOULD_DROP, len);
				return XDP_PASS;
			}
			return XDP_DROP;
		}
		kapkan_count(KAPKAN_STAT_PASS_MALFORMED, len);
		return XDP_PASS;
	}

	/* kapkan_parse() memsets pkt, so the two traversal invariants are set
	 * here, once, after it returns. Everything below reads them from pkt
	 * rather than taking them as arguments (see the struct's comment). */
	pkt.len = len;

	/* A non-first fragment is a normal, matchable packet that simply has no
	 * ports. Counted so the shape is visible, then evaluated like any
	 * other — it is NOT short-circuited, or a rule written specifically to
	 * catch a fragment flood could never fire. */
	if (!pkt.have_ports && pkt.is_frag)
		kapkan_count(KAPKAN_STAT_PASS_FRAG_NOPORTS, len);

	/*
	 * ---------------------------------------------------------------
	 * (1) SOURCE allowlist. Highest precedence in the program: an
	 * allowlisted sender is never touched by anything below, including an
	 * operator's own static drop. dataplane.allowlist exists so a scrubber
	 * cannot be talked into blackholing its own monitoring, its BGP peers
	 * or its management plane.
	 * ---------------------------------------------------------------
	 */
	if (pkt.is_v6) {
		struct kapkan_lpm_key_v6 k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, pkt.src.b, 16);
		if (bpf_map_lookup_elem(&kapkan_allow6, &k)) {
			kapkan_count(KAPKAN_STAT_PASS_ALLOW_SRC, len);
			return XDP_PASS;
		}
	} else {
		struct kapkan_lpm_key_v4 k = { .prefixlen = 32 };

		__builtin_memcpy(k.addr, &pkt.src.w32[0], 4);
		if (bpf_map_lookup_elem(&kapkan_allow4, &k)) {
			kapkan_count(KAPKAN_STAT_PASS_ALLOW_SRC, len);
			return XDP_PASS;
		}
	}

	/*
	 * ---------------------------------------------------------------
	 * (2) DESTINATION protected list — the protected_whitelist mirror.
	 * A different axis from (1): that one says "this sender is never to be
	 * touched", this one says "this victim is never to be banned".
	 *
	 * It has to be in the kernel rather than left to the userspace sweep.
	 * A rule rehydrated from a previous process, or one installed in the
	 * same instant an operator adds a prefix to protected_whitelist, would
	 * otherwise drop that customer's traffic until the sweep notices on
	 * its next 1 Hz tick. One second of blackholing a protected prefix is
	 * not a rounding error, it is an outage.
	 * ---------------------------------------------------------------
	 */
	if (pkt.is_v6) {
		struct kapkan_lpm_key_v6 k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, pkt.dst.b, 16);
		if (bpf_map_lookup_elem(&kapkan_protect6, &k)) {
			kapkan_count(KAPKAN_STAT_PASS_PROTECT_DST, len);
			return XDP_PASS;
		}
	} else {
		struct kapkan_lpm_key_v4 k = { .prefixlen = 32 };

		__builtin_memcpy(k.addr, &pkt.dst.w32[0], 4);
		if (bpf_map_lookup_elem(&kapkan_protect4, &k)) {
			kapkan_count(KAPKAN_STAT_PASS_PROTECT_DST, len);
			return XDP_PASS;
		}
	}

	/* One clock read for the whole decision path: expiry checks and every
	 * token bucket must agree on "now", and a helper call per rule would
	 * be both slower and semantically worse. */
	pkt.now = bpf_ktime_get_boot_ns();

	/*
	 * Fingerprint plane (E2): a sampled, bounded COPY of a recognised TLS
	 * ClientHello or QUIC Initial to userspace, where JA4 + SNI are computed.
	 * It sits here — past the allowlist/protected short-circuits, before the
	 * decision engine — but it is pure observation: it never reads or changes
	 * `dec`, and skipping it (disabled, throttled, or ring full) is invisible
	 * to the verdict. See "THE FINGERPRINT PLANE" above.
	 *
	 * ELIGIBILITY IS DECIDED HERE, BEFORE THE SAMPLER. A payload starting past
	 * KAPKAN_FP_MAX_OFF cannot be copied (kapkan_fp_emit could not bound the
	 * pointer), so such a packet is simply not eligible for fingerprinting: it
	 * must not spend a sampler token or it would go uncounted (neither emitted,
	 * throttled, nor ring-full), breaking the "every sampled copy is accounted"
	 * invariant. Gating fp_off here keeps that invariant exact.
	 */
	if (cfg->fp_enabled && (pkt.is_tls_chello || pkt.is_quic_initial) &&
	    pkt.fp_off <= KAPKAN_FP_MAX_OFF) {
		if (kapkan_fp_sample(cfg, pkt.now))
			kapkan_fp_emit(data, data_end, &pkt);
		else
			kapkan_count(KAPKAN_STAT_FP_THROTTLED, pkt.len);
	}

	/* Precedence 3, 4 and 5, all inside one GLOBAL function so the
	 * verifier checks them once instead of once per parser path. */
	dec = kapkan_decide(&pkt, cfg);
	if (dec != KAPKAN_DEC_NOMATCH)
		return kapkan_finish(dec, cfg, pkt.len);

	/* (6) Default. Nothing claimed this packet, so it is not ours to hold. */
	kapkan_count(KAPKAN_STAT_PASS_DEFAULT, len);
	return XDP_PASS;
}

/*
 * "Dual BSD/GPL" rather than "BSD": GPL-only helpers (bpf_ktime_get_boot_ns is
 * not one, but bpf_probe_read_kernel and every kfunc are) refuse to load into
 * a program whose license string is not GPL-compatible. Declaring the dual
 * license now keeps that door open without a later relicense. This does not
 * make the Kapkan binary GPL: the object is loaded INTO THE KERNEL by the
 * bpf(2) syscall, it is not linked into the Go program — the same arrangement
 * Cilium and loxilb use.
 */
char _license[] SEC("license") = "Dual BSD/GPL";
