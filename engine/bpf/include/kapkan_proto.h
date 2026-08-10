// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * kapkan_proto.h — on-the-wire packet header layouts.
 *
 * These are hand-written rather than pulled from <linux/if_ether.h>,
 * <linux/ip.h>, <linux/ipv6.h>, <linux/tcp.h>, <linux/udp.h> and
 * <linux/icmp.h> on purpose. They are not kernel internals: they are frozen
 * wire formats specified by IEEE 802.3 / 802.1Q, RFC 791, RFC 8200, RFC 9293,
 * RFC 768 and RFC 792. Their byte layout cannot change without inventing a new
 * protocol, so a local copy can never drift, and copying six small structs is
 * cheaper and far more auditable than making the whole of linux headers a build
 * dependency of a project that compiles its BPF on macOS.
 *
 * Bitfield note: the C bitfield allocation order in iphdr/tcphdr is
 * endianness-dependent, exactly as in the kernel headers. Kapkan only ever
 * builds little-endian objects (amd64 and arm64 targets), and the #error below
 * makes a big-endian build fail loudly instead of silently misparsing.
 */
#ifndef KAPKAN_PROTO_H
#define KAPKAN_PROTO_H

#include "kapkan_kern.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "kapkan_proto.h bitfield order assumes a little-endian target"
#endif

/* ------------------------------------------------------------- ethernet */

#define ETH_ALEN 6

#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD
#define ETH_P_8021Q	0x8100 /* 802.1Q customer VLAN tag */
#define ETH_P_8021AD	0x88A8 /* 802.1ad service VLAN tag */

struct ethhdr {
	__u8 h_dest[ETH_ALEN];
	__u8 h_source[ETH_ALEN];
	__be16 h_proto;
} __attribute__((packed));

/* The 4-byte 802.1Q tag, minus the TPID already consumed as h_proto. */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

/* ------------------------------------------------------------------ IPv4 */

struct iphdr {
	__u8 ihl : 4;
	__u8 version : 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
	/* Options follow when ihl > 5. */
} __attribute__((packed));

#define IP_MF		0x2000 /* "more fragments", host byte order */
#define IP_OFFSET	0x1FFF /* fragment offset mask, host byte order */

/* ------------------------------------------------------------------ IPv6 */

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct ipv6hdr {
	__u8 priority : 4;
	__u8 version : 4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __attribute__((packed));

/*
 * Generic IPv6 extension header (hop-by-hop, routing, destination options,
 * mobility). hdrlen is in 8-octet units *not counting* the first 8 octets.
 */
struct ipv6_opt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
} __attribute__((packed));

/* The fragment header is the odd one out: fixed 8 bytes, hdrlen is reserved. */
struct ipv6_frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off; /* low 3 bits are flags; bit 0 is "more fragments" */
	__be32 identification;
} __attribute__((packed));

/* The authentication header measures its length in 4-octet units, minus 2. */
struct ip_auth_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__be16 reserved;
	__be32 spi;
	__be32 seq_no;
} __attribute__((packed));

/* ---------------------------------------------------------------- L4 */

#define IPPROTO_HOPOPTS		0
#define IPPROTO_ICMP		1
#define IPPROTO_TCP		6
#define IPPROTO_UDP		17
#define IPPROTO_ROUTING		43
#define IPPROTO_FRAGMENT	44
#define IPPROTO_GRE		47
#define IPPROTO_ESP		50
#define IPPROTO_AH		51
#define IPPROTO_ICMPV6		58
#define IPPROTO_NONE		59
#define IPPROTO_DSTOPTS		60
#define IPPROTO_MH		135

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4;
	__u16 doff : 4;
	__u16 fin : 1;
	__u16 syn : 1;
	__u16 rst : 1;
	__u16 psh : 1;
	__u16 ack : 1;
	__u16 urg : 1;
	__u16 ece : 1;
	__u16 cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
} __attribute__((packed));

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
} __attribute__((packed));

struct icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
	__be32 rest;
} __attribute__((packed));

#endif /* KAPKAN_PROTO_H */
