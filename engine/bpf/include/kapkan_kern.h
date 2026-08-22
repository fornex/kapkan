// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * kapkan_kern.h — the minimal slice of the kernel UAPI that a BPF object
 * needs, hand-written instead of vendored.
 *
 * WHY HAND-WRITTEN, when include/bpf_helpers.h next door is vendored verbatim:
 *
 *   - The helper *declarations* (bpf_helper_defs.h) are a moving target. They
 *     are generated from the kernel's bpf.h, gain new helpers every release,
 *     and a hand-rolled copy silently rots into wrong signatures. Vendor those.
 *
 *   - What is in THIS file is either a wire format frozen by an RFC/IEEE spec
 *     (see kapkan_proto.h) or a UAPI ABI the kernel may never renumber:
 *     BPF_MAP_TYPE_* values, enum xdp_action, struct xdp_md's field order.
 *     Those cannot change without breaking every compiled BPF object on earth,
 *     so a 200-line copy is stable by construction — and it is far better than
 *     dragging in the whole of linux headers (which this macOS host does not have)
 *     or generating a 3 MB vmlinux.h (which is architecture-specific: the CI
 *     container is arm64, the deployment targets are amd64).
 *
 * Include order matters: bpf_helper_defs.h uses __u32/__u64 and takes pointers
 * to a long list of kernel structs, so the typedefs and the forward
 * declarations below must come first. kapkan_bpf.h enforces that ordering.
 */
#ifndef KAPKAN_KERN_H
#define KAPKAN_KERN_H

/* ------------------------------------------------------------------ types */

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

/* Endian-tagged aliases. The kernel decorates these with __bitwise for sparse;
 * clang does not check it, so plain aliases carry the same documentation value
 * without the sparse dependency. */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __sum16;
typedef __u32 __wsum; /* only referenced by bpf_csum_* declarations */

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef _Bool bool;
#ifndef true
#define true 1
#define false 0
#endif

/* --------------------------------------------------- forward declarations */
/*
 * bpf_helper_defs.h declares helpers taking pointers to these kernel types.
 * We call almost none of them, but a struct first named inside a function
 * prototype has prototype scope, which trips -Wvisibility under -Werror.
 * Declaring them at file scope here costs nothing and keeps the build clean.
 * The few we actually use (xdp_md, iphdr, ipv6hdr, tcphdr) are fully defined
 * later here or in kapkan_proto.h.
 */
struct __sk_buff;
struct bpf_dynptr;
struct bpf_fib_lookup;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_pidns_info;
struct bpf_redir_neigh;
struct bpf_sock;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct bpf_sock_tuple;
struct bpf_spin_lock;
struct bpf_sysctl;
struct bpf_tcp_sock;
struct bpf_timer;
struct bpf_tunnel_key;
struct bpf_xfrm_state;
struct btf_ptr;
struct cgroup;
struct file;
struct inode;
struct linux_binprm;
struct mptcp_sock;
struct path;
struct pt_regs;
struct seq_file;
struct sk_msg_md;
struct sk_reuseport_md;
struct sockaddr;
struct socket;
struct task_struct;
struct tcp6_sock;
struct tcp_request_sock;
struct tcp_sock;
struct tcp_timewait_sock;
struct udp6_sock;
struct unix_sock;

/* ------------------------------------------------------- bpf UAPI: maps */
/*
 * enum bpf_map_type — UAPI ABI, values are burned into every existing BPF
 * object file and can never be renumbered. Only the types Kapkan uses are
 * listed; the numbering is preserved so an added entry needs no renumbering.
 */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC		= 0,
	BPF_MAP_TYPE_HASH		= 1,
	BPF_MAP_TYPE_ARRAY		= 2,
	BPF_MAP_TYPE_PERCPU_HASH	= 5,
	BPF_MAP_TYPE_PERCPU_ARRAY	= 6,
	BPF_MAP_TYPE_LRU_HASH		= 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH	= 10,
	BPF_MAP_TYPE_LPM_TRIE		= 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS	= 12,
	BPF_MAP_TYPE_HASH_OF_MAPS	= 13,
	BPF_MAP_TYPE_RINGBUF		= 27, /* fingerprint plane (E2) */
};

/* bpf_map_update_elem() flags. */
#define BPF_ANY		0ULL
#define BPF_NOEXIST	1ULL
#define BPF_EXIST	2ULL
#define BPF_F_LOCK	4ULL

/* BPF_MAP_CREATE flags. LPM_TRIE *requires* BPF_F_NO_PREALLOC. */
#define BPF_F_NO_PREALLOC	(1U << 0)
#define BPF_F_NO_COMMON_LRU	(1U << 1)

/* -------------------------------------------------------- bpf UAPI: XDP */

/*
 * enum xdp_action — UAPI ABI. Kapkan's charter means the program only ever
 * returns XDP_PASS or XDP_DROP; the others are listed for completeness of the
 * enum's numbering.
 */
enum xdp_action {
	XDP_ABORTED	= 0,
	XDP_DROP	= 1,
	XDP_PASS	= 2,
	XDP_TX		= 3,
	XDP_REDIRECT	= 4,
};

/*
 * struct xdp_md — the context the verifier rewrites. Field order is UAPI; the
 * first two are 32-bit *offsets* that the verifier turns into real pointers,
 * which is why every access must go through (void *)(long)ctx->data.
 */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info. */
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

#endif /* KAPKAN_KERN_H */
