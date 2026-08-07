// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * kapkan_bpf.h — the single include every Kapkan BPF translation unit uses.
 *
 * Its only job is to fix the include order. bpf_helper_defs.h (vendored from
 * libbpf, see PROVENANCE.md) is written assuming vmlinux.h or linux/types.h
 * has already been included: it uses __u32/__u64 and takes pointers to a long
 * list of kernel struct types. kapkan_kern.h supplies exactly those, so it
 * MUST come first. Including the libbpf headers directly from a .c file works
 * only by accident of ordering; include this instead.
 */
#ifndef KAPKAN_BPF_H
#define KAPKAN_BPF_H

#include "kapkan_kern.h" /* types + UAPI enums; must precede libbpf headers */

#include "bpf_helpers.h" /* vendored libbpf: SEC, __uint/__type, helper decls */
#include "bpf_endian.h"  /* vendored libbpf: bpf_ntohs/bpf_htons             */

#include "kapkan_proto.h" /* wire formats */

#endif /* KAPKAN_BPF_H */
