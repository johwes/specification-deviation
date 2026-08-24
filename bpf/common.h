// SPDX-License-Identifier: GPL-2.0
//
// Shared types for the egress observation data plane (M0).
//
// These structs cross the kernel/user boundary: the node agent decodes
// conn_event from the ring buffer, and conn_key is the dedup map key.
// Field order and explicit padding are deliberate — do not reorder.
//
// Identity note: cgroup_id is the ephemeral kernel collection identity
// (architecture-specification.md §5, layer 1). It is used ONLY as the in-
// kernel dedup key. Resolution to a stable workload identity happens in
// the node agent, never here.

#ifndef __COMMON_H
#define __COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Local constants: avoids pulling in <linux/in.h> / <linux/socket.h>.
#define AF_IPV4   4
#define AF_IPV6   6
#define PROTO_TCP 6
#define PROTO_UDP 17

#define TASK_COMM_LEN 16

// Dedup map key: one entry per (workload cgroup, endpoint) tuple.
struct conn_key {
	__u64 cgroup_id;   // leaf cgroup v2 id of the connecting process
	__u8  addr[16];    // destination, network byte order; IPv4 uses addr[0..3]
	__u16 dport;       // destination port, host byte order
	__u8  protocol;    // PROTO_TCP / PROTO_UDP
	__u8  family;      // AF_IPV4 / AF_IPV6
	__u32 pad;         // explicit padding: deterministic 32-byte map key
};

// Ring buffer event: emitted once per net-new conn_key (cache miss).
struct conn_event {
	struct conn_key key;
	__u64 ts;                       // bpf_ktime_get_ns()
	__u32 pid;                      // thread id
	__u32 tgid;                     // process id (what user space calls "pid")
	__u8  comm[TASK_COMM_LEN];      // bpf_get_current_comm()
};

#endif /* __COMMON_H */
