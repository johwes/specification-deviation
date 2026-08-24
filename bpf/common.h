// SPDX-License-Identifier: GPL-2.0
//
// Shared types for the observation data plane (M0).
//
// These structs cross the kernel/user boundary: the node agent decodes
// events from the ring buffer, and conn_key is the dedup map key.
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

// Wire constants shared with user space. Deliberately NOT named AF_INET*:
// these are marker values (4/6) for the event family field, not the real
// syscall constants (2/10) — the naming must not invite that assumption.
//
// NOTE: mirrored by hand in cmd/sensor/main.go — bpf2go does not propagate
// #defines into the generated Go. If you change a value here, change the Go
// mirror; a mismatch silently misparses events instead of failing to build.
#define FAMILY_V4 4
#define FAMILY_V6 6
#define PROTO_TCP 6
#define PROTO_UDP 17

// Event type tag: the first field of every ring-buffer record. Mirrored in
// cmd/sensor/main.go (same hand-sync caveat as the constants above).
enum event_type {
	EVENT_CONN     = 1,
	EVENT_EXEC     = 2,
	EVENT_RAW_SOCK = 3,
};

// Real Linux UAPI values used for socket(2) argument filtering (from
// <linux/if_packet.h> / <linux/socket.h>, defined locally to keep includes
// minimal). Unlike the FAMILY_*/PROTO_* wire markers above, these ARE the
// real syscall constants.
#define LINUX_AF_PACKET      17
#define LINUX_SOCK_RAW       3
#define LINUX_SOCK_TYPE_MASK 0xf // SOCK_CLOEXEC/SOCK_NONBLOCK live above this

#define TASK_COMM_LEN 16
#define PATH_LEN      64

// Dedup map key: one entry per (workload cgroup, endpoint) tuple.
struct conn_key {
	__u64 cgroup_id;   // leaf cgroup v2 id of the connecting process
	__u8  addr[16];    // destination, network byte order; IPv4 uses addr[0..3]
	__u16 dport;       // destination port, host byte order
	__u8  protocol;    // PROTO_TCP / PROTO_UDP
	__u8  family;      // FAMILY_V4 / FAMILY_V6
	__u32 pad;         // explicit padding: deterministic 32-byte map key
};

// EVENT_CONN: emitted once per net-new conn_key (dedup cache miss).
struct conn_event {
	__u64 type;                     // EVENT_CONN
	struct conn_key key;
	__u64 ts;                       // bpf_ktime_get_ns()
	__u32 pid;                      // thread id
	__u32 tgid;                     // process id (what user space calls "pid")
	__u8  comm[TASK_COMM_LEN];      // bpf_get_current_comm()
};

// EVENT_EXEC: emitted on every sched_process_exec. The Go side joins these
// with conn events on (cgroup_id, tgid) to attribute egress to exec lineage.
struct exec_event {
	__u64 type;                     // EVENT_EXEC
	__u64 cgroup_id;
	__u64 ts;
	__u32 pid;                      // thread id
	__u32 tgid;                     // process id
	__u8  comm[TASK_COMM_LEN];      // post-exec comm (new image)
	__u8  path[PATH_LEN];           // exec'd filename, NUL-padded/truncated
};

// EVENT_RAW_SOCK: emitted on socket(2) with SOCK_RAW type or AF_PACKET
// family — invariant signal 3 (architecture-specification §12). Never
// emitted for ordinary socket creation.
struct rawsock_event {
	__u64 type;                     // EVENT_RAW_SOCK
	__u64 cgroup_id;
	__u64 ts;
	__u32 pid;
	__u32 tgid;
	__u8  comm[TASK_COMM_LEN];
	__s32 family;                   // socket(2) domain, e.g. 17 = AF_PACKET
	__s32 sock_type;                // masked: SOCK_CLOEXEC/SOCK_NONBLOCK stripped
	__s32 protocol;
	__u32 pad;                      // explicit padding to 8-byte alignment
};

#endif /* __COMMON_H */
