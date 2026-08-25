// SPDX-License-Identifier: GPL-2.0
//
// M0 observation spike — all kernel probes.
//
// Data plane: cgroup v2 sock_addr hooks (TCP connect, UDP sendmsg) emitting
// one event per net-new (cgroup, destination, port, protocol) tuple, deduped
// in-kernel via LRU. User space only ever sees cache misses.
//
// Invariant probes: sched_process_exec (exec lineage, Signal 1 input) and
// sys_enter_socket (raw/packet socket creation, Signal 3).
//
// ADVISORY-ONLY BY DESIGN: every program returns without affecting the
// operation. There is no blocking path. See architecture-specification §2.2 —
// enforcement is a deferred, post-PoC goal.

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// In-kernel dedup: (cgroup, endpoint) tuples already reported this epoch.
// LRU eviction bounds memory; an evicted tuple simply re-reports once.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct conn_key);
	__type(value, __u64); // last-seen timestamp (ns)
} seen_connections SEC(".maps");

// All events. 16 MiB ring buffer.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Ring-buffer maps have no value type, so the event structs would otherwise
// be pruned from the object's BTF. These anchors keep the types visible so
// bpf2go can generate the Go decoding structs. Never referenced by programs.
const struct conn_event *const conn_event_btf_anchor __attribute__((unused));
const struct exec_event *const exec_event_btf_anchor __attribute__((unused));
const struct rawsock_event *const rawsock_event_btf_anchor __attribute__((unused));

// ---------------------------------------------------------------------------
// Egress data plane
// ---------------------------------------------------------------------------

// observe is the shared fast/slow path for all four sock_addr hooks.
// Fast path: tuple already in seen_connections -> refresh timestamp, return.
// Slow path: insert tuple, emit one compact event to the ring buffer.
static __always_inline int observe(struct bpf_sock_addr *ctx, __u8 family)
{
	struct conn_key key = {0};
	__u64 now = bpf_ktime_get_ns();

	key.cgroup_id = bpf_get_current_cgroup_id();
	key.family = family;
	// ctx->protocol is the real IPPROTO_* of the underlying socket -- NOT
	// implied by which hook fired. connect() is not TCP-exclusive: "connected
	// UDP" sockets (connect() on a SOCK_DGRAM to fix the peer, e.g. what
	// chronyd does for its NTP peers) also hit cgroup/connect4/6, not just
	// cgroup/sendmsg4/6. An earlier version hardcoded PROTO_TCP per hook,
	// which silently mislabeled all such UDP-via-connect() traffic as TCP
	// -- found live via chronyd's NTP traffic (docs/report-m2.md). PROTO_TCP/
	// PROTO_UDP already equal the real IPPROTO_TCP/IPPROTO_UDP values, so no
	// remapping is needed, just reading the real field instead of assuming it.
	key.protocol = (__u8)ctx->protocol;
	// user_port is a __u32 holding the destination port in network byte
	// order. VERIFY on first live run: `curl :443` must print 443, not
	// 36863. See README "Known spike caveats".
	key.dport = bpf_ntohs((__u16)(ctx->user_port & 0xffff));
	if (family == FAMILY_V4) {
		__u32 a = ctx->user_ip4; // network byte order
		__builtin_memcpy(key.addr, &a, sizeof(a));
	} else {
		__builtin_memcpy(key.addr, ctx->user_ip6, sizeof(key.addr));
	}

	if (bpf_map_lookup_elem(&seen_connections, &key)) {
		// Fast path: known tuple. Nanosecond exit, no emission.
		bpf_map_update_elem(&seen_connections, &key, &now, BPF_EXIST);
		return 1;
	}

	// Slow path: net-new tuple for this cgroup.
	bpf_map_update_elem(&seen_connections, &key, &now, BPF_ANY);

	struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 1; // ring full: drop the report, never the connection

	e->type = EVENT_CONN;
	e->key = key;
	e->ts = now;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 1;
}

SEC("cgroup/connect4")
int egress_connect4(struct bpf_sock_addr *ctx)
{
	return observe(ctx, FAMILY_V4);
}

SEC("cgroup/connect6")
int egress_connect6(struct bpf_sock_addr *ctx)
{
	return observe(ctx, FAMILY_V6);
}

SEC("cgroup/sendmsg4")
int egress_sendmsg4(struct bpf_sock_addr *ctx)
{
	return observe(ctx, FAMILY_V4);
}

SEC("cgroup/sendmsg6")
int egress_sendmsg6(struct bpf_sock_addr *ctx)
{
	return observe(ctx, FAMILY_V6);
}

// ---------------------------------------------------------------------------
// Invariant probes
// ---------------------------------------------------------------------------

// Tracepoint context layouts, transcribed from the kernel's format files
// (events/sched/sched_process_exec/format and events/syscalls/
// sys_enter_socket/format on x86-64). Field offsets are ABI — do not reorder.
struct sched_process_exec_ctx {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__u32 filename_loc; // __data_loc: low 16 bits = offset from ctx, high 16 = length
	__s32 pid;
	__s32 old_pid;
};

struct sys_enter_socket_ctx {
	__u16 common_type;
	__u8  common_flags;
	__u8  common_preempt_count;
	__s32 common_pid;
	__s32 __syscall_nr;
	__u64 args[6]; // socket(2): args[0]=family, args[1]=type, args[2]=protocol
};

// Exec lineage capture (M0.4). Tracepoints are host-wide — cgroup scoping
// does not apply here; the cgroup_id on the event is the filter key.
SEC("tp/sched/sched_process_exec")
int handle_exec(struct sched_process_exec_ctx *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_EXEC;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ts = bpf_ktime_get_ns();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	// sched_process_exec fires after the new image is set up: comm is the
	// new binary's name.
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	// __data_loc: filename lives at ctx + (low 16 bits of filename_loc).
	const char *filename = (const char *)ctx + (ctx->filename_loc & 0xFFFF);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Raw/packet socket creation (M0.5, invariant signal 3). Emits only for
// SOCK_RAW or AF_PACKET — ordinary socket() calls are never events.
//
// NOTE: modern ping uses unprivileged SOCK_DGRAM ping sockets
// (net.ipv4.ping_group_range) and is intentionally NOT flagged. Test with an
// explicit AF_PACKET/SOCK_RAW creation; see README.
//
// NOTE: AF_NETLINK sockets are always SOCK_RAW or SOCK_DGRAM by convention
// (that's just the netlink API, not a raw-packet capability) and are created
// constantly by ordinary system plumbing — PAM, systemd, sudo, the audit
// subsystem. Confirmed live on docs/report-m0.md: a single `sudo` invocation
// produced 4-5 of these, 100% of observed raw_socket events under normal
// load. Excluded regardless of type to keep this invariant high-confidence.
SEC("tp/syscalls/sys_enter_socket")
int handle_raw_socket(struct sys_enter_socket_ctx *ctx)
{
	__s64 family = (__s64)ctx->args[0];
	__s64 type = (__s64)ctx->args[1];
	__s64 protocol = (__s64)ctx->args[2];
	// socket type carries SOCK_CLOEXEC/SOCK_NONBLOCK flag bits; mask them.
	__s64 masked_type = type & LINUX_SOCK_TYPE_MASK;

	if (family == LINUX_AF_NETLINK)
		return 0;

	// Raw ICMPv6 is how network-management daemons (NetworkManager,
	// systemd-networkd) do IPv6 SLAAC: router/neighbor solicitation and
	// advertisement need a genuine raw ICMPv6 socket -- it's not a
	// capability an attacker specifically needs. Confirmed live
	// (docs/report-m2.md): NetworkManager fires this exact pattern under
	// completely ordinary operation. Narrowly scoped to ICMPv6 specifically
	// -- a raw AF_INET6 socket for any OTHER protocol is still exactly the
	// primitive this invariant exists to catch.
	if (family == LINUX_AF_INET6 && masked_type == LINUX_SOCK_RAW && protocol == LINUX_IPPROTO_ICMPV6)
		return 0;

	if (family != LINUX_AF_PACKET && masked_type != LINUX_SOCK_RAW)
		return 0;

	struct rawsock_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_RAW_SOCK;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ts = bpf_ktime_get_ns();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->family = (__s32)family;
	e->sock_type = (__s32)masked_type;
	e->protocol = (__s32)ctx->args[2];
	e->pad = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
