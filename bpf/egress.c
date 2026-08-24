// SPDX-License-Identifier: GPL-2.0
//
// M0 egress observation spike.
//
// Attaches to the cgroup v2 sock_addr hooks (TCP connect, UDP sendmsg) and
// emits one event per net-new (cgroup, destination, port, protocol) tuple.
// Deduplication happens in-kernel via an LRU hash; user space only ever sees
// cache misses.
//
// ADVISORY-ONLY BY DESIGN: every program returns 1 (allow). This code has no
// blocking path and can never affect traffic. See architecture-specification
// §2.2 — enforcement is a deferred, post-PoC goal.

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

// Cache misses only. 16 MiB ring buffer.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Ring-buffer maps have no value type, so conn_event would otherwise be
// pruned from the object's BTF. This anchor keeps the type visible so bpf2go
// can generate the Go decoding struct. Never referenced by any program.
const struct conn_event *const event_btf_anchor __attribute__((unused));

// observe is the shared fast/slow path for all four hooks.
// Fast path: tuple already in seen_connections -> refresh timestamp, return.
// Slow path: insert tuple, emit one compact event to the ring buffer.
static __always_inline int observe(struct bpf_sock_addr *ctx, __u8 family, __u8 protocol)
{
	struct conn_key key = {0};
	__u64 now = bpf_ktime_get_ns();

	key.cgroup_id = bpf_get_current_cgroup_id();
	key.family = family;
	key.protocol = protocol;
	// user_port is a __u32 holding the destination port in network byte
	// order. VERIFY on first live run: `curl :443` must print 443, not
	// 36863. See README "Known spike caveats".
	key.dport = bpf_ntohs((__u16)(ctx->user_port & 0xffff));
	if (family == AF_IPV4) {
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
	return observe(ctx, AF_IPV4, PROTO_TCP);
}

SEC("cgroup/connect6")
int egress_connect6(struct bpf_sock_addr *ctx)
{
	return observe(ctx, AF_IPV6, PROTO_TCP);
}

SEC("cgroup/sendmsg4")
int egress_sendmsg4(struct bpf_sock_addr *ctx)
{
	return observe(ctx, AF_IPV4, PROTO_UDP);
}

SEC("cgroup/sendmsg6")
int egress_sendmsg6(struct bpf_sock_addr *ctx)
{
	return observe(ctx, AF_IPV6, PROTO_UDP);
}
