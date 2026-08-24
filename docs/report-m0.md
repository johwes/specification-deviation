# M0 Acceptance Test Report

Results of running `docs/testing-m0.md` against real hardware, across two
rounds. Findings from both rounds are already reflected in the code and in
`testing-m0.md` — this document is the record of what was found and why.

- **Round 1** — `rhel-9-ebpf`: RHEL 9.8, kernel 5.14.0-687.5.1.el9_8, cgroup
  v2, BTF present, **1 vCPU** / 3.5GiB RAM.
- **Round 2** — `rhel-9-2vcpu`: identical RHEL/kernel build, **2 vCPUs** /
  3.5GiB RAM. Run after the fixes Round 1 produced (`AF_NETLINK` exclusion,
  buffered stdout output, CRB repo-ID typo).

## Round 1 (1 vCPU)

### Environment prep

Build environment, Go toolchain install, clone, and `make build` all
succeeded following the runbook, with one correction:

- **Runbook bug (fixed):** step 1's CRB repo ID was missing the `-rpms`
  suffix. The correct ID is `codeready-builder-for-rhel-9-<arch>-rpms`; the
  bare `codeready-builder-for-rhel-9-<arch>` is not a valid repository and
  `subscription-manager repos --enable` fails with "does not match a valid
  repository ID." Fixed in `testing-m0.md`.

### Acceptance checks (§3)

| Check | Result |
|---|---|
| 3.1/3.2 — TCP egress + port byte order | **Pass.** `curl :443` produced `"port":443`, not `36863`. |
| 3.3 — dedup | **Pass.** Repeated identical tuple produced zero new `conn` events. |
| 3.4 — UDP | **Pass.** `dig` correctly captured as `"protocol":"udp","port":53`. |
| 3.5 — exec lineage | **Pass.** `conn` events for processes exec'd after sensor start carried `parent_comm`/`exec_path` correctly. |
| 3.6 — raw-socket invariant (explicit) | **Pass.** `python3 socket.AF_PACKET/SOCK_RAW` correctly captured (`"family":17,"sock_type":3`). |
| 3.7 — noise check | **Inconclusive** — see below. |
| Decode integrity | **Pass.** `decode_errors=0` across 10,011 `conn` + 2,649 `exec` + 835 `raw_socket` events during the benchmark run. |

#### Why 3.7 was inconclusive

The runbook assumes two live terminals: one holding a scoped interactive
shell, one running the sensor. Driving this non-interactively (no second
terminal available), test commands were injected into the target cgroup by
self-migration (`echo $$ > .../egress-test.scope/cgroup.procs && exec ...`).
This works for plain commands but not for `sudo`-wrapped ones: `pam_systemd`
re-scopes the process into a fresh transient session scope shortly after
migration, silently undoing it. Confirmed directly — the noise-check events
landed under a different `cgroup_id` than the test scope, and that session
scope had already been torn down by the time it was inspected.

This is a test-harness limitation, not a sensor defect, but it meant 3.7 had
not actually been validated in Round 1. Resolved in Round 2 (see below).

### Finding: raw-socket invariant was too noisy (fixed in Round 1, confirmed in Round 2)

Independent of the 3.7 harness issue — this is a host-wide tracepoint,
confirmed across multiple distinct `cgroup_id` values — **100% of the
`raw_socket_creation` events observed during ordinary system activity
(835 events across the benchmark run) were `family:16` (`AF_NETLINK`)**, not
`AF_PACKET`. A single `sudo` invocation alone produced 4-5 of them.

`AF_NETLINK` + `SOCK_RAW` is ordinary kernel↔userspace plumbing — PAM,
systemd, sudo, and the audit subsystem create these constantly. It has
nothing to do with raw-packet capture or spoofing capability, and its
presence would have swamped this invariant's signal-to-noise ratio on any
real system, undermining architecture-specification.md §12's requirement that
declared invariants be "binary, high [confidence]."

**Fixed** in `bpf/probes.c` / `bpf/common.h`: `handle_raw_socket` now excludes
`AF_NETLINK` unconditionally, the same way the ping (`SOCK_DGRAM` ping
socket) case was already excluded.

### M0.6 — CPU overhead benchmark (Round 1)

Two paths, baseline (no sensor) vs. sensor attached to the root cgroup:

| Path | Baseline | Sensor attached | Delta |
|---|---|---|---|
| Fast (2000× identical tuple — dedup-hit) | 11,883 ms wall, sy%≈49 avg | 12,174 ms wall, sy%≈50 avg | **+2.4% wall, ~1pt sy%** |
| Slow (10k net-new tuples — worst case) | 302 ms wall, cs≈1,282/s | 661 ms wall, cs≈30,986/s | **+119% wall, ~24× context-switch rate** |

**Fast path: consistent with the <1% CPU target.** The LRU dedup-hit path is
close to free, as designed — the delta is within noise for a 1-vCPU VM.

**Slow path: real signal, but the measurement was underpowered — not a
pass/fail verdict.** The test window (302-661ms) was too short to get more
than one full `vmstat` sample, and the VM's single vCPU meant every
ring-buffer wakeup (kernel BPF program → userspace consumer, once per
net-new tuple) fully serialized with everything else on the box, which a
multi-core production node would not. The large context-switch spike was
plausible but this specific number could not be used to certify or fail the
architecture's `<1%` CPU budget. Also confounded by an M0 sink artifact: the
sensor printed one line per event via unbuffered `fmt.Println` — one
`write(2)` syscall per event on top of whatever the ring-buffer path itself
costs. Fixed (buffered stdout, flush on 50 events or 200ms) before Round 2.

## Round 2 (2 vCPUs, after fixes)

### Setup

Same runbook, now with the `-rpms` CRB fix already in place (worked cleanly
on the first attempt). Cloned at commit `762de9d` (AF_NETLINK exclusion +
buffered stdout both included).

**Methodology change for 3.7:** rather than repeated `sudo`-wrapped
invocations (the Round 1 harness bug), all checks 3.1–3.7 ran inside a
**single** elevated shell: migrate into the test cgroup once via
`echo $$ > cgroup.procs`, then run every check as a plain command with no
further `sudo` calls in between. This avoids the `pam_systemd` re-scoping
race entirely.

### Acceptance checks (§3) — clean pass across the board

| Check | Result |
|---|---|
| 3.1/3.2 — TCP egress + port byte order | **Pass.** |
| 3.3 — dedup | **Pass.** Second `curl` to the same tuples produced zero new `conn` events. |
| 3.4 — UDP | **Pass.** `dig`'s resolver thread correctly captured as udp/53. |
| 3.5 — exec lineage | **Pass.** All `conn` events carried `"parent_comm":"bash"`. |
| 3.6 — raw-socket invariant (explicit) | **Pass.** `python3` `AF_PACKET`/`SOCK_RAW` was the *only* raw_socket event in the entire scoped test run. |
| **AF_NETLINK fix** | **Confirmed live.** `ip addr show lo` — the canonical heavy user of `AF_NETLINK` sockets — produced **zero** raw_socket events. |
| 3.7 — noise check | **Pass.** `ls` produced only an exec event; nothing else. |

All events in the scoped test were correctly and consistently attributed to
the target cgroup ID throughout — no cross-scope leakage this time.

### M0.6 — CPU overhead benchmark (Round 2)

Same fast/slow structure, slow path rescaled to a sustained 450,000-tuple
churn (10 loopback addresses × 45,000 ports each) so it runs ~10-15 seconds —
long enough for `vmstat` to collect a clean multi-sample average, unlike
Round 1's sub-second window.

| Path | Baseline | Sensor attached | Delta (wall) | Delta (total CPU%, us+sy)\* |
|---|---|---|---|---|
| Fast (2000× identical tuple) | 9,878 ms | 9,988 ms | **+1.1%** | **~+1.0 pt** |
| Slow (450,000 net-new tuples, sustained) | 9,963 ms, cs≈1,511/s | 14,913 ms, cs≈69,976/s | **+49.7%** | **~+5.5 pt** |

\* Averaged over the steady-state 1-second `vmstat` samples in each run
(warmup/cooldown idle samples excluded). `us`+`sy` is reported as a fraction
of *total* system CPU (both cores), consistent with `vmstat`'s convention.

**Fast path: at/within the <1% CPU target**, cleanly measured this time —
9 full-second samples per run rather than a guess.

**Slow path: the overhead is real, not a measurement artifact — but the
buffering fix wasn't the fix for it.** The context-switch rate rose ~46×
(1,511/s → 69,976/s), consistent with roughly one ring-buffer wakeup
(kernel BPF program → userspace consumer) per net-new tuple: at ~32,000
events/sec sustained, ~2 context switches per event predicts almost exactly
the observed rate. This is now a clean, well-sampled, reproducible number —
not the single ambiguous data point Round 1 produced — and it shows that
**sustained extreme churn (tens of thousands of never-before-seen
destinations per second) still costs meaningfully more than the 1% budget**,
even on 2 cores. The buffered-stdout fix addressed the *userspace print*
syscall cost (Round 1's confound) but not the *kernel-to-userspace wakeup*
cost, which is a separate, deeper mechanism.

Correctness under this load was solid: `conn=450003 exec=2376 raw_socket=0
decode_errors=0` — every one of the 450,000 generated tuples was captured
and decoded correctly at sustained high throughput.

**Next lever, if this needs to close further:** attribute the context-switch
cost properly (`perf stat -e context-switches` scoped to the sensor PID
alone, separating "wakeups caused by the sensor" from "context switches
caused by 900,000+ `connect()`/`close()` syscalls in the test workload
itself competing for the same 2 cores") before concluding the ring-buffer
consumer needs batching changes. The workload generator itself is also a
real consumer of both cores in this test, which dilutes how much of the
delta is attributable to the sensor specifically.

## Summary

Two full rounds. Round 1 found two real bugs from testing on hardware rather
than just compiling (`AF_NETLINK` false positives, CRB repo-ID typo) and one
real perf confound (unbuffered stdout) — all fixed. Round 2, on 2 vCPUs with
those fixes applied, is a clean pass on every functional/correctness check
(3.1–3.7, including confirmation the `AF_NETLINK` fix works against a real
heavy netlink user), plus a properly-sampled benchmark: the fast/dedup-hit
path is within the `<1%` CPU budget, and the slow/sustained-churn path has a
real, well-measured, non-trivial cost (~+5.5 percentage points of total
system CPU, ~46× context-switch rate) that is now understood well enough to
act on, rather than an inconclusive guess. Whether that residual cost
matters depends on how much sustained net-new-tuple churn is realistic for
target workloads — worth a decision before M1, not before shipping M0.
