# M0 Acceptance Test Report

Results of running `docs/testing-m0.md` against a real target VM (`rhel-9-ebpf`:
RHEL 9.8, kernel 5.14.0-687.5.1.el9_8, cgroup v2, BTF present, 1 vCPU / 3.5GiB
RAM). Findings from this run are already reflected in the code and in
`testing-m0.md` — this document is the record of what was found and why.

## Environment prep

Build environment, Go toolchain install, clone, and `make build` all succeeded
following the runbook, with one correction:

- **Runbook bug (fixed):** step 1's CRB repo ID was missing the `-rpms`
  suffix. The correct ID is `codeready-builder-for-rhel-9-<arch>-rpms`; the
  bare `codeready-builder-for-rhel-9-<arch>` is not a valid repository and
  `subscription-manager repos --enable` fails with "does not match a valid
  repository ID." Fixed in `testing-m0.md`.

## Acceptance checks (§3)

| Check | Result |
|---|---|
| 3.1/3.2 — TCP egress + port byte order | **Pass.** `curl :443` produced `"port":443`, not `36863`. |
| 3.3 — dedup | **Pass.** Repeated identical tuple produced zero new `conn` events. |
| 3.4 — UDP | **Pass.** `dig` correctly captured as `"protocol":"udp","port":53`. |
| 3.5 — exec lineage | **Pass.** `conn` events for processes exec'd after sensor start carried `parent_comm`/`exec_path` correctly. |
| 3.6 — raw-socket invariant (explicit) | **Pass.** `python3 socket.AF_PACKET/SOCK_RAW` correctly captured (`"family":17,"sock_type":3`). |
| 3.7 — noise check | **Inconclusive** — see below. |
| Decode integrity | **Pass.** `decode_errors=0` across 10,011 `conn` + 2,649 `exec` + 835 `raw_socket` events during the benchmark run. |

### Why 3.7 was inconclusive

The runbook assumes two live terminals: one holding a scoped interactive
shell, one running the sensor. Driving this non-interactively (no second
terminal available), test commands were injected into the target cgroup by
self-migration (`echo $$ > .../egress-test.scope/cgroup.procs && exec ...`).
This works for plain commands but not for `sudo`-wrapped ones: `pam_systemd`
re-scopes the process into a fresh transient session scope shortly after
migration, silently undoing it. Confirmed directly — the noise-check events
landed under a different `cgroup_id` than the test scope, and that session
scope had already been torn down by the time it was inspected.

This is a test-harness limitation, not a sensor defect, but it means 3.7 has
not actually been validated. **Re-run with a real two-terminal interactive
session**, or drive test commands without wrapping them in `sudo` inside the
migrated shell.

## Finding: raw-socket invariant was too noisy (fixed)

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
socket) case was already excluded. Not yet re-verified live — next VM session
should re-run 3.6/3.7 and confirm `sudo`-driven activity no longer appears in
the `raw_socket` stream.

## M0.6 — CPU overhead benchmark

Two paths, baseline (no sensor) vs. sensor attached to the root cgroup:

| Path | Baseline | Sensor attached | Delta |
|---|---|---|---|
| Fast (2000× identical tuple — dedup-hit) | 11,883 ms wall, sy%≈49 avg | 12,174 ms wall, sy%≈50 avg | **+2.4% wall, ~1pt sy%** |
| Slow (10k net-new tuples — worst case) | 302 ms wall, cs≈1,282/s | 661 ms wall, cs≈30,986/s | **+119% wall, ~24× context-switch rate** |

**Fast path: consistent with the <1% CPU target.** The LRU dedup-hit path is
close to free, as designed — the delta is within noise for a 1-vCPU VM.

**Slow path: real signal, but the measurement is underpowered — not a
pass/fail verdict.** The test window (302-661ms) was too short to get more
than one full `vmstat` sample, and the VM's single vCPU means every
ring-buffer wakeup (kernel BPF program → userspace consumer, once per
net-new tuple) fully serializes with everything else on the box, which a
multi-core production node would not. The large context-switch spike is
plausible and worth taking seriously — it's the expected cost of one wakeup
per net-new tuple — but this specific number should not be used to certify
or fail the architecture's `<1%` CPU budget.

**Before treating M0.6 as closed:**
1. Re-run on multi-core hardware closer to a real target node.
2. Use a longer, sustained churn window (100k+ connections over 10+ seconds)
   so `vmstat` collects enough samples to average cleanly.
3. If the overhead holds up under a real test, look at the ring-buffer
   consumer's read/wakeup behavior (batching, epoll coalescing) as the likely
   lever.

## Summary

M0.1-M0.5's core mechanics (dedup, byte order, dual-stack capture, exec
lineage join, explicit raw-socket detection) are verified working on real
RHEL 9 hardware, with zero decode errors under load. Two real issues were
found by testing on hardware rather than just compiling: the noisy
`AF_NETLINK` false-positive path (fixed) and a CRB repo-ID typo in the
runbook (fixed). M0.6's exit criterion (`<1%` CPU under churn) is not yet
demonstrated with confidence — the fast path looks good, the slow/churn path
needs a better test rig before it can be called either way.
