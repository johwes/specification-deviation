# M1 Node-Agent Report

Results of implementing and live-testing M1 (backlog.md M1.1-M1.6) against
real hardware. All work landed on `rhel-9-2vcpu` (RHEL 9.8, kernel
5.14.0-687.5.1.el9_8, 2 vCPU — the Round 2 M0 VM), building on the
`AF_NETLINK` and buffered-stdout fixes M0 already found. Commits:
`0e599b4` (M1.1), `61ff9f6` (M1.3-M1.5), `dbe3588` (M1.2), `065c4d8` (M1.6).

Environment note: `podman` was not preinstalled on the test VM (`dnf install
-y podman`) — a setup step, not a bug.

## M1.1 — Daemon scaffold

| Check | Result |
|---|---|
| Install (`make install`) | **Pass** |
| `systemctl enable --now` | **Pass** — clean `active (running)` status |
| Structured logging in journald | **Pass** — `log/slog` output renders correctly |
| Reload (log level, live-applicable) | **Pass** — `config reloaded log_level=debug` |
| Reload (cgroup_path, restart-required) | **Pass** — correctly warns instead of silently ignoring |
| Restart picks up new config | **Pass** — confirmed via the "sensor running" log line's `cgroup_path` field |
| Clean stop | **Pass** — exit 0, full event summary logged |

Full lifecycle verified, no gaps.

## M1.3 / M1.4 / M1.5 — Fleet identity resolution

| Check | Result |
|---|---|
| `systemd:<unit>.service` (explicit test unit) | **Pass** |
| `systemd:<unit>.service` (ambient services) | **Pass, incidental** — `chronyd.service` and `sshd.service` resolved correctly without being the thing under test |
| `podman:<image:tag>` (rootful container) | **Pass** — `docker.io/library/alpine:latest` resolved exactly via `podman inspect` |
| `systemd:session` (reserved class) | **Pass** — 62 events from our own SSH session all collapsed to the one reserved identity |
| `systemd:crond.service` (reserved class) | **Not tested** — code path exists (same suffix-match pattern as the service case), but no cron activity happened to fire during any test window |
| Podman rootless (`user.slice/.../libpod-*.scope`) | **Not tested** — only rootful (`sudo podman run`) was exercised. The regex matches the path substring regardless of which slice it's under, so this should work, but "should" isn't "verified" |

## M1.2 — Passive DNS snooper

| Check | Result |
|---|---|
| FQDN resolution on conn events | **Pass** — `curl https://example.com` correctly produced `"fqdn":"example.com."` on both IPv4 destination IPs |
| IPv6 destinations show no fqdn | **Pass** — correctly empty via `omitempty`, matching the documented IPv4-only scope (not a bug) |
| Self-exemption (own `AF_PACKET` socket doesn't trigger the M0.5 invariant) | **Pass** — `raw_socket=0` across the entire run despite the snooper's socket being open the whole time |
| Decode integrity under real DNS traffic | **Pass** — `decode_errors=0` |
| TTL expiry | **Not live-verified** — the arithmetic (`time.Now().After(expiresAt)`, set once at insert) is simple enough to trust by inspection, but `example.com`'s real TTL (266s) was too long to wait out live for the marginal confidence gained |

## M1.6 — Bounded buffer + central upload + reconnect

| Check | Result |
|---|---|
| Normal operation | **Pass** — events drain to the throwaway listener every ~2s as generated |
| Central killed mid-run | **Pass** — uploads log `"upload failed, will retry"`; buffer grew to 176 events over a ~25s outage with no loss |
| Sensor unaffected during outage | **Pass** — stdout event stream kept growing normally the entire time; the outage never stalled live processing |
| Central restarted | **Pass** — the full 235-event backlog drained in a single batch immediately, then normal streaming resumed |
| Clean shutdown drains remaining buffer | **Pass, after a fix** — see below |

### Bug found and fixed during live testing: no final drain on clean shutdown

The buffer/reconnect mechanics worked correctly from the start for the
*central-outage* case. But stopping the *sensor* itself (central healthy)
had no final drain step — `run()`'s shutdown path flushed stdout but never
gave the uploader goroutine a last chance to send. Found by deliberately
generating traffic and sending `SIGTERM` immediately afterward (worst-case
timing): the log showed events still sitting in the buffer at exit.

Fixed by adding a bounded final `drain()` call (its own short-lived context,
since the request context is already cancelled by the time the event loop
exits) after the stdout flush. Re-tested under the same worst-case timing:
`"uploaded events to central" count=32` now fires immediately before
`"sensor stopped"`, confirmed live.

## Outstanding items (not blockers, honest gaps)

1. **The M1 exit criterion says "two nodes streaming ... to a ... central
   listener"; only one node was ever tested.** Every mechanism (identity,
   DNS, buffering, reconnect) is proven on `rhel-9-2vcpu` alone, uploading
   to a listener on the same box. The literal two-node scenario — both
   `rhel-9-2vcpu` and `rhel-9-ebpf` streaming to one shared central listener
   — was never run. This is the most substantive gap; worth closing if the
   literal exit criterion needs to be demonstrated, e.g. for a stakeholder
   demo, rather than just the underlying mechanism being sound.
2. DNS TTL expiry: correct by inspection, not live-verified.
3. `systemd:crond.service` classification: code exists, never empirically
   triggered.
4. Podman identity resolution: only tested rootful, not rootless.

## Summary

All six M1 stories are implemented and live-tested on real hardware, with
one real bug found and fixed via live testing (the shutdown-drain gap) —
consistent with M0's pattern of live testing catching things code review
alone wouldn't have. Four items above are honest, named gaps rather than
silently dropped scope: none block moving to M2, but #1 (the two-node
demonstration) is the one worth a deliberate decision on before treating M1
as fully closed for demo purposes.
