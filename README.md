# Specification Deviation

PoC: platform-native egress discovery and specification engine, motivated by
the July 2026 OpenAI / Hugging Face breach. Advisory-only — the system detects
and signals; it never blocks traffic.

## Docs

- [`docs/openshift-defaults-breach-analysis.md`](docs/openshift-defaults-breach-analysis.md) —
  phase-by-phase evaluation of the breach against OpenShift default security settings.
- [`docs/specification-deviation-brief.md`](docs/specification-deviation-brief.md) —
  strategic brief on specification-based detection as a defensive primitive.
- [`docs/summary.md`](docs/summary.md) — synthesis of the two documents above;
  captures the conclusions that shaped the architecture.
- [`docs/architecture-specification.md`](docs/architecture-specification.md) —
  PoC system architecture (advisory-only, egress-focused).
- [`docs/backlog.md`](docs/backlog.md) — milestone-based backlog (M0–M3) implementing
  the architecture.
- [`docs/testing-m0.md`](docs/testing-m0.md) — M0 acceptance-test runbook for a RHEL 9 VM.
- [`docs/report-m0.md`](docs/report-m0.md) — results of running that runbook against
  real hardware: what passed, what was inconclusive, and the bugs it found.
- [`docs/report-m1.md`](docs/report-m1.md) — M1 node-agent live-test results:
  what passed, one real bug found and fixed, and named outstanding gaps.

## Repository layout

- `docs/` — design documents (see above)
- `bpf/` — eBPF kernel programs (C, CO-RE)
- `cmd/sensor/` — node-agent daemon: userspace loader/reader (Go, cilium/ebpf)
- `cmd/throwaway-listener/` — disposable test listener for M1.6's
  buffer/reconnect demo; not part of the product, M2 builds the real
  ingestion API
- `packaging/` — systemd unit + example config for running the daemon (M1.1)
- `Makefile` — `make build` generates and compiles everything; `make install`
  installs the daemon as a systemd service; `make build-listener` builds the
  test listener
- `Containerfile` — reproducible build environment

## Building the M0 spike

Prereqs (see `Containerfile`): clang, llvm, bpftool, golang, make,
libbpf-devel, kernel-headers.

    make build        # → bin/sensor

Run on a cgroup v2 host, as root. For an isolated test, attach to a throwaway
scope instead of the root cgroup:

    sudo systemd-run --scope --unit=egress-test bash
    # in another terminal:
    sudo ./bin/sensor -cgroup /sys/fs/cgroup/system.slice/egress-test.scope | jq .

Inside the scoped shell, exercise the three event types:

    curl -s https://example.com >/dev/null        # conn (egress tuple)
    ls                                            # exec (lineage)
    python3 -c 'import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)'
                                                  # raw_socket (invariant signal)

Note: the cgroup hooks are scoped to the `-cgroup` subtree; the exec and
raw-socket tracepoints are host-wide (cgroup_id on the event is the filter key).

Known spike caveats:

- Destination-port byte order follows the UAPI docs (network order) — verify on
  first live run (`curl :443` must print 443, not 36863).
- UDP on connected sockets is seen by both the connect and sendmsg hooks; dedup
  absorbs it.
- Lineage attribution only covers execs observed after sensor start, is
  best-effort via /proc for parent info (short-lived processes may be gone),
  and can mis-attribute on pid reuse. Eager in-kernel resolution is M1.
- Modern ping uses unprivileged SOCK_DGRAM ping sockets
  (net.ipv4.ping_group_range) and is intentionally NOT flagged — test the
  raw-socket invariant with the AF_PACKET one-liner above.
- AF_NETLINK sockets (used constantly by PAM, systemd, sudo, and the audit
  subsystem) are intentionally NOT flagged either — confirmed live
  (`docs/report-m0.md`) that they otherwise dominate the raw-socket signal.

## Running as a systemd daemon (M1.1)

    make install                     # installs binary, unit, example config
    sudo cp /etc/specification-deviation/sensor.json.example \
            /etc/specification-deviation/sensor.json   # optional; defaults apply if absent
    sudo systemctl daemon-reload
    sudo systemctl enable --now specdev-sensor
    sudo systemctl status specdev-sensor
    journalctl -u specdev-sensor -f

Config (`/etc/specification-deviation/sensor.json`) is optional — a missing
file runs on defaults (root cgroup, info logging, no central upload).
`cgroup_path`, `log_level`, and `central_url` are the settings so far.

    sudo systemctl reload specdev-sensor   # SIGHUP: re-reads config
    sudo systemctl stop specdev-sensor

Reload applies `log_level` immediately. Changing `cgroup_path` requires a
full restart (`systemctl restart specdev-sensor`) — reload logs a warning if
it sees a `cgroup_path` change it can't apply live.

No `bpfman` broker: the daemon loads BPF programs directly, the same way the
M0 spike did, and needs `CAP_BPF` itself (`User=root` in the unit for now).
See `docs/backlog.md`'s parking lot for why (`bpfman` has no supported
bare-metal RHEL 9 path today) and what it would otherwise be worth using for.

## Fleet identity, DNS names, and central upload (M1.2-M1.6)

Every event now carries `fleet_identity` — `systemd:<unit>.service`,
`podman:<image:tag>`, or the reserved `systemd:session` / `systemd:crond.service`
classes (M1.5's egress-visible-but-flagged treatment; there's no queue to
exclude them from by default until M2). `conn` events carry `fqdn` when the
destination has a passively-observed DNS answer in cache (IPv4 only this
milestone; TTL-bound, expired entries are treated as a cache miss).

Set `central_url` in the config to stream events to a central endpoint as
batched JSON POSTs (plain HTTP, not mTLS — see the parking lot in
`docs/backlog.md` for why), in addition to stdout:

    { "central_url": "http://central.example:8443/events" }

A bounded local buffer (200k events) means a central outage never blocks
live event processing or loses events within that bound — try it with the
disposable test listener:

    make build-listener
    ./bin/throwaway-listener -addr 127.0.0.1:8443   # separate terminal

Kill and restart the listener while the sensor runs: the backlog logs as
"upload failed, will retry" during the outage and drains in one batch the
moment the listener comes back (also drained once, on a clean sensor
shutdown, so a restart doesn't strand whatever's still buffered).

## Status

Design phase complete. M0 done (`docs/report-m0.md`); M1 (M1.1-M1.6, the
node-agent daemon) done. M2 (central store, ratification dashboard, the
actual demo) is next — see `docs/backlog.md`.
