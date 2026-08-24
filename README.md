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

## Repository layout

- `docs/` — design documents (see above)
- `bpf/` — eBPF kernel programs (C, CO-RE)
- `cmd/sensor/` — M0 sensor spike: userspace loader/reader (Go, cilium/ebpf)
- `Makefile` — `make build` generates and compiles everything
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

Known spike caveats: destination-port byte order follows the UAPI docs
(network order) — verify on first live run (`curl :443` must print 443, not
36863). UDP on connected sockets is seen by both the connect and sendmsg
hooks; dedup absorbs it. Processes are attributed by pid/comm only until
M0.4 (exec lineage) lands.

## Status

Design phase complete. M0 spike in progress (kernel egress sensor) per
`docs/backlog.md`; live testing targets a RHEL 9 VM.
