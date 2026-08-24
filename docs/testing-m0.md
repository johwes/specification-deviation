# Testing M0 on a RHEL 9 VM

Runbook for the M0 sensor spike acceptance tests (`docs/backlog.md`, M0.1–M0.6).
Everything below assumes a fresh RHEL 9 VM with internet access and a root
shell (or sudo).

## 1. Build environment (once)

```bash
# libbpf-devel lives in CRB (CodeReady Builder). Note the -rpms suffix — the
# repo ID is codeready-builder-for-rhel-9-<arch>-rpms, not ...-<arch> alone.
sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(uname -m)-rpms \
  || sudo dnf config-manager --set-enabled crb    # CentOS Stream equivalent

sudo dnf install -y git make clang llvm bpftool libbpf-devel kernel-headers
```

Go: `go.mod` requires **go ≥ 1.25.12**, newer than RHEL 9's stock `golang`.
Install upstream:

```bash
curl -sSLo /tmp/go.tgz https://go.dev/dl/go1.25.12.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
export PATH=$PATH:/usr/local/go/bin   # add to ~/.bashrc to persist
```

Clone and build:

```bash
git clone https://github.com/johwes/specification-deviation.git
cd specification-deviation
make build        # produces bin/sensor
```

## 2. Smoke test

```bash
sudo ./bin/sensor
```

Expected on stderr: the root-cgroup warning, then `sensor running; ...`.
Ctrl-C to stop; it should print the event counters line.

If it fails with `operation not permitted`: you are not root, or the kernel
locks down unprivileged BPF — run as root.

## 3. Acceptance checks (M0.1–M0.5)

Terminal 1 — start a scoped test workload:

```bash
sudo systemd-run --scope --unit=egress-test bash
```

Terminal 2 — attach the sensor to that scope only:

```bash
sudo ./bin/sensor -cgroup /sys/fs/cgroup/system.slice/egress-test.scope \
  | tee m0-events.jsonl | jq .
```

Run inside the **scoped shell** (terminal 1), one at a time, and check
`m0-events.jsonl`:

| # | Check | Command | Expected |
|---|-------|---------|----------|
| 3.1 | TCP egress (M0.1) | `curl -s https://example.com >/dev/null` | One `"type":"conn"` event, `"protocol":"tcp"`, `"port":443` |
| 3.2 | **Port byte order** | (same event) | Port prints `443`, **not** `36863`. If byte-swapped, the `user_port` note in `bpf/probes.c` applies — file it. |
| 3.3 | Dedup (M0.2) | `curl -s https://example.com >/dev/null` again | **No** new conn event |
| 3.4 | UDP (M0.3) | `dig @8.8.8.8 example.com` (or `host example.com 8.8.8.8`) | conn event, `"protocol":"udp"`, `"port":53` |
| 3.5 | Exec lineage (M0.4) | `/usr/bin/true` then repeat 3.1 | An `"type":"exec"` event with `"path":"/usr/bin/true"`, `"parent_comm":"bash"`; conn events for processes exec'd after sensor start carry `exec_path` |
| 3.6 | Raw socket invariant (M0.5) | `python3 -c 'import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)'` | `"type":"raw_socket"`, `"signal":"raw_socket_creation"` |
| 3.7 | Noise check | `ls; echo hi` | exec events only — no conn/raw_socket events for local-only activity |

Notes:

- The exec and raw-socket tracepoints are **host-wide**; only the egress hooks
  respect `-cgroup`. Expect background exec events from the VM itself — filter
  with `jq 'select(.type=="conn")'` if noisy.
- IPv6 (connect6/sendmsg6) is exercised implicitly if the VM has v6
  connectivity; an explicit check is `curl -s https://ipv6.google.com`.
- Modern `ping` uses SOCK_DGRAM ping sockets and is deliberately **not**
  flagged by the raw-socket probe — 3.6 is the honest test.

## 4. M0.6 — churn benchmark (< 1% CPU budget)

Two runs each: sensor attached to the root cgroup vs. not running. Redirect
sensor output to /dev/null so terminal rendering isn't part of the
measurement: `sudo ./bin/sensor >/dev/null &`

**Fast path (same tuple repeatedly — should be ~free):**

```bash
time bash -c 'for i in $(seq 1 2000); do curl -s -o /dev/null https://example.com; done'
```

**Slow path (10k net-new tuples — worst case):**

```bash
time python3 - <<'EOF'
import socket
for p in range(20000, 30000):
    s = socket.socket(); s.settimeout(0.05)
    try: s.connect(("127.0.0.1", p))
    except OSError: pass
    s.close()
EOF
```

During each run, sample system CPU in a second terminal: `vmstat 1 5` — watch
the `sy` column. Pass criterion: wall-time and `sy%` deltas between
sensor-attached and sensor-off runs are within noise (≈1%). Record the numbers
in an issue or the repo wiki; this is the evidence for the architecture's
"< 1% CPU" budget.

## 5. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `operation not permitted` at load | not root / BPF restricted |
| `libbpf-devel` not found | CRB repo not enabled (step 1) |
| `go.mod requires go >= 1.25.12` | stock RHEL golang; use the tarball in step 1 |
| No events at all | sensor attached to a different cgroup than the test shell — check `/proc/self/cgroup` inside the scoped shell |
| Verifier rejection | kernel too old / missing feature — collect `sudo bpftool prog load` output and file an issue |
