# Backlog: Egress Discovery & Specification Engine

Milestone-based backlog for the PoC defined in `architecture-specification.md`.
Advisory-only: nothing in M0–M3 blocks traffic. The PoC succeeds when a human
can ratify a workload's egress specification and the system signals on drift.

## PoC demo scenario (definition of done)

1. Environment: one RHEL 9 VM running a systemd service and a podman
   container; one OpenShift namespace with a sample workload. Central store +
   dashboard reachable by the reviewing team.
2. Seed infrastructure endpoints (DNS, LDAP/Kerberos, NTP, package mirrors)
   from static sources; reviewer confirms.
3. Discovery runs in parallel across all nodes. Proposals appear grouped by
   workload, static matches pre-suggested, risk-annotated items highlighted.
4. Reviewer ratifies (allow/deny per line). Decisions land in Git with
   `owner`, `decided_by`, version.
5. **Drift demo:** the ratified workload contacts a net-new endpoint →
   `spec_deviation` signal on the JSON stream *and* re-entry in the queue.
6. **Invariant demo:** the service spawns `/bin/sh` → `invariant_violation`
   signal with full process ancestry.

Success criteria:

- CPU overhead of the in-kernel plane < 1% under light/steady-state
  connection churn (measured in `docs/report-m0.md`: holds cleanly on the
  dedup-hit path). Sustained extreme churn exceeds this — accepted as a
  known PoC limitation, not a blocker; see the M0 exit notes below.
- Zero traffic blocked, ever (fail-open verified by killing central mid-demo).
- Signal latency: endpoint connect → structured signal < 10 s.
- Reviewer can clear initial queue for a 3-workload environment in < 15 min
  (the "ratifiable in minutes" property).

---

## M0 — Kernel sensor spike

Prove the Tier 1 data plane on a single RHEL 9 VM. No identity resolution, no
central server — events to local ring buffer reader, dumped as JSON lines.

| # | Story | Acceptance |
|---|-------|-----------|
| M0.1 | CO-RE/libbpf scaffold: load `cgroup/connect4` + `cgroup/connect6` programs; emit compact event (cgroup_id, daddr, dport, proto, ts) | Events visible for curl from a systemd service and a podman container; IPv4 + IPv6 |
| M0.2 | LRU dedup map (32k) keyed on `(cgroup_id, daddr, dport, proto)` | Repeated connections emit once per tuple; map-full path does not drop process or crash under fuzz |
| M0.3 | `cgroup/sendmsg4/6` for UDP/QUIC/DNS | DNS lookups and UDP flows captured |
| M0.4 | `sched_process_exec` lineage capture (pid, ppid, path, parent path, cgroup_id) | Can attribute each egress event to exec lineage |
| M0.5 | Raw socket probe (`sys_enter_socket`, SOCK_RAW/AF_PACKET) | `ping`/raw-socket test binary flagged |
| M0.6 | Benchmark harness: connection-churn load test (e.g., 10k conn/s loop) with CPU measurement | Report committed to repo (`docs/report-m0.md`) |

**M0 exit:** `sensor dump | jq` shows deduplicated, lineage-attributed egress
tuples on RHEL 9; benchmark report exists (`docs/report-m0.md`).

**M0.6 result, accepted as a known limitation — not reopened for M1:** the
dedup-hit (fast) path is within the <1% CPU budget, cleanly measured on both
1- and 2-vCPU hardware. Sustained extreme churn (tens of thousands of
net-new endpoints/sec) costs meaningfully more (~5.5 percentage points of
total CPU on 2 vCPUs, ~46× context-switch rate) — a real, well-measured
number, not a test artifact. Not pursued further in this PoC: the goal is
proving feasibility and value, not shipping a production-hardened sensor.
Revisit only if a real target workload's sustained net-new-endpoint rate
approaches that range. Also worth noting: RHEL 9's own minimum *supported*
configuration is 2 vCPUs — the 1-vCPU numbers are a deliberately-tested
worst case below Red Hat's own supported floor, not a realistic target
profile.

## M1 — Node agent

| # | Story | Acceptance |
|---|-------|-----------|
| M1.1 | Daemon scaffold (Go or Rust): structured lifecycle (start/stop/reload), config, logging. Loads BPF programs directly, same approach as M0 (`cilium/ebpf`, `CAP_BPF` held by the daemon itself) — bpfman-brokered privilege separation deferred, see parking lot | `systemctl status` clean; daemon starts/stops/reloads cleanly under systemd |
| M1.2 | Passive DNS snooper (port 53 UDP/TCP) → TTL-aware IP↔FQDN cache | curl to CDN hostname resolves to FQDN in output; TTL expiry respected |
| M1.3 | systemd identity resolver (cgroup path → unit name) | Events carry `systemd:<unit>` fleet identity |
| M1.4 | podman identity resolver (`libpod-<id>` → image/name) | Events carry `podman:<image:tag>` identity |
| M1.5 | Interactive-session classifier (`session-*.scope` → reserved class, excluded from queue by default) | SSH session egress visible but flagged; not in default queue |
| M1.6 | Local decision cache + bounded event buffer; plain-HTTP upload with reconnect (mTLS deferred — see parking lot) | Kill central 10 min → no event loss within buffer; traffic unaffected |

**M1 exit:** two nodes streaming enriched, identity-resolved events to a
throwaway central listener; survive central outage.

## M2 — Central store, ratification dashboard, signal stream (the demo)

| # | Story | Acceptance |
|---|-------|-----------|
| M2.1 | Ingestion API (mTLS, per-node creds), idempotent dedup | Duplicate deliveries collapse; two nodes' events for same fleet identity aggregate |
| M2.2 | Static-declaration ingestion (unit files, manifests, resolv.conf/kickstart network config) → platform seed + "suggested: allow" matching | Seed reviewable before any workload traffic; declared endpoints pre-marked in proposals |
| M2.3 | Proposal builder: group by `(fleet_identity, endpoint, port, proto)`; attach instance spread, first/last seen, process, risk annotations | Reviewer sees one line per endpoint per workload |
| M2.4 | Risk annotations: direct-to-ip, newly-registered-domain, shell-initiated, infrastructure-mismatch | Annotated items sort/highlight above clean ones |
| M2.5 | Git-backed decision store (§6.3 schema: owner, decided_by, source, version) | Every UI decision commits; repo history = audit trail; revert works |
| M2.6 | Review queue UI: grouped per-workload diff, allow/deny, bulk-accept static matches | Demo scenario step 3–4 passes; < 15 min for 3 workloads |
| M2.7 | Drift detector: ratified workload + net-new endpoint → `spec_deviation` signal + queue re-entry | Demo step 5 passes |
| M2.8 | Invariant signal pipeline: ancestry + raw-socket + direct-to-IP rules → `invariant_violation` | Demo step 6 passes; full parent chain in evidence |
| M2.9 | Signal stream: structured JSON (§6.4) via webhook + file sink; spec reference embedded | A trivial script consumer can parse and act; latency < 10 s |
| M2.10 | `denied_endpoint_observed` high-severity path | Deny an endpoint, generate traffic to it, observe top-severity signal (still no blocking) |

**M2 exit:** the full demo scenario runs end to end. This is the PoC.

## M3 — OpenShift coverage & hardening — DEFERRED

> Deferred — UX validation (M2 hardening + measured `ratifiable in minutes` trial `docs/report-m2.md:130`) takes precedence over K8s portability. Retained as design, not committed timeline.

| # | Story | Acceptance |
|---|-------|-----------|
| M3.1 | Kubernetes identity resolver (pod UID → namespace/SA → `k8s:<ns>/<workload>`) | Events from a Deployment aggregate across replicas |
| M3.2 | DaemonSet packaging via bpfman on OpenShift; SCC/SELinux posture documented | Deploys with default `restricted-v2` coexistence; no privileged daemon beyond bpfman contract |
| M3.3 | Existing NetworkPolicy manifests ingested as static declarations | Declared k8s egress pre-marked like unit-file declarations |
| M3.4 | Multi-node soak: 7 days on a lab cluster; dashboard metric for per-workload discovery-rate flattening | Metric visible; no auto-cutover (observability only) |
| M3.5 | Failure-mode game day: central down, node agent down, DNS-snooper bypass (DoH), short-lived process storm | Behavior matches §13 of the architecture spec |

---

## Post-PoC parking lot (do not groom yet)

- Enforcement: eBPF `EPERM` verdict in `cgroup/connect*`; then export of
  ratified specs as NetworkPolicy / CiliumNetworkPolicy.
- Multi-replica consensus automation and asymptotic cutover (only if human
  ratification proves to not scale).
- Owner-routed review (ChatOps per `owner` field), federated queues.
- SPIFFE/SPIRE cryptographic workload identity.
- L7 / operation-level specification ("write only to namespaces you own").
- RHEL 8 / cgroup v1 support; ingress direction; automated response via AAP.
- bpfman-brokered privilege separation for the node agent (no `CAP_BPF` on
  the daemon itself). Not a supported path on bare-metal RHEL 9 today (no
  official RPM; only an unofficial Fedora Copr build). Already available for
  the OpenShift target via the eBPF Manager Operator (M3.2) — this item is
  specifically about the bare-metal/VM systemd target.
- Signed/verified sensor bytecode via bpfman's OCI image + cosign/sigstore
  pipeline — the project's own "specification as security primitive" thesis
  applied to the sensor's own code provenance. Requires standing up signing
  infrastructure to matter; not automatic.
- Map sharing across independently-loaded programs (bpfman's
  `--map-owner-id`) — would allow splitting the node agent into a small
  privileged loader plus separate unprivileged consumer processes.
- SELinux policy module for pinned BPF maps (`ebpf_map_t`) — defense-in-depth
  against a compromised process tampering with sensor state; hardens the
  tool, doesn't demonstrate the detection thesis. Revisit if the pitch wants
  a "we eat our own dogfood" story.
- Package-signature-verified seed derivation for M2.2 (RPM database lookup +
  digest/GPG check against the running binary, proposed seed sourced from
  that package's own declared config) — see architecture-specification.md
  §11. Derives a spec faster for the boring majority; must never bypass
  ongoing drift detection on the resulting spec.
- Ancestry+egress compound invariant (architecture-specification.md §12,
  invariant 1) — not the generic "service spawned a shell" signal Falco
  already owns, but the narrower "ancestry-anomalous child *then* makes
  egress" signal, which needs the lineage-enriched egress this system
  already captures. Partially overlaps SELinux's `httpd_can_network_connect`
  on bare metal with default booleans; doesn't overlap in containers or
  once that boolean's been loosened, which is most real deployments.
- Risk-based (not category-based) treatment of `systemd:session` /
  `systemd:crond.service` in the default queue view — surface risk-annotated
  session activity (§11.2) prominently regardless of category; only
  deprioritize the risk-clean majority. Corrects an earlier framing
  (architecture-specification.md §5.2) that risked reading as blanket
  suppression, which would hide exactly the pastebin/dead-drop pattern this
  system exists to catch.
- SELinux AVC / OPA / Falco signal aggregation as a complementary signal
  source (the original `specification-deviation-brief.md` thesis this PoC
  did not pursue, having built a new eBPF sensor instead) — worth revisiting
  once the egress-specific path is further along, since platform signals and
  this system's signals cover different, only-partially-overlapping ground.
- mTLS for node→central upload (M1.6 uses plain HTTP for the PoC instead) —
  real PKI (per-node cert issuance/rotation) is production scope; the
  property actually being demonstrated is buffering/reconnect resilience,
  which doesn't depend on the transport's auth model. The same question
  will recur at M2.1 (central ingestion API currently specs mTLS too).
- Destination identity resolution (architecture-specification.md §5.3) — two
  findings, one mechanism. (1) East-west traffic between two monitored
  workloads never becomes a graph edge today (raw destination IP instead of
  the other workload's fleet identity); fixable if nodes self-report their
  own addresses. (2) Round-robin/pool infrastructure (confirmed live:
  chronyd/NTP pool, 38 separate direct-to-ip proposals for one conceptual
  relationship) defeats FQDN-first ratification because per-IP DNS-cache
  timing doesn't reliably line up with connection time for services designed
  to rotate across many backing addresses. Mechanism: a third `EndpointRef`
  type, `{"type": "group", "value": "<name>"}`, backed by an
  operator-declared match rule (DNS suffix/CIDR/exact-list) — the same
  pattern as Cilium's FQDN-based egress policies. Both findings are really
  the same "upgrade a raw endpoint to a richer identity before keying a
  decision off it" operation with two different sources of truth. Honest
  tradeoff: a named group is strictly a wider trust grant than an exact IP.

## Standing rules for grooming

1. Advisory-only is not negotiable in PoC: no story may introduce a blocking
   path.
2. Every signal must carry its specification reference.
3. Learned data never authorizes itself: no auto-promotion stories.
4. The review queue optimizes for reviewer minutes, not detector completeness.
