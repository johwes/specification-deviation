# Architecture Specification: Platform-Native Egress Discovery & Specification Engine

*Status: PoC scope — advisory-only. This revision supersedes the earlier
"zero-trust enforcement" framing. Items removed from the PoC path are listed
explicitly in §2.3 rather than silently dropped.*

---

## 1. Executive Summary & Problem Statement

### 1.1 The Problem

No component in the stack knows, in machine-readable form, what a workload is
*supposed* to talk to. Declared egress intent exists nowhere by default, so
detection falls back to signatures (blind to novel attacks) or statistical
anomaly detection (gameable at machine speed). The July 2026 breach ran for
days on exactly this gap: every connection the agent made was syntactically
valid, authenticated, and to legitimate services.

Building that missing declared intent by hand fails in production for four
reasons:

- **The Declaration Problem:** Authoring per-workload egress specifications
  manually across hundreds of services and thousands of hosts is intractable.
- **The Operational Maintenance Trap:** Ephemeral cloud IPs and CDN churn make
  static L3/L4 rules brittle within hours.
- **Brownfield Incompatibility:** Sidecar proxies (Istio/Envoy) require TLS
  termination and HTTP-only support. They fail on bare-metal RHEL hosts, VMs,
  and non-HTTP protocols — the majority of the estate.
- **Stateless Telemetry Exhaustion:** Streaming every raw socket event to
  user space floods CPU, memory, and the SOC with uncontextualized events.
- **The Day-0 Cold-Start Dilemma:** An empty-state detector across thousands of
  nodes produces an alert tsunami on day one.

### 1.2 The Solution

Discover egress behavior in-kernel via eBPF, keyed on cgroups — the one
identity primitive that exists identically for systemd services, podman
containers, and Kubernetes pods. Resolve those observations to stable
**workload identities** on the node, enrich with passive DNS, and aggregate
centrally into **per-workload proposals**. A human ratifies proposals into a
versioned **specification**. From that point on, deviation from the ratified
specification is a structured, binary **signal** — consumable by defensive AI
agents, SOCs, or SIEMs.

**The system is advisory-only. It never blocks traffic.** Its output is signal
and a ratified specification artifact. Enforcement (eBPF verdict, NetworkPolicy
generation) is a deferred goal, not part of this architecture's critical path.

The ratification review — a grouped, diff-style artifact a human can approve in
minutes — is the product. Everything else is plumbing.

---

## 2. Goals, Non-Goals, Deferred

### 2.1 Goals (PoC)

- Discover outbound connections per **workload identity** across:
  bare-metal/VM RHEL (systemd units), VMs running podman containers, and
  OpenShift pods.
- FQDN-first endpoint representation via passive DNS snooping (IP-lists rot;
  names don't).
- Central proposal queue; **human ratification is always in the loop** — no
  auto-promotion of learned endpoints.
- Ratified specifications versioned in Git, with an `owner` field from day one.
- **Drift as signal:** a ratified workload contacting a non-ratified endpoint
  is a first-class detection event, not a log line.
- Declared behavioral **invariant signals** (process ancestry, raw sockets)
  emitted on the same stream.
- Structured JSON signal output designed for AI-agent consumption: every signal
  carries the specification reference it violated.

### 2.2 Non-Goals (PoC)

- **No enforcement.** No blocking, no `EPERM` verdicts, no admission control.
  Fail-open by design.
- **No NetworkPolicy / CiliumPolicy generation.** A possible consumer of the
  ratified spec later; not now.
- **No automated baseline promotion.** No multi-replica consensus algorithm, no
  asymptotic auto-cutover. The human is the consensus mechanism in v1.
- **No multi-team routing / ChatOps.** One central queue, one team. The data
  model carries `owner` so routing can be retrofitted without migration.
- **No L7 / operation-level policy** ("write only to namespaces you own").
  The layer that would have caught the breach's dead-drop C2 — and the hardest
  one. Acknowledged, deferred.
- **No SPIFFE/SPIRE.** Derived workload identity (§5) is sufficient for PoC.
- **No RHEL 8 / cgroup v1.** PoC targets cgroup v2 only (RHEL 9+).
- **No ingress policy.** Egress only.

### 2.3 Explicitly removed from the previous revision

| Removed | Why | Where it went |
|---|---|---|
| Federated ChatOps routing, 1-click GitOps PRs | Premature; single-queue PoC | Deferred (post-PoC) |
| Multi-replica consensus auto-promotion (≥80%) | Human ratification replaces it | Deferred |
| Asymptotic cutover automation | Replaced by human ratification gate; discovery-rate flattening kept as an observability metric only | Deferred as automation |
| NetworkPolicy/Cilium serializer | Enforcement-adjacent | Deferred |
| Automated containment via EDA/AAP | Advisory-only mandate | Deferred; signals are emitted for an agent to act on |
| Dirty-baseline silent rejects | Silently dropping suspicious observations hides exactly the signal we want | Converted to **risk annotations** (§11.2) |

---

## 3. Design Principles

1. **Workload identity, not node identity.** A specification is a property of
   the workload, not the machine. A node-global allowlist is blind to a
   compromised pod reusing its neighbors' endpoints — which is precisely the
   breach pattern (C2 to the platform's own API looks "known good" fleet-wide).
2. **Learned proposes, declared decides.** Empirically observed endpoints never
   authorize themselves. Static declarations (unit files, manifests, kickstart,
   resolv.conf) and human ratification are the only trust roots.
3. **Fail-open, always.** The system must never be able to break a workload.
   This keeps deployment friction near zero and makes the poisoning/blind-spot
   failure modes honest: worst case is a missing signal, never an outage.
4. **Two signal classes, never conflated.** *Declared invariants* (binary,
   unpoisonable, always-on) vs. *spec deviations* (only meaningful after
   ratification). Learned-but-unratified observations produce queue items, not
   alerts.
5. **Review the diff, not the firehose.** Every UI and aggregation decision
   optimizes for a short, grouped, pre-annotated review queue.

---

## 4. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│            TIER 4: RATIFICATION UI & SIGNAL EGRESS                      │
│  - Central review queue (single team; owner field carried)              │
│  - Grouped per-workload diff view: allow / deny                         │
│  - Structured signal stream (JSON) → AI agents / SOC / SIEM             │
└───────────────────────────────────────▲─────────────────────────────────┘
                                        │ Proposals in, decisions down
┌───────────────────────────────────────┴─────────────────────────────────┐
│            TIER 3: CENTRAL AGGREGATION & SPECIFICATION STORE            │
│  - Per-workload proposal builder (static-declaration intersection)      │
│  - Git-backed ratified-spec store (versioned, owner, signed)            │
│  - Drift detector: ratified workload + new endpoint → signal + re-queue │
└───────────────────────────────────────▲─────────────────────────────────┘
                                        │ Enriched, identity-resolved events
┌───────────────────────────────────────┴─────────────────────────────────┐
│            TIER 2: NODE-LOCAL IDENTITY & STATE ENGINE                   │
│  - Passive DNS snooper (IP↔FQDN cache, TTL-aware)                       │
│  - Identity resolvers: systemd unit / podman container / k8s pod        │
│  - Local decision cache (fail-open when central is down)                │
│  - Privilege isolation via bpfman; SELinux confinement                  │
└───────────────────────────────────────▲─────────────────────────────────┘
                                        │ In-kernel lookups; cache misses only
┌───────────────────────────────────────┴─────────────────────────────────┐
│            TIER 1: IN-KERNEL eBPF DATA & DEDUPLICATION PLANE            │
│  - Probes: cgroup/connect4+6, cgroup/sendmsg4+6, execve, raw sockets    │
│  - Deduplication: BPF_MAP_TYPE_LRU_HASH keyed on cgroup identity        │
│  - RingBuffer emission: net-new (cgroup, endpoint) tuples only          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Workload Identity Model

The premise "a standalone RHEL box has no workload identity" is wrong: systemd
has placed every service in its own cgroup since long before cgroup v2. The
cgroup is the universal identity substrate across all three target
environments — and it is what the Tier 1 eBPF hooks already key on.

Three layers:

| Layer | Where | Value | Lifetime |
|---|---|---|---|
| **Collection identity** | Kernel | `cgroup_id` (u64) | Ephemeral — changes on restart/reschedule. In-kernel dedup key only, never persisted as identity. |
| **Logical identity** | Node agent | Resolved from cgroup path at observation time | Stable for the instance's lifetime |
| **Fleet identity** | Central | Instance-agnostic `kind:name` | Stable across restarts, replicas, machines |

### 5.1 Environment mapping

| Environment | Cgroup path shape | Logical identity | Fleet identity | Declared-spec source |
|---|---|---|---|---|
| Bare metal / VM, systemd | `system.slice/httpd.service` | unit name | `systemd:httpd.service` | unit file, drop-ins |
| VM, podman container | `machine.slice/libpod-<id>.scope`, `user.slice/...` (rootless) | container ID → image + name | `podman:registry/img:tag` (or Quadlet unit name) | Quadlet file, `podman inspect` labels |
| OpenShift pod | `kubepods.slice/.../pod<uid>.slice/...` | pod UID → namespace + serviceaccount | `k8s:<ns>/<workload>` | Pod/Deployment manifest, existing NetworkPolicy |

500 identical RHEL web servers running `httpd.service` aggregate into one fleet
identity — this is what makes parallel, fleet-wide learning work on bare metal
exactly as it does for k8s replicas. Hostname/pod-UID is carried as an
**instance attribute** on events, never as part of the identity.

### 5.2 Edge cases

- **Interactive sessions** (`session-*.scope`) and cron jobs: discovered under
  a reserved `systemd:session` / `systemd:crond.service` class, excluded from
  the ratification queue by default to protect reviewer attention. Visible on
  demand.
- **Eager resolution:** a short-lived process can exit before its cgroup is
  resolvable. The node agent resolves cgroup path → logical identity **at first
  observation**, caches for the cgroup's lifetime.
- **Restarts:** new `cgroup_id`, same logical identity. Resolution happens on
  the node; the central store never sees raw cgroup IDs as identity.
- **SPIFFE/SPIRE** can later upgrade fleet identity to cryptographic
  attestation (including on hosts, via Unix/systemd attestation). Not PoC.

---

## 6. Data Model

### 6.1 Discovery event (node → central)

```json
{
  "fleet_identity": "systemd:httpd.service",
  "instance": "web-17.example.com",
  "endpoint": { "type": "fqdn", "value": "api.stripe.com",
                "ips": ["104.18.2.5"], "ttl": 300 },
  "port": 443, "protocol": "tcp",
  "process": { "path": "/usr/sbin/httpd", "pid": 1234,
               "parent": "/usr/lib/systemd/systemd" },
  "first_seen": "...", "last_seen": "...", "count": 412,
  "annotations": ["matches-static-declaration"]
}
```

Direct-IP endpoints use `"type": "ip"` with no FQDN association.

### 6.2 Proposal (central → reviewer)

Grouped by `(fleet_identity, endpoint, port, protocol)`. Carries: instance
count and spread, first/last seen, initiating process, static-declaration
match (pre-suggested allow), and **risk annotations** (§11.2).

### 6.3 Decision record (the ratified specification)

```json
{
  "fleet_identity": "systemd:httpd.service",
  "endpoint": { "type": "fqdn", "value": "api.stripe.com" },
  "port": 443, "protocol": "tcp",
  "decision": "allow",
  "owner": "team:payments",
  "decided_by": "j.west", "decided_at": "...",
  "source": "learned",
  "version": "git:9f3a2c1"
}
```

Git-backed, signed, versioned. `deny` decisions are first-class: in advisory
mode a *denied-and-observed* endpoint is the highest-severity signal the
system can produce.

### 6.4 Signal (central → AI agent / SOC consumers)

```json
{
  "type": "spec_deviation | invariant_violation | denied_endpoint_observed",
  "fleet_identity": "k8s:production/datasets-converter",
  "instance": "hf-worker-7d9f", "severity": "high",
  "endpoint": { "type": "fqdn", "value": "pastebin.example" },
  "spec_reference": "git:9f3a2c1#k8s:production/datasets-converter",
  "evidence": { "process": "...", "parent_chain": ["..."], "first_seen": "..." }
}
```

Every signal carries the specification it deviates from — the consumer never
has to guess what "normal" was.

---

## 7. Tier 1: In-Kernel eBPF Data Plane

Unchanged in principle from the previous revision; corrections noted.

### 7.1 Hook points

- `cgroup/connect4` & `cgroup/connect6`: TCP connection initiation.
- `cgroup/sendmsg4` & `cgroup/sendmsg6`: UDP/QUIC/DNS datagrams.
- `sched_process_exec` (`execve`): process lineage for invariant signals.
- `sys_enter_socket`: unprivileged `SOCK_RAW` / `AF_PACKET` creation.
- `sys_exit_connect` / `kfree_skb`: connection-refused/timeout telemetry
  (secondary reconnaissance signal). **IPv4 and IPv6 from day one.**

### 7.2 Deduplication

`BPF_MAP_TYPE_LRU_HASH` (max 32768) keyed on
`(cgroup_id, daddr, dport, protocol)` → timestamp. Fast path: key exists →
return 0, no emission. Slow path: insert, emit compact event to
`BPF_MAP_TYPE_RINGBUF`. `cgroup_id` is ephemeral and is used **only** as the
dedup key — identity resolution happens in Tier 2. LRU eviction under high
cardinality (many distinct destinations per cgroup) causes only a duplicate
emission of an already-seen tuple — never a dropped one — so map pressure
degrades to redundant events, not blind spots.

### 7.3 Performance

"Sub-1% CPU" is an **acceptance criterion with a benchmark** (M0), not a
claim. The LRU fast path makes it plausible at steady state; it must be
demonstrated under connection churn on a loaded node.

---

## 8. Tier 2: Node-Local Identity & State Engine

Unprivileged daemon per node (bpfman-managed):

- **Passive DNS snooper:** parses port-53 UDP/TCP responses; caches
  IP→FQDN with record TTL; resolves raw destination IPs at event time.
  *Known limitation:* DoH bypasses snooping — legitimate DoH clients appear as
  direct-to-IP and will surface as such in proposals. Accepted for PoC;
  documented, not hidden.
- **Identity resolvers (plugins):** systemd (cgroup path → unit), podman
  (`libpod-<id>` → image/name via podman socket), Kubernetes (pod UID →
  namespace/SA via API). Only per-environment code in the system.
- **Local decision cache:** ratified specs and recent decisions cached on
  node; discovery continues when central is down (bounded buffer, flush on
  reconnect). Central is a convenience, never a dependency.
- **Privilege isolation:** no `CAP_BPF`/`CAP_SYS_ADMIN` on the daemon; map and
  probe operations brokered by bpfman over authenticated local gRPC. Pinned
  maps get a dedicated SELinux type (`ebpf_map_t`); compromised containers
  cannot write them.

---

## 9. Tier 3: Central Aggregation & Specification Store

- **Ingestion API** (mTLS, per-node credentials), idempotent event dedup.
- **Proposal builder:** aggregates discovery events by fleet identity;
  intersects with **static declarations** (unit files, manifests, kickstart
  network config, existing NetworkPolicies) so obvious infrastructure arrives
  pre-marked "suggested: allow." The reviewer sees a diff, not a firehose.
- **Specification store:** Git-backed decision records (§6.3). Every ratified
  spec is versioned, signed, attributable.
- **Drift detector:** for a workload whose spec is ratified, any net-new
  endpoint → `spec_deviation` signal **and** re-entry into the review queue.
  This re-entrant property is the detection engine: ratification is not
  onboarding, it is the permanent baseline.

**Removed:** multi-replica consensus auto-promotion and asymptotic cutover
automation. Discovery-rate flattening per workload remains as a dashboard
*metric* (a hint that a spec is converging), never as a trigger.

---

## 10. Tier 4: Ratification UI & Signal Egress

- **Single central queue**, one reviewing team for the PoC. `owner` field
  populated from namespace annotations / unit metadata where available, so
  per-team routing can be layered on later without data migration.
- **Grouped diff view:** per workload — what it talks to, what's covered by
  static declaration, what's new, what carries risk annotations. Allow/deny
  per line; bulk-accept static matches.
- **Signal stream:** structured JSON (§6.4) over webhook/file/gRPC, designed
  for AI-agent consumers: binary semantics, full causal context, spec
  reference included. No automated remediation is triggered by the platform
  itself in PoC.

---

## 11. Bootstrapping Workflow

1. **Stage 0 — Seed:** curated infrastructure endpoints (DNS, Kerberos/LDAP,
   NTP, package mirrors, logging/metrics collectors) from static sources;
   reviewed once, up front. Seeds are global; application endpoints are never
   global.
2. **Stage 1 — Discovery:** sensors live everywhere in parallel (not
   sequential — sequential inheritance is error propagation). All observations
   become proposals. Nothing pages anyone.
3. **Stage 2 — Ratification:** humans review the grouped diff. Static matches
   pre-suggested; risk-annotated items highlighted. Decisions land in Git.
4. **Stage 3 — Live specification:** drift on ratified workloads = signal.
   Denied-and-observed = high-severity signal. New workload onboarded → back
   to Stage 1 for that workload only.

### 11.2 Risk annotations (formerly "dirty-baseline rejects")

The previous revision silently *rejected* suspicious observations from
baselining. With a human in the loop that is exactly backwards: suspicious
observations are the ones the reviewer most needs to see. Filters become
**annotations** that raise prominence instead:

- `direct-to-ip` — no preceding DNS association observed.
- `newly-registered-domain` — domain < 30 days old.
- `shell-initiated` — endpoint first observed from `/bin/sh`, `bash`, or an
  interactive interpreter lineage.
- `infrastructure-mismatch` — endpoint plausibly infra but absent from seed.

*Honest limitation:* the direct-to-IP check is trivially satisfied by an
attacker who resolves their own domain first, and the breach's actual C2 used
legitimate, DNS-resolved SaaS. Annotations aid the reviewer; they are not a
poisoning defense. The poisoning defense is the human gate plus static
intersection — and the honesty that a patient attacker active during discovery
can still land endpoints in a ratified spec. Residual risk, stated.

---

## 12. Signal Classification

| Class | Basis | When it fires | Confidence |
|---|---|---|---|
| `invariant_violation` | **Declared** platform invariants | Always-on, no ratification needed | Binary, high |
| `spec_deviation` | **Ratified** workload spec | Only after ratification | Binary, high |
| `denied_endpoint_observed` | **Denied** decision observed in traffic | Always-on | Highest available pre-enforcement |
| discovery | Unratified observation | Never a signal — queue item only | — |

Declared invariants (PoC set):

1. **Process ancestry:** non-interactive service runtime (java, node, python,
   httpd…) spawning interactive shells, network tools, or executing from
   writable paths (`/tmp`, `/dev/shm`, memfd). Catches the breach's Phase 3b
   child shell.
2. **Raw/packet socket creation** by unprivileged workloads.
3. **Direct-to-IP public egress without DNS association** — *with the stated
   limitation that it does not catch C2 over legitimate, resolved services.
   That is what the ratified specification exists for.*

---

## 13. Failure Modes & Known Limitations

- **Central store down:** nodes run on cached decisions; discovery events
  buffered (bounded) and flushed on reconnect. No signal loss beyond buffer
  capacity; never any traffic impact.
- **Node agent down:** no telemetry from that node. Detectable via fleet
  heartbeat; alerting on agent absence is a dashboard function.
- **DoH:** bypasses DNS snooping → direct-to-IP proposals for legitimate
  software. Accepted PoC noise.
- **Poisoning:** human ratification + static intersection mitigate; a patient
  attacker inside the discovery window can still achieve a ratified endpoint.
  Residual risk accepted and documented.
- **Ratified direct-IP endpoints can go stale silently:** a `type: ip` decision
  record has no re-validation mechanism, unlike FQDN endpoints. If the address
  is later reassigned (common in cloud/CDN ranges), the ratified allow may now
  cover an unrelated destination with no drift signal, since traffic still
  matches the existing record. Post-PoC mitigation: periodic re-check on
  ratified IP-type decisions, or a review TTL that forces them back into the
  queue after N days.
- **cgroup races / ID reuse:** eager resolution at first observation; short
  grace window for PID reuse.
- **Advisory-only:** the system detects; it cannot stop anything. That is a
  commitment, not a gap.

---

## 14. Security of the System Itself

- bpfman-brokered privilege separation (no `CAP_BPF`/`CAP_SYS_ADMIN` on the
  daemon).
- SELinux type confinement for pinned BPF maps (`ebpf_map_t`).
- mTLS node→central with per-node credentials.
- Signed, Git-versioned decision records — the specification store is
  auditable and revertible.
- Dashboard authN/Z; decisions attributable (`decided_by`).

---

## 15. Platform Requirements

- RHEL 9+ (kernel ≥ 5.14, **cgroup v2**, BTF for CO-RE), podman 4+.
- OpenShift 4.x on RHEL 9 nodes for the k8s environment.
- bpfman for probe/map lifecycle.
- RHEL 8 / cgroup v1: explicit non-goal.

---

## 16. Delivery Approach

Milestone-based; full story-level backlog in `backlog.md`.

- **M0 — Kernel sensor spike:** Tier 1 hooks + LRU dedup on a RHEL 9 VM;
  prove the <1% CPU budget under churn.
- **M1 — Node agent:** DNS snooper, systemd + podman identity resolvers,
  local cache, mTLS upload.
- **M2 — Central store + ratification dashboard (the demo):** proposals,
  Git-backed decisions with `owner`, drift re-entry, signal stream. Demo:
  ratify a workload, then have it touch a new endpoint → `spec_deviation`
  signal + queue re-entry; plus a process-ancestry invariant firing.
- **M3 — OpenShift coverage:** k8s identity resolver, DaemonSet packaging,
  invariant signals hardened across environments.

**Post-PoC parking lot:** eBPF verdict enforcement, NetworkPolicy/Cilium
export, multi-replica consensus automation, asymptotic completeness metrics,
owner-routed ChatOps review, SPIFFE identity, L7 operation-level specs,
RHEL 8 / cgroup v1, ingress.
