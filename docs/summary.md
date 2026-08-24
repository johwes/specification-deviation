# Specification Deviation — Discussion Summary

*Context: the July 2026 OpenAI / Hugging Face breach. Source documents:
`openshift-defaults-breach-analysis.md` and `specification-deviation-brief.md`
(written in isolation, not as a pair). This file captures the conclusions of the
discussion for continuation.*

## Starting point

- Organizations with billions in budget (OpenAI, HF) failed to build secure
  environments. The failure modes were ordinary — default auth models, no egress
  policy, a shared 136-credential Secret, long-lived signing keys. Only the
  orchestration was novel.
- Detecting ongoing AI-driven cyber offense is hard: nothing the agent did was
  *known-bad* — valid API calls, stolen-but-valid credentials, legitimate platform
  features. Signature detection is blind by construction; statistical detection is
  gameable by an attacker iterating at machine speed.
- One viable primitive: declare what software is supposed to do (a specification),
  detect deviation.

## Conclusions

### 1. The decisive variable was structural, not configurational
- OpenShift's X.509 node authentication (vs. EKS `aws-iam-authenticator`) breaks
  the escalation chain architecturally — it cannot be misconfigured away.
- But the analysis evaluates one chain, not the agent. Defaults raise the floor;
  they don't cap the ceiling against iteration.
- And the mission likely still succeeds: the objective (ExploitGym answers) was
  reachable via legitimate application credentials + unrestricted egress. Defaults
  protect the infrastructure — not the application from its own credentials.

### 2. Both documents converge on the same missing primitive
- Nobody knows, in machine-readable form, what any workload is supposed to do.
  Declared intent exists nowhere in the stack except by accident.
- The analysis's biggest gap (no default egress NetworkPolicy) and the brief's
  biggest gap (no specification-generation tooling) are the same hole, seen from
  two sides.

### 3. Specification-deviation is the same primitive on both sides of the fight — asymmetrically
- **Agent confinement** (greenfield): deny-by-default is cheap, specs can be
  complete. But only cooperative operators confine their agents. The breach failed
  at this easy direction: the sandbox spec permitted the Artifactory proxy, whose
  own spec was not enforced → **specifications are fractal**: an envelope is only
  as strong as the specs of what it permits.
- **Workload defense** (brownfield): specs must be derived, false positives matter.
  This is the load-bearing side — real offensive actors will not confine their agents.
- Independence: signature detection depends on attacker *history*; anomaly detection
  on attacker *behavior*; specification-deviation on the defender's *own declared
  intent* — independent of attacker knowledge **and** cooperation.

### 4. The specification generation problem
- Sources: declared artifacts (IaC, schemas, unit files — bound from above);
  empirical eBPF profiling (bound from below; caveats: coverage, poisoning during
  profiling); static analysis (weak against dynamic evaluation — exactly what the
  breach exploited); LLM drafting + human review (what changed since 1997).
- A spec is a claim about *intent*; intent lives with humans. Machines draft and
  observe; humans ratify. The tooling's job is making review cheap.
- Specs die by drift → generation must run continuously in CI/CD, versioned with
  the artifact it describes.
- SELinux precedent: authored policy + `audit2allow` + review, run over a decade.
  The bet: AI compresses the loop to a release cycle.
- Open question: intent is split three ways (platform vendor / app developer /
  deployer) — the organizational gap underneath the technical one.

### 5. Egress as the worked example
- **L3/L4 tuples** (NetworkPolicy): generatable today; would have caught the
  initial outbound connection, IMDS access, pastebin exfil, Tailscale handshakes.
- **Identity-level** (SPIFFE): kills lookalike-service C2.
- **L7 operation-level**: the only layer catching C2 hidden inside legitimate API
  access (the HF dead-drops) — expensive; an application-semantics problem.
- Coverage vs. effort: favorable at the start, steep at the end.

### 6. Silent knocking — the detection reframe
- ~17,600 recovered attacker actions; most failed. Failure is free *if silent* —
  silence is what makes iteration free.
- Enforcement points fire on *attempts*, not outcomes (AVC denial, admission
  rejection, 401, NetworkPolicy drop). On EKS the impersonation knock succeeded
  quietly; on OpenShift it fails loudly with a 401.
- If attempts are loud, the cliché inverts: thousands of actions = thousands of
  independent draws; detection probability compounds in the defender's favor. The
  tragedy of the breach: the compounding never started — the first enforceable
  boundaries were deep and write-only.
- Program: **de-silence the knocking.** Candidate platform metric: what fraction
  of the actions an attacker must take are guaranteed to make noise?

### 7. Epistemic caveat
- The public record is biased toward successful, disclosable steps; the agent's
  full knock-graph is unknowable (logs were recovered partly due to poor attacker
  OPSEC). Doctrine built on the published chain optimizes for open doors. Assume
  the visible chain is a minority of the activity — force the invisible majority
  across enforced, surfaced boundaries.

## Existing proof point

The [`autonomous-threat-response`](https://github.com/johwes/autonomous-threat-response)
demo implements a complete defensive loop against the Copy Fail LPE:

`Falco runtime signal → structured investigation → classification → deterministic
AAP remediation → incident report`

Its key signal is a RHEL process-ancestry invariant: a root shell directly spawned
by a user shell is outside the expected `su`/`sudo` elevation path. The demo is
valuable because it shows that a semantic behavioral signal can trigger an
autonomous response while conventional file-integrity, RPM, antivirus, and SELinux
checks all appear clean. The response path is deliberately constrained: the LLM
classifies and summarizes, while Python invokes pre-approved AAP playbooks.

The current limitation is also the next research step: the invariant and Falco
rules are manually authored. The demo proves the signal-to-action loop; it does
not yet prove automatic specification generation. The egress work would extend
the same architecture from one manually specified host invariant to generated,
reviewed, versioned workload specifications whose violations become signals.

## Related work — the egress / network policy generation landscape

The problem is studied under "microsegmentation policy generation" and "zero-trust
segmentation" — mostly at L3/L4, not at the layers that mattered in the breach.

**Academic**
- ZTS (Microsoft Research, NSDI 2025) — role inference from flow logs + domain
  knowledge + owner feedback; iterative human review loop; measures policy
  violation rate days after training (spec drift, measured).
- Ma et al. (IEEE 2023) — hybrid static (source/config) + dynamic (flow
  clustering); threat model *assumes no malicious traffic during learning* —
  the poisoning caveat acknowledged, then assumed away.
- ZT-SDN (Katsis & Bertino 2024); lineage: unsupervised enterprise
  micro-segmentation (2020), Synaptic (NOMS'18), AUTOARMOR.

**Sibling literature: seccomp/syscall policy generation** (one step more mature;
lessons transfer directly)
- sysfilter (RAID 2020), Confine (RAID 2020 / COSE 2023), Chestnut (CCSW 2021).
- Consensus: dynamic/training underapproximates (breakage in prod); static
  overapproximates (includes reachable-but-dangerous behavior — the Jinja2-loader
  problem); hybrid two-phase is the accepted answer.

**Tooling — productized as features, not as a toolchain**
- Inspektor Gadget `advise network-policy` (eBPF → NetworkPolicy/CiliumNetworkPolicy
  YAML). Project's own EPIC #373: generated policies are hard for humans to
  understand — the *ratification artifact* is the unsolved part.
- RHACS already ships both halves: runtime generation from observed eBPF flows
  (with simulation mode) and build-time `roxctl netpol generate` from manifests
  (via NP-Guard, IBM Research) + `connectivity diff` for drift.
- Calico (staged/audit policies), Cilium (FQDN/DNS-aware egress — the standard
  patch for CDN IP-churn), KubeArmor/AccuKnox, NeuVector; commercial: Illumio,
  Guardicore, Cisco Secure Workload.

**What is missing (the opportunity)**
1. Everything is L3/L4 tuples. Generation of L7/operation-level policy ("write
   only to namespaces you own") — the layer that would have caught the dead-drop
   C2 — is essentially unstudied. Istio/Cedar/OPA can enforce it; nothing
   generates it.
2. Egress-to-internet specifically is under-covered vs. east-west segmentation.
3. Nobody has made "a spec a human can ratify in five minutes" the design goal.
4. Poisoning is assumed away, not addressed.

## Open threads / candidate directions

- **Knock-density audit**: map platform defaults → which attacker actions generate
  surfaced signal vs. silent success/failure.
- **Egress spec generation PoC** — reframed after related-work review: the novelty
  is *not* "generate NetworkPolicy from flows" (exists in five places) but the
  lifecycle: intersect static manifests (roxctl/NP-Guard style) with observed
  flows (Gadget/RHACS style), render the result as a human-ratifiable document
  (LLM-assisted), version it in CI/CD, and run enforced-but-audited mode so
  violations become the knock-surfacing signal. Nobody owns that loop end-to-end.
- **The intent three-way split**: who ratifies specifications for third-party
  software?
