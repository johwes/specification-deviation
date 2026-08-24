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

## Status

Design phase complete. Implementation starts at M0 (kernel sensor spike) per
`docs/backlog.md`.
