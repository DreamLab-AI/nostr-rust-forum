---
id: ADR-2009
title: Coerce every `.acl`/`.meta` sidecar access to `Control` via the shared upstream policy, reads and writes alike
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: 7795af5
owner: jjohare
review_trigger: a requirement to expose sidecar read visibility, or to add `acl:origin`-gated rules
repo: nostr-rust-forum
domain: BASELINE-architecture.md
lineage: distils legacy ADR-096 (ACL container resolution & delegation) and Sprint v9 STREAM-B B3 / audit P2-1
---

# ADR-2009 — Coerce every `.acl`/`.meta` sidecar access to `Control` via the shared upstream policy, reads and writes alike

## Context

A `.acl`/`.meta` sidecar governs another resource's authorization graph. If it is treated
as an ordinary resource, an `acl:Write` holder can seize control by overwriting it, and an
`acl:Read` holder can read the authorization graph (audit finding P2-1). The naive
HTTP-method→mode mapping (`GET`→Read, `PUT`→Write) leaves both holes open.

## Decision

Any request whose target is a sidecar path collapses to `AccessMode::Control` — **reads and
writes elevate identically** — and this detection is not re-derived locally: it funnels
through the single shared policy `effective_acl_target` re-exported from
`solid_pod_rs::wac`, co-owned with the solid-pod-rs native server, so the forum's
`coerce_required_mode_for_acl` and the pod-worker's `.acl` handler cannot drift from
upstream or from each other. Per-container delegation is built structurally by
`build_delegation_acl` so the owner is never coerced out, and the kit caps ACL JSON-LD at
64 KiB (stricter than upstream's 1 MiB).

## Consequences

- Forecloses per-mode sidecar access: you cannot grant read-only visibility into an
  authorization graph — any sidecar touch demands `Control` (Invariant: sidecar access
  coerces to Control; never widen it).
- The elevation decision is deliberately not owned locally; a future `acl:origin`-gated rule
  set must switch callers to `evaluate_access` directly rather than patch the coercion.
- Stricter-than-upstream doc cap means a large hand-authored ACL that upstream would accept
  is rejected here — an intentional divergence, not a bug.

## Verification

- Sidecar coercion delegates to the shared policy: `crates/nostr-bbs-pod-worker/src/acl.rs:85-90`;
  shared re-export and single-funnel rationale: `acl.rs:27-35`.
- Stricter 64 KiB cap vs upstream 1 MiB: `acl.rs:8-13`.
- Owner-preserving structural delegation: `acl.rs:14-17`.
- Established at `verified_commit` 7795af5 (`git rev-parse --short HEAD`).

## Closeout extension — 2026-09-04

Work packages: CP-04/08. Accountable owner: the existing owner above, with forum release/identity maintainers for cross-service acceptance. Historical verification and activation declarations are preserved; this review does not re-certify a live deployment.

Source funnels sidecar coercion through the pinned upstream helper. Sharing a function does not make deployed versions or surrounding resolver/cache policies equal.

**Acceptance condition:** Verify reads and writes of sidecars across path normalisation, malformed/missing policy, delegation, private caches and both deployment tiers. Record the exact consumed helper revision and preserve the intentional 64 KiB limit.

Dependencies: CP-01 release identity and the relevant identity, governance and recovery journeys. Reopen when the governed source, dependency, deployment profile or consumer contract changes. See the [estate forum review](../../../VisionFlow/docs/estate-review/forum-decisions.md) and [current source/test receipt](../../../VisionFlow/docs/estate-review/evidence/forum-closeout-snapshot.json).
# Shared resolver adoption — 2026-11-03

The pod Worker now consumes Solid's `classify_policy_read` contract for every R2/KV ACL read. Confirmed absence alone permits inheritance. Invalid or unavailable policy settles as denial; a malformed restrictive sidecar cannot expose a parent grant. The kit retains its stricter 64 KiB cap. This implements the resolution boundary and does not alter the sidecar-to-Control decision. See [repair evidence](../audit/external-fixes-2026-11-03.md). Deployment and consumer activation remain separate checks.
