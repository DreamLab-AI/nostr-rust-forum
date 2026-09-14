---
id: ADR-2011
title: Operator-declared task properties set the escalation boundary, not the requesting agent's self-tier
date: 2026-09-14
decision_status: accepted
implementation_status: partial
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: PLACEHOLDER_SHA
owner: jjohare
review_trigger: nostr-bbs-core publishing TaskProperties to crates.io, or a probe-blindness scheme that survives raw-event inspection
repo: nostr-rust-forum
---

# ADR-2011 — Operator-declared task properties set the escalation boundary, not the requesting agent's self-tier

## Context

A 31402 `ActionRequest` carried one boundary signal, `risk_tier`, declared by the requesting agent, with the doc comment "the agent's declaration stands". No relay or human path re-tiered it. The relay advertised `ESCALATION_DEFAULT_TIER=medium` and `ESCALATION_DEFAULT_POSTURE=escalate_to_human` in NIP-11 (`wrangler.toml:48-49`) and enforced neither. The party with the strongest incentive to under-tier was the only party that tiered. arXiv 2609.12482 sets the human–agent boundary by three properties of the *task* — verifiability, reversibility, stakes — not by the actor's self-assessment. This ADR is the forum's implementation of canon [VisionFlow ADR-2011](https://github.com/DreamLab-AI/VisionFlow) and the FR3/FR4/FR6/FR7 substrate work of PRD-augmentation-conditions. It builds on [ADR-2010](ADR-2010-durable-governance-outcome-receipts.md), whose receipt ladder it extends past `projection-committed`.

## Decision

1. **`nostr-bbs-core` owns the triple.** `TaskProperties { verifiability: Inspectable|Partial|Opaque, reversibility: Reversible|Compensable|Irreversible, stakes: Bounded|Significant|Critical }`, carried as tags `tp-verifiability` / `tp-reversibility` / `tp-stakes` on a 31400 `PanelDefinition` (the operator's declaration) and optionally on a 31402 (the agent's restatement). `TaskProperties::merge` is a per-axis `max` over enums whose declaration order **is** the tightness order, so "a request may tighten but never loosen" is structural rather than a rule that has to be remembered.
2. **`effective_tier(panel_props, request_props, declared, advertised_default)` is pure and total.** `Irreversible` reversibility or `Critical` stakes floors the case at `High`; `Opaque` verifiability floors it at `Medium` and forbids member suppression outright; a request that declares nothing at all folds to the relay's advertised default rather than to an accidental `Medium`. `risk_tier` survives as the agent's declaration for telemetry and carries no authority alone.
3. **The relay computes the boundary once and stores it.** `project_action_request` resolves the request's panel, computes the tier, and writes `broker_cases.effective_tier` together with the merged triple and the declared tier. Every consumer reads that column; there is nowhere else to look for a suppression or routing decision.
4. **A high or critical case is resolved only by a human.** `plan_action_response` refuses a 31403 whose `decided_by` names a `system:` actor when the case's effective tier is `High` or `Critical`.
5. **The receipt ladder extends past projection.** `ReceiptStage` moves into `nostr-bbs-core` and gains `consumer-received`, `applied`, `not-applied`, `applied-manually`, plus `escalated-on-age` and `expired` as side receipts that never advance the ladder. `can_advance_stage` enforces monotonicity; `applied-manually` is exempt from the `consumer-received` precondition because the outage path it serves has no consumer by construction.
6. **Delegation is scoped, sampling is deterministic, probes are withheld.** A `reviewer`-role pubkey decides exactly the cases an admin `Delegate`d to it, via a `case_delegations` row. A panel's `calibration-sample-rate` (default 0.1) selects otherwise-suppressible cases by `sha256(request_id)` and never by the clock. A `probe` tag is honoured only from the panel's registered probe agent, is kept out of `event_tags` so no client can enumerate probes by subscription, and is withheld from every REST projection of an undecided case.

## Consequences

- The relay gains a small amount of policy — one pure function and one default — which this ADR records as required by ADR-2006 (canon owns the cross-repo view, substrates own implementation). The schema stays owned by `nostr-bbs-core`.
- Legacy panels and requests keep working: absent `tp-*` tags parse to `None` (distinct from a declared-loosest triple), and a case projected before migration 0006 has no effective tier and is not retro-gated on one.
- Operators must now declare the triple when publishing a panel to get any benefit from it. A panel that declares nothing behaves as before except that its unlabelled requests fold to the advertised default rather than to `medium` by accident.
- Agents that habitually under-tier become measurable: declared-versus-effective divergence is now two columns on the same row.
- **Probe blindness is partial, and this is the reason `implementation_status` is `partial`.** The `probe` tag is removed from the tag index and never re-served in the D1 projection of an undecided case, so no client can query for probes and no governance API response reveals one. The tag nevertheless remains on the raw signed 31402 served over REQ, because removing it would invalidate the signature that both clients verify strictly (`verify_event_strict`) and the probe would vanish entirely rather than render blind. A scheme that survives raw-event inspection — committing to the probe out of band, or encrypting the marker to the relay — is follow-on work and is this ADR's `review_trigger`.
- `reviewer` became a privilege-granting role, which made the pre-existing stale-privilege defect in role revocation material; role grant/revoke now normalise pubkey casing and a revocation that matched no row returns 404 instead of reporting success.

## Verification

Established at `verified_commit` by executed commands, recorded with raw output in `.claude/evidence/EXP-AC-003.evidence.md`, `EXP-AC-004.evidence.md`, `EXP-AC-006.evidence.md` and `EXP-AC-007.evidence.md`:

- `cargo test -p nostr-bbs-core --lib governance::task_property_tests` — the 729-pair exhaustive tightening-only property and the effective-tier table over the whole triple space crossed with every declared tier.
- `cargo test -p nostr-bbs-core --lib governance::calibration_tests governance::receipt_stage_tests` — the deterministic sampling band (80..=120 of 1,000 at rate 0.1) and every stage pair checked for regression.
- `cargo test -p nostr-bbs-relay-worker --lib augmentation_boundary_tests ageing` — panel-tightened projection, advertised-default folding, delegation admission, the human-resolution guard, and the ageing predicate and its deadline ordering.
- `cargo test -p nostr-bbs-auth-worker --lib augmentation_api_tests` — application-stage authority (including the case-ownership bind), the manual-continuation precondition, monotonicity and its 409s, probe redaction, and the reviewer read model.
- `cargo test --workspace --exclude nostr-bbs-forum-client` — whole-workspace regression.
- `scripts/deepsec-gate.sh --diff main` — security gate; receipt path recorded in the evidence.

`activation_status` stays `inactive`: nothing here has been deployed and `nostr-bbs-core` 1.0.0-beta.11 has not been published. It moves to `staged` on publication and to `live` on edge deploy with the probe suite run (PRD milestone M4).
