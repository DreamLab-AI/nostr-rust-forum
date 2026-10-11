---
id: ADR-2001
title: Consolidate the ADR corpus into living ground-truth docs plus a thin ledger
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: 23be587
owner: nostr-rust-forum maintainers (dreamlab AI)
review_trigger: next material change to crate topology, key model, or pod mesh
repo: nostr-rust-forum
---

# ADR-2001 — Consolidate the ADR corpus into living ground-truth docs plus a thin ledger

## Context

The repository carried 24 legacy ADRs (086–109) authored 2026-05 to 2026-07. They
had drifted from the code: legacy upstream ADR-076 records the upstream `nostr`
absorption as merely *Proposed* while `Cargo.toml` already depends on
`nostr = "0.44.7"` with NIP flags and a build canary exists; the kit version
narrative cited `1.0.0-beta.3` against an in-tree `1.0.0-beta.9`; the ADR-109 index
entry lagged the shipped ADR; ADR-105's stated write-path decision diverged from the
shipped in-client signer. The corpus mixed durable policy with point-in-time
narrative, and no single doc stated current ground truth.

## Decision

Ground truth moves to two living governing documents at the repo docs root —
`docs/BASELINE-architecture.md` and `docs/IDENTITY-keys-and-trust.md` — each with
present-tense current state, `file:line` citations, explicit invariants, and a
change process. The legacy corpus (086–109) is frozen and moved to
`docs/archive/adr/` under a do-not-edit tombstone. New decisions are recorded here
in `docs/adr/` as thin, three-axis-status ledger records copied from
`TEMPLATE.md`, each amending a living doc in the same change. `PREAMBLE.md` carries
the routing prose; `scripts/adr-index-gen.js` validates frontmatter and regenerates
the index. The archive is history only, never authority.

## Consequences

- One lookup order for every agent: living doc → its code citations → this ledger →
  archive (history only).
- Legacy ADR numbers remain resolvable via the archive tombstone's mapping table.
- Sprint-resident ADRs 090/091/092 keep their canonical full text under
  `docs/sprint/2026-05-17-ux-audit/`; only the `docs/adr/` stubs were archived.
- New cost: every code change touching a governed area must update the living doc's
  `file:line` and re-record `verified_commit` in the same change.

## Verification

- Archive cut: `git mv` of 24 `ADR-086..109` files plus the legacy index into
  `docs/archive/adr/`; new `docs/adr/` contains only `TEMPLATE.md`, `PREAMBLE.md`,
  this record, and the generated `README.md`.
- Living docs authored against code at `verified_commit` 23be587
  (`git rev-parse --short HEAD`).
- Index generator run clean: `node scripts/adr-index-gen.js docs/adr` exits 0.

## Closeout extension — 2026-09-04

Work packages: CP-01/08. Accountable owner: the existing owner above, with forum release/identity maintainers for cross-service acceptance. Historical verification and activation declarations are preserved; this review does not re-certify a live deployment.

The operative ledger and frozen archive remain distinct. A generated index checks record structure; it cannot certify current implementation or deployment.

**Acceptance condition:** Keep all 24 archived entries and the three sprint canonical documents resolvable through their lineage. Bind each operative claim to source/build/deployment identity and a scoped receipt; amend both governing documents with their ledger records.

Dependencies: CP-01 release identity and the relevant identity, governance and recovery journeys. Reopen when the governed source, dependency, deployment profile or consumer contract changes. See the [estate forum review](../../../VisionFlow/docs/estate-review/forum-decisions.md) and [current source/test receipt](../../../VisionFlow/docs/estate-review/evidence/forum-closeout-snapshot.json).
