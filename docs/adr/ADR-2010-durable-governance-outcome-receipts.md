---
id: ADR-2010
title: Track governance decisions through durable projection and application receipts
date: 2026-09-04
decision_status: proposed
implementation_status: partial
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: a5b809e
owner: nostr-rust-forum maintainers (DreamLab AI)
review_trigger: adoption of the receipt contract or changes to projection, retention, authority consumers or signing UI
repo: nostr-rust-forum
domain: BASELINE-architecture.md
lineage: extends the historical governance intent in archived ADR-106; no retrospective ratification or supersession of the frozen record
---

# ADR-2010 — Track governance decisions through durable projection and application receipts

## Context

The client waits for relay OK before showing `Response sent`. The relay saves and broadcasts the event before projecting its decision into case tables. Projection and downstream agent application are separate operations; failures can leave a signed response accepted without its intended effect. Existing signature and domain-transition checks are necessary but do not establish delivery of that effect. The current source/test evidence is recorded in the [estate forum review](../../../VisionFlow/docs/estate-review/forum-decisions.md).

## Proposed decision

Track a response through distinct states: **signed → relay-accepted → projection-committed → consumer-received → applied or rejected**. An acknowledgement certifies only its own stage. Timeouts and interrupted delivery remain pending or failed with a recovery path; they must never imply approval or successful mutation. This contract is proposed, not an assertion that the stages are implemented.

Bind every receipt to the full signed event ID, request event ID, case ID, signer, decision outcome, target operation/version and relevant predecessor or supersession. Consumers independently verify authority and correlation before acting. A forum badge or relay OK cannot replace that check. Unknown requests remain unresolved until correlated; the ordinary planner's current missing-case fallback is not sufficient evidence of a valid request.

Persist the accepted envelope and projection atomically where their storage boundary permits it, or retain a durable replay record with idempotent reconciliation. Retrying the same signed event must not duplicate the mutation. Preserve verifiable signed decision history even when the relay replaces older events. Propagate supersession and appeal explicitly: reopening a case does not automatically undo a previously applied operation.

The UI must show the stage reached, collect substantive rationale where the decision requires it, prevent conflicting in-flight actions on the same request, and expose retry after lost acknowledgement or signer cancellation. The downstream operator must be able to distinguish a denied action from an approved action whose write failed.

## Consequences

Forum and agentbox maintainers must agree a versioned receipt contract and retention policy. The forum owns accepted-event persistence and projection; the authority consumer owns independent verification and delivery; the mutation owner supplies the applied/rejected receipt. Assigning these responsibilities does not imply that named owners have accepted a delivery date.

End-to-end atomicity across relay and mutation storage is not assumed. Recovery requires durable correlation, idempotency and operator-visible reconciliation. The existing human review and signature boundaries remain prerequisites for every transition.

## Verification and current gaps

At the recorded source revision, `handle_event` in `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` sends OK and broadcasts after `save_event`, then calls `project_action_response`. That projection inserts a decision and updates the case separately. The existing 47 passing core governance tests establish local domain rules; they do not execute D1, browser signing or the downstream mutation. The partial implementation status reflects existing component paths; inactive refers to this proposed complete receipt contract, not the historical forum deployment.

## Closeout extension — 2026-09-04

Work packages: CP-04/05/08/09. Dependencies: CP-01 revision identity, trusted authority configuration, storage recovery and the actual mutation receipt. Accountable roles: forum maintainers with agentbox authority and mutation maintainers. Reopen on protocol, retention, authentication, projection or consumer changes.

**Acceptance condition:** demonstrate one complete signed request/response/application journey and retain the correlated receipts. Inject failure after event persistence, before projection completion, after mutation but before acknowledgement, and during reconnect. Replay duplicates, early responses, unknown requests, revoked signers, conflicting responses, supersession and appeal. Verify restart recovery, retained signed history and visible terminal outcomes without duplicate writes or false success. Browser checks must include rationale, signer cancellation and acknowledgement timeout. Use isolated fixtures before any authorised live exercise.

The [source receipt](../../../VisionFlow/docs/estate-review/evidence/forum-snapshot.json) and [current revalidation](../../../VisionFlow/docs/estate-review/evidence/forum-governance-closeout.json) establish the assessment scope. No production receipt journey has been certified by this documentation change.

## History consumer closeout extension — 2026-09-05

The [decision-history review](../../../VisionFlow/docs/estate-review/decision-history.md) traces the authenticated D1 read API separately from relay-derived UI history. CP-04/05/08/09 must ratify cross-case read authority, provide stable complete traversal, retain exact decision-time request context and distinguish observed/current from projected/applied outcomes. Generated UI reasoning does not capture substantive human rationale. Six source hashes support this extension; no live request, D1 or browser acceptance ran.

## Disclosure closeout extension — 2026-09-05

The [disclosure review](../../../VisionFlow/docs/estate-review/agent-disclosure.md) establishes a public minimal registry and sixteen badge mounts. CP-04/06/09 must distinguish current registration from historical authorship and action-specific authority. One-shot fetch failures hide badges, while revocation removes old authors from fresh active-only results. Require explicit freshness/error states and event-time principal provenance; no badge or registrar label substitutes for the scoped receipt contract above. Source-only review; rendered coverage remains open.

## Acceptance progress — 2026-09-05

**Implemented (relay stages only).** `crates/nostr-bbs-relay-worker/src/relay_do/receipts.rs` adds a durable,
per-event receipt. A new `governance_receipts` table (migration `0005_governance_receipts.sql`, also in the
idempotent `ensure_schema` bootstrap) is keyed by the **full 64-hex signed event id** — never the truncated
`decision_id`, which is a projection key, not an identity — and carries the whole correlation set this ADR
requires: request event id, case id, signer, decision outcome, target operation, supersession, decision id,
and `signed_at` / `accepted_at` / `projected_at` / `replays`.

Stages are `signed → relay-accepted → projection-committed`, with `projection-failed` as the error state.
Each certifies only itself: `relay-accepted` says the relay durably holds the envelope, which is exactly what
the NIP-01 `OK` means and no more. `ReceiptStage::is_applied()` is true for `projection-committed` alone, so
the downstream distinction this ADR turns on — a denied action versus an approved action whose write failed —
is a first-class value rather than an inference.

The projection is now genuinely atomic. `broker_decisions` `INSERT`, `broker_cases` `UPDATE` and the
receipt's stage transition go out as one D1 `batch`, a single implicit transaction, replacing two independent
statements whose results were discarded. The half-applied projection is unrepresentable rather than unlikely.

End-to-end atomicity across `save_event` and the projection is **not** claimed and is not achievable on D1:
the envelope has already committed by the time a projection is planned. This ADR anticipates that and permits
the alternative — a durable replay record with idempotent reconciliation — and the receipt row is that
record. A replay of an already-committed event is counted and short-circuits before any write; a replay of a
receipt still at `relay-accepted` or `projection-failed` is treated as reconciliation and retried, which is
safe because the decision insert is `INSERT OR IGNORE` on a deterministic id and the case update is a state
assignment, not an increment. An event that cannot be correlated to a case mints no receipt and no
projection, rather than being absorbed by a fallback.

`GET /api/governance/receipts` (NIP-98 admin, filters `case` / `event` / `stage` / `signer`) exposes the
stage with derived `applied` and `awaitsProjection` flags. Read authority is scoped to the relay's existing
administrative authority: the history-consumer extension above leaves cross-case read authority for
CP-04/05/08/09 to ratify, so none was invented here.

**Tests and results.** `cargo test -p nostr-bbs-relay-worker --features test-exports` — 452 passed, 0 failed,
no warnings; `cargo test --workspace` — 1823 passed, 0 failed. Fourteen new tests in `receipts::tests` with
failure injection: projection failure after the envelope is stored (asserting no decision row, no case state
change, receipt at `projection-failed` with the reason retained, and `is_applied()` false); a duplicate
replay of a committed event never calling `commit_projection` at all; redelivery after a failure reconciling
exactly once and then degrading to a plain duplicate; repeated failures never applying the mutation; the
receipt store itself being unavailable reported rather than swallowed; and the wire form distinguishing a
failed write from a denial.

**Browser receipts.** The route was probed against a live local `wrangler dev` relay:
`GET /api/governance/receipts` returns `401 {"error":"NIP-98 authentication required"}` unauthenticated, and
`governance_receipts` was confirmed created on the live local D1 with the full column set. A **signed
governance journey was not driven**: a 31403 response requires secp256k1 Schnorr signing and no signing
library is installed in this container. See
[`browser-run.json`](../estate-closeout/2026-09-05/browser-run.json).

**Remaining.** The `consumer-received` and `applied`/`rejected` stages are not implemented — they belong to
agentbox and the mutation owner and need the versioned receipt contract this ADR says both sets of
maintainers must agree. `project_appeal` and `project_supersession` are not yet receipt-wired; only the
first-order `project_action_response` path is. No retention policy for `governance_receipts`. Browser-side
acceptance (rationale capture, signer cancellation, acknowledgement timeout, conflicting in-flight actions)
is untouched. Revoked-signer and conflicting-response handling remains with the existing authority checks:
the receipt records what happened, it does not add an authority gate.

**Governed paths changed:** `crates/nostr-bbs-relay-worker/src/relay_do/receipts.rs` (new),
`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs`,
`crates/nostr-bbs-relay-worker/src/relay_do/mod.rs`, `crates/nostr-bbs-relay-worker/src/lib.rs`,
`crates/nostr-bbs-relay-worker/migrations/0005_governance_receipts.sql` (new). Receipt:
[`adr-2010-receipts.json`](../estate-closeout/2026-09-05/adr-2010-receipts.json).

**Disclosure badges (the extension above).** The client now carries explicit badge states — loading,
loaded with an `as_of`, stale, and unavailable — and the unavailable panel says in terms that it "is not a
claim that there are none", so a fetch failure can no longer read as an absence. Freshness ("checked just
now") is always inspectable. 17 tests in `components::agent_badge`, 9 in `stores::badges`, 6 in
`utils::freshness`. The browser run surfaced a defect that defeats this at runtime: against an unreachable
relay the store still reaches `Loaded`, so the panel renders the *empty* branch rather than *unavailable*,
even 18 seconds past the store's 5-second no-EOSE deadline. The badge code, its wiring at the profile call
site and its tests are all correct — the fault is upstream, most plausibly the relay client invoking its EOSE
callback while the socket is not connected. That is the highest-value follow-up from this pass; details in
[`browser-run.json`](../estate-closeout/2026-09-05/browser-run.json).

`decision_status` stays `proposed` and `implementation_status` stays `partial`: the relay-side stages are
built and tested, but the contract this ADR proposes spans consumers that have not adopted it.

## Estate audit — 2026-09-07

Receipt batching and replay stages exist; proposed/partial/inactive remains the accurate full-contract posture. `crates/nostr-bbs-relay-worker/src/relay_do/receipts.rs:164-180` requires the case tag but accepts an absent request event reference. Case UPDATE construction at `:509-552` does not predicate on the observed prior state, and batch validation checks statement success rather than affected rows. The foreign key on decisions may reject an absent case; this audit does not claim a committed missing-case outcome.

Closeout: enforce complete request/case/operation correlation, legal guarded transitions, zero-row and concurrent-decision handling, then retain durable replay and external application evidence. Signed, relay-accepted and projection-committed are separate states from applied. CP-05/09. See the [federation audit](../../../VisionFlow/docs/estate-review/2026-09-07-federation-audit.md).

## Execution qualification — 2026-09-07

The working-tree relay now rejects a missing request case and unknown persisted state, checks event/case/request/signer/outcome agreement at apply, recognises completed receipts before planning against a terminal case, and uses INSERT OR IGNORE for request projection so redelivery cannot reopen a decided case. Decision insertion requires the observed request, legal prior state, latest decision and incomplete receipt. Subsequent case and receipt writes each depend on the preceding changed-row count; all three must affect one row. Exact-SQL tests cover races, zero-row paths, replay and rollback.

Still incomplete: operation payload binding to the originating signed request, cross-repo authority-consumer/mutation-owner receipt agreement, and live D1/restart/external application evidence. Supersession/appeal projection paths remain separate and are not certified by the ordinary-response transaction tests. A relay projection is not an external applied-operation receipt. Proposed/partial/inactive remains appropriate.

Evidence: [federation execution receipt](../../../VisionFlow/docs/estate-review/closeout/2026-09-07-execution-federation.md).

## Live signed journey and acceptance criterion — 2026-10-02

**The relay half is on the edge and was driven signed.** The forum kit deployed today (`49904f4`) carries the receipt store. The ADR-2011 M4 probe suite signed a 31402 and two 31403s against the live relay as a registered agent ([ADR-2011](ADR-2011-operator-task-properties-set-the-escalation-boundary.md), `.claude/evidence/EXP-AC-M4.live.evidence.md`). One 31403 was refused before storage (`rationale_required`). The other, `b46238b26fd409bc8f6aeba4cfbea437f617015318908d07d8bfb62989291d2b`, was stored and its projection refused. The relay's own receipt read back as `stage: projection-failed`, `applied: false`, with the refusal in `stageError` — a failed write recorded as distinct from an applied one, on the edge. That closes the 2026-09-05 gap "a signed governance journey was not driven" for the refusal path, not for the commit path. Hence `activation_status: staged`: the relay half runs live, but the contract this record proposes, which spans consumers, is not adopted.

**A defect that would have hidden the owner's decision, fixed in `a5b809e`.** `receipts::correlate` read the request id only from an `e` tag marked `request`. Every 31403 producer in the estate signs an unmarked `["e", <request id>]`; the dream engine and the client's decision chain both bind to the unmarked tag. Every decision taken in the forum UI therefore came back `Uncorrelated`: no receipt, no `broker_decisions` row, case still open, while the relay's OK said "accepted". The live table held three receipts, none of them a per-case UI decision. `correlate` now falls back to the first unmarked `e` tag. The projection SQL still requires that id to equal the case's `nostr_event_id`, so a wrong tag cannot commit. **The fix is not on the edge until the website's kit pin moves past `a5b809e`.** Until then the owner's decision would be stored but never projected.

**What closes this record (moves `decision_status` to `accepted`).** Both of:

1. A kind-31403 signed by the owner's pubkey on a case whose `broker_cases.effective_tier` is `high` or `critical`, with a `reasoning` the owner typed (at least 20 Unicode scalars after trimming, no template).
2. That event's `governance_receipts` row at `projection-committed`, with `requestEventId` equal to the case's `nostr_event_id` and a `decisionId`, plus the matching `broker_decisions` row (`GET /api/governance/decisions?case_id=<case>`).

The event id, the case id, both reads and the commit the edge ran are recorded in a new section here and in ADR-2011's activation section. An application receipt from the mutation owner (`consumer-received` → `applied` / `not-applied`, or FR7's `applied-manually`) is not required to accept the decision. It is what moves `implementation_status` towards `complete`.

**Owner procedure — the one live high-tier 31403.**

0. *Prerequisites (not the owner's typing).* (a) The edge runs a kit at or after `a5b809e` (website kit-pin bump, then "Deploy Cloudflare Workers"). (b) A **real** high-tier case exists. None does today: the only `high` cases are the two M4 probe cases, which must not be used. Every other open case is a dream-machine `low`/`medium` case or predates migration 0006. A real one is raised by an agent declaring a genuinely irreversible or critical task, e.g. agentbox `governance_request_action` with `action_class` of a `zero-tolerance` class or `task_properties.reversibility: irreversible`. A live candidate is the outstanding release decision "Publish solid-pod-rs 1.0.0-beta.1 and yank legacy alphas" (case `agentbox-release-ops`, raised before 0006 and so untiered; crates.io still tops out at `0.5.0-alpha.10`). A crates.io publish cannot be undone. Confirm with `nostr-bbs-governance-probe --auth-api https://dreamlab-auth-api.solitary-paper-764d.workers.dev --list-cases`, which must show the case at `high`.
1. Sign in with the owner key and open `https://dreamlab-ai.com/community/governance/admin`.
2. Open the card whose tier reads **High**. The proposal is at the top; the agent's declared tier and confidence sit below the controls. Read the proposal, not the agent's framing.
3. In the box labelled "Why you are deciding this, in your own words." type your own reasons: what you checked and why you decide as you do, at least 20 characters. Do not paste the agent's text or a template. Then press **Approve**, **Reject** or **Amend**. The relay refuses an empty or shorter rationale with `rationale_required`.
4. *Recording.* Any admin signer reads `https://dreamlab-nostr-relay.solitary-paper-764d.workers.dev/api/governance/receipts?case=<case id>`, e.g. `nostr-bbs-governance-probe --get '<that URL>'`. The row with `kind: 31403`, the owner's `signerPubkey` and `stage: projection-committed` carries the `eventId`. Record it here, in ADR-2011, and as exit item 4 of the cycle (`dreamlab-cumbria/docs/planning/audit-2026-09-21/evidence/J3-vision-coherence.md`).

