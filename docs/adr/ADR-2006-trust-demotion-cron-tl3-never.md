---
id: ADR-2006
title: Run trust demotion time-driven on the cron trigger with hysteresis; never auto-demote TL3
date: 2026-08-31
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: 7795af5
owner: jjohare
review_trigger: a demotion-latency complaint, or a requirement to demote in real time on the admission path
repo: nostr-rust-forum
domain: IDENTITY-keys-and-trust.md
lineage: distils legacy ADR-102 (inactivity-decay demotion sweep) and the TL0–TL3 ladder of ADR-100
---

# ADR-2006 — Run trust demotion time-driven on the cron trigger with hysteresis; never auto-demote TL3

## External review qualification — 2026-11-02

The [dated source reconciliation](external-review-2026-11-02.md) records the current
implementation evidence, open acceptance gaps and limits of the external review.
It supplements this decision without changing its adoption or activation status.

## Producer repair — 2026-11-03

The [external-review repair receipt](external-fixes-2026-11-03.md) records the
implemented ceremony, authority, concurrency and consumer-contract changes relevant
to this decision, with their migration and deployment limits. These changes do not
promote the whole decision's implementation or activation status.

## Context

Promotion up the TL0–TL3 ladder is driven by activity tallied at EOSE on the hot path.
Demotion is the mirror question, and the obvious symmetry is to also evaluate it inline
when a member acts. But `check_demotion`'s precondition is ~6 months of **inactivity** —
firing it on a request evaluates it precisely against active users, the opposite of its
gate — and TL3 is an administrative grant, not an earned level.

## Decision

Demotion is **time-driven and runs only on the scheduled (cron) trigger**, alongside the
profile-backfill sweep, never inline on admission. It applies **hysteresis** (TL2 demotes
at 90% of the promotion threshold combined with ~6-month inactivity), can move TL2 directly to TL0 when TL1 criteria are not met, with TL0 as a hard floor, and **never auto-demotes TL3** (admin-granted
levels and exempt rows are untouchable by the sweep). Promotion stays on the EOSE read
tally; demotion stays on the cron sweep.

## Consequences

- Forecloses inline/real-time demotion: putting `check_demotion` on the hot path would fire
  it against active users and add a write to admission latency (Invariant: demotion stays
  off the hot path).
- Demotion is only as fresh as the cron cadence — a member inactive past the gate keeps
  their level until the next sweep; acceptable given the ~6-month timescale.
- TL3 can only ever be revoked by an admin action, by design; an operator wanting automatic
  TL3 decay would have to override this decision explicitly.

## Verification

- Demotion sweep lives on the cron trigger, with the "would fire on active users" rationale:
  `crates/nostr-bbs-relay-worker/src/cron.rs:264-282`.
- Ladder, hysteresis and "TL3 never auto-demoted": `crates/nostr-bbs-relay-worker/src/trust.rs:9-10,26-35`;
  promotion never computes/modifies TL3: `trust.rs:165,200-202`.
- Established at `verified_commit` 7795af5 (`git rev-parse --short HEAD`).

## Closeout extension — 2026-09-04

Work packages: CP-04/05/08. Accountable owner: the existing owner above, with forum release/identity maintainers for cross-service acceptance. Historical verification and activation declarations are preserved; this review does not re-certify a live deployment.

Source can demote TL2 directly to TL0. It ignores execution errors from separate trust UPDATE and audit INSERT operations, then returns the planned level. The sweep counts that return as a decrease. A source-query SQLite fixture starts with 400 eligible rows, processes 200 and leaves 200 because OFFSET advances after qualifying rows leave the result set.

**Acceptance condition:** Use stable pagination over the mutation boundary and explicit committed/error outcomes. Verify more than one batch, tied timestamps, TL2-to-TL0, TL3/admin exclusions, write/audit failures and restart reconciliation. Counts must represent committed changes; protect audit/state consistency. This is source and synthetic-query evidence, not a deployed D1 reproduction.

Dependencies: CP-01 release identity and the relevant identity, governance and recovery journeys. Reopen when the governed source, dependency, deployment profile or consumer contract changes. See the [estate forum review](../../../VisionFlow/docs/estate-review/forum-decisions.md) and [current source/test receipt](../../../VisionFlow/docs/estate-review/evidence/forum-closeout-snapshot.json).

Implementation status changed from complete to partial because committed sweep coverage and audit outcomes are not established by the current implementation. The accepted cron/TL3 policy is retained.

## Acceptance progress — 2026-09-05

**Implemented.** The sweep moved to `crates/nostr-bbs-relay-worker/src/trust_sweep.rs` and now pages the
candidate set with a **keyset cursor** over `(COALESCE(last_active_at, 0) ASC, pubkey ASC)` instead of
`LIMIT/OFFSET`. The offset form was unsound for this workload: the sweep mutates `trust_level`, the very
column its candidate predicate filters on, so rows demoted out of the TL1–TL2 band left the result set
underneath the offset. Neither cursor component is written by a demotion, so every row's ordering key is
stable across the mutation boundary, and the `pubkey` tiebreak makes the order total for a cohort sharing
one `last_active_at`.

Outcomes are explicit. Every scanned row resolves to exactly one of committed, held (with a named
`HoldReason`), or failed (with the error), and `scanned == demoted + held + failed` is asserted in test and
checked on the live path. `demoted` counts confirmed commits only — the previous implementation discarded
both write results and then returned the *planned* level, so a failed write was indistinguishable from a
committed one. A page-query failure now sets `aborted` rather than presenting as clean completion.

Audit and state commit together: the `whitelist` `UPDATE` and the `admin_log` `INSERT` are submitted as one
D1 `batch`, which executes in a single implicit transaction. The `UPDATE` carries an optimistic guard on the
observed level and a `meta().changes == 0` check, so an admin grant landing mid-sweep is reported as a
conflict rather than clobbered.

Three structural changes reinforce the accepted policy rather than restating it. `trust::decide_demotion` is
now a pure function and the single authority for the decision. The `#[cfg(test)]` policy mirror in `cron.rs`
— which carried a comment insisting the two "MUST stay in lockstep" — is deleted; the tests exercise the live
function through an argument-shaping adapter, so drift is impossible rather than merely discouraged. And
`trust::check_demotion`, the per-pubkey entry point, is deleted: it had no caller but the sweep, and its
absence makes this ADR's "demotion never runs on the hot path" invariant structural. The sweep also selects
the full candidate row in its page query; the previous code re-read each row and reloaded every threshold
setting from D1 per candidate.

TL2 → TL0 is **retained**, because this ADR's Decision explicitly permits it when the TL1 criteria are not
met. "One step" is enforced as one committed transition per row per sweep, guaranteed by a cursor that never
revisits a row.

**Tests and results.** `cargo test -p nostr-bbs-relay-worker --features test-exports` — 452 passed, 0 failed,
no warnings. Fourteen new tests in `trust_sweep::tests` cover: 400 rows across multiple batches (the exact
scenario the closeout recorded as 400 → 200); tied timestamps across ten pages with a no-revisit assertion;
TL2 → TL1 and TL2 → TL0; TL3, admin/exempt and TL0-floor exclusions; a row that clears hysteresis being held
and counted; commit failure not counted as a demotion and not stalling the sweep; audit-half failure leaving
neither the level nor the audit changed; page-query failure aborting; truncation reporting a resume point;
and sweep-to-sweep convergence with no double counting. An in-memory store reproduces the feedback loop the
`OFFSET` form tripped over — a committed demotion changes the eligible set the next page query runs against.

**Local D1 reproduction.** The sweep was then run against a real worker: `wrangler dev --local` (workerd +
miniflare, local D1/SQLite), the release `worker-build` output, and wrangler's local cron trigger
(`GET /cdn-cgi/local/scheduled`) invoking the actual scheduled handler. No remote binding and no credentials.
The `whitelist` table is provisioned outside this repository, so a local fixture table was created with the
columns the sweep reads; `admin_log` and `governance_receipts` were created by the worker's own
`ensure_schema`. Four runs:

1. **Full sweep** over 400 idle TL1 rows (the first 200 sharing one identical `last_active_at`, so the keyset
   tiebreak is exercised against real SQLite ordering) plus the six named fixtures. Result
   `scanned=403 demoted=402`. All 400 idle rows reached TL0 — the `OFFSET` implementation processed 200 of
   these and reported clean completion. Every exclusion held: TL3 stayed TL3, the admin TL2 row stayed TL2,
   the active row was never a candidate. TL2 → TL0 and TL2 → TL1 both landed correctly, and `admin_log`
   carried exactly 402 entries — one per committed change.
2. **Convergence.** Re-running the sweep committed nothing further and left the audit count at 402.
3. **Audit-write failure injection.** 100 rows reset to TL1 and `admin_log` renamed away, so the audit
   `INSERT` — the second statement of the commit batch — fails. Result
   `scanned=102 demoted=0 held=2 failed=100 aborted=false`, and **not one trust level changed**. That is the
   D1 batch proving genuinely all-or-nothing: a failed audit half rolls back its paired `UPDATE`. Under the
   previous implementation these 100 would have been counted as demotions.
4. **Restart reconciliation.** With `admin_log` restored, the next sweep committed exactly the 100 that had
   failed and nothing else (`demoted=100 failed=0`), taking the audit count to 502 — no duplicates from the
   failed attempt, and no operator intervention.

**Browser receipts.** None; this path has no browser surface.

**Remaining.** No *deployed* (remote) D1 exercise — the reproduction above is local workerd/miniflare, which
shares D1's SQLite engine and batch semantics but is not the production binding. A cron tick interrupted
mid-page is not exercised. The `DEMOTION_MAX_ROWS` resume point is reported but not persisted, so the next
tick restarts from the first candidate; that is correct but not minimal on a very large backlog.

**Governed paths changed:** `crates/nostr-bbs-relay-worker/src/trust_sweep.rs` (new),
`crates/nostr-bbs-relay-worker/src/trust.rs`, `crates/nostr-bbs-relay-worker/src/cron.rs`,
`crates/nostr-bbs-relay-worker/src/lib.rs`. Receipts:
[`adr-2006-trust-sweep.json`](../estate-closeout/2026-09-05/adr-2006-trust-sweep.json) and
[`adr-2006-local-d1-reproduction.json`](../estate-closeout/2026-09-05/adr-2006-local-d1-reproduction.json).

`implementation_status` returns to `complete`: the acceptance condition is scoped by its own text to source
and synthetic-query evidence, and every clause of it — stable pagination over the mutation boundary,
committed/error outcomes, multiple batches, tied timestamps, TL2-to-TL0, TL3/admin exclusions, write and
audit failure, restart reconciliation, audit/state consistency — is now established. The deployed-D1 gap is
recorded above and is not part of that condition.

## Estate audit — 2026-09-07

Keyset paging, named outcomes and transaction rollback on SQL errors are source-supported. A fresh SQLite probe using the source queries establishes a different failure: a concurrent trust change causes the guarded UPDATE to affect zero rows while the unconditional audit INSERT commits. `crates/nostr-bbs-relay-worker/src/trust_sweep.rs:429-485` checks the affected-row count only after the batch. A transaction groups statements but does not make an audit claim conditional on its preceding UPDATE succeeding.

Closeout: make audit creation conditional on the accepted transition within the same transaction, and test concurrent level, administrator, exemption and activity changes. Preserve the protected trust level and emit no false transition. The 239 native relay tests passed; the isolated SQLite counterexample is not evidence of an observed deployed D1 incident. CP-04/05. See the [federation audit](../../../VisionFlow/docs/estate-review/2026-09-07-federation-audit.md).

## Execution qualification — 2026-09-07

The earlier optimistic-conflict audit finding is repaired in the working tree. `trust_sweep.rs` compares all observed policy inputs (level, admin exemption, activity/update timestamps and counters), uses null-safe nullable predicates, and executes `INSERT ... SELECT ... WHERE changes() = 1` immediately after the guarded UPDATE in one D1 batch. Both result counts must equal one before a demotion is reported. Exact production-SQL SQLite tests cover concurrent input changes, missing rows, null snapshots, duplicate delivery and audit-failure rollback. Native relay tests and wasm32 compilation pass. This is a repair candidate and local adapter evidence; the existing live axis does not certify deployment of these new bytes or a live D1 probe.

Evidence: [federation execution receipt](../../../VisionFlow/docs/estate-review/closeout/2026-09-07-execution-federation.md).
