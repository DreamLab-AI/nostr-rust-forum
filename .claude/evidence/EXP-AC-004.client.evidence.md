---
expectation_id: EXP-AC-004
scope: nostr-bbs-forum-client (the UI half of FR4.1 and FR4.3 only)
git_sha: ef0c9aa207ba16618cb4a09195546ef317823ba8
branch: feat/augmentation-conditions-client
produced_by: agent:claude-opus
produced_at: 2026-09-14T20:02:22Z
audited_by: agent:claude-sonnet-5 (degraded: same family as producer; codex GPT-6 Astra unavailable — bwrap sandbox refused in container)
audited_at: 2026-09-14T21:40:00Z
auditor_verdict: DISPUTED
auditor_counter_examples_attempted: 4
auditor_counter_examples_found: 1
---

# Evidence — EXP-AC-004 (forum client)

This receipt covers **only** the client's share of EXP-AC-004: that the decision
chain displays the receipt ladder including the application stages, and that a
stalled case ages visibly. The endpoint's stage machine, its 409 on regression,
its 403 on a non-admin `applied-manually`, the relay cron's idempotency, the
agentbox `broker-bridge` journal records and the VisionClaw `ElevationActor`
are other components' halves and are evidenced in
`.claude/evidence/EXP-AC-004.evidence.md` and the respective repositories.

## Scenario 1 — the ladder is read, and side receipts stay side receipts

```
$ cargo test -p nostr-bbs-forum-client stores::receipts
```

```
test stores::receipts::tests::parses_the_relay_receipt_envelope ... ok
test stores::receipts::tests::malformed_rows_are_skipped_not_fatal ... ok
test stores::receipts::tests::a_non_receipt_body_yields_nothing_rather_than_panicking ... ok
test stores::receipts::tests::the_furthest_ladder_stage_wins_per_decision ... ok
test stores::receipts::tests::an_out_of_order_row_never_regresses_a_decision ... ok
test stores::receipts::tests::side_receipts_flag_the_case_and_never_become_a_stage ... ok
test stores::receipts::tests::an_escalated_on_age_receipt_on_an_undecided_case_still_flags_it ... ok
test stores::receipts::tests::the_application_stages_each_have_a_distinct_honest_label ... ok
test stores::receipts::tests::a_failed_application_reads_as_a_failure_not_as_progress ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 382 filtered out; finished in 0.00s
```

`side_receipts_flag_the_case_and_never_become_a_stage` is DDD §6 invariant 5:
`escalated-on-age` and `expired` set their own flags and never overwrite a
decision's ladder stage. `an_out_of_order_row_never_regresses_a_decision` is
the display-side counterpart of the endpoint's 409.
`the_application_stages_each_have_a_distinct_honest_label` asserts all ten
stages read distinctly, and `a_failed_application_reads_as_a_failure_not_as_progress`
that `not-applied` and `projection-failed` are styled as failures — FR4.1's
"a denied action and an approved action whose write failed must never look the
same". `consumer-received`, `applied`, `not-applied` and `applied-manually`
all render; `DecisionChainRow` (`src/pages/governance.rs`) places the stage
beside its decision with the mutation owner's own acknowledgement as the
tooltip.

**Verdict: PASS**, for the display half only.

## Scenario 2 — a stalled case ages visibly

```
$ cargo test -p nostr-bbs-forum-client utils::governance_view
```

```
test utils::governance_view::tests::relative_age_labels_read_in_the_largest_whole_unit ... ok
test utils::governance_view::tests::a_future_created_at_reads_as_just_now_not_as_a_negative_age ... ok
test utils::governance_view::tests::a_missing_created_at_says_so_rather_than_claiming_an_age ... ok
test utils::governance_view::tests::overdue_trips_exactly_at_the_panel_deadline ... ok
test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured; 349 filtered out; finished in 0.00s
```

Age is differenced client-side from `created_at` as FR4.3 specifies and is
shown on **every** pending card, decidable or not. `overdue` trips exactly at
the panel's `max_pending_hours` (default 72, read from the 31400's tags), and
the pending list now sorts oldest-first so a stalled case rises rather than
sinking. The relay's authoritative `escalated-on-age` receipt renders as its
own badge where the viewer can read receipts.

**Verdict: PASS**, for the display half only.

## Honest limits

1. **The receipts read is admin-only.** `GET /api/governance/receipts` requires
   NIP-98 admin, so a member or a delegated reviewer sees the decision chain
   **without** application stages. The store records that as `unavailable` and
   stops retrying; it never renders absence as `not-applied`. The ageing badge
   those viewers do get is the client's own clock reading and is labelled
   advisory. Closing this needs a reviewer-scoped receipts read, which is a
   relay/auth-worker change and is **not** in this branch.
2. **Receipts are fetched per case on demand, not subscribed.** A stage that
   advances after the fetch appears on the next load of the surface.
3. **No live run.** Nothing here was exercised against a deployed relay; there
   is no `consumer-received → applied` transition observed end-to-end in a
   browser. These are host-target unit tests over the wire shapes the relay
   documents, plus a release build.

## Security gate

```
$ /home/devuser/.claude/skills/build-with-quality/scripts/deepsec-gate.sh --diff feat/augmentation-conditions
```

Run three times as the branch changed. The receipts are kept in full under
`.deepsec-gate/reports/`.

| Run | Receipt | Exit | New findings |
|---|---|---|---|
| 1 | `20260914T194300Z` | 1 | HIGH x2, MEDIUM x1, BUG x1 |
| 2 | `20260914T195646Z` | 1 | MEDIUM x4, HIGH_BUG x1, BUG x2 |
| 3 | `20260914T201424Z` | 1 | MEDIUM x2 |

**Final result: BLOCK, exit 1. Not a pass, and not recorded as one.**

The gate's `blocking` list is cumulative across runs, so the two HIGH entries on
the final receipt are run 1's, both **fixed in this tree** and absent from runs 2
and 3:

- *Stored XSS via unvalidated `ActionRequest.context_url` rendered into href*
  and its ingest-side twin. Real, and mine: the governance subscription carries
  no `authors` filter, so `context_url` is attacker-controlled, and I had bound
  it straight into an `<a href>`. Fixed by `safe_context_url`
  (`src/utils/governance_view.rs`), applied at **both** the store ingest and the
  render, allowing only `http`/`https` with a case-insensitive scheme match and
  rejecting any string carrying an ASCII control character (a browser strips
  embedded tabs before resolving a scheme, so `java\tscript:` is a
  `javascript:` URI in disguise). Tests:
  `only_http_and_https_context_urls_survive`,
  `a_script_bearing_context_url_never_reaches_an_href`,
  `control_characters_are_rejected_rather_than_trimmed_out`.

Also fixed in this branch, from runs 1 and 2:

- *`shorten_pubkey` byte-slices at fixed offsets and can panic* — a panic in
  WASM aborts the whole reactive render. Fixed by character-slicing, in
  `utils/mod.rs` and in the new `governance_view::short_id` used by the decision
  chain, where a hostile 31403's `delegate_to` is an arbitrary string.
- *Panels keyed by `d` tag alone let one agent clobber another agent's panel*
  and *`KIND_PANEL_RETIRED` removes any panel by `d` tag with no ownership
  check*. Material to this change specifically: since ADR-2011 a panel carries
  the operator's task-property declaration, so a `d`-tag collision was a way to
  **lower another operator's escalation boundary**. Fixed by keying panels and
  panel states by the NIP-33 address (`panel_address`), which makes retirement
  ownership-safe for free.
- *Decision chain computed with no scoping, so a colliding `d` tag injects into
  a victim case's chain*. Fixed by binding the chain to the request's event id
  (`bind_to_request`); a forged `approve` can no longer make a case read as
  decided (which would reveal its probe) and a forged `delegate` can no longer
  offer a stranger the controls.

**Left open, with reasons:**

- *Probe blindness is only enforced at the DOM; digests are readable on the
  wire* (MEDIUM, run 3). Correct, and already this branch's stated position:
  the relay cannot strip the tag from a signed event without invalidating the
  signature. It is ADR-2011's `implementation_status: partial` and its
  `review_trigger`. Not closable in the client.
- *Action requests appended and deduped by `event_id`, ignoring NIP-33
  replaceable semantics* (BUG). Pre-existing behaviour, unchanged by this
  branch; each 31402 is treated as a distinct case, which is what the relay's
  own `broker_cases` projection does. Untriaged beyond that.
- Four findings in `nostr-bbs-relay-worker` and `nostr-bbs-core`
  (device-key moderation bypass, `governance_rank` pubkey casing, 31405 defined
  twice, 64-bit decision ids). **Not this branch's code** — they belong to the
  backend half on `feat/augmentation-conditions` and are recorded here only so
  they are not lost.

## Auditor adversarial probes

Worktree `nostr-rust-forum-client-client`, HEAD `6b6f48a` (unchanged code from
`ef0c9aa`). No implementation files edited; probe below was run as a temporary
`#[cfg(test)]` block appended to `stores/receipts.rs` and reverted with `git
checkout --` before this commit.

```
$ cargo test -p nostr-bbs-forum-client
test result: ok. 393 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

1. **`reduce_case` with out-of-order stages: `applied` row arriving before a
   `consumer-received` row.** Reproduces the evidence's own
   `an_out_of_order_row_never_regresses_a_decision` — `applied` (ladder
   position 5) correctly outranks `consumer-received` (position 4) and wins.
   No counter-example on this pairing.

2. **`reduce_case` with duplicate stages (two `applied` rows for the same
   `event_id`, different `acknowledgement`).** `existing.stage >= row.stage`
   is `true` for a tie, so the *first*-seen row's `acknowledgement`,
   `applied_by` and `applied_at` are kept and the second is silently dropped.
   Not obviously wrong (there is no documented tie-break rule), but worth
   recording: whichever row an unstable relay-side ordering happens to return
   first wins, not the most recent. Not counted as a counter-example — no
   expectation specifies "most recent wins".

3. **`reduce_case` with `applied` then `not-applied` for the same
   `event_id`.** This is the finding. `ReceiptStage` derives `Ord` from
   declaration order (`governance.rs:663`): `Signed < RelayAccepted <
   ProjectionCommitted < ProjectionFailed < ConsumerReceived < Applied <
   NotApplied < AppliedManually < EscalatedOnAge < Expired`. `reduce_case`'s
   "furthest stage wins" (`stores/receipts.rs:106`) is exactly `row.stage >
   existing.stage` on that same derived order — which is only a sound
   "further along the ladder" measure for the *strictly sequential* prefix
   (`Signed` → … → `ConsumerReceived`). `Applied`, `NotApplied` and
   `AppliedManually` are not three further rungs of one ladder; they are three
   **mutually exclusive terminal outcomes** at the same rung, and their
   relative `Ord` is an accident of enum declaration order. Reproduced:

   ```rust
   let r = reduce_case(vec![
       ReceiptView { event_id: "dec-1".into(), stage: ReceiptStage::Applied, .. },
       ReceiptView { event_id: "dec-1".into(), stage: ReceiptStage::NotApplied, .. },
   ]);
   // r.by_decision["dec-1"].stage == ReceiptStage::NotApplied
   ```

   confirmed by running the block (then reverted) — the result is
   `NotApplied`. A successfully applied action, once a `not-applied` row for
   the same `event_id` is present, displays as failed. This is not a
   theoretical edge of the ordering; it is the *specific* pair FR4.1 and both
   evidence files single out by name: "a denied action and an approved action
   whose write failed must never look the same"
   (`the_application_stages_each_have_a_distinct_honest_label`,
   `a_failed_application_reads_as_a_failure_not_as_progress`) — this reduction
   can make them look like *the same thing in the wrong direction*: a
   successful application reads as a failure.

   **Reachability, stated honestly rather than overclaimed:** the relay's
   `governance_receipts` table is a single row per `event_id`, written by
   `UPDATE … WHERE event_id = ?` (`relay_do/receipts.rs:179,554`), never
   `INSERT` on a later stage — so `GET /api/governance/receipts` today can
   only ever return **one** row per `event_id`, and this exact two-row
   scenario cannot currently be produced through the documented endpoint. The
   defect is real in the code and in what the tests claim to guard
   (`an_out_of_order_row_never_regresses_a_decision`'s name promises more than
   its one tested pairing establishes), and it is exactly the class of thing
   the store's own doc comment anticipates changing ("where several ladder
   rows exist for one decision (a replayed projection, then an application)")
   — but it is not live against the current server. Recorded as a
   counter-example against the *code's* claimed guarantee, with the
   reachability caveat attached rather than omitted.

4. **Age label for `created_at` in the future.** Already covered by
   `a_future_created_at_reads_as_just_now_not_as_a_negative_age`; re-verified
   with `created_at` several days ahead of `now` (not just seconds) — still
   `"just now"`, `saturating_sub` floors at 0 regardless of skew magnitude. No
   counter-example.

**Verdict: DISPUTED** for the display half, on item 3: `reduce_case`'s
stage-ordering is unsound for the three terminal application outcomes, and can
display a successful application as `NOT applied`. Not currently reachable via
the relay's single-row-per-event_id write path, so it does not contradict the
evidence's Scenario 1 PASS as tested — but the evidence's tests do not cover
this pairing despite naming "out-of-order" and "distinct honest label" as the
properties under test, and neither evidence file's "Honest limits" section
discloses the ordering's scope. Item 2 is a minor, unspecified tie-break
observation, not a counter-example. Items 1 and 4 held.
