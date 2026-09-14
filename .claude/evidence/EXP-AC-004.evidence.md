---
expectation_id: EXP-AC-004
git_sha: 81aa0d9
produced_by: agent:claude-opus
produced_at: 2026-09-14T15:42:05Z
audited_by: agent:claude-sonnet-5 (degraded: same family as producer; codex GPT-6 Astra unavailable — bwrap sandbox refused in container)
audited_at: 2026-09-14T19:30:00Z
auditor_verdict: CONFIRMED
auditor_counter_examples_attempted: 6
auditor_counter_examples_found: 0
---

# Evidence — EXP-AC-004

Executed against `c2e4ef7e54a0df9065c54a5784a433082d08c80d` on branch `feat/augmentation-conditions`. Every command
below was run; the output is this run's, trimmed to the assertion lines.


## Scenario 1 — the receipt stage ladder is monotonic

```
$ cargo test -p nostr-bbs-core --lib governance::receipt_stage_tests
```

```
test governance::receipt_stage_tests::application_stages_require_a_committed_projection ... ok
test governance::receipt_stage_tests::applied_manually_may_follow_a_committed_projection_directly ... ok
test governance::receipt_stage_tests::applied_requires_consumer_received_first ... ok
test governance::receipt_stage_tests::every_stage_round_trips_through_its_wire_string ... ok
test governance::receipt_stage_tests::ladder_advances_committed_to_received_to_terminal ... ok
test governance::receipt_stage_tests::applied_then_consumer_received_is_a_regression ... ok
test governance::receipt_stage_tests::no_stage_pair_permits_a_regression ... ok
test governance::receipt_stage_tests::not_applied_is_not_applied ... ok
test governance::receipt_stage_tests::side_receipts_are_off_the_ladder ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 374 filtered out; finished in 0.00s
```

**Verdict: PASS.** 9 tests, 0 failures. `no_stage_pair_permits_a_regression`
checks **every** pair of the ten stages, not a sample.
`applied_then_consumer_received_is_a_regression` is the exact regression
EXP-AC-004 names. `side_receipts_are_off_the_ladder` pins that
`escalated-on-age` and `expired` never advance it (DDD §6 invariant 5).

## Scenario 2 — endpoint authority, the 409 on regression, and the 403s

```
$ cargo test -p nostr-bbs-auth-worker --lib augmentation_api_tests
```

```
test governance_api::augmentation_api_tests::a_case_without_a_probe_reveals_nothing ... ok
test governance_api::augmentation_api_tests::a_probe_is_revealed_once_the_case_is_decided ... ok
test governance_api::augmentation_api_tests::a_probe_is_withheld_from_every_undecided_case ... ok
test governance_api::augmentation_api_tests::a_registered_agent_may_not_report_on_another_agents_case ... ok
test governance_api::augmentation_api_tests::a_negative_time_to_decision_is_discarded ... ok
test governance_api::augmentation_api_tests::a_stranger_is_refused_with_403 ... ok
test governance_api::augmentation_api_tests::a_regression_is_409 ... ok
test governance_api::augmentation_api_tests::an_admin_needs_no_ownership ... ok
test governance_api::augmentation_api_tests::a_side_receipt_is_not_an_application_stage ... ok
test governance_api::augmentation_api_tests::a_registered_agent_may_report_the_ordinary_stages ... ok
test governance_api::augmentation_api_tests::an_empty_corpus_yields_no_reviewers ... ok
test governance_api::augmentation_api_tests::an_uncommitted_decision_cannot_be_applied ... ok
test governance_api::augmentation_api_tests::applied_manually_from_a_non_admin_is_403 ... ok
test governance_api::augmentation_api_tests::applied_manually_requires_a_prior_approve ... ok
test governance_api::augmentation_api_tests::an_admin_may_record_a_manual_continuation_on_an_approved_case ... ok
test governance_api::augmentation_api_tests::a_repeat_of_the_same_terminal_stage_is_409 ... ok
test governance_api::augmentation_api_tests::percentile_and_median_are_total_on_an_empty_series ... ok
test governance_api::augmentation_api_tests::calibration_and_probe_columns ... ok
test governance_api::augmentation_api_tests::superseded_decisions_are_counted ... ok
test governance_api::augmentation_api_tests::the_legacy_resolved_state_still_admits_a_continuation ... ok
test governance_api::augmentation_api_tests::decisions_time_to_decision_and_override_rate ... ok
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 215 filtered out; finished in 0.00s
```

**Verdict: PASS.** 21 tests, 0 failures. The mapping EXP-AC-004 specifies is
asserted with its status codes: a registered agent may set
`consumer-received | applied | not-applied`; `applied_manually_from_a_non_admin_is_403`;
`a_regression_is_409`; `an_uncommitted_decision_cannot_be_applied` pins the
counter-example the expectation opens with — a decision still at
`relay-accepted` or `projection-failed` cannot be reported applied.

`a_registered_agent_may_not_report_on_another_agents_case` was added after
deepsec found that registration alone let any active agent write a durable lie
about another agent's mutation; the fix and its test are in commit `df18a81`.

## Scenario 3 — escalation on age, exactly once per case

```
$ cargo test -p nostr-bbs-relay-worker --lib ageing
```

```
test cron::ageing_ordering_tests::a_younger_short_deadline_case_is_overdue_before_an_older_long_one ... ok
test cron::ageing_ordering_tests::equal_deadlines_order_oldest_first ... ok
test cron::ageing_tests::a_backwards_clock_escalates_nothing ... ok
test cron::ageing_tests::a_missing_deadline_falls_back_to_the_default ... ok
test cron::ageing_ordering_tests::an_undeclared_deadline_sorts_as_the_default ... ok
test cron::ageing_tests::the_deadline_boundary_is_exclusive ... ok
test cron::ageing_tests::a_case_inside_its_deadline_is_not_escalated ... ok
test cron::ageing_tests::the_panel_deadline_is_honoured_over_the_default ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 260 filtered out; finished in 0.00s
```

**Verdict: PASS.** 8 tests, 0 failures. "Exactly once per case" is not a code
path that has to remember: it is the `(case_id, stage)` primary key on
`case_side_receipts` (migration `0006`), with `INSERT OR IGNORE` as the write.
The predicate tests pin the exclusive deadline boundary, the panel deadline
overriding the default, the default applying when none is declared, and a
backwards clock escalating nothing.

`ageing_ordering_tests` pins a defect deepsec found in the first version of this
sweep: it ordered candidates by `created_at` and broke on the first case inside
its own deadline, which with per-panel deadlines skipped exactly the
short-deadline cases the feature exists for. The query now filters and orders by
`created_at + deadline` and there is no early break.

## Security gate — BLOCK (exit 1), with the blocking set analysed

```
$ /home/devuser/.claude/skills/build-with-quality/scripts/deepsec-gate.sh --diff main
deepsec-gate: BLOCK - 32 finding(s) {CRITICAL: 0, HIGH: 2, MEDIUM: 20, HIGH_BUG: 1, BUG: 9}, 2 at/above HIGH
exit code: 1
receipt: .deepsec-gate/reports/20260914T162917Z/receipt.json
```

**Verdict: BLOCK.** Exit code `1` — not 78, so the gate ran rather than being
skipped. It is recorded here as blocked, not passed.

### Why the blocking set is not current state

The gate's verdict is computed over `findings.json`, which the script produces
with `deepsec export --project-id <id> --min-severity LOW` — an export of the
**persistent project store** under `.deepsec-gate/data/`, not a fresh scan
result. That store accumulates and never retires a finding once fixed. Three
observations establish this:

1. The total grows monotonically across runs on the same branch: 5, 8, 13, 18,
   25, 30, 32 — while each run's `comment.md` reports only its *net-new*
   findings (the last reported 2).
2. The same issue appears many times, restated by different analyses: four
   separate probe-blindness findings, five for `ensure_schema`-per-request.
3. Both `HIGH` entries in the blocking set are findings **fixed on this branch**,
   in commits that predate the run that still reports them.

### Triage of the two blocking HIGH findings

Both were attributed against the **feature-only** state of the branch
(`main..71f6b26`, before either security fix landed). The feature diff has no
hunk in `nip_handlers.rs` between old lines 202 and 1750; both findings live in
that gap. Neither is in a line this branch changed for feature reasons — both
are **purely pre-existing blast radius**.

| | HIGH-1 | HIGH-2 |
|---|---|---|
| Location | `nip_handlers.rs:1288-1331` (`handle_req`) | `nip42.rs:85-108`, called from `nip_handlers.rs:1655-1675` (`authorize_event`) |
| In this branch's feature diff? | No — pre-existing | No — pre-existing |
| Exploit path | Send `REQ sub1 {"kinds":[1059]}` on an unauthenticated socket in `nip42` mode. The raw filter is inserted into `session.subscriptions` and persisted *before* the gates run; the gate then refuses the historical read with `CLOSED` and returns — leaving the subscription in place. `broadcast.rs` matches every subsequently-published event against that stored raw filter, so the attacker receives the live stream of sealed DMs they were just refused. | Send `REQ sub1 {}` — a filter with no `kinds` field. It matches every kind while naming none, so `protected_read_blocked` (which inspects `filter.kinds`) sees no protected kind and `gate_kind_1059_filters` applies no `#p` rewrite. `build_filter_conditions` adds no `kind IN (...)` predicate, so `query_events` returns sealed DMs, encrypted DMs and moderation events to an anonymous socket. |
| Contained? | Yes — a reorder | Yes — one predicate at an existing chokepoint |
| Disposition | **Fixed** in `a14b2b7`. Gates precede the insert; the stored value is the rebound gated filter. | **Fixed** in `12a10da`. `authorize_event` already guarded all three read paths, so the gate applies per event and cannot be dodged by omitting the kind. |
| Tests | `nip_handlers.rs:4144` `req_gate_ordering_tests` | `nip42.rs:383` `protected_read_permitted_tests`, 8 cases |

Both are recorded in ADR-2011's Consequences as out-of-scope security fixes
carried on this change, with file:line.

Findings that are pre-existing and **not** contained enough to fix here are in
`docs/security/known-findings.md` with an owner — including one `HIGH_BUG`
(KF-1, the retention sweep's `CAST`-versus-parse divergence, which silently
deletes events whose expiration tag is malformed). KF-1 is contained and worth
doing; it is not one of the two gate-blocking `HIGH`s and is recommended as a
standalone change rather than a third unrequested relay fix on this branch.

### Findings against this branch's own code — all fixed, each with a test

- `cross-tenant-id` — any registered agent could advance any receipt, writing a
  durable falsehood about another agent's mutation. Non-admin callers must now
  be the case's `created_by` (`df18a81`).
- `ageing-sweep-early-break` — the sweep ordered by `created_at` and broke on the
  first case inside its own deadline, skipping exactly the short-deadline cases
  the feature exists for (`a2847dd`).
- `other-info-disclosure` — the `TAG_PROBE` doc comment claimed the relay strips
  the tag from every projection. It does not; the comment now states what is
  enforced and what is not (`c86f9cf`).
- `revocation-silent-failure` and pubkey case-normalisation across the agent
  registry, broker roles and case delegations (`df18a81`, `96566dc`).

### Open, pre-existing, and routed rather than fixed

`ensure_schema` running on every request; `require_authed` on the governance
read endpoints being weaker than membership (note: this change widens what that
weak gate exposes by adding the effective tier and triple to the case
projection — low-sensitivity fields, but a real widening); gift-wrap senders
escaping suspension; the retention sweep's CAST-versus-parse divergence; and the
16-hex truncation of `decision_id`. Each belongs to a surface this expectation
does not own.

## Auditor adversarial probes

Cross-family audit degraded to same-family (see frontmatter). Whole-workspace
regression re-run independently:

```
$ cargo test --workspace --exclude nostr-bbs-forum-client
```

Aggregate across 37 `test result:` blocks: **1589 passed, 0 failed** — exact
match to the producer's stated total. (A first attempt at this command
mid-audit failed to compile with escalating, non-deterministic errors —
duplicate `k256`/`serde` type identities and a linker "duplicate symbol"
failure that grew worse between consecutive runs on an unchanged tree. Traced
to a concurrently-running producer process rewriting the working tree and
racing this same `target/` and shared `CARGO_HOME` registry cache — confirmed
by commits `68f0ef7`/`8576dfe` landing on this branch during the audit. Not a
code defect; the re-run above, after the producer's writes settled, compiled
and passed clean.)

Receipt-ladder probes (`can_advance_stage`), run against the same temporary
`tests/audit_scratch_probes.rs` as EXP-AC-003 (deleted after the run):

- `Applied -> ConsumerReceived` (the exact regression EXP-AC-004 names): rejected.
- `RelayAccepted -> AppliedManually` (manual continuation of a decision that
  never committed): rejected — `applied-manually`'s consumer-received exemption
  does not extend to skipping the projection precondition.

Endpoint-authority scenarios (`plan_application_advance`, read directly rather
than re-implemented, since it is already the pure seam the endpoint calls):
confirmed by code reading that `applied-manually` from a registered
(non-admin) agent returns `ApplicationRefusal::ManualRequiresAdmin` →
`status() == 403` (already asserted by the producer's own
`applied_manually_from_a_non_admin_is_403`), and that `applied-manually` for
an `open` case state returns `ManualRequiresApprovedCase` →
`status() == 409` (asserted by `applied_manually_requires_a_prior_approve`'s
`open`/`none` row). No counter-example: the status-code mapping in
`ApplicationRefusal::status()` matches EXP-AC-004's spec exactly, and no path
reaches `Ok(())` for either scenario.

Ageing idempotency: the "exactly once" guarantee is a `(case_id, stage)`
PRIMARY KEY on `case_side_receipts` (migration 0006) with `INSERT OR IGNORE`
as the write — verified by reading the migration and the cron write path, not
re-derivable as a pure-function probe without a D1 mock. Re-running the sweep
twice cannot double-insert given that schema; this is a structural guarantee
the auditor could confirm by code reading but not independently execute
outside a Workers/D1 runtime, same limitation the producer's own evidence
notes for the D1 shells.

**No counter-example found.** 6 attempted (2 executed as scratch tests, 2
confirmed by direct code/test reading, 1 whole-workspace regression rerun, 1
structural-guarantee code read for ageing idempotency).

**Verdict: CONFIRMED.**

## Auditor re-verification of deepsec HIGH fixes

Independent re-verification of the two `HIGH` auth-bypass findings ADR-2011
records as fixed-but-still-blocking-the-gate (`a14b2b7`, `12a10da`). Read
directly against current `HEAD` (`8576dfe`, docs/chore-only since `81aa0d9`;
no crate code changed underneath this audit).

### Fix 1 — `a14b2b7`: REQ subscription gated before storage

Read `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs`, `handle_req`
(current lines ~1280-1327):

- `nip42::protected_read_blocked(&filters, ...)` runs at line 1296 and returns
  early (`send_closed`) **before** any mutation of `session.subscriptions`.
- `Self::gate_kind_1059_filters(filters, ...)` runs at line 1308, rebinding
  `filters` to the gated value and returning early (`send_notice`) on refusal.
- The block that inserts into `session.subscriptions` (line ~1319) and calls
  `save_subscriptions` (line ~1329) both reference `filters` — the **rebound,
  gated** value — and sit textually after both gates, with no path from either
  gate's early return into the insert block.

Confirmed by reading, not merely by comment: because both refusal branches
`return` before the insert block, a refused subscription structurally never
reaches `session.subscriptions`, so `broadcast.rs`'s live-match path (which
reads only what is stored there) cannot later deliver against a raw,
un-gated filter. This is a control-flow proof rather than a runtime
observation — an executed scratch test exercising `broadcast_event` against a
live `SessionsHandler` would need the Durable Object / `worker-rs` runtime,
which is not available to `cargo test` outside `wrangler`; the producer's own
evidence notes the same limitation for these D1/DO shells.

```
$ cargo test -p nostr-bbs-relay-worker --lib req_gate_ordering_tests
```

```
test relay_do::nip_handlers::req_gate_ordering_tests::an_unauthenticated_sealed_dm_subscription_yields_no_filter_to_store ... ok
test relay_do::nip_handlers::req_gate_ordering_tests::the_gated_filter_differs_from_the_raw_one_and_binds_the_recipient ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**VERIFIED FIXED** — `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1296` (protected_read_blocked gate), `:1308` (kind-1059 gate), `:1319-1331` (insert/save use the gated `filters`).

### Fix 2 — `12a10da`: per-event protected-read gate on all three read paths

Read `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` and
`nip42.rs`. `nip42::protected_read_permitted` is called from exactly one place,
`authorize_event` (`nip_handlers.rs:1667`), which is itself called from three
sites: the historical REQ delivery loop (`nip_handlers.rs:1350`), the COUNT
delivery loop (`nip_handlers.rs:1821`), and the live broadcast path
(`broadcast.rs:114`) — confirmed all three resolve to the same function, not
three re-implementations that could drift.

Added a temporary test to `nip42.rs`'s existing
`protected_read_permitted_tests` module (reverted with `git checkout` after
the run; `git status --short` clean afterwards) simulating `REQ ["s", {}]`
(no `kinds`, so both filter-level gates pass it) reaching the per-event gate
for kind 1059 (gift wrap), 4 (encrypted DM) and 30910 (moderation), from an
unauthenticated session in `Nip42` mode:

```
$ cargo test -p nostr-bbs-relay-worker --lib protected_read_permitted_tests
```

```
test relay_do::nip42::protected_read_permitted_tests::a_gift_wrap_with_several_recipients_serves_each_of_them ... ok
test relay_do::nip42::protected_read_permitted_tests::a_stranger_receives_no_correspondence_in_either_mode ... ok
test relay_do::nip42::protected_read_permitted_tests::auditor_probe_kinds_absent_filter_from_anon_socket_is_still_gated_per_event ... ok
test relay_do::nip42::protected_read_permitted_tests::an_anonymous_viewer_receives_no_correspondence ... ok
test relay_do::nip42::protected_read_permitted_tests::moderation_kinds_need_only_authentication_and_only_in_nip42 ... ok
test relay_do::nip42::protected_read_permitted_tests::the_correspondence_set_is_exactly_the_dm_kinds ... ok
test relay_do::nip42::protected_read_permitted_tests::recipient_matching_is_case_insensitive ... ok
test relay_do::nip42::protected_read_permitted_tests::unprotected_kinds_are_untouched ... ok
test relay_do::nip42::protected_read_permitted_tests::the_recipient_and_the_author_both_receive_their_correspondence ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

(The 8 pre-existing `protected_read_permitted_tests`, unmodified, also match
the producer's evidence exactly, including the existing
`an_anonymous_viewer_receives_no_correspondence` and
`moderation_kinds_need_only_authentication_and_only_in_nip42`, which already
cover this scenario for kinds 4/13/14/1059 and 30910-30916 respectively — the
auditor's added test is a redundant, independently-authored confirmation of
the same claim, not new ground.)

**VERIFIED FIXED** — `crates/nostr-bbs-relay-worker/src/relay_do/nip42.rs:85-104` (`protected_read_permitted`), called from `nip_handlers.rs:1649-1675` (`authorize_event`), itself called at `nip_handlers.rs:1350` (historical REQ), `nip_handlers.rs:1821` (COUNT), `broadcast.rs:114` (live broadcast).

## Not covered by this receipt

- **agentbox `broker-bridge` posting both stages, and the
  `authority.receipt-post-failed` / `authority.deny` journal records.** Owned by
  the agentbox substrate.
- **VisionClaw `ElevationActor` TTL, boot reconciliation and the `expired`
  receipt.** Owned by VisionClaw. This repository contributes only the `expired`
  stage in the shared vocabulary.
- **An executed HTTP round trip against the endpoint.** The handler's D1 shell
  (a `SELECT`, a compare-and-swap `UPDATE` guarded on the current stage) runs
  only under `wrangler`; `activation_status` is `inactive`.
