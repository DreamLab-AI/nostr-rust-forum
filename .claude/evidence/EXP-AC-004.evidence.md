---
expectation_id: EXP-AC-004
git_sha: c2e4ef7e54a0df9065c54a5784a433082d08c80d
produced_by: agent:claude-opus
produced_at: 2026-09-14T15:42:05Z
audited_by:
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
