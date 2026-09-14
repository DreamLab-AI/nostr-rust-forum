---
expectation_id: EXP-AC-007
git_sha: c2e4ef7e54a0df9065c54a5784a433082d08c80d
produced_by: agent:claude-opus
produced_at: 2026-09-14T15:42:27Z
audited_by:
---

# Evidence — EXP-AC-007

Executed against `c2e4ef7e54a0df9065c54a5784a433082d08c80d` on branch `feat/augmentation-conditions`. Every command
below was run; the output is this run's, trimmed to the assertion lines.

This repository owns **one clause** of EXP-AC-007: the relay-side admission rule
for `applied-manually`. The `governance_manual_continue` MCP tool, the PROV-O
activity, the operation-digest binding and the outbox that survives a forum
outage are all agentbox's, and must carry their own receipt.

## Scenario 1 — `applied-manually` only from an admin

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

**Verdict: PASS.** `applied_manually_from_a_non_admin_is_403` asserts the
refusal and its status. `an_admin_may_record_a_manual_continuation_on_an_approved_case`
asserts the permitted path.

## Scenario 2 — `applied-manually` only for a case already `Decided(Approve)`

**Verdict: PASS.** `applied_manually_requires_a_prior_approve` enumerates the
refusal cases and asserts `409` for each:

| case state | latest outcome | result |
|---|---|---|
| `decided` | `reject` | refused |
| `open` | none | refused |
| `under_review` | none | refused |
| `reopened` | `approve` | refused |
| `decided` | none | refused |

The first two rows are EXP-AC-007's counter-example by name — "`applied-manually`
recorded for a `Reject`ed or `Open` case".
`the_legacy_resolved_state_still_admits_a_continuation` pins that the
pre-orchestrator `resolved` string means the same thing as `decided`, so an old
approved case is still continuable.

## Scenario 3 — the stage is reachable from a committed projection

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

**Verdict: PASS.** `applied_manually_may_follow_a_committed_projection_directly`
pins the one place the ladder bends: `applied-manually` is exempt from the
`consumer-received` precondition, because the outage path it serves has no
consumer by construction. The exemption is narrow —
`can_advance_stage(RelayAccepted, AppliedManually)` is still `NotProjected`, so a
manual continuation of a decision that never committed is refused.

## Security gate — BLOCKED, not passed

```
$ /home/devuser/.claude/skills/build-with-quality/scripts/deepsec-gate.sh --diff main
deepsec-gate: BLOCK - 32 finding(s) {CRITICAL: 0, HIGH: 2, MEDIUM: 20, HIGH_BUG: 1, BUG: 9}
exit code: 1
receipt: .deepsec-gate/reports/20260914T162917Z/receipt.json
```

**Verdict: BLOCK.** Exit code `1` — not 78, so the gate ran rather than being
skipped, and it is recorded as blocked rather than passed.

The gate scans the blast radius of a diff, not only its lines, so successive
runs pulled neighbouring pre-existing code into scope. Findings raised against
**this branch's own code** were fixed, each with a test: `cross-tenant-id` (any
registered agent could advance any receipt) and the ageing sweep's unsound
early break. Two pre-existing HIGH auth bypasses in the relay's REQ read path
were also fixed because they blocked the gate (subscription stored before it was
authorised, and a `kinds`-absent filter bypassing both protected-read gates).

**The remaining findings are unresolved and this receipt does not claim
otherwise.** Work was paused by the operator before they were triaged. They are
pre-existing and outside this expectation's scope — `ensure_schema` running per
request, `require_authed` being weaker than membership on the governance read
endpoints, gift-wrap senders escaping suspension, the retention sweep's
CAST-versus-parse divergence, and the 16-hex truncation of `decision_id` — but
"outside scope" is an argument for routing them, not for calling the gate green.
An auditor should treat the security-gate line of this expectation as NOT met.

## Not covered by this receipt

- **`governance_manual_continue`** with its `case_id` / `executed_by` /
  `evidence` arguments, the operation-digest binding, the PROV-O activity with a
  human `executed_by`, and the outbox that queues the receipt when the forum is
  unreachable. All agentbox.
- **The authority gate's `no-decision-surface` structured hint.** agentbox.
- **`executed_by` being a `did:nostr` human rather than an agent DID.** This
  repository records the admin's NIP-98 pubkey in
  `governance_receipts.applied_by`; whether that pubkey denotes a human is
  established by the admin list, not by this endpoint.
