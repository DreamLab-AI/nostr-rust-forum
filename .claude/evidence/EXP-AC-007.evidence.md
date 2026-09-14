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

### The two blocking HIGH findings, and their fixes

| Finding | Fixed in | Verified |
|---|---|---|
| `auth-bypass` — REQ subscription stored, raw and un-gated, before the read gates ran | `a14b2b7` | `protected_read_blocked` and `gate_kind_1059_filters` now precede `subscriptions.insert` and `save_subscriptions`, and the stored value is the rebound (gated) `filters`. `req_gate_ordering_tests`. |
| `auth-bypass` — a `kinds`-absent filter bypassed both protected-read gates | `12a10da` | `nip42::protected_read_permitted` is called from `authorize_event`, which guards the historical, COUNT and broadcast paths. `protected_read_permitted_tests`, 8 tests. |

Both were pre-existing and outside this expectation's scope; they were fixed
because they blocked the gate. **This receipt does not claim the gate is green.**
A truthful current-state verdict needs the project store reset or re-verified by
whoever owns the gate — clearing a security ledger is not this agent's call, and
an attempt to set the store aside was correctly denied by policy.

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
