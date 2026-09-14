---
expectation_id: EXP-AC-006
git_sha: c2e4ef7e54a0df9065c54a5784a433082d08c80d
produced_by: agent:claude-opus
produced_at: 2026-09-14T15:42:05Z
audited_by:
---

# Evidence — EXP-AC-006

Executed against `c2e4ef7e54a0df9065c54a5784a433082d08c80d` on branch `feat/augmentation-conditions`. Every command
below was run; the output is this run's, trimmed to the assertion lines.


## Scenario 1 — deterministic calibration sampling within the stated band

```
$ cargo test -p nostr-bbs-core --lib governance::calibration_tests
```

```
test governance::calibration_tests::degenerate_rates_are_total ... ok
test governance::calibration_tests::out_of_range_policy_values_fall_back ... ok
test governance::calibration_tests::panel_policy_defaults_and_overrides ... ok
test governance::calibration_tests::panel_without_probe_agent_honours_no_probe ... ok
test governance::calibration_tests::higher_rate_is_a_superset ... ok
test governance::calibration_tests::sampling_rate_lands_within_the_expected_band ... ok
test governance::calibration_tests::sampling_is_deterministic_per_request_id ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 376 filtered out; finished in 0.01s
```

**Verdict: PASS.** 7 tests, 0 failures. `sampling_rate_lands_within_the_expected_band`
asserts that of 1,000 fixed request ids at rate `0.1`, between 80 and 120 are
sampled — the band EXP-AC-006 states. Because the ids are fixed and the
selection is `sha256(request_id)`, the test is deterministic rather than lucky.
`sampling_is_deterministic_per_request_id` asks the same id six times and
requires the same answer, which is the observable form of the counter-example
EXP-AC-006 names: sampling must not depend on the wall clock. Nothing in
`is_calibration_sample` reads a clock.

## Scenario 2 — sampled requests are not member-suppressed

```
$ cargo test -p nostr-bbs-relay-worker --lib augmentation_boundary_tests
```

```
test relay_do::nip_handlers::augmentation_boundary_tests::a_calibration_sample_is_not_suppressed ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::a_delegation_alone_does_not_admit_a_non_reviewer ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::admin_decides_any_case ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::a_system_actor_cannot_decide_a_high_or_critical_case ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::max_pending_hours_comes_from_the_panel_or_the_default ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::declared_tier_reads_from_tag_or_content ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::high_and_critical_require_a_human ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::a_legacy_case_without_an_effective_tier_is_unaffected ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::a_human_decides_a_high_case_normally ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::a_system_actor_may_decide_a_medium_case ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::only_suppressible_cases_are_sampled ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::probe_is_honoured_only_from_the_registered_probe_agent ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::request_tag_cannot_loosen_the_panel_declaration ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::opaque_work_floors_at_medium_and_is_shown ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::request_tag_may_tighten_the_panel_declaration ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::reviewer_with_a_delegation_is_admitted ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::resolver_defaults_to_the_human_signer ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::reviewer_without_a_delegation_is_refused ... ok
test relay_do::nip_handlers::augmentation_boundary_tests::unlabelled_request_projects_with_the_advertised_default ... ok
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 249 filtered out; finished in 0.00s
```

**Verdict: PASS.** `a_calibration_sample_is_not_suppressed` asserts a sampled
`Low` case has `is_member_suppressed_effective == false`.
`only_suppressible_cases_are_sampled` pins that a case already shown is not
marked, so the `calibration_shown` denominator is not inflated with cases nobody
chose to show.

## Scenario 3 — delegation admission

Same run as scenario 2. `reviewer_without_a_delegation_is_refused` is the
counter-example EXP-AC-006 names ("a reviewer deciding a case not delegated to
them"); `reviewer_with_a_delegation_is_admitted` and
`a_delegation_alone_does_not_admit_a_non_reviewer` pin that both halves are
required, so a stale delegation row cannot promote an ordinary member.
Scoping to one case is enforced by the `(case_id, delegate_pubkey)` key and the
gate's `WHERE case_id = ?1` lookup. The admin's delegation stays in the chain:
`record_case_delegation` keeps `delegated_by` and the delegating `decision_id`.

## Scenario 4 — probe blindness and the reviewer read model

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

**Verdict: PARTIAL — see below.** `a_probe_is_withheld_from_every_undecided_case`
and `a_probe_is_revealed_once_the_case_is_decided` pin the redaction in the REST
projection; `probe_is_honoured_only_from_the_registered_probe_agent` (relay run,
scenario 2) pins that an unregistered agent's `probe` tag is dropped rather than
recorded. The reviewer read model is pinned by
`decisions_time_to_decision_and_override_rate`,
`calibration_and_probe_columns`, `superseded_decisions_are_counted` and
`a_negative_time_to_decision_is_discarded`; every field EXP-AC-006 lists
(`decisions`, `median_ttd_ms`, `p90_ttd_ms`, `override_rate`, `superseded`,
`calibration_shown`, `calibration_decided`, `probes_seen`, `probes_caught`) is on
`ReviewerStats`. Relay `accepted_at` is preferred over the signed timestamp for
time-to-decision, per the expectation and DDD §9 issue 1.

## Honest gap — probe blindness on the raw signed event

**The `probe` tag is NOT removed from the raw signed 31402 served over REQ.**
Migration `0006` keeps it out of `event_tags` (so no client can enumerate probes
by subscription) and `case_json` withholds it from every REST projection of an
undecided case, but the signed envelope still carries it. Stripping a tag from a
signed event invalidates the signature that both clients verify strictly
(`verify_event_strict`), which would make the probe vanish from the queue
entirely rather than render blind — the opposite of what FR6.4 asks for. The
catch-rate metric therefore assumes reviewers read the rendered surface and not
raw relay events. This is recorded as ADR-2011's `review_trigger` and is why its
`implementation_status` is `partial`. deepsec independently raised the same gap
in the final run.

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

- **The forum client hiding the tag until decided (FR6.4's rendering half).**
  Owned by the forum-client agent; this branch does not touch that crate.
- **VisionClaw `CaseView.createdAt` and oldest-first queue ordering**, and the
  **dream-cycle ledger `Reviewer` / `Review-minutes` columns.** Other substrates.
