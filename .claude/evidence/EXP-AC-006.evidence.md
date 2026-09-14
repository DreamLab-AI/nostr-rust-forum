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

## Not covered by this receipt

- **The forum client hiding the tag until decided (FR6.4's rendering half).**
  Owned by the forum-client agent; this branch does not touch that crate.
- **VisionClaw `CaseView.createdAt` and oldest-first queue ordering**, and the
  **dream-cycle ledger `Reviewer` / `Review-minutes` columns.** Other substrates.
