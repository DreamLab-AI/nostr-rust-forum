---
expectation_id: EXP-AC-003
git_sha: 81aa0d9
produced_by: agent:claude-opus
produced_at: 2026-09-14T15:42:05Z
audited_by: agent:claude-sonnet-5 (degraded: same family as producer; codex GPT-6 Astra unavailable — bwrap sandbox refused in container)
audited_at: 2026-09-14T19:30:00Z
auditor_verdict: CONFIRMED
auditor_counter_examples_attempted: 4
auditor_counter_examples_found: 0
---

# Evidence — EXP-AC-003

Executed against `c2e4ef7e54a0df9065c54a5784a433082d08c80d` on branch `feat/augmentation-conditions`. Every command
below was run; the output is this run's, trimmed to the assertion lines.


## Scenario 1 — the triple, the tightening-only merge and the effective-tier table

The tightening-only property is checked by **enumeration, not sampling**: the
triple space is 3x3x3, so all 27x27 = 729 (panel, request) pairs are asserted.
The effective-tier table is checked over the whole triple space crossed with
every declared tier including absence.

```
$ cargo test -p nostr-bbs-core --lib governance::task_property_tests
```

```
test governance::task_property_tests::critical_stakes_is_never_member_suppressed ... ok
test governance::task_property_tests::absent_tags_parse_to_none_not_loosest ... ok
test governance::task_property_tests::declared_tier_without_properties_stands_alone ... ok
test governance::task_property_tests::calibration_sample_overrides_suppression ... ok
test governance::task_property_tests::effective_tier_table_holds_for_every_triple_and_tier ... ok
test governance::task_property_tests::partial_tags_default_the_missing_legs ... ok
test governance::task_property_tests::properties_without_tier_respect_advertised_default ... ok
test governance::task_property_tests::tags_round_trip ... ok
test governance::task_property_tests::request_cannot_lower_irreversible_to_reversible ... ok
test governance::task_property_tests::unknown_tag_value_cannot_loosen ... ok
test governance::task_property_tests::merge_is_tightening_only_over_all_729_pairs ... ok
test governance::task_property_tests::unlabelled_request_folds_to_advertised_default ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 371 filtered out; finished in 0.00s
```

**Verdict: PASS.** 12 tests, 0 failures. `merge_is_tightening_only_over_all_729_pairs`
asserts `checked == 729`. Both EXP-AC-003 counter-examples are named tests:
`request_cannot_lower_irreversible_to_reversible` and
`critical_stakes_is_never_member_suppressed`.

## Scenario 2 — relay projection, default folding, and the human-resolution gate

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

**Verdict: PASS.** 19 tests, 0 failures. Covers: an unlabelled 31402 projecting
with the advertised default (`unlabelled_request_projects_with_the_advertised_default`,
over three different advertised defaults); a request tag failing to loosen and
succeeding to tighten the panel declaration; `opaque` flooring at medium and
never being suppressed; and the third counter-example —
`a_system_actor_cannot_decide_a_high_or_critical_case` asserts that a 31403
carrying `decided_by: system:whelk-gate` is refused for both `high` and
`critical`, while `a_human_decides_a_high_case_normally` and
`a_system_actor_may_decide_a_medium_case` pin that the guard is about the tier
rather than about disliking automation.

## Scenario 3 — legacy events parse to the default

`absent_tags_parse_to_none_not_loosest` (scenario 1) pins that a legacy event
with no `tp-*` tag parses to `None` rather than to a declared-loosest triple —
the distinction that lets `effective_tier` fall back to the advertised default.
`a_legacy_case_without_an_effective_tier_is_unaffected` (scenario 2) pins that a
case projected before migration 0006 is not retro-gated on a tier nobody computed.

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

Cross-family audit degraded to same-family (see frontmatter). Probes run as a
temporary `tests/audit_scratch_probes.rs` in `nostr-bbs-core`, deleted after
the run (`git status --short` clean afterwards). All probes target
`effective_tier`/`TaskProperties::merge` directly, calling the same pure
functions the producer's own tests call, but with adversarial inputs the
producer's test names do not name.

```
$ cargo test -p nostr-bbs-core --test audit_scratch_probes
```

```
test probe_applied_manually_from_relay_accepted_is_not_projected ... ok
test probe_calibration_negative_and_nan_rate_sample_nothing ... ok
test probe_calibration_rate_zero_selects_none_rate_one_selects_all ... ok
test probe_critical_stakes_plus_declared_low_is_at_least_high ... ok
test probe_calibration_sampling_determinism_same_id_same_result ... ok
test probe_irreversible_plus_declared_low_is_at_least_high ... ok
test probe_merge_request_looser_than_panel_on_all_three_axes ... ok
test probe_receipt_regression_applied_to_consumer_received_is_rejected ... ok
test probe_opaque_plus_declared_low_is_at_least_medium_not_suppressed ... ok
test probe_unlabelled_request_folds_to_env_absent_default ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

- `merge(panel=Opaque/Irreversible/Critical, request=Inspectable/Reversible/Bounded)`
  did **not** loosen any leg — matches `merge_is_tightening_only_over_all_729_pairs`
  but exercised as a single adversarial case rather than the enumeration.
- `effective_tier` with `Opaque` verifiability and a *declared* `Low` tier
  returned `≥ Medium` and `is_member_suppressed_effective` was `false` — the
  declared tier cannot pull the floor back down.
- `effective_tier` with `Irreversible` and declared `Low` returned `≥ High`;
  same for `Critical` stakes and declared `Low`.
- Fully unlabelled request (`None, None, None`) folded to exactly the
  advertised default for all four `RiskTier` values, not to an accidental
  `Medium`.
- `can_advance_stage(Applied, ConsumerReceived)` and
  `can_advance_stage(RelayAccepted, AppliedManually)` were both rejected, as
  the ADR's ladder requires.
- Calibration sampling was deterministic across 20 repeats of the same
  request id, rate 0 selected none of 5 fixed ids, rate 1 selected all of
  them, and a negative or NaN rate selected none.

**No counter-example found.** All four attempted counter-examples (looser
merge, Opaque-suppressed-by-declared-Low, Irreversible-suppressed-by-declared-Low,
unlabelled-not-folding-to-default) failed to materialise; the code held.

**Verdict: CONFIRMED.**

## Not covered by this receipt

- **agentbox `governance_request_action` derivation from `authority_class`.**
  Out of this repository. EXP-AC-003's agentbox clause is owned by the agentbox
  substrate and must carry its own evidence.
- **Live projection against a deployed D1.** `activation_status` is `inactive`;
  nothing here has been deployed. The D1 shells around the pure seams above are
  a paged `SELECT` and an `INSERT OR IGNORE`, exercised only by deployment.
