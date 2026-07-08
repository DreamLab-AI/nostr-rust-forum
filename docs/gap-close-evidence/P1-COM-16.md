# P1 Evidence — COM-16 / F3+F7 Graduated Escalation (WP-4)

**Item:** COM-16 / F3 (graduated escalation via `DecisionOrchestrator`) + F7
(risk-tier member suppression, approval-fatigue response)
**Wave:** P1
**Work package:** WP-4 (PRD `prd-gap-close-forum.md`), ADR-106 Decision 4
**Target maturity:** `integrated`
**Branch:** `gap-close/2026-07`
**Working-tree SHA at verification:** `fb78268` (pre-commit)
**Date:** 2026-07-08

## Falsification statement (authored before the code)

> WP-4 is falsified if a non-binary action still parks a case in `under_review`
> forever, if `DecisionOrchestrator` still has zero callers outside
> `nostr-bbs-core`, or if no risk tier suppresses any low-risk panel.

## What was built

Per ADR-106 Decision 4 ("consume the existing `DecisionOrchestrator`; assign
risk tier at the panel, suppress at the member Memo"):

1. **31403 projection routes through `DecisionOrchestrator::decide` — relay-worker (F3).**
   `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs`:
   `project_action_response` no longer maps action strings to ad-hoc states
   (the old `_ => "under_review"` fallback that made `delegate`/`promote`/
   `precedent` dead code). It now:
   - reads the case's `broker_cases` row + its latest `broker_decisions` id;
   - calls the pure `plan_action_response`, which parses the typed outcome
     (`DecisionOutcome::from_response_content`), hydrates a `BrokerCase`
     (`CaseSnapshot::hydrate`) and routes it through
     **`DecisionOrchestrator::decide`** (nip_handlers.rs:198 — a real caller
     outside `nostr-bbs-core`);
   - persists the decision to `broker_decisions` **with** the now-populated
     `outcome_detail` (delegate target / pattern id / precedent scope) and
     `prior_decision_id` columns, and moves `broker_cases.state` to the
     `CaseState` the orchestrator produced (`CaseState::as_str`).
   A malformed/unknown or terminal-case response yields an error and persists
   nothing — the case is left unchanged, never parked.
   The domain single-source stays in `nostr-bbs-core` (the orchestrator +
   `record_decision`, ADR-002/Decision 4); the worker adds only the D1 read/write
   shell and the hydration glue.

2. **Risk tier + member suppression — core + client (F7).**
   - `crates/nostr-bbs-core/src/governance.rs`: new `RiskTier`
     (`low`/`medium`/`high`/`critical`) value object with `is_member_suppressed`
     (only `low`) and a fail-open `parse` (unknown → `Medium`, shown). Declared
     by the agent on the 31402 `ActionRequest.risk_tier`.
   - `crates/nostr-bbs-forum-client/src/stores/panel_registry.rs`: `ActionEntry`
     carries `risk_tier`; `ActionEntry::is_member_visible()` suppresses `low`.
   - `crates/nostr-bbs-forum-client/src/pages/governance.rs`: `GovernancePage`
     gains a `member_view` prop; when `true` the actions Memo (and the count) is
     filtered by `is_member_visible()`. This is a **view filter** — the events
     stay in the store, visible on the admin surface (`member_view = false`, the
     default) and through the decisions read API. WP-1 mounts the member route
     with `member_view = true`.

3. **Lifecycle transitions (no permanent `under_review`).** The domain
   `CaseState` transitions the child PRD names are now reachable end to end:
   `approve`/`reject`/`amend` → `Decided`; `delegate` → `Delegated`; `promote` →
   `Promoted`; `precedent` → `Precedent`. At least three non-binary outcomes
   (delegate, promote, precedent) reach a matching state; none lands in
   `under_review`.

## Why each falsification clause fails to hold

- *"a non-binary action still parks a case in `under_review` forever"* — the
  `_ => "under_review"` fallback is deleted. A non-binary outcome moves through
  the orchestrator to `Delegated`/`Promoted`/`Precedent`. Tests
  `delegate_response_reaches_delegated_not_under_review` (asserts
  `!= UnderReview`) and `promote_and_precedent_reach_matching_states` prove it.
- *"`DecisionOrchestrator` still has zero callers outside `nostr-bbs-core`"* —
  `grep -rn DecisionOrchestrator crates | grep -v nostr-bbs-core` now returns
  `nip_handlers.rs` (use import + `let orch = DecisionOrchestrator;` +
  `orch.decide(...)` at line 198). The orchestrator is consumed by the relay's
  live 31403 ingest path (`handle_event` → `project_action_response` →
  `plan_action_response` → `DecisionOrchestrator::decide`).
- *"no risk tier suppresses any low-risk panel"* — `RiskTier::Low` is
  suppressed (`only_low_risk_is_member_suppressed`), `ActionEntry::is_member_visible`
  filters it, and the `GovernancePage` member Memo applies the filter. Medium
  and above (and unlabelled) stay visible (`risk_tier_parse_fails_open_to_medium`).

## Receipts

### R1 — state-machine test for the non-binary outcomes (core, WP-4 domain floor)

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T12:51:11Z
$ cargo test -p nostr-bbs-core governance
running 38 tests
...
test governance::tests::hydrate_decide_delegate_moves_case_to_delegated ... ok
test governance::tests::hydrate_decide_promote_and_precedent_reach_matching_states ... ok
test governance::tests::hydrate_decide_binary_outcomes_reach_decided ... ok
test governance::tests::hydrate_decide_links_prior_decision_id ... ok
test governance::tests::hydrate_decide_rejects_terminal_case ... ok
test governance::tests::hydrate_decide_rejects_malformed_response ... ok
test governance::tests::only_low_risk_is_member_suppressed ... ok
test governance::tests::risk_tier_parse_fails_open_to_medium ... ok
test governance::tests::non_binary_responses_parse_with_typed_detail ... ok
test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured; 269 filtered out
```

### R2 — orchestrator projection in the worker crate (relay-worker)

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T12:51:13Z
$ cargo test -p nostr-bbs-relay-worker governance_projection
test ...::governance_projection_tests::delegate_response_reaches_delegated_not_under_review ... ok
test ...::governance_projection_tests::promote_and_precedent_reach_matching_states ... ok
test ...::governance_projection_tests::binary_outcomes_reach_decided_with_no_detail ... ok
test ...::governance_projection_tests::absent_case_row_defaults_to_open_and_still_projects ... ok
test ...::governance_projection_tests::terminal_case_row_rejects_second_response ... ok
test ...::governance_projection_tests::malformed_response_is_rejected ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 177 filtered out
```

### R3 — full relay-worker suite (no regression from the projection rewrite)

```
$ cargo test -p nostr-bbs-relay-worker --lib
test result: ok. 183 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

(Baseline before this slice: 177. The six new tests are the projection planner.)

### R4 — `DecisionOrchestrator` now has a caller outside core (adversarial grep)

```
$ grep -rn 'DecisionOrchestrator' crates --include='*.rs' | grep -v nostr-bbs-core
crates/.../nip_handlers.rs:155:  ... DecisionOrchestrator, DecisionOutcome, ShareState,
crates/.../nip_handlers.rs:198:  let orch = DecisionOrchestrator;
```

## Canary — `forum-canary-escalation-outcome`

- **Wire observed:** a non-binary 31403 reaches `DecisionOrchestrator::decide`
  and persists a matching `broker_decisions` row (`outcome` = the non-binary
  action, case in the matching `CaseState`).
- **Observed in tests:** the reachability is proven in-process by
  `delegate_response_reaches_delegated_not_under_review` (worker crate) and
  `hydrate_decide_delegate_moves_case_to_delegated` (core): a `delegate` 31403
  reaches `DecisionOrchestrator::decide` and yields the persistable decision row
  + `Delegated` state.
- **State: `pending-live-session`** for the deployed wire. Firing end-to-end
  needs a deployed relay-worker with the `DB` binding to actually write the
  `broker_decisions` row on a real 31403, plus the VisionClaw harness Nostr tap
  observing it. Registration for the live session is **config** (the harness tap
  on the governance relay); the escalation lifecycle is no longer dead code — the
  orchestrator is on the live ingest path and the projection writes the outcome +
  `CaseState`. Open Issue 1 (DDD §12) on standing-monitor vs one-shot firing is
  the harness's to resolve; the forum wire is in place.

## Honest maturity

- **F3 escalation via `DecisionOrchestrator`:** `integrated` — the relay 31403
  projection consumes the tested orchestrator; delegate/promote/precedent reach
  matching `CaseState`s; `outcome_detail` + `prior_decision_id` persisted.
- **F7 risk-tier suppression:** `integrated` — `RiskTier` on the 31402, member
  Memo view-filter suppresses `low`, events remain auditable.
- **Live canary (`forum-canary-escalation-outcome`):** `pending-live-session`
  (deployed-relay dependency), per DDD §10. Reachability observed in tests.

## Files touched

- `crates/nostr-bbs-core/src/governance.rs` (RiskTier, CaseState/CaseCategory/ShareState helpers, DecisionOutcome::from_response_content/detail, CaseSnapshot::hydrate, tests)
- `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` (BrokerCaseRow, plan_action_response → DecisionOrchestrator::decide, project_action_response rewrite, tests)
- `crates/nostr-bbs-forum-client/src/stores/panel_registry.rs` (ActionEntry.risk_tier + is_member_visible)
- `crates/nostr-bbs-forum-client/src/pages/governance.rs` (GovernancePage member_view suppression)
- `docs/gap-close-evidence/P1-COM-16.md` (this file)
