---
id: ADR-2013
title: The ontology-governance panel activates Promote, adds Demote, and expires proposals rather than re-surfacing them forever
date: 2026-09-22
decision_status: accepted
implementation_status: partial
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: b45c672b5bc73e5858f03490aa212d7e15526742
owner: jjohare
review_trigger: the `vault` binary (VisionClaw WS-C) landing, or the first real 31402 raised against the `ontology-governance` panel on the production relay
repo: nostr-rust-forum
---

# ADR-2013 — The ontology-governance panel activates Promote, adds Demote, and expires proposals rather than re-surfacing them forever

## Context

`DecisionOutcome::Promote { pattern_id }` has existed since the broker aggregate was written and has never had a producer or a consumer: the 31403 projection published only `{action, reasoning}`, so nothing wrote a `pattern_id` and nothing read one (`docs/prd/prd-gap-close-forum.md:77`). VisionFlow `PRD-sovereign-corpus` §3.3 gives it its first real consumer — a human-signed corpus promotion — and that consumer addresses its subject by OKF `resource` IRI, not by a pattern id. The same PRD requires the inverse (`Demote`), requires schema-level proposals to be floored at tier `High` (§2 Q7), and requires a 14-day `stale_after` on every `PatchProposal` after which the proposal is no longer safe to apply because the corpus has moved on beneath it. [ADR-2011](ADR-2011-operator-task-properties-set-the-escalation-boundary.md) already supplies the tiering machinery and an `expired` side receipt that nothing yet writes; [ADR-2010](ADR-2010-durable-governance-outcome-receipts.md) supplies the ladder.

## Decision

1. **`Promote` carries an IRI.** `DecisionOutcome::Promote { iri: String }`, and the new `DecisionOutcome::Demote { iri: String }` beside it. This is not a rename of a value anyone held — `pattern_id` had no writer and no reader — so there is no migration and no compatibility alias. Both outcomes carry the IRI **redundantly** with the 31402's `context_url` tag, deliberately: the signed human decision must name its subject inside its own signed bytes, so the apply path cannot be pointed at a different page by a later edit to the request. A `promote` or `demote` body with no `iri` does not parse and is refused rather than parked. `Promote` reaches `CaseState::Promoted` as it always did; `Demote` reaches `CaseState::Decided` and gets no state of its own, because nothing branches on one — the outcome in `broker_decisions.outcome` is what the apply path reads.

2. **The `ontology-governance` panel is a named profile, not a new protocol.** `nostr_bbs_core::ontology_governance` holds one 31400 `PanelDefinition` (`d = ontology-governance`), three request tags (`context_url`, `digest`, `level`), and nothing else. The panel's operator declaration is `verifiability: partial`, `reversibility: reversible`, `stakes: significant`, and `max_pending_hours: 336` — fourteen days, matching the `stale_after` a `PatchProposal` carries, so the escalate-on-age receipt and the expiry sweep land at the same moment rather than a day either side of it. Its actions are `promote | demote | reject`; there is deliberately no `approve`, because a bare approval carries no subject for the apply path to act on.

3. **A schema-level proposal is floored at `High` by a *property*, not by a tier.** `level: schema` or `level: demotion` contributes `stakes: critical` to the ADR-2011 merge, whose `tier_floor()` is `High`. Declaring a tier directly would be an agent setting its own boundary — precisely what the tightening-only merge exists to prevent — whereas a property is merged with `max()` and can only ever raise it. It also puts the *reason* in `broker_cases.tp_stakes`, so a reviewer sees why a case is `High` rather than only that it is. An unrecognised or absent `level` falls back to `content`, the loosest, for the reason `Verifiability::parse` falls back to the loosest: a misspelling loses this profile's extra floor and keeps the panel's, rather than escaping oversight. Combined with ADR-2011 §4, this is what reserves every corpus schema write for a person: a reasoner stamping `system:whelk-gate` cannot resolve the case however well its gate ran.

4. **Expiry closes a case; ageing does not.** A 31402 carrying a `level` tag has its `PatchProposal`'s `stale_after` copied onto `broker_cases.stale_after` at projection time (migration 0007, mirrored in `ensure_schema()`), and a new `expire_stale_proposals` cron sweep closes every still-pending case past it — `CaseState::Closed`, **without a decision**, with an `expired` side receipt saying why and no `broker_decisions` row, because nobody decided anything. This is a different sweep from `escalate_stale_cases` and deliberately so: ageing answers "nobody has looked at this yet" and leaves the case open so somebody still can; expiry answers "this diff no longer describes the page" and must stop the apply. Both receipts routinely land on the same case, in that order, and the history then reads "surfaced, then expired unattended", which is the true story. The receipt is written **before** the close, so a partial failure leaves a visibly-wrong pending case that the next tick retries, rather than a silently-closed case with nothing saying why.

5. **A `stale_after` is only honoured on a request that declared a `level`.** Reading it off any 31402 would let an unrelated agent give its own case a self-serving deadline. An unreadable `stale_after` yields `None` and leaves the case out of the sweep entirely — it still ages, so it is not lost, but it is never closed on a guess.

## Consequences

- The ontology promotion loop is wired end to end and testable without a corpus: `scripts/e2e-ontology-promotion.sh` signs real 31402/31403 events, asserts the `High` floor, runs the relay's own projection and expiry SQL against SQLite loaded from this repository's migrations, and drives agentbox's apply path against a stub `vault`.
- `nostr-bbs-core` gains an RFC 3339 parser (`ontology_governance::parse_rfc3339_utc`). It exists because the crate compiles to `wasm32-unknown-unknown` for the relay worker and carries no calendar dependency; it is deliberately narrow (the profile `vault propose` and `Date#toISOString` emit), refuses anything else rather than guessing, and is tested against offsets, fractional seconds and leap years. A guessed expiry closes a case a human was still reading.
- A published `nostr-bbs-core` gains a new public module and a **breaking** change to `DecisionOutcome`. The crate is `1.0.0-beta.11`; the variant had no users, but the enum is `pub` and the next release note must say so.
- `Demote` is the only decision that may be raised about an already-stable subject. Nothing in this ADR enforces that — the proposer does, by only raising a demotion against a `status: stable` page. Making it a relay rule would require the relay to read the corpus, which it must not.
- The panel is **staged, not live**: the 31400 is defined in code and no operator has published it. Until one does, no 31402 resolves to it and every ontology proposal falls back to its own declaration and the relay's advertised default. Publishing it is the activation step.

## Verification

`implementation_status: partial` — the forum's half is complete and green; the apply path it hands to is agentbox's (ADR-2109) and the corpus it writes to is WS-C's `vault`, which does not exist yet.

At `verified_commit`:

- `cargo test -p nostr-bbs-core --lib` — 413 pre-existing + 14 new `ontology_governance` tests pass. They cover the `High` floor for `schema`/`demotion`, `content` contributing no floor, the loosest-fallback on an unrecognised `level`, the panel's actions and deadline, `stale_after` parsing including the refusals, and the strict-inequality expiry predicate. `the_panel_alone_does_not_floor_a_content_case_at_high` is the falsification target: if the panel itself declared `Critical`, the `level` rule would be untestable theatre.
- `cargo test -p nostr-bbs-relay-worker --lib` — 306 pass, including 10 new `ontology_governance_boundary_tests`: the floor surviving an agent's `risk-tier: low`, a content proposal *not* being floored, `stale_after` ignored on a request with no `level`, `promote`/`demote` projecting with the signed IRI as `outcome_detail`, a subjectless `promote` refused, and `a_reasoner_may_not_promote_a_schema_level_page`.
- `cargo clippy -p nostr-bbs-core -p nostr-bbs-relay-worker --all-targets` — no warnings. `cargo fmt --all` clean.
- `scripts/e2e-ontology-promotion.sh` — 29 assertions, exit 0, including the expiry sweep closing the past-due fixture with an `expired` receipt and **zero** `broker_decisions` rows, the promoted case *not* being swept, and the sweep's idempotency.
- Migration 0007 and its `ensure_schema()` mirror both add `broker_cases.stale_after`; the e2e loads every migration in `wrangler` order, so a column added to one and not the other fails there.
