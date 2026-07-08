# P1 Evidence — COM-17 / F4+F5 Decision Integrity (WP-3)

**Item:** COM-17 / F4 (ack-confirmed publish) + F5 (decisions read API + panel schema)
**Wave:** P1
**Work package:** WP-3 (PRD `prd-gap-close-forum.md`), ADR-106 Decision 5
**Target maturity:** `integrated`
**Branch:** `gap-close/2026-07`
**Working-tree SHA at verification:** `fb78268` (pre-commit)
**Date:** 2026-07-08

## Falsification statement (authored before the code)

> WP-3 is falsified if a relay-rejected decision still reads as "Sent", if
> `publish` is still called fire-and-forget on the governance path, if the
> decisions read route is absent while `broker_decisions` holds rows, or if the
> panel shows no confidence at decision time.

## What was built

Per ADR-106 Decision 5 ("replace optimistic send with `publish_with_ack`; add a
tenth governance route for decision reads"):

1. **Ack-confirmed publish — forum-client (F4).**
   `crates/nostr-bbs-forum-client/src/pages/governance.rs`: both governance
   publish sites — the `PanelCard` action buttons and the `ActionRow`
   Approve/Reject — replaced the fire-and-forget `relay.publish(&signed)` +
   immediate `sent.set(true)` with `relay.publish_with_ack(&signed, Some(ack))`.
   The on-OK callback (`crate::relay::PublishCallback`) advances the UI state:
   - `accepted == true` → `sent` / `response_sent` set true ("✓ Sent" / "Response
     sent"). The state advances **only** on the relay OK, never on sign.
   - `accepted == false` → a new `rejected` / `response_rejected` state; `sent`
     stays false so the control re-enables and the reader sees a retryable
     failure ("⚠ Retry" on a panel button, "⚠ Rejected by relay — retry" under
     the action row). A `publish_with_ack` transport error raises the same
     rejection state.
   Between sign and ack the control shows the loading state (Pending), matching
   the `PublishOutcome::{Sent, Rejected, Pending}` value object (DDD §5). This
   mirrors the seven write paths already on `publish_with_ack` (`rsvp_buttons.rs`,
   `thread.rs`, `settings.rs`, …); the governance path was the outlier.

2. **Decision-audit read API — auth-worker (F5).**
   `crates/nostr-bbs-auth-worker/src/governance_api.rs` adds the **tenth**
   governance route, `GET /api/governance/decisions` (`handle_list_decisions`),
   mirroring `handle_list_cases`: same `require_authed` (NIP-98) gate, same
   `relay_db` (`RELAY_DB`) binding, newest-first over `broker_decisions`. It adds
   pagination (`?limit=`, clamped `1..=200`, default 100; `?offset=`) and an
   optional `?case_id=` filter, driven by a pure `parse_decisions_query` helper
   (unit-tested — the handler itself is Env/D1-bound, so the query contract is
   split out the same way `normalize_provision` is). `DecisionRow` returns the
   full audit shape: `outcome`, `outcome_detail`, `reasoning`,
   `prior_decision_id`. Route registered in
   `crates/nostr-bbs-auth-worker/src/lib.rs` beside the `cases` routes; the
   module doc table now lists ten routes.

3. **Panel schema — confidence + risk_tier at decision time (F5).**
   - `crates/nostr-bbs-core/src/governance.rs`: `ActionRequest` (the 31402
     content) gains `#[serde(default)] risk_tier: Option<RiskTier>` and
     `#[serde(default)] confidence: Option<f32>` — additive, backward-compatible
     with legacy requests.
   - `crates/nostr-bbs-forum-client/src/stores/panel_registry.rs`: `ActionEntry`
     gains `confidence: Option<f32>` and `risk_tier: Option<String>`, populated
     in `ingest_event` from the parsed 31402 (`req.confidence`,
     `req.risk_tier`) — sourced from the ActionRequest, never inferred.
   - `pages/governance.rs`: `ActionRow` renders the agent's stated `risk` +
     `confidence` on a decision-context line so a human sees them before
     responding.

## Why each falsification clause fails to hold

- *"a relay-rejected decision still reads as 'Sent'"* — the `publish_with_ack`
  callback sets `sent`/`response_sent` only on `accepted == true`; on
  `accepted == false` it sets the rejection state and leaves `sent` false, so a
  rejected 31403 reads as retryable, not sent. Verified by inspection: the only
  writers of the sent signals are inside the `if accepted` arm.
- *"`publish` is still called fire-and-forget on the governance path"* —
  `grep -n '\.publish(&' pages/governance.rs` returns nothing; both sites now
  call `publish_with_ack` (`grep -c publish_with_ack` = 2).
- *"the decisions read route is absent while `broker_decisions` holds rows"* —
  `GET /api/governance/decisions` exists (`lib.rs:521`) and reads
  `broker_decisions`. The relay's orchestrator projection (WP-4) is what fills
  that table; this route reads it back. `parse_decisions_query` tests prove the
  pagination/filter contract.
- *"the panel shows no confidence at decision time"* — `ActionEntry` carries
  `confidence` from the 31402 and `ActionRow` renders it; core tests
  `action_request_carries_risk_tier_and_confidence` and
  `legacy_action_request_defaults_tier_and_confidence_to_none` prove the field
  parses (and that legacy requests default cleanly).

## Receipts

### R1 — decisions read-API parser (auth-worker)

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T12:51:27Z
$ cargo test -p nostr-bbs-auth-worker governance_api
test governance_api::tests::decisions_query_defaults_when_empty ... ok
test governance_api::tests::decisions_query_reads_case_id_limit_offset ... ok
test governance_api::tests::decisions_query_clamps_limit_and_ignores_junk ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 174 filtered out
```

### R2 — full auth-worker suite (no regression from the new route)

```
$ cargo test -p nostr-bbs-auth-worker --lib
test result: ok. 186 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

(Baseline before this slice: 183. The three new tests are the decisions-query
parser.)

### R3 — core schema tests (confidence + risk_tier on the ActionRequest)

```
$ cargo test -p nostr-bbs-core governance
running 38 tests
...
test governance::tests::action_request_carries_risk_tier_and_confidence ... ok
test governance::tests::legacy_action_request_defaults_tier_and_confidence_to_none ... ok
test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured; 269 filtered out
```

### R4 — forum-client compiles clean (native check) with the ack path + schema

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T12:51:32Z
$ cargo check -p nostr-bbs-forum-client
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 27.08s
```

The `wasm32-unknown-unknown` target hits an unrelated local `secp256k1-sys` C
toolchain failure (`gnu/stubs-32.h` not found — a nix cross-compile issue in the
C dependency, not this slice's Rust). Reproduced this session; native
`cargo check` is the repo's documented equivalent (see P0 evidence R3) and is
clean.

## Canaries

Both canaries observe a **forum-side wire** and are observed in unit tests where
the wire is reachable without a live deployment; the cross-substrate live fire
is via the Nostr tap at sprint end.

### `forum-canary-ack-reject`

- **Wire observed:** a relay-rejected 31403 (`OK false`) flips the UI out of
  "Sent" through the `publish_with_ack` callback.
- **State: `pending-live-session`.** The callback wiring is `integrated` and
  compile-verified; firing needs a deployed relay to emit `OK …=false` for a
  signed 31403 and an authed member session to observe the rejection state.
  Registration for the live session is **config** (VisionClaw harness Nostr tap
  on the governance relay + a member session); this forum-only slice cannot
  stand up the live relay-reject from this container. The optimistic-send
  illusion is closed in code (no `sent` write outside the `accepted` arm).

### `forum-canary-decisions-read`

- **Wire observed:** `GET /api/governance/decisions` returns a persisted
  `broker_decisions` row to an authed operator.
- **State: `pending-live-session`.** The route + pagination are `integrated` and
  unit-verified; firing needs the deployed auth-worker with the `RELAY_DB`
  binding and at least one persisted decision (written by the WP-4 projection).
  Live fire via the Nostr-tapped harness session at sprint end.

## Honest maturity

- **F4 ack-confirmed publish:** `integrated` — both governance publish sites on
  `publish_with_ack`, rejection state wired, native check clean.
- **F5 decisions read API:** `integrated` — tenth route added, pagination
  unit-tested, gated identically to `handle_list_cases`.
- **F5 panel schema:** `integrated` — `confidence`/`risk_tier` on the
  ActionRequest and ActionEntry, rendered at decision time.
- **Live canaries:** `pending-live-session` (deployment dependency), per DDD §10.

## Files touched

- `crates/nostr-bbs-core/src/governance.rs` (RiskTier + ActionRequest fields)
- `crates/nostr-bbs-auth-worker/src/governance_api.rs` (decisions route + parser + tests)
- `crates/nostr-bbs-auth-worker/src/lib.rs` (route dispatch)
- `crates/nostr-bbs-forum-client/src/stores/panel_registry.rs` (ActionEntry schema)
- `crates/nostr-bbs-forum-client/src/pages/governance.rs` (publish_with_ack + decision-context display)
- `docs/gap-close-evidence/P1-COM-17.md` (this file)
