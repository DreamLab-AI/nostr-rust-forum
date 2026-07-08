# P1 Evidence — REC-6 Escalation-Default Relay Projection (WP-9)

**Item:** REC-6 share (escalation-default relay projection)
**Wave:** P1/P2 (dependency-gated)
**Work package:** WP-9 (PRD `prd-gap-close-forum.md`), ADR-106 Decision 4 (consequence)
**Target maturity (this sprint):** `scaffolded`, agentbox-gated
**Branch:** `gap-close/2026-07`
**Base SHA at verification:** `20980bc` (pre-commit)
**Date:** 2026-07-08

## Falsification statement (authored before the code, PRD WP-9)

> WP-9 is falsified if this slice invents an escalation-default schema divergent
> from agentbox's, or claims closed while no relay surface projects it.

## What was built

Per PRD WP-9 ("expose … the escalation-default schema … as a relay-side NIP-11
`nostr_bbs` block field … projected the way governance kinds are gated today")
and DDD §9 (`EscalationDefaultProjection`, `planned` → `scaffolded`,
agentbox-gated):

1. **Config surface — `crates/nostr-bbs-relay-worker/wrangler.toml`.**
   Two new `[vars]`: `ESCALATION_DEFAULT_TIER = "medium"` and
   `ESCALATION_DEFAULT_POSTURE = "escalate_to_human"`. This is the
   authority-boundary posture config the register found missing (PRD WP-9: "no
   config surface … expresses a default authority-boundary posture"). An operator
   sets it without a code change.

2. **Relay projection — `crates/nostr-bbs-relay-worker/src/nip11.rs`.**
   `relay_info` reads those vars (conservative fallbacks) and projects them in the
   NIP-11 `nostr_bbs.escalation_defaults` block via the pure
   `escalation_defaults_block(tier, posture)` helper. The block is **labelled a
   scaffold**: `status: "scaffolded"`, `schema_owner: "agentbox:REC-6"`, and a
   `note` stating the authoritative schema is agentbox's and that this reflects
   the shipped forum default until REC-6 lands. `default_escalation_tier` is
   normalised through `RiskTier::parse`, and `risk_tiers` is built from the
   `RiskTier` enum variants (`low`/`medium`/`high`/`critical`) so the projected
   vocabulary cannot drift from the forum's own value object. `registry_gated:
   true` records that the governance-*kind* form of this projection (the activated
   state) is gated identically to kinds 31400-31405.

The default tier (`medium`) means only `low` acts autonomously — exactly the tier
the member surface suppresses (`RiskTier::is_member_suppressed`), so the advertised
default and the enforced view filter stay consistent (test R1c).

## Why each falsification clause fails to hold

- *"invents an escalation-default schema divergent from agentbox's"* — the block
  does **not** define an authority model; it is explicitly `scaffolded` and
  `schema_owner: "agentbox:REC-6"`, reflecting the *shipped forum default* (the
  `RiskTier` vocabulary the forum already owns) and deferring the authoritative
  schema to agentbox. It normalises unknown tiers to the forum's own default
  rather than admitting a novel tier (test R1b), so it cannot advertise a schema
  the forum does not already model.
- *"claims closed while no relay surface projects it"* — a relay surface now
  projects it: `nip11.rs` emits `nostr_bbs.escalation_defaults` in the NIP-11
  document (test R1a). The item is claimed `scaffolded`, not `integrated` — it
  stays below `integrated` until agentbox's authority model lands (PRD maturity
  summary; DDD Invariant 5).

## Receipts

### R1 — escalation-default projection unit tests (relay-worker, native)

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-07-08T13:11:53Z
$ cargo test -p nostr-bbs-relay-worker --lib nip11
running 3 tests
test nip11::tests::escalation_block_normalises_unknown_tier_to_default ... ok
test nip11::tests::escalation_block_reflects_config_and_lists_all_risk_tiers ... ok
test nip11::tests::projected_default_matches_member_suppression_boundary ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 183 filtered out
```

- R1a `escalation_block_reflects_config_and_lists_all_risk_tiers` — the block
  carries `status`/`schema_owner`/`registry_gated`/`default_escalation_tier`/
  `default_posture` and lists all four `RiskTier` values.
- R1b `escalation_block_normalises_unknown_tier_to_default` — a junk configured
  tier folds to `medium`, so no unmodelled tier is advertised.
- R1c `projected_default_matches_member_suppression_boundary` — the shipped
  default keeps only `low` autonomous, matching `RiskTier::is_member_suppressed`.

### R2 — no relay-worker regression (full lib suite)

```
$ cargo test -p nostr-bbs-relay-worker --lib
test result: ok. 186 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

(Baseline before this slice: 183. The three new tests are the escalation block.)

## Canary

### `forum-canary-escalation-default-projection`

- **Wire observed:** the relay projects agentbox's escalation-default schema.
- **State: `deferred` (agentbox-gated).** Registered now; not expected to fire
  this wave. This slice ships the forum-side *reflection* surface (the NIP-11
  `escalation_defaults` block, config-driven and unit-verified), labelled
  `scaffolded` with `schema_owner: agentbox:REC-6`. The canary fires when agentbox's
  REC-6 authority model lands and the projected field shape aligns to it; until
  then it is a scaffold, not a claim (PRD WP-9; DDD §10).

## Honest maturity

- **REC-6 escalation-default projection:** `scaffolded`, agentbox-gated — a
  config-driven relay surface (`nostr_bbs.escalation_defaults`) projects the
  shipped forum default, schema-owned by agentbox, unit-verified, no regression.
  It is **not** claimed `integrated` (PRD maturity summary; DDD Invariant 5).

## Files touched

- `crates/nostr-bbs-relay-worker/src/nip11.rs` (`escalation_defaults_block` + projection + tests)
- `crates/nostr-bbs-relay-worker/wrangler.toml` (`ESCALATION_DEFAULT_TIER`, `ESCALATION_DEFAULT_POSTURE`)
- `docs/gap-close-evidence/P1-REC-6.md` (this file)
