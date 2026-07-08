# P0 Evidence — COM-13/F2 Agent Disclosure Badge (WP-2)

**Item:** COM-13 / F2 (agent disclosure badge)
**Wave:** P0
**Work package:** WP-2 (PRD `prd-gap-close-forum.md`), ADR-106 Decision 3
**Target maturity:** `integrated`
**Branch:** `gap-close/2026-07`
**Working-tree SHA at verification:** `15755e0` (pre-commit)
**Date:** 2026-07-08

## Falsification statement (authored before the code)

> WP-2 is falsified if any agent-authored item (author pubkey active in
> `agent_registry`) renders without a badge, if a human item renders a badge,
> or if the badge's principal is read from event content rather than the
> registry.

## What was built

Per ADR-106 Decision 3 ("the disclosure badge sources the authorising
principal from the registry, never from event content"):

1. **Public read endpoint — relay-worker.**
   `crates/nostr-bbs-relay-worker/src/agent_disclosure.rs` adds
   `GET /api/agents/disclosure` (public, no auth), returning the minimal
   active-agent set `{ pubkey, name, registered_by }`.
   - The existing `GET /api/governance/agents` (auth-worker) was **not** reused:
     it is NIP-98-gated (`require_authed`) and lists ALL agents (active +
     inactive) with the full column set. A disclosure badge must render for any
     reader, including unauthenticated visitors browsing posts, and needs only
     the active set and the three public fields — so a lighter public endpoint
     is the correct surface.
   - The endpoint lives on the relay-worker because `agent_registry` is
     physically in that worker's own D1 (`DB` binding) and the relay-worker
     already serves the public read surface the client uses
     (`relay_api_base()` → `/api/check-whitelist`). It follows the
     `whitelist.rs` public-read idiom (`crate::cors::json_response`).
   - Route registered in `crates/nostr-bbs-relay-worker/src/lib.rs` (module
     decl + `route()` dispatch beside the other public reads).
   - SQL filters `WHERE active = 1`; a pure `active_disclosures()` projection
     re-asserts the active-only + minimal-field contract and is unit-tested.

2. **Client component — forum-client.**
   `crates/nostr-bbs-forum-client/src/components/agent_badge.rs`:
   - `provide_agent_disclosure()` — one fetch of the active set for the whole
     page (wired at the app root, `app.rs`), cached in a Leptos context. Fails
     open: a fetch error leaves the map empty, so a missing disclosure renders
     no badge rather than a wrong one.
   - `AgentBadge` component — reactive lookup; renders nothing for a human
     (pubkey absent from the active registry) and a visually distinct blue
     `AGENT · <principal>` pill for an active agent, with the authorising
     principal (`registered_by`) resolved to a human label via the shared
     profile cache. Follows the existing `Badge` / `use_display_name_tracked`
     idioms.
   - Wired at every author-render site: the post/thread author line
     (`components/message_bubble.rs`, beside the existing `BadgeBar`), the
     governance `PanelCard` (`pages/governance.rs`, beside `agent_name`), and
     the governance `ActionRow`.

## Why each falsification clause fails to hold

- *"any agent-authored item renders without a badge"* — `AgentBadge` is mounted
  at all three author-render loci; it fires whenever the author pubkey resolves
  in the active-disclosure cache. Test `active_agent_is_disclosed_with_authorising_principal`
  proves an `active = 1` row projects to a disclosure carrying its principal.
- *"a human item renders a badge"* — the cache only holds active-registry
  pubkeys; a human pubkey misses the lookup → `None` → no badge. Tests
  `inactive_agent_is_excluded` and `empty_registry_discloses_nothing` prove the
  projection excludes non-active / absent rows.
- *"the badge's principal is read from event content"* — the principal is the
  `registered_by` column, carried from the D1 row through the endpoint into the
  client cache; no event content is consulted. Test
  `active_agent_is_disclosed_with_authorising_principal` asserts the disclosed
  principal equals the registry column verbatim;
  `disclosure_serialises_only_the_minimal_public_fields` asserts nothing else
  leaks.

## Receipts

### R1 — targeted endpoint tests (relay-worker)

```
$ date -u
Wed Jul  8 10:19:40 UTC 2026
$ cargo test -p nostr-bbs-relay-worker agent_disclosure
   Compiling nostr-bbs-relay-worker v1.0.0-beta.3
    Finished `test` profile [unoptimized + debuginfo] target(s) in 10.12s
     Running unittests src/lib.rs
running 5 tests
test agent_disclosure::tests::active_agent_is_disclosed_with_authorising_principal ... ok
test agent_disclosure::tests::disclosure_serialises_only_the_minimal_public_fields ... ok
test agent_disclosure::tests::empty_registry_discloses_nothing ... ok
test agent_disclosure::tests::inactive_agent_is_excluded ... ok
test agent_disclosure::tests::parses_d1_shaped_row_with_numeric_active ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 172 filtered out
```

### R2 — full relay-worker suite (no regression from route/module additions)

```
$ date -u
Wed Jul  8 10:20:03 UTC 2026
$ cargo test -p nostr-bbs-relay-worker
test result: ok. 177 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### R3 — forum-client compiles with the new component + wiring (native check)

```
$ date -u
Wed Jul  8 10:20:10 UTC 2026
$ cargo check -p nostr-bbs-forum-client
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 31.16s
```

A re-check after touching `agent_badge.rs` emitted zero warnings/errors from the
new code. (The `wasm32-unknown-unknown` target hits an unrelated local
secp256k1 toolchain issue per the repo recon; native `cargo check` is the
documented equivalent and is clean.)

## Canary — `forum-canary-agent-badge`

- **Wire observed:** an agent-authored item (author ∈ active `agent_registry`)
  renders an `AgentBadge` naming `registered_by`.
- **Harness:** VisionClaw `governance-decision` topology (v1.0.0, `integrated`;
  substrates `agentbox`, `nostr-rust-forum`, `visionclaw`).
- **State: `pending-live-session`.** `harness_validate` against
  `governance-decision` reports the loop requires the `agentbox` and
  `visionclaw` substrates to be addressed live: the canary fires only when a
  real agent (agentbox) publishes a governance item, an authed member session
  in the deployed forum renders the badge, and the VisionClaw sensor observes
  it. This forum-only slice owns the `nostr-rust-forum` substrate — the
  endpoint, cache, component and wiring are in place and unit-verified — but it
  cannot stand up the agentbox + visionclaw live parts from this container.
  Firing awaits a deployed live session (per PRD wave-gating and DDD §10, a
  loop item with no fired canary is `Open`, not closed; the badge mechanism is
  `integrated`, the live canary is pending).

```
$ harness_validate(topology=governance-decision, output_summary=<badge impl>)
{ "compliant": false,
  "violations": ["Topology substrates not addressed: agentbox, visionclaw"],
  "template_version": "1.0.0" }
```

This is the expected result for a single-substrate slice: the forum half of the
cross-substrate canary is complete; the agentbox + visionclaw halves are the
live-session dependency.

## Files touched

- `crates/nostr-bbs-relay-worker/src/agent_disclosure.rs` (new)
- `crates/nostr-bbs-relay-worker/src/lib.rs` (module decl + public route)
- `crates/nostr-bbs-forum-client/src/components/agent_badge.rs` (new)
- `crates/nostr-bbs-forum-client/src/components/mod.rs` (module decl)
- `crates/nostr-bbs-forum-client/src/app.rs` (provider wiring)
- `crates/nostr-bbs-forum-client/src/pages/governance.rs` (PanelCard + ActionRow badge)
- `crates/nostr-bbs-forum-client/src/components/message_bubble.rs` (author-line badge)
