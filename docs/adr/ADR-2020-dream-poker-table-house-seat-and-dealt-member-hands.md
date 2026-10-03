---
id: ADR-2020
title: Play poker for DREAM against a house seat that holds its own key, and between members with the house dealing; settle each hand with one chain transfer
date: 2026-10-03
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit:
owner: jjohare
review_trigger: a chain with value behind the table; a second operator running a house seat; mental poker or a hitch channel replacing the house as dealer; any proposal to add a forum event kind for hands or settlements; the daily cap or buy-ins moving above what the treasury's plain sats can settle
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2020 — Play poker for DREAM against a house seat that holds its own key, and between members with the house dealing; settle each hand with one chain transfer

## Context

The practice table (2026-10-02) runs the Libre Poker engine in the browser for chips worth nothing;
its settlement rules (`wallet::poker`) were written but not wired, because money against a bot the
browser drives is unsound: the browser holds the bot's cards and the bot's key. ADR-2012 D3 forbids a
forum ledger or event kind for value; ADR-2015 makes every member's key a wallet on `sidestr:dreamlab`
with DREAM as the one asset, tips as chain records. The operator asked for DREAM play, scheduled game
times on the calendar, and invitations to real players.

## Decision

1. **One shared crate, two engines of one truth.** `nostr-bbs-poker` carries the engine and the house
   bots as a Rust port of `libre-poker/engine` 564d4c3 (byte-identical JSON; `tests/differential.rs`
   holds 160 recorded hands, 378 decisions and 400 evaluations to the JavaScript), the fair deal, the
   settlement rules moved from the client, the HAND.md record, the member↔house protocol and a replay
   verifier over an abstract engine. The browser keeps the vendored JavaScript for play and verifies
   with it; the house seat runs the Rust port.
2. **A house seat that holds the hand and its own key.** `nostr-bbs-poker-citizen` (native service;
   pure table state machine, ledger and chain scan compile for wasm32) deals every DREAM hand, plays
   the bot under the derived per-step seed, and sends each member only their seat view. The deck is
   `sha256(secret ‖ nonces…)`: the house commits before anyone sits, each player adds a nonce. When
   the hand ends the secret, record and root go to each player, who replays the hand and checks every
   house action against `bots::decide`; the browser also requires its own nonce in the seed.
3. **Members play each other with the house dealing.** A member challenges another the offer lists as
   present; the opponent accepts with a nonce; the house deals and holds no seat. Replay verification
   skips the house-play check (`house_seat: None`).
4. **Settlement is one DREAM transfer per hand, `hand:<root>` beside the tally**, from the loser to the
   winner (`rules::settlement`): the member's browser signs its own from the wallet at once; the house
   signs its own with its key through the local producer. No forum event kind, no ledger: the chain is
   the ledger (ADR-2012). The house keeps a small JSON book of what is not yet on the chain, refuses
   to deal to a member who owes for a hand the chain has not shown paid (a reported transfer id buys a
   grace period), and stops paying out at a daily cap.
5. **Transport is NIP-59 gift wrap of rumor kind 20779** (Libre Poker's table kind) on the forum relay,
   so DM inboxes never show a hand; `nostr-bbs-core` gift wrap takes the rumor kind as a parameter.
   The relay's recipient-whitelist gate means the house key must be whitelisted.
6. **Scheduled games are NIP-52 events (kind 31923) tagged `poker`** with invited members as `p`
   participants (`core::CalendarEventSpec`), created under the relay's existing admin/mod gate, and
   each invitee gets a NIP-17 DM with the time and the table's link. The events page links a poker
   event to the table.
7. **Gates unchanged, one more.** The table still needs `POKER`, the wallet and the member's own
   preference; the DREAM table also needs `POKER_CONFIG.citizen_pubkey`. Testnet only (ADR-2015 D1).

## Consequences

Members can lose and win DREAM; the house is the operator's agent and the daily cap bounds its
exposure to a cheating client (a member who refuses to pay is refused further hands; a payment the
chain never shows reinstates the debt). Each settlement costs the payer about 200 sats of fee from a
chain holding ~30,000; the faucet's sats and the house's plain coins are the real limit on play, and
fees collect at the producer to be recycled. The house sees both members' cards when it deals for
them: it is a trusted dealer, not mental poker. Two services must agree on protocol `VERSION`; the kit
pin moves them together. The practice table is unchanged for an instance without a house seat.

## Verification

- `cargo test -p nostr-bbs-poker`: 50 pass (44 unit, 5 differential against the JavaScript
  fixtures, 1 doc). `cargo test -p nostr-bbs-poker-citizen`: 11 pass, including a full house hand and
  a full two-member hand driven through the state machine, each replay-verified, debts, cap and lapse.
- `cargo test -p nostr-bbs-forum-client`: 586 pass; `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` and `cargo fmt --all -- --check` clean; `cargo check --target
  wasm32-unknown-unknown` for the two new crates clean.
- `grep -rn RUMOR_KIND crates/` shows the one transport constant; `grep -rn citizen_pubkey
  crates/nostr-bbs-forum-client/src` shows the one extra gate.
