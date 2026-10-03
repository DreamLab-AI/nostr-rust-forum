---
id: ADR-2021
title: Pin two sidestr chains — sidestr:dreamlab and sidestr:dreamlab-txbt4 — with one wallet store and one asset table per chain
date: 2026-10-03
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 0ca3ff7d020af09918c74e32becc15ccc8d41337
owner: jjohare
review_trigger: any proposal to pin a third chain or to let runtime config name a chain; a chain with value (a mainnet parent); BLAKES7's issue landing (its id goes into SIDESTR_CHAINS and the txbt4 house seat's --asset-id, not into the code); poker protocol 2 naming the asset on the wire; sidestr-agent gaining a family-generic ChainView (the client and house seat drop their ChainState)
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2021 — Pin two sidestr chains — sidestr:dreamlab and sidestr:dreamlab-txbt4 — with one wallet store and one asset table per chain

## Context

ADR-2015 D1 locked the wallet to one chain (`sidestr:dreamlab`, beside testnet4) and one asset
(DREAM); ADR-2020 settles the poker table on it through one house seat. The estate sealed a second
chain on 2026-10-02, `sidestr:dreamlab-txbt4` beside BLAKE2b testnet4 (`txbt4`; genesis
`1009aa29…d108`, prefix `drt`), for the agent-payments demo, with its own asset, BLAKES7, issued
later. A chain beside `txbt4` inherits the BLAKE2b header family: Knots' 164-byte v2 headers and the
unified sighash, which `sidestr_agent::ChainView` (stock headers only) cannot replay. The operator
asked for the wallet and the poker table to work on both chains at once.

## Decision

1. **Two chains in the lock, both compiled in, none from config.** `wallet/chain.rs` holds a `Pin`
   per chain — id, parent, genesis, address prefix and the sealed document byte for byte as its
   producer serves it — in `PINS`. `sidestr:dreamlab`'s pin and constants are unchanged.
   `check_document` refuses any document whose id, parent or genesis differs from its pin. Runtime
   config chooses which pinned chains are offered and how each is reached; it cannot add a chain.
2. **The replay follows the parent's header family.** The client and the house seat replay through
   `StateOf<F>` for `F: HeaderFamily`, dispatched by the document's parent: sidestr-core's `Stock`
   beside `tbtc4`, sidestr-header's `Blake2bV2` beside `txbt4` (already compiled in through
   sidestr-agent, so the wasm gains no dependency). Signing already follows the family
   (`sidestr-wallet` reads the sighash rules from the document's parent).
3. **Chain profiles from `window.__ENV__.SIDESTR_CHAINS`.** A JSON array (string or object) of
   `{ id, mirror?, asset_id?, ticker?, label?, citizen_pubkey?, relays? }`, in offer order
   (`wallet/profile.rs`). An entry naming an unpinned chain, a duplicate, or a field that does not
   read (a mirror that is not `https://`, an asset id that is not 64 hex digits) is ignored with a
   console warning, and the pin's default stands. Absent, or naming no pinned chain, the wallet is
   exactly ADR-2015's. `SIDESTR_MIRROR` and `SIDESTR_RELAYS` keep applying to `sidestr:dreamlab`
   where its entry does not set its own. DREAM's id stays the compiled default for
   `sidestr:dreamlab`; `sidestr:dreamlab-txbt4` has no compiled asset id, and until the env names
   BLAKES7's it shows sats only and offers no poker table.
4. **One wallet store per chain.** Snapshot, pending list, held coins and session unlock are per
   chain; pending lists persist under `sidestr.pending.<chain id>.<owner>` (dreamlab's earlier
   `sidestr.pending.<owner>` is moved across once). The member's chosen chain is kept in the
   preferences (`wallet_chain`); `/wallet` shows a switcher with each chain's ticker and parent, and
   says which chain's balance it shows. Faucet requests, sends, tips, starter packs and extension
   signing go through the chosen chain's store with that chain's id, document, relays and address
   prefix. One key is one script on both chains; each chain writes its own address (`drm1…`,
   `drt1…`), and an address under either prefix pays that script (sidestr-wallet's rule).
5. **One asset table per chain with an asset and a house seat.** `[poker] citizens = { "<chain id>"
   = "<hex>" }` names each house seat; the scalar `citizen_pubkey` still works and means
   `sidestr:dreamlab` (if both name it they must agree). `POKER_CONFIG` carries `citizens` (the
   scalar folded in) beside the legacy `citizen_pubkey`. The client resolves a chain's house seat
   from `citizens`, then the chain's `SIDESTR_CHAINS` `citizen_pubkey`, then (dreamlab only) the
   scalar. `/table` shows a tab per table ("DREAM table", "BLAKES7 table"), each a `LiveStore` bound
   to that chain's wallet store and house seat, opened by its `#sidestr-<name>` fragment; one table
   is open at a time, so one inbox and one set of shortcuts are live. Settlement memos and the
   wallet's `hand:<root>` matching are per chain because the stores are.
6. **One house seat per chain.** `nostr-bbs-poker-citizen` takes `--chain-id` (default
   `sidestr:dreamlab`), `--asset-id` (DREAM's id by default there, required elsewhere) and
   `--ticker`. The producer's `/chain.json` must equal the chain's pinned document field for field,
   and blocks replay against the compiled copy. Two instances run, each with its own key and
   ledger. Poker protocol 1 is unchanged: its one asset tag, `dream`, names the house seat's chain
   asset, and a browser only ever sends it to the house seat of the table it sat at.
7. **Scheduled games name their chain.** The calendar event carries `["chain", "<id>"]`
   (`CalendarEventSpec::extra_tags`, which skips the builder's own tag names); the schedule modal
   offers the chain when more than one table runs, and the events page links to that table's
   section.

## Consequences

The same member key now holds coins on two testnet chains, and a member can tip, send and play in
either asset; ADR-2015 D2's identity-key-as-wallet departure extends to the second chain on the same
testnet-only terms. A second chain is a second download and replay, made only when the member opens
it. The client and the house seat each carry a small `ChainState` enum until sidestr-agent offers a
family-generic view; the pinned documents are duplicated into the house seat's crate. Activating
BLAKES7 is configuration, not code: its issue txid goes into `SIDESTR_CHAINS` and the second house
seat's `--asset-id`, and its key into `[poker] citizens`. `POKER_CONFIG` gains a key, so a
deployment that mirrors it by hand must add `"citizens":{…}`. A third chain needs a new pin and this
record revisited. The `sidestr:dreamlab-txbt4` document says it is not anchored (no checkpoints in
`txbt4` at the seal): until checkpoints are on, its blocks are the single signer's word, which the
wallet validates but cannot strengthen.

## Verification

- `cargo test -p nostr-bbs-forum-client`: 607 pass, among them the txbt4 chain replayed to block 26
  under `Blake2bV2` (`testdata/txbt4-blocks.dat`, the producer's file on 2026-10-03), each chain's
  blocks refused by the other's lock, a txbt4 document with a wrong genesis, parent or id refused
  (`a_txbt4_document_that_is_not_the_pinned_one_is_refused`), `SIDESTR_CHAINS` entries naming
  unknown chains ignored (`entries_naming_unknown_chains_are_ignored`), per-chain pending keys, and
  one asset table per chain with an asset and a house seat.
- `cargo test -p nostr-bbs-poker-citizen`: 14 pass, among them the flags (`select`), a producer
  document that differs from the sealed one in any field refused, and both chains scanned under
  their families. Smoke run against the live producers: `:3450` with the defaults, `:3451` with
  `--chain-id sidestr:dreamlab-txbt4` (26 BLAKE2b blocks), and `:3450` refused for the txbt4 chain.
- `cargo test -p nostr-bbs-config` (the `citizens` map, its projection and checks) and `cargo test
  -p nostr-bbs-core` (`extra_tags` written, the builder's own names never forged).
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D
  warnings`, `cargo test --workspace` and `cargo check -p nostr-bbs-forum-client --target
  wasm32-unknown-unknown` clean on branch `multichain`.
