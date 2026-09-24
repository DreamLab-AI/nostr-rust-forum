---
id: ADR-2015
title: Every member's key is a wallet on sidestr:dreamlab (testnet4 only), DREAM is the one asset, and tips are chain records
date: 2026-09-24
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: b2d9e14407b5d3d768596fa970a709815602d424
owner: jjohare
review_trigger: any proposal to add a chain or asset to the lock; a chain with value (a mainnet parent); ADR-2101's derived spend key being implemented; DREAM moving to a chain whose document names the assets rule; JavaScriptSolidServer gaining sidestr support (then the wallet moves upstream)
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2015 — Every member's key is a wallet on sidestr:dreamlab (testnet4 only), DREAM is the one asset, and tips are chain records

## Context

The operator wants every forum member to hold a wallet on the estate's sidestr chain, limited to
testnet4 and a DreamLab token, so members can provision other members and agents, and can tip each
other's comments. JavaScriptSolidServer (upstream of solid-pod-rs, at `e7e0525`, package `0.0.220`)
has no sidestr code, so the feature cannot land upstream-first. It goes in this kit, off by default.
ADR-2012 already settled that the chain is the ledger and the forum keeps no balance of its own. On a
sidestr chain a Nostr key's coins pay `OP_1 <x-only key>`, so every member's npub is already an
address. `sidestr:dreamlab` names no SPEC 12 rules, so an issued asset there is held to the rule by
the clients that read it, not by the producer.

## Decision

1. **One chain, one asset, compiled in.** The client pins `sidestr:dreamlab`'s sealed document
   (`src/wallet/sidestr-dreamlab.chain.json`), refuses it unless its id, its `tbtc4` parent and its
   genesis hash match the constants in `src/wallet/chain.rs`, and knows one asset: DREAM,
   `issue:DREAM:0` at txid `608005d3…b978a9`, block 372, supply 1,000,000. Runtime config
   (`window.__ENV__`) may set `SIDESTR_WALLET` (off unless `on`, `true` or `1`), `SIDESTR_MIRROR`
   (`https://` only) and `SIDESTR_RELAYS` (`wss://` only). It cannot name another chain or asset.
2. **The identity key is the wallet, on this testnet chain only.** A member's receive script is
   `5120‖pubkey`, so anyone can pay anyone by npub, with nothing for the recipient to set up. This is
   a deliberate, scoped departure from agentbox ADR-2101 D3 (derived spend keys), which is proposed
   and unimplemented. The price of D3 is that a member must publish a binding before they can be
   paid, and that contradicts "every member has a wallet". The lock in D1 confines the departure to
   a chain whose coins have no value. Any chain with value reopens this ADR.
3. **The browser validates the chain itself.** The client downloads the mirror's `blocks.dat` and
   replays every block against the pinned document (`sidestr_core::mirror`). It reads DREAM under
   the SPEC 12 assets rule as a view (`sidestr_core::assets::AssetView`). No forum worker serves a
   balance, and none is added.
4. **Signing stays in the browser.** Spends are built and signed with `sidestr-wallet` /
   `sidestr-agent` (published, `default-features = false`, wasm32) using the session key. That key
   is a passkey or local key, or, for a member signed in through a NIP-07 extension, a key unlocked
   for this tab only. An unlocked key must match the signed-in pubkey, lives in memory, and is
   cleared on sign-out. Transactions travel as kind-23500 events to the public relays the producer
   follows, signed by a throwaway key: a transaction authorises itself (SPEC 11), as in the
   reference wallet, so the member's key signs only the spend.
5. **Tips are chain records, not forum events.** A tip is a DREAM transfer to the author's script,
   carrying a `tip:nostr:<event id>` record beside its tally. A post's total is what the chain says,
   so it is the same for everyone who replays it. This repo adds no event kind (ADR-2012 D3 holds).
   The tip control lives in the reaction row, so every surface that shows reactions offers it.
6. **Provisioning is one transaction.** A "starter pack" carries DREAM (on a 330-sat carrier) and
   plain sats (for the recipient's fees). It goes to a member or a registered agent by npub. The
   `sidestr-agent faucet` answers kind-23501 requests the same way, once per script per day.
7. **Coins that carry DREAM are never spent as plain sats.** Plain payments select only coins the
   view reads as carrying nothing. Every built transfer is checked against the view before it is
   signed.
8. **An extension that signs spends is used before a pasted key** (added 2026-09-24). When the
   member has no key in the tab and `window.nostr.sidestr` offers `version >= 1` (sidestr spec
   `proposals/browser-signer.md`; reference signer Podkey), the spend is built unsigned from the
   member's public key (`sidestr_wallet::external::ExternalSigner`, sidestr-wallet 0.4.1), the bare
   transaction goes to `signTransaction({ chain, tx })`, and the answer is taken only when its txid
   is the one built and every input verifies under the parent family's sighash against the coins
   this tab built from (`external::accept_signed`, prevouts from `chain::prevouts_for`). The
   extension resolves and validates the chain itself and asks the member every time; the page
   never sees the key. The extension's error codes read as plain sentences
   (`wallet::extension::explain`). The nsec unlock remains only as the fallback for an extension
   without the method.

## Consequences

Members get a wallet with no sign-up step, and a deployment that does not set `SIDESTR_WALLET` sees
no change at all: no nav item, no tip control, no download. With it on, the first view of a page
with posts downloads and validates the chain once per session (about 116 KB, 367 blocks at the time
of writing), and the WASM bundle grows by about 0.43 MB. That is with libsecp256k1's low-memory
tables; without them it is 1.5 MB. DREAM is only as safe as its readers. A wallet that ignores the
assets rule can destroy DREAM by spending a carrier, so the UI warns members to move DREAM only from
here. The whole chain holds about 30,000 sats, and each transfer costs about 200 in fees. Fees
collect at the signer and have to be recycled into the faucet. More supply needs a peg-in from a
wallet other than the peg holders' own (sidestr/spec issue 15). The pending list lives in
localStorage per member and self-heals: a transaction the chain never shows releases its coins
after 30 minutes. When JSS gains sidestr support, the wallet should move upstream and this module
should follow it.

## Verification

- Browser-signer path (D8, branch `browser-signer`): `cargo test -p nostr-bbs-forum-client`: 475
  pass. `wallet::chain::tests::browser_signer` builds the treasury's DREAM pack from its public key
  alone on the live fixture, accepts a validly signed answer (same txid, same vsize as the
  placeholder sized it), and refuses swapped signatures, another key's signatures, a different
  transaction signed validly, an answer still unsigned, and a coin that is not the member's.
  sidestr-rs `9f9efff5` publishes sidestr-wallet 0.4.1 with `external` and 7 unit tests of its own.

- `cargo test -p nostr-bbs-forum-client`: 462 pass. `wallet::chain` replays the live chain fixture
  (`src/wallet/testdata/blocks.dat`) and finds DREAM's supply at the treasury, with no transaction
  read as broken.
- `cargo clippy -p nostr-bbs-forum-client --target wasm32-unknown-unknown`: clean.
- sidestr-rs `f4b95047` (sidestr-core 0.3.1, sidestr-wallet 0.4.0, sidestr-agent 0.3.0, published):
  `sidestr-wallet/tests/assets_on_chain.rs` runs issue, tip and a plain payment through
  `State::submit` and replays the block file to the same balances.
- Live chain: DREAM issued by the treasury, txid `608005d3…b978a9`, mined at height 372 on
  `sidestr:dreamlab`.
- `grep -rn "SIDESTR_WALLET" crates/nostr-bbs-forum-client/src` shows the one gate in
  `src/wallet/mod.rs`. Every surface goes through `wallet::enabled()` or `use_wallet()`.
