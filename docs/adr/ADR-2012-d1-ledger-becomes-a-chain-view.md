---
id: ADR-2012
title: The pod-worker D1 ledger becomes a derived view over the sidestr chain, and solid-pod-rs moves in lockstep with the host
date: 2026-09-21
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 64b15d5b574608c68a527c78b75a548b91f4c6e8
owner: jjohare
review_trigger: the three-ledger equality test first passing; the solid-pod-rs post-port version publishing to crates.io; any proposal to add a forum-owned event kind for value or settlement
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2012 — The pod-worker D1 ledger becomes a derived view over the sidestr chain, and solid-pod-rs moves in lockstep with the host

## Context

`crates/nostr-bbs-pod-worker/src/payments.rs` runs one of three unsynced `did:nostr`-keyed sats
ledgers in the estate. It is the best-engineered of them: `D1PaymentStore`
(`crates/nostr-bbs-pod-worker/src/payments.rs:148`) settles through single-statement SQL, with
`credit_atomic` (`:161`) and `debit_atomic` (`:183`, `UPDATE ... WHERE balance >= cost`) and a
28-test suite, while the `PaymentStore` trait's `read_ledger` (`:279`) and `write_ledger`
(`:301`) exist for trait compliance and the module itself says to prefer the atomic pair
(`:303`). Atomicity is not authority: nothing reconciles this balance with solid-pod-rs's
`WebLedger` or the host's `FsPaymentStore`, and the version pin skews
(`crates/nostr-bbs-core/Cargo.toml:41` resolving to `=0.5.0-alpha.7` at `Cargo.toml:155`,
against the host's `0.4.0-alpha.15`). `nostr-bbs-core` already supplies the estate's
HMAC-SHA256 domain-separated child derivation, `derive_subkey`
(`crates/nostr-bbs-core/src/keys.rs:251-265`). The owner decided on 2026-09-21 that the chain
is truth (PRD-024 D4).

## Decision

1. **The D1 ledger is demoted to a derived, height-stamped view.** `read_balance` and the
   trait's `read_ledger` fold UTXOs read through the `sidestr-node` HTTP surface rather than
   reporting a stored number. The D1 tables become a bounded cache whose staleness bound is an
   error, not a slightly old figure. The adapter and its 28 tests survive; its authority does
   not (agentbox ADR-2099 D2).
2. **`credit_atomic` and `debit_atomic` stop being settlement.** After the cutover the only
   credit in the estate is a peg-in claim and the only debit is a chain spend
   (agentbox ADR-2099 D3). The two functions either move behind the view as cache maintenance
   or are removed with `WebLedger::credit` / `debit` upstream (solid-pod-rs ADR-2008 D5). No
   route may charge, gate or settle on the view without resolving to the chain.
3. **This repo adds no ledger of its own and no new event kind.** The forum keeps owning kinds
   31400 to 31405 and adds nothing; sidestr's kinds and the estate's `sidestr-account-binding`
   kind are registered elsewhere (agentbox ADR-2098 D2). Value does not become a forum concern.
4. **`solid-pod-rs` moves in lockstep with the host.** This repo and the host repo adopt one
   post-port `solid-pod-rs` version together, after the rust-bitcoin port and the removal of
   the ledger write API (solid-pod-rs ADR-2008 D1, D5, D8). Closing the skew is a P1 exit
   criterion, not a later tidy-up; the exact pin at `Cargo.toml:155` is bumped in the same
   change as the host's `Cargo.toml:218`.
5. **`derive_subkey` is supplied to the settlement domain as a Published Language, unchanged.**
   agentbox ADR-2101 D3 derives the sidestr spend and signer keys as
   `derive_subkey(k_id, "sidestr/spend/" ‖ chain_id)` and
   `derive_subkey(k_id, "sidestr/sign/" ‖ chain_id)`, reusing this function and its JS-parity
   vector (ADR-2003). That makes `crates/nostr-bbs-core/src/keys.rs:251-265` load-bearing for
   money as well as identity: its behaviour, its HMAC construction and its parity vector are
   frozen, and any change to them is a consensus-affecting change that requires the settlement
   owners as reviewers.

## Consequences

The forum stops being a place where a balance can exist that the chain does not know about,
which is the defect this record exists to end. The D1 write path keeps working as a cache and
its atomicity now buys consistency rather than truth, so the tests that assert a balance after
a debit have to be rewritten to assert a cache state or to resolve to the chain. A pod-worker
request now depends on `sidestr-node` reachability, and the failure mode is a refusal rather
than an optimistic charge. Lockstep pinning couples this repo's release cadence to the host's,
which is the price of one shared pod library. Freezing `derive_subkey` narrows this repo's
freedom to refactor its own key module.

## Verification

Proposed; nothing built. Ratification evidence will be:

- `balance(did)` identical from the forum view, from solid-pod-rs and from `sidestr-node`
  directly for 100 random DIDs, with an explicit error rather than a stale figure when the
  node is unreachable.
- `grep -n "credit_atomic\|debit_atomic" crates/nostr-bbs-pod-worker/src/payments.rs` showing
  no remaining caller on a settlement path.
- `Cargo.toml:155` and the host's `Cargo.toml:218` naming the same post-port `solid-pod-rs`
  version at the same commit.
- The `derive_subkey` JS-parity vector green at that commit, plus a known-answer test that the
  `sidestr/spend/` and `sidestr/sign/` tags derive distinct keys from the same root.
