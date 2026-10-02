---
id: ADR-2012
title: The pod-worker D1 ledger becomes a derived view over the sidestr chain, and solid-pod-rs moves in lockstep with the host
date: 2026-09-21
decision_status: proposed
implementation_status: partial
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 5f361e8f77c1b76b85aa9c36c2a9eeffc33ed190
owner: jjohare
review_trigger: the three-ledger equality test first passing; any change to `derive_deposit_address` or its known-answer vectors; any new route that credits a `/pay/` balance; the solid-pod-rs post-port version publishing to crates.io; any proposal to add a forum-owned event kind for value or settlement
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

**Amended 2026-10-02: the routes are live, not dormant.** This record was written and
triaged (P3, parked) as if `/pay/*` were dormant. It is not: production sets
`PAY_ENABLED = "true"` (dreamlab-ai-website `forum-config/deploy/pod-worker.wrangler.toml:53`,
beside `PAY_TOKEN_TICKER = "DREAM"`, `PAY_TOKEN_RATE = "10"`), and
`https://dreamlab-pod-api.solitary-paper-764d.workers.dev/pay/.info` answers with token
DREAM at rate 10. The dormant assumption is withdrawn. Read live, the code had three
evidence-free value paths: `POST /pay/.deposit` with `{"amount_sats": n}` credited `n` on
the caller's word; `POST /pay/.withdraw` credited sats for DREAM that no D1 balance held
or debited; the TXO path credited any confirmed output to whoever named it first, whatever
script it paid, keyed without its chain and with the txid's case preserved.

## Decision

1. **The D1 ledger is demoted to a derived, height-stamped view.** `read_balance` and the
   trait's `read_ledger` fold UTXOs read through the `sidestr-node` HTTP surface rather than
   reporting a stored number. The D1 tables become a bounded cache whose staleness bound is an
   error, not a slightly old figure. The adapter and its 28 tests survive; its authority does
   not (agentbox ADR-2099 D2).
   *Amended 2026-10-02:* until the view lands, **every D1 credit row carries an outpoint
   or a signed-request id.** The journal is `pay_credits`
   (`crates/nostr-bbs-pod-worker/src/pay_ledger.rs:110`; auth-worker migration
   `0004_pay_credits.sql`, additive): a deposit row names its chain and outpoint, a
   job-hold release row the NIP-98 event id of the request that released it, and a CHECK
   refuses a row with neither. A balance moves only in the D1 batch that writes its row,
   reading account and amount back from it (`:168`), so the view can later be checked
   row by row against the chain. Existing rows and balances are untouched.
2. **`credit_atomic` and `debit_atomic` stop being settlement.** After the cutover the only
   credit in the estate is a peg-in claim and the only debit is a chain spend
   (agentbox ADR-2099 D3). The two functions either move behind the view as cache maintenance
   or are removed with `WebLedger::credit` / `debit` upstream (solid-pod-rs ADR-2008 D5). No
   route may charge, gate or settle on the view without resolving to the chain.
   *Amended 2026-10-02:* `credit_atomic` and `D1PaymentStore` (with its `write_ledger`) are
   removed; every credit is a journalled row (D1, D6). `debit_atomic` survives as
   `pay_ledger::debit`.
3. **This repo adds no ledger of its own and no new event kind.** The forum keeps owning kinds
   31400 to 31405 and adds nothing; sidestr's kinds and the estate's `sidestr-account-binding`
   kind are registered elsewhere (agentbox ADR-2098 D2). Value does not become a forum concern.
   *Amended 2026-10-02:* the Web Ledgers teller's kinds, 30333 (the ledger) and 3700 (a
   signed request), are external: this repo may read them and never mints them. No D1
   token balance exists, so `/pay/.buy` and `/pay/.withdraw` are withdrawn (410) rather
   than given one (`pay_ledger.rs:810`).
4. **`solid-pod-rs` moves in lockstep with the host.** This repo and the host repo adopt one
   post-port `solid-pod-rs` version together, after the rust-bitcoin port and the removal of
   the ledger write API (solid-pod-rs ADR-2008 D1, D5, D8). Closing the skew is a P1 exit
   criterion, not a later tidy-up; the exact pin at `Cargo.toml:155` is bumped in the same
   change as the host's `Cargo.toml:218`.
5. **`derive_subkey` is supplied to the settlement domain as a Published Language, unchanged,
   for principal spend keys only.** *Amended 2026-10-02, per the disposition below and
   agentbox ADR-2101 D3:* the sidestr principal spend key is
   `derive_subkey(k_id, "sidestr/spend/" ‖ chain_id)`, reusing this function and its
   JS-parity vector (ADR-2003). Signer and bridge keys are independent seeds and are never
   derived from `k_id`; the earlier `"sidestr/sign/"` derivation is struck. That makes
   `crates/nostr-bbs-core/src/keys.rs:251-265` load-bearing for money as well as identity:
   its behaviour, its HMAC construction and its parity vector are frozen, and any change to
   them is a consensus-affecting change that requires the settlement owners as reviewers.
6. **A deposit is credited only on chain evidence, once, by outpoint keyed with its chain
   (the teller model).** *Added 2026-10-02.* `POST /pay/.deposit` credits a confirmed output
   only when its scriptPubKey equals the depositor's own derived deposit script
   (`pay_ledger.rs:558`), and credits it once under the receipt `txo:<chain>:<txid>:<vout>`
   with the txid lower-cased (`:369`), as solidpayorg/teller 7c00cea `credit` does ("the
   outpoint is the receipt"). The same outpoint on two chains is two receipts; a chain whose
   unit is not `sat` is refused, not credited as sats (`:637`); legacy chain-less
   `txo_deposits` rows still block a second credit and are no longer pruned. The
   evidence-free `amount_sats` credit and the DREAM withdraw credit-without-debit are
   removed, and `.buy`'s debit-for-nothing with them.
   `derive_deposit_address` is **frozen as live**: a raw additive tweak
   `Q = P + SHA256(x(P) ‖ user_x)·G`, then TapTweak on the **unlifted** `Q`, hrp `bc`; it is
   **not BIP 341** (the two differ whenever `Q` has odd y). Known answers for three
   `(MASTER_SECRET, user)` pairs, covering odd-y and even-y `Q`, were captured from the k256
   code before its port to rust-bitcoin and must pass unchanged
   (`crates/nostr-bbs-pod-worker/src/deposit_address.rs:160`). Any new scheme follows
   sidestr/spec `keys.mjs` (full points, tweaks added to the point as it is) and the teller's
   tagged, ledger-scoped tweak `tagged("webledgers/deposit", ledgerHash ‖ account ‖ nonce)`
   under a **new route**; it never changes the addresses this route has issued.

## Consequences

The forum stops being a place where a balance can exist that the chain does not know about,
which is the defect this record exists to end. The D1 write path keeps working as a cache and
its atomicity now buys consistency rather than truth, so the tests that assert a balance after
a debit have to be rewritten to assert a cache state or to resolve to the chain. A pod-worker
request now depends on `sidestr-node` reachability, and the failure mode is a refusal rather
than an optimistic charge. Lockstep pinning couples this repo's release cadence to the host's,
which is the price of one shared pod library. Freezing `derive_subkey` narrows this repo's
freedom to refactor its own key module. D6 costs a deposit one explorer round trip and the
`MASTER_SECRET` read, refuses test-coin deposits that used to be credited as sats, and
returns 410 to any client still calling `.buy` or `.withdraw`; a balance credited by the
removed paths before this change stays as it is (live state is never moved), so the journal
covers credits from this change on. Pruned `txo_deposits` rows cannot be restored: an
outpoint pruned before this change could be claimed once more, by its own address owner only.

## Verification

D6 and the D1 journal are built at `5f361e8` and verified by
`cargo test -p nostr-bbs-pod-worker`: `deposit_address_known_answers_are_frozen`,
`known_answers_cover_both_parities_of_q` and `live_construction_is_not_bip341_for_odd_q`
(`deposit_address.rs`); and handler fixtures that run the production dispatcher and SQL on
SQLite (`pay_ledger/tests.rs`): `deposit_with_amount_sats_is_refused_and_credits_nothing`,
`deposit_to_another_accounts_script_is_refused`,
`teller_credit_once_by_outpoint_at_the_derived_address`,
`the_same_outpoint_on_two_chains_is_two_receipts`,
`dream_withdraw_on_zero_balance_is_refused_and_credits_nothing`,
`every_credit_row_names_its_evidence`. Not deployed: activation stays inactive until the
pod-worker ships this commit. The rest of the record is proposed; nothing else built.
Ratification evidence will be:

- `balance(did)` identical from the forum view, from solid-pod-rs and from `sidestr-node`
  directly for 100 random DIDs, with an explicit error rather than a stale figure when the
  node is unreachable.
- `grep -n "credit_atomic\|debit_atomic" crates/nostr-bbs-pod-worker/src/payments.rs` showing
  no remaining caller on a settlement path.
- `Cargo.toml:155` and the host's `Cargo.toml:218` naming the same post-port `solid-pod-rs`
  version at the same commit.
- The `derive_subkey` JS-parity vector green at that commit, plus a known-answer test that the
  `sidestr/spend/` and `sidestr/sign/` tags derive distinct keys from the same root.

## Disposition — 2026-10-02

- **Suitability:** fits, needs revision
- **Priority:** P3 — parked (review trigger: agentbox ADR-2099 reopens, or the solid-pod-rs post-port version publishes)
- **Why:** D1 to D3 follow agentbox ADR-2099 and park with it: §9 scopes the next sidechain work to a valueless demo chain, and that chain does not need the D1 view. D5 conflicts with agentbox ADR-2101. This record derives `k_sign` from `k_id` with `derive_subkey`. ADR-2101's amended D3 and its adversarial review require signer and bridge roots to be independent seeds, never derived from `k_id`, and the live `sidestr:dreamlab` signer key is not derived from identity (agentbox ADR-2103 first seal). ADR-2101 survives. D4's facts are stale: the forum pin is now `=0.5.0-alpha.10` at `Cargo.toml:166`, not `=0.5.0-alpha.7` at `:155`, and the host is still `0.4.0-alpha.15`. Code otherwise as described at `14b9fa4` (`crates/nostr-bbs-pod-worker/src/payments.rs:148,161,183`; `crates/nostr-bbs-core/src/keys.rs:251`).
- **Next:** On reopening, restate D5 so that `derive_subkey` covers principal spend keys only, as in agentbox ADR-2101 D3, and refresh D4's pin facts.
