---
id: ADR-2019
title: The member wallet shows the identity key's BLAKE2b testnet4 coins read-only, beside the one sidestr chain
date: 2026-09-30
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 7def3e4e74e92fdf2f29416ce08ae6dadc878c8d
owner: jjohare
review_trigger: a BLAKE2b testnet4 address backend the operator runs (Knots-blake2b node plus electrs and the blaketest shim, or an address index in bitcoin-blake/blaketestnode) answering from the forum's origin; blaketestnode running in the browser with an address index; a sidestr chain for this estate sealed beside txbt4 (agentbox ADR-2103); any proposal to sign a parent-chain spend in the forum; a BLAKE2b parent with value
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2019 — The member wallet shows the identity key's BLAKE2b testnet4 coins read-only, beside the one sidestr chain

## Context

ADR-2015 D1 locks the wallet to one chain (`sidestr:dreamlab`, parent `tbtc4`) and one asset, and
its review trigger fires on any proposal to add a chain. The operator asked for a BLAKE testnet token
in members' wallets. Upstream (sidestr/spec 0.0.6) seals every example chain beside `txbt4`, the
Knots BLAKE2b fork of testnet4 (fork height 150,308), and bitcoin-blake/blaketest already treats a
Nostr key as a `txbt4` wallet: the x-only key is the taproot program, so the npub and the `tb1p`
address are one key. So every member already holds a `txbt4` address; nothing shows it. The coin
there is the parent chain's own, not a sidestr asset. The estate's only node (`192.168.2.27:48332`,
Bitcoin Core 30.3.0, stock testnet4) follows the SHA-256d branch past the fork, so it cannot answer.

## Decision

1. **The wallet shows one parent coin, read-only.** With `SIDESTR_WALLET` on and a new
   `BLAKE_TESTNET_API` set (`https://` only, an Esplora-shaped base URL), `/wallet` shows the signed-in
   key's confirmed and unconfirmed `txbt4` balance and its `tb1p` address, labelled "BLAKE2b testnet4
   (no value)". The address is derived from the session pubkey (`OP_1 <x-only key>`, untweaked, as
   blaketest does; bech32m `tb1p` through the `bitcoin` crate, no hand-written encoder); no secret
   key is read. Unset, nothing is shown and nothing is fetched.
2. **This is not a second chain in the lock.** ADR-2015 D1 still governs everything the wallet
   validates, builds or signs: one sidestr chain, one asset. The `txbt4` figure comes from a backend
   the operator names, is not validated in the browser, and is shown as that backend's answer (the pair side of D5 is a second hop: the backend's word about another API's word). D2's
   identity-key-as-wallet departure is unchanged in scope: the key already controls those coins
   whether or not the forum shows them, and both chains are testnet.
3. **The forum never signs a parent-chain spend.** Moving `txbt4` coins is done in blaketest (linked
   with `?api=` set to the same backend; blaketest holds its own key, so there is no address to
   prefill) or a Knots BLAKE2b wallet. Parent spends need `SIGHASH_UNIFIED` (0x21)
   and a different signing path from sidestr spends; the browser-signer proposal likewise excludes
   parent transactions. Adding a send path reopens this record.
4. **The backend follows upstream, not a bespoke API.** The forum reads Esplora's `address/:a` (the
   route blaketest reads its balance from; `chain_stats` and `mempool_stats`, funded minus spent) and,
   for D5, blaketestnode's `address/:a/pair`. An answer about any other address is refused. Preferred backend: bitcoin-blake/blaketestnode with
   `run --address-index`, proposed upstream as bitcoin-blake/blaketestnode PR #1 (2026-09-30), which
   serves those routes from the node's own validated UTXO set. Fallback: a Knots 29.4.1 BLAKE2b
   testnet4 node with jasonsopko/electrs (`blake2b` branch) and `blaketest/shim/server.mjs`.
   `mempool.guide` is not a conforming backend: it follows a dead release-candidate chain.
5. **Both branches, one address.** The two testnet4 chains share every block up to 150,307, and an
   address is the same string on both, so a key made before the fork owns the same coins on both
   until each is spent. With the same backend run with `--pair-api` (an Esplora API on stock
   testnet4), `/address/:a/pair` gives what is only on BLAKE2b, only on stock testnet4, and unspent on
   both. A backend without `--pair-api` answers 404 and the split is simply not shown. The wallet
   shows that split as it comes, in either direction, so a member arriving from
   either chain sees their coins on the other; coins on both are marked as spendable on both, since
   a spend signed without `SIGHASH_UNIFIED` is valid on each. Still read-only (D3).

## Consequences

Members see a coin they already hold, with no new key, no new chain in the validated lock and no
new signing surface. The price is trust: the `txbt4` balance is whatever the named backend says,
unlike the DREAM balance, which the tab replays. When blaketestnode runs in the browser with an
address index, the figure can be validated in the tab and D2 of this record should say so.
The forum side is built (`crates/nostr-bbs-forum-client/src/wallet/parent.rs` and one card on
`/wallet`). What it waits on is the backend: a new service on the operator's hardware, which does not
exist yet, and the `BLAKE_TESTNET_API` entry in `window.__ENV__` through the operator overlay's
`deploy.yml`. If this estate seals a sidestr chain beside `txbt4` (agentbox ADR-2103, amendment of
2026-09-30), members could peg these coins into it, and that chain entering the wallet reopens
ADR-2015 D1.

**Key handling.** This record adds none. It reads the session's public key only; the identity key
standing as the wallet key is ADR-2015 D2's testnet-scoped departure from agentbox ADR-2101 D3 (signer
and identity keys independent), unchanged in scope here because nothing is signed.

## Verification

Accepted 2026-10-02 on the owner's ruling (a canonical feature; no users, no money, no legal risk).
Built and staged: the view is in the client and off until a deployment sets both `SIDESTR_WALLET`
and `BLAKE_TESTNET_API`, and it reaches members when the website kit pin moves past the merge.
Live activation further needs a conforming backend, which the estate does not run yet.

Ratification evidence, `wallet::parent::tests` (7 tests): the `tb1p` address of secret keys 1 and 3
matches bitcoin-blake/blaketest `bitcoin.js` `getTaprootAddress` at gh-pages `df14e48`
(`tb1p0xlxvlhem…47zagq`, `tb1plycg5qvj…wq2wgh`), and pays the same `5120<key>` script as the sidestr
wallet; invalid and off-curve keys have no address; `BLAKE_TESTNET_API` unset, empty, bare or
`http://` yields no base, so the page makes no request; an Esplora answer reads as confirmed and
unconfirmed sats and is refused for another address; a blaketestnode `/pair` answer (shape of
`lib/pair.mjs` `comparePair`, blaketestnode PR #1, merged 2026-09-30) splits into only-BLAKE2b,
only-stock and both. Outstanding: a live read against the operator's backend matching
`blaketest?api=<same base>`, once one runs.

Evidence gathered 2026-09-30: `getblockhash 150308` on the estate node
returns `0000000000cf9d15…`, not the BLAKE2b fork hash `000000000000b9d1…` (sidestr/spec
`siding/lib/parents.mjs`), so it is on the SHA-256d branch; `getnetworkinfo` reports
`/Satoshi:30.3.0/`. blaketestnode `d2764d2` `lib/api.mjs` routes only `/tip`, `/mempool`,
`/template` and outpoint lookup; PR #1 adds the address and pair routes with 24 checks (`test/address-test.mjs`), and `mempool.space/testnet4` passes its fork check (base `…a57b1cc` at 150,307, `…0f91302d` at 150,308).
