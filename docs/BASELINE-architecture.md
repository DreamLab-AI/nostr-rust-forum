---
title: Architecture Baseline — nostr-rust-forum
doc_id: NRF-BASELINE
version: 0.2.0
status: draft-for-ratification
verified_commit: 0065dd9 (ADR-2030 to ADR-2032 sections, crate count and NIP-29 divergence only; older sections keep their earlier stamp)
sources:
  - Cargo.toml
  - crates/nostr-bbs-upstream-canary/src/lib.rs
  - crates/nostr-bbs-core/src/lib.rs
  - crates/nostr-bbs-pod-worker/src/acl.rs
  - crates/nostr-bbs-auth-worker/src/schema.rs
  - crates/nostr-bbs-forum-client/src/main.rs
  - crates/nostr-bbs-bbs-client/src/app.rs
  - crates/nostr-bbs-bbs-client/src/signer.rs
  - crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs
date: 2026-08-31
---

# Architecture Baseline — nostr-rust-forum

## Purpose

Single source of truth for how this repository is built today: the crate
topology, the two-tier pod mesh, the Cloudflare Workers portability constraints,
the status of the upstream `nostr` absorption, NIP-05 federation, ACL delegation,
kit publishing, and the two Leptos clients. Ground-truth order: **live code >
audit facts > legacy ADR prose**. Legacy ADRs (086–109, archived 2026-08-31) are
citable evidence, never authority. Identity, key derivation, device keys, DM
delivery and trust levels live in the sibling doc `IDENTITY-keys-and-trust.md`.

## Current State

### Workspace topology

A Cargo workspace (`resolver = "2"`, `edition = "2021"`, `rust-version = "1.85"`,
`Cargo.toml`) of 20 member crates (counted at `0065dd9`; the layer list below
names the original four layers and is not exhaustive: poker, sidestr-admin,
zone-migrate, jev and governance-probe have since joined) (`Cargo.toml`
`[workspace.members]`). A pure NIP-29 engine crate, `nostr-bbs-groups`, is
proposed by ADR-2030 and is not a member (see "NIP-29 spaces" below):

- **Foundation** — `nostr-bbs-core`: the hand-rolled Nostr protocol primitives
  (event, keys, signer, NIP-04/19/44/59/98, gift-wrap, governance, moderation).
- **Config / federation** — `nostr-bbs-config`, `nostr-bbs-mesh`,
  `nostr-bbs-setup-skill`, `nostr-bbs-rate-limit`, `nostr-bbs-ascii`.
- **Cloudflare Worker reference implementations** — `nostr-bbs-auth-worker`,
  `nostr-bbs-pod-worker`, `nostr-bbs-preview-worker`, `nostr-bbs-relay-worker`,
  `nostr-bbs-search-worker`.
- **Clients (Leptos CSR)** — `nostr-bbs-forum-client` (modern forum) and
  `nostr-bbs-bbs-client` (retro ASCII/BBS terminal, served at `/community/bbs/`).
- **Validation** — `nostr-bbs-upstream-canary` (build canary; not linked into any
  binary).

The release profile is WASM-optimised (`opt-level = "z"`, `lto = true`,
`codegen-units = 1`, `strip = true`, `panic = "abort"`; `Cargo.toml`
`[profile.release]`) because the workers and both clients target
`wasm32-unknown-unknown`.

### Upstream `nostr` absorption — in-flight, not complete

The workspace **already depends on the upstream `nostr` crate**:
`nostr = { version = "0.44.7", features = ["nip04", "nip44", "nip59", "nip98"] }`
(`Cargo.toml` `[workspace.dependencies]`). The `nostr-bbs-upstream-canary` crate
exists to prove the absorption path (rust-nostr replacing hand-rolled crypto)
compiles and runs on this build matrix **before any `nostr-core` module is
deleted** — PASS records "Shape A" (full absorption), FAIL records "Shape C"
(patch-in-place) (`crates/nostr-bbs-upstream-canary/src/lib.rs:1-30`).

Crucially, **no `nostr-bbs-core` crypto module has been deleted**: the hand-rolled
`nip04.rs`, `nip44.rs`, `nip98.rs`, `gift_wrap.rs`, `keys.rs`, `signer.rs`, `event.rs`
and `nip19.rs` are all still present and are what the workers and clients link
against (`crates/nostr-bbs-core/src/`). The upstream dependency is enabled, the
canary is built, but the absorption itself is unfinished. Legacy upstream ADR-076
(status *Proposed*) understates this: the dependency and canary are live work; the
deletion is not done.

### Two-tier native pod mesh

Pods are served by two tiers (legacy ADR-093, which superseded ADR-089):

- **CF-Workers tier** (`nostr-bbs-pod-worker`) — pods as R2 prefixes; no
  filesystem, no `tokio::process`, no git. Non-git by design.
- **agentbox native tier** — the git-capable pod, resolving the git-pods gap that
  ADR-089 had deferred.

ACL is Web Access Control absorbed over `solid_pod_rs::wac`
(`crates/nostr-bbs-pod-worker/src/acl.rs:1`). The escalation guard
`coerce_required_mode_for_acl` funnels every `.acl`/`.meta` sidecar path to
`AccessMode::Control`, closing the read-side disclosure and write-side control-
coercion holes (`acl.rs:66-88`); per-container delegation is built structurally by
`build_delegation_acl` so the owner is never coerced out (`acl.rs:16`).

### CF-Workers portability constraints (open)

Three `solid-pod-rs` Phase-1 surfaces (`provision-keys`, `nip05-endpoint`,
`export-jsonld`) remain structurally unreachable from `wasm32` CF Workers — legacy
ADR-087 is *Draft, decision deferred*, so ADR-086's pod-federation fallback is
degenerate (the pod returns the same data D1 already holds). The related WAC Turtle
serializer bare-path IRI quirk (legacy ADR-088, *Draft, deferred*) has **zero live
impact** today because the pod-worker writes JSON-LD ACLs and never round-trips
Turtle. Both are latent-risk notes awaiting an upstream champion, not scheduled
work.

### NIP-05 federation & identity storage

NIP-05 usernames are a centrally-administered registry written at claim time into
the auth-worker's D1: `username_reservations(username, pubkey, created_at, …)`
under a pubkey-uniqueness invariant, with a pubkey index and a later `real_name`
column (`crates/nostr-bbs-auth-worker/src/schema.rs:208-232`). The claim/invite
path uses upsert-with-`DO NOTHING` to survive the SELECT-then-branch race
(`crates/nostr-bbs-auth-worker/src/invites.rs:217-225`).

### Kit publishing & versioning

The `nostr-bbs-*` crates are the publishable kit surface (legacy ADR-103). The
current in-tree version is **`1.0.0-beta.10`** (`crates/nostr-bbs-core/Cargo.toml:3`;
workspace path deps are pinned to `1.0.0-beta.10` in `Cargo.toml`). `solid-pod-rs`
is an **exact** pin (`=0.5.0-alpha.7`, `default-features = false`, `features =
["core"]`) so a caret range cannot silently pull a newer published alpha at resolve
time (`Cargo.toml`).

### Client surfaces

- **Forum client** (`nostr-bbs-forum-client`) — the `FORUM_BASE` prefix is added in
  exactly two places (`<Router base=>` and `base_href()`); every internal path is
  base-relative and the service-worker scope is computed against `FORUM_BASE`
  (`crates/nostr-bbs-forum-client/src/main.rs:40-52`; legacy ADR-090). Channel post
  counts are derived from the event set on demand, never accumulated (legacy
  ADR-091); deep-link entry self-bootstraps its own state (legacy ADR-092).
  Zone-first landing scopes navigation to the operator's `[[zones]]` config
  projected into `window.__ENV__.ZONE_CONFIG` (legacy ADR-107).
  Member wallets and tips (ADR-2015, ADR-2021) are gated on
  `window.__ENV__.SIDESTR_WALLET` in `crates/nostr-bbs-forum-client/src/wallet/mod.rs`;
  unset, the client renders as before. `window.__ENV__.SIDESTR_CHAINS` chooses which
  of the two pinned chains are offered (`src/wallet/profile.rs`); absent, only
  `sidestr:dreamlab`.
- **Retro BBS client** (`nostr-bbs-bbs-client`, served at `/community/bbs/`) — the
  M2 write-path is implemented via an in-client signer (`BbsSigner`) that adopts
  the forum session key when same-origin (`crates/nostr-bbs-bbs-client/src/app.rs:20-26`,
  `crates/nostr-bbs-bbs-client/src/signer.rs:64,224,250`). Mobile-first redesign
  (legacy ADR-108) is T1-shipped, T2/T3 in progress; the zone-bound one-shot PWA
  install (legacy ADR-109) shipped in release `1.0.0-beta.5`.

### Relay admission

The relay worker (`nostr-bbs-relay-worker`) gates events by trust level and kind.
Gift-wraps (kind 1059) are recipient-gated on the first `["p", <hex>]` tag rather
than the ephemeral author, and are accepted only if that recipient is a
whitelisted member (`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:103-110,510-516`).
Ban-gating covers user-authored content kinds explicitly; gift-wraps are excluded
from ban-gating because the recipient-whitelist gate already bounds them
(`nip_handlers.rs:58-64`).

## Known divergences & open items

- **Absorption incomplete.** Upstream `nostr` is a live dependency with NIP flags
  enabled and the canary is built, but zero `nostr-bbs-core` crypto modules have
  been deleted (`crates/nostr-bbs-core/src/`). Legacy ADR-076's *Proposed* status
  understates the in-flight dependency+canary work. The absorption is gated on the
  canary verdict (Shape A vs Shape C); until it lands, `nostr-bbs-core` remains the
  authority for on-`wasm32` Schnorr.
- **Kit version drift.** The published-version narrative in legacy ADR-103 and the
  `Cargo.toml` comment ("published to crates.io as 1.0.0-beta.3") is stale — the
  workspace is on `1.0.0-beta.10` (`crates/nostr-bbs-core/Cargo.toml:3`). Reconcile
  the published/registry version before the next release.
- **ADR-109 index/file disagreement.** `docs/adr/README.md:50` lists ADR-109 as
  "implementation pending" while the ADR file header states it shipped in
  `1.0.0-beta.5` (`docs/archive/adr/ADR-109-zone-bound-bbs-pwa-install.md:3`). The file is
  correct; the index is stale.
- **BBS write-path key custody.** Legacy ADR-105 §2.3 decided the BBS client would
  delegate signing to a forum `sign()` seam; the shipped code holds key material
  directly in `BbsSigner` (`crates/nostr-bbs-bbs-client/src/app.rs:25`,
  `signer.rs:64`). ADR-105 was amended (2026-07-03) to acknowledge this; the
  decision-as-originally-stated diverges from code.
- **CF-Workers pod federation degenerate.** ADR-086's pod fallback returns only
  data D1 already holds because ADR-087's portable-cores decision is unresolved.
- **NIP-29 is advertised but not implemented.** `supported_nips` lists 29
  (`crates/nostr-bbs-relay-worker/src/nip11.rs:207`) while the relay only
  admin-gates 9000-9020 and 39000-39002 on an `h` tag and stores them
  (`relay_do/nip_handlers.rs:52-54,1298-1311`); kind 9 is world-readable
  (`relay_do/nip42.rs:44`). Recorded at `0065dd9`; ADR-2030 proposes the fix.
- **Sprint-resident ADRs.** ADR-090/091/092 keep their canonical full text under
  `docs/sprint/2026-05-17-ux-audit/`; the `docs/adr/` stubs reserve the numbers.

## Invariants (must not silently change)

1. **`nostr-bbs-core` owns on-`wasm32` Schnorr** until the canary records Shape A
   and a module is deliberately deleted. Enabling the upstream `nostr` NIP flags
   does not, by itself, retire any hand-rolled module.
2. **`FORUM_BASE` is applied in exactly two places** (`<Router base=>`,
   `base_href()`). Adding a third re-introduces the double-prefix / deep-route-404
   class of bugs.
3. **Channel counts are derived, never accumulated** — a mutable counter drifts
   against deletions and replaceable events.
4. **ACL `.acl`/`.meta` sidecar access coerces to `Control`** — never widen it, or
   the read-disclosure / control-coercion holes reopen.
5. **Gift-wraps are recipient-whitelist-gated**, not author-gated; the ephemeral
   author must never be used for the admission decision.
6. **`solid-pod-rs` stays an exact (`=`) pin** — a caret range would let a resolve
   pull a newer published alpha.

## Change process

Any change to the crate topology, the absorption status, the pod tiers, ACL
coercion, or a kit version requires: (1) updating the affected section with the new
`file:line`; (2) confirming the touched invariant still holds; (3) bumping `version`
and re-recording `verified_commit` from `git rev-parse --short HEAD`; (4) recording
the decision as a new `docs/adr/` ledger entry (copy `docs/adr/TEMPLATE.md`) in the
same change and regenerating the index (`node scripts/adr-index-gen.js docs/adr`).
Legacy ADR prose is evidence, not authority — cite it, do not defer to it.

## Estate closeout qualification — 2026-09-04

The operative ADR-2001–2009 closeout extensions qualify release identity, canary execution, signer custody and cross-version ACL claims. Index validity is documentation evidence. Native tests and WASM compilation are separate from an executed deployed journey. Shared policy code does not certify equal resolver/cache behaviour across differing pod revisions. Governance relay OK precedes projection and downstream application; expose these as separate receipt stages and require durable reconciliation before complete-system acceptance.

See the [forum review](../../VisionFlow/docs/estate-review/forum-decisions.md) for scoped evidence and acceptance requirements. Historical verified commits and activation claims are not refreshed by this source review.

## Proposed durable governance receipts — ADR-2010

[ADR-2010](adr/ADR-2010-durable-governance-outcome-receipts.md) proposes distinct signed, relay-accepted, projection-committed, consumer-received and applied/rejected states. Current relay OK establishes acceptance only. The complete receipt contract remains proposed; its relay half is deployed and was observed live on a signed journey on 2026-10-02 (a refused projection recorded as `projection-failed`), so its activation is `staged`. Adoption requires agreement with the authority consumer and mutation owner, plus failure/restart evidence; acceptance waits on the owner's first high-tier 31403 reaching `projection-committed` (procedure in ADR-2010). Historical ADR-106 supplies rationale, not proof of this contract.

## Operator task properties set the escalation boundary — ADR-2011

[ADR-2011](adr/ADR-2011-operator-task-properties-set-the-escalation-boundary.md) moves the human–agent boundary off the requesting agent's own `risk_tier`. `nostr-bbs-core` owns a `TaskProperties {verifiability, reversibility, stakes}` triple carried as `tp-*` tags on a 31400 panel (the operator's declaration) and optionally on a 31402 (the agent's, tightening only); `effective_tier()` derives the tier a case is actually governed by, and the relay stores it on `broker_cases.effective_tier` at projection time so no consumer reads `risk_tier` for suppression or routing. An unlabelled request folds to the advertised `ESCALATION_DEFAULT_TIER` rather than to an accidental `medium`, making the NIP-11 advertisement load-bearing for the first time. A case whose effective tier is high or critical is resolved only by a human 31403.

The ADR-2010 receipt ladder extends past `projection-committed` with the application stages `consumer-received`, `applied`, `not-applied` and `applied-manually`, plus `escalated-on-age` and `expired` as side receipts; `ReceiptStage` moved into `nostr-bbs-core` because the auth worker's receipts endpoint and the relay's projection must agree on the ladder and share no other code. The auth worker gains `POST /api/governance/receipts/{id}/application` (the mutation owner reports what happened; admin-only for `applied-manually`, and only on a case already decided `Approve`) and `GET /api/governance/reviewers` (per-reviewer decisions, time-to-decision, override rate, calibration and probe columns). A relay cron emits one `escalated-on-age` receipt per case past its panel's `max_pending_hours`.

Implementation is **partial and live**: probe blindness holds in the tag index and the D1 projection but not on the raw signed 31402 served over REQ, where stripping the tag would break the signature clients verify. `nostr-bbs-core` is published (`1.0.0-beta.11` 2026-09-15, `1.0.0-beta.12` 2026-10-01); the edge runs kit `49904f4`, and the M4 probe suite (`crates/nostr-bbs-governance-probe`) passed 11/11 against it on 2026-10-02. The boundary is only as strong as the admin list: the agent that raises dream-machine cases holds the admin flag (ADR-2011, activation section).

## Member wallets on sidestr:dreamlab and DREAM tips — ADR-2015

[ADR-2015](adr/ADR-2015-member-wallets-on-sidestr-dreamlab-and-dream-tips.md) gives every member a wallet without a sign-up step: on a sidestr chain a Nostr key's coins pay `OP_1 <x-only key>`, so a member's npub is their address. The forum client (`src/wallet/`) pinned exactly one chain, `sidestr:dreamlab` beside Bitcoin testnet4, and one asset, DREAM (issued at block 372); ADR-2021 adds a second pin (below). It downloads the mirror's `blocks.dat` and validates every block in the browser with the published `sidestr-core` 0.4, and reads DREAM under the SPEC 12 assets rule as a view. It signs transfers with the session key through `sidestr-wallet` 0.5 and `sidestr-agent` 0.4 (`default-features = false`), and delivers them as kind-23500 events to the producer's public relays. No worker holds a balance and no event kind is added (ADR-2012 D3 holds). A tip is a DREAM transfer that carries a `tip:nostr:<event id>` record, rendered by `components/tip_button.rs` inside the reaction row. `/wallet` offers give (DREAM, sats, or a one-transaction starter pack for members and agents), receive, agents, activity, and a tab-only unlock for NIP-07 members. The whole feature is off unless `SIDESTR_WALLET` is set; the identity-key-as-wallet choice is a testnet-scoped departure from agentbox ADR-2101 D3 that the chain lock enforces.

**BLAKE2b testnet4 coins, read-only — [ADR-2019](adr/ADR-2019-member-wallet-shows-blake2b-testnet4-coins-read-only.md).** The same identity key is already a `txbt4` address (`tb1p`, the x-only key untweaked, as bitcoin-blake/blaketest treats it). With `BLAKE_TESTNET_API` set (`https://` only), `/wallet` shows that address and its balance from an Esplora-shaped backend the operator runs (`wallet/parent.rs`), and the split across both branches of the fork when the backend serves `/address/:a/pair`. It does not validate the figure in the tab, and it links to blaketest to move coins. The forum signs no parent-chain spend, and the chain lock (ADR-2015, two chains since ADR-2021) still governs everything it validates or signs. Staged: no conforming backend runs yet (the estate's node follows the SHA-256d branch).

**Two pinned chains — [ADR-2021](adr/ADR-2021-two-pinned-sidestr-chains-dreamlab-and-dreamlab-txbt4.md).** The lock holds two sealed documents (`wallet/chain.rs` `PINS`): `sidestr:dreamlab` beside `tbtc4` (DREAM) and `sidestr:dreamlab-txbt4` beside `txbt4` (genesis `1009aa29…d108`, prefix `drt`; BLAKES7, whose id is named at runtime). The replay follows the parent's header family (`Stock`, or sidestr-header's `Blake2bV2` for Knots v2 headers). `window.__ENV__.SIDESTR_CHAINS` (`[{id, mirror?, asset_id?, ticker?, label?, citizen_pubkey?, relays?}]`) chooses and orders the chains; an unpinned id is ignored with a warning. There is one `WalletStore` per chain (pending lists under `sidestr.pending.<chain>.<owner>`), a chain switcher on `/wallet` remembered in preferences, and one poker asset table per chain with an asset and a house seat (`[poker] citizens`, projected as `POKER_CONFIG.citizens`). One `nostr-bbs-poker-citizen` runs per chain (`--chain-id`, `--asset-id`, `--ticker`). Tips may be paid in any chain's asset (`components/tip_button.rs`: a token picker defaulting to the wallet's chain, totals per asset), and the tip control sits at the far right of a post's reply row, not in `ReactionBar`. Absent `SIDESTR_CHAINS`, the client is exactly ADR-2015's.


## Pod-worker `/pay/` credits only on chain evidence — ADR-2012 D6

The pay routes are live (`PAY_ENABLED = "true"` in production). `crates/nostr-bbs-pod-worker/src/pay_ledger.rs` holds the rules behind a `LedgerDb` seam (D1 in `payments.rs`, SQLite in tests): a deposit is credited only from a confirmed output paying the caller's own derived deposit script, once, under the receipt `txo:<chain>:<txid>:<vout>`; every credit is a `pay_credits` row naming an outpoint or a NIP-98 request id, applied in the same D1 batch. There is no D1 token balance, so `.buy` and `.withdraw` answer 410. `deposit_address.rs` freezes the live derivation (raw additive tweak plus TapTweak on the unlifted key, hrp `bc`, not BIP 341) behind known-answer vectors captured before its rust-bitcoin port; a new scheme takes a new route (sidestr/spec `keys.mjs`, the teller's tagged ledger-scoped tweak).

## Relay read cost — ADR-2018

[ADR-2018](adr/ADR-2018-relay-read-caches-and-activity-throttle.md) makes the relay's D1 cost scale with requests rather than delivered events. The Durable Object holds 60-second memos of channel → zone, viewer cohorts and device owner (`relay_do/read_cache.rs`, fields at `relay_do/mod.rs:97`), the read gate decides membership from the cached cohorts with the pure `zone_read_permitted` (`relay_do/nip_handlers.rs:1746`), and the trust-ledger writes are coalesced by `ActivityLedger` to one flush per pubkey per five minutes. The forcing fact was D1's free tier: 5 M row reads a day, of which the old per-event lookups spent ~70% on machine traffic alone. Any new per-event D1 read on a read path reopens that ADR.

## Encrypted zones and sealed-original history — ADR-2016, ADR-2017

[ADR-2016](adr/ADR-2016-end-to-end-encrypted-zones.md) encrypts new kind-42 posts in a zone with `encrypted = true` behind the exact-`"true"` `ENCRYPTION_ENABLED` gate: NIP-44 v2 to a per-epoch zone key, a `["zk", zone, epoch, pk]` tag, keys granted by NIP-59 gift wrap (rumor kind 21453) from an admin, and a relay write gate that refuses plaintext into such a channel (`relay_do/nip_handlers.rs:1100-1115`). [ADR-2017](adr/ADR-2017-sealed-original-history-migration.md) migrates the plaintext history that predates the gate: each original is re-published by an admin as a kind-42 envelope carrying a `["sealed", inner_id, "1"]` tag whose ciphertext is the full original signed event (`nostr_bbs_core::sealed`), keeping its id, author and `created_at`; readers substitute the verified inner event. The relay exempts sealed kind-42 from the seven-day drift check (`MAX_TIMESTAMP_DRIFT`, `nip_handlers.rs:44`) and accepts them only from admins into encrypted zones. The plaintext is then removed through the silent `POST /api/admin/events/delete`, never kind-5, because the forum client tombstones kind-5 targets (`fold_deletions`, `stores/channels.rs:779`) and those are the ids the envelopes restore. `nostr-bbs-zone-migrate` drives the run; the operator procedure is [`security/encrypted-zone-history-migration.md`](security/encrypted-zone-history-migration.md).

## Rust toolchain floats on stable, deliberately — 2026-10-02

**Decision (owner decision 2026-10-02, R8):** the forum does not pin a Rust toolchain. `rust-toolchain.toml:2` stays `channel = "stable"`, and the CI clippy job keeps `-D warnings` (`.github/workflows/ci.yml:87`), so each new stable release is picked up the day it ships. In the owner's words: "whatever is latest is fine, we don't want to forget and recovery is trivial from a failure to keep up with releases."

**Context.** Stable moved to rustc 1.99.0 on 2026-09-28. Its clippy reports `clippy::double_must_use` on every `#[async_trait]` trait, because the macro's own `#[must_use]` lands on a method that already returns a `must_use` boxed future. Under `-D warnings` that broke CI on 2026-10-02 with no change to forum code.

**Recovery pattern** (d8bd0c7, 6708c38): when a new clippy lint fires on code we do not own, such as a macro expansion, add a scoped `#[allow(clippy::<lint>)]` to the item that triggers it, with a comment that names the cause. Do not add a crate-wide allow and do not pin the toolchain. The first allow site carries the full explanation (`crates/nostr-bbs-core/src/signer.rs:75-76`, `crates/nostr-bbs-core/src/nip98.rs:90-91`), and every other site points back to it (`nostr-bbs-mesh/src/transport.rs:236`, `:249`, `nostr-bbs-relay-worker/src/mesh.rs:141`, `relay_do/receipts.rs:267`, `trust_sweep.rs:191`, `nostr-bbs-setup-skill/src/lib.rs:71`). When a lint fires on our own code, fix the code instead.

**Rejected alternative:** a pinned channel such as `1.98.0`. A pin keeps CI green on release day, but then someone has to remember to move it, and a forgotten pin fails silently: the build stays green on an old compiler while the rest of the estate moves on. A floating channel fails loudly, and the fix takes minutes.

**Reopen if** a stable release breaks the build in a way the recovery pattern cannot fix, such as a miscompile, a wasm32 target regression, or an MSRV floor raised by a dependency. Also reopen if the forum ever ships a crate whose consumers need a declared MSRV.

## Web Push alerts are content-free — ADR-2023

The relay wakes installed PWAs with an **empty** VAPID-signed push after `save_event` (`relay_do/push_fanout.rs`,
`push.rs`); the forum service worker (`sw.js`, which owns push) then calls `POST /api/push/drain` with a
per-subscription bearer token and shows generic notifications from counters. Invariants: no message text, author
or channel in any push-service request; recipients of kind 40/42 alerts pass `resolve_viewer_context` +
`authorize_event`; a wrap addressed to its own submitter alerts nobody; subscription endpoints are `https` on an
allow-listed push-service host; the feature is off unless `PUSH_ENABLED="true"` and the VAPID pair is consistent.
Carrying text in a payload (RFC 8291) needs a new ADR. Tables `push_subscriptions` / `push_prefs` (migration
`0010_push.sql`); preference wire types live in `nostr_bbs_core::push`.

## Deployment profiles — ADR-2029 (proposed)

The kit is specified to build one of two boards from one source tree, chosen once per
deployment by `[deployment] profile` in `forum.toml`. `forum` is everything this document
describes. `room` (proposed, not implemented) replaces NIP-28 channels with Anagram public
rooms (kind 34550 definition, kind 9 messages, flat `q` replies), encrypted zones with NIP-171
epoch groups (ADR-2028) and adds the NIP-17 overlay (ADR-2027), so that nostr.chat, Anagram and
Iris read and join it natively. Kanban, calendar, governance and moderation kinds are identical
in both. The DreamLab deployment is and remains `forum`; a profile cannot change after the first
post because the channel kind is inside every signed event id. Comparison, diagrams and the
decision tree: `docs/deployment-profiles.md`. The relay is the authority for the dialect: it
takes `CHANNEL_DIALECT` from config, publishes it in its NIP-11 `nostr_bbs` block, and pins it in
a D1 settings row on first write; the single client build reads it at runtime. `forum`-only
surfaces are `channel_zones`, the zone write gate (`nip_handlers.rs:1414`), the zone read decision
(`:2354`), sealed originals (ADR-2017) and the channel-creator table (`:2549`). The dialect
abstraction must also cover the ban gate (`:69`), post counters (`:1556`), profile stats
(`profile_stats.rs:11`) and, in the client, tag interpretation in `core/src/thread.rs:69` and
`pages/message_jump.rs:68`, not only kind numbers.

## NIP-29 spaces, federation and spatial descriptors — ADR-2030, ADR-2031, ADR-2032 (proposed)

Nothing in this section is live behaviour. It records three proposed decisions so a reader
can tell what the code does not yet do. Citations to current code were verified at `0065dd9`;
the rest of this document's `verified_commit` stamp is not re-asserted for the older sections.

- **Group engine (ADR-2030).** A new AGPL-3.0-only crate, `nostr-bbs-groups` (pure, no I/O,
  `wasm32`, `?Send`), folds kinds 9000-9022 in the home's admission order and produces
  relay-signed 39000-39003; the relay worker consumes it. `nostr-bbs-core` stays
  `MIT OR Apache-2.0` and never depends on an AGPL crate or holds derived code. obelisk-relay
  code may be ported into the engine with its notice and a `NOTICE` entry; every file is marked
  `own` or `derived`, and derived files are never relicensed permissively. A group backed by a
  zone is a projection of the zone cohort (ADR-2014): 9000, 9001, 9005, 9021 and 9022 are routed
  through the cohort authority, 9009 is refused, and projection lag denies access. A standalone
  group takes membership from the home's admitted NIP-29 event stream; either way the home signs
  the 39002 that consumers read. The
  VisionClaw bridge reads private groups under a forum-issued read grant, not membership.
  End-to-end private groups remain NIP-171 zones (ADR-2028). In `forum` kind 9 carries `h`;
  in `room` NIP-29 is off and an `h`-tagged kind 9 is refused (an amendment of ADR-2029).
- **Federation (ADR-2031).** A space is `(home relay pubkey, group id)`; the operator pins the
  key in configuration and NIP-11 `self` is discovery only. The home is the only writer: it
  applies moderation in admission order (so backdating cannot reorder it), and stamps every 3900x
  with a monotonic `["rev", <u64>]`; `created_at` is wall-clock only and is never bumped; it orders only equal-`rev` heartbeats.
  Mirrors store the home's state verbatim, replace on a greater `rev` or an equal-`rev` heartbeat (identical content, later `created_at`), keep a
  persisted watermark per group and per kind of `(rev, created_at, event id, content digest)`, enforce locally and forward
  writes. The home re-signs 39002 every 30 s and publishes a removal at once. A 39002 is fresh
  while `now − created_at ≤ L + S` (L = 60 s, S = 10 s), stale after it, and stale means deny,
  including live sessions, which are re-checked every C = 10 s. The single end-to-end guarantee
  is D = 90 s from removal at the home to closure of every presence session and dataspace stream
  (rejoin refused). Voice is bound separately: it needs a reachable LiveKit API, and because an
  issued token cannot be revoked it is D_voice = 2L + 2S + C = 150 s, with rejoins removed within
  C until then; a LiveKit API partition is an accepted exception needing operator sign-off. For a zone-backed group the home
  signs 39002 only while the projection is coherent with the cohort (`["proj", <cohort-rev>]`)
  and stops signing when it lags. The signing key is separate from NIP-11 `pubkey`
  and lives in Worker secrets. No `moved_to`: a fork is a new space. Transport is plain signed
  events through `nostr-bbs-mesh`'s `PeerManager`. Prerequisites: an addressable-replacement
  guard in `relay_do/storage.rs`, ordered by `rev` for 3900x, 30312 and kind 30078 only in the
  `visionclaw:dataspace:*` d-tag namespace (a D1 `rev` migration; other kinds keep NIP-01 ordering;
  today both replaceable branches keep a late older row, `storage.rs:97-139`), persisted dedup and watermark, and a
  `PeerConnector` implementation (`relay-worker/src/mesh.rs:143`, no implementor today). The
  30 s re-sign and the C re-check need a Durable Object alarm; the only alarm today is idle
  eviction (`relay_do/mod.rs:371`). Activation order across the estate (round-2 C9): agentbox
  2162; VisionClaw 2159 then 2161 (`public`, `dids`); forum 2030 then 2031 (with the ADR-2032
  30312 publisher, which voice needs); VisionClaw 2157 then 2161 (`space:`); VisionClaw 2160.
- **Spatial descriptor (ADR-2032).** Extra tags on the home-signed 39000 whose content
  references come from a closed set (VisionClaw dataspace URN, Codescape URN, or a relative path
  on the home's node); unknown refs are ignored. The descriptor's frame is the home's own; each
  consumer applies its own placement transform. NIP-53 30312 per space, carrying `rev`, with
  `service` equal to the configured SFU URL (a consumer refuses a mismatch); 10312 coarse
  presence; NIP-78 30078 claims are advisory display state, the claimant must be a member, and
  the d-tag includes the home key. No new kinds.
- **Licence disclosure (ADR-2030 decision 10).** The forum client shows a footer and about-page
  link to Corresponding Source for the exact deployed commit; the NIP-11 `nostr_bbs` block
  (`source_url`, `licence`, commit) supplements it. Today NIP-11 carries only `software`
  (`nip11.rs:208`).

**Pending invariants** (this document has no convention for proposed invariants, so they
are not numbered above; each becomes an Invariant when its ADR is accepted and implemented):
`nostr-bbs-core` has no AGPL crate in `cargo tree`; a mirror never stores a 39000-39003 not
signed by the pinned home key and never emits one; for kinds other than 3900x, 30312 and 30078 under `visionclaw:dataspace:*`, addressable replacement never lets a late
older event or a same-second higher id replace a newer one; those three families instead never let a lower `rev` replace a higher one; 3900x orders by (`rev`, `created_at`) with equal-`rev` changes of content rejected as equivocation; `created_at` of a 3900x is never bumped; a group backed by a zone has
no membership event applied directly (9000, 9001, 9005, 9009, 9021, 9022 are routed or refused);
the home signs no 39002 while a zone-backed group's projection is incoherent with the cohort;
a 39002 older than L + S = 70 s denies, including joined sessions, and a removal closes every presence session and dataspace
stream within D = 90 s (voice: D_voice = 150 s with the LiveKit API reachable, no bound during a partition); a mirror never accepts a snapshot that does not order strictly after its persisted
per-kind `(rev, created_at, event id, content digest)` watermark, though it may rehydrate the exact accepted event; no
`<content-ref>` outside the closed set is honoured; a 30312 whose `service` differs from the
configured SFU URL is refused; `29` is not in `supported_nips` until the whole applicable
gate passes (the forum-applicable tests among E1 to E6 of PLAN §6 and the coherence test), not E1 alone and not the downstream presence or voice gates.

## Nostr kinds in use

This document owns the registry of Nostr kinds the forum reads or writes. It lists the kinds
that have an owning decision; it is not exhaustive for client-only or test-only kinds. Status
is `live` when the code at `0065dd9` handles the kind, `partial`, or `proposed` when only an
ADR names it. Add a row in the same change as any ADR that introduces or reuses a kind.

| Kind | Use | Status | Owner |
|---|---|---|---|
| 13, 14, 1059 | NIP-59 seal, rumor, gift wrap (`nostr-bbs-core/src/gift_wrap.rs:30,33`) | live | ADR-2005, ADR-2025 |
| 40, 41, 42 | NIP-28 channels, ban gate at `nip_handlers.rs:69` | live | legacy, no ledger record (ADR-2029 context lists the call sites) |
| 21453 | zone-key grant rumor | live (staged) | ADR-2016; replaced by 1014 in ADR-2028 |
| 9, 9000-9022 | NIP-29 chat and moderation: only the admin gate exists; zone-backed groups route membership events through the cohort | partial | ADR-2030 (proposed) |
| 39000-39003 | NIP-29 relay-signed group state; every event carries `rev`; 39002 re-signed every 30 s while the projection is coherent (`proj`); 39000 carries the ADR-2032 descriptor | proposed | ADR-2030, ADR-2031, ADR-2032 |
| 34550 | Anagram room definition (`room` profile) | proposed | ADR-2029 |
| 1014 | NIP-171 ticket | proposed | ADR-2028 |
| 30301, 30302 | kanban board and card (`nostr-bbs-core/src/kanban.rs:54,56`) | live | `kanban.rs` (no ledger record) |
| 31922, 31923, 31925 | calendar events and RSVPs (`nostr-bbs-core/src/calendar.rs:34-38`) | live | `calendar.rs` (no ledger record) |
| 30910-30916 | moderation actions, protected-read (`nip42.rs:44`; `moderation_events.rs:27`) | live | legacy, no ledger record |
| 31400-31405 | agent control surface (`governance.rs:27`) | live | ADR-2010, ADR-2011 |
| 30033 | mesh service list; an entry in the default federated-kind list (`nostr-bbs-mesh/src/config.rs:37`) | partial | archived ADR-074 D9 |
| 23500 | DREAM transfer or tip, delivered to the chain producer's relays (`nostr-bbs-poker-citizen/src/net.rs:322`) | live (staged) | ADR-2015, ADR-2021 |
| 22242, 27235 | NIP-42 AUTH (`relay_do/nip42.rs:29`), NIP-98 HTTP auth (`nostr-bbs-core/src/nip98.rs:1`) | live | `IDENTITY-keys-and-trust.md` |
| 30312 | NIP-53 interactive room, one per space; carries `rev`, stored by `rev` | proposed, **deferred with voice** | ADR-2032, ADR-2031 |
| 10312 | NIP-53 room presence | proposed | ADR-2032 |
| 30078 | NIP-78 application data; claims are advisory display state | proposed | see d-tag table |

**Kind 30078 d-tag namespaces** (kind 30078 is addressable by `d`; a new namespace needs a row):

| d-tag | Use | Status | Owner |
|---|---|---|---|
| zone recovery and imported-epoch records (own `d` namespace, NIP-44 self-encrypted) | zone key recovery | proposed | ADR-2028 |
| `visionflow:claim:<home-key-hex>:<group>:<spot>` | spot or seat claim, NIP-40 expiry 90 s, plaintext, claimant must be a member, advisory only | proposed | ADR-2032 |
| `visionclaw:dataspace:*` | VisionClaw dataspace catalogue, including endpoint-less withdrawal replacements; the only 30078 namespace stored by `rev` (D1 `rev` migration); every other 30078 `d` tag keeps NIP-01 ordering | proposed | VisionClaw ADR-2161, ADR-2031 decision 7 |

Obelisk's private kinds (20390, 31313, 31314, 25050-25052) and its 30078 d-tags are not
adopted (ADR-2030).
