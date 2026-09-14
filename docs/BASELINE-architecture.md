---
title: Architecture Baseline — nostr-rust-forum
doc_id: NRF-BASELINE
version: 0.1.0
status: draft-for-ratification
verified_commit: 23be587
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
`Cargo.toml`) of 14 member crates in four layers (`Cargo.toml`
`[workspace.members]`):

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

[ADR-2010](adr/ADR-2010-durable-governance-outcome-receipts.md) proposes distinct signed, relay-accepted, projection-committed, consumer-received and applied/rejected states. Current relay OK establishes acceptance only. The complete receipt contract remains proposed and inactive; adoption requires agreement with the authority consumer and mutation owner, plus failure/restart evidence. Historical ADR-106 supplies rationale, not proof of this contract.

## Operator task properties set the escalation boundary — ADR-2011

[ADR-2011](adr/ADR-2011-operator-task-properties-set-the-escalation-boundary.md) moves the human–agent boundary off the requesting agent's own `risk_tier`. `nostr-bbs-core` owns a `TaskProperties {verifiability, reversibility, stakes}` triple carried as `tp-*` tags on a 31400 panel (the operator's declaration) and optionally on a 31402 (the agent's, tightening only); `effective_tier()` derives the tier a case is actually governed by, and the relay stores it on `broker_cases.effective_tier` at projection time so no consumer reads `risk_tier` for suppression or routing. An unlabelled request folds to the advertised `ESCALATION_DEFAULT_TIER` rather than to an accidental `medium`, making the NIP-11 advertisement load-bearing for the first time. A case whose effective tier is high or critical is resolved only by a human 31403.

The ADR-2010 receipt ladder extends past `projection-committed` with the application stages `consumer-received`, `applied`, `not-applied` and `applied-manually`, plus `escalated-on-age` and `expired` as side receipts; `ReceiptStage` moved into `nostr-bbs-core` because the auth worker's receipts endpoint and the relay's projection must agree on the ladder and share no other code. The auth worker gains `POST /api/governance/receipts/{id}/application` (the mutation owner reports what happened; admin-only for `applied-manually`, and only on a case already decided `Approve`) and `GET /api/governance/reviewers` (per-reviewer decisions, time-to-decision, override rate, calibration and probe columns). A relay cron emits one `escalated-on-age` receipt per case past its panel's `max_pending_hours`.

Implementation is **partial and inactive**: probe blindness holds in the tag index and the D1 projection but not on the raw signed 31402 served over REQ, where stripping the tag would break the signature clients verify. Nothing is deployed and `nostr-bbs-core` 1.0.0-beta.11 is unpublished.
