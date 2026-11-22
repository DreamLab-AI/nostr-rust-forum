---
id: ADR-2016
title: A zone can be end-to-end encrypted with per-epoch zone keys granted by gift wrap, behind a deployment gate
date: 2026-09-26
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: a7e89dd
verified_paths: [crates/nostr-bbs-forum-client/src/zone_crypto/mod.rs, crates/nostr-bbs-relay-worker/src/zone_config.rs, crates/nostr-bbs-forum-client/src/stores/zones.rs]
owner: jjohare
review_trigger: the first member removal that needs a rotation; an operator setting agent_keys = true; NIP-EE / MLS reaching a stable Nostr mapping
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2016 — A zone can be end-to-end encrypted with per-epoch zone keys granted by gift wrap, behind a deployment gate

## External review qualification — 2026-11-02

The [dated source reconciliation](../audit/external-review-2026-11-02.md) records the current
implementation evidence, open acceptance gaps and limits of the external review.
It supplements this decision without changing its adoption or activation status.

## Context

`nostr_bbs_config::Zone.encrypted` existed and operators set it (the dreamlab
family zone), but nothing acted on it: channel messages were signed plaintext
in D1, in backups, and to any Nostr client the relay would serve. Zone
membership is access control only — it protects against other users while the
relay is configured correctly, and not at all against the relay, the host or a
leaked backup. Only NIP-17 DMs were encrypted. The kit already ships NIP-44 v2
(`nostr_bbs_core::nip44`, rust-nostr, upstream-vector tested) and NIP-59 gift
wraps (`nostr_bbs_core::gift_wrap`).

## Decision

**Gate.** Zone encryption is dormant unless the operator enables it. Operator
config `[encryption] enabled` (default `false`) projects to the plain string
env var `ENCRYPTION_ENABLED` in the relay worker's `[vars]` and in the forum
client's `window.__ENV__`; only the exact string `"true"` is on. A zone is
encrypted only when the gate is on AND the zone sets `encrypted = true`.

**Public zones cannot be encrypted.** `encrypted = true` on a
`visibility = "public"` zone is a configuration error: anonymous readers can
never hold a key. The relay never enforces encryption on a public zone either.

**Keys.** Each `(zone, epoch)` has its own random secp256k1 keypair; epochs
increase from 1. An admin grants the epoch secret to each member as a NIP-59
gift wrap whose rumor is kind 21453 with content
`{"zone","epoch","secret","pubkey","created_at"}`. A client accepts a grant only
when the seal's verified author is a relay admin and the secret derives to the
stated pubkey. The rumor kind and content are a project-private construction:
they live in the unpublished `nostr-bbs-forum-client`, never in the published
`nostr-bbs-core`.

**Messages.** A kind-42 (edits included) in an encrypted zone's channel has
`content = nip44_encrypt(author_sk, zone_epoch_pk, plaintext)` and the tag
`["zk", <zone id>, <epoch>, <zone epoch pubkey hex>]`; every other tag is
unchanged. Any holder of the zone secret decrypts with the event's author
pubkey (`ECDH(zone_sk, author_pk)`), and the author's signature still proves
authorship. The relay refuses a kind-42 into such a channel without a
well-formed `zk` tag and NIP-44 v2-shaped content ("blocked: encrypted zone
requires zone-key ciphertext"), for every author including admins and agents.

**Client behaviour.** Every kind-42 publish path encrypts to the newest held
key, or refuses with the draft kept — never a plaintext fallback. Decryption
happens once, as events enter the channel store; a missing key renders a
placeholder. Encrypted text is never sent to the search index, and link
previews are off for encrypted posts (a preview would send the URL to the
preview worker). With the gate off nothing is encrypted on write and the admin
Encryption tab is hidden, but `zk` messages still decrypt with any held key, so
turning the gate off never makes history unreadable. The retro BBS client holds
no keys: it shows a placeholder and, with the gate on, offers no composer on
encrypted boards.

**Agents.** Grant targeting excludes every member with the `agent` cohort —
an agent admin included — unless the zone sets `agent_keys = true`.

**Membership changes.** Removing a member means rotating to a new epoch and
granting it to everyone who remains (admin > Encryption > Rotate key).
A grant carries one epoch, so a member added after a rotation would read only
from the newest epoch on. "Grant to members missing it" therefore also sends
the earlier epochs the admin holds (skipping recipients already recorded for
each), behind an on-by-default "Also send earlier keys" option that the admin
can clear to give a newcomer the current key only (`zone_crypto::grant_plan`).
"Recorded" means the relay accepted that member's grant, kept per device in
IndexedDB; the relay cannot say who holds a key. A batch's acks arrive
together, so the record is an in-memory set persisted by whole-set rewrites
(`zone_crypto::grant_ledger`), never a per-ack read-modify-write, which lost a
random subset of accepted grants and showed those members as missing.

**Accounts sharing a browser.** Cached zone keys belong to the identity that
received or created them (`zone_crypto::key_owner`): each IndexedDB row carries
its owner in its `owner` field and in its id (`"<owner>/<store id>"`), so an
identity sees only its own rows and two identities can never overwrite each
other's. Signing out drops every key from memory and turns decrypted messages
back into placeholders; the next sign-in, with or without a reload, loads that
identity's keys before the Encryption card offers Create or Rotate, and a key
is never minted at an epoch another account on the browser holds. Rows written
before owners existed are not attributable to anyone, so they stay as a
read-only layer every signed-in identity sees (as before) and none sees while
signed out; they are never deleted, because a device can hold the only copy of
an undelivered key. This is isolation between accounts in the UI, not access
control: same-origin storage is readable by anyone with the device.

**History.** Existing plaintext messages are left as they are. Re-publishing
them as encrypted "sealed originals" (the full signed original event inside a
zone-encrypted envelope, so ids, authorship and reply threading survive) is a
separate decision, taken in
[ADR-2017](ADR-2017-sealed-original-history-migration.md).

### What it protects

| Protected | Not protected |
|---|---|
| Message text against the relay, Cloudflare, D1 backups and any non-member Nostr client | Metadata: tags, authors, timestamps, channel ids, the reply graph, `p` mentions |
| Messages posted after a member's removal (after a rotation) | Messages a removed member already read or could read with keys they hold |
| | Reactions (kind 7), which stay plaintext |
| | Forward secrecy within an epoch: a leaked epoch secret reads that whole epoch |
| | A key at rest on a member's device (IndexedDB, unencrypted) |
| | One account's keys against another account, script or person using the same browser profile (per-identity scoping is UI isolation only; keys stored before it are shared by every account there) |

### `agent_keys` trade-off

With `agent_keys = true`, an agent holding the zone key means the zone's
plaintext reaches the agent stack and whatever model the agent calls. That
may be acceptable for a work zone and is not for a family zone, so it is a
per-zone choice, off by default.

### Alternative: MLS (NIP-EE / Marmot)

MLS gives forward secrecy, post-compromise security and efficient removal. It
is deferred: its Nostr mapping is still a draft, it needs `openmls` in the
browser, and it replaces the channel model rather than extending it. For small
zones epoch keys on NIP-44 + NIP-59 deliver the core property — the relay and
host cannot read message text — at a fraction of the risk, and the `zk` tag
leaves room to migrate.

## Consequences

- An operator can turn encryption on per deployment and per zone without code
  changes; the relay and every client agree on one gate value.
- Server-side search, link previews and relay-side moderation by content no
  longer work for encrypted zones.
- An admin must create the first key and grant it; a member without a grant
  can read nothing new and cannot post. Grants are per member key, so a new
  member needs a grant on approval. Since the auto-grant follow-on
  (`zone_crypto/auto_grant.rs`) that grant is sent without the Encryption
  tab, still from an admin's browser: on allocation (Members table cohort
  edit, section-request approval, registration approval) to that member, and
  once per page load at an admin's sign-in to every eligible member the
  device's ledger has no record of. An admin signed in through a NIP-07
  extension is told how many grants are waiting rather than sent a sweep,
  since an extension may prompt for each encryption and signature. No server
  or agent holds a key to grant on anyone's behalf.
- Which members hold a key is known only for grants sent from the granting
  admin's device.
- Follow-on: sealed-original history migration (ADR-2017); encrypting reactions if
  wanted; key backup/recovery for a member who loses every device.

## Verification

At `cb86790`: `cargo test` in `nostr-bbs-forum-client` (497 passed, including
zone_crypto round-trips in both ECDH directions, NIP-44 v2 shape the relay
accepts, zk tag parsing, grant validation incl. secret/pubkey mismatch and
non-admin sealer, gift-wrap grant round-trip through core, agent exclusion and
`agent_keys` inclusion, the gate's exact-"true" rule, write refusal without a
key, read placeholders, legacy plaintext untouched), `nostr-bbs-bbs-client`
(164 passed: masking, gated board detection), `nostr-bbs-config` (47 passed:
encrypted public zone rejected, locked/hidden accepted, gate defaults off);
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean;
`cargo fmt --all -- --check` clean; `cargo check --target wasm32-unknown-unknown`
for both client crates. Not yet exercised in a live browser.

## Close-out 2026-10-30

`activation_status` staged → live. The gate this record defines is on in production, and the code behind it is deployed.

- Live endpoint: `curl -sL https://dreamlab-ai.com/community/` at 2026-10-30T19:30Z serves `window.__ENV__` with `ENCRYPTION_ENABLED:"true"`, the exact string `zone_crypto::GATE_ENV_KEY` (`crates/nostr-bbs-forum-client/src/zone_crypto/mod.rs:91`) treats as on.
- Deployed config: dreamlab-ai-website `f653f58` `forum-config/dreamlab.toml` sets `[encryption] enabled = true` and `encrypted = true` on `zone2` (minimoonoir), `zone3` (family) and `zone4` (dreamlab); "Deploy Cloudflare Workers" run `41028875471` on `f653f58` succeeded (2026-10-30T08:47:55Z) with the kit pinned to forum `9c36b60`.
- Ancestry: `git merge-base --is-ancestor cb86790 9c36b60` exits 0.

- Relay side: the same run's "Deploy Rust Workers (nostr-bbs-relay-worker, relay-worker, dreamlab-nostr-relay)" step logs the binding `ENCRYPTION_ENABLED: "true"` (`gh run view 41028875471 -R DreamLab-AI/dreamlab-ai-website --log`, 08:50:46Z), and the pre-deploy gate reports `encryption-enabled 3 site(s) in sync` (dreamlab.toml, deploy.yml, `forum-config/deploy/relay-worker.wrangler.toml`).

Not established from here: a member removal that forces an epoch rotation. The earlier verification line "not yet exercised in a live browser" still describes the test record; the review trigger already covers the first rotation.

## Per-identity browser state — 2026-11-22

Extends the "Accounts sharing a browser" paragraph above (PR #92); that paragraph is unchanged and still the statement of
how zone keys are keyed. This section adds what the paragraph does not say. `implementation_status` and
`activation_status` above are not re-verified here; this section is verified at `3c48e26` only.

- **Create and Rotate plan above every epoch on the device.** `plan_mint` takes the epochs any row on this browser holds
  for the zone, whatever account owns it, and mints above them, because another account's key may be pending delivery and
  so be in no post yet. An epoch more than `MAX_EPOCH_SKIP` (8) beyond what this identity can vouch for is reported and
  ignored, not obeyed. An identity that holds no key for the zone, with only far-ahead epochs in sight (in posts or in
  another account's rows), is `Blocked` with an explanation, because epoch 1 could clash with the zone's real one. When
  posts name an epoch above the one to be minted, `mint_confirmation` asks the admin to confirm, since members who send
  under the higher epoch keep doing so and the rotation does not take effect for them
  (`zone_crypto/keyset.rs:169`, `:220-226`, `:271`; `zone_crypto/key_owner.rs:131`).
- **Unsent text and previews never cross accounts.** Drafts are stored as `draft:v2:<pubkey>:<channel>`
  (`components/draft_indicator.rs:49`); nothing is loaded or saved while signed out or locked; drafts saved before the
  change cannot be attributed and are all deleted once at start-up (`drop_legacy_drafts`, `:84`, called at `app.rs:329`).
  Bookmarks are stored per identity under `nostrbbs_bookmarks:v2:<pubkey>` (`anon` when signed out); a bookmark of a
  message from an encrypted zone keeps no text; bookmarks saved before the change stay visible to every account, with
  their previews erased (`bookmarks_modal.rs:38`, `:57`). A notification for a post in an encrypted zone reads "New
  encrypted message in <channel>" with no text and no author; one saved before the change has its body replaced when the
  list loads (`stores/notifications.rs:106`, `:1340`).
- **Costs.** An unsent draft from before the change is lost once. Bookmarks and zone keys written before the change
  remain visible to every account on the browser; nothing on the device records which account received them. Keys load
  after sign-in, not at boot, so the first encrypted messages of a cold load can show placeholders briefly.

Verification at `3c48e26`, by reading code; no cargo test or build was run. Commands run from the repository root:
`grep -n "pub fn plan_mint\|pub fn mint_confirmation\|MintPlan::Blocked(format" crates/nostr-bbs-forum-client/src/zone_crypto/keyset.rs` returned `:169`,
`:220`, `:226`, `:271`; `grep -n "pub fn mint_decision" crates/nostr-bbs-forum-client/src/zone_crypto/key_owner.rs` returned `:131`;
`grep -n "pub fn draft_key\|pub fn drop_legacy_drafts" crates/nostr-bbs-forum-client/src/components/draft_indicator.rs` returned `:49`, `:84`, and
`grep -n "drop_legacy_drafts" crates/nostr-bbs-forum-client/src/app.rs` returned `:329`; `grep -n "fn bookmarks_key\|fn redact_legacy" crates/nostr-bbs-forum-client/src/components/bookmarks_modal.rs`
returned `:38`, `:57`; `grep -n "fn post_body\|fn redact_legacy_preview\|const LEGACY_POST_BODY" crates/nostr-bbs-forum-client/src/stores/notifications.rs`
returned `:100`, `:106`, `:1340`. CI run 45056144222 on that commit concluded `success` (its test step is
`.github/workflows/ci.yml:113`). Not exercised in a browser: the thread of PR 92 records that the live test follows the repin.
