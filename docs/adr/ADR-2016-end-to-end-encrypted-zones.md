---
id: ADR-2016
title: A zone can be end-to-end encrypted with per-epoch zone keys granted by gift wrap, behind a deployment gate
date: 2026-09-26
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: cb86790
owner: jjohare
review_trigger: the first member removal that needs a rotation; an operator setting agent_keys = true; a proposal to migrate plaintext history ("sealed originals"); NIP-EE / MLS reaching a stable Nostr mapping
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2016 — A zone can be end-to-end encrypted with per-epoch zone keys granted by gift wrap, behind a deployment gate

## Context

`nostr_bbs_config::Zone.encrypted` existed and operators set it (the DreamLab
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

**History.** Existing plaintext messages are left as they are. Re-publishing
them as encrypted "sealed originals" (the full signed original event inside a
zone-encrypted envelope, so ids, authorship and reply threading survive) is a
separate, future decision.

### What it protects

| Protected | Not protected |
|---|---|
| Message text against the relay, Cloudflare, D1 backups and any non-member Nostr client | Metadata: tags, authors, timestamps, channel ids, the reply graph, `p` mentions |
| Messages posted after a member's removal (after a rotation) | Messages a removed member already read or could read with keys they hold |
| | Reactions (kind 7), which stay plaintext |
| | Forward secrecy within an epoch: a leaked epoch secret reads that whole epoch |
| | A key at rest on a member's device (IndexedDB, unencrypted) |

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
  member needs a grant on approval.
- Which members hold a key is known only for grants sent from the granting
  admin's device.
- Follow-on: sealed-original history migration; encrypting reactions if
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
