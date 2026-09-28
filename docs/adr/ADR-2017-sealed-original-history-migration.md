---
id: ADR-2017
title: Migrate plaintext history into encrypted zones as sealed originals, then purge the plaintext silently
date: 2026-09-27
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: 0144411
owner: jjohare
review_trigger: a second sealed-original format version; NIP-EE / MLS replacing zone keys (ADR-2016); a relay change to MAX_TIMESTAMP_DRIFT or to kind-5 handling; search-index purge of encrypted-zone embeddings landing
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2017 — Migrate plaintext history into encrypted zones as sealed originals, then purge the plaintext silently

## Context

ADR-2016 encrypts new kind-42 posts in encrypted zones and explicitly defers
existing history. A zone switched to encryption after it has been used keeps
its older messages as signed plaintext in D1, in backups and in any client
cache. Re-posting that text signed by an admin would forge authorship. The
relay rejects any event with `|now − created_at| > MAX_TIMESTAMP_DRIFT` (seven
days, `relay_do/nip_handlers.rs:44`, checked at `:1311` inside `validate_event`
at `:1283`) before it knows whether the author is an admin (`:905`), and the
forum client folds every kind-5 it sees into tombstones by event id
(`forum-client/src/stores/channels.rs:345` subscribes `kinds:[5,40,41]` with no
bound; `fold_deletions` at `:779`).

## Decision

**Sealed original.** Plaintext history in an encrypted zone is re-published as
a *sealed original*: a zone-encrypted envelope whose plaintext is the full,
original signed event. Ids, authorship, timestamps and the reply graph survive,
and the original author's signature still proves the text. The format lives in
`nostr_bbs_core::sealed` (published, pure, wasm32) and is the single source of
truth; this ADR fixes version 1.

| Field | Outer event (what the relay stores) |
|---|---|
| `kind` | `42` |
| `pubkey` | the migrator key — must be a relay admin |
| `created_at` | equal to the inner event's `created_at` |
| tag | `["e", <channel_id>, "", "root"]` — the inner event's root channel |
| tag | `["zk", <zone>, "<epoch>", <zone_pk_hex>]` — the ADR-2016 zone-key tag |
| tag | `["sealed", <inner.id>, "1"]` — discriminator, inner id, format version |
| `content` | `nip44_v2_encrypt(migrator_sk, zone_pk, inner_json)` |
| `sig` | the migrator's Schnorr signature |

`inner_json` is the original signed event serialised with exactly the seven
NIP-01 fields `id, pubkey, created_at, kind, tags, content, sig` and nothing
else. Because the outer author is the migrator, a zone-key holder decrypts with
`ECDH(zone_sk, outer.pubkey)` exactly as for a live ADR-2016 post. The `sealed`
tag, not the shape of the plaintext, marks an envelope, so a normal message
whose text happens to be JSON is never mistaken for one.

**Opening.** A reader decrypts, parses the inner event, and accepts it only if
all six checks pass; any failure is treated as undecryptable
(`ReadOutcome::Failed`) and nothing from the envelope is partially trusted:

1. `inner.kind == 42`;
2. `verify_event(inner)` — id recomputed and BIP-340 signature valid;
3. `inner.id` equals the `sealed` tag's inner id (lowercase hex);
4. the inner event has no `zk` tag — a sealed original wraps plaintext only,
   never another envelope;
5. the inner event's channel (first root-marked `e` tag, else first `e` tag)
   equals the outer event's channel;
6. `inner.created_at == outer.created_at`.

A reader that opens an envelope substitutes the whole inner event — id, author,
timestamp, tags — not just its content, so reactions, threads and unread state
keyed on the original id keep working. The forum client does this in
`ZoneCryptoStore::prepare_incoming` / `redecrypt`; the agentbox reader
(`management-api/lib/zone-keys.js` `readOutcome`) does the same. The retro BBS
client holds no keys and masks any `zk` kind-42, so an envelope shows there as
the existing encrypted placeholder.

**Relay rules.**
- `validate_event` skips the drift check for a kind-42 carrying a parseable
  `sealed` tag; every other check in it still applies. Envelopes must keep the
  original `created_at` for pagination, ordering and unread logic, and
  `validate_event` runs before admin status is known, so the exemption is keyed
  on the tag and the admin rule below closes it.
- A `sealed` event from a non-admin is refused:
  `blocked: sealed originals are admin-only`.
- A `sealed` event into a channel with no zone, or a zone that is not
  encrypted, is refused: `blocked: sealed originals belong to encrypted zones`.
- The ADR-2016 ciphertext rule still applies: an envelope without a well-formed
  `zk` tag and NIP-44 v2-shaped content is refused with
  `blocked: encrypted zone requires zone-key ciphertext`.

**Silent purge.** Plaintext rows are removed by `POST /api/admin/events/delete`
(NIP-98 admin via `auth::require_nip98_admin`, `relay-worker/src/auth.rs:223`),
body `{"ids":[…], "reason":"…"}` with 1–200 ids. It deletes `events` rows by id
where `kind = 42`, emits **no kind-5 and no broadcast**, writes one
`events.delete` entry through `audit::log_admin_action`
(`relay-worker/src/audit.rs:25`) with the count and reason, and answers
`{"deleted": n, "notFound": […], "skipped": […]}` (`skipped` = present but not
kind 42). A kind-5 cannot be used: it is stored, every forum client receives it
through the unbounded `kinds:[5,40,41]` subscription, and `fold_deletions`
tombstones the id — which is also the id of the restored inner event, so a
kind-5 purge would hide the very history the envelope preserves.

**Migrator.** The kit ships `nostr-bbs-zone-migrate` (workspace crate; pure
library compiling to wasm32, native binary). The key comes only from
`NOSTR_BBS_MIGRATE_KEY`; zone keys from `--keys-file` and/or `--fetch-grants`
(gift-wrapped kind-21453 grants from an admin sealer, ADR-2016 rules), highest
epoch per zone used for sealing; the channel→zone map only from an explicit
`--channels` file — never inferred for a destructive tool. Subcommands `plan`
(dry run), `seal` (publish, read back, open, compare byte-for-byte), `verify`,
`purge --yes` (refuses unless every entry is `verified`) and `status`, over a
resumable, atomically written `--state` file. Plaintext is a kind-42 in a listed
channel with neither a `zk` nor a `sealed` tag; an original that fails
`verify_event` is reported and never sealed. Operator procedure:
[`docs/security/encrypted-zone-history-migration.md`](../security/encrypted-zone-history-migration.md).

### Alternatives rejected

| Alternative | Why it lost |
|---|---|
| Admin re-posts each message's text as a new encrypted kind-42 | Forges authorship: the admin's signature replaces the author's, ids change, and every reaction, reply and unread marker keyed on the old id breaks. |
| Purge the plaintext with kind-5 deletions | The kind-5 is stored and served to every client, whose `fold_deletions` tombstones the id — the id the restored inner event carries — so the history disappears again. |
| A new event kind for envelopes | Three readers (forum client, BBS client, agentbox) and every REQ filter that asks for `kinds:[42]` would need changing, and envelopes would drop out of existing pagination. Kind 42 with a `sealed` tag reuses every existing path. |
| Envelopes stamped with the migration time | Breaks ordering, pagination and unread logic, and places years-old messages at the bottom of every channel. |
| Envelopes keep the original `created_at` with no relay change | The relay rejects them on the seven-day drift check for every author, admins included. |
| Delete the plaintext without re-publishing | Destroys the zone's history for members, which the operator did not choose when they enabled encryption. |

## Consequences

- Metadata exposure after migration is **less** than for a live ADR-2016 post:
  only the channel `e` tag is visible; the original's reply `e` tags and `p`
  mentions travel inside the ciphertext. The outer author is the migrator, so
  the original author is also hidden from the relay.
- The retro BBS client shows each envelope as the encrypted placeholder
  attributed to the **migrator**, not the original author.
- Members' clients that already cached the plaintext keep it until their cache
  is cleared; the forum client dedupes a restored inner event against a cached
  copy by id, so they see one message, not two.
- D1 backups and exports taken before the purge retain plaintext until they
  rotate out under the operator's retention policy. The migration does not
  reach them.
- Search-index embeddings of zone messages ingested before encryption are out of
  scope; removing them is a follow-on.
- The migrator key must hold the zone keys. ADR-2016 grant targeting excludes
  any key with the `agent` cohort (`zone_crypto::AGENT_COHORT`), so an agent
  admin receives no grant: the operator either uses a non-agent admin key or
  removes that key's `agent` cohort for the run and restores it afterwards.
- Every holder of the current epoch key can read the migrated history, and so
  can anyone who held a key file used during the run. The operator rotates each
  migrated zone to a new epoch afterwards if any such copy may persist.
- `purge` is irreversible at the relay: after it the only copies of the
  plaintext rows are the envelopes and pre-purge backups.
- The drift exemption widens `validate_event` for one narrow shape; it is safe
  only while the admin-only and encrypted-zone rules sit behind it. A change to
  either rule, to `MAX_TIMESTAMP_DRIFT`, or to kind-5 handling re-opens this ADR.
- A future format change takes a new `sealed` version value and a successor
  ADR; version 1 as fixed here does not change in place. Every reader (core
  `open_sealed`, the forum client, agentbox `zone-keys.js`) treats a `sealed`
  tag with any version other than `1`, or a malformed tag, as undecryptable:
  it is never rendered as a normal decrypted message and never falls back to
  plain zone decryption.
- Lookups by the **original** id no longer reach the relay after `purge`: only
  the envelope id is stored. Channel reading is unaffected (the client restores
  the inner event in place), but two by-id paths are follow-ons: the forum
  client's single-note permalink (`pages/note_view.rs` loads one note by id)
  and the agentbox nightly suggestions job (`scripts/dream-forum-suggestions.mjs`
  finds its thread with `#e:[rootId]` / `ids:[rootId]`). Both need to fetch by
  channel and match on the inner event's id and tags.

## Verification

Verified at kit `0144411` (core `194aba4`, relay `c7b8437`, forum client
`991e47f`, migrator `0144411`, docs `ad8ce50`) on 2026-09-27 with the full
workspace gate run from a clean `target/`:

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo test --workspace --all-targets` | 35 test binaries, **2280 passed, 0 failed** |
| `cargo check --workspace --target wasm32-unknown-unknown` | exit 0 |
| `cargo deny check` | advisories, bans, licenses, sources ok |
| `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps` | exit 0 |

Feature-specific coverage within that total:

- `nostr-bbs-core::sealed`: round trip; each of the six open checks failing on
  its own; extra/duplicate/missing inner fields; tampered content; wrong zone
  key; proptest identity.
- `nostr-bbs-relay-worker`: 24 new tests — the drift exemption and both write
  rules (asserting the exact reject strings above, and that a real
  `seal_original` envelope passes all three gates), and 14 for
  `POST /api/admin/events/delete` (body limits, hex validation, `notFound` /
  `skipped` reporting, audit row).
- `nostr-bbs-forum-client`: 10 tests in `zone_crypto::read_cache` (round trip,
  placeholder replaced in place, dedupe against cached plaintext and against a
  second envelope, tampered envelope → placeholder, tombstoned original stays
  hidden, reactions and replies attach to the restored id) plus the bbs-client
  masking assertion.
- `nostr-bbs-zone-migrate`: 44 tests — planner, state resume, key-file and
  grant validation, 200-id chunking, refusal paths, and 12 end-to-end runs over
  an in-memory relay (seal → verify → purge, resume, envelope adoption after
  lost state, relay rejection, tampered or vanished read-back before `verify`
  and before `purge`).
- agentbox `management-api/lib/zone-keys.js` (separate repo, `e0e331afd`): 39
  tests, each of the six checks shown to be load-bearing by disabling it.

### First production run (DreamLab, 2026-09-27/28)

`activation_status: live` since the first `purge`. Run with the deployed kit at
`2f437bc` against `wss://dreamlab-nostr-relay.solitary-paper-764d.workers.dev`,
migrator = the house admin key, keys obtained with `--fetch-grants`:

| Zone | Channels | Sealed | Verified | Purged | Failed |
|---|---|---|---|---|---|
| zone4 (dreamlab) | 4 | 236 | 236 | 236 | 0 |
| zone2 + zone3 (minimoonoir, family) | 6 | 194 | 194 | 194 | 0 |

Independent read-back, separate from the migrator: agentbox's
`management-api/lib/zone-keys.js` reader, NIP-42 authenticated, opened
236 / 236 zone4 envelopes with JunkieJarvis's own key store and 194 / 194
zone2/3 envelopes with keys unwrapped from the migrator's grants. After the
purge a logged-out reader received 0 events across all ten channels, D1 held
430 `sealed` rows and 0 plaintext kind-42 in the private zones, and
`admin_log` carried three `events.delete` rows (200 + 36 + 194 ids). A full
backup containing every plaintext original was taken before the first purge.

Observed: an admin migrator keeps read access to the sealed history for as
long as its zone-key grants exist on the relay, and admins bypass cohort
gating; rotating the zone key protects new posts only. Operators who want the
migrator excluded afterwards must use a dedicated, revocable admin key (see
the runbook).
