---
id: ADR-2033
title: The relay keeps NIP-09 tombstones and gates members' kind-5s; clients sync deletions incrementally and scope each tombstone to its deleter
date: 2026-11-22
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 3c48e26
verified_paths: [crates/nostr-bbs-relay-worker/src/lib.rs, crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs, crates/nostr-bbs-relay-worker/src/moderation.rs, crates/nostr-bbs-relay-worker/src/admin_events.rs, crates/nostr-bbs-relay-worker/src/user_admin.rs, crates/nostr-bbs-forum-client/src/stores/deletion_sync.rs, crates/nostr-bbs-forum-client/src/stores/tombstones.rs]
owner: jjohare
review_trigger: the first moderator removal of a migrated post observed on a live deployment; an admin un-tombstone route or a record of original authors of migrated posts (sealed_authors) being built; any change to MAX_TIMESTAMP_DRIFT or to the relay's kind-5 handling; the first browser or live-relay run of the incremental sync
repo: nostr-rust-forum
domain: BASELINE-architecture.md
evidence_class: source+ci
acceptance_boundary: Established at 3c48e26 - the code paths below exist and are wired as described (read by line), and the CI workflow run for that commit concluded success (it runs the crates' unit and SQL tests; no cargo test or build was run for this record). Not established - behaviour against real Cloudflare D1 (a 2,000-target gate lookup binds one JSON parameter of about 134 KB), any WebSocket-level test of the gate wiring, any browser run of the client sync, and whether the deployed DreamLab workers and client run this commit. The PR threads record that the live test follows the repin.
---

# ADR-2033 — The relay keeps NIP-09 tombstones and gates members' kind-5s; clients sync deletions incrementally and scope each tombstone to its deleter

## Context

Before 2026-11-22 the relay honoured a kind-5 by deleting the target rows and kept no record that it had, so anyone
holding the original signed event could publish it again and it was stored as new. The kind-5 gate for members treated
an `e` target with no stored row as the signer's own, so any whitelisted member could publish a kind-5 naming an id the
relay did not hold; the relay stored and broadcast it, and every forum client folded every `e` tag into its tombstones
with no author check. The ADR-2017 sealed originals, whose plaintext rows are purged and which survive only inside admin
envelopes, were the exposed case: one kind-5 (up to 2,000 `e` tags) hid them on every client. Clients also re-fetched
the newest 1,000 deletions every session. Six PRs (#89, #90, #91, #92, #93, #94) settled the rules below; the other
decisions in them are ADR-2034 and the 2026-11-22 section of ADR-2016.

## Decision

**1. The relay records tombstones in D1 and refuses a deleted event.**

- Two tables, created by `ensure_schema` (there is no migration file): `deleted_events (id, pubkey, deleted_at)` keyed
  `(id, pubkey)`, and `deleted_addresses (kind, pubkey, d_tag, deleted_until)` keyed `(kind, pubkey, d_tag)`
  (`crates/nostr-bbs-relay-worker/src/lib.rs:746`, `:755`). An event id commits to its author, so a row naming the wrong
  author blocks nothing; a member can only ever block their own events.
- An address tombstone exists only for replaceable and addressable kinds (0, 3, 10000-19999, 30000-39999). It covers
  versions with `created_at <= deleted_until`, clamped to now, and the author's next version is accepted. Plain
  replaceable kinds are keyed with an empty d-tag whatever `d` tag the event carried (`address_d_tag`, `lib.rs:970`).
  An `a`-ref of any other kind is ignored entirely: no DELETE, no tombstone (`a_ref_target`,
  `relay_do/nip_handlers.rs:2841`).
- Ingest refuses a tombstoned event with `blocked: this event was deleted`, after every other gate and before
  `save_event` (`nip_handlers.rs:1607`). A failed lookup lets the event through (`is_deleted`, `:3474`): the check is a
  re-insert guard, not an availability gate.
- What gets a tombstone: a kind-5 `e` target, under the signer, and for a moderator also under the target's real author
  read from the row; a gift wrap deleted by its recipient, also under the wrap's ephemeral author
  (`process_deletion`, `:3510`); a report resolved as `delete` (`moderation.rs:349`); the ADR-2017 purge, id only
  (`admin_events.rs:279`); a user delete with `delete_events`, every row of the author (`user_admin.rs:225`). A report
  resolved as `hide` and kind retention in `cron.rs` record none: hiding is reversible and retention is storage policy.
  The helper runs before the DELETE, never in the same D1 batch, and its failure is reported, not acted on
  (`tombstone_before_delete`, `lib.rs:1569`).
- The tables are not served to clients. That is why the ADR-2017 purge may tombstone without hiding the restored inner
  event, which a client-visible kind-5 would.
- Two one-time maintenance passes record themselves in `settings`: `nip09_tombstones_backfilled` (rebuild from stored
  kind-5s, own-deletion semantics) and `nip09_plain_addresses_rekeyed` (`lib.rs:984`, `:981`). `POST /api/admin/reset-db`
  clears both tables (`whitelist.rs:524`) and leaves the markers.

**2. A member's kind-5 is accepted only if the relay can vouch for every `e` target.** Below TL3 (non-admin), each target
must be 64 lowercase hex and be one of: the signer's own stored event; a gift wrap addressed to one of the signer's
recipient keys; or an id with a `deleted_events` row for `(id, signer)` and no stored row. Otherwise the whole kind-5 is
refused, because the event is signed and the relay cannot strip a tag that every client will fold
(`member_deletion_gate`, `nip_handlers.rs:3349`, called at `:1321`). Refusals, in precedence order: another author's
stored row (`restricted: TL3+ required to delete others' events`); a sealed original, with no row and a stored kind 42
naming it in a `sealed` tag (`restricted: migrated (sealed) posts can only be removed by a moderator`), refused even if
the signer holds a tombstone for it; any other id, including a non-canonical rendering (`restricted: deletion names an
event this relay does not hold`); a D1 failure (`error: could not check deletion targets, try again`, fail closed). A
stored row is judged by its author before any flag is read (`classify_member_target`, `:3045`). A kind-5 with only `a`
targets is not gated by this check. Members cannot delete migrated posts: the original author is inside the envelope's
ciphertext, and the purge does not record it.

**3. A moderator's kind-5 (admin or TL3+) skips the gate and, for a sealed original, also deletes the envelope.** The
envelope row must have the full wire shape (kind 42, a `sealed` tag naming the id with a decimal version, and a `zk`
tag) and its author must be a current admin; it is tombstoned under its author first (`delete_sealed_envelopes`,
`:3404`, `SEALED_ENVELOPES_FOR_SQL`, `lib.rs:838`). A kind 42 that merely carries a `sealed` tag is left.

**4. Clients fetch deletions incrementally and scope every tombstone to its deleter.**

- A device that has completed a deletion sync asks only for kind-5s with `created_at >= since`, where the marker is
  `min(newest kind-5 delivered, local now) - 14 days` (`DELETION_SINCE_MARGIN_SECS`, two relay drift allowances,
  `stores/deletion_sync.rs:119`), kept per scope in localStorage (`nostrbbs_deletion_sync_v3_*`, `:158`), never moved
  backwards, and advanced only when the sync settled complete. A backfill that hits the 1,000-row cap pages downwards on
  an inclusive `until` for at most `MAX_PAGES = 20` pages (`:123`, `next_page`, `:424`); it keeps the old marker if it
  gives up. A device with no usable marker behaves as before and does not page.
- A tombstone is `(id, deleter)` (`stores/tombstones.rs:67`). It hides an ordinary post whatever its deleter, because the
  relay gated that deletion. It hides a restored sealed original only if the deleter is the original's verified author or
  a pubkey the relay vouches for as admin through `GET /api/check-whitelist` (`honoured`, `tombstones.rs:114`;
  `signer_admin.rs:108`). The client cannot identify TL3 moderators; their deletions of sealed originals take effect
  through decision 3.
- Across sessions a device persists only tombstones on restored sealed originals: `sealed` (honoured deleters, at most
  256 per deleter, 1,024 in all) and `held` (unresolved, at most 64 per deleter, 1,024 in all), each trimmed by fair share
  (`deletion_sync.rs:126-132`).

**Alternatives rejected.** Ignoring a bad `e` tag relay-side and accepting the rest (the event is signed; clients would
still hide the id). Keeping the marker behind any unresolved tombstone (most targets are ordinary posts the relay has
already hard-deleted, so they never resolve and the marker would stay pinned). A kind-5 for the ADR-2017 purge (ADR-2017).
A tombstone per row pruned by retention (unbounded growth, and not a decision that the content must never return).

## Consequences

- A deleted event, a purged plaintext original and a removed user's events cannot be published again by anyone holding
  the signed event, until a database reset or a restore of an older backup. Moderator and purge tombstones are
  permanent: there is no un-delete route. A user delete with `delete_events` leaves the member's pubkey and event ids
  (no content) in `deleted_events`.
- Members lose two things they had by accident: deleting an id the relay does not hold (pre-emptive deletion), and
  deleting their own migrated posts. Moderators remove migrated posts on their behalf.
- Known gaps, recorded in `docs/security/known-findings.md` KF-14 to KF-21 and KF-25: no un-tombstone route; `process_deletion`
  still writes an `(id, signer)` claim for a target with no row, and claims written before the gate let a pre-fix signer
  re-name an id never stored here; the envelope delete checks the author against current admin status, not a migrator
  list; kind-5s with no `e`/`a` target are accepted; user purge covers neither device-key events nor gift wraps; the
  2,000-target gate query is untested against real D1; paging has no resume cursor when it gives up.
- Operator procedure: `docs/runbooks/relay-deletion-and-tombstones.md`.

## Verification

Run in the worktree at `3c48e26` (`git rev-parse --short HEAD`), reading code only. No `cargo test` or build was run;
test counts in the PR bodies are the PRs' claims, not evidence here.

- Tables and markers: `grep -n "DELETED_EVENTS_CREATE_SQL\|DELETED_ADDRESSES_CREATE_SQL\|TOMBSTONE_BACKFILL_SETTING\|PLAIN_ADDRESS_REKEY_SETTING" crates/nostr-bbs-relay-worker/src/lib.rs` returns the definitions at `:746`, `:755`, `:981`, `:984` and the `ensure_schema` calls; `ls crates/nostr-bbs-relay-worker/migrations` ends at `0014_zone_epoch_keys.sql`, and `grep -rn deleted_events crates/nostr-bbs-relay-worker/migrations` returns nothing, so there is no migration.
- Ingest refusal: `grep -n "blocked: this event was deleted" crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` returns `:1608`, inside `if self.is_deleted(&event).await` at `:1607`, ahead of `save_event`.
- Gate: `grep -n "member_deletion_gate\|DELETE_.*_REFUSAL" .../nip_handlers.rs` returns the call at `:1321` under `event.kind == 5 && trust_level < TrustLevel::Trusted` (`:1320`) and the four refusal constants at `:2958-2975`.
- Moderator path and envelope: `process_deletion` at `:3510` passes `can_delete_any` to `delete_sealed_envelopes` at `:3630`; the admin check at `:3446` is `self.admin_cache.is_admin(author, ...)`.
- Routes that tombstone: `grep -rn "tombstone_before_delete" crates/nostr-bbs-relay-worker/src` returns call sites at `moderation.rs:349`, `admin_events.rs:279`, `user_admin.rs:225`, `nip_handlers.rs:3453` (envelope) and `:3558` (kind-5), and the definition at `lib.rs:1569`; `cron.rs` has none, and its comment at `:454-456` says so deliberately.
- No un-delete route: `grep -rn "FROM deleted_" crates --include=*.rs` shows the only `DELETE FROM deleted_*` statements at `whitelist.rs:524-525` (reset-db) and the re-key prune at `lib.rs:964`; every other hit is a SELECT, an INSERT or a test.
- Client: `grep -n "pub const MAX_PAGES\|DELETION_SINCE_MARGIN_SECS\|nostrbbs_deletion_sync_v3" crates/nostr-bbs-forum-client/src/stores/deletion_sync.rs` returns `:123`, `:119`, `:158-159`; `grep -n "pub fn honoured" crates/nostr-bbs-forum-client/src/stores/tombstones.rs` returns `:114`; `grep -rn "fn fold_deletions" crates` returns nothing, so the name cited by ADR-2017 and the relay's comments is gone and the function is `tombstones::fold_deletion` (`tombstones.rs:164`).
- CI: `gh run list -R DreamLab-AI/nostr-rust-forum --commit 3c48e2656d7cabefa894a59b827f5f0d3a8b32b7` returned one run, "CI", run 45056144222, conclusion `success`.
- Index: `node scripts/adr-index-gen.js docs/adr` regenerates `docs/adr/README.md`; `--check` passes.
