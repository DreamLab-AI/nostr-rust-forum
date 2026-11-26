# Relay deletion and tombstones: what an admin should know after upgrading

Applies to a deployment that moves to kit `3c48e26` (`v1.0.0-beta.21-rc.2`) or later. The decisions are
[ADR-2033](../adr/ADR-2033-nip09-tombstones-member-deletion-gate-and-deleter-scoped-sync.md) and
[ADR-2034](../adr/ADR-2034-absence-is-reported-only-after-an-authenticated-answer.md); open gaps are
[`known-findings.md`](../security/known-findings.md) KF-14 to KF-28. Everything below was read from the code at `3c48e26`. The
D1 queries and routes are given from the code, not run for this note: no live relay was touched.

Names: wrangler resolves `nostr-bbs-relay` only from a config that declares it (see
[disaster-recovery.md](disaster-recovery.md) section 0); the live name is `dreamlab-relay`.

## 1. First start after the relay deploys

- `ensure_schema` creates two tables, `deleted_events` and `deleted_addresses`. There is no migration file for them, so a
  database provisioned by `wrangler d1 migrations apply` alone has neither until the relay serves its first request.
- The same pass runs two one-time jobs and records each in `settings` once it has succeeded:
  - `nip09_tombstones_backfilled`: rebuilds tombstones from the kind-5s already stored (own-deletion semantics only).
    A moderator's past deletion of someone else's event left no record of that author, so it is not rebuilt.
  - `nip09_plain_addresses_rekeyed`: moves address tombstones for plain replaceable kinds (0, 3, 10000 to 19999) onto an
    empty d-tag. Only rows written by an earlier build of this feature have anything to move.
- Check: `SELECT key, value FROM settings WHERE key LIKE 'nip09_%';` should return both keys, and `SELECT count(*) FROM
  deleted_events;` should be non-zero if the relay holds any kind-5 with an `e` tag of 64 lowercase hex (the backfill reads no other). A missing key means that job has not completed: a
  failing statement logs `ensure_schema: ... failed` and the job is retried on the next cold isolate, and nothing is lost
  meanwhile except the re-insert refusal. Ingest keeps working if the tables or the lookup fail.

## 2. Moderators must remove migrated posts

A member's kind-5 naming a sealed original (a post migrated under ADR-2017) is refused with `restricted: migrated (sealed)
posts can only be removed by a moderator`, and so is any kind-5 naming an id the relay does not hold (`restricted: deletion
names an event this relay does not hold`) or another member's post (`restricted: TL3+ required to delete others' events`).
Members therefore cannot delete their own migrated posts, and cannot delete a post before the relay has stored it. Expect
support requests.

To remove a migrated post, an admin or TL3+ publishes a kind-5 naming its original id (the message Delete action in the forum
client publishes one, `components/message_bubble.rs:339`). The relay then deletes the envelope that wraps it, and records a tombstone, provided the envelope's
author, normally the migrator key, is **still a current admin**. If the migrator was demoted or removed, the envelope stays and
the post stays readable from it. Keep the migrator an admin until the posts that matter are handled, or accept that they cannot
be removed relay-side (KF-18).

Clients differ in what they do next. A client that loads afterwards no longer receives the envelope. A client already showing
the post hides it only if the kind-5's author is the original's author or an account whose whitelist row has `is_admin = 1`;
a TL3 moderator, or an admin who exists only in the static `ADMIN_PUBKEYS` variable, is not recognised by clients (KF-27). If
a post must disappear from open sessions, delete it from an account with `is_admin = 1` in D1. Whether a cached copy outlives
the envelope on a device was not checked.

## 3. The deletion audit fields

| Route | Reply and audit fields |
|---|---|
| `POST /api/reports/resolve` with `resolution: "delete"` | Reply: `removed` (`{id, author, kind}` of the row actually deleted, or `null`), `tombstoned`, and `deleteError` only if the DELETE failed. The `admin_log` row has action `report_resolve`, `target_pubkey` = the stored author when a row was found (else the reporter's claim), and `new_value` JSON `{status, removed, tombstoned, reportedPubkey, deleteError?}`. |
| `POST /api/admin/user/delete` with `delete_events: true` | Reply and `admin_log` `new_value`: `tombstoned`. Without `delete_events` there is no `tombstoned` field: nothing was attempted. |
| `POST /api/admin/events/delete` (ADR-2017 purge) | Unchanged reply `{deleted, notFound, skipped}` and one `events.delete` audit row; tombstones are recorded but not reported. |

Reading them:

- `removed: null` means no row was found, the read of the row failed, or the DELETE failed. If it failed, `deleteError` is set.
  The relay never claims a removal the DELETE did not make.
- `tombstoned: true` means every tombstone statement ran without error. It is also `true` when no row existed, in which case
  nothing was recorded, so read it with `removed`. `tombstoned: false` means a tombstone could not be written: the deletion
  went ahead, and the content can be published again by anyone holding the signed event. For a user purge this cannot be
  retried once the rows are gone, so treat it as an incident.
- A report resolved as `hide` records no tombstone, because it can be reversed. Retention pruning in `cron.rs` records none either.
- `reported_pubkey` in the report list is only what the reporter claimed; the stored author and kind are known only after the
  resolve (KF-15).
- The audit log is `GET /api/admin/audit-log`.

## 4. Tombstones are permanent, and live in D1

- There is no route that removes one tombstone (KF-14). A moderator's, a report-delete's and a purge's tombstone is permanent.
  A user delete with `delete_events` leaves that member's pubkey and event ids (no content) in `deleted_events`; a member
  re-admitted afterwards cannot re-publish what was removed.
- `POST /api/admin/reset-db` clears `events`, `whitelist`, `deleted_events` and `deleted_addresses`. It does not clear the
  `settings` markers, so after a reset the backfill does not run again; a kind-5 replayed through ordinary ingest records its
  own tombstones as it is processed.
- Tombstones travel with D1. An export (`scripts/dr-export.sh`) includes them. A Time Travel or backup restore returns the
  tombstones of its restore point: a deletion made after it can be published again, and a purge tombstone made after a
  pre-purge backup is gone along with the purge (the plaintext returns with that backup and nothing refuses it).
- A user purge covers rows authored by the member's identity key only. Events signed by their device keys and gift wraps
  addressed to them are not tombstoned or deleted by it (KF-16).

## 5. What members and clients will notice on first load of the new client

- Unsent drafts from before the change are deleted once (they cannot be attributed to an account).
- Bookmarks saved before the change stay, visible to every account on the browser, with their text previews erased.
  Post notifications saved before the change have their body replaced by "Open to read this message.".
- Zone keys stored before the change stay visible to every account on that browser; new ones are per account. Keys load
  after sign-in, so the first encrypted messages of a cold load can show placeholders briefly.
- A device with no deletion marker fetches the newest 1,000 deletions once, as before, then only newer ones. A cold link into
  an encrypted zone can still say "Topic Not Found" for some seconds before correcting itself (KF-23).
  Note 2026-11-23: from kit `fd31193` (PR #98, tag `v1.0.0-beta.21-rc.3`) such a link shows "Fetching your keys for this
  zone…" until the keys arrive instead; KF-23 is closed.
- Admins creating or rotating a zone key are told when another account on the same browser holds a higher epoch, and are
  asked to confirm when posts name an epoch above the one about to be minted.

## 6. Rollback

The new tables and `settings` rows are additive. Rolling the relay worker back to a build that predates them leaves the
tables unread; a later roll-forward finds the markers set and does not re-run the backfill, so kind-5s accepted by the older
build in between are not tombstoned. This was reasoned from the code, not rehearsed.
