# Disaster recovery runbook

Status: Phase 0, verified by one restore rehearsal on 2026-10-20 (see
[Rehearsal record](#rehearsal-record)). Rule: use wrangler's own export, import and
Time Travel commands. Never hand-write SQL dumps.

## 0. Names: config versus live account (the incident trap)

The `wrangler.toml` files and the live Cloudflare account use **different names** for
the same resources. D1 matches by UUID; R2 binds by name, so the mismatch matters.

| Resource | Name in `wrangler.toml` | Live account name | Identifier |
|---|---|---|---|
| Relay D1 | `nostr-bbs-relay` | `dreamlab-relay` | `97c77d23-0e24-4325-ada7-1747eab4095b` |
| Auth D1 | `nostr-bbs-auth` | `dreamlab-auth` | `e3981999-e8f0-4c07-9e4b-2e50859b8524` |
| Pods R2 | `nostr-bbs-pods` (pod-worker, auth-worker) | `dreamlab-pods` | by name |
| Vectors R2 | `nostr-bbs-vectors` (search-worker) | `dreamlab-vectors` | by name |

`wrangler d1 <cmd> nostr-bbs-relay` only resolves when wrangler reads a config that
declares it (run from `crates/nostr-bbs-relay-worker/` or pass `--config
crates/nostr-bbs-relay-worker/wrangler.toml`, which binds both D1s). Outside a config,
use the live names or the UUIDs. No file in `scripts/`, `dream.config.json` or
`forum.example.toml` records the mapping; production R2 buckets must therefore be
deployed from a config that is not in this repository. Confirm which before any R2
restore.

## 1. Inventory

Verified 2026-10-20 (UTC). `C` = `--config crates/nostr-bbs-relay-worker/wrangler.toml`.

| Store | Holds | Export | Restore | Verified |
|---|---|---|---|---|
| D1 `nostr-bbs-relay` (21 user tables, 39 indexes, 3 triggers) | all events, tags, profiles, whitelist, governance, broker, push | `wrangler d1 export nostr-bbs-relay --remote $C --output relay.sql` (or `scripts/dr-export.sh`) | `wrangler d1 execute <empty-db> --remote --yes --file relay.sql`; or Time Travel | 2026-10-20: export, import to scratch DB, row counts identical |
| D1 `nostr-bbs-auth` | WebAuthn credentials, challenges, members, invitations, username reservations, agent_jobs, broker and ledger tables (25 tables) | `wrangler d1 export nostr-bbs-auth --remote $C --output auth.sql` | as above | export verified 2026-10-20; **import not rehearsed** |
| D1 Time Travel (both) | point-in-time history (retention depends on the Cloudflare plan; confirm it, not verified here) | `wrangler d1 time-travel info <db> $C` | `wrangler d1 time-travel restore <db> --bookmark=<id> $C` (destructive, in place) | `info` verified; `restore` **deliberately not run** |
| Durable Object (relay) | session state only, rebuilt on reconnect | none needed | none needed | by design |
| KV `POD_META` `8ec8759a…` | pod metadata, 125 keys | `wrangler kv bulk get <keys.json> --namespace-id <id> --remote` (open beta) | `wrangler kv bulk put` | key count verified; bulk get not run |
| KV `SEARCH_CONFIG` `440b1f07…` | search config, 1 key | as above | as above | key count verified |
| R2 `dreamlab-pods` (config: `nostr-bbs-pods`) | pod files, 1,051 objects, 15.2 MB | none in wrangler (see §7) | `wrangler r2 object put` per object | `r2 bucket info` verified |
| R2 `dreamlab-vectors` (config: `nostr-bbs-vectors`) | search vectors, 1 object, 18.8 kB | none in wrangler | rebuildable by the search worker | `r2 bucket info` verified |

The relay holds 7,987 rows across its tables at rehearsal time (events 2,439;
event_tags 4,527; admin_log 301; broker_cases 254; channel_zones 115; others smaller).

## 2. Procedure: SAFE-READ then WRITE, in this order

**SAFE-READ (any time, changes nothing in production):**

1. Record the Time Travel bookmark for each DB: `wrangler d1 time-travel info
   nostr-bbs-relay $C` and the same for `nostr-bbs-auth`. This is your rollback point.
2. Export both DBs to a directory **outside the repo**: `scripts/dr-export.sh
   <backup-root>`. It refuses a path inside the repo, writes a dated directory, and
   prints `sha256sum` values plus before/after bookmarks. If the relay bookmark moved
   during the export, treat the "before" bookmark as the restore point.
3. Copy the directory to storage that survives loss of this host. Exports contain
   personal data and ciphertext; keep them private and never commit them.

**WRITE (only after SAFE-READ is complete and a human has approved):**

4. Prefer Time Travel for "bad write or bad migration inside the Time Travel retention window" (see §4).
5. For loss or corruption beyond that, create a fresh D1 and import the export (§3).
   Rehearse into a scratch DB first and compare counts.
6. Re-point bindings (`database_id`) only after the counts match; redeploy workers
   from the host shell, not from here.

## 3. Hazard: the `event_tags` trigger, and the drop-only rule

`wrangler d1 export` emits `CREATE TABLE` statements first and `CREATE TRIGGER`
statements last (observed: 8,053 statements, tables before triggers). So **importing
into a database that already has `trg_event_tags_ai_v2` fires the trigger for every
inserted `events` row and doubles `event_tags`**; `event_tags` has no primary key to
reject the duplicates. Rules:

- Import only into an **empty** database. Never import "on top of" a live one.
- If you must load into a DB that already has the trigger, **drop** the triggers
  (`DROP TRIGGER`) first, import, then recreate them from the export. This is the
  drop-only rule: the only permitted mid-restore schema change is dropping triggers;
  never delete or edit `event_tags` rows by hand.
- `reset-db` deletes `events` and `whitelist`, and `event_tags` via
  `trg_event_tags_ad`, but leaves `channel_zones`, `profiles` and `broker_*` orphaned.
  It is not a restore tool; do not use it as the first step of one.
- After any restore compare `event_tags` against the source (4,527 at rehearsal) and
  the trigger count (3). A doubled `event_tags` is the signature of this hazard.

## 4. Time Travel path

```
wrangler d1 time-travel info nostr-bbs-relay $C               # current bookmark
wrangler d1 time-travel info nostr-bbs-relay $C --timestamp=<RFC3339>   # bookmark at a time
wrangler d1 time-travel restore nostr-bbs-relay $C --bookmark=<id>      # DESTRUCTIVE
```

`restore` rewinds the live database in place and overwrites everything after the
bookmark; the pre-restore state is reachable only if you recorded its bookmark first (wrangler
also reports one on restore; not exercised). Capture the current bookmark first. Bookmarks advance continuously on
the live relay even when row data is unchanged, so a bookmark is a point in time, not
a content hash: use `sha256sum` of an export to prove content. Time Travel covers the
D1 databases only, not KV or R2.

## 5. KV inventory (read-only)

Counted 2026-10-20 with `wrangler kv key list --namespace-id <id> --remote`.

| Namespace | Id | Keys | Nature |
|---|---|---|---|
| POD_META | `8ec8759ab40d4709a831bf6b0e5241eb` | 125 | durable, back up |
| SEARCH_CONFIG | `440b1f07ff224fb8ad644e094c6766c0` | 1 | durable, back up |
| auth-worker-admin-kv | `761619675e114d53ab92d3895cd8c274` | 0 | empty |
| dreamlab-admin-kv | `b294deb03d3a49df9ccb9bee41bcb5ef` | 0 | empty |
| pod-worker-admin-kv | `9e414a16557a4c4b82a1c5dbffbd26b2` | 0 | empty |
| CONFIG | `cbb857ac37424993a3aeafbabe9b808e` | 0 | empty |
| SESSIONS | `901345296c2848788066686aa67d5909` | 0 | ephemeral |
| RATE_LIMIT | `c56bfb95f0984b3a8822866b094f3a61` | 0 | ephemeral |
| auth-worker-nip98-replay | `56f21af59b4f44468f2967b51cd656fe` | 0 | ephemeral |
| pod-worker-nip98-replay | `335e75ee88754e099bd813795322928e` | 0 | ephemeral |
| relay-worker-nip98-replay | `c5f76343697f473aa9e43965bb21ae2c` | 0 | ephemeral |
| search-worker-nip98-replay | `329cd5c59ca3494299a72bb92f174d6d` | 0 | ephemeral |

Twelve namespaces exist. Only POD_META and SEARCH_CONFIG hold state worth restoring.
A key list is not a backup; it only proves what a backup must contain. Dump values
with `wrangler kv key list` piped to a `keys.json` and `wrangler kv bulk get` (open
beta; not exercised in Phase 0).

## 6. EVENT-replay path (rebuilding the relay from signed events)

If D1 is lost and only signed events survive elsewhere, events can be replayed to the
relay as `EVENT` messages. The relay rejects any event whose `created_at` is more than
7 days from now (`MAX_TIMESTAMP_DRIFT = 60*60*24*7`,
`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:44`), so replaying old
events needs a **maintenance waiver**: a reviewed, time-boxed change that relaxes the
drift check for the replay window and is reverted afterwards. Do not ship the waiver as
a standing config. Replay preserves signatures and event ids but not rows derived by
other paths (whitelist, profiles, channel_zones, broker_*, governance receipts);
prefer a D1 export restore whenever one exists.

## 7. What no backup preserves

- **Zone epoch secrets** held in the admin's browser IndexedDB. Neither D1, KV nor R2
  contains them. Losing that browser profile loses the ability to read zone-encrypted
  history; export them from the admin client separately.
- **DM recipient keys.** Gift-wrapped DMs are encrypted to recipient keys the server
  never holds. A restored relay returns ciphertext only the original key holders can
  read.
- **Author attribution** after any restore path that rewrites ids or loses the
  `pubkey_aliases` / whitelist linkage; check `pubkey_aliases` (1 row) and `whitelist`
  (39 rows) after restore.
- **R2 and KV have no wrangler export.** `wrangler r2 object` offers only `get`, `put`
  and `delete` in 4.147.0 (`wrangler r2 object list` fails verbatim: `Unknown
  arguments: list, nostr-bbs-pods`). Bulk R2 backup needs the S3 API (for example
  `rclone`), which is not set up. Counts come from `wrangler r2 bucket info`.
- Secrets (`wrangler secret`) cannot be read back; keep them in the secret store.

## 8. Schedule recommendation

- Weekly `scripts/dr-export.sh` to off-host storage; retain at least four.
- Before every migration or deploy that touches D1: run it, and note the bookmark.
- Monthly: the restore rehearsal in §9, including a first rehearsal of the **auth**
  DB, which is not yet covered.
- Quarterly: confirm the R2 bucket mapping in §0 and set up an S3-based copy.

## Rehearsal record

| Field | Value |
|---|---|
| Date (UTC) | 2026-10-20, 10:48 to 10:51 |
| Source | production relay D1 `97c77d23-…` (live name `dreamlab-relay`), SELECT and export only |
| Scratch DB | `nostr-bbs-relay-restore-rehearsal`, `8239259f-74dc-468b-8d2d-840db0c50ff0`, created 10:49:03Z, deleted |
| Export | `wrangler d1 export nostr-bbs-relay --remote --config crates/nostr-bbs-relay-worker/wrangler.toml --output relay-rehearsal.sql`, exit 0, sha256 `ae52029f…32f0` |
| Import | `wrangler d1 execute nostr-bbs-relay-restore-rehearsal --remote --file relay-rehearsal.sql --yes`, exit 0, 8,053 queries in 719 ms, final bookmark `00000000-000005e5-…` |
| Compare | per-table `count(*)` over the 21 user tables, production (SELECT) versus scratch: **identical** (total 7,987 rows each, `event_tags` 4,527, `events` 2,439); `sqlite_master` object counts identical (39 indexes, 21 tables, 3 triggers) |
| Drift control | production bookmark `0000a738-0000011f-…` before and after both count queries: unchanged |
| Outcome | **PASS.** Restore into an empty D1 reproduced rows, indexes and triggers. `event_tags` equalled production, so the §3 hazard did not occur on an empty target |
| Teardown | `wrangler d1 delete nostr-bbs-relay-restore-rehearsal --skip-confirmation`: "Deleted … successfully"; `d1 list` then shows only `dreamlab-relay` and `dreamlab-auth` |
| Not covered | auth DB import; Time Travel `restore`; KV and R2 restore; the import-into-populated-DB hazard (documented from the export's statement order, not triggered) |

Notes: the brief expected `event_tags` = 4,515 and 7,964 total rows; production had
since grown to 4,527 and 7,987, and scratch matched production, not the earlier
figures. `d1 list` reports `num_tables: 0` for both DBs, a display quirk and not
evidence of emptiness.
