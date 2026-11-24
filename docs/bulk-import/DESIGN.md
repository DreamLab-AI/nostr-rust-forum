# Bulk import: design

Status: **draft for review** (2026-11-24). Reviews are appended in §15.

A kit-native pipeline that loads an external chat archive (Keybase today; Discord,
Slack or Matrix through new adapters) into a forum deployment **offline**, seals the
encrypted zones, and hands the operator a database and an object list to upload to a
new Cloudflare stack. It generalises the Node migrator built for the Keybase pilot
(`keybase-port/migrator`, which stays where it is for that pilot). This crate is its
successor: everything reusable moves here, everything Keybase-specific becomes one
adapter.

Crate: `crates/nostr-bbs-bulk-import` (library + binary `nostr-bbs-import`),
`publish = false`: the keystore, ledger and plan files are project-private formats
(global rule: no bespoke key or token formats as reusable crates). It still ships full
rustdoc, a README, the licence and repository metadata.

## 1. Goals and non-goals

Goals

* Any operator can turn an archive into a forum deployment with original timestamps,
  reply structure, attachments and reactions preserved, and no plaintext of an
  encrypted zone left behind.
* Every step is offline, resumable and idempotent. Re-running any step with the same
  inputs changes nothing.
* Nothing the tool does can reach a production service. **The crate makes no network
  calls at all** (no HTTP or WebSocket client in its dependency tree). Remote steps
  (D1 upload, R2 copy, admin calls) are written out as a plan and a runbook for the
  operator to run.
* Reuse kit crates (`nostr-bbs-core` for events, keys, NIP-44, gift wraps and the
  whitelist SQL; `nostr-bbs-zone-migrate` for sealing; `nostr-bbs-search-build` for
  the sealed search index) instead of copying them.

Non-goals

* Discord, Slack and Matrix adapters (the contract in §3 makes them small; not built).
* Executing the remote upload or the R2 copy.
* Minting or granting zone keys offline. Key distribution stays in the forum client
  (§8.2); an offline grant generator would be bespoke key distribution.
* Importing source-platform DMs. Only already-signed kind-1059 wraps travel (§11).

## 2. Pipeline

```
 source archive ──adapter──▶ intermediate (JSONL v1, §3) ──validate──▶
   ──plan──▶ identity plan (§4) + structure map (§5) + media plan (§6)
   ──keys──▶ keystore (atomic, refuse-to-change)
   ──media──▶ optimised content-addressed objects + manifest + upload manifest
   ──build──▶ local D1 (full ingest parity, ledger, §7)
   ── operator: mint + grant zone key in the client, archivist anchor post (§8.2)
   ──seal──▶ zone-migrate seal-offline → apply → commit → verify (§8)
   ──search-input──▶ docs.jsonl for nostr-bbs-search-build (§9, before purge)
   ──purge──▶ zone-migrate purge-offline → apply → commit
   ──upload-plan──▶ D1 export/import commands, R2 object list, cutover runbook (§10)
```

All state lives in a **work directory** (`--work DIR`, created 0700, files 0600):

| File | Written by | Holds secrets |
|---|---|---|
| `archive/` (intermediate) | `adapt` | no (but private content) |
| `identities.json` | operator (template from `plan`) | no |
| `structure.json` | operator (template from `plan`) | no |
| `target.json` | operator | no |
| `keys.json` | `keys` | **yes** (0600, never logged) |
| `media/` + `media/manifest.json` | `media` | no |
| `state/<db-fingerprint>/ledger.jsonl`, `run.json` | `build` | no |
| `seal/channels.json` | `seal-prep` | no |
| `search/docs.jsonl` | `search-input` | plaintext (0600, delete after the index build) |
| `upload/` | `upload-plan` | no |

## 3. Intermediate format (versioned JSONL)

Full spec: `FORMAT.md`. Summary:

```
archive/
  manifest.json        {"format":"nostr-bbs-bulk-import","version":1,"source":"keybase","source_id":"<team>",
                        "exported_at":<unix>,"counts":{…}}
  authors.jsonl        {"id","handle","display_name"?,"about"?,"avatar"?:{"sha256","path"},"bot"?:bool}
  channels.jsonl       {"id","name","topic"?,"created_at"?}
  messages.jsonl       {"id","channel","author","created_at","text","reply_to"?,"edited_at"?,
                        "attachments"?:[{"sha256","path"?,"filename","mime","bytes","status"}]}
  reactions.jsonl      {"message","author","emoji","created_at"}
  attachments/…        files named by the paths above (relative, confined to archive/)
  dms.jsonl            already-signed kind-1059 events, verbatim (optional)
```

Rules: one JSON object per line, UTF-8, `version` major must match; ids are opaque
strings unique per file (messages per archive); `created_at` is unix seconds of the
**original** send time; edits and deletes are already applied by the adapter (the
format holds final text, `edited_at` is informational); `reply_to` names a message id
in any channel or one absent from the archive (the planner decides what an unresolved
reply becomes); attachment `path` is relative and is canonicalised and confined to the
archive root before any read; `status` is `ok` | `unavailable` | `skipped` (with
`filename`, `mime`, `bytes` kept so a placeholder line can be written).

Adapters: a Rust trait

```rust
pub trait SourceAdapter {
    fn name(&self) -> &'static str;
    fn convert(&self, input: &Path, out: &mut ArchiveWriter) -> Result<AdapterReport, ImportError>;
}
```

with `ArchiveWriter` enforcing the format (sorted, deduplicated, validated lines,
attachments copied by content address). Two adapters ship:

* `generic`: the format itself (validate and normalise an archive another tool wrote,
  in any language). This is the main extension point: a Discord exporter written in
  Python only has to emit these files.
* `keybase`: reads the archiver's raw layout (`team.json`, `channels/<dir>/messages/YYYY/*.jsonl`,
  `users/<name>/profile.json`, `assets/manifest.jsonl`, `assets/refs.jsonl`), applies
  edits/deletes, splits reactions out, maps refs to attachment entries. It never copies
  raw lines (they carry Keybase attachment decryption keys).

## 4. Identity plan

`identities.json` maps each source author id to exactly one decision:

| Decision | Signs that author's history | Forum key | Recovery sheet |
|---|---|---|---|
| `fresh` (default) | a new key generated here | same | yes |
| `existing { pubkey }` | a per-person **archive key** generated here | live key kept; alias archive → live | optional |
| `existing_signs { }` | not allowed: we never hold another person's live secret | — | — |
| `merge { into }` | the target author's key (after its own decision) | — | — |
| `drop` | nothing imported; replies to it carry a "not migrated" note | — | — |
| `operator { handle, defer }` | the operator's key; with `defer` the messages are recorded and imported later by `build --deferred-only` once the operator imports their key (`keys import`) | operator | no |
| `archivist` | (reserved) the archivist: signs topic roots and seals, admin, zone cohorts, never `agent` | — | no |

Validation refuses: unknown authors, chains or cycles in `merge`, a `merge` into a
dropped author, a pubkey shared by two people, an `existing` pubkey equal to a key we
generate, and any author without a decision when `--strict` (default) is on.

**Why archive keys plus aliases.** History must be signed by *someone*, and Nostr
signatures cannot be re-attributed. A person who already has a live key keeps it (we
never hold or ask for it); their imported history is signed by a fresh per-person
archive key, and a **profile successor** (`pubkey_aliases`, many predecessors → one
successor since migration 0016) makes every client show the live identity. Signing the
history with an operator key and attributing it in text would forge authorship;
holding people's live keys would be key custody. See `SECURITY.md`.

**Keystore.** `keys.json` (0600, directory 0700): `{version:1, keys:{<label>:{pk, sk,
created_at, role}}}`. Every write goes through one function: temp file in the same
directory opened `O_EXCL` 0600, write, fsync, rename, fsync directory, and it refuses
(writing nothing) if any existing label would be removed or have `pk`/`sk` changed.
Keys come from `nostr_bbs_core::keys::generate_keypair` (OS RNG). Secret bytes are
held in `Zeroizing` buffers and never formatted into logs, errors or the ledger.
`keys import --label L --from FILE` (FILE 0600, hex or nsec) is the only way an external
secret enters (the deferred operator path); it is refused if `L` exists with a
different key.

## 5. Structure mapping

`structure.json`:

```json
{ "zones": [{"id":"zone2","cohorts":["zone2","minimoonoir"],"encrypted":true}],
  "threads": { "rants": {"zone":"zone2","section":"zone2-rants",
                          "channel": {"existing":"<kind-40 id>"} | {"new":{"name":"Rants","about":"…"}}} },
  "channels": { "<source channel id>": {"thread":"rants","topic":"#economics"} },
  "archivist_label": "archivist" }
```

* One **topic per source channel**: a kind-42 root signed by the archivist,
  `created_at` = the channel's first imported message − 1 s (the sealer works in
  `(created_at, id)` order, so a root seals before its replies), content
  `#<topic> — archived from <source> <source_id> (<first> – <last>, <n> messages)`.
  Several source channels may fold into one thread (section).
* **Section rule.** The forum client routes a kind-40 by its `section` tag: equal to a
  zone id or `<zone-id>-…`, otherwise it falls through to the first zone silently.
  The planner refuses any section that does not start with its thread's zone id.
* New threads get a kind-40 signed by the archivist with `["section",…]` and
  `["zone",<zone id>]` tags (what the admin UI publishes), plus a `channel_creators`
  row and a `channel_zones` row (§7). Existing threads must already be stored in the
  target D1 (`build` checks) and bound to the same zone.
* **Tags.** Replies use the client's own shapes with an empty relay hint, so no
  deployment URL is signed into tags: `["e",<thread>,"","root"]`,
  `["e",<topic root>,"","reply"]`, `["p",<root author>]`, and for a reply to an imported
  message `["e",<parent>,"","quote"]` (+ `["p",<parent author>]`). An unresolved reply
  gets a first line `↪ reply to <handle> (<date>)` or `↪ reply to a message that was
  not migrated`. A `["source","<source>:<source_id>#<message id>"]` tag records
  provenance (the Node tool used `keybase`; the new tag name is source-neutral).
* **Outer tags are the sealer's.** The build never writes `zk` or `sealed` tags;
  `seal_original` copies the reply link outward itself. A test asserts it.
* **Reactions** are folded into the target message's text
  (`— reactions: 👍 ×3 (alice, bob, carol)`), never kind-7: the relay's retention
  sweep deletes kind 7 after 30 days.
* Long text is truncated at 60 000 characters with a marker.

## 6. Media

* **Content-addressed.** Each attachment is keyed by the SHA-256 of its original bytes;
  identical bytes are processed once however often they were posted.
* **Optimisation** shells out to ImageMagick (`magick`, a thin wrapper, acceptable
  under the Rust-first rule): `-auto-orient -strip -resize 2048x2048> -quality 82` to
  WebP plus a 480 px thumbnail; animated GIFs keep their frames (stripped). The input
  coder is pinned (`jpeg:`, `png:`, `gif:`, `webp:`, `heic:`, `avif:`, `tiff:`, `bmp:`
  from the sniffed magic bytes, never from the extension), SVG/MVG/MSL/PS/PDF/text
  coders are refused, a policy-restricted environment is set, and an image that fails
  to strip is **never** uploaded raw (it may carry GPS). EXIF `DateTimeOriginal` and the
  first send time are kept in `media/manifest.json`, not in the stored bytes.
* **Placement.** Zone media go to `pods/<owner>/media/zones/<zone>/<sha16>.webp` (+
  `_thumb.webp`): only zone members can read them (pod zone ACL). The owner is the
  archivist by default (one pod to provision and size), or each author's signing key
  (`--media-owner author`). Zone containers accept only image types; other attachment
  kinds become `[video|audio|pdf|file not migrated: name, size, date]` lines. URLs are
  built from `target.json` (`pod.http`).
* **Quota.** `media plan` totals bytes per owner pod and refuses when a pod exceeds
  `--pod-quota-mb` (default the kit's 50 MiB built-in, or the deployment's
  `POD_QUOTA_MB`), naming the admin `/.quota` override.
* **Upload manifest.** `upload/r2-objects.jsonl`: `{key, file, content_type, bytes,
  sha256, owner}`; the runbook turns it into `wrangler r2 object put` lines. A bulk
  R2 put bypasses the pod's `quota_usage` accounting: the runbook says to set the owner
  pod's admin limit first and records the gap (§14).
* **Cutover copy.** `upload/r2-copy.jsonl` lists objects that must move bucket to
  bucket at the identical key (e.g. verbatim live posts that link the old pod).

## 7. Build: local D1 with ingest parity

Port of the Node `d1.mjs`/`fold-publish.mjs` (INGEST-PARITY.md), extended to the rows
the offline target can no longer get from admin endpoints:

| Row | How |
|---|---|
| `events` | `INSERT … WHERE NOT EXISTS (deleted_events …) ON CONFLICT (id) DO NOTHING`; replaceable (0, 3, 10000–19999) and addressable kinds use the relay's insert-if-not-beaten + prune pair; `d_tag`, `received_at` = build time; `created_at` = original |
| `event_tags` | **never by hand**: the relay trigger `trg_event_tags_ai_v3` fills it; `build` refuses without it |
| `channel_creators` | kind 40, first write wins |
| `profiles` | kind 0 upsert guarded on `last_kind0_at` |
| `channel_zones` | the admin endpoint's upsert (`INSERT … ON CONFLICT (channel_id) DO UPDATE`), for every new thread; zone-migrate's offline sealer refuses unbound channels |
| `whitelist` | `nostr_bbs_core::whitelist_sql::WHITELIST_GRANT_COHORTS_SQL` (merge-only cohorts) for every key that signs or must read; `is_admin = 1` only for the archivist and the operator; never the `agent` cohort |
| `posts_created`, `last_active_at` | `MAX(…)` over the whole ledger, so resumed runs never under-count |
| `pubkey_aliases` | archive key → live key, the relay's guarded upsert (no chains, keys lowercase) |

Not written (as live ingest at import time would not matter): broadcast, push,
search embeddings, moderation projections.

**Apply modes.** `--apply sqlite --d1 FILE` writes the miniflare SQLite file directly
in one `BEGIN IMMEDIATE` transaction per batch (the stack must be down; the tool
refuses if the file is locked). `--apply sql-out DIR` writes numbered chunks for
`wrangler d1 execute <db> --local --persist-to … --file`, which the operator (or
`nostr-bbs-import apply`, which strips `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID`
and refuses `--remote`) runs.

**Ledger.** `state/<fp>/ledger.jsonl`: one line per committed event `{k:<source key>,
id, pk, t, kind}`, appended and fsynced only after its batch committed; a torn final
line is ignored. A re-run emits only what the ledger lacks; ids are pinned, so a
growing archive never yields a second copy and children always cite the id actually
stored. `run.json` records the target URLs and the D1 file fingerprint; a different
target or database in the same state dir is refused (signed content embeds pod URLs;
sealing freezes them).

**Guards.** `build` refuses when the zone-migrate state file shows any `purged` entry
(plaintext must never come back), when a thread kind-40 it needs is not stored, or when
a section breaks the rule in §5. The `deleted_events` guard in every insert backs this
up at the SQL level.

**Batching.** ≤ 500 statements per batch (D1 per-query limits); a batch is one
transaction in sqlite mode and one file in sql-out mode.

## 8. Seal, verify, purge

### 8.1 Glue, not a second sealer

`nostr-bbs-zone-migrate` owns sealing. This crate adds one thin module (`seal`) that:

* writes `seal/channels.json` (`[{"id","zone"}]`, the tool denies unknown fields) for
  every encrypted-zone thread the build touched;
* checks preconditions offline and explains what is missing: the archivist is a
  whitelisted non-agent admin; every thread is bound in `channel_zones`; an anchor
  (a `zk`-tagged post of the zone) exists or the unanchored path is chosen;
* prints the zone-migrate commands (`seal-offline`, apply, `seal-offline-commit`,
  `verify`, `purge-offline`, apply, `purge-offline-commit`) with
  `NOSTR_BBS_MIGRATE_KEY` taken from the archivist entry by the operator's shell (the
  key is never passed on a command line);
* `verify-parity` (§12) runs after each phase.

The library calls it makes (`offline::open_d1`, `read_channel_events`, state types) are
confined to this module and written against the API at the branch point; the paging
agent is changing zone-migrate (`binding_refusal`, `topic_refusal`, `PurgeItem`), so a
small fix at rebase is expected and reported.

### 8.2 Where the zone key comes from

Sealing needs the zone's epoch key **before** upload, and the forum client is the only
place keys are minted and granted. The workable order (the pilot's):

1. `build` into a local D1 that a local copy of the target stack (same zone config,
   `RELAY_URL` set) serves.
2. In the client, as the operator/archivist: Admin → Encryption → Create key (epoch 1),
   then "Grant to members missing it". The grants are kind-1059 rows in this D1 and
   travel with the upload.
3. The archivist posts one zk-encrypted notice: the **anchor** that lets the sealer
   confirm the key against a live encrypted post.
4. Seal, verify, purge; then upload.

Alternative without an anchor: zone-migrate's `--allow-unanchored-first-encryption
--expect-zone-key ZONE=EPOCH:PUBKEY` (the first encryption of an all-plaintext zone,
refused unless the relay holds no encrypted post of the zone). Purge then needs a member
post at the sealed key first. A key file (`--keys-file`) seals correctly but nobody can
read the result until the same key is granted; rotate the zone afterwards if one was
used.

## 9. Search index hand-off

`search-input` writes `search/docs.jsonl` (0600) for `nostr-bbs-search-build`: one
`{"id","text","epoch","zone_pk"}` per sealed original, `id` = the **original** event id
(what the sealed envelope's `sealed` tag names and what the client resolves), `text` =
the plaintext from D1, `epoch` from the zone-migrate state entry, `zone_pk` from the
key file or the operator-supplied pubkey. It must run **after** `seal-offline-commit`
and **before** purge (the plaintext is gone afterwards) and refuses otherwise. The
publisher is the archivist. Delete the file after the build.

## 10. Upload and cutover

`upload-plan` writes `upload/RUNBOOK.md` and `upload/commands.sh` (never executed by
the tool):

1. New stack alongside the old one (new worker names, new D1, new R2 bucket, new KV),
   config projected from the same forum config. Boot the relay once so
   `ensure_schema()` creates the schema and triggers.
2. `wrangler d1 export <local db> --local --no-schema --output data.sql`, with
   `event_tags` **excluded** (it has no primary key; dumped rows plus trigger rows would
   double every tag): either `--table` per table, or a filter the tool applies to the
   dump. `upload-rehearse` proves the chosen form locally: import the dump into a fresh
   local relay D1 and compare per-table counts and the tag index (§12).
3. `wrangler d1 execute <new db> --remote --file data.sql` (chunked under D1's request
   limits), then the R2 object puts and the bucket-to-bucket copy list.
4. One revertable website commit points the forum at the new stack; the old stack is
   frozen read-only (not deleted) until the operator retires it. Roll-back = revert
   that commit.

Cost notes (README): D1 rows written/stored per event (≈ 1 `events` + n `event_tags`
rows each), Workers Paid for D1 size beyond the free tier, R2 storage and class-A ops
for the puts, pod quota.

## 11. DMs

* **Verbatim copy** of kind-1059 wraps whose recipient keeps their key in the new
  deployment (an `existing` identity, or the operator's old keys): same id, signature
  and `created_at`; nothing decrypted. Grants (rumor 21453) cannot be told apart
  without decrypting, so copies are refused unless the operator acknowledges stale
  grants travel (`--allow-stale-grants`).
* **Re-wrap** only of DMs the operator **sent**: unwrap in memory with the operator's
  old key (0600 file), require rumor author = old key, re-seal with the old key (the
  seal signer must be the rumor author), wrap to the new key. Rumors by anyone else are
  skipped and counted: we never forge a sender. Only NIP-17 kinds (14, 7, 5, 15) travel.
  Uses `nostr_bbs_core::gift_wrap`.

## 12. Parity invariants (`verify-parity`, and the e2e test)

Before seal:

* every message source key in the ledger maps to a stored event; counts match the plan;
* 0 orphan e-tags: every `root` resolves to a stored kind-40, every `reply`/`quote` to a
  stored kind-42 **in the same thread**;
* `event_tags` rows = Σ tags of stored events (trigger fired once per insert);
* `channel_creators`, `channel_zones`, `profiles` and `whitelist` rows as planned;
  `posts_created` = ledger counts.

After purge: no plaintext kind-42 in sealed threads; every original id is tombstoned in
`deleted_events`; every `reply`/`quote` resolves through the relay's F2 rule (the stored
kind-42 or an admin envelope whose `sealed` tag names it, in the same channel).

Idempotence: a second `build` adds 0 rows (before and after purge); after purge it
re-inserts no plaintext.

## 13. Tests

* Unit tests per module (format validation, adapters, identity validation, keystore
  refusal and atomicity, section rule, tag shapes, SQL generation, ledger torn line,
  media coder pinning, DM copy/re-wrap rules).
* End to end on a synthetic Keybase-layout archive (4 authors incl. a bot, a merged
  account, an existing live user, 2 channels, edits, deletes, replies, reactions, one
  image when `magick` exists): adapt → plan → keys → build into a temp SQLite built from
  the relay migrations plus the boot SQL (as zone-migrate's tests do) → parity → re-run
  → anchor post + key → zone-migrate offline seal → apply → commit → verify → search
  input → purge → parity after purge → re-run (no plaintext back).
* Drift guard: a test `include_str!`s the relay's `lib.rs` and `user_admin.rs` and
  asserts the trigger name and the SQL fragments this crate mirrors are still there.
* Workspace wasm32 check: native dependencies under `cfg(not(target_arch = "wasm32"))`,
  native-only modules gated, a stub `main` for wasm32.

## 14. Deferred and known gaps

* Discord, Slack, Matrix adapters.
* Running the remote upload and the R2 copy (plans only).
* Pod `quota_usage` is not updated by a bulk R2 put; per-pod provisioning (root
  container markers, KV metadata) must happen through the pod API before the objects
  are visible to its listing.
* Anything that needs a zone-migrate change is a follow-up, not edited here.
* Client limits for very long topics (KIT-FIXES.md) are client work, unchanged here.

## 15. Reviews

(appended)
