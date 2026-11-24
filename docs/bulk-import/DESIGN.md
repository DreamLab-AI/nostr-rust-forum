# Bulk import: design

Status: **implemented** (2026-11-24) after the architecture and security reviews (§15).

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
  encrypted zone left in the deployed database (local residue is the operator's to
  destroy: SECURITY.md checklist; zone media are access-controlled, not encrypted).
* Every step is offline, resumable and idempotent. Re-running any step with the same
  inputs changes nothing.
* Nothing the tool does can reach a production service. **The crate makes no network
  calls at all**: no HTTP or WebSocket client in its runtime dependency tree (it does
  not link `nostr-bbs-zone-migrate`, whose library carries one; that crate is a
  dev-dependency for the end-to-end test only). Remote steps (D1 upload, R2 copy,
  admin calls) are written out as a plan and a runbook for the operator to run.
* Reuse kit tools instead of copying them: `nostr-bbs-core` (events, keys, NIP-19,
  gift wraps, the whitelist SQL) as a library; `nostr-bbs-zone-migrate` (sealing) and
  `nostr-bbs-search-build` (sealed search) through their CLIs, whose contracts are
  documented; their file formats (channels file, sealed envelopes, search input rows)
  are produced or read here.

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
| `state/ledger.jsonl`, `state/run.json` | `build` | no |
| `seal/channels.json`, `seal/RUNBOOK.md` | `seal-prep` | no |
| `search/docs.jsonl` | `search-input` | plaintext (0600, delete after the index build) |
| `upload/` | `upload-plan` | no |

## 3. Intermediate format (versioned JSONL)

Full spec: `FORMAT.md`. Summary:

```
archive/
  manifest.json        {"format":"nostr-bbs-bulk-import","version":1,"source":"keybase","source_id":"<team>",
                        "exported_at":<unix>,"counts":{…}}
  authors.jsonl        {"id","handle","display_name"?,"about"?,"bot"?:bool}
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

Limits of v1, by design: no thread concept separate from the channel (a Slack
`thread_ts`, Discord thread or Matrix `m.thread` maps to `reply_to` the thread's first
message); mentions stay text (no `p`-tag rewriting); system messages (joins, pins) are
dropped by the adapter; `sha256`/`path` exist only when `status` is `ok`; the writer
holds the archive in memory (fine to a few hundred thousand messages; an external sort
is a follow-up).

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
| `existing { pubkey, proof \| trust }` | a per-person **archive key** generated here | live key kept; alias archive → live; the live key is whitelisted **only with a signed `proof`** (`trust: operator` writes the alias only) | optional |
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

**Keystore.** `keys.json` (0600, directory 0700): `{version:1, keys:{<label>:{pk, sk?,
created_at, role, retired_at?}}}`. Every write goes through one function, under a lock
file: temp file in the same directory opened `O_EXCL` 0600, write, fsync, rename, fsync
directory; it refuses (writing nothing) if any existing label would be removed, change
its `pk`, or regain a secret after retirement. **Retirement** (secret dropped, public
key kept) is the only permitted change. Keys come from
`nostr_bbs_core::keys::generate_keypair` (OS RNG); secrets are held in `Zeroizing`
buffers and never formatted into logs, errors, `Debug` output or the ledger. **The
operator key is never stored**: `keys import --from FILE` records its public key, and a
run that signs as the operator reads the secret from that 0600 file (opened without
following symlinks, owner and mode checked) for the run only.

## 5. Structure mapping

`structure.json`:

```json
{ "zones": [{"id":"zone2","cohorts":["zone2","minimoonoir"],"encrypted":true}],
  "threads": { "rants": {"zone":"zone2","section":"zone2-rants",
                          "channel": {"existing":"<kind-40 id>"} | {"new":{"name":"Rants","about":"…"}}} },
  "channels": { "<source channel id>": {"thread":"rants"} },
  "archivist_label": "archivist" }
```

* One **topic per source channel**: a kind-42 root signed by the archivist,
  `created_at` = the channel's first imported message − 1 s (the sealer works in
  `(created_at, id)` order, so a root seals before its replies). **Its content is
  exactly the topic's title** and nothing else (operator rule, 2026-11-24): no `#`, no
  "archived from …", no dates or counts. The client takes a topic's title from the
  root's first non-empty line clipped at 90 characters (`first_line`,
  `pages/thread.rs`; there is no subject tag), so a title is one line of at most 90
  characters. Titles come from the reviewable `titles.json` (source channel id →
  title); `titles` fills the humanised source name (`kids_and_shit` → `Kids and
  shit`) for channels without an entry and never changes an existing one.
  Provenance lives only in tags (`["import","<source>:<source_id>#root:<channel>"]`).
  Several source channels may fold into one thread (section).
* **Section rule.** The forum client routes a kind-40 by its `section` tag: equal to a
  zone id or `<zone-id>-…`, otherwise it falls through to the first zone silently.
  The planner refuses any section that does not start with its thread's zone id.
* Cross-thread replies become the note line (a `quote` must stay inside the thread).
* New threads get a kind-40 signed by the archivist with `["section",…]` and
  `["zone",<zone id>]` tags (what the admin UI publishes), plus a `channel_creators`
  row and a `channel_zones` row (§7). Existing threads must already be stored in the
  target D1 (`build` checks) and bound to the same zone.
* **Tags.** Replies use the client's own shapes with an empty relay hint, so no
  deployment URL is signed into tags: `["e",<thread>,"","root"]`,
  `["e",<topic root>,"","reply"]`, `["p",<root author>]`, and for a reply to an imported
  message `["e",<parent>,"","quote"]` (+ `["p",<parent author>]`). An unresolved reply
  gets a first line `↪ reply to <handle> (<date>)` or `↪ reply to a message that was
  not migrated`. An `["import","<source>:<source_id>#<key>"]` tag on every emitted event
  records provenance and rebuilds the ledger (§7; the Node tool used `keybase`; no kit
  code reads either tag).
* **Outer tags are the sealer's.** The build never writes `zk` or `sealed` tags;
  `seal_original` copies the reply link outward itself. A test asserts it.
* **Reactions** are folded into the target message's text
  (`— reactions: 👍 ×3 (alice, bob, carol)`), never kind-7: the relay's retention
  sweep deletes kind 7 after 30 days.
* Long text is cut so the signed event fits the sealing budget (§7).

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
* **Placement.** Zone media go to `pods/<archivist>/media/zones/<zone>/<sha16>.webp`
  (+ `_thumb.webp`): only zone members can read them (pod zone ACL), and one pod is
  provisioned and sized. (Per-author placement is a follow-up.) Zone containers accept only image types; other attachment
  kinds become `[video|audio|pdf|file not migrated: name, size, date]` lines. URLs are
  built from `target.json` (`pod.http`).
* **Quota.** `media plan` totals bytes per owner pod and refuses when a pod exceeds
  `--pod-quota-mb` (default the kit's 50 MiB built-in, or the deployment's
  `POD_QUOTA_MB`), naming the admin `/.quota` override.
* **Upload manifest.** `upload/r2-objects.jsonl`: `{key, file, content_type, bytes,
  sha256, owner}`; the runbook turns it into `wrangler r2 object put` lines. A bulk R2
  put bypasses the pod's accounting, so `upload/quota.sql` (for the auth database,
  `REPLAY_DB`, which holds `quota_usage`) raises the archivist pod's `used_bytes` by the
  uploaded total (`MAX`, idempotent). The pod must be provisioned through the pod API
  (first sign-in) before its listing shows the objects.
* **Names.** Objects are named by the full source SHA-256 (`<sha256>.webp`,
  `<sha256>_thumb.webp`); a 64-bit prefix could be collided by a crafted archive.
* **Cutover copy.** `upload/r2-copy.jsonl` lists objects in the OLD bucket that kept
  events link (existing threads, kind-0 pictures): data-driven, from a scan of the
  plaintext for `…/pods/<64-hex>/media/<path>` URLs (`seal-prep` saves the scan before
  sealing hides it), minus the import's own objects, accepting only safe object keys
  (segments `[A-Za-z0-9._-]`, no dot-files, `.acl` or `.meta`). `commands.sh` copies
  each from `OLD_BUCKET` to `NEW_BUCKET` at the identical key, so signed URLs keep
  working once the pod host points at the new stack.

## 7. Build: local D1 with ingest parity

Port of the Node `d1.mjs`/`fold-publish.mjs` (INGEST-PARITY.md), extended to the rows
the offline target can no longer get from admin endpoints. Written **directly into the
local D1 SQLite file** (the miniflare file under `--persist-to`, or any SQLite built
from the relay migrations), one `BEGIN IMMEDIATE` transaction per batch, with the stack
**down** (the tool refuses a locked file). There is no SQL-file mode for the build:
it could not know whether a chunk was applied.

| Row | How |
|---|---|
| `events` | `INSERT … WHERE NOT EXISTS (deleted_events …) ON CONFLICT (id) DO NOTHING`; replaceable kinds (0, 3, 10000–19999) use the relay's insert-if-not-beaten + prune pair; `d_tag`, `received_at` = build time; `created_at` = original |
| `event_tags` | **never by hand**: the relay trigger `trg_event_tags_ai_v3` fills it (DISTINCT `(name, value)`, skips `probe`); `trg_event_tags_ad` removes them on delete. `build` refuses unless both exist |
| `channel_creators` | kind 40, first write wins |
| `profiles` | kind 0 upsert guarded on `last_kind0_at` |
| `channel_zones` | the admin endpoint's upsert, for every new thread (zone-migrate's offline sealer refuses unbound channels) |
| `whitelist` | `nostr_bbs_core::whitelist_sql::WHITELIST_GRANT_COHORTS_SQL` (merge-only cohorts) for fresh keys, kept live keys, the operator and the archivist; then `UPDATE … SET is_admin = 1` for the archivist and operator only. **Archive keys get no row**: with zone cohorts, "Grant to members missing it" would wrap the zone key to keys whose secrets sit in `keys.json`. Never the `agent` cohort |
| `posts_created`, `last_active_at` | `MAX(…)` from the counted kinds (1, 7, 9, 40, 42, 1984) the ledger holds per key, so resumed runs never under-count |
| `pubkey_aliases` | archive key → live key, the relay's guarded upsert (no chains, keys lowercase) |

Not written: broadcast, push, search embeddings, moderation projections. Not applicable
to plaintext: `zone_epoch_keys` pinning (only with `ZONE_GROUPS_ENABLED`; the first `zk`
pubkey seen for a zone epoch is pinned, which is the anchor the operator posts).

**Invariant: the archivist stays admin for good.** Sealed topics resolve only through
envelopes signed by an `is_admin = 1` key (the relay's F2 rule), so revoking the
archivist's admin flag hides every imported topic.

**Ledger.** Every emitted event carries `["import","<source>:<source_id>#<key>"]`
(roots, thread headers and profiles included). At start the ledger is the union of
`state/ledger.jsonl` and the `import` tags in D1 (the database is the truth; a crash
between commit and the ledger append is healed by appending what D1 has). The file is
kept because purge deletes the plaintext rows and their tags. A ledgered key is never
re-signed: ids are pinned, so a changed plan or a growing archive never yields a second
copy and children cite the id actually stored. `state/run.json` binds the state
directory to the canonical D1 path and the target (`target.json` URLs, which signed
content embeds and sealing freezes); a mismatch is refused.

**After purge.** Detected from D1 (tombstones in `deleted_events` for ledgered ids, or
sealed envelopes in a target thread), not from a file path. Then a plain `build` is
refused; only `build --deferred-only` may run, it emits only keys absent from the
ledger, and it reports that a second seal round is required. Deferral is transitive: a
message quoting a deferred one is deferred with it. The `deleted_events` guard in every
insert backs this up at the SQL level.

**Size budget.** The sealed envelope encrypts the whole signed original with NIP-44 v2
(plaintext ≤ 65 535 bytes; after padding and base64 the relay's 64 KiB `content` cap
leaves ≈ 40 960 bytes). Every kind-42 is therefore fitted so its serialised JSON is
≤ 40 000 bytes: the text part is cut at a character boundary (multibyte-safe, JSON
escaping counted) with a truncation marker. A message that cannot seal would block
purge.

**Batching.** ≤ 500 events per transaction.

## 8. Seal, verify, purge

### 8.1 Glue, not a second sealer

`nostr-bbs-zone-migrate` owns sealing; this crate drives it through its CLI contract.
Its offline commands still need the **running local relay** (`--relay`, admin check,
`--fetch-grants`), while `build` and `apply-direct` need it **down**. `seal-prep`:

* writes `seal/channels.json` (`[{"id","zone"}]`) for every encrypted-zone thread the
  build touched;
* checks preconditions in D1 and lists what is missing: the archivist is a whitelisted
  non-agent admin; every thread is bound in `channel_zones` to its zone; **every thread
  holds its own anchor** (a `zk`-tagged kind-42 of the zone; zone-migrate checks the
  anchor per channel, so one anchor cannot vouch for another thread);
* writes `seal/RUNBOOK.md` with the exact sequence, the relay URL restricted to
  loopback (`ws://127.0.0.1…`, `ws://localhost…`; anything else is refused), and the
  secret passed by `NOSTR_BBS_MIGRATE_KEY="$(cat FILE)"` from `keys export --label
  archivist --out FILE` (0600, deleted afterwards):

```
stack up    nostr-bbs-zone-migrate --relay ws://127.0.0.1:P --channels seal/channels.json --fetch-grants --state seal/state.json seal-offline --d1 D1 --sql-out seal/sql
stack down  nostr-bbs-zone-migrate … apply-direct --d1 D1 seal/sql/seal-*.sql
stack up    nostr-bbs-zone-migrate … seal-offline-commit --d1 D1 --manifest seal/sql/seal-manifest.json
            nostr-bbs-zone-migrate … verify
            nostr-bbs-import search-input …          (§9, before purge)
            nostr-bbs-zone-migrate … purge-offline --d1 D1 --sql-out seal/purge --yes
stack down  nostr-bbs-zone-migrate … apply-direct --d1 D1 seal/purge/purge-*.sql
stack up    nostr-bbs-zone-migrate … purge-offline-commit --d1 D1 --manifest seal/purge/purge-manifest.json
            nostr-bbs-import verify-parity --phase purged …
```

`verify-parity` (§12) runs after each phase.

### 8.2 Where the zone key comes from

Sealing needs the zone's epoch key **before** upload, and the forum client is the only
place keys are minted and granted (no offline grant generator: that would be bespoke key
distribution). The order (the pilot's):

1. `build` into a local D1 that a local copy of the target stack serves (same zone
   config, `RELAY_URL` set to the local ws URL).
2. In the client, as an admin: Admin → Encryption → Create key (epoch 1), then "Grant to
   members missing it". The archivist is whitelisted with the zone cohorts, so it is
   granted too; the grants are kind-1059 rows in this D1 and travel with the upload.
3. As the archivist, post one zk-encrypted notice **in every imported thread** of the
   zone: the anchors.
4. Seal, verify, purge (§8.1); then upload (§10).

There is no unanchored offline path (`--allow-unanchored-first-encryption` is an online
`seal` option only).

## 9. Search index hand-off

`search-input` writes `search/docs.jsonl` (0600) for `nostr-bbs-search-build`: one
`{"id","text","epoch","zone_pk"}` per original that has a sealed envelope in D1. All of
it comes from D1: `id` = the original id (the envelope's `sealed` tag; what the client
resolves), `text` = the original's plaintext content, `epoch` and `zone_pk` from the
envelope's outer `["zk", zone, epoch, zone_pk]` tag. It refuses when an envelope's
original is already gone (run it after `seal-offline-commit` and before purge). Run
the builder with `--dry-run --out DIR` (it otherwise uploads to a pod and publishes a
manifest over the network) and `--relay-url` set to the **new** deployment's URL (it is
bound into the manifest); `upload-plan` adds the built objects to `r2-objects.jsonl`
under the archivist's `media/zones/<zone>/search/` folder. The publisher is the
archivist. Delete `docs.jsonl` after the build.

## 10. Upload and cutover

`upload-plan` writes `upload/` (never executed by the tool):

* `data-NNNN.sql`: the tool's own **allowlisted** dump of the built D1, every row as
  `INSERT OR IGNORE` (an ignored row fires no AFTER INSERT trigger, so re-running a
  chunk is idempotent): `events`, `deleted_events`, `channel_creators`, `channel_zones`,
  `profiles`, `pubkey_aliases`, `admin_log` (without its autoincrement `id`). `whitelist`
  rows go through the merge-only grant upsert plus the admin flag and `MAX` counters.
  Never dumped: `event_tags` (no primary key; the trigger rebuilds it from `events`, a
  dumped copy would double every tag) and `settings` (boot marker rows). Chunks stay
  under D1's statement and request limits. A raw `wrangler d1 export` is not used: it
  emits plain `INSERT`s that collide with boot rows and duplicate `event_tags`.
* `quota.sql` for the auth database (§6), `r2-objects.jsonl`, `r2-copy.jsonl` (§6). Text that is not plain
  printable ASCII (or contains `;`, quotes, comment markers) is written as
  `CAST(X'…' AS TEXT)` so no statement splitter can misread archive text.
* `RUNBOOK.md` and `commands.sh`:
  1. New stack alongside the old one (new worker names, D1, R2 bucket, KV), config
     projected from the same forum config.
  2. Relay migrations with `wrangler d1 execute --remote --file`: `0009_events.sql`
     first (0004's trigger reads `events`), then all in numeric order (`event_tags`,
     its delete trigger and 0016 exist only there; `migrations apply` would run 0004
     first and fail on a fresh database). Boot the relay once so `ensure_schema()`
     installs the v3 trigger, `channel_zones`, `admin_log` and the rest, then
     `wrangler d1 execute <new db> --remote --file data-NNNN.sql` per chunk.
     `commands.sh` (bash, `set -euo pipefail`) refuses when a new resource name equals
     an old one or the new D1 already holds events.
  3. R2 object puts, the bucket-to-bucket copy list, `quota.sql` on the auth database.
  4. One revertable website commit points the forum at the new stack; the old stack is
     frozen read-only (not deleted). Roll-back = revert that commit.

`upload-rehearse` proves the dump locally: a fresh SQLite from the migrations plus the
boot SQL, every chunk applied twice, then per-table counts and the tag index compared
with the source D1.

Cost notes (README): D1 rows written/stored per event (1 `events` row + one
`event_tags` row per distinct tag), Workers Paid for D1 beyond the free tier, R2
storage and class-A operations for the puts, the pod quota (`POD_QUOTA_MB`).

## 11. DMs

* **Verbatim copy** of kind-1059 wraps (id and signature verified, exactly one `p`)
  whose recipient is a live key kept by a proven identity, or the operator, and is
  whitelisted in the new deployment (the relay only accepts wraps to whitelisted
  recipients): same id, signature and `created_at`,
  nothing decrypted. Zone-key grants (rumor 21453) cannot be told apart without
  decrypting, so copies need `--allow-stale-grants` (stale epochs are noise, not a
  leak: they are addressed to the same recipient).
* **Re-wrap** only of DMs the operator **sent**: unwrap in memory with the operator's
  old key (0600 file), require rumor author = old key, re-seal with the old key (the
  seal signer must be the rumor author), wrap to the new key. Rumors by anyone else
  are skipped and counted: we never forge a sender. Only NIP-17 kinds (14, 7, 5, 15)
  travel. Opening uses `nostr_bbs_core::gift_wrap::unwrap_gift`, which verifies the
  wrap and seal signatures and the rumor-author = seal-signer binding. Output goes into
  the D1 like any event. The new zone key must be minted at an epoch above any old one,
  so copied stale grants cannot shadow it.

## 12. Parity invariants (`verify-parity`, and the e2e test)

Phase `built`:

* every ledgered key maps to a stored event; counts match the plan;
* 0 orphan e-tags: every `root` resolves to a stored kind-40, every `reply`/`quote` to
  a stored kind-42 in the same thread;
* `event_tags` rows = Σ over stored events of the DISTINCT `(name, value)` pairs of
  array tags, `probe` excluded (the v3 trigger's rule);
* `channel_creators`, `channel_zones`, `profiles`, `whitelist`, `pubkey_aliases` as
  planned; `posts_created` = ledger counts; no archive key whitelisted.

Phase `purged`: no plaintext kind-42 left in sealed threads (only envelopes and the
anchors); every original id tombstoned in `deleted_events`; no `event_tags` row of a
purged id; every envelope's topic resolves by the relay's F2 rule (a stored kind-42,
or an admin envelope whose `sealed` tag names it, in the same channel).

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

* Discord, Slack, Matrix adapters; thread/mention/system-message concepts in the
  format; an external sort for very large exports.
* Running the remote upload and the R2 copy (plans only).
* Per-author media placement; avatars.
* Importing verbatim live events (another deployment's signed posts, LIVE-MERGE.md's
  "keep keys and posts as-is") beyond DMs.
* Anything that needs a zone-migrate change is a follow-up, not edited here (for
  example a no-network build of its library, or an offline unanchored path).
* Pinning the archivist pubkey in the kit so the archivist could be demoted after
  sealing (today it must stay admin, §7).
* `secure_delete` during zone-migrate's own `apply-direct` of the purge (the importer's
  `scrub` runs `VACUUM` afterwards instead).
* Client limits for very long topics (KIT-FIXES.md) are client work.

## 15. Reviews

### 15.1 Architecture review (system-architect, 2026-11-24): accepted, design revised

Blocking, all fixed in the sections above:

| # | Finding | Resolution |
|---|---|---|
| B1 | zone-migrate checks the anchor per channel; offline sealing has no unanchored path | one archivist anchor per thread, checked by `seal-prep`; unanchored alternative removed (§8) |
| B2 | zone-migrate's offline commands need the running relay and its library links HTTP/WebSocket clients | drive it by CLI with a loopback-only `--relay`; documented up/down sequence; zone-migrate is a dev-dependency only (§1, §8.1) |
| B3 | 60 000-character truncation can exceed what NIP-44 + the 64 KiB content cap can seal | fit the serialised original to ≤ 40 000 bytes, multibyte-safe (§7) |
| B4 | a raw `wrangler d1 export` collides with boot `settings` rows, duplicates `event_tags`, and boot alone does not create `event_tags` | own allowlisted `INSERT OR IGNORE` dump; migrations, then boot, then import; `upload-rehearse` (§10) |

Should-fix, adopted: no SQL-file build mode, ledger rebuilt from D1 `import` tags, a
stable state binding (S1); the trigger's DISTINCT/probe rule and `trg_event_tags_ad`
required (S2); no whitelist row for archive keys, separate admin UPDATE, the
archivist-stays-admin invariant (S3); post-purge detection from D1, transitive deferral,
`--deferred-only` after purge (S4); `zone_epoch_keys` noted, the kind-1059 recipient
gate, `quota.sql` for the auth DB (S5); search-build run `--dry-run` with the new relay
URL, objects routed to the R2 list (S6); v1 limits of the format stated (S7). Nits
adopted: cross-thread replies become a note; `keys export --out` instead of shell
extraction; `WRANGLER_SEND_METRICS=false`; per-author media dropped from v1. Not adopted:
dropping the DM re-wrap (the operator asked for it).

### 15.2 Security review (security-reviewer, 2026-11-24): accepted, fixed in code

No critical findings, no path to production, no hand-rolled cryptography.

| # | Finding | Resolution |
|---|---|---|
| H1 | the keystore's derived `Debug` printed every secret through its change baseline | manual `Debug` (public data only); the baseline holds public keys only; test |
| H2 | `existing` live keys were whitelisted, granted and aliased unverified | signed `proof` (content = `link_statement`, `verify_event_strict`) required to whitelist; `trust: operator` writes the alias only; live keys may not equal any keystore key |
| H3 | `keys.json` held every secret indefinitely, the operator's included | retirement as the one permitted keystore change; operator stored as public key only and unlocked per run; custody timeline in SECURITY.md |
| M1 | a Keybase asset path could name a message file (raw lines carry decryption keys) | asset paths confined to `assets/`, symlinks refused; e2e test |
| M2 | symlinks could escape the Keybase input tree | every read checks for a regular file; channel dirs are one segment and confined |
| M3 | ledger keys could collide (`root:` message ids) | separate namespaces `#m:`, `#root:`, `#thread:`, `#profile:`, `#dm:` |
| M4 | plaintext survives purge on disk | `scrub` (`secure_delete`, `VACUUM`, WAL truncate); residue checklist; §1 claim corrected |
| M5 | offline grants left no audit trail | `admin_log` rows with the relay's action names, actor = archivist |
| M6 | the upload script could merge into the live stack | bash `set -euo pipefail`, refuses new = old names and a non-empty new D1; objects are image or search files only |
| Low | stale-grant shadowing; unwrap function unnamed; DM copy recipients too broad; keystore save race; secret-file checks; `keys import` role; hash-then-copy race; oversized messages; SQL encoding in the dump; R2 key length; ImageMagick policy; `keys export`; bots never dropped; unbounded lines | epoch rule documented; `unwrap_gift` named; recipients limited to proven live keys and the operator; lock file; `O_NOFOLLOW` + owner + mode; import is operator-only; copies re-hashed; 40 000-byte budget (§7); hex-encoded dump text; full-digest names; deny-all `policy.xml` with limits; `O_EXCL` 0600 export and prefix-env form; Keybase `bot`/`restrictedBot` roles; 16 MiB line cap |
