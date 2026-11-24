# Bulk import: operator guide

`nostr-bbs-import` (crate `crates/nostr-bbs-bulk-import`) loads an external chat archive into
a forum deployment **offline**, seals the encrypted zones, and writes a plan for uploading the
result to a new Cloudflare stack. It makes no network calls: every remote step is written out
for you to run.

It is the generalised successor of the Node migrator written for the Keybase pilot
(`keybase-port/migrator`). Keybase is one adapter; any platform can be imported by writing the
[intermediate format](FORMAT.md). Read [SECURITY.md](SECURITY.md) before handling real data, and
[DESIGN.md](DESIGN.md) for the reasoning and the review record.

## Prerequisites

| Need | Why |
|---|---|
| Rust (workspace toolchain), `cargo build --release -p nostr-bbs-bulk-import -p nostr-bbs-zone-migrate` | the importer and the sealer |
| ImageMagick 7 (`magick`) with the HEIC/WebP coders | image optimisation (`media`) |
| `wrangler` | the local stack, the export and, at cutover, the upload |
| A local copy of the target stack (relay, auth, pod workers) with the target's zone config, `RELAY_URL` set to its local ws URL | minting and granting the zone key, posting anchors, sealing |
| Cloudflare **Workers Paid** on the new stack | Free caps D1 at 100k writes/day and 500 MB per database |
| A work directory on an encrypted disk, mode 0700 | it holds private chat and every generated key |

Throughout, `W` is the work directory and `D1` is the local relay's D1 SQLite file (for
`wrangler dev --persist-to P`: `P/v3/d1/miniflare-D1DatabaseObject/<hash>.sqlite`). Commands print
JSON; exit code 0 = done, 2 = done with problems listed, 3 = refused by a safety rule (nothing
written), 1 = error.

## Runbook: archive to cutover

### 1. Adapt the source export

```sh
nostr-bbs-import adapt keybase --in ~/archive/myteam --work W --source-id myteam
# or, for an archive another tool wrote in the intermediate format:
nostr-bbs-import adapt generic --in ./export --work W
```

Writes `W/archive/` (validated, content-addressed attachments). Edits and deletes are applied;
raw source lines are never copied.

### 2. Decide identities and structure

```sh
nostr-bbs-import plan --work W --zone zone2     # first run: writes templates
$EDITOR W/identities.json W/structure.json
echo '{"name":"production","pod":{"http":"https://pods.example.org"}}' > W/target.json
nostr-bbs-import plan --work W                  # validates, prints counts and the keys needed
```

* `identities.json`: per source author, `fresh` (new identity and recovery sheet), `existing`
  (keeps a live key; history signed by an archive key and linked to it by a profile successor),
  `merge` (same person as another author), `drop` (bots), `operator` (with `"defer": true` to
  import the operator's history later). An `existing` key is whitelisted only with a `proof`: the
  person signs, with that key, an event whose content is exactly what
  `nostr-bbs-import link-statement --work W --author ID` prints (any NIP-07 signer can do this,
  and nothing is published). Without a proof, `"trust": "operator"` writes the alias but leaves
  whitelisting to your normal invite flow.
* `structure.json`: zones (in the deployment's config order), threads (kind-40 channels: an
  existing id, or a new one the archivist signs), and one entry per source channel (`thread`, an
  optional `topic` title, or `"skip": true`). Each source channel becomes one topic. A section
  must be `<zone id>` or `<zone id>-…`, or the client files it under the first zone; the planner
  refuses anything else.
* `target.json`: the pod URL that image links will embed. It is frozen into signed and then
  sealed content, so a pilot build cannot be reused for production: build again with the
  production target. One work directory (archive, plan files, keys, media) serves both: pass
  `--target FILE --state DIR` to `build`, `dm`, `seal-prep`, `search-input`, `verify-parity`,
  `upload-plan` and `upload-rehearse` for the second target. The state directory is bound to one
  database and one target (a mix-up is refused) and also holds that run's `seal/`, `search/` and
  `upload/`.

### 3. Keys

```sh
nostr-bbs-import keys --work W ensure                 # posters + the archivist; never regenerates
nostr-bbs-import keys --work W import --from op.key   # operator: public key recorded, secret never stored
nostr-bbs-import keys --work W list
```

### 4. Media

```sh
nostr-bbs-import media --work W
```

Images become stripped WebP (animated GIFs stay GIF) plus thumbnails in `W/media/`, named by the
full SHA-256 of the archived bytes. Other attachment kinds become `[video not migrated: …]` lines.

### 5. Build into the local D1 (stack down)

Boot the local relay once on a fresh persist directory (after applying the relay migrations,
`0009_events.sql` first, as `keybase-port/stack/apply-migrations.sh` does), stop it, then:

```sh
nostr-bbs-import build --work W --d1 D1
nostr-bbs-import verify-parity --work W --d1 D1 --phase built
```

Re-running is safe and adds nothing. The operator's deferred history is imported later with
`build --deferred-only --operator-key op.key`. Copied or re-wrapped DMs:
`nostr-bbs-import dm --work W --d1 D1 --allow-stale-grants [--rewrap-old-key old.key]`.

### 6. Zone key and anchors (stack up, in the client)

1. Sign in as an admin. Admin → Encryption → the zone → **Create key**, then **Grant to members
   missing it** (the archivist is a member, so it is granted too).
2. Sign in as the archivist (`keys --work W export --label archivist --out a.key` gives its key;
   use a throwaway browser profile) and post one zk-encrypted message **in every imported
   thread**. These anchors let the sealer confirm the key.

### 7. Seal, verify, search input, purge

```sh
nostr-bbs-import seal-prep --work W --d1 D1 --relay ws://127.0.0.1:8787
```

It writes `W/seal/channels.json` and `W/seal/RUNBOOK.md` and lists anything still missing (an
unbound thread, a missing anchor, a non-admin archivist). Follow the runbook: `seal-offline`
(stack up), `apply-direct` (stack down), `seal-offline-commit`, `verify`, then
`nostr-bbs-import search-input` **before** the purge, `verify-parity --phase sealed`,
`purge-offline`, `apply-direct`, `purge-offline-commit`, and `verify-parity --phase purged`.
Finally, with the stack down, `nostr-bbs-import scrub --d1 D1`.

### 8. Search index

```sh
NOSTR_BBS_MIGRATE_KEY="$(cat a.key)" nostr-bbs-search-build --zone zone2 --input W/search/docs.jsonl \
  --keys-file zone-keys.json --model-dir models/bge-small-en-v1.5 \
  --relay-url wss://NEW-relay.example.org --dry-run --out W/search/out
shred -u W/search/docs.jsonl
```

`--relay-url` must be the **new** deployment's URL (it is bound into the manifest).

### 9. Upload plan and rehearsal

```sh
nostr-bbs-import upload-plan --work W --d1 D1 --search-out W/search/out --pod-quota-mb 50
nostr-bbs-import upload-rehearse --work W --d1 D1 --fresh-d1 FRESH   # FRESH: migrations applied, relay booted once
```

`W/upload/` holds `data-NNNN.sql` (an allowlisted `INSERT OR IGNORE` dump: no `event_tags`, which
the relay trigger rebuilds, and no `settings`), `r2-objects.jsonl` (the import's own objects),
`r2-copy.jsonl` (objects in the OLD bucket that kept events link, such as existing threads and
profile pictures, copied bucket to bucket at the identical key; found by scanning the plaintext,
including the pre-purge scan `seal-prep` saved), `quota.sql` (auth database), `commands.sh` and
`RUNBOOK.md`. The rehearsal applies the dump twice to a fresh D1 and compares
every table.

### 10. Cutover and roll-back

Follow `W/upload/RUNBOOK.md`:

1. A new stack alongside the old one (new workers, D1, R2 bucket, KV). The old one is untouched.
2. Relay migrations (`0009_events.sql` first, then all in order, with `d1 execute --file`), one
   relay boot, then the data chunks, the R2 objects, the old-bucket copies and `quota.sql`. `commands.sh` refuses to run
   if a new resource name equals an old one or the new D1 already holds events.
3. Check counts against the rehearsal and read a sealed topic as a member.
4. One revertable website commit points the forum at the new stack; freeze the old stack
   read-only. Roll-back = revert that commit.

Afterwards: `keys --work W retire --role archive`, retire fresh keys once their recovery sheets
are delivered, move the archivist key off the work directory, and work through the residue
checklist in [SECURITY.md](SECURITY.md).

## Costs and limits

Figures from Cloudflare's published pricing as read on 2026-11-24
(`keybase-port/analysis/CLOUDFLARE-PRICING-2026-11.md`); check before relying on them.

| Item | What drives it | Notes |
|---|---|---|
| **Workers Paid** | required | $5/month. Free allows 100k D1 writes/day and 500 MB per D1 database |
| D1 rows written | 1 `events` row + 1 `event_tags` row per distinct tag per event (an imported reply has about 6), plus the envelope and its tags after sealing | 50M rows/month included, then $1.00/M. A 250k-message import is a few million rows |
| D1 storage | sealed events are larger than plaintext (NIP-44 + base64) | 10 GB per database, a hard cap; 5 GB included, then $0.75/GB-month |
| D1 limits | one `wrangler d1 execute --file` per chunk | chunks hold at most 2,000 statements; sealed events are capped at 40,000 bytes so every one fits |
| R2 storage | optimised images + thumbnails + search shards | 10 GB-month included, then $0.015/GB-month; egress free |
| R2 Class A | one PUT per object in `r2-objects.jsonl` | 1M/month included, then $4.50/M |
| Pod quota | all imported images sit in the archivist's pod | `POD_QUOTA_MB` (default 50 MiB per pod). `upload-plan --pod-quota-mb` warns when the archivist pod needs more: raise the variable or set the archivist's limit with the admin `/.quota` call before uploading |

## Writing an adapter

See [FORMAT.md](FORMAT.md), section "Writing an adapter".
