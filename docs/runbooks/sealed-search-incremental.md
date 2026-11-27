# Sealed search: incremental nightly updates

> Status: readiness runbook. Nothing here has been run against a deployed relay
> or pod. Creating the indexer identity, admitting it, changing
> `SEARCH_PUBLISHERS` and scheduling the job are operator actions.

The base index of an encrypted zone is built once, at import, by the archivist.
Posts written later are not in it. This job adds them every night, without
re-uploading the base and without asking browsers to download it again.

## What it does

`scripts/sealed-search-nightly.sh <config>` runs, for one zone:

1. **`nostr-bbs-search-build update`**:
   - Reads the zone's encrypted kind-42 posts and the kind-5 deletions from
     the relay, NIP-42 authenticated as the indexer.
   - Reads from the state file's high-water mark, less an overlap of 7 days
     and 1 hour. The relay accepts `created_at` up to 7 days in the past.
   - Opens each post with the zone key of its epoch, embeds the new ones
     locally (FP32 bge-small, candle, CPU), and seals them into one more shard
     pair per epoch.
   - Publishes manifest `index_version + 1`. It lists every earlier object
     unchanged, together with the new ones and the ids of indexed posts that
     have since been deleted or edited.
2. **`status --field partial_pairs`**: if it is at least `NBSS_COMPACT_AT`
   (default 14), it runs **`compact`**. That folds every shard pair that is not
   full into fresh full ones. Rows are re-packed verbatim, so no embedding
   runs. Only excluded rows (authorised deletions and supersessions) are
   dropped. A row the relay merely does not serve is kept.
3. It runs **`compact --all`** once `NBSS_FULL_COMPACT_EXCLUDED_AT` ids are
   excluded (default 4,096, a quarter of the manifest's cap of 16,384). That
   re-packs the whole index into the indexer's pod and empties the list.

The job takes a lock (`flock`), keeps within a time budget (`NBSS_TIMEOUT`) and
logs one JSON report per step: counts only, never text or keys.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | Done: published, or nothing new. |
| 3 | Published, but posts under an epoch the indexer holds no key for were held back. The high-water mark is set just below the oldest of them, so every later run reads them again (more each night, the older they are) until the epoch is granted. |
| 1 | Error. |
| 4 | The relay session is not NIP-42 authenticated. Nothing was read. |
| 5 | Retired. Compaction no longer refuses or drops on rows the relay does not serve. |
| 6 | The pods show an older index than this job published. Rollback or withholding; refused. |
| 9 | The zone has an index but the author book was never seeded. Refused; run `seed-book` once (see "Switching it on"). |
| 8 | The exclusion list would pass its cap (16,384). Refused; run `compact --all`. The default full-compaction threshold keeps this from happening. |
| 7 | The relay serves none of the zone's already-indexed posts to the indexer. Refused. The relay's zone read gate answers an authenticated non-member with nothing rather than an error, so without this check a missing cohort would look like "nothing new" every night. |
| 10 | Another run holds the lock. |
| 11 | Timed out. |
| 12 | Configuration error. |

## Design choices

### Manifest v2

The manifest format is versioned and backward compatible.

Every new field is optional, and its default reads exactly as v1:

- `objects[].owner`: the trusted publisher whose pod holds the object. It
  defaults to the signer.
- `objects[].version`: the index version the object's header was built at.
  It defaults to `index_version`.
- `excluded`: the ids a searcher must not return. It defaults to empty.

So a current v1 manifest is a valid v2 manifest.

`Manifest::verify` adds these rules for v2:

- an `owner` must be a listed publisher;
- `version` must be at most `index_version` and equal the `v<N>` in the name;
- no two objects share a name or an `(epoch, zone_pk, shard, kind)`;
- excluded ids are lowercase hex, at most 131,072 of them.

A v1 manifest that carries any v2 field is refused.

**Zone-key MAC (security review M3).** In v1, a higher version means objects
sealed at that version, which needs the zone key. In v2 a manifest can re-list
existing objects at any version. Without more, a listed publisher key alone
could add exclusions and raise every browser's high-water mark. So a v2
manifest also carries:

```
["mac", "hmac-sha256-v1", <epoch>, <zone_pk>, <hex>]
key = HKDF-SHA256(salt = "nostr-bbs/sealed-search/manifest-mac/v1",
                  ikm  = zone secret of the newest (epoch, zone_pk) listed,
                  info = "manifest-mac\0" || zone || "\0" || be32(epoch)
                         || zone_pk || be64(index_version))
mac = HMAC-SHA256(key, the event's content string, exactly as signed)
```

- **Where it is checked.** Browsers and the builder check it with
  `Manifest::accept` before a manifest is chosen or its version can move the
  high-water mark. The comparison is constant-time (`verify_slice`).
- **What it proves.** Any member holding that epoch key could compute it, so it
  proves "made by someone holding the zone key". With the publisher signature,
  that restores the v1 property. It does not tell members apart. A searcher
  without the newest epoch key cannot check it, so cannot use the manifest.
- **Implementation.** RustCrypto `hkdf`, `hmac` and `sha2`, private to this
  project.
- **Bounds.** A browser accepts a version jump of at most 16,384 (44 years of
  nightly runs) and at most 16,384 excluded ids, applied as a set lookup.
- **Tie-break.** Equal versions resolve to the first publisher in
  `SEARCH_PUBLISHERS`, in both the client and the builder.
- **Epoch floor.** Each device records the newest epoch of the last manifest it
  accepted. A later v2 manifest must be MAC'd with at least that epoch, so a
  former member holding old epoch keys and a publisher key cannot MAC a
  manifest that lists only old-epoch objects.
- **Fallback.** A browser tries the verified manifests newest first. If one
  fails to load (a higher v1 signed with a publisher key alone, whose objects
  do not verify), it loads the next. Only a manifest that loaded moves its
  high-water mark.

Updates and compactions always sign `v: 2`. A browser built before this change
refuses a v2 manifest as unsupported. It then keeps using the newest v1 manifest
it can find, the archivist's base, so it still works with stale results. It
never raises its rollback mark to a version it could not load later.

The high-water mark of the relay read moves only on verified events of this
zone, never past the job's clock. That is stricter than the relay's own bound
of now + `MAX_CREATED_AT_DRIFT_SECS`: a post dated ahead is read again each run
until the clock passes it.

A second the relay cannot page completely (more than 1,000 events) holds the
mark below it only if that query returned a verified event that matters at
that second: a post of this zone, or a kind-5 naming one. Junk or unrelated
deletions hold nothing. Even a relevant second is released after 3 days, with a
warning in the report, because events at it may never be readable.

A full build (`--manifest-format auto`, the default) signs v1 while no trusted
publisher holds a v2 manifest for the zone, and v2 once one does. The import
hand-off (§9 of `docs/bulk-import/DESIGN.md`: `--input … --dry-run --out DIR`,
no pod) therefore still produces a v1 base at version 1 that every browser
reads.

Signing v1 above a v2 manifest would strand such a browser:

1. It accepts a v1 manifest at version M.
2. It refuses the v2 manifest at M+1.
3. It refuses the archivist's version as a rollback below M.

`--manifest-format v1` or `v2` forces the format; `auto` is the safe default.

### Publisher continuity: reference, don't re-upload

The archivist's key no longer exists, so nobody can write to its pod. The
indexer's first update therefore lists the archivist's base objects by `owner`
rather than copying 108 MB into its own pod.

This is consistent with the trust rules:

- **§3, authenticity.** The client accepts the manifest only if a listed
  publisher signed it. Every object must match the signed SHA-256 and its
  authenticated header. Where the bytes are fetched from cannot change what
  is accepted.
- **Fixed publisher list (M1).** Restricting `owner` to the same publisher list
  keeps requests on pods the client already trusts, found by path.
- **§14, writes.** Each identity writes only to its own pod. Nothing new
  writes cross-pod.
- **Rollback protection (M2).** Unchanged. The job builds on the newest
  verified manifest across all publishers and publishes that version + 1.
  Browsers keep their strict `>` high-water mark. The job also refuses to run
  when the pods show an older index than its state recorded (exit 6).

A full rebuild under the indexer would have re-uploaded the whole base and made
every browser download it again on day one. `compact --all` does that later, at
a time the operator chooses.

**Coupling:**

- The archivist must stay in `SEARCH_PUBLISHERS` until `compact --all` has
  re-homed every object. Otherwise browsers refuse the manifest.
- The pod's read rule depends only on the reader (an active member whose
  cohorts satisfy the zone), not on the owner. The archivist's objects stay
  readable even if it leaves `SEARCH_ARCHIVISTS` or the whitelist.
- Superseded objects in the archivist's pod cannot be deleted by anyone, since
  the key is gone. After `compact --all` they are unreferenced. Removing them
  needs direct R2 access.

### Deletions and edits (review M5)

The relay is untrusted here. Only positive evidence the builder checks itself
removes a row.

- **Deletions.** A verified kind-5 deletes a row only when its signer is the
  post's author, or a key in `NBSS_MODERATORS` (admins and moderators,
  supplied in config; a malformed entry is an error, never silently dropped).
  For an imported post, the author is the original's author. The target may be
  a live post id, an envelope id or an original id.
  - **Moderator deletions need no author.** They count as soon as the target
    names a row of the index, directly or through a known envelope. The relay
    removes the post at once, often before any run saw its author.
  - The author comes from the post itself if it was read this run, else from
    the job's **author book**, else from the relay. The book records every row
    id's author and every envelope's original id when the job opens the post.
    It is **seeded** once, before the first update, from the zone's events
    (`seed-book`). The first update refuses to run (exit 9) without it. The
    book is pruned to the rows of the index on every run, so it stays the
    index's size.
  - The book matters because the relay removes a post at once on its author's
    kind-5. Without it, an ordinary author deletion could never be verified
    afterwards.
  - A target none of them establishes is skipped this run, never assumed.
- **Edits.** A post is superseded by a kind-42 tagged `["e", <target>, "",
  "edit"]` only when the editor is the target's author. A target the relay
  does not return, and the book does not know, is skipped.
- **When it shows.** A post the relay no longer serves stops showing
  **immediately**, because every hit resolves through the relay. Excluded posts
  are listed in the next manifest's `excluded`, so they take effect at the
  **next nightly run**. The worker never returns them or uses them as decoys,
  and the main thread drops them too.
- **Physical removal.** A compaction drops only excluded rows from the shards it
  folds. A row the relay merely does not serve, such as one deleted through the
  admin HTTP API with no kind-5, is kept and counted (`missing_rows`).
  Withholding must never become a signed, permanent exclusion.
- **Takedown.** A post moderated without a kind-5 (the admin HTTP API), or one
  that must go for any other reason, is taken down explicitly. See "Takedown
  procedure" below.
- **Base shards.** The archivist's full base shards are re-packed only by
  `compact --all`. By default it runs once 4,096 ids are excluded. Until then,
  the embeddings of excluded posts in those shards are hidden from members but
  still sit in the sealed bytes they download.

### Takedown procedure

1. **Exclude the post now.** Put its id in a file: the id members see, which is
   the original's id for an imported post. Then run:

   ```
   nostr-bbs-search-build takedown --ids ids.txt --reason "<why>" <the job's usual flags>
   ```

   The next manifest, signed by the indexer, lists the id as excluded.
   Browsers stop returning it once they load that manifest (minutes, at their
   next manifest check). The report records the ids and the reason; keep it
   with the moderation record. An id not in the index is reported and skipped.
2. **Remove its embedding.** The row stays in the sealed shard until a
   compaction folds it. That happens at the next `compact`, when the row is in
   an update shard or the base's last shard, and at the next `compact --all`
   (or a full rebuild) when it is in a full base shard. Run `compact --all` at
   once when the embedding must not stay in the sealed bytes.
3. **Full rebuild, if needed.** A full build from the relay (no subcommand,
   `--from-relay`) re-embeds the zone as it now stands. It is the last resort,
   for example when many posts must go or the base itself is in doubt.

### Disclosure

The exclusion list puts post ids in `m.json`, which §3 described as disclosing
no ids. It is served only behind the zone read gate, to members. The relay
already holds every id, including the inner ids in `sealed` tags. So nothing new
reaches Cloudflare or non-members.

### Object lifecycle

- An object that a new manifest stops listing is deleted from the indexer's
  pod **48 hours later** (`--retire-after-secs`; the state's `retired` list
  records when). A browser that read the previous manifest can still finish
  loading it, even if the job is rerun by hand.
- Browsers cache objects in IndexedDB by SHA-256. An object listed unchanged is
  never fetched again.
- On a new version the worker re-reads the bin layers from that cache, about
  0.5 s for the whole index (§13), then swaps the index in. The old version
  keeps answering until the swap.

## What is stored where

| What | Where | Readable by |
|---|---|---|
| Base objects (`b-5-N-v1.age`, `q-5-N-v1.age`) and the archivist's `m.json` (v1) | `pods/<archivist>/media/zones/zone2/search/` | Zone members (pod zone read gate) |
| Update and compacted objects, the indexer's `m.json` (v2) | `pods/<indexer>/media/zones/zone2/search/` | Zone members |
| Indexer key | `NBSS_KEY_FILE` (0600) on the job machine | The job user |
| State file (`<zone>.state.json`): high-water mark, last version, retired names with times | `NBSS_STATE_DIR` (0600) | The job user |
| Author book (`<zone>.state.authors.json`): row id → author, envelope id → original id, seeded flag; no text; pruned to the index's rows. Written before the state, so the mark never moves past an unsaved book | `NBSS_STATE_DIR` (0600) | The job user |
| Zone-key file, if used instead of grants (`NBSS_KEYS_FILE`) | 0600, checked by the job and the builder | The job user |
| Object cache (`<zone>.cache/<sha256>`): sealed bytes only | `NBSS_STATE_DIR` | The job user |
| Log (`<zone>.log`): JSON counts | `NBSS_STATE_DIR` | The job user |

Plaintext and embeddings exist only in the job's memory, while it runs.

## Switching it on

1. **Deploy the clients first.** The forum and BBS clients, and the sealed-search
   worker, must come from this change before any v2 manifest exists. Older
   browsers keep using the archivist's v1 base.
2. **Create the indexer identity.** Use a new keypair, never the operator's
   personal key. Store the secret in a 0600 file on the job machine, owned by
   the job user.
3. **Admit it to the relay and the zone:**
   - a whitelist row with the cohort that satisfies zone2's read rule, so its
     NIP-42 REQs return the zone's posts;
   - a zone2 grant through "Grant to members missing it", for every epoch in
     the index.

   The job fetches its own grants (`--fetch-grants`). No key is exported.
4. **Admit it to the pod.** Add its pubkey to the pod's `SEARCH_ARCHIVISTS`,
   with an active, unsuspended whitelist row. It can then write only to its own
   `.../search/` folder.
5. **Add it to the clients' trust list.** Add it to `SEARCH_PUBLISHERS`, after
   the archivist and the admin: `"<archivist>,<admin>,<indexer>"`. Use the same
   list for `NBSS_PUBLISHERS`.
6. **Choose the machine.** It needs about 1 GB of RAM, outbound access to the
   relay and pod, and the bge-small FP32 checkpoint plus the Q8 GGUF the index
   pins (the job refuses an update with a different model).

   **What that machine can then read:** with the indexer key and its grants,
   everything any zone2 member can read. That means every post in the zone, in
   plaintext, and the whole index. Treat it like a member's device that never
   sleeps.
7. **Write the config file.** Copy the variables in the script header into a
   0600 file owned by the job user. Run once by hand. Then schedule it nightly
   (systemd timer or cron) with the config path as the only argument.
8. **Seed the author book.** Run once, before the first update:

   ```
   nostr-bbs-search-build seed-book --from-events <export> | --from-relay <url> <the job's flags>
   ```

   It records every zone post's author, so later deletions can be verified.
   Prefer a NIP-01 export of the zone's events taken at import (`--from-events`).
   A post deleted between the import and seeding is gone from the relay, so
   seeding from the relay cannot record it; only a moderator's kind-5 or a
   takedown can then remove it from the index. A full build from the relay
   seeds the book too.
9. **Check the first run.** The first update has no high-water mark, so it reads
   the whole zone (241,929 envelopes, paged). It finds them all indexed and
   publishes nothing unless something is new. Later runs read about 8 days.
10. **Retire the archivist (later).** Run `compact --all` once, then remove the
   archivist from `SEARCH_PUBLISHERS`.

After a new import or zone-migrate run, the new envelopes carry their original,
older `created_at`, below the high-water mark. Run `update --since 0` once. It
reads the whole zone and indexes only what is missing.

The state file is format 2 (retired objects carry the time they were retired).
A state file of format 1 from an earlier build is refused with a message, not
migrated. No such file exists outside test runs; delete it and let the next run
start a fresh state.

The state directory must be owned by the job user and be mode 0700. The
config file's directory must be owned by the job user or root, and not be
writable by group or others.

A `--dry-run` writes the new objects and `m.json` to `--out` and changes no pod
and no state (its report says `"dry_run": true`). Without `--pod` it builds as
if no index existed yet.

## Cost (measured on synthetic text, candle FP32, CPU)

These are local runs. The texts are generated sentences of about 30 words each,
never archive text.

| New rows | 56 cores (default 28 workers) | 4 cores (`taskset`, 4 workers) |
|---:|---:|---:|
| 500 | 2.4–2.5 s embedding, about 3.7 s wall | 5.9–7.4 s embedding, about 9.4 s wall |
| 5,000 | 15.3 s embedding, 17.4 s wall | 66.8 s embedding, 68.8 s wall |

- Sealing takes under 0.1 s.
- A nightly update uploads one pair per epoch: about 0.47 KB per row sealed.
- A browser with the base cached downloads only that pair.
- Reading the relay is the other cost. Paging is 1,000 events per REQ at
  about 16 frames per second, so the first full read of 241,929 envelopes is
  roughly 4 minutes.

## Not tested against real infrastructure

- `--from-relay` was exercised in tests and locally against an in-memory relay
  and a NIP-01 export, not against a deployed relay. Whether a production REQ
  pages through `#zk` with `since` within the relay's rate limits is
  unverified.
- Pod writes were exercised against a directory standing in for the pod, not
  through the pod worker's NIP-98 gate.
- No browser ran against a v2 manifest. The client changes are unit-tested; the
  worker change is the shared `Index`, which is integration-tested natively.
