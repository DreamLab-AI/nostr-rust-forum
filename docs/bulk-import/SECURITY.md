# Bulk import: security

What the importer protects, what it relies on you for, and why it is built the way it is. The
reviews behind this are recorded in [DESIGN.md §15](DESIGN.md#15-reviews).

## Threat model

| Asset | Threat | Defence |
|---|---|---|
| Production | an import step reaches the live stack | the crate makes no network calls; sealing talks only to a loopback relay (`seal-prep` refuses other URLs); remote steps are written, never run; `commands.sh` refuses when a new resource name equals an old one or the new D1 is not empty |
| Members' keys | forged authorship, key custody | nobody's live secret is ever asked for; history is signed by keys made for the purpose (below) |
| Encrypted-zone history | plaintext left behind | seal → verify → purge with zone-migrate; parity check after purge; `scrub`; the residue checklist below |
| Zone access | a stranger whitelisted (and so granted the zone key) | live keys need a signed proof; archive keys are never whitelisted; the `agent` cohort is never granted |
| The work directory | theft | 0700/0600 everywhere; operator key never stored; keys retired when no longer needed |
| The operator's machine | hostile archive input | strict parsing, confined paths, no symlinks, bounded lines, pinned ImageMagick coders under a deny-all policy, bound SQL |

What a signature on an imported event proves: that **the operator's tool produced it from the
archive**, not that the person signed it. Source authorship is exactly as trustworthy as the
archive and the identity plan.

## Keys

* **Generated keys** come from `nostr_bbs_core::keys::generate_keypair` (the OS RNG). No
  cryptography is implemented in this crate: signing, NIP-44, gift wraps and sealing all come
  from `nostr-bbs-core` and `nostr-bbs-zone-migrate` (RustCrypto underneath).
* **The keystore** (`W/keys.json`) is written atomically (`O_EXCL` temp file 0600, fsync,
  rename, fsync of the directory) under a lock file, and refuses any change that would remove a
  label or replace a key: a re-run can never replace a key someone holds a recovery sheet for.
  The only permitted change is **retirement** (`keys retire`): the secret is dropped and the
  public key kept. Secrets are held in zeroizing buffers and never appear in logs, errors or
  `Debug` output.
* **Secret files** (`--operator-key`, `--rewrap-old-key`, `keys import --from`) are opened
  without following symlinks and must be regular files owned by you with mode 0600.
* **The operator key is never stored.** `keys import` records its public key; a run that signs
  operator messages reads the secret from its file for that run only.
* **Custody timeline.** The work directory holds every fresh key (each one a whitelisted member
  who will receive the zone key), every archive key and the archivist key.
  1. Retire archive keys after the final build (`keys retire --role archive`).
  2. Deliver recovery sheets out of band, then retire the fresh keys (`keys retire --role fresh`).
     Recommend that people rotate to a key of their own afterwards (a profile successor keeps their
     history attached).
  3. After sealing, export the archivist key to offline storage and retire it here. It is
     needed again only for a later `--deferred-only` round.
* **`NOSTR_BBS_MIGRATE_KEY`.** Use the per-command prefix form,
  `NOSTR_BBS_MIGRATE_KEY="$(cat a.key)" nostr-bbs-zone-migrate …`, never `export`. It keeps the key
  out of shell history, but not out of `/proc/<pid>/environ` for the same user. Shred the file
  afterwards.

## Why archive keys and profile successors

History has to be signed by someone, and a Nostr signature cannot be moved to another key.

* Signing a person's history with the operator's key would forge authorship.
* Asking for people's live secrets would be key custody.

So a person who keeps a live key gets a per-person **archive key** that signs only their imported
history. A **profile successor** (`pubkey_aliases`, many predecessors to one successor since
migration 0016) then makes every client show the live identity wherever the archive key appears.

* The archive key is never whitelisted. With zone cohorts, "Grant to members missing it" would
  wrap the zone key to a key whose secret sits in `keys.json`.
* **The live key must be proven.** A typo or a hostile mapping would otherwise whitelist a stranger,
  grant them the zone key, and show a real person's history under the stranger's profile.
  * A `proof` is an event signed by the live key whose content is exactly
    `nostr-bbs-bulk-import link <source>:<source_id> <author id>` (printed by `link-statement`). It is
    verified with `verify_event_strict`, and only then is the live key whitelisted.
  * `"trust": "operator"` records the operator's assertion. It writes the alias but no whitelist
    row, so the person joins through the normal invite flow.
* Successors resolve **one hop**. Do not chain aliases.

## The archivist

The archivist signs topic roots, new thread headers and the sealed envelopes. It is a
whitelisted admin with the zone cohorts, never `agent`. Treat it as a root-equivalent credential:

* it can read every imported zone (it holds the zone key grant);
* sealed topics resolve only through envelopes signed by an `is_admin = 1` key (the relay's F2
  rule), so **the archivist must stay admin for as long as the history exists**; revoking it hides
  every imported topic. A kit follow-up could pin the archivist pubkey so that it can be demoted.
* Use a throwaway browser profile when posting the anchors as the archivist.

## The anchor rule

The sealer will not encrypt a zone with a key it cannot confirm against a live encrypted post
**in the same channel**. A database built offline is all plaintext, so after minting and granting
the zone key the archivist posts one zk-encrypted message in every imported thread. Without
anchors, `seal-prep` lists the threads and `seal-offline` stops before sealing anything. There is
no unanchored offline path: a wrong key would produce a history nobody can read. Mint the new zone
key at an epoch above any epoch used before (old grants copied with `--allow-stale-grants` must
not shadow it).

## Untrusted archive input

* Every record type refuses unknown fields. NUL characters, invalid UTF-8, lines over 16 MiB and
  symlinked files are refused.
* Attachment paths must be relative and resolve inside the archive. Keybase asset paths must
  resolve inside `assets/`, so a crafted manifest cannot pull message files, which carry decryption
  keys, into the archive. The Keybase adapter parses a fixed set of fields and never copies raw
  lines.
* Images are typed from their magic bytes. ImageMagick runs with the input coder pinned
  (`png:file`) under a policy that denies every other coder, every delegate and `@file`
  indirection, with memory, area, size and time limits. Outputs are checked for EXIF/XMP (a WebP
  chunk walk, a GIF block walk); an image that fails any check is never uploaded. Objects are named
  by the full SHA-256 of their source bytes.
* SQL: every value is bound in the build. The upload dump writes any text that is not plain
  printable ASCII (or that contains `;`, quotes or comment markers) as `CAST(X'…' AS TEXT)`, so no
  statement splitter can misread it.

## The bucket-to-bucket copy

`r2-copy.jsonl` comes from URLs inside event content, which is untrusted. Only keys of the form
`pods/<64-hex>/media/<path>` with safe segments are listed (no dot-files, `.acl`, `.meta`, `..` or
containers), the import's own objects are excluded, and the copy runs from the old bucket to the
new one at the identical key, never the other way.

## Trusted operator input

`identities.json`, `structure.json` and `target.json` are trusted. A mistake in them is a
privilege grant: whitelisting, admin rows, aliases, and the URL that gets sealed into history.
Review them like code.

## DMs

* Only already-signed gift wraps travel. Source-platform DMs are never imported.
* **Copy** is verbatim (same id and signature, nothing decrypted), and only to live keys kept by
  proven identities (or the operator) that are whitelisted in the new deployment.
* **Re-wrap** covers only DMs the operator sent. Each wrap is opened in memory with
  `nostr_bbs_core::gift_wrap::unwrap_gift`, which verifies the wrap and the seal signatures and
  requires the rumor author to equal the seal signer. The operator's own rumors are re-sealed with
  the old key and wrapped to the new key. A rumor by anyone else is skipped and counted, because a
  seal must be signed by the rumor's author and we never forge a sender. The old key is read from
  a 0600 file and never stored.

## Residue checklist (after the purge)

Sealing removes the plaintext from the database, not from your disks.

* [ ] `nostr-bbs-import scrub --d1 D1` (stack down): `secure_delete`, `VACUUM`, truncating WAL
  checkpoint.
* [ ] Delete the other copies of the local persist directory, and any snapshots or backups taken
  before the purge.
* [ ] `shred -u W/search/docs.jsonl` once the search index is built.
* [ ] Destroy `W/archive/` and `W/media/` once the upload is verified (they hold the full
  plaintext and the images).
* [ ] Clear the browser profiles used against the local stack (cached decrypted pages).
* [ ] Retire keys as described above; destroy exported key files.

Zone media in R2 are **access-controlled, not encrypted**: the pod serves them only to zone
members, but they are stored in the clear.
