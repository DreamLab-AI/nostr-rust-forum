# Bulk import intermediate format, version 1

The contract between a source adapter and the importer. Any tool, in any language, that writes
this layout can feed `nostr-bbs-import adapt generic`. Rust adapters write it through
`nostr_bbs_bulk_import::format::ArchiveWriter`, which enforces everything below.

## Versioning

`manifest.json` names the format and an integer `version`. This document is version **1**.
Every record type refuses unknown fields, so adding a field is a new version; an importer reads
only the versions it knows and refuses the rest. There are no optional extensions.

## Layout

```
manifest.json
authors.jsonl
channels.jsonl
messages.jsonl
reactions.jsonl      (may be empty or absent)
dms.jsonl            (may be empty or absent)
attachments/…        files named by the attachment paths
```

`.jsonl` files hold one JSON object per line, UTF-8, `\n`-separated. Blank lines are ignored.
Lines longer than 16 MiB, invalid UTF-8, NUL characters anywhere in a string, and symlinked files
are refused. All times are **unix seconds**.

## `manifest.json`

```json
{"format":"nostr-bbs-bulk-import","version":1,"source":"keybase","source_id":"myteam",
 "exported_at":1732400000,
 "counts":{"authors":12,"channels":4,"messages":5321,"reactions":880,"dms":0}}
```

| Field | Rule |
|---|---|
| `format` | exactly `nostr-bbs-bulk-import` |
| `version` | `1` |
| `source` | the platform, `[a-z0-9-]+` (`keybase`, `discord`, `slack`, `matrix`) |
| `source_id` | what was exported (team, guild, workspace, room); with `source` it forms the provenance `<source>:<source_id>` |
| `exported_at` | when the archive was written |
| `counts` | must equal the line counts of the files |

## `authors.jsonl`

```json
{"id":"alice","handle":"alice","display_name":"Alice A","about":"…","bot":false}
```

| Field | Rule |
|---|---|
| `id` | required, unique, non-empty; the key `identities.json` uses |
| `handle` | required, non-empty; shown in profiles |
| `display_name`, `about` | optional |
| `bot` | optional, default `false`; bots are proposed as `drop` |

## `channels.jsonl`

```json
{"id":"0f3a…","name":"general","topic":"Anything goes","created_at":1500000000}
```

`id` is required and unique; `structure.json` maps channels **by id**, never by name (names can be
missing or repeated). `name` is required (no leading `#`). `topic` and `created_at` are optional.
Each channel becomes one forum topic.

## `messages.jsonl`

```json
{"id":"0f3a…:1234","channel":"0f3a…","author":"alice","created_at":1600000000,
 "text":"hello","reply_to":"0f3a…:1200","edited_at":1600000100,
 "attachments":[{"sha256":"9b1c…","path":"attachments/9b/9b1c…","filename":"cat.jpg",
                 "mime":"image/jpeg","bytes":48211,"status":"ok"}]}
```

| Field | Rule |
|---|---|
| `id` | required, unique across the **whole archive** (prefix with the channel id when the source numbers per channel) |
| `channel`, `author` | must name a channel and an author in the archive |
| `created_at` | the ORIGINAL send time, non-zero; it becomes the event's `created_at` |
| `text` | the final text after every edit (may be empty when there are attachments) |
| `reply_to` | optional; any message id, possibly absent from the archive (deleted upstream) or in another channel. A reply to an imported message in the same thread becomes a `quote` link; anything else becomes a first-line note |
| `edited_at` | optional, informational |
| `attachments` | optional list, see below |

Edits and deletes are **applied by the adapter**: a deleted message is simply absent, and so are
reactions to it. Messages are sorted by the writer; order in the file carries no meaning.

### Attachments

| Field | Rule |
|---|---|
| `status` | `ok` (bytes present), `unavailable` (the source could not deliver them) or `skipped` (not fetched) |
| `sha256` | lowercase hex SHA-256 of the bytes; required when `ok`, absent otherwise |
| `path` | relative path of the bytes under the archive root; required when `ok`. Absolute paths, `..` and anything resolving outside the root (symlinks included) are refused |
| `filename`, `mime` | required (declared values; the importer sniffs image types from the bytes) |
| `bytes` | optional size |

Only images reach the forum (as zone-restricted pod objects). Other kinds become a line such as
`[video not migrated: clip.mov, 3.3 MB, 2021-01-07]`.

## `reactions.jsonl`

```json
{"message":"0f3a…:1234","author":"bob","emoji":":+1:","created_at":1600000050}
```

`message` and `author` must exist. `emoji` is a Unicode emoji or a `:shortcode:`. Reactions are
folded into the target message's text (`— reactions: 👍 ×3 (alice, bob, carol)`), never published
as kind 7, which the relay's retention sweep deletes after 30 days.

## `dms.jsonl`

Already-signed NIP-59 gift wraps (kind 1059), verbatim, one per line. They are copied only to
recipients that keep their key in the new deployment, or re-wrapped when the operator wrote them
(see SECURITY.md). **Source-platform DMs are out of scope**: importing them would mean signing
in someone else's name.

## Limits of version 1

* No thread concept separate from the channel: a Slack `thread_ts`, Discord thread or Matrix
  `m.thread` maps to `reply_to` the thread's first message.
* Mentions stay text; no `p`-tag rewriting.
* No system messages (joins, pins, topic changes): adapters drop them.
* No avatars.
* The Rust writer holds the archive in memory (fine for a few hundred thousand messages).

## Writing an adapter

1. Read the export with the platform's own tools or API; never copy raw records through (they
   can hold secrets: Keybase lines carry attachment decryption keys).
2. Map accounts to `authors`, channels or rooms to `channels`, and give every message a
   globally unique id.
3. Apply edits (keep the final text) and deletes (drop the message and its reactions).
4. Emit attachments with their bytes and digest, or with `status` `unavailable`/`skipped`.
5. Write the files, then run `nostr-bbs-import adapt generic --in DIR --work W`, which validates
   and normalises them (re-digesting every attachment).

In Rust, implement `nostr_bbs_bulk_import::adapter::SourceAdapter` and add the type to the CLI's
`Source` enum. `adapter/keybase.rs` is a complete example. Platform notes:

| Platform | Notes |
|---|---|
| Discord | message ids are global snowflakes; `created_at` from the snowflake or `timestamp`; replies via `message_reference`; threads are channels in the API, so either map them to channels (one topic each) or flatten into `reply_to` |
| Slack | message ids are `ts` per channel: use `<channel>:<ts>`; thread replies carry `thread_ts`, so use it as `reply_to`; files need a token to download |
| Matrix | event ids are global; edits are `m.replace` relations (apply them), redactions are deletes, `m.in_reply_to` is `reply_to`; encrypted rooms must be decrypted by the exporter |
