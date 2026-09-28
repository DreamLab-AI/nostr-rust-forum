# Encrypted-zone history migration — operator runbook

Seals the plaintext history of an encrypted zone and then removes the plaintext
from the relay. Decision and wire format:
[ADR-2017](../adr/ADR-2017-sealed-original-history-migration.md); zone keys and
grants: [ADR-2016](../adr/ADR-2016-end-to-end-encrypted-zones.md).

Each plaintext kind-42 in a listed channel is re-published as a *sealed
original* — a zone-encrypted kind-42, signed by your admin key, that carries the
full original signed event. Members with the zone key see the original message,
author, time and replies unchanged. Only after every envelope has been read back
and checked are the plaintext rows deleted, silently (no kind-5).

**`purge` cannot be undone.** After it, the relay holds the text only inside
envelopes, readable only with the zone key. Back up first.

## Prerequisites

1. **A D1 backup**, taken immediately before `purge`, stored where you can
   restore it. It contains the plaintext you are about to remove; treat it
   accordingly and decide now when it will be destroyed (see
   [After the run](#after-the-run)).
2. **Encryption switched on** for the deployment (`ENCRYPTION_ENABLED = "true"`)
   and `encrypted = true` on every target zone. The relay refuses envelopes into
   any other channel.
3. **An admin key that is not an agent.** The relay accepts envelopes only from
   an admin. The key must also hold every target zone's key, and grants skip any
   member with the `agent` cohort. Either use a non-agent admin key, or remove
   the `agent` cohort from the key you will use, grant it the keys, run the
   migration, and restore the cohort afterwards.
4. **The zone keys, on that admin key.** Either:
   - grants: in the forum, Admin › Encryption › *Grant to members missing it*
     with the migrating key included, then run with `--fetch-grants`; or
   - a key file (`--keys-file`), same schema as agentbox `zone-keys.json`:

     ```json
     {"version":1,"owner":"<admin pubkey hex>","keys":[
       {"zone":"zone3","epoch":2,"secret":"<hex>","pubkey":"<hex>"}]}
     ```

   Both may be given; they are merged, and the highest epoch held per zone is
   used for sealing. A key file is a zone secret on disk: keep it off shared
   storage and delete it after the run.
5. **A channels file** (`--channels`) naming every channel to migrate and its
   zone. The tool never guesses a zone from section tags.

   ```json
   [{"id":"<64-hex channel id>","zone":"zone3"},
    {"id":"<64-hex channel id>","zone":"zone4"}]
   ```

   `--print-channels` lists the relay's kind-40 channels with their section tag
   to help write it (it needs `--relay` and the admin key, because the relay
   withholds zone channels from non-members).
6. **The key in the environment**, never on the command line:

   ```sh
   export NOSTR_BBS_MIGRATE_KEY=nsec1…   # or 64-char hex
   ```

   The tool pre-checks the key against `GET /api/check-whitelist` and stops if
   it is not an admin.

## Running it

All subcommands take the same connection, key and state options; `--state` is
the record of the run and must be the same file throughout. Progress goes to
stderr; `--json` adds a machine-readable summary on stdout.

```sh
M="nostr-bbs-zone-migrate --relay wss://relay.example.org \
   --channels channels.json --fetch-grants --state migrate-state.json"
```

### 1. `plan` — dry run

```sh
$M plan
```

Lists, per channel: plaintext messages, messages already sealed, and the ids
that would be sealed. Writes nothing to the relay. Messages whose own signature
does not verify are reported and will never be sealed — review them; they stay
as plaintext and are not purged.

### 2. `seal` — publish envelopes

```sh
$M seal --limit 20     # try a small batch first
$M seal                # then the rest
```

For each original: builds the envelope, publishes it, waits for the relay's
`OK true`, fetches the envelope back by id, opens it with the zone key and
checks the inner event equals the original byte-for-byte. Resumable: re-running
skips entries already done, and retries entries that failed at `seal` or
`verify`. If an envelope for an original is already on the relay (for example,
the state file was lost after a run) and it opens to exactly that original, it
is *adopted* rather than published again. Nothing is deleted.

### 3. `verify` — re-check every envelope

```sh
$M verify
```

Fetches every envelope recorded in the state file again and opens it. Run it
after `seal`, and again just before `purge` if time has passed.

### 4. `purge` — remove the plaintext

```sh
$M purge --yes
```

Refuses unless **every** entry in the state file is `verified` (entries already
`purged` by an interrupted earlier run are allowed, so purge resumes). Just
before each chunk is deleted, its envelopes are fetched and opened once more.
If any fails, that chunk is not deleted, its entries are marked `failed`, and
purge stops. It deletes the original plaintext rows through `POST /api/admin/events/delete` in chunks of at
most 200, authenticated with NIP-98. No kind-5 is published and nothing is
broadcast, so clients do not tombstone the ids the envelopes restore. Each call
is recorded in the relay's admin audit log as `events.delete`.

`status` prints the state file's counts and failed entries at any point. It
needs only `--state`, with no relay or key.

Exit codes: `0` success; `1` error or refusal (nothing further was changed);
`2` the step finished but some entries are `failed`. The state file holds ids,
zones, epochs and a SHA-256 of each sealed event. It holds no secrets and no
message text, and it is rewritten atomically after every change.

## Entry states

| State | Meaning | Next |
|---|---|---|
| `planned` | Plaintext found, envelope not yet published. | `seal` |
| `sealed` | Envelope accepted by the relay, read back and opened; inner event matched the original. | `verify` |
| `verified` | `verify` fetched the envelope again and it opened and matched. The only state `purge` accepts. | `purge --yes` |
| `purged` | Plaintext row deleted from the relay. | none |
| `failed(reason)` | A step failed. The state file records it as `"status":"failed","step":"seal"\|"verify"\|"purge","reason":…`. At `seal` or `verify` the plaintext is untouched; at `purge` the relay kept the row because it is not kind 42. | fix, then `seal` (retries `seal` and `verify` failures) and `verify`; investigate a `purge` failure by hand |

A single `failed` or unverified entry blocks `purge` for the whole run, by design.

## Troubleshooting

| Relay message | Cause | Fix |
|---|---|---|
| `blocked: sealed originals are admin-only` | The migrating key is not a relay admin. | Use an admin key; confirm with `GET /api/check-whitelist?pubkey=<hex>`. |
| `blocked: sealed originals belong to encrypted zones` | The channel has no zone, its zone is not `encrypted`, or the deployment gate is off. | Correct the zone mapping in `channels.json`, set `encrypted = true`, or enable `ENCRYPTION_ENABLED`. |
| `blocked: encrypted zone requires zone-key ciphertext` | The envelope's `zk` tag or ciphertext is malformed — normally a stale or mismatched zone key. | Re-fetch grants or correct the key file; check the epoch pubkey matches the zone's current key. |
| `invalid: event validation failed` on an envelope more than seven days old | The relay predates ADR-2017 and applies the timestamp drift check to sealed originals. | Deploy a relay worker built from a kit commit that includes ADR-2017. |
| Envelope accepted but read-back does not match | Relay returned a different event, or the key used to open differs from the sealing key. | Leave the entry `failed`; re-run `seal` after checking keys. Do not purge. |
| `purge` refuses | Some entry is not `verified`. | `status`, fix the failures, `verify`, then purge. |
| `purge` reports ids in `notFound` | Already deleted (an earlier interrupted purge) or never stored. | Harmless if the envelope verified. |
| `purge` reports ids in `skipped` | The id exists but is not kind 42. | Investigate; the endpoint deletes only kind-42 rows. |

## After the run

- **Rotate each migrated zone** to a new epoch (Admin › Encryption › Rotate
  key) if any copy of the epoch secret used for sealing may persist outside
  members' devices — a key file, a shell history, a temporary grant to a
  normally-excluded agent key. Envelopes stay readable with the old epoch key,
  which members keep.
- Restore the `agent` cohort if you removed it, and delete any key file.
- **Backups:** D1 backups and exports from before the purge still hold the
  plaintext. They leave your estate only when your retention policy rotates them
  out; shorten it for this window if that matters.
- **The migrator keeps reading:** whichever admin key ran `seal` holds the
  epoch key used for the envelopes, and its grant stays on the relay for it to
  fetch again; admins also bypass cohort gating. Rotation does not take that
  away. If the migrator must not be able to read the zone afterwards, run it
  with a dedicated admin key created for the migration, then remove that key
  from the whitelist and delete its grants.
- **Member caches:** members' devices that already showed the plaintext keep
  their cached copy until the cache is cleared. The forum client shows one
  message, not two.
- **Retro BBS client:** envelopes appear as the encrypted placeholder,
  attributed to the migrating admin.
- **Search:** embeddings of zone messages indexed before encryption are not
  touched by this tool.
