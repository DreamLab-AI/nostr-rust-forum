# nostr-bbs-zone-migrate

Operator CLI for the nostr-bbs kit that seals the plaintext history of an
encrypted zone into *sealed-original* envelopes, verifies them, and then
purges the plaintext from the relay
([ADR-2017](../../docs/adr/ADR-2017-sealed-original-history-migration.md)).

Each plaintext kind-42 in a listed channel is re-published as a zone-encrypted
kind-42, signed by an admin, that carries the **full original signed event**.
Its id, author, timestamp and replies survive, and the author's own signature
still proves the text. Members holding the zone key see the original message
unchanged. The wire format lives in `nostr_bbs_core::sealed`.

**Runbook:** [`docs/security/encrypted-zone-history-migration.md`](../../docs/security/encrypted-zone-history-migration.md).
Read it before running `purge`, which cannot be undone.

## Usage

```sh
export NOSTR_BBS_MIGRATE_KEY=nsec1…     # admin key: environment only, never a flag
M="nostr-bbs-zone-migrate --relay wss://relay.example.org \
   --channels channels.json --fetch-grants --state migrate-state.json"

$M --print-channels   # list kind-40 channels + section tags to write channels.json
$M plan               # dry run (the default); writes nothing
$M seal --limit 20    # small batch first
$M seal               # the rest; resumable
$M verify             # re-fetch and re-open every envelope
$M purge --yes        # delete plaintext; refuses unless every entry is verified
$M status             # counts from the state file (no network)
```

| Command | Does | Writes |
|---|---|---|
| `plan` (default) | Per channel: plaintext count, already-sealed count, ids that would be sealed, originals whose signature does not verify. | nothing |
| `seal [--limit N]` | Publishes an envelope per planned original, waits for `OK true`, fetches it back by id, opens it with the zone key, and requires the inner event to equal the original byte for byte. Envelopes already on the relay that open correctly are adopted rather than duplicated. | relay, state |
| `verify` | Re-fetches and re-opens every recorded envelope; the inner event must hash to what was sealed. | state |
| `purge --yes` | Refuses unless every entry is `verified` (or already `purged`). Re-checks each chunk's envelopes, then deletes the originals via `POST /api/admin/events/delete` (NIP-98, ≤ 200 ids per call). No kind-5, no broadcast. | relay, state |
| `status` | Counts by state. | nothing |

Global options: `--relay <wss://…>`, `--channels <path>`, `--keys-file <path>`,
`--fetch-grants`, `--state <path>`, `--json` (summary on stdout; progress
always on stderr).

Exit codes: `0` success; `1` error or refusal; `2` the step finished but some
entries are `failed`.

## Inputs

**Channels file** (explicit; zones are never inferred from section tags):

```json
[{"id": "<64-hex channel id>", "zone": "zone3"}]
```

**Key file** (optional; same schema as agentbox `zone-keys.json`):

```json
{"version": 1, "owner": "<admin pubkey hex>",
 "keys": [{"zone": "zone3", "epoch": 2, "secret": "<64 hex>", "pubkey": "<64 hex>"}]}
```

With `--fetch-grants`, kind-1059 zone-key grants addressed to the admin key are
accepted only when their seal verifies, the rumor is kind 21453, the secret
derives to the stated pubkey, and the sealer is a relay admin. These are the
forum client's rules. Keys from both sources are merged, and the highest epoch
per zone seals.

**State file**: per original id, the channel, zone, status
(`planned | sealed | verified | purged | failed`), the envelope id, the epoch
and the SHA-256 of the sealed JSON. It holds no secrets and no message text.
It is written atomically (temporary file, then rename).

## Library

The library is pure and compiles to `wasm32-unknown-unknown`. It contains the
planner, the state model, key and grant handling, and a seal/verify/purge
engine generic over a small async `Relay` trait. The binary's WebSocket
(NIP-42) and HTTP (NIP-98) client is one implementation of that trait. The
tests drive the full flow over an in-memory relay. All cryptography comes from
`nostr-bbs-core` (NIP-44, BIP-340, NIP-98).

This crate is not published: it is a project-specific operator tool for kit
deployments.

## Licence

AGPL-3.0-only, as the rest of the kit.
