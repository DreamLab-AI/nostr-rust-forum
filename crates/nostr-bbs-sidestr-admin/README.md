# nostr-bbs-sidestr-admin

The operator's wallet for a kit deployment's pinned sidestr chains: list a
key's holdings, issue an asset, send asset units or plain sats.

The kit pins two chains (`nostr-bbs-poker-citizen`'s `chain::PINS`):

| Chain | Parent | Header family | Producer on the estate |
|---|---|---|---|
| `sidestr:dreamlab` | `tbtc4` (testnet4) | stock | `http://127.0.0.1:3450` |
| `sidestr:dreamlab-txbt4` | `txbt4` (BLAKE2b testnet4) | `Blake2bV2` | `http://127.0.0.1:3451` |

The crates.io `sidestr-agent` CLI assumes one BLAKE2b header shape and cannot
replay `sidestr:dreamlab-txbt4`'s blocks. This tool replays the producer's
`/blocks.dat` with the house seat's two-family replay
(`nostr_bbs_poker_citizen::chain::replay`), after holding the producer's
`/chain.json` to the compiled pin field for field, and builds every
transaction with `sidestr-wallet` against the validated state and assets view.

## Usage

```
nostr-bbs-sidestr-admin [--url http://127.0.0.1:3450] [--chain-id sidestr:dreamlab] \
   --key-file <file> <SUBCOMMAND>
  assets
  issue      <TICKER> <SUPPLY> [--decimals N] [--dry-run] [--post]
  send-asset <ASSET_ID|TICKER> <RECIPIENT> <UNITS> [--memo TEXT] [--dry-run] [--post]
  send       <RECIPIENT> <SATS> [--dry-run] [--post]
```

- `--key-file` holds 64 hex characters or an `nsec1…`. The key is never a
  flag's value and never printed.
- `RECIPIENT` is a 64-hex pubkey or an `npub1…`; its `OP_1 <key>` script is paid.
- `issue` follows SPEC 12: output 0 carries the whole supply to the issuer.
  The printed txid is the asset's id.
- Default: build, sign, print the transaction hex and txid, post nothing.
  `--dry-run`: build and check in memory, print no hex. `--post`: `POST /tx`
  to the producer and print the accepted txid.
- Plain sends and fees spend only coins that carry no asset, so an asset is
  never destroyed; every built transaction is re-checked against the assets
  view first.

Example (txbt4 treasury, nothing posted):

```
nostr-bbs-sidestr-admin --url http://127.0.0.1:3451 --chain-id sidestr:dreamlab-txbt4 \
  --key-file ~/sidestr/agents/treasury-dreamlab-txbt4.key issue BLAKES7 10000000 --dry-run
```

Coins on these chains carry no value.

## Licence

AGPL-3.0-only, like the rest of the kit.
