# nostr-bbs-poker-citizen

The house seat of the [nostr-bbs](https://github.com/DreamLab-AI/nostr-rust-forum)
poker table. It holds its own Nostr key, deals committed heads-up limit
hold'em hands to members over gift-wrapped relay messages (kind 20779 rumors,
so DM inboxes never see them), plays the house bot by the book, and settles
every finished hand with one transfer of its chain's asset carrying the memo
`hand:<root>`. The member's browser only ever receives its own seat view.

One instance serves one chain. Two chains are pinned (kit ADR-2021), both
sealed documents compiled in:

| `--chain-id` | Parent | Asset | Producer on the estate's box |
|---|---|---|---|
| `sidestr:dreamlab` (default) | testnet4 (`tbtc4`) | DREAM, `608005d3…78a9` (default) | `http://127.0.0.1:3450` (default) |
| `sidestr:dreamlab-txbt4` | BLAKE2b testnet4 (`txbt4`) | BLAKES7: `--asset-id` and `--ticker` required | `http://127.0.0.1:3451` |

The producer's `/chain.json` must be, field for field, the pinned document of
the chosen chain, or the house seat refuses to start; every block it serves is
then validated against the compiled document under the header family its
parent hands down (Knots' 164-byte v2 headers beside `txbt4`).

The DREAM table:

```sh
nostr-bbs-poker-citizen \
  --key-file ~/sidestr/agents/poker-citizen.key \
  --relay wss://relay.example.org \
  --producer http://127.0.0.1:3450 \
  --state ~/sidestr/agents/poker-citizen.json \
  --stakes-bb 2,10,20,100,200 --buyin-bb 100 --profile tag --daily-cap 20000
```

The BLAKES7 table, a second instance with its own key and its own ledger:

```sh
nostr-bbs-poker-citizen \
  --chain-id sidestr:dreamlab-txbt4 \
  --asset-id <BLAKES7 issue txid, 64 hex> \
  --ticker BLAKES7 \
  --key-file ~/sidestr/agents/poker-citizen-txbt4.key \
  --relay wss://relay.example.org \
  --producer http://127.0.0.1:3451 \
  --state ~/sidestr/agents/poker-citizen-txbt4.json \
  --stakes-bb 2,10,20,100,200 --buyin-bb 100 --profile tag --daily-cap 20000
```

Every flag has an environment variable (`--help` lists them; the chain's are
`POKER_CITIZEN_CHAIN`, `POKER_CITIZEN_ASSET` and `POKER_CITIZEN_TICKER`). The
key file is 64 hex characters or an `nsec1…`; it is never a flag's value and
never printed. Testnet only: coins on these chains carry no value.

The relay must admit each house key (whitelisted, so members' wraps to it are
accepted), and each key must hold its chain's asset to cover buy-ins and plain
sats to pay transfer fees. Until the chain shows the asset's issue the house
seat says so at start and members cannot buy in. The ledger (`--state`)
remembers what members owe, what the house owes, and what it paid out today,
across restarts. The forum learns each house seat's key from
`[poker] citizens` (`POKER_CONFIG.citizens`).

Licence: AGPL-3.0-only.
