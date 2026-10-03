# nostr-bbs-poker-citizen

The house seat of the [nostr-bbs](https://github.com/DreamLab-AI/nostr-rust-forum)
poker table. It holds its own Nostr key, deals committed heads-up limit
hold'em hands to members over gift-wrapped relay messages (kind 20779 rumors,
so DM inboxes never see them), plays the house bot by the book, and settles
every finished hand with one DREAM transfer on `sidestr:dreamlab` carrying the
memo `hand:<root>`. The member's browser only ever receives its own seat view.

```sh
nostr-bbs-poker-citizen \
  --key-file ~/sidestr/agents/poker-citizen.key \
  --relay wss://relay.example.org \
  --producer http://127.0.0.1:3450 \
  --state ~/sidestr/agents/poker-citizen.json \
  --stakes-bb 2,10,20,100,200 --buyin-bb 100 --profile tag --daily-cap 20000
```

Every flag has an environment variable (`--help` lists them). The key file is
64 hex characters or an `nsec1…`; it is never a flag's value and never
printed. Testnet only: coins on `sidestr:dreamlab` carry no value.

The relay must admit the house's key (whitelisted, so members' wraps to it
are accepted) and the key must hold DREAM to cover buy-ins and plain sats
to pay transfer fees. The ledger (`--state`) remembers what members owe,
what the house owes, and what it paid out today, across restarts.

Licence: AGPL-3.0-only.
