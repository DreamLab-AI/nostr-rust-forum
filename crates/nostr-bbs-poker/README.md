# nostr-bbs-poker

Heads-up poker for the [nostr-bbs](https://github.com/DreamLab-AI/nostr-rust-forum)
forum: the Libre Poker engine and house bots in Rust, the two-party fair
deal, the settlement rules (one transfer per hand, `hand:<root>` memo, RFC
8785 roots), the HAND.md record, the member ↔ house table protocol, and
replay verification. Pure Rust, no I/O; builds for `wasm32-unknown-unknown`
and natively.

The engine and bots are ports of AGPL-3.0 JavaScript by the
[Libre Poker](https://github.com/libre-poker/engine) project (commit
`564d4c3`); `tests/differential.rs` holds the port to the original on 160
recorded hands. Regenerate the fixtures after a vendored-engine update with
`node tools/gen-fixtures.mjs > tests/fixtures/hands.json`.

See the crate documentation for the protocol and the fairness argument.
Licence: AGPL-3.0-only.
