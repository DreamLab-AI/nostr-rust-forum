# Vendored: Libre Poker engine

| | |
|---|---|
| Upstream | https://github.com/libre-poker/engine |
| Commit | `564d4c3f1ab069589b4c5d82f4e5db35a699f41c` (2026-08-16, "bestFive: the hand names its cards") |
| Licence | AGPL-3.0 (same as this kit) |
| Copied | byte-for-byte, unmodified |

| File | SHA-256 |
|---|---|
| `poker.js` | `d71b4f67d61080e3723b57592d0236ea3a83d9ea85e1e35a3893706aa2621339` |
| `bots.js` | `fec0dcac45014c2730bb10f9881c525b7fb6809f068c47ce847a0d2761f1e5de` |

## What is here and why

The practice table (`/table`, `src/pages/table.rs`) reaches the engine only
through `../poker-table.js`, which imports `poker.js` (hand state machine,
evaluator, seeded shuffle) and `bots.js` (the character bots). `bots.js`
imports only `poker.js`, so these two files are the complete transitive set.

Not vendored, deliberately:

- `ladder.js`, `river-solver.js`, `equity-buckets.js` — the trained
  heads-up strategy needs `strategy-hulimit.json` (6.7 MB) at runtime; the
  house bot is a `bots.js` character, so nothing imports them.
- `eval.js`, `tests.js`, `lbr.js`, `cfr.js`, `train*.js` and the other rigs —
  node-only (`node:fs`, `node:crypto`) tooling, never loaded in a browser.

## How the files reach the browser

wasm-bindgen ships each `#[wasm_bindgen(module = "/js/…")]` file as its own
text and does not follow `import`s, so `src/poker/mod.rs` declares both engine
files directly (`cardName` from `poker.js`, `ROSTER` from `bots.js`). That
writes them to `snippets/<crate>-<hash>/js/librepoker/`, beside the shim at
`snippets/<crate>-<hash>/js/poker-table.js`, where its relative imports
resolve. A new engine file the shim imports needs the same declaration.

## Updating

Copy the two files from a new upstream commit without editing them, update the
commit and hashes above, then regenerate the fixtures in `src/poker/testdata/` by running the shim under
node, and run `cargo test -p nostr-bbs-forum-client poker::`.
