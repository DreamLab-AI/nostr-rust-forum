# nostr-bbs-bbs-client

A modern **retro ASCII/BBS TUI** face for the `nostr-rust-forum` kit — a
responsive Leptos CSR/WASM application served at `/community/bbs/` and driven
by `forum.toml` (`window.__ENV__`).

Rather than maintaining a parallel reimplementation, `nostr-bbs-bbs-client`
consumes the shared headless [`nostr-bbs-client-core`](../nostr-bbs-client-core)
engine alongside `nostr-bbs-forum-client`. Auth, relay sync, NIP-42 AUTH,
encrypted zones (ADR-2016/2017), reactions, NIP-09 tombstones, governance,
NIP-59/17 DMs, Kanban, Calendar, Colloquy Knowledge, Poker, and Sidestr wallets
all run on the exact same stores and crypto primitives.

## Surfaces & Feature Parity

| View / Hash Route | Kit Capability |
|---|---|
| `#/zones`, `#/zone/<slug>` | Config-driven zones & boards (`[[zones]]`), kind-40/42, encrypted zone badges |
| `#/board/<id>`, `#/thread/<ch>/<post>` | NIP-28 / NIP-22 threads, Markdown, reactions + custom emoji, edits, NIP-09 delete, NIP-56 report, encrypted `ZoneWriter`, image upload + ASCII/Raw toggle |
| `#/live` | Cross-board live post feed |
| `#/kanban/<zone>` | Per-zone Kanban (`30301`/`30302`), approval gates (`31402`), `38000` agent dispatch |
| `#/events/<zone>` | NIP-52 Calendar & Events (`31923`/`31925`), live RSVPs, free/busy, poker deep links |
| `#/knowledge/<zone>` | Colloquy Knowledge Board (`colloquy-core`/`colloquy-nostr`), principal-counted attestations, gap signals |
| `#/agents` | Governance control plane (`31400–31405`), relay-authoritative risk tiers, calibration samples, receipts, Approve/Reject/Promote/Demote/Delegate |
| `#/dm`, `#/dm/<pubkey>` | Encrypted NIP-59/17 DMs with reactions, deletions, delivery reports, foreign-relay consent |
| `#/games`, `#/games/poker[/<chain>]` | Door Games Hub: UA 571-C Sentry Gun (with Opus audio) + Practice & Live Sidestr Hold'em Poker (`nostr-bbs-poker`) + AI Coach |
| `#/wallet` | Multi-chain Sidestr Wallet (`DREAM`, `BLAKES7`, `kind:23500`, receive QR, faucet, tab unlock) |
| `#/pod` | NIP-98 authenticated Solid Pod browser (`solid-pod-rs`) + Pod Git status/commit/log |
| `#/members`, `#/u/<pubkey>` | Member directory, `did:nostr` / WebID profiles, NIP-58 badges, non-clobbering kind-0 editor |
| `#/bookmarks`, `#/notifications`, `#/settings`, `#/help` | Per-identity bookmarks, live notification center, 4 phosphor themes + CRT toggle + auth + device keys + ADR-109 PWA |

## Desktop & Mobile Phone UX

- **Desktop (`>= 900px`)**: Collapsible left sidebar with unread badges, main scrollable viewport, `/` slash command bar, `Ctrl/Cmd+K` global + sealed search, `g <key>` chord navigation.
- **Mobile (`< 900px`)**: Native vertical scrolling (zero scroll-hijack JS), slide-over navigation drawer, sticky 5-tab thumb bar (`Zones`, `Live`, `DMs`, `Agents`, `More`), `>= 44px` tap targets, `16px` inputs (no iOS auto-zoom), safe-area inset support, and zero horizontal overflow.

## Configuration (`forum.toml` → `window.__ENV__`)

Projected globals: `THEME`, `NODE_NAME`, `TAGLINE`, `LOCATION`, `BANNER_URL`,
`LOGO_URL`, `RELAY_URL`, `POD_API`, `PREVIEW_API`, `SEARCH_API`, `ZONE_CONFIG`,
`ENCRYPTION_ENABLED`, `BBS_PWA_ENABLED`, `SIDESTR_WALLET`, `SIDESTR_CHAINS`,
`POKER`, `POKER_CONFIG`, `DEVICE_KEYS_ENABLED` — identical to `nostr-bbs-forum-client`.

## Build & Test

```bash
cargo test -p nostr-bbs-bbs-client
cargo check --target wasm32-unknown-unknown -p nostr-bbs-bbs-client
cd crates/nostr-bbs-bbs-client && trunk build --release --public-url /community/bbs/
```
