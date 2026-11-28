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
| `#/board/<id>`, `#/thread/<ch>/<post>` | NIP-28 / NIP-22 threads, Markdown, reactions + custom emoji, edits, NIP-09 delete, NIP-56 report, encrypted `ZoneWriter`, image upload; tap an ASCII image for the original picture (zone media fetched with the member's own credentials) |
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
- **Mobile (`< 900px`)**: Native vertical scrolling (zero scroll-hijack JS), slide-over navigation drawer, sticky 5-tab thumb bar (`Zones`, `Live`, `DMs`, `Agents`, `More`), `>= 44px` tap targets, inputs never below `16px` (no iOS auto-zoom), safe-area inset support, and zero horizontal overflow.
- **Topic subscriptions** (signed-in members): each board topic row has a `[ ]`/`[*]` subscribe toggle (or press `s` on a focused row; Enter opens it; on touch, swipe the row either way). Subscribed topics are listed alphabetically, with a glowing new-post count to the left of each name, in a collapsible right-hand column on desktop (`]` or the top-bar `[*]` button) and, at `<= 640px`, in a right-hand drawer opened by tapping or pulling the small `SUBS` tab on the right edge (closed by pushing it right, tapping the scrim or Escape). Opening a thread clears its count.
- **Phones (`<= 640px`, or touch screens in portrait below `900px`)**: all text at twice the desktop size. Every size is in `rem` from one root ladder (browser text size × shared font preference × the BBS TEXT SIZE setting × 2 on phones), so the member's browser setting and TEXT SIZE: LARGE still apply; ASCII art is fitted to its container instead of doubling.

## Configuration (`forum.toml` → `window.__ENV__`)

Projected globals: `THEME`, `NODE_NAME`, `TAGLINE`, `LOCATION`, `BANNER_URL`,
`LOGO_URL`, `RELAY_URL`, `POD_API`, `POD_API_ALIASES` (BBS only: earlier origins of the same pod storage that old posts still link to, comma separated), `PREVIEW_API`, `SEARCH_API`, `ZONE_CONFIG`,
`ENCRYPTION_ENABLED`, `BBS_PWA_ENABLED`, `SIDESTR_WALLET`, `SIDESTR_CHAINS`,
`POKER`, `POKER_CONFIG`, `DEVICE_KEYS_ENABLED` — identical to `nostr-bbs-forum-client`.

## Build & Test

```bash
cargo test -p nostr-bbs-bbs-client
cargo check --target wasm32-unknown-unknown -p nostr-bbs-bbs-client
cd crates/nostr-bbs-bbs-client && trunk build --release --public-url /community/bbs/
```
