---
id: ADR-2036
title: Extract shared nostr-bbs-client-core engine and re-imagine the retro BBS client as a responsive desktop and mobile TUI
date: 2026-11-26
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: [ADR-2008]
superseded_by: []
verified_commit: branch retro-bbs/integration (4e14871 merged with fix/forum-navigation 9339a11, plus the integration fixes under Verification); not 3d6d557, the main commit 4e14871 was cut from, which does not contain this change
verified_paths: [Cargo.toml, crates/nostr-bbs-client-core/Cargo.toml, crates/nostr-bbs-client-core/src/lib.rs, crates/nostr-bbs-forum-client/src/main.rs, crates/nostr-bbs-bbs-client/Cargo.toml, crates/nostr-bbs-bbs-client/index.html, crates/nostr-bbs-bbs-client/assets/bbs.css, crates/nostr-bbs-bbs-client/src/app.rs, crates/nostr-bbs-bbs-client/src/router.rs, crates/nostr-bbs-bbs-client/src/shell.rs, crates/nostr-bbs-bbs-client/src/pwa.rs]
owner: jjohare
review_trigger: first production deployment and real-phone touch/viewport verification of the rebuilt /community/bbs/ bundle; any future divergence in protocol stores between forum-client and bbs-client; any future remote-signer or hardware-signer backend added to nostr-bbs-client-core::auth
repo: nostr-rust-forum
domain: BASELINE-architecture.md
evidence_class: source+test
acceptance_boundary: Established on branch retro-bbs/integration, not on 4e14871 as first committed — cargo fmt --check, clippy -D warnings (workspace, all targets and features; and the three client crates on wasm32-unknown-unknown), cargo check --workspace on wasm32, cargo test --workspace --all-targets --all-features, rustdoc -D warnings, the forum's node tests and table3d recorded-hand test, anti-drift-lint.sh, identity-vector parity, config validation, the ADR frontmatter, evidence and ratchet checks, cargo-deny 0.22.1, and release trunk builds of both clients whose static JS module graphs resolve with no missing file. Not established — live browser or phone rendering, iOS Safari standalone PWA rebind against a live relay, the BBS start-up relay-scope check against production storage, or a production Cloudflare Pages deployment (which also needs the website deploy changes listed under Verification).
---

# ADR-2036 — Extract shared `nostr-bbs-client-core` engine and re-imagine the retro BBS client as a responsive desktop and mobile TUI

## Context

`nostr-bbs-bbs-client` (served at `/community/bbs/`) originally duplicated its own relay socket (`relay.rs`), signer (`signer.rs`, recorded as a divergence in ADR-2008), passkey/NIP-07 auth, DM store, notification store, and search modules. As `nostr-bbs-forum-client` evolved through encrypted zones (ADR-2016/2017), NIP-09 tombstones (ADR-2033), authenticated absence receipts (ADR-2034), governance control panels (ADR-2010/2011/2013), Sidestr multi-chain wallets (ADR-2015/2021), Heads-Up Poker (ADR-2020), Kanban (`30301`/`30302`), Calendar/Events (`31923`/`31925`), and Colloquy Knowledge (`ADR-2085/2086`), the BBS client drifted far behind trunk. Its legacy UI also depended on hostile browser hacks (a 60fps `outerHTML` phosphor-ghost loop, a `touch-action: none` slide-to-select scroll hijacker, and an Escape-spamming swipe listener) that degraded mobile usability.

## Decision

**1. Extract a shared headless client engine crate (`crates/nostr-bbs-client-core`, `publish = false`, `AGPL-3.0-only`).**

- `nostr-bbs-client-core` owns the shared reactive browser-client infrastructure: `auth` (Passkey PRF, NIP-07, local key, NIP-98), `relay` (NIP-42 AUTH, receipts, backoff), `zone_crypto` (ADR-2016/2017 encryption, sealed originals, grant paging/queues), `stores` (`ChannelStore`, `ReactionStore`, `PanelRegistry`, `ReceiptStore`, `CaseProjectionStore`, `NotificationStoreV2`, `ProfileCache`, `BadgeStore`, `MuteStore`, `CustomEmojiStore`, `ReadPositionStore`, `ZoneAccess`, tombstones, deletion sync), `dm` (NIP-59/17 with reactions, deletions, delivery reports, foreign-relay consent), `poker` (`HandState`, Libre Poker JS interop, `LiveStore`, AI coach), `wallet` (pinned multi-chain Sidestr stores), `utils` (Markdown sanitization, sealed search, bake/unbake, device keys, pod client), `toast`, `name_cache`, `agent_disclosure`, `types`, and `whitelist`.
- Both `nostr-bbs-forum-client` and `nostr-bbs-bbs-client` depend on `nostr-bbs-client-core` (`Cargo.toml` workspace dependency). `nostr-bbs-forum-client` re-exports its modules so its call sites are unchanged. The extraction was not regression-free as first committed (4e14871); see Verification.
- The standalone `BbsSigner` (`crates/nostr-bbs-bbs-client/src/signer.rs`) and all duplicated BBS transport/store modules (`relay.rs`, `dm.rs`, `outbox.rs`, `passkey.rs`, `nip07.rs`, `notifications.rs`, `search.rs`, `search_core.rs`) are deleted. This **supersedes ADR-2008**: key custody and signing now live in one shared implementation (`nostr_bbs_client_core::auth::AuthStore`), so any future remote/hardware signer automatically serves both clients. ADR-2008's custody rule for the BBS survives the merge: the BBS stores a raw key only when the member ticks "Stay signed in" (off by default), otherwise it signs in with `KeyPersistence::MemoryOnly`, and an installed app's key stays in its bake.

**2. Re-imagine `nostr-bbs-bbs-client` as a modern, responsive desktop + mobile TUI with feature parity.**

- **Responsive TUI shell (`src/shell.rs`, `assets/bbs.css`):** Desktop (`>= 900px`) renders a collapsible sidebar + scrollable main viewport + `/` slash command bar + `Ctrl/Cmd+K` global/sealed search + `g <key>` chord navigation. Mobile (`< 900px`) renders native vertical scrolling, a slide-over navigation drawer, a sticky 5-tab thumb bar (`Zones`, `Live`, `DMs`, `Agents`, `More`), `>= 44px` tap targets, `16px` inputs (preventing iOS auto-zoom), safe-area insets (`viewport-fit=cover`), and zero horizontal overflow.
- **Retro vibes preserved without hostile JS (`index.html`, `assets/bbs.css`):** The 60fps `outerHTML` ghost loop, `touch-action: none` scroll hijacker, and swipe-Escape script are removed. Four phosphor palettes (`amber`, `green`, `purple`, `sky`), pure-CSS CRT scanlines (with user toggle and `prefers-reduced-motion` gating), on-theme phosphor `AsciiImg` rendering (with raw toggle), and the UA 571-C Sentry Gun door game with Opus audio are retained.
- **Hash URL routing (`src/router.rs`):** `#/...` routes support deep links, reload persistence, and browser Back/Forward under `/community/bbs/` without proxy rewrite rules, while preserving ADR-109 `?pwa=1` zone-pinned one-shot boot (`src/pwa.rs`, `#/rebind`).
- **Member feature parity (`src/views/`):** Covers Zones/Boards/Threads (Markdown, reactions + custom emoji, edits, NIP-09 delete, NIP-56 report, encrypted `ZoneWriter`, drafts, bookmarks), Live Feed, per-zone Kanban (`30301`/`30302` + approval gates + `38000` agent dispatch), NIP-52 Calendar/Events & RSVPs, Colloquy Knowledge Board, Agent Governance (`31400–31405`), NIP-59/17 DMs, Door Games Hub (UA 571-C Sentry + Practice & Live Sidestr Hold'em Poker + Coach), Multi-Chain Sidestr Wallet, Authenticated Solid Pod Browser + Git, Members/Profiles/NIP-58 Badges, Notifications, and Settings (including revocable device keys and ADR-109 PWA controls). Operator admin consoles remain exclusive to `nostr-bbs-forum-client`.

## Consequences

- **Eliminates structural drift:** Protocol changes in `nostr-bbs-client-core` (zone encryption, tombstones, governance receipts, wallet pins, DM routing) propagate to both `forum-client` and `bbs-client` automatically.
- **Single auth/signing custody seam:** Both clients share `AuthStore`, retiring the dual-custody maintenance burden documented in ADR-2008. (Honest note: local-key/passkey sessions still hold a `SecretKey` in browser memory inside `AuthStore`; the improvement is eliminating the second, diverged signer implementation.)
- **Trade-off — larger BBS WASM surface:** Sharing the full client engine (including `sidestr-wallet`, `colloquy-*`, `comrak`, and `qrcode`) increases the BBS binary size compared to the minimal M2 read-only client; release builds continue to use workspace WASM size optimization (`opt-level = "z"`, `lto = true`, `strip = true`).
- **Follow-on work:** Live device testing across iOS Safari (including standalone PWA rebind) and Android Chrome after deploying the updated `/community/bbs/` bundle.

## Verification

**As first committed (4e14871), the earlier verification overstated what held.** It was run against `origin/main` `3d6d557` with the new code but without a trunk build, browser load or full-workspace gates, and it missed:

- the forum built from 4e14871 did not start in a browser: `js/table3d.js` imports `./librepoker/poker.js`, which wasm-bindgen now emitted only into client-core's snippet folder, so the module graph 404'd;
- CI's `tools/table3d-test.mjs` read test data from a path that had moved to client-core;
- the BBS defaulted "Stay signed in" to on, and that flag is the site-wide `nostr_bbs_remember`, so one BBS sign-in stored the private key in localStorage for the forum too;
- the installed-app start-up and re-link view copied the baked key into web storage as plain hex, and a generated key was stored where the old BBS kept it in memory (ADR-2008);
- `AuthStore.state`, `privkey` and `signer` were widened from `pub(crate)` to `pub`;
- the BBS never ran the forum's relay-scope storage check (`relay_scope::enforce`) over the storage it now shares.

**Fixed on branch `retro-bbs/integration`:**

- merged `fix/forum-navigation`; the post deep-link helpers (`jump_link`, `post_link`, `channel_of`) moved to `nostr_bbs_client_core::utils::post_link`, since client-core's notification store needs them;
- the forum crate declares `/js/librepoker/poker.js` so it ships beside `table3d.js`; the table3d test reads client-core's test data;
- "Stay signed in" defaults to off; `AuthStore` gains `KeyPersistence { RememberFlag, MemoryOnly }` with a tested storage plan, and the BBS signs in memory-only unless the box is ticked, including PWA adoption and re-link;
- `set_remember_me` re-saves only a local-key session's key, never a passkey-derived one;
- the three fields are `pub(crate)` again, with `AuthStore::state()` as a read-only accessor;
- both clients await `relay_scope::enforce_within(3_000)` before mounting.

**Website deploy changes this needs (dreamlab-ai-website `deploy.yml`):** the BBS `window.__ENV__` must carry the forum's `VITE_RELAY_URL`, `VITE_POD_API_URL`, `VITE_RELAY_EPOCH`, `SEARCH_PUBLISHERS`, `DEVICE_KEYS_ENABLED`, `SIDESTR_WALLET`, `SIDESTR_CHAINS` and `BRAND_LABEL`, and the BBS trunk step needs `NOSTR_BBS_NIP05_DOMAIN`. Without the same relay URL and epoch, the forum and the BBS compute different relay scopes and each clears the other's cached relay data whenever the member switches between them, so the website change must ship with this one.

Gates run on the integration branch (CI runs the same):
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo clippy --target wasm32-unknown-unknown -p nostr-bbs-client-core -p nostr-bbs-bbs-client -p nostr-bbs-forum-client --all-features -- -D warnings`
- `cargo check --workspace --target wasm32-unknown-unknown`
- `cargo test --workspace --all-targets --all-features`
- `RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links" cargo doc --workspace --no-deps`
- `node --test crates/nostr-bbs-forum-client/tests/*.test.mjs` and `node crates/nostr-bbs-forum-client/tools/table3d-test.mjs`
- `bash scripts/anti-drift-lint.sh`, `node scripts/identity-vector-parity.mjs`, `bash scripts/validate-forum-config.sh forum.example.toml`
- `node scripts/adr-index-gen.js docs/adr --check`, `bash scripts/tests/adr-ratchet-evidence.test.sh`, `bash scripts/tests/adr-evidence-class.test.sh`, `bash scripts/adr-ratchet.sh docs/adr <merge-base> HEAD`
- `cargo deny check` (cargo-deny 0.22.1, CI's version)
- release trunk builds of both clients from a clean `target/`, each checked for a static JS module graph with no missing file
