# PRD — Retro ASCII/BBS client (`nostr-bbs-bbs-client`)

- **Status:** Draft (M1 in flight)
- **Date:** 2026-06-28
- **Owners:** `nostr-bbs-bbs-client` (the retro client, served at `/community/bbs/`),
  with read seams onto `nostr-bbs-config`, `nostr-bbs-core`, `solid-pod-rs`, and a
  future write seam onto `nostr-bbs-forum-client`'s signer/session.
- **Parity baseline:** `nostr-bbs-forum-client` (the modern forum, served at
  `/community/`) — the BBS is measured against its capability surface.
- **Related:** [ADR-105](../adr/ADR-105-bbs-door-games-and-write-architecture.md)
  (door-games framework + write-path architecture),
  [ddd-bbs-bounded-contexts](../ddd/ddd-bbs-bounded-contexts.md) (domain model).

---

## 1. Vision

A **faithful retro BBS** that is not a museum piece but a genuine, navigable face
over the same Nostr + Solid infrastructure the modern forum exposes. The terminal
aesthetic — phosphor palettes, CRT scanlines, ASCII art, number-key navigation — is
the *interface*, not the *limit*. The goal is that a member can do at the BBS the
things they came to the community to do (read boards, post, react, govern, browse
their pod) through a rational, discoverable terminal UX, with the retro skin adding
character rather than removing capability.

The BBS earns its place in the kit by being **driven by the same `forum.toml`**
(projected to `window.__ENV__`; see `src/config.rs`) and **reusing the kit's own
types** (`nostr_bbs_core::governance::PanelDefinition`, `nostr_bbs_core::did`,
`solid_pod_rs::webid`) rather than reimplementing them. It is a *projection* of the
forum, themed as a 1990s dial-up board.

## 2. Current-state assessment (the QE audit)

A QE audit established that the BBS today is a **read-only render skin**. The
evidence is structural, not impressionistic:

- **No identity/write surface in the dependency graph.** `Cargo.toml` depends only
  on `nostr-bbs-config`, `nostr-bbs-core`, `solid-pod-rs` (plus Leptos/wasm glue).
  There is **no auth crate, no signer, no key access**. The viewer's **public** key
  is read once, read-only, from the forum client's `localStorage` session
  (`src/config.rs:136` `FORUM_SESSION_KEY = "nostr_bbs_keys"`,
  `read_forum_session_pubkey` at `:156`, `pubkey_from_session` at `:144` reads only
  the `publicKey` field — the private-key entry is never touched).
- **No publish path.** `src/relay.rs` opens one WebSocket and only ever sends `REQ`
  and `CLOSE` frames (`connect` at `:172` sends two `REQ`s; `subscribe_board` at
  `:213` sends `CLOSE`+`REQ`). It **never sends an `EVENT`**. `RelayStore::ingest`
  (`:43`) routes inbound events into per-kind buckets; there is no outbound
  counterpart.
- **Consequence:** the client cannot post, reply, react, DM, RSVP, report,
  moderate, set a profile, or sign governance decisions. Every screen is a viewer.

### 2.1 Screen-by-screen current state

| # | Screen | Source | Current state |
|---|--------|--------|---------------|
| 1 | Main Menu | `chrome.rs:117` `MainMenu` | Navigable; rows have `on:click` (`:131`) |
| 1 | Message Base | `screens.rs:82` | Boards (kind-40) → posts (kind-42), read-only. Board rows (`screens.rs:146`) had **no `on:click`** — mouse users could not open a board (keyboard/touch only via `chrome.rs:245`) |
| 2 | File Base | `screens.rs:207` | Solid pod browser, **root container only** — `fetch_container(&pod_api, &hex, "")` at `:228` passes an empty path; no descent into sub-containers |
| 3 | Node List | `screens.rs:288` | **3 static rows** (relay/pod/mesh, `:303–310`); relay row is live-tinted, the rest are config strings |
| 4 | User List | `screens.rs:316` | kind-0 roster, read-only; no profile open, no mute |
| 5 | Chat | `screens.rs:350` | **Static placeholder** — prose claims DMs "stream over the relay" but nothing subscribes to kind-1059; no DM transport exists |
| 6 | Door Games | `screens.rs:397` | Governance panels (31400–31405) rendered read-only via `panel_view` (`:360`); action buttons are inert glyphs. **Now also launches the sentry-gun door game** (`launch_sentry` at `:387`) |
| 7 | Code Exchange | `screens.rs:435` | One prose line |
| 8 | System Info | `screens.rs:443` | Live read-only status (counts, DID, relay state) |
| 9 | Settings | `screens.rs:480` | Theme cycle only (`:486`, a `span.bbs-link`), **not persisted** across reloads |
| 0 | Help | `screens.rs:495` | Static about text |

### 2.2 Input model (current)

- **Desktop:** number keys `1`–`9`/`0`, `j`/`k`, arrows, `ENTER`, `ESC`, and `/`
  command line — installed by `install_key_handler` (`chrome.rs:219`). `ESC`/`Quit`
  only returns to the Main Menu (`menu.rs` `Command::Quit` → `chrome.rs:45` `go(MainMenu)`); there is **no real exit back to the forum**.
- **Mobile:** touch slide-to-select and lift-to-confirm (`index.html:97–141`), plus
  swipe-from-top → Main Menu (`index.html:147–164`). A single full-screen zoomed
  list per screen.

## 3. Goals / non-goals

### Goals
- Make every list screen **fully navigable by mouse, keyboard, and touch**.
- Reach **WCAG 2.1 AA** for the interactive chrome (roles, contrast, motion, focus).
- Persist the chosen theme.
- Give the BBS a **write path** by reusing the forum's signer, not by embedding auth.
- Ship the **UA 571-C sentry-gun door game** as the first member of a reusable
  door-games framework.
- Close parity with the forum in a rational order (write before DMs before admin).

### Non-goals
- The BBS **does not** re-implement auth, onboarding, the signer, or key lifecycle.
  Those live in `nostr-bbs-forum-client` / the auth-worker and are reused.
- The BBS is **not** a second source of truth for zones, governance schema, or pod
  URL formatting — it consumes the kit crates (anti-corruption boundary; see DDD).
- No URL routing: navigation stays a `Screen` state machine, faithful to a BBS.
- Door games are **not** gameplay infrastructure — they are self-contained overlays
  (see §5), not networked or persisted.

## 4. Parity matrix (forum domain → BBS status → target)

Status legend: **Full** = feature-complete · **Partial** = present but incomplete ·
**Read-only** = renders but cannot act · **Missing** = absent.

| Forum domain (`forum-client`) | BBS today | Target milestone |
|---|---|---|
| Identity / auth (NIP-07 · passkey · local-key · magic-link) | **Read-only** viewer pubkey from `localStorage` | Reuse forum session (M2) |
| Onboarding | **Missing** | Out of scope (forum owns) |
| Boards / zones (kind-40, zone-gating) | **Read-only** | Full read M1, themed M1 |
| Threads / posts — compose kind-42 | **Read-only** | **Full (M2)** |
| Replies (kind-1111) | **Missing** | **Full (M2)** |
| Mentions → p-tags | **Missing** | M2 |
| Reactions (kind-7) | **Missing** | **Full (M2)** |
| Pins (kind-41) · bookmarks · export | **Missing** | M3 |
| Media / link embeds | **Partial** (inbound images → ASCII via preview-worker) | Full M2 (outbound) |
| DMs (NIP-59 gift-wrap, kind-1059) | **Missing** (Chat is a placeholder) | **Full (M3)** |
| Profiles (kind-0) | **Read-only** roster | Open + edit M3, mute M3 |
| Calendar (kind-31923/31925 RSVP) | **Missing** | M3 |
| Governance (31400–31405) | **Read-only** panels | Render M1, **sign ActionResponse (M2)** |
| Pods (Solid LDP browser · git · upload) | **Partial** — root-only browse | Descent M1, upload M3 |
| Search (search-worker + semantic) | **Missing** | M3 |
| Notifications | **Missing** | M3 |
| Admin (10 tabs) · moderation (kind-1984) | **Missing** | M3 (subset) |
| Badges (NIP-58) | **Missing** | M3 |
| Settings (6 tabs incl devices) | **Partial** — theme only, unpersisted | Persist M1, devices M3 |
| PWA / offline / a11y (SW, IndexedDB, read positions, SR announcer) | **Missing** a11y; offline N/A | a11y P0s M1 |

## 5. Sentry-gun door game (requirement)

The **UA 571-C remote sentry weapon system** is a faithful Aliens (1986) control
deck — mode selectors, rounds counter, CRITICAL low-ammo warning, temperature
gauge, radar sweep, firing simulation, and a boot sequence — adapted from the
MIT-licensed CentriGUI project but **re-skinned in our phosphor theme**.

Requirements:

- **Auth-optional.** It must work whether the viewer is logged in or not. It touches
  no relay, no signer, no key (`launch_sentry` at `screens.rs:387` dispatches a
  `bbs:sentry` DOM event; the overlay in `index.html:170–331` handles it client-side).
- **Our styling, not CentriGUI's.** The overlay inherits the active theme via
  `curTheme()` (`index.html:197`) — `.sentry bbs-crt theme-*` — so it picks up our
  `--accent`/`--fg`/`--bg` and scanlines (`assets/bbs.css:348+`). CentriGUI's yellow
  GRID look and VCR font are **not** used.
- **Sounds.** Opus effects (`screenon`, `bip`, `buttonclick`, `noisefan`,
  `gameover`) in `assets/sentry-sounds/`, copied verbatim by Trunk
  (`index.html:12` `copy-dir`). MIT attribution retained.
- **Desktop + mobile.** Launchable from the Door Games screen (`[ ▶ PLAY ]` link,
  `screens.rs:401`); `ESC` exits (`index.html:329`). Buttons are keyboard-operable
  (`role="button" tabindex="0"`, `index.html:219–222`, `:243`).
- **Zero bundle cost.** The overlay is inline JS + CSS, adding nothing to the WASM
  bundle (rationale in ADR-105).

## 6. UX requirements

| ID | Requirement | Current gap |
|----|-------------|-------------|
| UX-1 | Every selectable row is openable by **mouse, keyboard, and touch** | Board rows lacked `on:click` (`screens.rs:146`); `nav_len` (`chrome.rs:210`) only counts Main Menu + boards, so `ENTER`/`j`/`k` are inert on other list screens |
| UX-2 | A real **"back / exit to forum"** affordance distinct from "back to Main Menu" | `Command::Quit` only returns to Main Menu (`chrome.rs:45`); no link out to `/community/` |
| UX-3 | **Persisted theme** across reloads | Theme cycle (`screens.rs:486`) mutates a signal only; not written to `localStorage` |
| UX-4 | **Discoverable input model** — the keyboard/touch grammar is visible, not folklore | Footer legend exists (`chrome.rs:144`) but mobile gestures and the `/` command set are undocumented in-app |
| UX-5 | Pod **descent** — open sub-containers in File Base | `fetch_container(..., "")` (`screens.rs:228`) is hard-wired to root |

## 7. Accessibility requirements

The audit found the chrome conveys state by **colour alone** and ships motion that
ignores user preference. Targets (WCAG 2.1 AA):

| ID | Requirement | Current gap |
|----|-------------|-------------|
| A11Y-1 | **ARIA roles + `aria-selected`** on lists/rows (`role="listbox"`/`option` or `menu`/`menuitem`) | None on `.bbs-menu-item`/`.bbs-row`; selection is the `.selected` class only — fails **1.4.1 Use of Colour** and **4.1.2 Name, Role, Value** |
| A11Y-2 | **Non-colour selection marker** (e.g. a `▸` glyph / inverse block) on the selected row | Selection shown only via `--select-bg` recolour |
| A11Y-3 | **AA contrast on body copy** | `--fg-dim: #8a5e00` on `--bg: #0a0a0a` (`bbs.css:9,13`) is used for `.bbs-dim` body text and subtitles; fails AA at body size |
| A11Y-4 | **Reduced-motion gating** of `crt-flicker` and cursor blink | `crt-flicker` (`bbs.css:99`) and `.bbs-blink` (`bbs.css:187`) are **not** gated; only `.phosphor-ghost` (`:268`) and the sentry overlay (`:433`) respect `prefers-reduced-motion` |
| A11Y-5 | **Focusable rows + Tab order** | Rows have no `tabindex`; keyboard is a single global `keydown` handler (`chrome.rs:219`), so there is no Tab traversal or visible focus ring |
| A11Y-6 | Settings theme control is a **`<button>`**, not a `<span>` | It is a `span.bbs-link` (`screens.rs:486`) — not in the tab order, no button semantics |

## 8. Milestone roadmap

### M1 — "rational & navigable" (no auth)
**Rationale:** make the read-only skin a *good* read-only skin first. Everything
here is achievable without a signer or relay write, so it ships independently and
de-risks the rest.

- UX-1 (add `on:click` to every selectable row; extend the central
  `nav_len`/`ENTER` model in `chrome.rs:210`/`:243` to all list screens).
- UX-2 (real exit-to-forum link), UX-3 (persist theme to `localStorage`), UX-5 (pod
  descent).
- A11Y P0s: A11Y-1, A11Y-2, A11Y-3, A11Y-4, A11Y-5, A11Y-6.
- Sentry-gun door game (already landed) + the door-games framework seam (ADR-105).
- **Effort:** ~1 sprint. Low risk; touches the client only, no kit crates.

### M2 — "it can write" (reuse the forum signer)
**Rationale:** the single highest-value gap. Reusing the forum's same-origin signer
(ADR-105) avoids duplicating auth and unlocks the core forum loop.

- Expose a minimal `sign()` seam onto `nostr-bbs-forum-client`'s session; add an
  `EVENT` publish path to `relay.rs` (the missing outbound counterpart to `ingest`).
- Compose / reply / react: kind-42, kind-1111, kind-7.
- Governance **ActionResponse** signing from the Door Games panels (the inert
  buttons in `panel_view` become real).
- Outbound media/link embeds.
- **Effort:** ~2 sprints. Medium risk (cross-client session seam, event signing).

### M3 — "parity"
**Rationale:** the long tail — valuable but each independent, so they fan out.

- DMs (kind-1059 gift-wrap subscribe + send) — replaces the Chat placeholder.
- Search (search-worker), calendar RSVP (31923/31925), notifications, profiles
  (open/edit/mute), badges (NIP-58), pod upload, and an admin/moderation subset.
- **Effort:** ~3–4 sprints, parallelisable across the independent surfaces.

## 9. Success criteria

- M1: every row openable by mouse/keyboard/touch; AA contrast and reduced-motion
  pass an automated a11y scan; theme survives reload; sentry game launches
  logged-out.
- M2: a member can post, reply, react, and approve a governance action from the BBS,
  signed by the forum session.
- M3: Chat streams real DMs; search returns results; the parity matrix shows no
  **Missing** rows in the in-scope set.
