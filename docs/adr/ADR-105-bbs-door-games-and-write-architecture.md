# ADR-105 — BBS door-games framework, auth-optional public surfaces, and the M2 write-path

- **Status:** Accepted (door-games framework + auth-optional principle implemented).
  **Amended 2026-07-03 (closeout):** the M2 write-path is now **implemented** in
  `nostr-bbs-bbs-client`, but it **diverges from the §2.3 decision** — it holds key
  material directly via the kit's audited signer rather than delegating to a forum
  `sign()` seam. See §6 (Amendment, 2026-07-03) below.
- **Date:** 2026-06-28
- **Owners:** `nostr-bbs-bbs-client` (the retro client), with a future write seam onto
  `nostr-bbs-forum-client` (the signer/session it will reuse).
- **Related:** [prd-bbs-retro-client](../prd/prd-bbs-retro-client.md) (the product
  context and milestones), [ddd-bbs-bounded-contexts](../ddd/ddd-bbs-bounded-contexts.md)
  (the Door Games and Identity contexts).

---

## 1. Context

The BBS (`/community/bbs/`) is today a **read-only render skin** (see the PRD §2):
its `Cargo.toml` pulls only `nostr-bbs-config`, `nostr-bbs-core`, `solid-pod-rs`;
there is no auth crate and no signer, and `relay.rs` only ever sends `REQ`/`CLOSE`,
never `EVENT`. Two distinct architectural questions arise as the client grows:

1. **Door games.** A new sprint adds a UA 571-C sentry-gun "door game" — a faithful
   Aliens (1986) control deck adapted from the MIT-licensed CentriGUI project. We
   need a repeatable way to add such self-contained interactive toys to the Door
   Games screen without dragging them through the relay, the signer, or the WASM
   bundle, and without losing the phosphor look.
2. **The write-path.** To move past read-only (PRD M2), the BBS must sign and
   publish events (kind-42/1111/7, governance `ActionResponse`). The question is
   whether it grows its **own** auth/signer or **reuses** the forum's.

Both share a principle worth recording explicitly: which BBS surfaces require
identity and which must work for anyone.

## 2. Decisions

### 2.1 Door games are pure client-side overlays launched by DOM events

A **door game** is a self-contained overlay rendered outside the Leptos tree,
opened by a custom DOM event dispatched from the Door Games screen.

- The Door Games screen exposes a launch affordance; activating it calls
  `launch_sentry` (`src/screens.rs:387`), which dispatches a `bbs:sentry`
  `CustomEvent` on `document`.
- The overlay is an inline `<script>`/`<style>` pair in `index.html` (`:170–331`)
  plus `.sentry-*` rules in `assets/bbs.css` (`:348+`). It listens for `bbs:sentry`
  (`index.html:328`), builds its DOM lazily, and tears down on `ESC` (`:329`).
- It **inherits the active phosphor theme**: `curTheme()` (`index.html:197`) reads
  the `theme-*` class off `.bbs-crt` and copies it onto the overlay
  (`.sentry bbs-crt theme-*`), so the game uses our `--accent`/`--fg`/`--bg` tokens
  and scanlines. CentriGUI's yellow GRID styling and VCR font are deliberately not
  carried over.
- Assets (the five `*.opus` sounds) live in `assets/sentry-sounds/` and are copied
  verbatim to `dist/` by Trunk (`index.html:12`, `rel="copy-dir"`).

The sentry gun is the **first** door game; the `bbs:<name>` DOM-event convention is
the seam for future ones.

### 2.2 Door games (and public surfaces) are auth-optional

Door games **must work whether the viewer is logged in or not**. The sentry overlay
touches no relay, no signer, and no key — it reads no `__ENV__` endpoint and sends
no event. This generalises to a principle: **a BBS surface requires identity only
when it reads private data or writes a signed event.** Everything else — the door
games, the masthead, the Help screen, read-only board/roster rendering — is public
and must degrade gracefully when `viewer_pubkey` is `None` (the logged-out case the
config already models at `src/config.rs:119`).

### 2.3 M2 write-path: reuse the forum's signer; do not embed auth in the BBS

When the BBS gains a write path (PRD M2), it will **reuse the modern forum's
signer/session rather than embedding its own authentication**. This is sound
because the two clients are **served same-origin**: the BBS at `/community/bbs/`,
the forum at `/community/`. The BBS already leans on this — it reads the viewer's
**public** key from the forum's `localStorage` session today
(`src/config.rs:136` `FORUM_SESSION_KEY = "nostr_bbs_keys"`).

The decision:

- The forum client exposes a **minimal `sign(event) -> SignedEvent` seam** (a
  same-origin capability — a small JS bridge or a shared signing helper), reachable
  from the BBS. The BBS never holds private-key material; it hands an unsigned event
  template to the forum's signer and receives a signed event back.
- `relay.rs` gains the missing **outbound `EVENT` path** — the publish counterpart
  to `RelayStore::ingest` (`src/relay.rs:43`). It sends `["EVENT", {…}]` over the
  existing socket; admission is the relay's job (the forum's whitelist rules apply
  unchanged).
- The signer covers **all four signup methods** the forum supports (NIP-07,
  passkey/PRF, local-key, magic-link) for free, because the BBS calls the forum's
  signer rather than re-implementing any of them.

### 2.4 Navigability model: `on:click` on every row + the central nav model extended to every list

The BBS keyboard model lives in one place — `install_key_handler`
(`src/chrome.rs:219`) with `nav_len` (`:210`) and the `ENTER` dispatch (`:243`).
Today `nav_len` only counts the Main Menu and the board list, and `ENTER` only acts
on those two; mouse `on:click` exists on Main Menu rows (`chrome.rs:131`) but **not**
on Message Base board rows (`screens.rs:146`). The decision:

- **Every selectable row gets an `on:click`** that performs the same action `ENTER`
  performs on that row (open board, open profile, open pod sub-container, …).
- `nav_len` and the `ENTER` branch are **extended to every list screen**, so the
  keyboard, mouse, and touch paths converge on one action per row. Touch already
  bridges to the keyboard model (`index.html:97–141`), so extending the keyboard
  model fixes all three input methods at once.
- A **real exit-to-forum** affordance is added, distinct from `Command::Quit`'s
  current "return to Main Menu" (`chrome.rs:45`) — a link out to `/community/`.

## 3. Consequences

- **Positive (door games).** Zero WASM-bundle cost (inline JS/CSS), full theme
  integration (inherits `theme-*`), and a clean launch seam (`bbs:<name>` events).
  Adding a second door game is "write an overlay + dispatch an event" with no Rust
  rebuild. MIT-licence compliance is satisfied by attribution in `index.html:169`
  and `assets/bbs.css:349`.
- **Positive (write-path).** The BBS inherits the forum's entire auth surface
  without duplicating it; no second key store, no second onboarding, no divergence
  in key lifecycle (ADR-099/100). One login at `/community/` carries into the BBS.
- **Negative / accepted (door games).** Overlays live outside the Leptos reactive
  tree and bypass Rust's type safety — they are plain DOM/JS and must be reviewed as
  such. Their state is ephemeral and not persisted (acceptable for toys).
- **Negative / accepted (write-path).** A hard **same-origin coupling** to the forum
  client: the BBS cannot write if the forum client is not deployed alongside it, and
  the `sign()` seam is a contract both clients must keep stable. This is acceptable
  because they ship together as one kit and are pinned together (the dual-pin rule).
- **Coupling note.** The BBS already depends on the forum's `localStorage` key name
  (`nostr_bbs_keys`); the write-path formalises that incidental coupling into an
  intentional, documented seam rather than leaving it implicit.

## 4. Alternatives considered

### Door games
- **`<iframe>` to an external app.** Rejected: an iframe cannot inherit our CSS
  custom properties, so the game could not be on-theme; it adds a navigation/origin
  boundary and a second asset pipeline for no benefit.
- **A Leptos port of the game.** Rejected: it would bloat the WASM bundle for a
  self-contained toy, couple the game's lifecycle to the reactive tree, and gain
  nothing — the game has no Nostr/Solid state to manage. Adapting CentriGUI's logic
  and sounds into an inline overlay is cheaper and keeps the MIT lineage clear.

### Write-path
- **Embed an auth crate / signer in the BBS.** Rejected: duplicates the forum's
  identity, onboarding, and key-lifecycle work; creates a second key store and a
  divergence risk across ADR-099/100; violates "forum behaviour belongs upstream."
- **A shared signer crate consumed by both clients.** Viable long-term, but heavier
  than M2 needs. The same-origin `sign()` seam delivers the capability now; a shared
  crate can replace the seam later without changing the BBS's call site.
- **Read-only forever.** Rejected by the PRD: it strands the BBS as a viewer and
  fails the parity vision.

## 6. Amendment (2026-07-03) — shipped write-path diverges from §2.3

The M2 write-path shipped, but **not** as the §2.3 delegated-`sign()`-seam decision
described. This amendment records what was actually built and why, so the register
matches the code (the decision's key-custody assertion is security-load-bearing).

**What shipped.** `nostr-bbs-bbs-client` gained a **crypto-owning** signer
(`src/signer.rs` — module doc: "the crypto-owning module"). `BbsSigner::install`
wraps a `Keypair` in the kit's audited `nostr_bbs_core::signer::PrfSigner` and holds
it in-process; `relay.rs::publish` now emits `["EVENT", …]` (contradicting §1's "then
`relay.rs` only ever sends `REQ`/`CLOSE`, never `EVENT`"); `screens.rs::publish_signed`
signs and publishes, and the governance `action_button` signs + publishes a kind-31403
`ActionResponse`. The write-path is live, not deferred.

**How it diverges from §2.3.** §2.3 decided the BBS would **never hold private-key
material** and would instead hand an unsigned template to a forum `sign()` bridge.
The shipped design instead **holds the key directly**, via two acquisition paths:

1. **Adopt the forum session, same-origin.** For local-key / imported-nsec logins it
   reads the forum's `nostr_bbs_sk` hex from `localStorage`/`sessionStorage` (the BBS
   is served same-origin at `/community/bbs/`), decodes it into a `Keypair`, and
   scrubs the transient hex.
2. **Minimal in-memory login.** Paste an `nsec1…`/hex key or generate a fresh one; the
   `Keypair` lives only in memory, is zeroized on drop, and is never persisted by the
   BBS. Passkey / NIP-07 users (no readable `nostr_bbs_sk`) take this path or sign in
   at `/community/`.

**Rationale for accepting the divergence.** It reuses the kit's NCC-audited crypto
(BIP-340 Schnorr + NIP-44 via `PrfSigner`) with **no hand-rolled cryptography**, which
the delegated seam was partly meant to guarantee. The same-origin boundary means the
adopted key confers **no new exposure**: any same-origin script — including the JS
`sign()` bridge §2.3 envisioned — can already read `nostr_bbs_sk`, so a direct-hold and
a same-origin delegated seam sit on the identical trust boundary. The in-memory path
fails closed (no signer ⇒ write actions disabled).

**Residual boundary to note.** A passkey/NIP-07 user who takes path 2 with a
freshly-generated key is signing under a **distinct** in-memory key, not their
passkey-derived root — operators surfacing BBS governance writes should be aware the
BBS does not itself derive from the PRF root. Closing that (a true forum-signer
delegation for passkey sessions) remains the option §2.3 preferred; it is deferred,
not lost. Until then, the crypto-owning `BbsSigner` above is the accepted design.
