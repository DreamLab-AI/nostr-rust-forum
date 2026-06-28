# DDD — BBS bounded contexts (`nostr-bbs-bbs-client`)

- **Status:** Draft (describes the current read-only model and the M2 signer seam)
- **Date:** 2026-06-28
- **Owners:** `nostr-bbs-bbs-client` (the retro ASCII/BBS client at `/community/bbs/`).
- **Related:** [prd-bbs-retro-client](../prd/prd-bbs-retro-client.md),
  [ADR-105](../adr/ADR-105-bbs-door-games-and-write-architecture.md).

---

## 1. Purpose

This document models the BBS as a set of **bounded contexts** with an explicit
**anti-corruption boundary** to the kit's shared crates. The BBS is a *projection*
of the forum's domain into a terminal UX, so most of its model is borrowed: it
consumes `nostr_bbs_core` (event + governance + DID schema), `nostr_bbs_config`
(zones), and `solid_pod_rs` (WebID/pod URLs) rather than owning those concepts. The
contexts the BBS genuinely **owns** are navigation/screen state, rendering/theme,
and door games. The current model is **read-only**; §6 marks exactly where the
signer seam enters.

## 2. Bounded contexts

| Context | Owns | Source | State today |
|---------|------|--------|-------------|
| **Navigation / Screen state machine** | the `Screen` enum, selection index, command-line, board focus | `menu.rs`, `chrome.rs` (`BbsState`) | Owned, complete |
| **Identity (Viewer)** | the read-only viewer; future signer seam | `identity.rs`, `config.rs` | **Read-only viewer** |
| **Boards & Posts** | projection of kind-40/42 into board/post lists | `relay.rs`, `screens.rs` (Message Base) | Read-only |
| **Pods / Files** | projection of the Solid LDP container into a file list | `pod.rs`, `screens.rs` (File Base) | Read-only, root-only |
| **Governance / Agent panels** | projection of 31400–31405 panels; future `ActionResponse` | `agent.rs`, `screens.rs` (Door Games) | Read-only render |
| **Door Games** | self-contained interactive overlays (the sentry gun) | `index.html`, `assets/bbs.css` | Owned, working, auth-optional |
| **Rendering / Theme** | phosphor palette, CRT chrome, ASCII-image rendering | `theme.rs`, `ascii_img.rs`, `bbs.css` | Owned |

### Context map (sketch)

```
            ┌─────────────────────────────────────────┐
            │  Navigation / Screen state machine        │  (owns BbsState)
            │  menu.rs · chrome.rs                       │
            └───────────────┬───────────────────────────┘
                            │ drives
   ┌────────────┬───────────┼────────────┬──────────────┬────────────┐
   ▼            ▼           ▼            ▼              ▼            ▼
Identity   Boards&Posts   Pods/Files  Governance     Door Games   Render/Theme
(Viewer)   (kind-40/42)   (Solid LDP) (31400-31405)  (overlays)   (phosphor/ASCII)
   │            │            │            │              ┊            │
   └─ ACL ──────┴── ACL ─────┴── ACL ─────┘         (no kit dep)     │
        anti-corruption boundary (§5)                                │
   ┌────────────────────────────────────────────────────────────────┘
   ▼ shared kit crates
 nostr-bbs-core (event/governance/did) · nostr-bbs-config (Zone) · solid-pod-rs (webid)
```

## 3. Ubiquitous language

| Term | Definition in the BBS |
|------|----------------------|
| **Screen** | One of ten terminal views, a variant of `menu.rs::Screen`; the unit of navigation. Not a URL. |
| **Board** | A kind-40 channel (`NostrEvent`), zone-tagged, rendered as a Message Base row (`relay::channel_name`, `relay::channel_zone`). |
| **Post** | A kind-42 channel message whose first `e`-tag roots it to a Board (`relay::post_root_channel`). |
| **Zone** | A `nostr_bbs_config::schema::Zone` (id, display name, visibility, `accent_hex`, banner) — the access/visibility grouping a Board belongs to. Owned upstream; the BBS only tints/labels by it. |
| **Viewer** | The signed-in member as seen by the BBS — **public key only** (`config.viewer_pubkey`), resolved to an `Identity` (DID + WebID + pod-git URLs). Read-only today. |
| **Panel** | A `nostr_bbs_core::governance::PanelDefinition` — an agent's human-in-the-loop control panel (fields + actions + schema), rendered in ASCII by `panel_view`. |
| **ActionResponse** | The kit's `nostr_bbs_core::governance::ActionResponse` — the signed human decision returned for a Panel action. **Not yet produced** by the BBS (the M2 seam). |
| **DoorGame** | A self-contained interactive overlay launched by a `bbs:<name>` DOM event; outside the Leptos tree; auth-free. The UA 571-C sentry gun is the first. |
| **AsciiArt** | A server-rendered phosphor fragment (`<pre class="ascii-img">…<span class="pN">`) returned by the preview-/pod-worker `/ascii` route; the BBS never shows a raw `<img>`. |
| **PhosphorLevel** | A `pN` (p0..p7) cell in an AsciiArt fragment — a theme-agnostic intensity recoloured per active Theme via `color-mix`. Also the conceptual unit of the Theme palette. |

## 4. Key aggregates

### 4.1 `BbsState` — the Screen state-machine aggregate (`chrome.rs:13`)

The navigation aggregate root. All fields are `Copy` `RwSignal`s, so the whole
aggregate is `Copy` and threads through the view tree without cloning:

- `screen: Screen`, `selection: usize`, `theme: Theme`, `cmd_open: bool`,
  `cmd_text: String`, `board: Option<String>`.
- **Invariants enforced by its methods:** `go(screen)` (`:31`) resets `selection`,
  clears `board`, and closes the command line — a screen change always lands on a
  clean selection. `activate_menu` (`:51`) only acts on the Main Menu; `open_board`/
  `close_board` (`:60`/`:65`) manage the Message Base drill-down.
- **Transitions** are driven from exactly one place per input method: the global
  `keydown` handler `install_key_handler` (`:219`), the touch bridge
  (`index.html:97–164`), and command-line `apply` (`:40`). `nav_len` (`:210`) is the
  single definition of "how many selectable rows the active screen has."

### 4.2 `DoorGame` — the overlay aggregate (`index.html:170–331`)

A door game is an aggregate whose **entire lifecycle is self-contained**: lazy
`build()`, `open()` (boot sequence + sounds), per-tick firing simulation, and
`close()` (teardown + restore scroll). Its state object `{ rounds, temp, firing }`
(`index.html:305`) is private to the overlay and never leaves it. It depends on
**no kit crate and no BBS Rust type** — only on the `bbs:sentry` event and the
active `theme-*` class. This isolation is what makes it auth-optional (ADR-105 §2.2).

### 4.3 `RelayStore` — the read-projection aggregate (`relay.rs:17`)

Not a domain aggregate so much as a **read-model**: per-kind buckets (`profiles`,
`channels`, `posts`, `governance`) populated by `ingest` (`:43`) from verified
inbound events, capped and de-duplicated (`insert_event`, `:62`). Every screen
derives its view reactively from this store. It has **no write side** — the absence
of an `emit`/`publish` counterpart to `ingest` is precisely the read-only boundary.

## 5. Anti-corruption boundary

The BBS deliberately does **not** model Nostr events, governance, DIDs, or pod URLs
itself. It adapts the kit's canonical types at a thin boundary so the terminal UX
can never drift from the kit's schema:

- **Event schema → kit.** `relay.rs` uses `nostr_bbs_core::event::NostrEvent` and
  `verify_event_strict` (`:195`); it only *projects* events (e.g.
  `channel_name`/`channel_zone`/`post_root_channel`) — it never defines the event
  shape. Governance kinds are classified by `nostr_bbs_core::governance::is_governance_kind`
  (`:48`) and `GOVERNANCE_KIND_RANGE` (`:184`), not a local list.
- **Governance schema → kit.** Panels are `nostr_bbs_core::governance::PanelDefinition`
  (`agent.rs`, `screens.rs:17`), serialised/deserialised through the kit's serde
  representation so the ASCII render is wire-compatible with real governance events
  (`agent.rs:108` round-trips them). The BBS renders the schema; it does not own it.
- **Identity / pod URLs → kit.** `identity.rs` builds DIDs and WebID/pod-git URLs
  entirely via `nostr_bbs_core::{did_nostr_uri, well_known_path}` and
  `solid_pod_rs::webid::{webid_url, pod_git_clone_url}` (`:1–9`) — there is **no
  hand-rolled `did:`/pod URL formatting**. `Identity::derive` fails closed on a
  malformed pubkey (`:29`).
- **Zones → kit config.** `config.rs` parses zones into `nostr_bbs_config::schema::Zone`
  (`:14`, `parse_zones` at `:77`); the BBS reads `accent_hex`/`display_name`/banner
  but owns none of the zone model.

The boundary's job: the BBS may render the kit's domain in ASCII, but a change to
the kit's event/governance/DID/zone schema propagates through the shared crates, not
through a parallel BBS copy that could rot.

## 6. Where the signer seam enters (M2)

The model is read-only at exactly two points, and both are in the **Identity** and
**Boards/Governance** contexts:

1. **Identity (Viewer → Signer).** Today `config.rs` reads only the **public** key
   from the forum session (`FORUM_SESSION_KEY = "nostr_bbs_keys"`, `:136`;
   `pubkey_from_session` at `:144` extracts only `publicKey`). The Viewer is a
   read-only value object. The **M2 seam** (ADR-105 §2.3) adds a `sign()` capability
   onto the forum's same-origin session — turning the Viewer into a principal that
   can author events **without the BBS ever holding private-key material**.
2. **Relay (read-model → write-model).** `RelayStore` has `ingest` but no publish.
   The seam adds an outbound `EVENT` path to `relay.rs`, so the Boards/Posts context
   can emit kind-42/1111/7 and the Governance context can emit a signed
   `ActionResponse` for a Panel action (the inert buttons in `panel_view`,
   `screens.rs:360`, become real).

No other context changes: Door Games stay auth-free, Rendering/Theme is unaffected,
and the anti-corruption boundary (§5) is unchanged — the BBS still signs the kit's
event types via the forum's signer, never its own schema.
