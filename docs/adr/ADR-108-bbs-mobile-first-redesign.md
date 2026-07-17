# ADR-108: BBS mobile-first redesign ("split the difference")

**Status:** Accepted (T1 shipped; T2/T3 in progress)
**Date:** 2026-07-17
**Decision Owners:** nostr-rust-forum maintainers (DreamLab AI)
**Related:** [ADR-105 BBS door-games and write-path](ADR-105-bbs-door-games-and-write-architecture.md), [ADR-107 Zone-first landing and scoped navigation](ADR-107-zone-first-landing-and-scoped-navigation.md), [ADR-090 Path discipline at the FORUM_BASE boundary](ADR-090-forum-base-path-discipline.md), [PRD BBS retro client](../prd/prd-bbs-retro-client.md), [DDD BBS bounded contexts](../ddd/ddd-bbs-bounded-contexts.md), authoritative spec: operator overlay [`docs/sprint/bbs-redesign-2026-07.md`](../../../docs/sprint/bbs-redesign-2026-07.md)

## Context

The retro BBS client (`nostr-bbs-bbs-client`, Rust/Leptos CSR, served at
`/community/bbs/`) is a strong *aesthetic* whose *interaction model* was copied
too literally from 1990s wildcat boards. A live mobile UX audit — 14 screenshots
at 390×844 and 360×640 under an iOS user-agent, with DOM/geometry/contrast
measurement, plus a direct source review and a feature-parity matrix against
`nostr-bbs-forum-client` — found the numbered MENU screen excellent on a phone,
but both the newcomer journey and the sign-in journey failing outright. Three
load-bearing failures anchor the redesign:

1. **Sign-in is structurally broken on mobile.** `sign_in_panel` packs the
   `key/` prompt, the nsec input, `[ sign in ]` and `[ generate ]` into a single
   `.bbs-cmdline` flex row where the input is `flex:1`. The input eats the width;
   the two action buttons squeeze to ~32 px and ~62 px and, inheriting
   `white-space:pre-wrap` from the panel, shatter their labels vertically. At
   360 px "generate" clips off-screen and `[ sign in ]` sits at 32 px — below the
   44 px touch minimum. This is the *primary* authentication surface.
2. **There is no extension-free mobile sign-in.** The extension CTA renders only
   when a `window.nostr` NIP-07 provider is present; on real iOS Safari and
   Android Chrome there is none, so the only remaining path is the broken nsec
   row. A first-time phone user has no working way in.
3. **Logged-out newcomers get trope-soup and zero onboarding.** The landing is a
   status line over a numbered `[1]`–`[0]` jargon menu. Every content screen is
   empty or locked when signed out — even the public Support/Introductions
   boards read "(no messages yet — or you lack read access to this zone)". The
   only explainer is buried behind `[0] Help`.

Supporting failures compound these: zone identity is right-appended as a clipped
`@handle` into a `white-space:pre` row (two "Fairfield Events" boards are
indistinguishable, measured overflow of 101–128 px); back-navigation from a board
is a non-tappable `[ESC] back to boards` label; friendly names degrade to raw hex;
roughly half of every content screen is blank because the panel bottom-anchors
its content; and DMs are advertised but "coming".

The baseline `/community/` forum is the explicit usability target: a plain-language
onboarding hero, Create-Account/Sign-In front and centre, a persistent bottom tab
bar, skip-to-content, and zero horizontal overflow. The operator brief is
unambiguous: *"Completely reimagine the /bbs rendering option making it far more
user friendly and conformant. The ideas are ok but the mapping to early-BBS tropes
has lost much of the intuitive usability of the rest of the forum. We can afford to
split the difference."*

This ADR records that split: which retro elements are load-bearing delight and stay,
and which modem-era interaction tropes are replaced by the forum's proven patterns.
The relay stays the security boundary (ADR-105 auth-optional surfaces, ADR-107 zone
read gate); nothing here moves enforcement client-side, and the change is confined to
`nostr-bbs-bbs-client` and shared kit crates — not the React overlay (`/community/bbs/`
boundary discipline, ADR-090).

## Decision 1 — Keep the phosphor skin; it earns its place

The retro *skin* is not the problem. Every element below reads as delightful, costs
the user nothing to learn, and is retained unchanged or enhanced:

- **Amber/green/purple/sky phosphor palette** with CRT scanlines, bloom and
  phosphor-ghost — a measured WCAG AA pass (10.8:1 status, 6.6:1 dim on `#0a0a0a`),
  the aesthetic differentiator, zero usability cost.
- **Monospace type + box-drawing headers** — terminal identity; alignment is
  intrinsic to the look.
- **ASCII image rendering** (`ascii_img.rs`, `AsciiImg`) — the signature delight
  feature: inbound images, pod files and banners render as phosphor ASCII,
  responsive-scrolled. It stays the read-path renderer untouched; the redesign only
  adds the *upload* half (F10).
- **The numbered main menu** — the audit's single strongest screen. It stays the
  "home" surface *and* a power-user accelerator.
- **The full keyboard model, four CRT themes, and the UA 571-C sentry Easter egg**
  (ADR-105 door games) — on-brand personality off the main path.

## Decision 2 — Replace the modem-era interaction grammar with the forum's proven patterns

Every trope a first-time phone user must *learn* before they can act is replaced by
the interaction pattern the main forum already proves. The retro look is preserved;
the navigation vocabulary becomes the forum's:

1. **Onboarding landing (logged-out).** A one-screen "what is this / why join" hero
   with plain-language value-prop chips and three first-class stacked CTAs —
   **Sign in**, **Create account** (→ `/community/`), and **Look around**
   (read-only menu) — shown *before* the numbered menu when signed out. Directly
   answers failure 3.
2. **Vertical, ≥44 px sign-in sheet with extension-free paths.** The cramped
   single-line command row is replaced by a `flex-direction:column` stack of
   full-width options, each a `min-height:44px; white-space:nowrap` target on its
   own line, in priority order: extension (only if a NIP-07 provider is present) →
   **Continue at `/community/`** (passkey/WebAuthn, same-origin, session adopted
   back via `adopt_forum_session()` — the extension-free primary path until native
   passkey lands) → paste nsec/hex on its own row with `[ sign in ]` below →
   generate a throwaway key with a shown-once backup. The input gains an `id`/`name`
   for autofill. Answers failures 1 and 2.
3. **Zones-as-cards drill-down: Zones → Boards → Threads → Thread.** The forum's
   mental model (Zone → Section → Topic → Thread) is mapped onto the kinds the BBS
   already streams, *without* porting the forum's four-table data model. The flat
   all-zones-at-once board list becomes one accent **card per configured zone**
   (`cfg.zones`), tapping a zone opens its **boards**, tapping a board opens its
   **thread list** (root kind-42 events), and tapping a thread opens the **thread
   view** (root + `e`-tagged replies + composer). Navigation depth is added by new
   `RwSignal` fields on `BbsState` (`zone`, `thread`), *not* by adopting a router
   (see Decision 3). The clipped right-appended `@handle` becomes a left-side accent
   chip that is always visible and never clipped; names resolve from kind-40/kind-0
   with hex only as a dim fallback.
4. **Tappable back + breadcrumbs.** The dim `[ESC] back to boards` label becomes a
   real `← Back` control, with a `Zone › Board` breadcrumb line at every depth.
   Content is top-anchored (relaxing the bottom-anchoring flex rule), the composer
   is pinned as a proper input bar, and empty states become friendly and actionable.
5. **Persistent bottom nav.** A skinned terminal bottom bar
   (Menu / Boards / DMs / Agents / You) is rendered on every screen, gated exactly
   like the forum's (`Show`-when-authed for DMs/You). It replaces the undocumented
   header-tap / swipe-from-top as the return path; swipe stays as an accelerator.
6. **Three-state status bar.** The `● ONLINE` / `○ CONNECTING` flip is really
   NIP-42 deny-by-default awaiting AUTH and reads as "node down". A third state is
   added: connected-but-unauthenticated shows `◐ SIGN IN TO READ`, linking to the
   sign-in sheet.
7. **Config-driven `NODE_NAME` + `TAGLINE` text masthead.** The box-glyph masthead
   art (dropped on mobile, non-brand-neutral, and prone to clipping) is replaced by
   a compact **text** masthead driven by `window.__ENV__.NODE_NAME` and
   `window.__ENV__.TAGLINE`. The kit ships brand-neutral defaults; the operator's
   name and one-line tagline come from the overlay branding config, so the masthead
   is legible at 360 px and carries operator identity without hardcoded art.

The unifying rule (Decision 4): every one of these is reachable by tap, and every
retained hotkey keeps a visible tappable twin.

## Decision 3 — Keep the navigation state machine; do not adopt `leptos_router`

Navigation depth (Zones → Boards → Threads → Thread) is added as new `RwSignal`
fields on `BbsState` with explicit `open_*`/`close_*` transitions, extending the
deliberately non-routed state machine. The BBS is not put behind `leptos_router`.

| Alternative | Verdict | Rationale |
|---|---|---|
| Adopt `leptos_router` for the new drill-down depth (mirror the forum client's routed pages) | Rejected | The BBS is deliberately a single-surface CSR state machine (no URL routes); its whole chrome — full-screen phosphor CRT, hotkey capture, swipe, the door-game overlays (ADR-105) — assumes one mounted view driven by signals. Bolting a router on to gain four depth levels would fork the client's core model, re-introduce the FORUM_BASE path-handling the forum client already owns (ADR-090), and buy nothing the state machine cannot: `back`, breadcrumbs and deep-state are all expressible as signal transitions. |
| Add depth via `RwSignal` fields on `BbsState` and explicit transitions | **Accepted** | Preserves the non-routed model, keeps hotkeys/swipe/overlays working unchanged, and localises the change to the state struct and the screen dispatch. Depth is a pure function of signals; back is a transition. |

## Decision 4 — Hotkeys stay as accelerators, never the only path

The entire keyboard model is retained (it already yields focus to inputs correctly),
but no hotkey is ever the *sole* affordance. **Every hotkey has a visible, tappable
twin**: number keys ↔ tappable menu rows; `ESC` back ↔ the `← Back` button and the
bottom-bar `≡ Menu`; `↑↓`/`jk` ↔ tap-to-select; `/` command line ↔ an optional `⌕`
affordance; `T` theme ↔ the Settings cycle control. Keyboard-centric in-content copy
("Keys: … ESC back · T theme", "Sign in ([9] Settings)") is reworded tap-first ("Tap
a board to open it", "Tap **Sign in** below"), with the key hint demoted to a
parenthetical.

## Tranche plan (F1–F15)

Effort scale: **S** ≤1 day · **M** 2–3 days · **L** 4–6 days. Ordered so the audit's
primary defect and the newcomer path land first (T1), then the "matters:yes"
parity gaps.

| # | Feature | Effort | Tranche |
|---|---|---|---|
| **F1** | Fix the sign-in flex row — stack controls vertically, ≥44 px, full-width, nowrap labels, input `id`/`name` | S | **T1** |
| **F2** | First-class extension-free sign-in — priority-ordered sign-in sheet; `/community/` passkey as the primary extension-free path via adopted session | S | **T1** |
| **F3** | Logged-out onboarding landing — explainer + value props + CTAs, shown before the menu; config-driven `NODE_NAME`/`TAGLINE` masthead | M | **T1** |
| **F4** | Zone visibility + board naming — zones-as-cards, left accent chip on board rows, name-not-hex, no clipping at 360/390 | M | **T1** |
| **F5** | Tappable back + breadcrumbs + top-anchored content — real `← Back`, breadcrumb line, friendly empty states | M | **T1** |
| **F6** | Persistent bottom nav — skinned terminal bottom bar (Menu/Boards/DMs/Agents/You), auth-gated like the forum's | M | **T1** |
| **F7** | Threaded topics — Board → thread list (root kind-42) → thread view (root + `e`-tagged replies); composer posts to a thread root | L | **T2** |
| **F10** | Image upload in composer — reuse `image_compress` + `pod_client` (PUT/NIP-98); post the URL, ASCII-preview inline | M | **T2** |
| **F13** | A11y / density prefs in Settings — text-size + reduced-motion toggle mirroring `preferences` | S | **T2** |
| **F14** | nsec backup / recovery sheet — QR + copy for a generated/adopted key | S | **T2** |
| **F15** | Profile detail — tap a member → bio/name/short-id panel (kind-0), no raster avatar (ASCII surface) | S | **T2** |
| **F8** | Encrypted DMs (incl. Jarvis 1:1) — wire a DM screen to the shared NIP-44/59 gift-wrap path; replace "DMs are coming" | L | **T3** |
| **F9** | Native passkey sign-in — reuse `auth/{passkey,webauthn}` so the BBS derives a key on-device without leaving to `/community/` | L | **T3** |
| **F11** | Global search (Cmd/Ctrl+K + tap) — surface `search-worker` via the shared search client; `/search` command + `⌕` affordance | M | **T3** |
| **F12** | Notifications (bell/badge) — mentions/replies count; a bottom-bar badge | M | **T3** |

**T1 = F1–F6** (the entire audit-critical newcomer + navigation fix, all S/M) ships
first and independently. **T2 = F7, F10, F13, F14, F15.** **T3 = F8, F9, F11, F12.**

Reuse is preferred over duplication throughout: image compression, pod upload
(PUT + NIP-98), encrypted DM, global search, the home-zone flag model (ADR-107),
passkey/WebAuthn, nsec backup, and the empty-state / bottom-nav patterns all already
exist in `nostr-bbs-forum-client` and take the shared `nostr_bbs_core::signer::Signer`
trait that `BbsSigner` already satisfies — so they are reusable without an auth
rewrite. Each is promoted into a shared kit crate and depended on from both clients
rather than copied.

**Explicitly out of scope** (parity-matrix `matters:no`, and correctly N/A for a
terminal): calendar/events/RSVP, bookmarks, emoji reactions, moderation
report/hide/mute, PWA/offline store, raster avatar upload, and member/registration
admin. Governance write is already at parity via the Agents screen; only
member/report admin stays deferred.

## Alternatives considered

| Alternative | Verdict | Rationale |
|---|---|---|
| **Full router adoption** — re-platform the BBS onto `leptos_router` to gain routed drill-down, mirroring the forum client | Rejected | The state machine is kept (Decision 3). Routing would fork the client's single-surface CSR model, break the hotkey/swipe/door-game assumptions, and re-open the FORUM_BASE path-handling the forum client already owns (ADR-090), for depth that signals already express. |
| **Pure trope preservation** — keep the modem-era grammar (numbered-only entry, single-line sign-in, `[ESC]`-only back, swipe-from-top return) and treat the audit failures as user education | Rejected | Directly contradicts the operator brief ("the mapping to early-BBS tropes has lost much of the intuitive usability… we can afford to split the difference") and leaves the three load-bearing failures — broken mobile sign-in, no extension-free path, zero onboarding — unfixed. The skin is delight; the grammar is a barrier. |

## What this ADR does not decide

- **The relay / write-path.** Auth-optional public surfaces and the M2 write-path are
  owned by ADR-105; this redesign consumes that write seam (composer posts, DM sends)
  and does not change it. The relay stays the security boundary.
- **Zone authoring and enforcement.** `[[zones]]`, `required_cohorts`, visibility and
  the read gate stay owned by the operator overlay and the relay (ADR-107). The BBS
  reads `ZONE_CONFIG` to *render* zones as cards; it never gates access.
- **Operator branding values.** `NODE_NAME`, `TAGLINE`, theme and banner are supplied
  by the overlay branding config via `window.__ENV__`; the kit only defines the
  brand-neutral defaults and the surfaces that consume them.

## Consequences

**Positive.** The BBS reaches **feature parity with the main forum** on every
"matters:yes" surface — a logged-out newcomer understands what the board is and how
to get in within one screen, signs in on mobile with or without an extension, drills
Zones → Boards → Threads → Thread with tappable back and breadcrumbs, and never sees
a clipped zone or a raw-hex board. **Every hotkey has a tappable twin**, so the
power-user keyboard model and the touch model coexist rather than compete. The kit
stays **brand-neutral**: the masthead, themes and taglines are config-driven, so an
operator supplies identity through `window.__ENV__` (`NODE_NAME`/`TAGLINE`) with no
fork of the client. Most parity gaps close by *reusing* shared kit crates over the
common `Signer` trait, not by writing new domain code.

**Neutral / unchanged.** The phosphor skin, ASCII renderer, numbered menu, keyboard
model, four themes and the sentry door game are retained as-is. The relay layer
(NIP-42 AUTH, `flat_zone_order`, `publish_with_ack`) and the read-path image surfacing
are untouched. The non-routed state machine is preserved (Decision 3), so the
door-game overlays and swipe accelerators keep working.

**Tradeoffs.** Navigation depth adds new `BbsState` signals and new screen states, so
the screen-dispatch and CSS grow (sign-in stack, zone cards, bottom nav, top-anchored
bodies, larger mobile status/footer type). The redesign is delivered across three
tranches rather than atomically: **T1 (F1–F6) has shipped**; **T2 and T3 are in
progress**, so the client transiently carries the parity gaps those tranches close
(threaded topics, image upload, DMs, native passkey, search, notifications) behind the
already-fixed newcomer and navigation core.

## Verification

The method mirrors the audit: mobile-emulated `browser-gpu` (chrome-devtools-mcp
sidecar) with an iOS/Android UA and touch, live a11y snapshots, DOM/geometry/contrast
measurement, console capture, and per-iteration screenshots at 390×844 and 360×640,
plus a desktop regression pass for the keyboard model. Native `cargo test` covers the
pure modules (`menu.rs`, `config.rs`, `theme.rs`, `pod.rs`, `screens.rs`). The
load-bearing invariants: `document.documentElement.scrollWidth === clientWidth` at
360 and 390 on every screen (today Boards fails by 101–128 px → must be 0); every
sign-in control ≥44 px tall/wide with an `id`/`name` input; a newcomer can sign in
with `window.nostr` removed; the logged-out landing explains the board and shows
Create/Sign-in above the fold without opening Help; both "Fairfield Events" boards are
distinguishable with the zone chip fully visible; `← Back` and the bottom-bar `≡ Menu`
return without a physical `ESC`; and the desktop hotkey regression stays green. T1
(F1–F6) has been exercised against this plan on `/community/bbs/`; T2/T3 acceptance is
gated on the same per-feature checklist in the operator overlay spec.
