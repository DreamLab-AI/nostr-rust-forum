# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project tracks its architecture decisions in [`docs/adr/`](docs/adr/).

## [Unreleased]

## [1.0.0-beta.5] — 2026-07-18

Workspace release: every crate changed since its last version stamp moves to
`1.0.0-beta.5` (ascii, auth-worker, bbs-client, config, core, forum-client,
mesh, pod-worker, preview-worker, relay-worker); `rate-limit`,
`search-worker`, `setup-skill` and `upstream-canary` are unchanged and keep
their prior versions.

### Added

- **Zone-bound one-shot BBS PWA (ADR-109).** A single-locked-zone member can
  install their zone as a mobile app: a gated "Install mobile app" Settings
  section (forum-client) takes explicit consent with a lost-phone warning and
  bakes the key on-device (non-extractable AES-256-GCM wrap in IndexedDB +
  BootProfile); the BBS ships a manifest + maskable icons + a network-first
  service worker, boots one-shot via `?pwa=1` pinned to the bound zone, and
  handles iOS home-screen storage isolation with a one-time first-launch
  rebind. Shared contract in `nostr-bbs-core::boot_profile`; feature is gated
  on `window.__ENV__.BBS_PWA_ENABLED` (default off). Design trio:
  `docs/prd/prd-zone-bound-bbs-pwa.md`,
  `docs/adr/ADR-109-zone-bound-bbs-pwa-install.md`,
  `docs/ddd/ddd-zone-bound-bbs-pwa.md`.
- **Quote-and-append topic replies** (forum-client). Every post in a topic
  carries a "Reply" that quotes that message and appends the reply at the
  bottom (flat, chronological, never nested); the card shows an inline quote
  and the quoted author is p-tagged. Threading stays correct by structure:
  the NIP-10 `reply` marker always targets the topic root, the quoted sibling
  rides a separate `quote` marker.
- **Per-zone auto-approval** (auth-worker + relay-worker + config). Zones gain
  an `auto_approve` flag; new joiners are additively granted an auto-approved
  zone's `required_cohorts` at username-claim time.

### Fixed

- **Avatar survives login** (forum-client): the auto-whitelist kind-0
  republish now consults the relay's existing profile and merges, instead of
  clobbering `picture`/`about`/`birthday` on every reconnect.
- **Media serves with its real MIME** (forum-client + pod-worker): uploads
  send the blob's type (extension fallback), and the pod-worker recovers
  `image/*` from the path for legacy `application/octet-stream` objects — so
  images render in `<img>` (nosniff) and reach the BBS ASCII transform.
- **Posted images no longer print their pod URL** (forum-client): embedded
  media URLs are stripped from the visible body; the embed carries a
  hover-revealed "open full" affordance instead.
- **BBS resolves author nyms** (bbs-client): board threads, chat, topic list,
  snippets and DM rows resolve kind-0 display names instead of raw truncated
  pubkeys.
- **Forum→BBS sash navigates** (forum-client): `rel="external"` + an explicit
  hard navigation so the Leptos router no longer intercepts the click into a
  404.
- **Photo upload 403** (forum-client): pod provisioning uses
  `POST /pods/{pubkey}/.provision` and the upload self-heals (provision +
  retry) on 403/404.
- **One-deep channel replies** (forum-client): a channel message that is
  itself a reply no longer offers a Reply affordance.
- **New-joiner signup race** (forum-client): kind-0 publish retries until the
  whitelist claim lands, and zone access refreshes after the claim; the forum
  service worker no longer intercepts `<base>/bbs/` navigations.


Soak-test fix sprint (2026-07-16) — 16 issues surfaced by a 10-persona browser
soak of `nostr-bbs-forum-client`; see the operator overlay's
`docs/sprint/soak-test-2026-07-16.md`. All changes are confined to
`nostr-bbs-forum-client`. Issue numbers below follow the in-code `#N` references.

### Fixed

- **Breadcrumb separators** unified to a styled `›` (was a bare `/`) across the
  Settings, Events, Glossary, Note and Pod-browser breadcrumbs, all now using
  the shared `.breadcrumb-separator` class.
- **Settings — Username section** no longer renders for accounts without a
  legacy handle. Onboarding captures a display name only, so the card is now
  reactive and appears solely to release a still-resolving legacy handle;
  everyone else manages their display name under Profile. (#6)
- **Settings — display-name length** is now stated honestly: a live `n/50`
  counter, helper copy, and an at-limit message, instead of clipping silently at
  50 characters. (#13)
- **Humanised error messages** for avatar/media upload, whitelist / zone-access
  lookup, and channel creation. The user sees a friendly, actionable message;
  the raw `JsValue` / fetch detail goes to the browser console rather than the
  UI. (#14/#16)
- **Avatar upload input-reset ordering** — the file `<input>` value is no longer
  cleared before the blob bytes are read (which invalidated the selected `File`
  in some browsers, surfacing `NotFoundError`). It is cleared only in early
  returns that never touch the blob and in the upload's terminal branch, still
  letting a re-select of the same file re-fire `change`. (#16)
- **Notifications — own join suppression**: never raise a "New member" alert for
  the signed-in user's own join. (#8)
- **Notifications — per-pubkey baseline**: the sync baseline and dedup set are
  now keyed per pubkey, so a recovery-key login (a different account on the same
  device) starts from a fresh `now()` floor and never inherits the previous
  user's history — the cause of the stale historical-join backlog. A one-time
  backlog snapshot records already-known members without notifying, while genuine
  post-baseline joins still notify (the dropped-join trap). (#10/#12/#15)
- **Notification drawer outside-click** is now a capture-phase document
  `pointerdown` listener instead of a full-viewport click-catcher `<div>`, which
  swallowed the first click on controls behind it — most visibly the header
  "Log Out" button. The underlying control now receives the same click. (#9)
- **nsec / local-key recovery login** rehydrates the account's kind-0 profile
  (display name + avatar) from the relay projection, so the header shows the real
  identity instead of a truncated pubkey until the user re-saves. Fire-and-forget,
  silent on failure, and never clobbers an in-session edit. (#11)
- **Forums welcome greeting** trims trailing whitespace and punctuation from the
  display name, so a name ending in a title suffix (e.g. "…, PhD,") no longer
  renders "Welcome, …,!".
- **Auto-whitelist for name-less users**: a brand-new user with no display name
  and no claimed handle now registers for auto-whitelist by publishing a minimal
  kind-0 — but only when the relay holds none, so an existing profile is never
  clobbered. Previously such a user could be authenticated yet permanently unable
  to post. (#5)

### Changed

- **Governance empty states** are now role-aware. Members see read-only "About
  governance" guidance; admins see the management-surface copy naming the
  Approve/Reject controls and a "Register an agent" affordance to get the first
  policy flowing.
- **Nav label** "Agents" renamed to "Governance" (desktop and mobile).
- **Empty zones** show admins a "Create a section" CTA that deep-links to the
  admin panel's Channels tab (`/admin?tab=channels`), where sections are actually
  created; members keep the informational copy and a link back to Forums.
- **Channel-creation pending state** now tracks the full async publish lifecycle
  (relay ack, rejection, or ~10 s timeout) via `AdminState.channel_creating`,
  with a one-shot guard so a late ack cannot overwrite a timeout error; the create
  button re-enables for retry.
- **Admin Settings "Default Zone"** options derive from the live `ZONE_CONFIG`
  rather than a hardcoded legacy zone list.

### Added

- **Zone-first landing and scoped navigation** ([ADR-107](docs/adr/ADR-107-zone-first-landing-and-scoped-navigation.md)):
  a member authorised for exactly one locked zone now lands on that zone instead
  of the generic forums index. The home zone is derived client-side from
  `ZONE_CONFIG × cohorts` via `Zone::is_member` (`home_zone_for`) — exactly one
  accessible locked zone, admins exempt, no hardcoded zone ids. The `/forums`
  index auto-forwards to the zone root with replace navigation (so "back" skips
  the bare index); the header + mobile nav anchor is re-labelled to the zone and
  points at the zone root; and the zone-page breadcrumb re-roots to
  `Home › {Zone}` (dropping the global "Forums" crumb). Multi-zone members and
  admins are unchanged, deep links and the `returnTo` flow (ADR-090) are
  untouched, and the feature is dormant when no `ZONE_CONFIG` locked zone matches
  the member's cohorts.
- **Admin panel deep-linking**: `/admin?tab=<slug>` opens the panel on a named
  tab (channels, users, pending, sections, settings, reports, audit, pods…).
- **`dev-auth` cargo feature** (off by default): pre-provisioned deterministic
  dev identities (admin / user / jarvis), a floating identity picker, a
  zone-access bypass, and a local jarvis DM echo-bot for offline UI testing
  without touching the relay whitelist. Not compiled into release builds.

BBS mobile-first redesign — "split the difference" (2026-07); see
[ADR-108](docs/adr/ADR-108-bbs-mobile-first-redesign.md) and the operator
overlay's `docs/sprint/bbs-redesign-2026-07.md`. Reimagines the retro BBS client
(`nostr-bbs-bbs-client`, served at `/community/bbs/`) after a live mobile UX
audit: the phosphor skin, ASCII image rendering, numbered menu and keyboard model
are kept, while the modem-era interaction grammar is replaced by the main forum's
proven patterns. Delivered in three tranches — **all shipped**: T1 (F1–F6),
T2 (F7, F10, F13–F15) and T3 (F8, F9, F11, F12). Feature-matched to the main
board and verified by mobile-emulated browser testing and an adversarial review
panel (which caught and fixed a cross-account DM leak before release).

### Added

- **BBS onboarding landing (F3)** — a logged-out newcomer now sees a
  plain-language "what is this / why join" hero with value-prop chips and three
  stacked ≥44 px CTAs (**Sign in** · **Create account** → `/community/` ·
  **Look around**) before the numbered menu, replacing the trope-soup landing
  that offered only a jargon menu and a buried `[0] Help`. The masthead is now a
  compact, config-driven `NODE_NAME` + `TAGLINE` text masthead
  (`window.__ENV__`) instead of box-glyph art, so it is legible at 360 px and
  carries operator branding without a fork. *(T1)*
- **BBS mobile sign-in sheet (F1/F2)** — the cramped single-line `.bbs-cmdline`
  sign-in row is rebuilt as a vertical stack of full-width, ≥44 px,
  nowrap-labelled options in priority order: extension (if a NIP-07 provider is
  present) → **Continue at `/community/`** (passkey/WebAuthn, session adopted
  back — the extension-free primary path) → paste nsec/hex → generate a throwaway
  key. The input gains an `id`/`name` for autofill. Fixes the broken 32 px
  buttons and the missing extension-free path on real iOS Safari / Android
  Chrome. *(T1)*
- **BBS zones-as-cards navigation (F4/F5)** — the flat, all-zones-at-once board
  list becomes a Zones → Boards → Threads → Thread drill-down: one accent card
  per configured zone, a left-side always-visible zone chip on board rows
  (replacing the clipped right-appended `@handle`), channel/profile names
  resolved before hex, a real tappable `← Back` control and a `Zone › Board`
  breadcrumb (replacing the dead `[ESC] back to boards` label), and top-anchored
  content with friendly empty states. Overflow drops from a measured 101–128 px
  to 0 px at 360/390. Depth is added via new `BbsState` signals, keeping the
  non-routed state machine (`leptos_router` deliberately not adopted). *(T1)*
- **BBS persistent bottom nav (F6)** — a skinned terminal bottom bar
  (Menu / Boards / DMs / Agents / You), auth-gated like the forum's, replaces the
  undocumented swipe-from-top return path (swipe kept as an accelerator). *(T1)*
- **BBS three-state status bar** — connected-but-unauthenticated now shows
  `◐ SIGN IN TO READ` (linking to the sign-in sheet) instead of an ambiguous
  `○ CONNECTING` that read as "node down". *(T1)*

### Changed

- **BBS hotkeys demoted to accelerators** — every hotkey now has a visible,
  tappable twin, and keyboard-centric in-content copy ("Keys: … ESC back",
  "Sign in ([9] Settings)") is reworded tap-first with the key hint as a
  parenthetical. The full keyboard model, four CRT themes and the UA 571-C sentry
  door game are retained unchanged. *(T1)*

### Fixed

- **BBS ASCII image render fallback (F10)** — a pod-hosted image whose direct
  `?format=ascii` fetch does not return an ASCII fragment (a local `solid-pod-rs`
  dev pod ignores the param and serves the raw image as
  `application/octet-stream`, failing the `text/html` gate; an owner-only `.acl`
  401s) no longer dead-ends at `[ image unavailable ]`. `AsciiImg` now tries an
  ordered candidate list — pod-direct first, then the preview-worker's `/ascii`
  route over the public pod URL — and injects the first `text/html` fragment,
  degrading to `[ image unavailable ]` only when every route fails. No raw
  `JsValue`, no WASM panic. *(T2)*

### Added (T2 / T3)

- **Threaded topics (F7)** — boards drill Zones → Boards → **Thread list**
  (root kind-42s with reply count + last activity) → **Thread view** (root +
  `e`-tagged replies, chronological); legacy unthreaded posts render as
  single-post threads. *(T2)*
- **In-composer image upload (F10)** — a `[ ▸ image ]` affordance validates
  (`is_accepted_image`, 5 MB cap) with friendly terminal errors, compresses
  client-side, uploads to the viewer's pod over **NIP-98 PUT**
  (`upload_to_pod_signer`), posts the URL, and renders it inline as phosphor
  ASCII. *(T2)*
- **Accessibility/density prefs (F13)** — Settings toggles for text size and
  reduced motion, persisted to `localStorage` and applied as root classes;
  reduced motion defaults to the OS `prefers-reduced-motion`. *(T2)*
- **nsec backup sheet (F14)** — a shown-once key backup (copy + written-it-down
  confirm, no-reset warning) after a throwaway key is generated and for any
  readable local key in Settings. *(T2)*
- **Profile detail (F15)** — member rows are tappable to a kind-0 profile panel
  (name / about / short-id / `did:nostr` WebID). *(T2)*
- **Encrypted DMs incl. Jarvis 1:1 (F8)** — a NIP-44/59 gift-wrapped DM screen
  (inbox → per-peer thread → composer) over a dedicated NIP-42-authenticated DM
  socket, with a one-tap "Message Jarvis" quick-start. Decrypted state is wiped
  on sign-out / account switch (app-root owner watcher). *(T3)*
- **Native passkey sign-in (F9)** — WebAuthn PRF → HKDF-derived Nostr key
  (byte-identical to the forum's derivation, so a BBS passkey resolves to the
  same identity as one made at `/community/`), adopted in-memory via the same
  install path as generate/paste; feature-detected and gracefully absent when
  unsupported. *(T3)*
- **Global search (F11)** — a phosphor search palette (Ctrl/Cmd+K accelerator +
  a `/search` command + a tappable affordance) over the search-worker, graceful
  when the worker is unreachable. *(T3)*
- **Notifications (F12)** — a bottom-bar unread badge for replies/mentions, with
  own-event suppression and a **per-pubkey first-seen baseline** so a fresh login
  never surfaces the historical backlog; visible items are scoped per pubkey so a
  new viewer on a shared device sees none of the prior owner's. *(T3)*

  T2/T3 close shared-crate reuse (`image_compress`, `pod_client`, `dm`,
  `search_client`, `auth/{passkey,webauthn}`) over the common `Signer` trait
  rather than new domain code.

## [1.0.0-beta.4] - 2026-07-08

### Changed

- **nostr-bbs-core** bumped to `1.0.0-beta.4` (did-doc canonicalisation gate,
  shared WAC/did:nostr policy from solid-pod-rs `0.5.0-alpha.4`). The other 13
  crates remain at `1.0.0-beta.3` per ADR-103 (only the changed crate bumps).
- **solid-pod-rs** dependency raised to `0.5.0-alpha.4`.

### Added

- **COM-13/F2** Agent disclosure badge — renders at all author sites; public
  `/api/agents/disclosure` endpoint for transparency.
- **F8** Admin Agents roster tab — wired to the nine `/api/governance/*`
  endpoints for operator-managed agent lifecycle.
- **F1** Member read-only view of agent roster.
- **COM-16/COM-17** Decision integrity and graduated escalation enforcement.
- **REC-6** Escalation-default projection for new operator deployments.
- **F6** Supersession authority aligned to canonical DDD §7a.
- **NIP-07** Browser-extension signing (PodKey/nos2x/Alby).
- Zone hero board grouping — boards interleaved under their zone hero banner.

### Fixed

- Closeout security audit remediation (shared WAC/did:nostr policy).
- DID-doc fixture converged to CID/v1 and ADR-125 canonical form.
- WoT registration gate fail-closed on settings-read D1 error.

## [ADR backfill] - 2026-06-11

### Added

- **ADR index / register** (`docs/adr/README.md`): canonical register of ADR-086
  onward, listing the three sprint-resident ADRs (090/091/092 under
  `docs/sprint/2026-05-17-ux-audit/`), noting ADR-102 as incoming (trust demotion),
  and recording the numbering-authority convention (sequential, unique, this dir
  canonical; ADRs 001–085 are the upstream/historical kit record, not filed here).
  Closes register gap **G6**.
- **ADR-100 — Key lifecycle** (`docs/adr/`): three-tier key model (root /
  purpose-subkey / device key); device keys absorb day-to-day exposure so root
  rotation stays a rare, identity-fatal last resort; compromise-response playbook
  by scope; ordering invariant **revoke → rotate → re-enrol**. Reconciles ADR-094's
  no-compromise-isolation disclaimer with ADR-099's `device_keys.revoked`.
- **ADR-101 — Multi-device NIP-17 DM delivery** (`docs/adr/`): the ADR-099 phase-2
  deferral. Our client multi-wraps each DM to the recipient's master **and** each
  registered non-revoked device key; graceful degradation when an outside client
  reaches only the master; relay admission unchanged (per ADR-104). Implementation
  deferred — `forum-client/src/dm/mod.rs` send-path expansion + auth-worker per-owner
  device lookup; relay untouched.
- **ADR-103 — Kit semver / publish / yank policy** (`docs/adr/`): defines
  API-breaking (removing any `pub` item — the `!` commits dropping `nip26`/`nip90`),
  `1.0.0-beta.N` line semantics (breaking bumps the beta counter, not major; betas
  don't auto-match), next publish is **1.0.0-beta.3**, yank-for-defect-only policy,
  and the SHA-pin downstream contract (downstream overlays pin by SHA). Codifies the R2/R4
  audit findings.
- **ADR-104 — NIP-59 gift-wrap recipient admission + relay gating** (`docs/adr/`):
  documents the implemented rule — the relay admits kind-1059 by **recipient `#p`
  whitelist membership**, never the ephemeral author, without decrypting. Privacy
  boundary (relay is a zero-knowledge router), device-key effective-pubkey
  attribution, and why DM `#p` is deliberately **not** rebound to the owner
  (`relay_do/nip_handlers.rs:649-657`). References `docs/diagrams/relay-event-admission.md`.

> ADR-102 (trust demotion, anomaly O1) is reserved and owned by concurrent
> `relay-worker/src/trust.rs` work; it lands with that change.

## [Upstream kit features] - 2026-06-11

### Added

- **ADR-094 — Deterministic purpose-scoped subkey derivation** (`nostr-bbs-core`):
  `derive_subkey(root, tag)` = HMAC-SHA-256(root_sk, tag) → validated secp256k1
  `SecretKey`. One canonical primitive (native + wasm bridge) for rotatable,
  recoverable, purpose-scoped child keys; byte-for-byte parity with agentbox's
  JS mirror derivation, pinned by a known-answer vector (root `0x01`×32 + tag
  `agentbox-mirror-v1` → `2d07f2ce…695d`). Domain separation, not compromise
  isolation — revocable delegation is provided by device keys (ADR-099);
  NIP-26 was evaluated and rejected.
- **ADR-095 — Recovery & device-onboarding sheet** (`nostr-bbs-forum-client`):
  a `RecoverySheet` Leptos component renders a 100% client-side printable
  one-page sheet at signup (nsec/npub/relay QRs + metadata + restore steps +
  optional relay "sweep" block), Save-as-PDF via `window.print()`. Additive to
  `NsecBackup`; insist-with-override exit gate; target mobile client is 0xchat
  (NIP-17/28/42). The nsec never leaves WASM; ncryptsec/NIP-49 deferred.
- **ADR-096 — ACL container resolution + per-container delegation**
  (`nostr-bbs-pod-worker`): `find_effective_acl` now probes the per-container
  sidecar `<dir>/.acl` at every walk-up level (with correct `inherited` flags),
  fixing the previously-unreachable container ACL. Adds `build_delegation_acl`
  and an opt-in `PUT {"@delegation":{agent,modes}}` to `<container>/.acl`;
  `acl:Control` is never delegated and owner Control is always preserved.
  Retires the flat-sidecar workaround (migration is non-breaking).
- **ADR-097 — Consolidated agent identity provisioning** (`nostr-bbs-auth-worker`):
  `POST /api/governance/agents/provision` (NIP-98 admin) performs the whitelist
  upsert + `agent_registry` upsert atomically in one D1 `batch()`, replacing the
  four-call seed dance. Idempotent on `pubkey`; `/register` and
  `/api/whitelist/add` unchanged. The agent's kind-0/NIP-65 stay client-side.

## [3.0.0-rc11] - 2026-05-17

### Added

- **Native pod support**: `[native_pod]` config section in nostr-bbs-config; when
  `native_pod.enabled = true`, pod browser shows a second "Native pod" card probing
  the native server URL. Available → GitPanel + AppManifestPanel. Probing/Unavailable
  states handled gracefully.
- **Admin: Native Pods tab**: provision a native pod for any user pubkey via the admin
  control panel. Calls CF auth-worker `POST /api/native-pod/provision` → forwards to
  native server `/_admin/provision/{pubkey}` with PSK header.
- `NATIVE_POD_URL` build-time env wires the forum client to the native server URL.

## [3.0.0-rc10] - 2026-05-17

### Added

- **Git control panel** (`components/git_panel.rs`): VS Code–style Source
  Control panel for in-pod git repositories. Staged/unstaged/untracked file
  sections with per-file stage, unstage, discard, and inline diff viewer
  (green/red syntax colouring). Commit textarea + button. Lazy-loaded commit
  history. Busy guard prevents concurrent mutations. Shows "Git API not
  available" gracefully on CF Workers (HTTP 404/501).
- **App manifest panel** (JSS #464): `AppManifestPanel` below the git card;
  GET/PUT `{pod}/apps/manifest.json` with NIP-98 auth. Enables pods as
  first-class app distribution repositories.
- **Auto-probe on pod mount**: `pod_browser` fires a one-shot `Effect::new`
  when `pod_base_url` and signer are ready. No manual "Check Git" button.
  `Available` → git card + panels; `Unavailable` → compact note; `Probing` →
  spinner. CF Workers settle immediately to `Unavailable`.
- **solid-pod-rs pinned to alpha.14** (`rev = "4ac7670"`): nine `/_git/*`
  REST endpoints, `/.well-known/apps` discovery, GAP-ANALYSIS E.1 SHIPPED.

### Fixed

- **JSS v0.0.197 pod HTTP parity for the Worker tier**: Solid-compatible CORS
  envelope, `WWW-Authenticate` on 401 responses, notification discovery via
  `Updates-Via`, and authenticated `POST /.pods` returning `{ name, webId,
  podUri }`.
- **Provisioned media containers**: new pods now include `media/` and
  `media/public/`, matching the forum-client image upload destination.
- **Pod browser TypeIndex link** now points at
  `/settings/publicTypeIndex.jsonld`, matching the provisioned Solid document.

## [3.0.0-rc7] -- 2026-05-12

Agent Control Surface Protocol: governance types, relay integration, REST API,
forum UI, and D1 migration. The forum becomes a universal human-in-the-loop
control plane for any agent system.

### Added

- **Agent Control Surface Protocol** (kinds 31400-31405). Six new parameterized
  replaceable event kinds for agent-published control panels: PanelDefinition,
  PanelState, ActionRequest, ActionResponse, PanelUpdate, PanelRetired. Agents
  declare interactive panels via nostr events; the forum renders them as
  decision surfaces; humans respond with cryptographically signed events.
- **`nostr_bbs_core::governance` module** (1003 LOC, 19 tests). Full domain
  model: `PanelDefinition`, `ActionRequest`/`ActionResponse`, `BrokerCase`
  aggregate root with `DecisionOrchestrator`, `RegisteredAgent` types,
  tag-extraction helpers, governance kind-range constants. Ported from
  VisionClaw ADR-041/057 with framework-agnostic design.
- **`governance_api.rs`** in auth-worker. Seven NIP-98-gated REST endpoints:
  `GET/POST /api/governance/agents{,/register,/revoke}`,
  `GET /api/governance/cases{,:id}`,
  `POST /api/governance/roles/grant`, `GET /api/governance/roles`.
  Admin-only registration/revocation/role-grant; authenticated read for all.
- **Agent registry gate in relay-worker**. Governance events (kinds 31400-31405)
  from agent pubkeys are validated against the `agent_registry` D1 table at
  relay ingress. Unregistered agents are rejected. `ActionResponse` (kind 31403)
  from humans passes through standard NIP-98 auth.
- **Action request projection to `broker_cases`**. Kind 31402 events are
  projected into the `broker_cases` D1 table for queryable governance inbox.
- **`0002_governance.sql` migration** for relay-worker. Creates four D1 tables:
  `agent_registry`, `broker_cases`, `broker_decisions`, `broker_roles` with
  appropriate indexes. Idempotent (IF NOT EXISTS).
- **Governance D1 tables in auth-worker schema**. Inline DDL in `schema.rs`
  mirrors the relay migration for the auth-worker's D1 database.
- **`GovernancePage`** in forum-client. Reactive dashboard at `/governance`
  showing active panels, pending actions, and registered agent count. Includes
  `PanelCard` (renders agent panel definitions with action buttons) and
  `ActionRow` (renders action requests with approve/reject signing via the
  user's nostr key).
- **`PanelRegistry` reactive store** in forum-client. Ingests governance events
  from the relay subscription, maintains `HashMap<d_tag, PanelEntry>` for panels
  and `Vec<ActionEntry>` for pending actions. Provided as Leptos context from
  `app.rs`.
- **Governance relay subscription** in `app.rs`. Subscribes to kinds 31400-31405
  and feeds events into `PanelRegistry`.
- **`AgentGovernance` service endpoint** in `did:nostr` Tier-3 DID documents.
  `nostr_bbs_core::did` now accepts a governance API URL and emits an
  `AgentGovernance` service endpoint in the DID document.
- **Navigation entry** for `/governance` in the forum client sidebar with
  dedicated icon.
- **Value assessment document**: `docs/sprint/enterprise-lift-value-assessment.md`
  covering the ADR, DDD domain model, MCP tool surface design, and cross-repo
  SSO alignment plan.
- **NIP-98 SSO parity report**: `docs/sprint/milestone-0-sso-parity.md`
  documenting the Schnorr pre-hashing mismatch between nostr-bbs-core and
  solid-pod-rs, with fix instructions.

### Changed

- **`nostr-bbs-core`** gains `governance` module (behind default feature).
  `BrokerCase` domain model with invariants: no self-review, append-only
  history, terminal state idempotency, provenance chain.
- **Relay-worker `handle_event`** extended with agent-kind routing block
  (same pattern as NIP-29 admin kinds) for governance event validation.
- **Auth-worker `lib.rs`** routes 7 new `/api/governance/*` paths.
- **Forum-client `app.rs`** provides `PanelRegistry` context and subscribes
  to governance events on relay connect.

## [Security Audit Sprint] - 2026-05-11

An ecosystem-wide security audit. 12 fixes applied to nostr-rust-forum
covering P0 critical, P1 high, P2 medium, and P3 housekeeping findings.

### Security

- **P0-01**: PRF salt is now server-derived in webauthn.rs, preventing
  client-controlled salt injection in passkey registration flows
- **P0-02**: Admin model checks both members and whitelist in relay auth.rs,
  closing a privilege-escalation path where non-whitelisted members could
  bypass admin gates
- **P0-03**: Replay DB binding corrected to REPLAY_DB in relay wrangler.toml;
  the previous binding name silently created a second empty D1 database,
  leaving the replay cache ineffective
- **R2-P0-01**: /pay/.cleanup endpoint now requires NIP-98 auth guard in
  payments.rs, preventing unauthenticated callers from triggering cleanup

### Fixed

- **P1-18**: Job settle/cancel operations are now atomic via
  UPDATE...WHERE in payments.rs, eliminating TOCTOU races between
  concurrent settle and cancel on the same job
- **P1-19**: Job IDs generated via CSPRNG (getrandom) in payments.rs,
  replacing the previous sequential/predictable scheme
- **P1-20**: Deterministic invite code fallback removed in invites.rs;
  all invite codes are now CSPRNG-generated with no weak fallback path
- **P2-01**: DID pubkey validated as 64-character lowercase hex in
  payments.rs, rejecting malformed did:nostr identifiers at the boundary
- **P2-02**: NIP-26 delegation handler returns 501 Not Implemented in
  delegation.rs instead of silently accepting unverified delegations
- **P2-03**: Admin cache uses 5-minute TTL in relay auth.rs, bounding
  stale-admin-list exposure after revocation
- **P3-02**: Job expiry column added to payments schema, with orphan
  recovery sweep and /pay/.cleanup endpoint for operator-initiated GC

### Removed

- **P3-01**: KvPaymentStore dead code removed from payments.rs; the KV
  backend was superseded by D1 but never cleaned up

## [3.0.0-rc6] -- 2026-05-11

Payments, security hardening, and upstream alignment.

### Added

- **HTTP 402 payments** (`/pay/` routes in pod-worker). Web Ledgers spec
  implementation: `.info`, `.balance`, `.deposit`, metered resource access,
  multi-chain TXO verification, `/.well-known/webledgers/webledgers.json`
  discovery. All identities are `did:nostr:<pubkey>` — users and agents
  are indistinguishable at the protocol level.
- **`Nip98Token.event_id`** field: canonical event ID (recomputed by
  `verify_event_strict`) carried through to replay caches. Eliminates the
  redundant `compute_event_id_from_header` re-parse.
- **Wrangler.toml KV bindings**: `ADMIN_KV`, `ADMIN_KV_RO`, `NIP98_REPLAY`
  provisioned across all 4 workers.
- **`PAY_ENABLED` / `PAY_COST_SATS`** env vars in pod-worker wrangler.toml.

### Fixed

- **NIP-98 URL matching** (JSS alignment): removed trailing-slash
  normalisation; exact match only, per JSS source of truth.
- **Quota overflow**: `check_quota` uses `checked_add()` to prevent
  arithmetic overflow on projected usage.
- **admins.rs KV cache write**: `.execute().await` was missing — the
  future was dropped without awaiting. Cache writes now persist.
- **Whitelist `update_cohorts`**: added 64-char hex validation on pubkey
  input (was only checking non-empty).
- **NIP-19 proptest relay generator**: simplified to avoid generating
  invalid IDN labels (`xn--` prefixes). All 13 proptests pass.

### Changed

- **solid-pod-rs**: upgraded to 0.4.0-alpha.7 (payments, LWS-CID, CID v1
  WebID terms, NIP-98 WebID elevation).
- **`d1_helpers`** extracted to `nostr-bbs-core` (shared by auth-worker
  and relay-worker). Gated on `cfg(target_arch = "wasm32")`.

## [3.0-rc1] -- 2026-05-07

Phase 2 kit-extraction import. Brings critical security fixes, the F26 upstream
canary crate, L1 reference-vector test scaffolds, and Phase-1 substrate scripts
across from the legacy operator fork (where
they were authored during the mega-sprint Phase 0 + Phase 1 windows).

### Fixed (Critical)

- **C1 -- NIP-44 v2 conversation-key interop bug** in `crates/nostr-core/src/nip44.rs`.
  The previous implementation chained `HKDF-Extract -> HKDF-Expand` and produced
  `HMAC(PRK, 0x01)` instead of the PRK itself, breaking interoperability with
  every reference NIP-44 v2 implementation. Replaced with direct
  `HMAC-SHA256(salt="nip44-v2", ikm=shared_x)`. Validated against
  `paulmillr/nip44` test vectors (`docs/specs/fixtures/nip44-v2.json` in
  VisionClaw monorepo). Refs: ADR-076 D5, mega-sprint Phase 0.

- **C5 -- NIP-42 AUTH challenge CSPRNG** in
  `crates/relay-worker/src/relay_do/session.rs`. Replaced
  `js_sys::Math::random()` (non-cryptographic PRNG) with `getrandom::getrandom`,
  which on the Cloudflare Workers runtime delegates to `crypto.getRandomValues`
  (a CSPRNG). Predictable challenges allow a network attacker to forge an AUTH
  response, so this is the entire security property of the handshake. Added
  `getrandom = { workspace = true }` to `crates/relay-worker/Cargo.toml`.
  Refs: ADR-082, mega-sprint Phase 0.

### Added

- **F26 -- `nostr-upstream-canary` crate** (`crates/nostr-upstream-canary/`).
  Smoke-tests the upstream `nostr` 0.44.2 crate (without `nostr-sdk`) on the
  forum's WASM/Cloudflare Workers build matrix. Three smokes: keypair
  round-trip, NIP-44 v2 conversation-key derivation against
  `paulmillr/nip44` vector 0, NIP-19 npub bech32 round-trip. PASS unblocks
  ADR-076 D5 module absorption (Shape A); FAIL records a Shape C
  patch-in-place fallback. Crate is `publish = false` and not linked into the
  forum binary. Refs: ADR-076 D5, PRD-009.

- **L1 -- reference-vector test scaffolds**
  (`crates/nostr-core/tests/upstream_vectors/`). Loader at `mod.rs` resolves
  fixtures from `tests/fixtures/` (or `VISIONCLAW_FIXTURE_ROOT` env var) and
  asserts metadata blocks. `all_fixtures.rs` wires one test per fixture across
  13 files: NIP-01/04/19/26/44-v2/59/98, BIP-340, RFC 8785, multibase, DID-Doc
  conformance, IS-envelope v1, mesh-federation. Tests skip cleanly when the
  fixture is absent so the bring-up window stays green. Run
  `scripts/sync-fixtures.sh` first to populate. Refs: ADR-082 D5.

- **Phase-1 substrate scripts**:
  - `scripts/sync-fixtures.sh` -- pulls cross-substrate fixtures from VisionClaw's
    `docs/specs/fixtures/` into `tests/fixtures/`, writes `CHECKSUM.txt` for CI
    drift detection. Supports `--verify` mode for CI gates and
    `VISIONCLAW_FIXTURES_PATH` for offline / local-monorepo dev.
  - `scripts/anti-drift-lint.sh` -- ADR-077 P3 anti-drift lint. Rejects
    Operator-specific Schnorr verification suite identifiers
    (`NostrSchnorrKey2024`, `SchnorrSecp256k1VerificationKey2022`/`2025`/`2026`)
    in favour of the canonical `SchnorrSecp256k1VerificationKey2019`. Rejects
    hand-rolled DID-Document emitters outside `crates/pod-worker/src/did.rs`
    and `crates/nostr-core/`. Exit non-zero on drift.

### Changed

- **`Cargo.toml` workspace members** -- added `crates/nostr-upstream-canary` so
  the canary participates in `cargo check --workspace` runs.

### Notes

- This release does **not** include the full Sprint v9-v11 feature set authored
  in the legacy fork (NIP-98 replay store, profiles backfill, username
  reservations, mesh service-list, Tailwind CDN replacement, etc.). Those land
  incrementally in Phase 3+.
- Crate renaming to a `nostr-bbs-*` prefix and the new `nostr-bbs-config`,
  `nostr-bbs-mesh`, `nostr-bbs-setup-skill` crates remain deferred.
- The `admin-cli` crate is operator-specific and stays in the legacy fork.

### Provenance

- Charter: RuVector key
  `project-state/mega-sprint-phase-2-kit-extraction-charter`.
- Final report: RuVector key
  `mega-sprint-2026-05-07/phase-2-kit-extraction-final-report`.
- Prior sprint reports: `mega-sprint-2026-05-07/phase-0-final-report`,
  `mega-sprint-2026-05-07/phase-1-final-report`.

## [2.0] -- 2026-04-06

Complete Rust rewrite (pre-existing kit baseline, see commit `ab4b403`).

[Unreleased]: https://github.com/DreamLab-AI/nostr-rust-forum/compare/v3.0.0-rc7...HEAD
[3.0.0-rc7]: https://github.com/DreamLab-AI/nostr-rust-forum/compare/v3.0.0-rc6...v3.0.0-rc7
[3.0.0-rc6]: https://github.com/DreamLab-AI/nostr-rust-forum/compare/v3.0-rc1...v3.0.0-rc6
[3.0-rc1]: https://github.com/DreamLab-AI/nostr-rust-forum/compare/v2.0...v3.0-rc1
[2.0]: https://github.com/DreamLab-AI/nostr-rust-forum/releases/tag/v2.0
