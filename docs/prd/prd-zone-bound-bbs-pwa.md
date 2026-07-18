# PRD — Zone-bound one-shot BBS PWA ("install this zone as an app")

- **Status:** Draft (v1 spec — implementation not started)
- **Date:** 2026-07-18
- **Owners:** `nostr-bbs-forum-client` (owns the install entry point, consent, and
  the key bake) and `nostr-bbs-bbs-client` (owns the manifest, service worker,
  one-shot boot, zone pin, key adoption, and "Forget this device"), with a read
  seam onto `nostr-bbs-relay-worker` for the lost-phone alias/whitelist workflow.
- **Related:**
  [ADR-107 Zone-first landing and scoped navigation](../adr/ADR-107-zone-first-landing-and-scoped-navigation.md)
  (the home-zone predicate this feature gates on),
  [ADR-108 BBS mobile-first redesign](../adr/ADR-108-bbs-mobile-first-redesign.md)
  (the touch BBS this app installs),
  [ADR-099 Revocable device keys](../adr/ADR-099-revocable-device-keys.md)
  (the default-off, gated-feature precedent this follows),
  [ADR-094 Deterministic purpose-scoped subkey derivation](../adr/ADR-094-deterministic-subkey-derivation.md)
  and [ADR-100 Key lifecycle](../adr/ADR-100-key-lifecycle.md)
  (passkey-PRF identity derivation, key handling),
  [prd-bbs-retro-client](prd-bbs-retro-client.md) (the BBS this extends),
  [ddd-bbs-bounded-contexts](../ddd/ddd-bbs-bounded-contexts.md) (domain model).
  A companion ADR (`ADR-109-zone-bound-bbs-pwa-install.md`, next free number) and
  DDD note (`ddd/ddd-zone-bound-bbs-pwa.md`) record the decision and the
  bounded-context seams; this PRD is the authoritative product spec.

---

## 1. Problem statement

The forum's zone model (ADR-107) already recognises a common operator shape: a
community whose non-admin members are all authorised for **exactly one locked
zone**. For that member the whole product *is* one zone — one shelf with one
item. ADR-107 removed the redundant zone-index click on the web by resolving a
"home zone" and landing there. This PRD carries the same simplification onto the
**phone home screen**.

The target member uses the community almost entirely on mobile, has one place to
be, and re-authenticates on every visit — currently a sign-in ceremony (passkey
tap, or nsec paste, or a `/community/` session that may have lapsed) before they
reach the one board list they care about. There is no way to turn "my community"
into a single tap from the home screen that opens straight into their zone
already signed in.

The retro BBS at `/community/bbs/` (ADR-108) is the right surface to install:
it is a single-screen terminal SPA with no URL sub-routes, a self-contained
touch model, and its own `window.__ENV__` branding projection — a natural,
brandable app shell. Today it ships **no manifest and no service worker**
(`crates/nostr-bbs-bbs-client/index.html` has neither), so it is not installable
and cannot fire an install prompt.

This feature makes the single-locked-zone member able to **install their zone as
a standalone app** that boots one-shot into their zone's boards, already signed
in, with the security trade-off of on-device key persistence stated honestly and
gated behind explicit consent — and behind an operator flag, default off.

## 2. Persona

**"Sole-zone Sam" — a single-locked-zone member on mobile.**

- Authorised for exactly one locked zone (has the zone's `required_cohorts`,
  satisfies `Zone::is_member`). Not an admin. Not a member of any second locked
  zone. This is precisely `home_zone_for(...) == Some(zone)` — see §4.
- Signs in with a passkey (the common case; PRF-derived identity per ADR-094) or,
  on older accounts, an imported nsec / recovery key.
- Lives in the community from a phone. Opens it several times a day, briefly.
- Wants "my community" to be one tap from the home screen, opening into the one
  board list they use, with none of the sign-in ceremony and none of the
  zone-shelf scaffolding.
- Is not a security specialist and will not read a threat-model table — so the
  consent copy must be plain, short, and honest, and the operator flag must let a
  community that considers on-device key persistence unacceptable simply not
  offer it.

Explicitly **not** this persona, and must never see the feature: admins (home
zone is `None` by construction), multi-zone members (`None` — two or more locked
zones), and signed-out visitors.

## 3. Goals and non-goals

### 3.1 Goals

1. Offer an **"Install mobile app"** action, visible **only** to a signed-in
   single-locked-zone member (§4), that installs the BBS as a standalone app
   bound to that member's one zone.
2. **Bake the key** on consent: persist the member's secp256k1 secret durably in
   origin storage, wrapped by a non-extractable WebCrypto AES-GCM key held in
   IndexedDB, alongside a `BootProfile` record — so the installed app boots
   already signed in on platforms that share origin storage (§6, §7).
3. Make the BBS **installable** with a minimal, correct manifest and a
   network-first service worker scoped to `/community/bbs/`, without ever
   reintroducing the historic BBS cache-404 failure mode (§8).
4. **One-shot boot**: the installed app detects `?pwa=1` or a `BootProfile`,
   adopts the baked key, skips Landing and Main Menu, and lands pinned in the
   bound zone's Boards, with other zones hidden while in PWA mode (§9).
5. Handle **iOS storage isolation** honestly: a one-time first-launch rebind
   (passkey-PRF tap when the account has a passkey, else paste-recovery-key
   once), one-shot thereafter (§10).
6. State the **security trade-off** plainly at consent time (verbatim copy in
   §11.2) and provide a **"Forget this device"** action that unbakes locally.
7. Ship gated behind an operator flag `BBS_PWA_ENABLED` (default off — §14), so
   the feature is operator-generic and opt-in.
8. Keep **all feature code upstream** in the kit; the operator overlay carries
   only deploy wiring and the kit repin.

### 3.2 Non-goals (out of scope for v1)

- **Push notifications.** The manifest/SW exist only for installability; no
  `PushManager`, no notification permission prompt. (Deferred — §15.)
- **Multi-zone switching inside the app.** The installed app is bound to one
  zone; other zones are hidden. A multi-zone member never qualifies for the
  install in the first place.
- **Per-user or dynamic manifests.** One static manifest per deployment; the
  zone binding lives in the `BootProfile`/`?pwa=1`, not in a generated manifest.
- **QR / key-sync device transfer.** Moving the baked identity between devices is
  not a feature; a new device re-derives (passkey) or re-pastes (recovery key),
  or the lost-phone alias workflow (§12) applies.
- **Changing the security boundary.** Server-side cohort/zone enforcement at the
  relay (ADR-022) remains the *only* real access boundary. Nothing in this
  feature gates access client-side; the zone pin is a UX affordance, not a
  control.
- **Web-tab (non-installed) behaviour changes.** `/community/bbs/` opened in an
  ordinary browser tab behaves exactly as today unless `?pwa=1`/`BootProfile` is
  present; the feature is dormant otherwise.

## 4. The exactly-one-locked-zone gating rule

The install action is shown if and only if, for the signed-in member:

```
!is_admin  &&  home_zone().is_some()
```

This reuses the ADR-107 predicate verbatim — **no new access logic is written**:

- Pure derivation: `home_zone_for(zones, cohorts, is_admin) -> Option<Zone>` at
  `crates/nostr-bbs-forum-client/src/stores/zone_access.rs:112` (verified).
  Admin → `None` (`:113`). A zone qualifies only when it has non-empty
  `required_cohorts` **and** `Zone::is_member(cohorts)` is true
  (`:116-118`); exactly one match → `Some(zone)` (`:119-125`); zero or two or
  more → `None`.
- Reactive wrapper: `ZoneAccess::home_zone(&self) -> Option<Zone>` at
  `zone_access.rs:88` reads `loaded`/`is_admin`/`cohorts` unconditionally and
  returns `None` until the whitelist/access fetch has completed (`:94-96`), so
  the install action never flashes before access is known and re-hides reactively
  if access changes. Obtain via `use_zone_access()` (same store), identical to
  the nav-anchor consumer already in `app.rs`.
- `Zone::is_member` is the same membership predicate the tile renderer and the
  relay read gate use (`crates/nostr-bbs-forum-client/src/stores/zones.rs`), so
  the install offer can never diverge from what the member can actually enter.

**Consequences of reusing the predicate.** Admins never see the option (there is
no single home zone for an all-zones admin). Multi-zone members never see it. A
member whose second-zone access is later revoked, collapsing them to one zone,
becomes eligible with no code change. A renamed or reconfigured zone flows
through `ZONE_CONFIG` with no id hardcoded anywhere in this feature — the same
config-driven totality ADR-107 guarantees. When `ZONE_CONFIG` is absent the
predicate falls back to the legacy zone list and, for most operators, resolves to
`None`, so the feature is simply dormant rather than wrong.

The **bound zone** carried into the bake and the one-shot boot is exactly the
`Zone` returned by `home_zone()` at consent time — captured by id into the
`BootProfile` (§6.2), never re-derived on the phone from ambient state.

## 5. Entry point and placement

Per QUEEN decision 7, the entry point lives in the **forum client** (`/community/`),
which owns the signer, the session key, and the zone-access store. There is no
existing user-menu dropdown to nest into (`app.rs` renders a flat authed nav with
a non-clickable user chip and a `LogoutButton`, no menu). Settings is already the
home for device and account actions, so the install offer is a **new Settings
section**, gated exactly like the existing feature-gated sections:

- New section **"Install mobile app"** in `crates/nostr-bbs-forum-client/src/pages/settings.rs`,
  slotting after the ADR-099 **Devices** section and before **Account** — the same
  `<div class="glass-card p-6 space-y-4">` shell, `<h2>` with icon, divider, then
  content, matching the existing section pattern.
- Gated with `<Show when=move || show_install()>` where
  `show_install = move || !zone_access.is_admin.get() && zone_access.home_zone().is_some()`
  — mirroring the `device_keys_on` gate the Devices section already uses.
- The section shows: a one-line explanation naming the bound zone
  ("Install *<zone label>* as an app on this phone"), the consent block (§11),
  and a state-aware primary button ("Install app" / "Installed" / platform
  guidance). It never renders for an unqualified member because the `<Show>`
  predicate is false.

**Interaction sequencing note.** `beforeinstallprompt` only fires after the user
has interacted with the page at least once (even in a prior load). Reaching a
Settings section is itself an interaction, so by the time the member is looking at
the install section the gesture requirement is already satisfied; the captured
`beforeinstallprompt` event (§9.1) is available to the button handler.

## 6. The bake — what is persisted, and where

"Baking the key" persists the member's existing secp256k1 secret durably so the
installed app can sign without a fresh ceremony. It is **the same secret already
present** in the forum session (`SESSION_PRIVKEY_KEY = "nostr_bbs_sk"`,
`crates/nostr-bbs-forum-client/src/auth/session.rs`), read via the existing
`get_privkey_bytes()` accessor — the bake introduces no new way to obtain the
key, only a new way to store it.

NIP-07 (extension-signer) members have no readable key (`privkey: null`); for
them the bake is not offered — the install section shows a short note that the app
install needs a local key and is unavailable with an extension signer. (The
single-locked-zone predicate can still be true; the bake specifically cannot.)

### 6.1 Wrapped-secret record (defense-in-depth, honest threat model)

- Generate a **non-extractable** AES-GCM `CryptoKey` (`generateKey({name:"AES-GCM",
  length:256}, /*extractable*/ false, ["encrypt","decrypt"])`) and store the
  handle in IndexedDB via structured clone. `extractable: false` makes
  `exportKey()`/`wrapKey()` throw, so same-origin JS can never pull the raw AES
  bytes out of the handle.
- Encrypt the 32-byte secp256k1 secret with a fresh 96-bit IV; store
  `{ ciphertext, iv }` in IndexedDB alongside the key handle.
- Memory hygiene mirrors the existing `PrivkeyMem` discipline (zeroize-on-drop,
  `session.rs`): the plaintext secret exists only transiently during wrap and
  during each unwrap-then-adopt.

**What this buys, stated plainly (full matrix in §13):**

- **Genuine value:** defeats *passive* offline/backup forensic dumps. An
  extractor with no live JS gets AES-GCM ciphertext plus an opaque, engine-internal
  key record; turning that into the plaintext key requires re-running the origin's
  JS in a matching engine to trigger unwrap.
- **No value against:** same-origin XSS (can call `crypto.subtle.decrypt()` with
  the same handle the app uses) and unlocked-device access (attacker opens the
  installed app and simply *is* the user). Only CSP/Trusted Types/output-encoding
  reduce the XSS surface; only the OS lock screen addresses the unlocked phone.
  This is why consent (§11.2) says the unlocked-phone risk out loud, and why the
  feature is operator-gated.

**Hardening that ships alongside the bake (not a substitute for it):** the BBS
scope should serve a strict Content-Security-Policy and, where feasible, Trusted
Types, with rigorous output encoding in the client — WebCrypto explicitly does not
protect against XSS, so shrinking the XSS surface is the real mitigation for
attacker class 2.

### 6.2 BootProfile record

A small durable record in the same origin storage:

```
BootProfile {
  mode:       "zone-app",     // discriminant; future modes reserved
  zone:       <zone id>,      // the id from home_zone() at consent time
  created_at: <unix seconds>
}
```

The `BootProfile` is the boot discriminant read on the BBS side (§9). It carries
the **zone id**, not the zone object — the BBS resolves the id against its own
`ZONE_CONFIG` projection at boot, so a renamed/re-described zone still resolves.
`created_at` supports "Forget this device" confirmation copy and future audit.

Both records live in **origin storage** for the origin serving `/community/bbs/`
— on Android/desktop Chrome that is the same bucket the browser tab uses, so the
bake carries straight into the installed app; on iOS it is not (see §10).

## 7. Key adoption in the installed app

The BBS already adopts the forum's same-origin session key today —
`BbsSigner::adopt_forum_session()` reads `FORUM_PRIVKEY_KEY = "nostr_bbs_sk"`
(`crates/nostr-bbs-bbs-client/src/signer.rs`) and installs a signer if a local
key is present, else falls back through `choose_adoption()` (pure, unit-tested).
The baked path **extends this same seam**:

1. At boot, if a `BootProfile`/`?pwa=1` is present, attempt **baked-key
   adoption** first: read the wrapped-secret record and the non-extractable
   AES-GCM handle from IndexedDB, `decrypt()` to recover the 32-byte secret in
   memory, and install it via the existing signer install path (the same call
   `adopt_forum_session()` uses once it has key bytes).
2. If no baked record exists (fresh iOS install — §10), fall through to the
   first-launch rebind.
3. If neither yields a key, fall through to the existing sign-in panel (the app
   degrades to the ordinary BBS sign-in rather than failing).

The recovered secret is never re-persisted in plaintext; it lives only in the
signer's in-memory `StoredValue`, zeroized on "Forget this device" and on logout,
exactly as the existing key-handling paths do.

## 8. Installability: manifest and service worker

### 8.1 Manifest (`/community/bbs/manifest.webmanifest`)

Minimum installable set, plus the fields this feature specifically needs:

- `name`, `short_name` — operator-branded, projected from `window.__ENV__`
  (`NODE_NAME`/`FORUM_NAME`); "MINIMOONOIR" is one deployment's value, not baked in.
- `id: "/community/bbs/"` — **set explicitly.** `id` defaults to `start_url`, and
  because `start_url` carries `?pwa=1` the default would fork the installed app's
  identity across deploys. A stable `id` pins one app identity.
- `start_url: "/community/bbs/?pwa=1"` — the query string is the one-shot boot
  signal (§9). Honoured on Chrome/Edge and on iOS (Safari opens the manifest
  `start_url`, query string included, overriding the page ATHS was invoked from).
- `scope: "/community/bbs/"` — **must contain `start_url`.** If `start_url` is not
  a sub-path of `scope`, the browser silently derives scope from `start_url` and
  ignores the declared value; `/community/bbs/` contains `/community/bbs/?pwa=1`,
  so the relationship holds. Trailing slash required.
- `display: "standalone"` — the no-browser-chrome installed feel; required on both
  platforms.
- `icons`: `192×192` and `512×512` PNG with `purpose: "any"`, **plus a separate**
  `512×512` PNG with `purpose: "maskable"` — never `"any maskable"` on one file.
  Maskable artwork stays inside the safe zone (a centred circle at ~40% of the
  icon width, i.e. the central ~80% of the square kept clear of edge crop).
- `theme_color`, `background_color` — recommended for splash/OS-chrome tinting
  (projected from the BBS theme); not gating installability.

Manifest and icon files flow through the existing Trunk `copy-file`/`copy-dir`
`data-trunk` directives in `index.html` (same mechanism as the existing
`copy-dir` for `assets/sentry-sounds`), landing in `kit/dist/community/bbs/`; a
`<link rel="manifest" href="manifest.webmanifest">` tag is added to `index.html`.
No per-user templating is needed — the manifest is static; any branded strings
that must be operator-specific are handled the same way `window.__ENV__` already
is (a `sed` step in deploy, analogous to the existing `BBS_ENV` injection), only
if a value cannot be a build-time constant.

### 8.2 Service worker (`/community/bbs/sw.js`, network-first)

The SW exists for two reasons, both required:

1. **`beforeinstallprompt` prerequisite.** Since Chrome 108 (mobile) / 112
   (desktop) a fetch-handling SW is no longer required for *menu*-based install,
   but the `beforeinstallprompt` event that drives the custom "Install app" button
   still requires a registered SW **with a fetch handler**. Without it the button
   has no prompt to present. So the SW is a hard prerequisite, not only bug
   defense.
2. **Installability defense that cannot reproduce the cache-404 bug.** The forum
   SW deliberately **bypasses** `/bbs/` (`crates/nostr-bbs-forum-client/sw.js:85-87`
   — no `respondWith`, falls through to network) precisely because caching the BBS
   shell under the forum SW's key poisoned the offline shell and served the forum
   shell for `/bbs/` URLs → 404. The BBS's own SW must not recreate that.

Design rules for the BBS SW:

- Registered with **explicit `scope: "/community/bbs/"`**. SW scope resolution is
  "longest matching registered scope wins", so a `/community/bbs/`-scoped SW
  controls BBS fetches in preference to the forum's `/community/`-scoped SW. The
  script sits at `/community/bbs/sw.js`, whose directory is its default max scope,
  so no `Service-Worker-Allowed` header is needed.
- **Network-first for the navigation document**, with `cache: 'reload'`-style
  conditional revalidation so a stale HTTP-cached `index.html` can never re-pin an
  old build (the same crux the forum SW fixes). It must **never** serve a cached
  app shell that can outlive a deploy — the app shell is always revalidated
  against origin. An offline fallback, if any, is a static "you are offline"
  response, never a stale shell that could 404 against a moved bundle.
- The SW is **build-stamped** (a `BUILD_TOKEN`/`__SW_BUILD__` analogous to the
  forum SW, stamped in deploy) so each deploy invalidates the prior SW cleanly.
- It caches nothing that the one-shot boot depends on for correctness; boot state
  lives in origin storage / the `BootProfile`, not in SW cache.

Because only the BBS scope carries a manifest+SW pair aimed at
`beforeinstallprompt`, the documented sibling-PWA gotchas (link capture between an
installed outer scope and an inner scope, duplicate prompts) do not arise — the
parent `/community/` forum is not itself pursuing installability.

## 9. One-shot boot into the pinned zone

The BBS boot today computes `initial_screen` in `crates/nostr-bbs-bbs-client/src/app.rs:30`
(`MainMenu` if a session was adopted, else `Landing`). PWA boot inserts ahead of
that decision:

1. **Detect PWA mode.** Read `?pwa=1` from the launch URL (the manifest
   `start_url`) or a persisted `BootProfile` (§6.2). Either present ⇒ PWA mode.
   Parsing lives alongside the existing `window.__ENV__` parsing in
   `src/config.rs`.
2. **Adopt the baked key** (§7). On success the signer has the member's identity
   with no ceremony.
3. **Resolve the bound zone** from `BootProfile.zone` against the BBS's
   `ZONE_CONFIG` projection.
4. **Skip Landing and Main Menu**; set `initial_screen` straight to Boards for the
   bound zone. `BbsState` (`src/chrome.rs`) gains a pin — a `pwa_mode: bool` plus
   the existing `zone: RwSignal<Option<usize>>` set to the bound zone index — and
   the navigation methods (`go`/`open_zone`/`close_zone`) honour the pin: while
   pinned, the zones list (`zones_screen`) and the "← Zones" back-crumb are hidden,
   and the home-gesture / ESC path returns to the bound zone's Boards rather than
   Main Menu.
5. **Other zones hidden while in PWA mode.** This is presentation only. Server-side
   cohort enforcement at the relay remains the real boundary (ADR-022); the pin
   never grants or withholds access, it only removes navigation the member does not
   need. A member who somehow reaches another zone's data is still gated by the
   relay exactly as in the web app.

If PWA mode is detected but no key can be adopted (fresh iOS install), boot
diverts to the first-launch rebind (§10) before landing in Boards.

### 9.1 Android / desktop Chrome install flow (`beforeinstallprompt`)

Origin storage is shared between the browser tab and the installed app, so the
bake done at `/community/` carries straight into the installed BBS with no rebind:

1. Member opens Settings → **Install mobile app** (qualified per §4). The forum
   page has captured the `beforeinstallprompt` event (fired because the member has
   interacted with the page).
2. Member reads the consent block and ticks the checkbox (§11). "Install app"
   enables.
3. On tap: perform the **bake** (§6) at the shared origin, then call
   `prompt()` on the captured `beforeinstallprompt` event. The OS install dialog
   appears; on accept the app is added to the home screen / launcher.
4. Launching the installed app hits `start_url = /community/bbs/?pwa=1`. The BBS
   boots one-shot (§9), reads the baked key from shared origin storage, and lands
   pinned in the bound zone's Boards, already signed in.

If `beforeinstallprompt` is unavailable (already installed, or an engine that does
not fire it), the section shows the platform's manual add-to-home-screen guidance
instead of a dead button, and still performs the bake so the eventual installed
launch boots one-shot.

## 10. iOS Safari flow and the one-time first-launch rebind

iOS is the honest special case. Web Storage (localStorage/sessionStorage),
cookies, and IndexedDB for a Home Screen web app are **isolated** from Safari's
storage, and each Add-to-Home-Screen instance gets its own bucket. So the bake
performed in Safari at `/community/bbs/` **cannot** be read by the installed app —
by platform design, permanently, not as a legacy quirk. The design accepts this
and does a one-time rebind:

1. **Add to Home Screen.** The Settings section shows iOS-specific guidance (Share
   → Add to Home Screen). Because a manifest is present, iOS launches the
   manifest's `start_url` (`?pwa=1`), not the page ATHS was invoked from. (As of
   current iOS, ATHS opens standalone by default even without a manifest; shipping
   the manifest keeps `start_url` and identity deterministic.)
2. **First launch → rebind.** The installed app boots into PWA mode, finds **no**
   baked record in its isolated storage, and runs a one-time rebind:
   - **Passkey branch (account has a passkey):** call `passkey_authenticate(pubkey)`
     (`crates/nostr-bbs-bbs-client/src/passkey.rs`) — a single biometric/PRF tap
     that **re-derives the same secp256k1 identity** (HKDF-SHA-256 over the PRF
     output, `nostr_bbs_core::derive_from_prf`; deterministic, unit-proven). No
     secret crosses the Safari↔app boundary; it is recomputed. Passkeys live in
     iCloud Keychain (OS-level), unaffected by Web Storage isolation, so the Safari
     passkey for the same RP ID is usable by the installed app. iOS 17.4+ dropped
     the mandatory user-gesture requirement for WebAuthn (rate-limited instead), so
     the tap is a clean first-launch prompt.
   - **Paste branch (no passkey):** prompt for the recovery key / nsec **once**.
   - The rebind's recovered key is then **baked into the app's own isolated
     storage** (§6) so every subsequent launch is one-shot, exactly like
     Android/desktop after install.
3. **One-shot thereafter.** Second and later launches read the app-local baked key
   and land pinned in Boards with no tap.

The passkey rebind is a convenience for the *legitimate* user's isolated-storage
instance — it is **not** device-loss protection: anyone who can unlock the phone
and pass the biometric derives the same identity. Device loss is handled by the
operator alias/whitelist workflow (§12), not by the rebind.

There is no EU-specific gating. The iOS 17.4 Home Screen web-app removal shipped
only in early betas, was reversed, and full support was restored in the iOS 17.4
final release (March 2024) and has continued since; 2026 blog posts claiming EU
PWAs remain broken are stale. No DMA branch is written into this feature.

## 11. Consent

### 11.1 Consent gate (behaviour)

- The "Install app" / "Add to Home Screen" primary control is **disabled** until
  the member ticks an explicit consent checkbox.
- The consent block is shown in the forum Settings section (§5), before any bake
  occurs. No key is ever persisted without the ticked checkbox.
- The consent copy is presented verbatim (§11.2). It is not summarised, truncated,
  or softened by the implementation.

### 11.2 Consent copy (verbatim — do not alter)

> This saves your key on this phone so the app can sign you in without a password.
> Anyone who unlocks this phone can read your zone and post as you. If your phone
> is lost or stolen, tell an admin at once to rotate your key. 'Forget this
> device' removes the saved key from this phone only — it does not protect a phone
> already in someone else's hands.

(UK English, 68 words. It names the unlocked-phone risk and the admin-rotation
lost-phone path directly, with no hedging, matching the honest threat model in
§13.)

### 11.3 "Forget this device" (unbake)

Owned by the **BBS client** (QUEEN decision 6), placed in the BBS Settings screen
(`crates/nostr-bbs-bbs-client/src/screens.rs`, alongside the existing sign-out /
back-up-key pair in `sign_in_panel`):

- Deletes the wrapped-secret record, the non-extractable AES-GCM key handle, and
  the `BootProfile` from origin storage.
- Zeroizes the in-memory signer key (same discipline as logout).
- Returns the app to the ordinary BBS sign-in state; a subsequent launch is no
  longer one-shot (it will offer rebind/sign-in).
- The confirmation copy restates that Forget removes the key **from this phone
  only** and does not protect a phone already in someone else's hands, and — if the
  device may be compromised — points the member to tell an admin to rotate
  (§12). `BootProfile.created_at` is surfaced ("saved on <date>") so the member
  can recognise a stale bake.

## 12. Lost-phone operator workflow (relay-side alias + whitelist removal)

A Nostr key cannot be cryptographically rotated in place — the key **is** the
identity, so no admin can re-sign the lost key's past events. The relay worker
already ships the realistic equivalent, and this PRD depends on it rather than
inventing anything:

1. The member mints a **fresh keypair** on a device they still control (generate,
   or `passkey_register` if they still hold the passkey/security key).
2. An admin calls **`POST /api/admin/alias`**
   (`crates/nostr-bbs-relay-worker/src/user_admin.rs:527`) with
   `{ old_pubkey: <lost>, new_pubkey: <fresh>, inherit_cohorts: true }`. This links
   old→new (UPSERT on `new_pubkey`) and copies the lost key's cohorts onto the new
   key's whitelist row, carrying zone access forward and preserving display
   attribution. Audit-logged `pubkey_alias_set`.
3. An admin calls **`POST /api/admin/user/delete`**
   (`user_admin.rs:151`) with `{ pubkey: <lost> }`, which removes the compromised
   key from `whitelist` — the actual relay-access revocation (cuts connect/post
   immediately) — and cascades a delete of the now-dangling `pubkey_aliases` rows
   referencing it. Refuses to delete the last admin. Audit-logged.

All three routes are live and wired (`crates/nostr-bbs-relay-worker/src/lib.rs`
delete/aliases-list/alias-set), so this is an existing capability the consent copy
and "Forget this device" guidance can point at truthfully. The passkey ceremony
is **not** a substitute here — it deterministically regenerates the *same* lost
identity, so it does not revoke a compromised device.

## 13. Threat model (stated honestly)

| # | Attacker class | Outcome | Mitigation in this design |
|---|----------------|---------|---------------------------|
| 1 | Remote, no code execution on the device | Cannot read the key; sees only AES-GCM ciphertext + an opaque `CryptoKey` record | Baseline non-extractable AES-GCM wrap in IndexedDB — works as designed |
| 2 | Same-origin XSS | **Full compromise** — injected JS calls `crypto.subtle.decrypt()` with the same handle the app uses, exfiltrates the secret or signs arbitrary events | **Not** mitigated by baking. Only strict CSP / Trusted Types / output encoding shrink the XSS surface. Stated plainly; never implied as protected |
| 3 | Unlocked phone (theft, borrowed, shoulder access) — attacker opens the installed app | **Full compromise** — reads the zone, posts as the member | **Not** mitigated by baking. The OS lock screen is the only barrier. "Forget this device" helps only after the fact and only if the attacker has not acted first. Consent copy says this out loud |
| 4 | Device backup / cloud sync / offline forensic dump (no live JS) | Attacker obtains ciphertext + opaque key handle only; must re-run origin JS in a matching engine to unwrap | **Meaningfully raised bar — the pattern's genuine value** |
| 5 | Malicious / compromised browser extension injecting same-origin script | Same as class 2 | Not mitigated; out of scope for BBS code — minimise extension surface |
| 6 | Forensic examiner with live browser/heap attach | Captures plaintext key at the moment of unwrap | Not mitigated; there is no hardware enclave in this design |
| 7 | Lost/stolen **locked** phone, attacker cannot unlock | No direct read, but risk persists until revoked | Operator alias + whitelist removal (§12) — carries access to a new key and cuts the old key's relay access immediately |

The design's defensible claim is exactly class 4 (and class 1). It makes **no**
claim against classes 2, 3, 5, 6. This honesty is the reason for the explicit
consent, the operator flag, and the alias/whitelist recovery path.

## 14. Rollout — operator flag `BBS_PWA_ENABLED`

The feature is gated by a single operator flag, projected into `window.__ENV__`
for the BBS the same way branding already is, and read by the forum client for the
Settings gate and by the BBS for boot:

- **Flag:** `BBS_PWA_ENABLED` (boolean-ish string in `window.__ENV__`, matching the
  existing `window.__ENV__` string convention; parsed in `config.rs` on the BBS
  side and read by the forum client's zone-access/settings layer).
- **Projection:** authored in the operator overlay's branding/config projection and
  injected in the deploy `BBS_ENV` script (the same `sed`-before-`</head>` step that
  already injects `THEME`/`RELAY_URL`/`ZONE_CONFIG`), plus surfaced to the forum
  client so the Settings section can gate on it. No new overlay wiring beyond one
  env value and (if a branded manifest string cannot be a build constant) one
  manifest `sed` step.
- **Default: OFF.** Justification:
  1. **Security-adjacent key persistence is an operator policy choice.** This
     feature durably persists a private key on a member's phone with a threat
     model that offers no protection against unlocked-device or XSS access. An
     operator must consciously accept that trade-off for their community rather than
     inherit it. This is the same posture as the closest precedent, ADR-099
     revocable device keys, which ships **gated and default-off**
     (`DEVICE_KEYS_ENABLED`).
  2. **Greenfield v1.** A grep across the kit for `BootProfile` / `zone-app` /
     `bake_key` / `manifest.webmanifest` returns zero hits — nothing pre-exists.
     Shipping a brand-new key-persistence surface enabled-by-default would change
     behaviour for every operator on the next kit repin, including operators for
     whom on-device key storage is unacceptable.
  3. **Operator-generic.** Some operators are multi-zone (the feature is inert for
     their members anyway) or explicitly do not want home-screen key baking;
     default-off means the kit ships the capability without imposing it.
- **Fully dormant when off:** no Settings section renders, no manifest/SW is
  advertised for install intent (the SW may still be registered harmlessly, but the
  install entry point and bake never appear), and `?pwa=1` on a flag-off deploy
  boots the ordinary BBS (no pin, no baked adoption). When off the feature adds no
  member-visible surface.
- **Enabling** is a per-deploy operator decision: set `BBS_PWA_ENABLED=true` in the
  overlay projection and repin the kit. The **dual-pin rule** applies — the kit ref
  moves in all four pinned places together (`deploy.yml`, `workers-deploy.yml`,
  `rust-ci.yml`, and the `nostr-bbs-*` `rev=` pins in `forum-config/Cargo.toml` /
  `Cargo.lock`).

## 15. Acceptance criteria (testable)

Gating and visibility:

1. For a signed-in member with `is_admin == false` and `home_zone().is_some()`
   **and** `BBS_PWA_ENABLED` true, the "Install mobile app" Settings section
   renders. (Unit: the `home_zone_for` predicate at `zone_access.rs:112` returns
   `Some` for exactly-one-locked-zone inputs and `None` for admin / zero /
   two-or-more — extend the existing `zone_access.rs` test module.)
2. For an admin, the section never renders (predicate `None`).
3. For a member of two or more locked zones, the section never renders.
4. With `BBS_PWA_ENABLED` false, the section never renders and `?pwa=1` boots the
   ordinary BBS (no pin, no baked adoption).
5. For a NIP-07 (extension-signer) member, the bake is not offered; the section
   shows the "needs a local key" note instead of an enabled Install button.

Consent and bake:

6. "Install app" / "Add to Home Screen" is disabled until the consent checkbox is
   ticked; no `BootProfile` or wrapped-secret record is written before the tick.
7. The rendered consent text equals the §11.2 copy byte-for-byte.
8. After bake, IndexedDB holds (a) a wrapped-secret record `{ ciphertext, iv }`
   and (b) an AES-GCM `CryptoKey` for which `exportKey()` and `wrapKey()` reject
   (non-extractable), plus a `BootProfile { mode:"zone-app", zone:<id>, created_at }`.
9. The baked `zone` id equals the id of `home_zone()` at consent time.

Installability:

10. The BBS serves `manifest.webmanifest` with `id:"/community/bbs/"`,
    `start_url:"/community/bbs/?pwa=1"`, `scope:"/community/bbs/"` (start_url is a
    sub-path of scope), `display:"standalone"`, and icons `192` + `512` (`any`)
    plus a separate `512` (`maskable`).
11. A network-first SW is registered with `scope:"/community/bbs/"`; the forum SW's
    `/bbs/` bypass (`sw.js:85-87`) remains intact, and the BBS SW never serves a
    cached app shell that survives a deploy (a moved bundle after redeploy never
    yields a 404 from a stale cached shell — the historic bug does not recur).
12. On a Chromium engine, with the SW registered and after a page interaction,
    `beforeinstallprompt` fires and its `prompt()` is invocable from the Install
    button handler.

One-shot boot and pin:

13. Launching `start_url` on a shared-origin platform (Android/desktop Chrome)
    with a bake present: the BBS skips Landing and Main Menu and lands in the bound
    zone's Boards, signed in (signer has the member's pubkey), with no sign-in tap.
14. While in PWA mode the zones list and the "← Zones" back-crumb are not shown,
    and the home-gesture/ESC path returns to the bound zone's Boards, not Main Menu.
15. The `choose_adoption`/boot-mode selection is covered by a pure unit test in the
    BBS lib (the crate has a `[lib]` target; runs under `cargo test -p
    nostr-bbs-bbs-client`): `{?pwa=1 present, BootProfile present, baked key
    present}` combinations select the correct boot path.

iOS rebind:

16. On a first launch with **no** baked record (simulating iOS isolated storage),
    PWA mode diverts to the rebind: passkey branch when the account has a passkey
    (single `passkey_authenticate` tap re-derives the same pubkey — assert derived
    pubkey equals the account pubkey), else the one-time paste branch; after rebind
    the key is baked into app-local storage and the next launch is one-shot.

Forget this device:

17. "Forget this device" (BBS Settings) deletes the wrapped-secret record, the
    AES-GCM key handle, and the `BootProfile`, zeroizes the in-memory signer key,
    and a subsequent launch is no longer one-shot.

CI:

18. New bake/adopt/boot-selection unit tests run in the kit workspace advisory
    suite (`cargo test --workspace`); the crypto-adjacent wrap/unwrap and
    boot-selection logic is a candidate for promotion into the `test-security`
    hard-gate job (which does not currently include forum-client/bbs-client).

## 16. Deferred to v2

- **Push notifications** — `PushManager` becomes available in an iOS Home Screen
  app's SW only after ATHS with `display: standalone`; the plumbing exists but push
  UX, permission prompts, and delivery are out of scope for v1.
- **Multi-zone switching inside the installed app** — a bound-zone app only. A
  future mode could let a genuine multi-zone member install a zone switcher.
- **Per-user / dynamic manifests** — one static manifest per deployment in v1.
- **QR / key-sync device transfer** — moving a baked identity between devices;
  v1 uses re-derive (passkey) / re-paste (recovery) / operator alias instead.
- **Hardware-backed key storage** — no Secure Enclave/TPM binding in v1; the wrap
  is an API constraint, not a hardware boundary. A future design could bind the
  AES-GCM key to a platform authenticator.
- **Auto-repin / self-heal of a stale bake** across kit deploys beyond the SW
  build-stamp invalidation already specified.

## 17. Ownership and placement summary

| Concern | Crate / file | Owner |
|---------|--------------|-------|
| Gating predicate (reused) | `forum-client/src/stores/zone_access.rs:112,88` | ADR-107 (reuse) |
| Install Settings section, consent, bake | `forum-client/src/pages/settings.rs` (new section), key access via `forum-client/src/auth/*` | forum-client |
| `beforeinstallprompt` capture + `prompt()` | `forum-client` (install section handler) | forum-client |
| Manifest + icons + SW + `<link rel=manifest>` | `bbs-client/index.html`, `bbs-client/manifest.webmanifest`, `bbs-client/sw.js` | bbs-client |
| `?pwa=1` / `BootProfile` parse | `bbs-client/src/config.rs` | bbs-client |
| Baked-key adoption at boot | `bbs-client/src/signer.rs` (extends `adopt_forum_session`) | bbs-client |
| One-shot boot + zone pin | `bbs-client/src/app.rs`, `src/chrome.rs`, `src/screens.rs` | bbs-client |
| "Forget this device" | `bbs-client/src/screens.rs` (BBS Settings) | bbs-client |
| Lost-phone alias/whitelist (existing) | `relay-worker/src/user_admin.rs`, `lib.rs` | relay-worker (reuse) |
| Deploy wiring: `BBS_PWA_ENABLED`, manifest/icons/SW pass-through, SW build-stamp | overlay `deploy.yml`; kit repin (dual-pin) | operator overlay |

All feature logic is upstream in the kit; the overlay carries only the flag value,
any branded-string `sed`, and the repin.
