# ADR-109: Zone-bound one-shot BBS PWA install

**Status:** Accepted (design ratified; implementation pending)
**Date:** 2026-07-18
**Decision Owners:** nostr-rust-forum maintainers (DreamLab AI)
**Related:** [ADR-107 Zone-first landing and scoped navigation](ADR-107-zone-first-landing-and-scoped-navigation.md), [ADR-108 BBS mobile-first redesign](ADR-108-bbs-mobile-first-redesign.md), [ADR-105 BBS door-games and write-path](ADR-105-bbs-door-games-and-write-architecture.md), [ADR-099 Revocable device keys](ADR-099-revocable-device-keys.md), [ADR-100 Key lifecycle](ADR-100-key-lifecycle.md), [ADR-094 Deterministic purpose-scoped subkey derivation](ADR-094-deterministic-subkey-derivation.md), [ADR-090 Path discipline at the FORUM_BASE boundary](ADR-090-forum-base-path-discipline.md), ADR-022 NIP-29 Group Access Model (upstream/historical kit record — the relay zone read gate), [PRD BBS retro client](../prd/prd-bbs-retro-client.md), [DDD BBS bounded contexts](../ddd/ddd-bbs-bounded-contexts.md), relay admin alias/delete surface (`crates/nostr-bbs-relay-worker/src/user_admin.rs`)

## Context

A single-zone operator — one gated cohort community behind one locked zone, of
which "MINIMOONOIR" is one branded deployment — wants its members to reach the
retro BBS (`nostr-bbs-bbs-client`, served at `/community/bbs/`) the way they reach
a native app: tap a home-screen icon, land already signed in, already inside their
one zone, with no password, no menu, no zone shelf. ADR-107 already resolves *where*
such a member lands in the forum (their single locked zone, derived from cohorts);
ADR-108 already makes the BBS itself mobile-usable. What is missing is (a) an
installable home-screen entry point for the BBS, and (b) a way to keep the member
signed in across that installed launch without re-authenticating each time.

Two facts make this hard, and both are load-bearing for the design:

1. **The BBS holds a Nostr secret key, and a Nostr key *is* the identity.** There is
   no server-side session cookie to lean on and no way for an operator to re-sign a
   member's events; staying "signed in" means the secp256k1 secret must be present
   on the device at launch. The forum already persists that secret in origin storage
   for local-key / imported-nsec logins (localStorage key `nostr_bbs_sk`,
   `auth/session.rs`), and the BBS already adopts it (`signer.rs`
   `adopt_forum_session`). A home-screen launch needs that same secret to survive,
   durably, into the installed context.

2. **Installed-app storage is not uniform across platforms.** On Android and desktop
   Chrome an installed same-origin PWA shares the ordinary tab's `localStorage`/
   `IndexedDB` bucket (Chrome's storage-partitioning work targets third-party iframe
   isolation, not first-party PWA-vs-tab), so an already-baked key carries straight
   in. On iOS a Home Screen web app's Web Storage and IndexedDB are **isolated** from
   Safari's, and each Add-to-Home-Screen instance gets its own bucket — the baked key
   provably cannot be read across the Safari → installed-app boundary, so first launch
   must re-establish the identity once, in the installed app's own storage.

Persisting a high-value signing key in a web origin is exactly what mainstream Nostr
tooling tells users *not* to do — NIP-46/47 remote signers (nos2x, Amber, bunkers)
keep the key out of the web client entirely and advertise "the client never sees your
private key". This design deliberately accepts on-device persistence for the
one-tap UX, so it must carry that decision **honestly**: the threat model is
documented in full (below and in the Consequences), the consent copy states the real
residual risk plainly rather than implying protection the mechanism does not provide,
and the feature is confined to the single-zone case where the UX gain is real.

The relay stays the security boundary throughout (ADR-022, ADR-105, ADR-107): none of
the client-side rendering, key baking, or zone pinning below moves enforcement
off the relay. All feature code lands **upstream** in `nostr-rust-forum` — the
forum client owns the install affordance, consent and bake; the BBS client owns the
manifest, service worker, one-shot boot, zone pin and key adoption; the operator
overlay carries only deploy wiring and the kit repin. A pre-flight grep across the
kit (`BootProfile`, `bake_key`, `manifest.webmanifest`, `zone-app`) returned zero
hits: this is greenfield v1 with nothing to conflict against.

## Decision 1 — Show "Install mobile app" only to a signed-in member with exactly one locked zone

The affordance is gated on the **same predicate ADR-107 already ships**:
`home_zone_for(zones, cohorts, is_admin)` (`stores/zone_access.rs`) returns
`Some(zone)` only for a non-admin whose cohorts resolve to exactly one **locked**
zone (`required_cohorts` non-empty and `Zone::is_member(cohorts)` true), and `None`
otherwise. The install entry point renders under `Show when=move || !is_admin.get()
&& home_zone().is_some()` — reusing the reactive `ZoneAccess::home_zone` wrapper, so
it re-evaluates when the whitelist/access fetch completes and never renders
prematurely. Admins (early-return `None`) and multi-zone members (`None` on ≥2
matches) never see it, because a home-screen app that boots straight into *one*
pinned zone is meaningless for someone who legitimately spans several or governs all
of them.

Placement is a new **Settings section** in the forum client
(`pages/settings.rs`), slotted after the gated Devices section (4e, ADR-099) and
before Account, following that section's exact gating and list/action layout
(`Show`-when-flag, `glass-card` block, consent controls, a busy-button, a status
line). Settings is already where device- and account-level actions live, so no new
header real estate is needed and the entry stays off the main nav for the members
who must not see it.

| Alternative | Verdict | Rationale |
|---|---|---|
| Show the install option to everyone and let the browser's ambient install UI decide | Rejected | A baked-key one-shot boot pins the app to a single zone (Decision 4); offering it to an admin or a multi-zone member produces an app that hides zones they are entitled to, or bakes a governing key into a phone. The gain only exists for the exactly-one-zone case, so the affordance is scoped to exactly that case. |
| A new header/nav button for install | Rejected | Adds header real estate and a second surface to gate, for a rarely-tapped one-time action. Settings already carries device/account actions and already proves the feature-gated section pattern (ADR-099 Devices). |
| Reuse the `beforeinstallprompt` event alone (browser-native mini-infobar) | Rejected as the *gate* | The native prompt cannot be conditioned on cohort facts and would surface to every visitor. The event is still *used* (Decision 3) to drive the gated button, but the gate is the ADR-107 predicate, not the browser. |

## Decision 2 — "Bake the key": wrap the secret with a non-extractable AES-GCM key in IndexedDB, plus a BootProfile record

Baking persists the member's existing secp256k1 secret — the same raw hex already in
`nostr_bbs_sk` — durably in **origin storage**, encrypted at rest:

- A WebCrypto AES-GCM `CryptoKey` is generated with `extractable: false` and stored
  as a structured-clone record in IndexedDB. `extractable: false` makes
  `exportKey()`/`wrapKey()` throw, so the raw AES key bytes never reach JavaScript.
- The secp256k1 secret is encrypted with that key (AES-GCM, per-record random IV) and
  the **ciphertext** is written to IndexedDB alongside the key record.
- A **BootProfile** record is written: `{ mode: "zone-app", zone: <zone.id>,
  created_at: <unix> }`. This is what the BBS boot reads to enter one-shot mode
  (Decision 4) and which zone to pin to.

The bake reuses the forum's existing zeroize discipline (`PrivkeyMem`,
`session.rs`; logout already zeroes `privkey` and clears the session key): the
plaintext secret exists in memory only for the duration of the wrap and is zeroed
after. "Forget this device" (Decision 6) deletes the ciphertext, the AES key record
and the BootProfile, and zeroes any in-memory copy.

**The threat model is stated plainly, not implied away.** A non-extractable AES-GCM
key in IndexedDB is genuine defence-in-depth against *export* and against *passive*
extraction, and nothing more:

- **Against a passive disk/backup/forensic dump with no live JS execution** the bar is
  meaningfully raised: the extractor obtains only AES-GCM ciphertext plus an opaque,
  engine-internal `CryptoKey` record and must re-run the origin's JavaScript in a
  matching browser profile to unwrap. This is the mechanism's real value.
- **Against same-origin XSS the mechanism gives zero protection.** Any script running
  in the origin can fetch the same `CryptoKey` handle and call
  `crypto.subtle.decrypt()`/`sign()` exactly as the app does. WebCrypto does not
  protect against XSS. The mitigations that *do* reduce that surface — strict CSP,
  Trusted Types, rigorous output encoding, dependency hygiene — sit alongside the
  bake and are not a substitute for it, nor it for them.
- **Against an unlocked phone the mechanism gives zero protection.** Anyone who opens
  the installed app on an unlocked device reads the zone and posts as the member. The
  OS lock screen is the only barrier here. The consent copy says exactly this.

| Alternative | Verdict | Rationale |
|---|---|---|
| Store the secret as plaintext in `localStorage` (as the forum already does for remember-me) | Rejected for the baked copy | Plaintext at rest is trivially recovered from any backup/forensic dump. The wrapped copy strictly dominates it for the passive-extraction case at negligible cost, and the durable, install-surviving copy warrants the stronger treatment. The transient forum session key is out of scope of this ADR. |
| Remote signer / NIP-46 bunker — never persist the key in the web origin | Acknowledged, not adopted for v1 | This is the genuinely safe answer and the industry norm for high-value keys, but it defeats the one-tap, offline-capable, self-contained home-screen UX this feature exists to deliver (it requires a second always-available signer app and a live connection). Recorded as the honest upgrade path; the consent copy borrows its directness. |
| Password-derived encryption key (PBKDF2/Argon2 over a user passphrase) | Rejected for v1 | Adds a passphrase prompt at every launch, defeating the "no password" goal, and only helps the passive-dump case that the non-extractable AES-GCM key already covers — while a forgotten passphrase becomes an unrecoverable lockout. |

## Decision 3 — Installability: a static manifest + a minimal network-passthrough service worker at the BBS scope

The BBS today ships **no manifest and no service worker** (`index.html` has neither;
`find` confirms). This ADR adds both, scoped tightly to `/community/bbs/`.

**Manifest** (`manifest.webmanifest`, a single static shared file copied verbatim by
Trunk, with brand-neutral kit defaults the operator may override):

```json
{
  "id": "/community/bbs/",
  "scope": "/community/bbs/",
  "start_url": "/community/bbs/?pwa=1",
  "name": "<operator NODE_NAME> BBS",
  "short_name": "BBS",
  "display": "standalone",
  "background_color": "#0a0a0a",
  "theme_color": "#0a0a0a",
  "icons": [
    { "src": "icons/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any" },
    { "src": "icons/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any" },
    { "src": "icons/icon-512-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ]
}
```

Load-bearing manifest details:

- **`id` is set explicitly** to `/community/bbs/`, *not* left to default. Because
  `start_url` carries the `?pwa=1` query, an omitted `id` would default to the
  query-bearing `start_url` and could fork the installed app's identity across
  re-deploys. A stable `id` pins one app identity regardless of the boot query.
- **`scope` contains `start_url`.** `start_url` (`/community/bbs/?pwa=1`) is a sub-path
  of `scope` (`/community/bbs/`) — the query string does not affect path containment.
  If it were *not* contained, the browser would silently derive scope from `start_url`
  and ignore the declared `scope`; the two are chosen so containment holds exactly.
  `scope` ends in a trailing slash.
- **Icons** are `192×192` and `512×512` at `purpose:"any"` plus a *separate* `512×512`
  at `purpose:"maskable"` — never `"any maskable"` on one file. Maskable artwork is
  kept inside the ~80%-of-square safe zone. `theme_color`/`background_color` tint the
  splash and OS chrome but do not gate installability.

**Service worker** (`sw.js` served at `/community/bbs/sw.js`, registered with explicit
`scope: "/community/bbs/"`): a **fetch handler that is pure network passthrough** —
`event.respondWith(fetch(event.request))` — and writes **nothing** to Cache Storage.
Two reasons it exists and one reason it is deliberately inert:

- **It is a hard prerequisite for the gated install button.** Since Chrome 108
  (mobile) / 112 (desktop) a *menu-based* install no longer strictly requires a
  fetch-handling SW, but the `beforeinstallprompt` event — the event Decision 1's
  custom "Install mobile app" button captures and later calls `prompt()` on — still
  requires a registered SW with a `fetch` handler. So the SW is not merely
  defence-against-a-bug; without it the gated button has no prompt to fire.
- **Its scope is `/community/bbs/`, so longest-match wins.** A page under
  `/community/bbs/` is controlled by this SW in preference to the forum's
  `/community/sw.js`; the SW script lives at `/community/bbs/sw.js`, so its default
  maximum scope is already `/community/bbs/` and no `Service-Worker-Allowed` header is
  needed. The forum SW independently bypasses `/bbs/` (`sw.js:77-87`, "no
  `respondWith` → default browser network handling"), so the two never contend.
- **It never caches the app shell.** It writes nothing to Cache Storage at all, so it
  is *structurally incapable* of reproducing the historic BBS cache-404 class that the
  forum SW's `/bbs/` bypass was written to prevent — namely caching a BBS/forum
  `index.html` under the wrong key and then serving a shell a router cannot resolve
  offline. "Network-first purely for installability" here means the degenerate
  network-first with no cache fallback: always the network, cache never.

`beforeinstallprompt` also fires only after at least one prior user interaction, so
the button binds the deferred event and becomes active after any tap; menu-based
"Add to Home Screen" remains available regardless.

| Alternative | Verdict | Rationale |
|---|---|---|
| **No service worker at all** (rely on menu-based install only) | Rejected | Menu install is SW-optional since Chrome 108/112, but the custom gated "Install mobile app" button depends on `beforeinstallprompt`, which still *requires* a fetch-handling SW. Dropping the SW would either remove the gated affordance (leaving only ambient browser UI that cannot be cohort-gated) or leave the button dead. A single inert passthrough SW is the minimum that makes the intended UX work. |
| **Full offline-caching / app-shell-precaching SW** (cache `index.html` + WASM for offline use) | Rejected | This is exactly the pattern that produced the historic BBS cache-404 class the forum SW's `/bbs/` bypass exists to prevent: a cached shell served for a path the client can't resolve, or a stale shell that can't reach fresh branding/WASM. The BBS gains nothing from offline caching in v1 (it needs the live relay to be useful), and the risk is a known, previously-fixed failure mode. Caching is out of scope; the SW writes nothing. |
| **Per-user / dynamically-generated manifest** (embed the member's zone or key per request) | Rejected | The deployment is static hosting (GitHub Pages); there is no per-request server to vary a manifest, and a manifest is a **single shared static file served identically to every user** — it must never vary per user. Per-member state (which zone, which key) lives in the member's own origin storage (BootProfile + baked key), never in a shared asset. |
| **Carry key material or member identity in `start_url` / the manifest** | Rejected outright | `start_url` and the manifest are shared static, cacheable, CDN-served artefacts read identically by every visitor and every crawler. Putting any secret or per-user identity there would leak it to everyone. `?pwa=1` is a *mode flag only* — it carries no identity; the identity is the baked key in the member's private origin storage. |

## Decision 4 — One-shot boot: `?pwa=1` or a BootProfile adopts the baked key and lands pinned in the bound zone's Boards

BBS boot (`app.rs`, which today computes `initial_screen` as `MainMenu` when a forum
session was adopted else `Landing`, per ADR-108) gains a one-shot branch evaluated
*before* that:

1. If the launch URL carries `?pwa=1` **or** a `BootProfile` record exists in origin
   storage, the client enters **pwa mode**.
2. It unwraps the baked key (AES-GCM decrypt via the non-extractable IndexedDB key)
   and installs it through the same seam `adopt_forum_session()` already uses to build
   a `PrfSigner` and call `install_signer` — the baked path is a peer of the existing
   forum-session adoption, not a new signer type.
3. It **skips `Landing` and `MainMenu`** and lands directly on `Boards`, **pinned** to
   `BootProfile.zone`: the zones-as-cards shelf (ADR-108 Decision 2) and the
   all-zones view are bypassed, and the other zones are hidden while in pwa mode. The
   pin is a new field on `BbsState` (a `pinned_zone: Option<usize>` alongside the
   existing `zone` signal) plus the existing `open_zone`/`close_zone` transitions
   constrained so "back to Zones" is unreachable in pwa mode.

Zone *hiding* here is presentation only. **The relay's cohort read gate (ADR-022,
ADR-107) remains the real boundary**: a pwa-mode client that somehow requested another
zone's events would still be denied by the relay, exactly as the ordinary client is.
The pin removes the *chrome* for other zones; it does not grant or withhold access.

If the baked key is absent or fails to unwrap (for example the isolated iOS first
launch, Decision 5), pwa mode falls through to the one-time rebind rather than to a
dead screen.

| Alternative | Verdict | Rationale |
|---|---|---|
| Detect pwa mode from `display-mode: standalone` media query instead of `?pwa=1` + BootProfile | Rejected as the *sole* signal | `display-mode` tells you the app is running installed, not that this member opted into a baked one-shot boot, and it is unreliable at first paint. `?pwa=1` (honoured in `start_url` by Chrome and by iOS's manifest-driven launch) plus a durable BootProfile is an explicit, member-scoped opt-in that survives a stripped query. `display-mode` may still be read as a secondary hint. |
| Land on `MainMenu` (the numbered menu) in pwa mode and let the member pick the zone | Rejected | Defeats the feature: the whole point of a zone-bound app is to arrive *inside* the one zone. The member already has exactly one zone (Decision 1's gate); a menu step is friction the install exists to remove. |
| Enforce the zone pin client-side as an access control | Rejected | The client never gates access (ADR-107 "What this ADR does not decide"). The pin is navigation chrome; enforcement stays on the relay. Framing it as access control would invite treating client state as a security boundary. |

## Decision 5 — iOS first launch does a one-time rebind; Android/desktop carry the bake straight in

On **Android and desktop Chrome** the installed app shares the tab's origin storage,
so the baked key and BootProfile are already present at first launch — Decision 4
runs unchanged, no rebind, truly one-shot from install.

On **iOS** the Home Screen web app's storage is isolated from Safari's (and from any
other ATHS instance), so the baked key is provably not present in the fresh installed
bucket. First launch therefore performs a **one-time rebind**, then persists into the
app's own storage and is one-shot thereafter:

- **If the account has a passkey**, first launch invokes `passkey_authenticate(pubkey)`
  (`crates/nostr-bbs-bbs-client/src/passkey.rs`). Passkeys live in iCloud Keychain at
  the OS level, *not* in per-origin Web Storage, so a passkey registered in Safari for
  the site's RP ID is available to the same-RP-ID installed web app despite the storage
  isolation. The WebAuthn PRF output is re-derived through the same HKDF→secp256k1
  construction the forum uses (ADR-094), yielding the **identical** identity with no
  secret crossing the Safari→app boundary — the key is *recomputed*, never transferred.
  iOS 17.4+ dropped the mandatory user-gesture requirement for WebAuthn (rate-limiting
  instead), so the PRF tap is a single clean biometric prompt on first launch.
- **Otherwise** first launch shows a **one-time paste-recovery-key** step (paste the
  nsec/hex once), mirroring the existing BBS backup/recovery sheet pattern (ADR-108
  F14). The pasted key is then baked into the app's isolated storage, and subsequent
  launches are one-shot.

`passkey_authenticate` is deterministic regeneration, not a secret transfer: it does
**not** mitigate the lost/unlocked-phone case (an attacker who unlocks the phone and
passes the biometric derives the same identity). It serves only the *legitimate*
member's iOS storage-isolation rebind. Lost-phone mitigation is Decision 6's rotation.

The stale "EU DMA removed Home Screen web apps" claim circulating in some 2026 blog
posts is **not** a factor: Apple's removal shipped only in early iOS 17.4 betas, was
reversed, and full Home Screen web app support was restored in the iOS 17.4 final
release and has continued since. No EU-specific gating is added.

## Decision 6 — Explicit consent before baking; "Forget this device"; admin rotation on loss

Baking requires **explicit consent**: a warning plus a checkbox the member must tick
before the bake runs, in the forum client's install section. The copy states the
residual risk directly (UK English, 68 words):

> This saves your key on this phone so the app can sign you in without a password.
> Anyone who unlocks this phone can read your zone and post as you. If your phone is
> lost or stolen, tell an admin at once to rotate your key. 'Forget this device'
> removes the saved key from this phone only — it does not protect a phone already in
> someone else's hands.

- **"Forget this device"** is a local unbake action, owned by the **BBS client**
  Settings screen (`screens.rs` settings, beside the existing sign-out / back-up-key
  pair — decision 6 is BBS-owned, not forum-owned). It deletes the ciphertext, the
  AES-GCM key record and the BootProfile from origin storage and zeroes any in-memory
  copy. It is after-the-fact and local-only: it cannot protect a phone already in an
  attacker's hands, which the consent copy says.
- **Lost-phone rotation** uses machinery that already exists and is wired in the relay
  worker (`user_admin.rs`, routes live at `lib.rs`). A Nostr key cannot be
  cryptographically rotated in place — the key *is* the identity, and an admin can
  never re-sign the lost key's past events. The operator playbook is:
  1. the member mints a fresh keypair on a device they still control (generate, or
     `passkey_register` if they still hold their passkey);
  2. an admin `POST /api/admin/alias` `{old_pubkey, new_pubkey, inherit_cohorts:true}`
     — the new key inherits the lost key's zone/cohort access and the alias records
     display-attribution continuity (`handle_alias_set`);
  3. an admin `POST /api/admin/user/delete` `{pubkey: <lost>}` — removes the
     compromised key from `whitelist`, cutting its relay access immediately, and the
     same handler cascades a cleanup of the now-dangling `pubkey_aliases` row
     (`handle_delete_user`).

  Both endpoints are shipped and admin-gated (NIP-98) today; this ADR consumes them and
  adds no relay change.

## Manifest / service-worker containment invariants

The install surface is correct only if these hold exactly (checked in review and CI):

- `manifest.scope` = `/community/bbs/` (trailing slash) and `manifest.start_url`
  (`/community/bbs/?pwa=1`) is path-contained by it, so the browser honours the
  declared scope rather than deriving one from `start_url`.
- `manifest.id` is an explicit stable string (`/community/bbs/`), independent of the
  `?pwa=1` query, so the installed identity does not fork across re-deploys.
- The SW script is served at `/community/bbs/sw.js` and registered with
  `scope: "/community/bbs/"`; its fetch handler writes nothing to Cache Storage.
- The forum SW's `/bbs/` bypass (`sw.js:77-87`) stays in place, so the forum SW and
  the BBS SW have disjoint effective control and neither shadows the other's shell.
- Icons: `192` + `512` at `purpose:"any"` and a separate `512` at
  `purpose:"maskable"`; no file combines `"any maskable"`.

## Placement and ownership

- **Forum client (`nostr-bbs-forum-client`)** owns the gated "Install mobile app"
  Settings section, the consent warning + checkbox, and the bake (AES-GCM wrap +
  BootProfile write).
- **BBS client (`nostr-bbs-bbs-client`)** owns `manifest.webmanifest`, the icons, the
  `sw.js` + registration, the `?pwa=1`/BootProfile boot branch, the zone pin
  (`BbsState`), the baked-key adoption (peer of `adopt_forum_session`), the iOS
  first-launch rebind, and "Forget this device".
- **Operator overlay** carries only deploy wiring — the manifest/icons/SW flow through
  the existing Trunk `copy-file`/`copy-dir` directives into `dist/community/bbs/` and
  the existing `cp -r` merge, needing a new `sed` step only if the operator templates
  `name`/icon URLs into the manifest at deploy time — plus the four-place KIT_REF
  repin when this feature lands (deploy.yml, workers-deploy.yml, rust-ci.yml, and the
  `nostr-bbs-*` `rev` pins in `forum-config/Cargo.toml` + `Cargo.lock`).
- **PRD/ADR/DDD** live in the kit's `docs/` tree. This ADR is the decision record;
  the companion PRD/DDD (if authored) follow the kit's `prd-<slug>.md` / `ddd-<slug>.md`
  conventions.

## What this ADR does not decide

- **Access enforcement.** The relay stays the security boundary (ADR-022, ADR-105,
  ADR-107). The zone pin and zone hiding are presentation; the baked key does not
  widen access; the exactly-one-zone gate decides *who sees the install option*, never
  *what the relay permits*.
- **Push notifications** (out of scope v1). `PushManager` becoming available in an
  installed iOS SW is noted only for completeness; the SW registers no push.
- **Multi-zone switching inside the installed app** (out of scope v1). The app is bound
  to one zone by construction of the gate; switching is deferred.
- **QR / key-sync device transfer** (deferred to v2). See Alternatives.
- **The forum's transient remember-me key at rest.** This ADR wraps the *baked* durable
  copy; it does not change how `nostr_bbs_sk` is stored for ordinary browser logins.

## Alternatives considered

Decision-local alternatives are tabled under each decision above. Cross-cutting ones:

| Alternative | Verdict | Rationale |
|---|---|---|
| **QR / key-sync device transfer** — pair the installed app to an existing session by scanning a QR that carries the key or a channel to it | Deferred to v2 | A real convenience for iOS (it would replace the paste-recovery-key rebind), but it is a distinct surface with its own threat model (a QR that carries key material is a transferable secret; a channel-based transfer needs a live rendezvous). v1 leans on the passkey-PRF rebind (no secret transferred) and a one-time paste fallback, both of which already exist. Recorded as the planned v2 upgrade to the iOS rebind. |
| **Native-app wrapper (Capacitor / a store binary)** for the zone-bound experience | Rejected for v1 | Pulls the project out of the static dual-SPA deployment, adds store review and signing overhead, and buys little over an installed PWA for a text-first terminal client. The PWA path keeps the whole feature inside the existing kit + overlay build. |
| **Server-issued session token** instead of an on-device key | Not applicable | There is no server session to issue: authorship is bound to the Nostr key, which must be on-device to sign. A token cannot sign events. This is why the design bakes the key rather than a session. |

## Consequences

**Positive.** A single-zone member installs the BBS to their home screen and, on every
launch, arrives already signed in and already inside their one zone with no password,
no menu and no zone shelf — the native-app feel the feature exists to deliver. On
Android and desktop the bake carries in with zero extra steps; on iOS a single
first-launch biometric (passkey) or one-time paste re-establishes the identity, then
it is one-shot. The gate reuses the ADR-107 predicate verbatim, so admins and
multi-zone members are correctly excluded by construction. All feature code is
upstream and kit-generic (`NODE_NAME`/icons/theme are operator-supplied), so any
single-zone operator — MINIMOONOIR is one example — gets it with only a repin.

**Neutral / unchanged.** Multi-zone members and admins see no install option and no
behaviour change. The forum SW's `/bbs/` bypass, the relay read gate, the zones-as-cards
model (ADR-108) and the ordinary (non-pwa) BBS boot are untouched. The manifest and SW
are inert for anyone who never installs. The BBS remains a non-routed CSR state machine
(ADR-108 Decision 3): the zone pin is a signal, not a route.

**Negative / tradeoffs — security, stated honestly.** A durable signing key now lives
in a web origin on the member's phone. The threat model:

| Attacker class | Outcome | Mitigation |
|---|---|---|
| Remote, no code execution | Cannot read the key; sees only AES-GCM ciphertext + an opaque `CryptoKey` record | Baseline: non-extractable AES-GCM wrap in IndexedDB works as designed |
| Same-origin XSS / malicious extension injecting same-origin script | **Full compromise**: calls `crypto.subtle.decrypt()`/`sign()` with the app's own key handle | **Not** mitigated by baking — only CSP, Trusted Types, output encoding and dependency hygiene reduce the XSS surface. Stated plainly in consent. |
| Unlocked phone (theft, borrowed, shoulder access) opens the installed app | **Full compromise**: reads the zone, posts as the member | **Not** mitigated by baking — the OS lock screen is the only barrier. "Forget this device" only helps after the fact and only if the attacker has not acted. |
| Device backup / cloud sync / offline forensic dump, no live JS | Obtains ciphertext + opaque key only; must re-run origin JS in a matching engine to unwrap | **Meaningfully raised bar** — the mechanism's genuine value |
| Lost/stolen **locked** phone (attacker cannot unlock) | No direct read, but risk persists until revoked | Admin `alias(old→new, inherit_cohorts)` then `user/delete(old)` — carries access forward, cuts the compromised key's relay access immediately (`user_admin.rs`) |

The residual burden this places on operators: a lost phone is an admin ticket
(mint-new-key → alias → delete-old), not a self-service reset, because Nostr identity
cannot be rotated in place. This is inherent to the protocol, surfaced in the consent
copy, and backed by machinery that already ships. Implementations SHOULD land strict
CSP + Trusted Types + rigorous output encoding *alongside* the bake, since WebCrypto
explicitly does not protect against XSS and those are the only levers that reduce that
class.

## Verification

- **Pure-logic tests** (native `cargo test`, `--lib` for the BBS pure suite): the
  exactly-one-zone gate reuses `home_zone_for` (already unit-tested,
  `zone_access.rs`); the baked-key adoption decision is a peer of `choose_adoption`
  (already pure/unit-tested, `signer.rs`); the `?pwa=1`/BootProfile boot branch and the
  zone-pin transitions are pure functions of signals and are unit-testable in the BBS
  lib target. Crypto-adjacent wrap/unwrap logic is a candidate for promotion into the
  kit CI `test-security` hard-gate job, not only the advisory workspace suite.
- **Manifest/SW containment** is checked against the invariants above: `scope`
  contains `start_url`; `id` is explicit and query-independent; the SW is served at
  `/community/bbs/sw.js` with `scope:"/community/bbs/"` and writes nothing to Cache
  Storage; the forum SW `/bbs/` bypass is intact.
- **Install + boot** is exercised on the mobile-emulated `browser-gpu`
  (chrome-devtools-mcp sidecar) used for ADR-108: on Android/desktop Chrome the gated
  button captures `beforeinstallprompt`, install succeeds, and a subsequent launch
  boots straight into the pinned zone's Boards with no Landing/MainMenu; the SW's
  presence (fetch handler) is confirmed as the reason the prompt fires; and no Cache
  Storage entry is created for the BBS shell. The iOS rebind path is validated against
  the documented storage-isolation behaviour (fresh installed bucket → one passkey PRF
  tap or one paste → one-shot thereafter).
- **Compile gate**: `cargo check --target wasm32-unknown-unknown` clean for both
  clients (the kit CI `wasm` hard gate), warnings only.
- **Security review** confirms the consent copy states the unlocked-phone and XSS
  residual risks without hedging, and that "Forget this device" plus the admin
  alias/delete rotation are the documented loss path.
