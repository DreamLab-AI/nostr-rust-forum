# DDD — Zone-bound one-shot BBS PWA

- **Status:** Draft (greenfield v1 — no BootProfile / bake / manifest machinery exists yet)
- **Date:** 2026-07-18
- **Owners:** `nostr-bbs-forum-client` (install offer, consent, bake) and
  `nostr-bbs-bbs-client` (manifest/SW, one-shot boot, key adoption, zone-pin,
  forget-device). `nostr-bbs-relay-worker` is an unchanged enforcement dependency.
- **Related:** [ADR-109 — zone-bound BBS PWA install](../adr/ADR-109-zone-bound-bbs-pwa-install.md),
  [prd-zone-bound-bbs-pwa](../prd/prd-zone-bound-bbs-pwa.md),
  [ADR-107 — zone-first landing](../adr/ADR-107-zone-first-landing-and-scoped-navigation.md),
  [ADR-108 — BBS mobile-first redesign](../adr/ADR-108-bbs-mobile-first-redesign.md),
  [ADR-099 — revocable device keys](../adr/ADR-099-revocable-device-keys.md),
  [ADR-105 — BBS door games and write architecture](../adr/ADR-105-bbs-door-games-and-write-architecture.md),
  [ddd-bbs-bounded-contexts](./ddd-bbs-bounded-contexts.md).

---

## 1. Purpose

This document models the **zone-bound one-shot BBS PWA** as three bounded
contexts and one new aggregate. The feature lets a signed-in member whose zone
access resolves to **exactly one locked zone** install the retro BBS at
`/community/bbs/` as a home-screen app that boots straight into that zone's
Boards, signing as them, without a landing screen or a password prompt. A
single-zone community deployment (for example the MINIMOONOIR node, one operator
branding among many) is the canonical shape this serves, but nothing here is
operator-specific: the gate is the generic ADR-107 predicate, and the bound zone
is whatever single locked zone the member belongs to.

The design deliberately reuses existing domain machinery rather than inventing a
parallel model. The zone gate is the ADR-107 `home_zone_for` predicate verbatim.
The key that gets "baked" is the **same** secp256k1 secret the forum already
persists. The BBS already knows how to adopt that secret from the forum session.
What is genuinely **new** is: the notion of a durable, wrapped, zone-bound boot
record (the **BootProfile** aggregate), the installability surface (manifest +
scoped service worker), and the one-shot boot / rebind / forget lifecycle. Those
are the concepts modelled below.

The security posture is stated honestly throughout and is not a domain invariant
the code can enforce: baking a key gives **zero** protection against same-origin
XSS or an attacker holding the unlocked phone. Its only genuine value is raising
the bar against passive offline/backup forensic extraction (ciphertext plus an
opaque non-extractable key handle). The context boundaries and the consent
invariant exist to keep that honesty structural.

## 2. Bounded contexts

| Context | Owns | Crate(s) | State today |
|---------|------|----------|-------------|
| **Identity & Signing** | the secp256k1 secret lifecycle across the two same-origin SPAs: baking a wrapped durable copy, adopting/unwrapping it, and the iOS first-launch **rebind** (passkey PRF or paste-recovery-key) | `forum-client` (`auth/`), `bbs-client` (`signer.rs`, `passkey.rs`) | Bake/unwrap/rebind are **new**; forum key-persistence and BBS adoption exist |
| **Zone Access** | the exactly-one-locked-zone predicate that gates the install offer and names the bound zone; the client-side zone-pin | `forum-client` (`stores/zone_access.rs`, `stores/zones.rs`) | Predicate exists (ADR-107); pin is **new** |
| **App Installation / Boot Profile** | the **BootProfile** aggregate, the `?pwa=1` boot flag, the `manifest.webmanifest`, the network-first BBS-scoped service worker, one-shot boot, and forget-device | `forum-client` (consent + bake), `bbs-client` (`index.html`, `app.rs`, `chrome.rs`, `screens.rs`) | **New** (greenfield) |
| **Zone Enforcement** *(supporting, unchanged)* | the *real* access boundary: server-side cohort gate, `ZONE_CONFIG`, and the lost-phone alias/rotation + whitelist-revocation playbook | `relay-worker` (`user_admin.rs`, DO relay) | Exists and is **untouched** by this feature |

Identity & Signing and App Installation both **straddle the two SPAs** because
`/` (forum) and `/community/bbs/` (BBS) are the **same origin** and therefore
share one origin storage bucket on Android/desktop. Zone Enforcement is the
authoritative boundary and gains no new code — the whole client feature is UX
convenience layered over a server gate that already exists.

### Context map (sketch)

```
        signed-in member, exactly one locked zone (ADR-107)
                              │
                              ▼
  ┌───────────────────────── forum-client (/) ──────────────────────────┐
  │  Zone Access            │  App Installation      │  Identity&Signing │
  │  home_zone_for()  ──────┼─► "Install mobile app" │  bake:            │
  │  is_member()            │   consent + checkbox   │   wrap nostr_bbs_sk│
  │  (gate + bound zone id) │   write BootProfile     │   with AES-GCM key │
  └─────────────────────────┴──────────┬──────────────┴──────────┬───────┘
                                        │ same-origin storage      │
             ┌──────────────────────────┼──────────────────────────┼──────┐
             │ localStorage             │ IndexedDB                 │      │
             │  nostr_bbs_keys (pub)    │  BootProfile + WrappedSecret + │  │
             │  nostr_bbs_sk (secret)   │  non-extractable WrapKey       │  │
             └──────────────────────────┼──────────────────────────┼──────┘
                                        ▼                          ▼
  ┌──────────────────── bbs-client (/community/bbs/) ────────────────────┐
  │  App Installation      │  Identity&Signing      │  Zone Access        │
  │  manifest + scoped SW  │  adopt: unwrap → signer│  zone-pin           │
  │  ?pwa=1 → one-shot boot │  iOS rebind (PRF/paste)│  hide other zones   │
  │  forget device ────────┼─► destroy profile+key  │  land in Boards     │
  └────────────────────────┴────────────────────────┴─────────┬──────────┘
                                                               │ signs kind-42/… 
                                                               ▼
  ┌──────────────── relay-worker (unchanged enforcement) ─────────────────┐
  │  whitelist cohort gate · ZONE_CONFIG · NIP-42 AUTH                     │
  │  lost-phone: POST /api/admin/alias (inherit_cohorts) then             │
  │              POST /api/admin/user/delete (revoke whitelist access)     │
  └───────────────────────────────────────────────────────────────────────┘
```

**Ownership rule.** `forum-client` owns *offer + consent + bake* (it holds the
authenticated session and the zone predicate). `bbs-client` owns
*install-surface + boot + adopt + pin + forget + rebind* (it is the app that gets
installed). `relay-worker` owns *enforcement* and changes for **neither** — the
zone-pin is cosmetic; the server decides who may read and post. Per the kit's
placement rule, all feature code lands upstream in these crates; the operator
overlay carries only deploy wiring and the kit repin.

## 3. Ubiquitous language

| Term | Definition |
|------|-----------|
| **Bake** | Persist a durable copy of the member's secp256k1 secret in **origin** storage (IndexedDB), encrypted with AES-GCM under a **non-extractable** `CryptoKey` held in IndexedDB. Baking is an explicit, consented act performed by `forum-client`. It does **not** move the key anywhere new conceptually — it is the same secret already in `nostr_bbs_sk`, now wrapped and paired with a BootProfile. |
| **BootProfile** | The aggregate record `{ mode: "zone-app", zone, created_at, pubkey, rebind }` that marks this origin/app as a one-shot zone app and names the single zone it is bound to. Its presence (or `?pwa=1`) is what makes boot skip onboarding. |
| **Wrapped secret** | The AES-GCM ciphertext (plus IV) of the 32-byte secp256k1 secret, stored alongside the BootProfile. Part of the BootProfile aggregate's consistency boundary. |
| **Wrap key** | The `extractable:false` AES-GCM `CryptoKey` in IndexedDB used to wrap/unwrap the secret. `exportKey`/`wrapKey` throw on it, so raw bytes never reach JS; **use** is not prevented (any same-origin code can call `decrypt`). |
| **One-shot boot** | The BBS boot path that, on seeing `?pwa=1` or a BootProfile, adopts the baked key, skips `Landing`/`MainMenu`, and lands pinned in the bound zone's Boards. "One-shot" = happens once per launch with no user interaction after the first successful bind. |
| **Adopt** | The BBS installing the unwrapped secret as its active signer (extending the existing `adopt_forum_session` path), so the installed app can author events as the member. |
| **Rebind** | The **iOS-only** one-time re-establishment of the baked key inside the home-screen app's *isolated* storage, because iOS gives a home-screen web app a storage bucket separate from Safari. Done by a passkey PRF tap (`passkey_authenticate(pubkey)`, deterministic re-derivation) when the account has a passkey, else a single paste of the recovery key. After rebind the app is one-shot like any other platform. |
| **Zone-pin** | The BBS navigation constraint, active only in PWA mode, that fixes the app to the bound zone: the Zones screen and cross-zone back-crumbs are bypassed and other zones are hidden. A rendering/UX constraint only — **not** an access-control boundary. |
| **Forget device** | The BBS Settings action that **atomically destroys** the BootProfile, the wrapped secret, and the wrap key from this device's storage. It unbakes locally; it does **not** revoke relay access and cannot protect a phone already in someone else's hands. |
| **Home zone** | The single locked zone a non-admin member is authorised for, per `home_zone_for` (ADR-107): `None` for admins, for zero accessible locked zones, or for two-plus (a genuine multi-zone member). `Some(zone)` is the precondition for the install offer and the value bound into the BootProfile. |
| **Locked zone** | A zone with non-empty `required_cohorts` that the member satisfies via `Zone::is_member`. An open/public landing zone (empty `required_cohorts`) is never a home zone and can never be bound. |

## 4. The BootProfile aggregate

The feature introduces exactly one new aggregate. Its **root** is the BootProfile
record; the wrapped secret and the wrap-key handle sit **inside its consistency
boundary** — they are created together at bake time and destroyed together at
forget time, and no external context may hold a reference that outlives the root.
Modelling them as one aggregate is what makes the atomic-forget invariant (I4)
expressible: "profile gone but ciphertext lingering" is an illegal state by
construction, not by convention.

### 4.1 Fields

| Field | Type | Meaning |
|-------|------|---------|
| `mode` | `"zone-app"` (discriminator) | Marks this origin/app as a one-shot zone app. The only value in v1. |
| `zone` | `ZoneId` (string) | The single **locked** zone this app is bound to. Matches a `nostr_bbs_config::schema::Zone` `id`. |
| `created_at` | epoch (i64) | When the bake happened. Audit/UX only; not security-bearing. |
| `pubkey` | 64-hex string | The member's **public** key. Carried so the iOS rebind can call `passkey_authenticate(pubkey)` (which requires the caller to already know the target pubkey — no discovery oracle) and for display continuity. Never secret. |
| `rebind` | `"passkey" \| "recovery-key"` | Which first-launch rebind path applies on isolated-storage platforms, chosen at bake time from whether the account has a passkey. |
| *(paired, in-boundary)* `wrapped_secret` | `{ ciphertext, iv }` | AES-GCM ciphertext of the 32-byte secp256k1 secret. |
| *(paired, in-boundary)* `wrap_key` | non-extractable `CryptoKey` | The IndexedDB-resident AES-GCM key. Opaque handle; never exported. |

`mode`, `zone`, `created_at`, `pubkey`, and `rebind` are all non-secret and could
in principle live in a single IndexedDB record; the `wrapped_secret` and
`wrap_key` are the sensitive members. All are one aggregate.

### 4.2 Invariants

- **I1 — Consent precedes bake.** A BootProfile is created **only** after explicit
  consent is recorded (the warning copy plus a ticked checkbox). No code path may
  bake silently or as a side effect of another action. The consent text states in
  plain UK English that anyone who unlocks the phone can read the zone and post as
  the member, and that a lost phone means asking an admin to rotate the key.
- **I2 — The bound zone is a member zone.** `zone` must reference a **locked** zone
  the member satisfies at creation: `Zone::is_member(cohorts) == true` **and**
  `required_cohorts` non-empty. An open/public zone can never be bound.
- **I3 — The exactly-one-zone gate holds at creation.** At bake time
  `home_zone_for(zones, cohorts, is_admin)` must equal `Some(zone)`. This makes
  three things structurally true: `is_admin == false` (admins get `None`), there is
  **exactly one** accessible locked zone, and it is the one being bound. Admins and
  multi-zone members can never create a BootProfile because the offer is never
  shown to them and the bake would fail the gate.
- **I4 — Forget is atomic and total.** Forget-device destroys the BootProfile
  record, the wrapped secret, **and** the wrap key together. No partial residue is
  permitted — not an orphaned ciphertext, not a dangling non-extractable key, not a
  profile pointing at deleted key material. This is the aggregate's transactional
  boundary.
- **I5 — One binding; stable identity.** A BootProfile binds exactly one `pubkey`
  to exactly one `zone`; re-baking **upserts** (overwrites) rather than
  accumulating. The installed app's manifest `id` is a fixed value (not the default
  derived from a `?pwa=1`-bearing `start_url`), so the installed identity does not
  fork across redeploys.
- **I6 — The pin never widens access (boundary law).** The `zone` binding is a
  client pin for rendering and boot only. It grants nothing: if the relay-worker
  later removes the member's cohort, the server gate rejects reads/writes
  regardless of the still-present BootProfile. Server-side cohort enforcement is
  authoritative; the aggregate is convenience state layered on top of it.

### 4.3 Lifecycle

```
  create  ──(consent I1 + gate I3 + member-zone I2)──►  BootProfile{zone-app, zone}
                                                        + WrappedSecret + WrapKey
     │
     ├─ Android/desktop: same origin bucket → BBS reads directly → adopt → pin
     │
     ├─ iOS first launch: isolated bucket, ?pwa=1 present, profile absent
     │       └─ rebind (passkey PRF tap  |  paste recovery key)
     │             └─ re-bake into the app's own IndexedDB (upsert, I5) → one-shot
     │
  forget  ──(atomic I4)──►  ∅   (local unbake; relay access unaffected)
```

Rebind is **not** a secret transfer across the Safari↔app boundary: the passkey
path deterministically **regenerates** the same identity from a fresh PRF tap
(HKDF-SHA-256 over the WebAuthn PRF output → the same secp256k1 keypair), so no key
crosses the isolation boundary. This is also why rebind is *not* a device-loss
mitigation: an attacker who can unlock the phone and pass the biometric derives the
identical key. Device-loss recovery is the relay-side rotation in §6, not rebind.

## 5. Shared storage keys & integration points

The two SPAs are the **same origin**, so on Android/desktop they share one
localStorage/IndexedDB bucket (Chrome storage partitioning targets third-party
iframes, not first-party PWA-vs-tab). iOS home-screen apps are the exception: an
isolated bucket, which is exactly why rebind exists.

| Key / surface | Storage | Owner (writes) | Reader | Role in this feature |
|---------------|---------|----------------|--------|----------------------|
| `nostr_bbs_keys` (`STORAGE_KEY`) | localStorage | forum `auth/mod.rs` | BBS `config.rs` (`FORUM_SESSION_KEY`) | Session metadata JSON — **public key only**, never secret. Supplies `pubkey` for the BootProfile and BBS viewer. |
| `nostr_bbs_sk` (`SESSION_PRIVKEY_KEY` / `FORUM_PRIVKEY_KEY`) | localStorage | forum `auth/session.rs::save_privkey_session` | BBS `signer.rs::adopt_forum_session` | The raw 32-byte secret (hex) already persisted for remember-me logins. **This is the plaintext the bake wraps.** |
| `nostr_bbs_remember` (`REMEMBER_ME_KEY`) | localStorage | forum `auth/session.rs` | forum | Remember-me flag (default on). Governs whether `nostr_bbs_sk` is durable at all. |
| BootProfile store (new, e.g. IndexedDB DB `nostr_bbs_pwa`, object store `boot_profile`) | IndexedDB | forum bake | BBS boot (`app.rs` initial-screen) | The `{mode, zone, created_at, pubkey, rebind}` record. |
| Wrapped-secret + wrap-key store (new, e.g. object stores `wrapped_secret` / `wrap_key`) | IndexedDB | forum bake | BBS adopt (`signer.rs`) | Ciphertext/IV and the non-extractable AES-GCM `CryptoKey`. In the BootProfile aggregate boundary (I4). |
| `?pwa=1` | URL query on `start_url` | manifest (BBS `index.html`) | BBS `config.rs` / `app.rs` | Boot discriminator carried by the manifest's `start_url`; primary signal on iOS where the shared-storage BootProfile is absent on first launch. |
| `manifest.webmanifest`, `sw.js` | HTTP assets under `/community/bbs/` | BBS `index.html` (`data-trunk` copy directives) | browser | Installability. SW scope `/community/bbs/`, network-first, never caches the app shell (must preserve the forum SW's deliberate `/bbs/` bypass so the historic BBS cache-404 bug cannot recur). |

**Integration seams to extend (not rebuild):**

1. **Zone Access → offer (forum).** Gate the install-offer UI on
   `!is_admin.get() && use_zone_access().home_zone().is_some()`, the same call
   pattern already used for nav re-rooting and the `is_admin` memo. Placement is a
   new feature-gated Settings section (the natural home for device/account
   actions), modelled on the ADR-099 Devices section's `Show when=…` gating.
2. **Identity & Signing → bake (forum) / adopt (BBS).** Bake wraps the existing
   `nostr_bbs_sk` (or the in-memory `privkey` bytes) — reusing the zeroize-on-drop
   discipline of the existing `PrivkeyMem` model. Adopt extends
   `adopt_forum_session` / `choose_adoption` to try the unwrapped BootProfile
   secret before falling back to the plaintext forum session or NIP-07.
3. **App Installation → boot + pin (BBS).** The `initial_screen` computation (today:
   `MainMenu` if a session was adopted, else `Landing`) gains a prior branch: on
   `?pwa=1`/BootProfile, land in `Boards` pinned to `zone`. `BbsState` gains a
   PWA-mode marker (a `pwa_mode` flag plus the existing `zone` signal, or a
   dedicated `pinned_zone`) and the navigation methods (`go`/`open_zone`/
   `close_zone`) honour the pin by hiding other zones and the Zones-screen
   back-crumb. Forget-device is a new action in the BBS Settings screen, beside the
   existing sign-out / back-up-key pair.

NIP-07 (extension-signer) members are structurally excluded from baking: they have
no readable `nostr_bbs_sk` (`privkey: null`), so there is nothing to wrap — the
offer must additionally check that a wrappable secret exists, not merely that the
zone gate passes.

## 6. Zone Enforcement context (unchanged) & lost-phone recovery

This feature adds **no** relay-worker code. The relay remains the only real
boundary: the whitelist cohort gate and `ZONE_CONFIG` decide who may connect,
read, and post, and NIP-42 AUTH binds the connection to the pubkey. A zone-pinned
installed app that lost its cohort server-side would simply be rejected.

A Nostr key cannot be cryptographically rotated in place — the key **is** the
identity, and an admin can never re-sign the lost key's historic events. The
existing, already-wired operator playbook (see `user_admin.rs`) is the lost-phone
answer the consent copy points members to:

1. The member mints a **fresh** keypair on a device they still control (generate,
   or `passkey_register` if their passkey/security key survives).
2. Admin `POST /api/admin/alias { old_pubkey, new_pubkey, inherit_cohorts: true }`
   — copies the lost key's zone/cohort access onto the new key and records the
   link for display attribution.
3. Admin `POST /api/admin/user/delete { pubkey: old_pubkey }` — strips the
   compromised key from `whitelist` (immediate relay-access revocation) and the
   same handler auto-cleans the now-dangling `pubkey_aliases` row.

Forget-device (I4) is the *local* counterpart — it removes the baked key from one
phone — but it is not revocation and does nothing for a phone already in an
attacker's hands. The two together (local forget where possible, admin
alias+delete always) are the complete device-loss response.

## 7. Threat model (honest boundary)

The aggregate and its consent invariant exist to keep the security story
structural and truthful, not to imply protection the design cannot give.

| Attacker class | Outcome | What actually mitigates it |
|----------------|---------|----------------------------|
| Remote, no code execution | Cannot read the key; sees only AES-GCM ciphertext + an opaque non-extractable key handle | The bake, working as designed |
| Same-origin XSS | **Full compromise** — calls `crypto.subtle.decrypt` with the same handle the app uses, exfiltrates the secret or signs arbitrary events | **Not** the bake. Only strict CSP + Trusted Types + output encoding + dependency hygiene reduce the XSS surface |
| Unlocked phone (theft, borrowed, shoulder) | **Full compromise** — reads the zone, posts as the member | **Not** the bake. Only the OS lock screen. Forget-device helps only after the fact and only if the attacker has not acted |
| Device backup / offline forensic dump (no live JS) | Meaningfully raised bar — needs to re-run origin JS in a matching engine to unwrap | The bake's **genuine** value |
| Malicious browser extension injecting same-origin script | Same as XSS — full compromise | Not the bake; out of scope for BBS code |
| Forensic examiner with live heap attach | Captures plaintext at the moment of unwrap | Not mitigated — no hardware enclave in this design |
| Lost/stolen **locked** phone (cannot unlock) | No direct read; risk until revoked | Admin alias + `user/delete` (§6) |

The consent copy (≤80 words) must carry this directness — matching how NIP-46/47
remote signers and extension key-vaults warn users — rather than implying the
non-extractable wrap protects a phone in someone else's hands. It does not.

## 8. Anti-corruption boundary

Consistent with the existing BBS DDD, this feature **borrows** the kit's canonical
types and never forks them:

- **Zone model → kit config.** The gate reads `home_zone_for` / `Zone::is_member`
  from `stores/zone_access.rs` / `stores/zones.rs` and the `Zone` type from
  `nostr_bbs_config`. The BootProfile stores only a zone `id`, resolved back to a
  `Zone` at render time; it never copies zone fields.
- **Key derivation → kit core.** The iOS passkey rebind uses
  `nostr_bbs_core::derive_from_prf` (HKDF-SHA-256 over the WebAuthn PRF output),
  identical to the forum and existing BBS passkey paths, so a passkey minted at `/`
  and one used at `/community/bbs/` resolve to the same identity. No hand-rolled
  derivation.
- **Signer seam → existing BBS adoption.** Adoption extends `adopt_forum_session` /
  `choose_adoption` rather than introducing a second signer path; the BBS still
  signs the kit's event types, never its own schema.
- **Enforcement → relay-worker.** The client models a *pin*, never an
  *authorisation*. Authorisation stays in `whitelist` / `ZONE_CONFIG` /
  `pubkey_aliases`, unchanged.

A change to the zone schema, key derivation, or enforcement therefore propagates
through the shared crates, not through a parallel copy inside the PWA feature that
could rot.
