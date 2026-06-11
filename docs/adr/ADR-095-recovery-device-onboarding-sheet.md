# ADR-095 — Recovery & Device-Onboarding Sheet

- **Status**: Accepted
- **Date**: 2026-06-11
- **Deciders**: Forum client maintainers
- **Supersedes / extends**: complements the one-time `NsecBackup` (the plain
  nsec card shown at signup). Does **not** replace it — the sheet is additive.

## Context

At signup the forum client generates a Nostr keypair entirely in the browser
(`auth.register_with_generated_key`). The secret key is the user's sole bearer
credential. Today the only backup affordance is `NsecBackup`: a card that copies
or downloads the bare hex key to a `.txt` file. Two problems:

1. **No mobile on-ramp.** Users who want to read/post from a phone have no guided
   path. The canonical mobile client is **0xchat** (Android): NIP-17 gift-wrap
   DMs by default, NIP-28 public channels, NIP-42 relay AUTH. 0xchat's login
   accepts a QR code whose payload is a **bare `nsec1…` bech32 string**; the
   relay is added separately (the deployment already publishes a NIP-65
   kind-10002 relay-list nudge).

2. **No durable physical backup.** A `.txt` in the Downloads folder is fragile
   and easy to leak. A printed one-page sheet (Save-as-PDF or paper) is the
   recommended cold-storage form for a bearer key.

## Hard invariant (non-negotiable)

> The secret key is the in-browser key generated at signup. It MUST NEVER leave
> the browser or touch the network.

Therefore the sheet is rendered **100% client-side**. The nsec is bech32-encoded
in-WASM (via the existing `nostr_bbs_core::encode_nsec` / `encode_npub` NIP-19
path — we never hand-roll bech32), the QR codes are generated in-WASM by a
pure-Rust QR crate, and the sheet is materialised through `window.print()` /
a `Blob` object URL. **No server round-trip ever sees the nsec.**

## Decision

Add a `RecoverySheet` Leptos component (`src/components/recovery_sheet.rs`) that
renders a print-optimised one-page layout inside a `.recovery-sheet` container,
plus a component-scoped `@media print` stylesheet (injected as an inline
`<style>` so no global CSS file is touched) that hides every element except
`.recovery-sheet` when printing. The sheet contains:

| Block | Contents |
|-------|----------|
| 🔑 **Secret (nsec)** | QR of the bare `nsec1…` (bech32) + the string. Labelled **SECRET / bearer credential**, red warning border. This is the 0xchat login payload. |
| 📡 **Relay** | QR of the relay URL + the text URL. Source: `window.__ENV__.VITE_RELAY_URL` via `utils::relay_url::relay_url()`, or a prop override. |
| 🪪 **Public identity** | npub QR + `npub1…`, NIP-05 handle (if claimed), display name, and the sheet's created date. |
| 📖 **Restore steps** | Restore-on-web (paste nsec on the login page) and mobile setup (install 0xchat → scan the nsec QR → add the relay). |
| ⚙️ **Sweep (optional)** | Shown **only** when the "lock my phone to this relay only" checkbox is ticked: Settings → Relays → remove the default relays so the phone talks to one relay. A **privacy option, not required.** |
| 🔒 **ncryptsec (NIP-49)** | **Deferred — omitted.** See below. |

A **"Download / Print sheet"** button calls `window.print()`. Because the print
stylesheet hides everything but `.recovery-sheet`, the browser's print dialog
yields a clean one-page document the user can Save-as-PDF or print to paper.

### Signup gate (insist-with-override)

The sheet is wired into the existing signup **Backup** phase, alongside the
unchanged `NsecBackup`. The finish/exit control (which calls
`on_backup_done` → `auth.confirm_nsec_backup()` → navigate away) is gated:

- The exit button is **disabled** until the user has **both**
  1. clicked **Download / Print sheet** (proves a copy was produced), **and**
  2. ticked **"I've saved my recovery sheet"**.
- An **"I've stored my key elsewhere (advanced)"** override link bypasses the
  gate unconditionally (insist-with-override: we strongly steer, never trap).

The nsec source is **exactly** the same as `NsecBackup`'s: the hex from
`register_with_generated_key`, held in the `privkey_hex` signal. The sheet
bech32-encodes it for display/QR; it never re-derives or re-fetches a key.

### ncryptsec (NIP-49) — deferred

The optional encrypted-secret-key (`ncryptsec1…`) QR is **deferred**.
`nostr-bbs-core` does not currently expose a NIP-49 encryption surface (no
`nip49` module, no `EncryptedSecretKey`). Per the change constraints we do
**not** implement NIP-49 inside the client. When core adds NIP-49, the sheet
gains a third optional QR (passphrase-encrypted key) behind its own checkbox;
the layout already reserves the optional-block slot used by the sweep section.

## Consequences

- **Pro**: a single printed page backs up the account and onboards a phone; no
  new network surface; the nsec never leaves WASM.
- **Pro**: the QR crate (`qrcode`, pure-Rust, `no_std`-friendly) compiles to
  `wasm32-unknown-unknown` with no JS QR dependency.
- **Con**: a printed bearer credential is physically sensitive — mitigated by
  the red SECRET labelling and the optional sweep/ncryptsec guidance.
- **Con**: ncryptsec deferral means the printed nsec is plaintext until core
  ships NIP-49. Acceptable: the existing `NsecBackup` already prints plaintext;
  the sheet does not regress the threat model.

## Alternatives considered

- **JS QR library** (e.g. `qrcode.js`): rejected — adds a JS dep and risks the
  nsec crossing the WASM/JS boundary into untrusted code. The pure-Rust crate
  keeps the secret inside the WASM heap until the QR SVG is rendered.
- **Server-rendered PDF**: rejected outright — violates the hard invariant.
- **`fast_qr`**: viable wasm alternative; `qrcode` chosen for its direct SVG
  string renderer and zero extra runtime deps.
