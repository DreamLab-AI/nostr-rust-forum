# ADR-098 — `/connect` Magic-Link Onboarding

- **Status**: Accepted
- **Date**: 2026-06-11
- **Deciders**: Forum client maintainers
- **Builds on**: [ADR-095](ADR-095-recovery-device-onboarding-sheet.md) — the
  recovery & device-onboarding sheet. This ADR adds a magic-link QR to that
  sheet and a route to consume it.

## Context

At signup the forum client generates a Nostr keypair entirely in the browser
(`auth.register_with_generated_key`); the secret key is the user's sole bearer
credential. ADR-095 introduced a printable recovery sheet that backs up the key
as QR codes and, for mobile, onboards the third-party **0xchat** client by
encoding the bare `nsec1…`.

That third-party hop has real friction and a worse product outcome:

1. **Wrong surface.** 0xchat / Amber give the user a generic Nostr DM+channel
   client, not *this forum*. The forum's categories, sections, governance
   agents, pod browser, and moderation UX do not exist there. Onboarding a phone
   into a foreign client is a downgrade from the product we actually ship.
2. **Confusing QR semantics.** 0xchat exposes two QR flows — "Login with private
   key" (paste the nsec) and "Login with QR code" (a *remote-signer* / bunker
   pairing QR). Users conflate them. The recovery sheet's nsec QR only works with
   the former, and the labelling never made that explicit.
3. **No first-party mobile on-ramp.** The forum is a PWA. A phone can run the
   full forum in the browser, but there was no friction-free way to move the
   in-browser key from the signup device to the phone.

Modern phone cameras (Android, iOS) detect an HTTPS URL in a QR and offer to open
it directly. If that URL opens the forum PWA and self-authenticates, the phone is
in the **full forum** in one scan — no app install, no client switch.

## Decision

Add a first-party magic-link onboarding flow:

- The recovery sheet emits a **📱 "Open on this phone"** QR encoding
  `{origin}{FORUM_BASE}/connect#k=<nsec1…>`, computed from the **live** browser
  origin so the link targets the exact deployment the user signed up on. This is
  the **primary** mobile path on the sheet.
- A new **`/connect`** route reads the key from the URL **fragment**, imports it
  through the **existing local-key auth path** (`auth.login_with_local_key`, the
  same import the login page uses for a pasted recovery key — including the
  existing NIP-19 bech32 decode), signs the device in, and redirects into the
  forum.
- The existing 🔑 nsec QR is **relabelled** as the power-user path: paste into
  0xchat's "Login with private key", or scan into Amber — explicitly **not**
  0xchat's "Login with QR code" (a remote-signer QR). 0xchat/Amber remain an
  optional power path, not the default.

## Hard security invariants (non-negotiable)

> The secret key MUST live only in the URL **fragment** and MUST be stripped from
> browser history **before** it is imported.

1. **Fragment only — never transmitted.** The key is encoded after `#`
   (`…/connect#k=<nsec>`). URL fragments are **not** included in the HTTP request
   line, so the server / relay / any proxy never receives the nsec. The key is
   never placed in a query string and never sent anywhere. This is the entire
   reason the flow is safe over plain navigation.
2. **History strip happens first.** On `/connect` mount, the page:
   1. reads `window.location().hash()` and parses `#k=<key>` (a leading `k=` is
      stripped; a bare `#<key>` is tolerated),
   2. **immediately** calls `history.replaceState(null, "", "{FORUM_BASE}/connect")`
      to rewrite the visible URL — *before* any validation, any import, and any
      `await* — so the nsec never lingers in the address bar, history, or the
      back button,
   3. only *then* validates and imports the key.

   The ordering is load-bearing: read → strip → import. There is no `await`
   between reading the fragment and stripping it.
3. **HTTPS only.** The phone camera opens the `https://` origin; the PWA is
   served over TLS. The fragment is therefore confidential in transit (it is not
   sent at all) and the page load itself is encrypted.
4. **Strict validation, no silent fallback.** `/connect` accepts `nsec1…`
   (bech32, decoded via the existing NIP-19 path inside `login_with_local_key`)
   or a 64-char hex key. Anything else is rejected with a clear error and a link
   to `/login` — no import is attempted, no signer is set.

## Bearer-credential risk (accepted, surfaced)

A magic link that signs you in **is** the account. Whoever holds that QR or URL
can sign in as the user — there is no second factor, by design (the whole point
is a frictionless camera scan). We accept this and mitigate by *surfacing* it
loudly:

- The recovery-sheet 📱 block carries a red "This link/QR IS your account"
  warning and instructs the user to keep the sheet private.
- On successful `/connect` sign-in the page shows a red bearer-credential
  warning ("anyone who had that QR/link can sign in as you — keep your recovery
  sheet private") before redirecting.

The residual risk is identical in kind to the nsec QR that already exists on the
sheet (ADR-095); the magic link does not expand the attack surface beyond "the
sheet is a bearer secret — protect it", which was already true. The fragment-only
+ history-strip invariants ensure the link is no *more* exposed than the nsec it
wraps: it never reaches a server and does not persist in the browser after
consumption.

## Why this beats third-party clients

- **Full forum surface.** One camera scan and the phone is in *this* forum — all
  categories, governance, pod browser, moderation — not a generic Nostr client.
- **Zero install.** No app store, no client choice, no relay-add step (the PWA
  already knows its relay).
- **No QR-semantics confusion.** The user scans one camera-native HTTPS link; the
  ambiguous "Login with QR code" remote-signer flow is explicitly steered away
  from.
- **Power path preserved.** 0xchat (Login with private key) and Amber (Login
  with Amber) remain available via the relabelled 🔑 nsec QR for users who want a
  dedicated signer / multi-account client.

## Consequences

- New non-auth-gated route `/connect` (it is the route that authenticates; gating
  it would deadlock). Placed next to `/login` in `src/app.rs`.
- New `web-sys` feature `History` for `replace_state_with_url`.
- The recovery sheet gains a fourth QR; the print stylesheet already scopes all
  `.rs-qr svg` sizing, so the new block prints on the sheet unchanged.
- The connect URL embeds the nsec; the sheet is, as before, a bearer secret to be
  stored offline. No new durable storage and no new network surface are
  introduced — `/connect` reuses `login_with_local_key` verbatim.

## Alternatives considered

- **Keep onboarding via 0xchat only.** Rejected: wrong surface, install friction,
  QR-semantics confusion (see Context).
- **Encode the key in a query string.** Rejected outright: query strings are sent
  to the server, violating the no-server-sees-the-key invariant.
- **Encrypt the key in the link (NIP-49 ncryptsec).** Deferred for the same
  reason ADR-095 deferred it: `nostr-bbs-core` exposes no NIP-49 surface yet.
  When it does, the magic link can carry an `ncryptsec1…` with a short passphrase
  prompt on `/connect`, downgrading the bearer-credential risk. Tracked as a
  follow-up to this ADR.
