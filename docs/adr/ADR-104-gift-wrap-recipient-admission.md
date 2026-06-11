# ADR-104 — NIP-59 gift-wrap recipient admission and relay gating

- **Status:** Accepted
- **Date:** 2026-06-11
- **Owners:** `nostr-bbs-relay-worker` (`relay_do/nip_handlers.rs` — the admission
  gate), `nostr-bbs-core` (NIP-59 transport), forum client (DM send/subscribe).
- **Related:** [ADR-099](ADR-099-revocable-device-keys.md) (device-key effective
  pubkey), [ADR-100](ADR-100-key-lifecycle.md) (key lifecycle),
  [ADR-101](ADR-101-multi-device-dm-delivery.md) (multi-device DM delivery — the
  send-path counterpart). Ground-truth map:
  [docs/diagrams/relay-event-admission.md](../diagrams/relay-event-admission.md).

---

## 1. Context

The relay must admit private DMs (NIP-17 over NIP-59 gift-wrap, kind-1059) onto a
whitelisted forum **without ever seeing plaintext** and **without trusting the
event author**. NIP-59 makes the author untrustworthy by design: every gift-wrap
is signed by a **fresh ephemeral key**, generated per message, that is *never*
whitelisted and carries no identity. Admitting kind-1059 by author would either
reject every DM (the ephemeral key is unknown) or, if the relay tried to relax the
author check, open an unauthenticated write channel.

The relay also cannot read who the DM is *for* by decrypting it — the payload is
sealed to the recipient. The only thing the relay can see in the clear is the
gift-wrap's **`#p` recipient tag**, which NIP-59 places on the outer wrap precisely
so relays can route without decrypting.

This ADR records the admission rule already implemented in
`relay_do/nip_handlers.rs` and, more importantly, **why the privacy boundary is
drawn exactly there.**

## 2. Decision

### 2.1 The admission rule

The relay admits a kind-1059 event by checking that its **recipient `#p` tag** is a
member of the relay's whitelist — **not** the ephemeral author:

- `gift_wrap_recipient()` (`nip_handlers.rs:87-95`) extracts the first `p` tag from
  the wrap.
- That recipient pubkey is run through the standard whitelist check
  (`is_whitelisted`, `storage.rs:310-326`) — the same allowlist gate every other
  event passes, but keyed on the **recipient** rather than the author.
- If the recipient is whitelisted, the wrap is admitted, stored, and delivered to
  the recipient's authenticated session (the kind-1059 delivery gate,
  `broadcast.rs:41-67`, only fans a 1059 out to the session whose `authed_pubkey`
  equals the wrap's `#p`). If not, it is rejected `["OK", id, false, ...]`.

The author signature is still verified (the wrap is a valid signed event), but the
*authorisation* decision is made on the recipient, because the author is
deliberately anonymous.

This is the most architecturally significant branch in the admission waterfall
(`nip_handlers.rs:181-207`): the gift-wrap split is the one place admission keys on
the recipient instead of the author.

### 2.2 The privacy boundary — and why it sits here

**The relay never decrypts.** It sees three things in the clear: that the kind is
1059, the ephemeral author (which it ignores for authz), and the `#p` recipient. It
sees the *fact that an admitted member is receiving a DM* and *who from the wider
key space sent the outer wrap* (an ephemeral key — i.e. nothing). It does **not**
see the sender's real identity, the recipient's reply, or any content.

The boundary is drawn at "recipient membership" rather than anywhere deeper for
three reasons:

1. **It is the strongest check the relay can make without plaintext.** Recipient
   membership is the only authorisation signal visible on an end-to-end-encrypted
   wrap. Drawing the line here admits exactly "DMs *to* our members" and nothing
   else — the minimum the relay must know to route, and no more.
2. **Author-based admission is impossible by NIP-59 construction.** The author is a
   per-message throwaway; there is no author identity to admit. Any attempt to
   authorise on the author would be either always-reject or a hole.
3. **Anything stricter would require decryption.** To check *who really sent it* or
   *what it says*, the relay would have to break the gift-wrap — defeating the
   entire privacy model. The boundary is therefore the deepest the relay can probe
   while remaining a zero-knowledge router of sealed payloads.

### 2.3 Device-key effective-pubkey attribution

Under ADR-099, a device key acts with its owner's read scope. For gift-wrap
admission and delivery this interacts carefully:

- **Admission** keys on the wrap's `#p` recipient pubkey directly. If a sender
  multi-wraps to a device key (ADR-101), that wrap's `#p` is the **device pubkey**,
  and the device pubkey is itself an admitted principal (its `device_keys` row
  grants the owner's scope, ADR-099 §2.2). So device-addressed wraps are admitted on
  the device pubkey's whitelist standing — no special case.
- **Delivery `#p` is NOT rebound to the owner.** This is the load-bearing subtlety
  recorded at `nip_handlers.rs:649-657`: the effective-pubkey resolution
  (`effective_pubkey()` → `effective_principal()`, `nip_handlers.rs:1098-1132`)
  rebinds **zone/cohort read scope** from device to owner, but the kind-1059 `#p`
  filter in `handle_req` deliberately **stays on the literal `session_pubkey`**. A
  device session therefore receives only wraps addressed to *its own* device key —
  never the owner's master-addressed wraps, which it could not decrypt anyway.
  Rebinding `#p` to the owner would hand a device session ciphertext sealed to the
  master: useless to the device and a needless widening of who-receives-what.

So the attribution rule is: **device keys borrow the owner's *read scope* for the
public forum, but DM recipiency stays per-key.** Public read is fungible across a
user's devices; private decryption is not.

## 3. Consequences

- **Positive.** Private DMs flow on a whitelisted relay with the relay as a
  zero-knowledge router: it authorises on recipient membership, never on the
  anonymous author, never on plaintext. The boundary admits the minimum necessary
  fact (a member is receiving a DM) and nothing more.
- **Negative / accepted.** The relay learns *that* member X received a wrap and at
  what time (metadata), even though it learns nothing about content or true sender.
  This is inherent to any relay that routes by recipient and is the accepted floor
  for NIP-59 on a gated relay.
- **Interlock.** ADR-101 multi-device delivery rides this rule unchanged — each
  per-device wrap is admitted on its own `#p`. The non-rebound `#p` filter is the
  invariant both ADRs depend on; changing it would break recipiency isolation.
- **Stability.** This admission path lives in the same file
  (`relay_do/nip_handlers.rs`) as concurrent trust-demotion work (ADR-102); the
  gift-wrap recipient gate and the non-rebound `#p` filter are invariants that
  trust-level changes must preserve.
