# ADR-101 — Multi-device NIP-17 DM delivery

- **Status:** Accepted (implementation deferred — the ADR-099 phase-2 work)
- **Date:** 2026-06-11
- **Owners:** `nostr-bbs-forum-client` (the DM send path), `nostr-bbs-auth-worker`
  (device registry read), `nostr-bbs-relay-worker` (gift-wrap admission, unchanged
  by this ADR).
- **Related:** [ADR-099](ADR-099-revocable-device-keys.md) (revocable device keys —
  this is its explicitly deferred phase 2), [ADR-100](ADR-100-key-lifecycle.md)
  (key lifecycle), [ADR-104](ADR-104-gift-wrap-recipient-admission.md) (gift-wrap
  recipient admission — the relay rule this delivery model must satisfy).

---

## 1. Context

ADR-099 ships device keys that fully work for the **public** forum surface (read,
post, zones, governance) and are revocable in one click. It explicitly defers
**private DMs** to phase 2, for a hard cryptographic reason:

> A NIP-17 / NIP-59 gift-wrap is encrypted to **exactly one** recipient pubkey. A
> device key cannot decrypt a gift-wrap addressed to the master.

So a user who onboards a phone with a device key (ADR-098/099) sees the full forum
but receives **no DMs** on that phone — the gift-wraps are encrypted to their
master, which only lives on the signup device. The relay reinforces this: the
kind-1059 `#p` filter in `handle_req` deliberately stays on the literal
`session_pubkey` and is **not** rebound to the owner
(`relay_do/nip_handlers.rs:649-657`), precisely so a device key cannot pull down
owner DMs it could never decrypt.

Phase 2 is therefore a **send-path** problem, not a relay problem: to reach every
device, the sender must produce one gift-wrap per recipient *device*, since each is
a distinct decryption target.

## 2. Decision

**Our client multi-wraps every outgoing DM** to the recipient's master key **and**
to each of the recipient's registered, non-revoked device keys.

### 2.1 Send path

When the forum client sends a DM to recipient `R`:

1. Resolve `R`'s delivery set: `R`'s master pubkey **plus** every row in
   `device_keys WHERE owner_pubkey = R AND revoked = 0` (read via the
   auth-worker device endpoint, ADR-099's `GET /api/devices` generalised to a
   per-owner lookup the sender is permitted to read).
2. Produce **one NIP-59 gift-wrap per pubkey** in that set — the same rumour/seal
   payload, sealed and wrapped independently to each recipient pubkey (each wrap
   has its own ephemeral author and its own `#p` tag).
3. Publish all wraps. The relay admits each by its `#p` recipient (ADR-104);
   nothing about admission changes.

Each registered device decrypts the wrap addressed to *its* device key; the master
device decrypts the wrap addressed to the master. Revoked devices are excluded at
send time (step 1 filters `revoked = 0`), so a revoked phone receives nothing
even before the relay would have stopped honouring it.

### 2.2 Graceful degradation

This is a **first-party send-path enhancement only**. It does not change the wire
format and does not require cooperation from other clients:

- A **generic outside client** (0xchat, Amber, any stock Nostr client) sending to
  `R` knows nothing of `R`'s device registry and wraps **only to the master**. The
  master device receives that DM; `R`'s device-key phones **miss it**. This is the
  acknowledged honest caveat from ADR-099 — degradation is silent and bounded:
  device phones see DMs sent *by forum-aware clients*, not DMs from the wider Nostr
  world.
- An **incoming** wrap addressed only to the master is delivered to the master
  session by the relay's existing kind-1059 gate; no device sees it. Correct — the
  relay never rebinds `#p` (see ADR-104), so there is no leakage and no spurious
  delivery.

### 2.3 Relation to the gift-wrap admission rule (ADR-104)

This delivery model is admission-compatible with ADR-104 by construction. ADR-104
admits a kind-1059 by **recipient `#p` whitelist membership** without decrypting.
A device key is a whitelisted principal (its `device_keys` row grants the owner's
read scope per ADR-099), so each per-device wrap's `#p` points at a pubkey the
relay already admits. No new admission rule, no relay change, no plaintext
exposure to the relay. Multi-wrapping is purely "send N wraps to N admitted
recipients" — the privacy boundary ADR-104 draws is untouched.

## 3. Implementation (deferred — what changes when phase 2 lands)

The send path is the only place that changes:

- **`forum-client/src/dm/mod.rs`** — the DM send function (currently single-wrap to
  the recipient master) gains a delivery-set expansion: fetch the recipient's
  non-revoked device keys and emit one gift-wrap per pubkey. The existing
  single-wrap path is the `device_keys`-empty (or feature-off) case, so the change
  is additive and degrades to today's behaviour when no devices are registered.
  This is also where O6 (the NIP-07 silent-no-op DM subscription, anomaly register)
  should be addressed, since both touch the DM client surface.
- **`auth-worker` device endpoint** — a sender-readable per-owner device lookup
  (the read side of ADR-099's registry), returning only `{device_pubkey}` for
  `revoked = 0` rows. No private data; device pubkeys are public delivery targets.
- **Relay:** **no change.** `nip_handlers.rs` kind-1059 admission and the
  non-rebound `#p` filter (lines 649-657) are already correct for this model. This
  is the crate the sibling trust-demotion work is editing — phase 2 must not
  perturb the admission path.

Gated behind `DEVICE_KEYS_ENABLED` (ADR-099) like the rest of the device-key
feature.

## 4. Consequences

- **Positive.** Device-key phones become first-class DM recipients for forum-aware
  traffic, closing the one functional gap ADR-099 left open. No wire-format change,
  no relay change, no new admission rule.
- **Negative / accepted.** Fan-out cost grows linearly with a recipient's device
  count (N wraps per DM). Bounded in practice (a user has a handful of devices).
  DMs from generic outside clients still reach only the master — by design, since
  we cannot make stock clients aware of our registry.
- **Privacy.** The relay still never decrypts and still never rebinds `#p`
  (ADR-104). Multi-device delivery is achieved entirely by the sender addressing
  more recipients, not by the relay re-routing anything.
- **Reversible.** Behind `DEVICE_KEYS_ENABLED`; with devices unregistered the path
  collapses to single-wrap-to-master, i.e. today's behaviour.
