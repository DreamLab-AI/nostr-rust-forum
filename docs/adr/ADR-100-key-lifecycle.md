# ADR-100 — Key lifecycle: root rotation, subkey re-derivation, device revocation

- **Status:** Accepted
- **Date:** 2026-06-11
- **Owners:** `nostr-bbs-core` (`keys.rs`, `derive_subkey`), `nostr-bbs-auth-worker`
  (device registry), `nostr-bbs-relay-worker` (AUTH-time attribution), forum client
  (Settings → Devices, recovery sheet).
- **Related:** [ADR-094](ADR-094-deterministic-subkey-derivation.md) (deterministic
  subkey derivation — disclaims compromise isolation), [ADR-095](ADR-095-recovery-device-onboarding-sheet.md)
  (recovery sheet), [ADR-098](ADR-098-connect-magic-link-onboarding.md) (`/connect`
  magic link), [ADR-099](ADR-099-revocable-device-keys.md) (`device_keys` table with
  the `revoked` flag), [ADR-101](ADR-101-multi-device-dm-delivery.md) (multi-device DM
  delivery), [ADR-104](ADR-104-gift-wrap-recipient-admission.md) (gift-wrap admission).

---

## 1. Context

The forum's identity primitives ship across four ADRs but no single record states
the **lifecycle policy** that binds them: when a key rotates, how a compromise is
contained, and the ordering of revocation versus rotation. This left three gaps:

- **ADR-094 §5 explicitly disclaims compromise isolation.** A `derive_subkey`
  child is fully recoverable from the root: it provides domain separation, not
  independence. So a subkey leak that is *also* a root leak is not contained by
  re-derivation alone.
- **ADR-099 introduced `device_keys.revoked`** but defined only the per-device
  revocation mechanism, not the policy around it (cadence, response playbook,
  ordering against rotation).
- **Root rotation in Nostr is identity-fatal.** The pubkey *is* the identity;
  rotating the root means a new pubkey — a new handle, a severed social graph,
  abandoned NIP-05, and DMs encrypted to the old key becoming undecryptable.
  There is no "change the lock, keep the address" in raw Nostr.

A lifecycle policy must therefore make root rotation **rare** and push day-to-day
key churn down onto revocable device keys, which can be cycled with zero identity
cost.

## 2. Decision

### 2.1 Three-tier key model

| Tier | Key | Rotatable? | Cost of rotation |
|------|-----|-----------|------------------|
| Root | master `nsec` (the account identity) | Yes, but identity-fatal | New pubkey → lost handle, social graph, NIP-05, undecryptable old DMs |
| Purpose subkey | `derive_subkey(root, tag)` (ADR-094) | By tag bump (`v1`→`v2`) | Cheap; old/new independent but both root-recoverable |
| Device key | `derive_subkey(root, "device:<uuid>")` registered in `device_keys` (ADR-099) | By revocation + fresh device | Zero identity cost; one-click in Settings |

The **design intent is that device keys absorb day-to-day exposure** (the phone,
the second laptop, the lost device) so the **root is rarely, ideally never,
rotated**. Each device gets its own derived key registered to the master; losing
a device revokes that key, not the identity.

### 2.2 Rotation cadence

- **Device keys:** no fixed schedule. Rotate on the event that warrants it — device
  lost, sold, decommissioned, or suspected compromised. Revoke-and-re-enrol is the
  operation; it is cheap and self-service.
- **Purpose subkeys (tag bump):** rotate when a purpose's key is suspected exposed
  or when a downstream contract requires a clean key (e.g. agentbox mirror tag
  `agentbox-mirror-v1` → `-v2`). Old and new are independent (HMAC domain
  separation) but **both remain recoverable from the root** — a tag bump does
  **not** contain a *root* compromise.
- **Root:** never on a schedule. Root rotation is a **last-resort compromise
  response**, not hygiene. There is no benefit to rotating an uncompromised root
  and the cost is the entire identity.

### 2.3 Compromise-response playbook

Triggered by the **scope** of the compromise, not by which key file leaked:

1. **A single device key is suspected leaked** (phone stolen, device key seen):
   → **Revoke** the device row (`POST /api/devices/revoke`, ADR-099). The relay
   stops honouring it at the next AUTH. Re-enrol a fresh device key if still
   needed. **No root rotation.** This is the overwhelmingly common case and the
   whole reason device keys exist.

2. **A purpose subkey is suspected leaked but the root is *not* believed exposed**:
   → **Bump the tag** (ADR-094 §2 rotation). Re-derive consumers on the new tag.
   The old subkey is now orphaned (no longer used) but cannot be cryptographically
   "revoked" on generic relays — its forum-scoped authority ends when consumers
   stop using it and, where it was a registered device, when its `device_keys` row
   is revoked. **No root rotation.**

3. **The root itself is suspected exposed** (the master `nsec` leaked — e.g. the
   recovery sheet was photographed, the `/connect#k=` link captured):
   → **Root rotation is unavoidable.** Because every subkey and device key is
   `derive_subkey(root, …)`, a root leak compromises *all* of them — revoking
   device rows does **not** help, since the attacker holds the root and can derive
   or sign as any child. The response is:
   1. Generate a **new master keypair** (new identity, accept the handle/graph loss).
   2. Re-establish NIP-05 / profile / relay list under the new pubkey.
   3. Re-enrol devices against the new root (fresh `device_keys` rows).
   4. Announce the migration through whatever social channel survives (the old
      identity should be treated as fully compromised — do not sign a "I moved"
      note that an attacker could also forge; out-of-band where possible).
   This is the expensive path the device-key tier exists to keep us *out of*.

### 2.4 Revocation-vs-rotation ordering

When both a device-key revocation and a key rotation are in play, the ordering is
**revoke first, then rotate, then re-enrol** — and it is load-bearing:

1. **Revoke** the compromised device row(s) first. This is the action with
   immediate relay-enforced effect (next AUTH), so it shrinks the live attack
   surface before anything slower happens.
2. **Rotate** the affected tier (tag bump for a subkey; new master for the root).
   Only meaningful for root/subkey compromise — for a lone device leak, step 1 is
   the whole response.
3. **Re-enrol** fresh device keys against the (possibly new) root *last*, so new
   devices are never registered against a key that is mid-rotation.

Rationale: revocation is the fast, reversible, relay-enforced control; rotation is
the slow, identity-affecting one. Doing the fast containment first means a partial
or interrupted response still leaves the compromised device locked out.

## 3. Consequences

- **Positive.** Root rotation is reframed as a rare emergency, not a routine. The
  device-key tier (ADR-099) is the documented shock absorber that keeps the
  identity-fatal operation off the day-to-day path. A clear playbook maps
  compromise *scope* to the cheapest sufficient response.
- **Honest limit.** ADR-094's disclaimer stands: derived keys are not isolated, so
  a **root** compromise is genuinely identity-fatal and no amount of device
  revocation contains it. The policy minimises the probability of reaching that
  state; it cannot make root rotation cheap.
- **Operational.** Revocation is self-service (Settings → Devices, ADR-099);
  rotation of the root is not automatable in raw Nostr and is documented as a
  manual, last-resort migration.
- **Reversible.** Device-key revocation is the only reversible step (re-enrol).
  Root rotation is irreversible by construction — a new identity is a new identity.
