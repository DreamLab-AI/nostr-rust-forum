---
id: ADR-099
title: Revocable device keys — tear-off mobile onboarding without the master key
status: Proposed
date: 2026-06-11
related: [ADR-094, ADR-095, ADR-097, ADR-098]
---

# ADR-099: Revocable Device Keys

## Status

Proposed (2026-06-11). Built behind a gate (`DEVICE_KEYS_ENABLED`, default off) —
queued for later activation. Multi-device DM delivery is explicitly phase 2.

## Context

ADR-098 puts the **master** key on the phone via a `/connect#k=` magic link.
That is a bearer copy of the whole identity: lose the phone and the only
recovery is to rotate the master — which in Nostr means a *new identity*
(new handle, lost social graph). The operator asked for a **tear-off** sheet
section carrying a key the user can **revoke from their master** if the phone is
lost.

Generic Nostr makes true revocable delegation hard:
- **NIP-26** (delegation tokens) is the technically-correct "child signs as
  master", but revocation is expiry-only and major clients have dropped it.
- **NIP-46** (remote signing) revokes cleanly but the phone holds no key — it
  asks an online master signer to sign. Too much infrastructure for a sheet.
- **NIP-17 DMs are encrypted to exactly one pubkey** (the master), so a child
  key literally cannot decrypt the master's DMs.

We own the relay, auth, and client, so a **forum-scoped device key** is
tractable where generic Nostr is not.

## Decision

A **device key** is a deterministic subkey (ADR-094,
`derive_subkey(master, "device:<uuid>")`) registered to its owner and honoured
by our relay/forum, revocable in Settings. It never exposes the master key to
the phone.

### Components

1. **Registry** (auth-worker, ADR-097-adjacent). A `device_keys` row in the
   relay's D1 (so the relay can read it at AUTH without a cross-worker call):

   ```sql
   CREATE TABLE IF NOT EXISTS device_keys (
     device_pubkey TEXT PRIMARY KEY,   -- 64-hex child/device key
     owner_pubkey  TEXT NOT NULL,      -- 64-hex master account
     label         TEXT,               -- "My phone"
     created_at    INTEGER NOT NULL,
     revoked       INTEGER NOT NULL DEFAULT 0
   );
   ```

   Endpoints (NIP-98, signed by the **master**):
   `POST /api/devices/register {device_pubkey,label}` (owner derived from the
   NIP-98 author), `GET /api/devices` (list own), `POST /api/devices/revoke
   {device_pubkey}` (sets `revoked=1`). Idempotent.

2. **Relay attribution** (relay-worker). At NIP-42 AUTH, if the authing pubkey
   is a non-revoked `device_keys` row, the session is granted the **owner's**
   cohorts/zone access (the device acts with the owner's read scope). On write,
   a device-authored event is accepted under the owner's allowlist and the
   relay records an owner-attribution tag so the client renders it as the owner.
   Gated by `DEVICE_KEYS_ENABLED`; when off, a device key is just an unknown
   pubkey (fails the allowlist) — fully inert.

3. **Tear-off sheet** (forum-client, builds on ADR-095/098). A *separable*
   card on the recovery sheet carrying `{/connect#k=<device-key>}` (the same
   ADR-098 route — a device key in the fragment instead of the master). Print
   CSS marks it as a tear-off. Settings → **Devices**: list + revoke.

### What works, and the honest caveat

- **Public surface fully works + is revocable**: read channels, post (attributed
  to the owner), zone access, governance — revoke in Settings and the relay
  stops honouring the device immediately.
- **Private DMs are phase 2.** A child key cannot decrypt the master's
  gift-wraps. To deliver DMs to the phone, our client must multi-wrap each DM to
  the recipient's master **and** their registered devices (multi-device NIP-17).
  We can do this since our client + registry control sending; it degrades
  gracefully (a DM from a generic outside client only reaches the master, so the
  phone misses *those*). Deferred to phase 2 to keep this change bounded.

## Consequences

- **Positive.** A lost phone is revoked in one click without touching the master
  identity. No master key on the device. Reuses ADR-094 derivation, ADR-097
  registry pattern, ADR-098 `/connect` route.
- **Negative / scope.** Forum-only semantics (a device key is itself on generic
  relays/clients). DMs need phase-2 multi-wrap. Relay attribution is
  security-load-bearing — gated off until reviewed and activated.
- **Reversible.** Entirely behind `DEVICE_KEYS_ENABLED`; off = no behaviour
  change anywhere.
