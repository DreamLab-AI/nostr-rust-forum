---
title: Identity, Keys & Trust — nostr-rust-forum
doc_id: NRF-IDENTITY
version: 0.1.2
status: draft-for-ratification
verified_commit: 0065dd9 (pending-keys section only; older sections keep their earlier stamps)
sources:
  - crates/nostr-bbs-core/src/keys.rs
  - crates/nostr-bbs-auth-worker/src/devices.rs
  - crates/nostr-bbs-relay-worker/src/trust.rs
  - crates/nostr-bbs-relay-worker/src/cron.rs
  - crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs
  - crates/nostr-bbs-auth-worker/src/schema.rs
  - crates/nostr-bbs-bbs-client/src/signer.rs
date: 2026-08-31
---

# Identity, Keys & Trust — nostr-rust-forum

## Purpose

Single source of truth for the cryptographic identity chain: how keys are derived
and rotated, how device keys are provisioned and revoked, how agents are
provisioned, how DMs are delivered and admitted, and how relay trust levels are
promoted and demoted. Ground-truth order: **live code > audit facts > legacy ADR
prose**. Legacy ADRs (094–102, 104) are citable evidence, never authority. System
topology, pod mesh and clients live in the sibling doc `BASELINE-architecture.md`.

## Current State

### Two distinct key-derivation constructions

`nostr-bbs-core::keys` exposes **two different** derivations that must not be
conflated:

1. **`derive_from_prf(prf_output, salt)`** — HKDF-SHA256 from a WebAuthn PRF
   output, salt-separated per identity (`crates/nostr-bbs-core/src/keys.rs:196-205`).
   Used for passkey-backed keys.
2. **`derive_subkey(root, tag)`** — deterministic, purpose-scoped child secret from
   a root secret key, computed as a single raw **HMAC-SHA-256** keyed by the root's
   32 secret bytes with the tag as the message
   (`crates/nostr-bbs-core/src/keys.rs:251-256`; legacy ADR-094). This is *not*
   HKDF — there is no Extract/Expand step; it is the exact JS
   `crypto.createHmac('sha256', root).update(tag).digest()` construction. Same `(root, tag)` always yields the same child; distinct tags give
   domain separation (`agentbox-mirror-v1` vs `agentbox-agent-v1` vs a rotated
   `agentbox-mirror-v2`). This is the cross-stack contract that agentbox's
   JavaScript mirror-key derivation matches byte-for-byte (known-answer JS-parity
   test, `keys.rs:478-486`).

**A derived subkey is recoverable from the root** by anyone holding the root — it
provides *domain separation*, **not** compromise isolation (`keys.rs:240`). This
disclaimer is load-bearing for the device-key and rotation model below.

### Device keys — revocable, gated, default-off

Revocable device keys (legacy ADR-099) let a device onboard without the master
key. The whole feature is gated behind the Worker var `DEVICE_KEYS_ENABLED`, which
enables only on the **exact** string `"true"` (default off) — checked
independently in the auth worker (`crates/nostr-bbs-auth-worker/src/devices.rs:88-92`)
and the relay worker (`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1626-1665`).

The `device_keys` row lives in the **relay worker's D1** (`RELAY_DB` binding), not
the auth worker's, and carries a `revoked INTEGER NOT NULL DEFAULT 0` flag
(`crates/nostr-bbs-auth-worker/src/devices.rs:81-110`). Revocation is a
`revoked = 1` write the relay honours at NIP-42 AUTH time (`devices.rs:7`). When
the feature is off, a known device→owner mapping is **ignored** and the author key
is used as-is (`nip_handlers.rs:531,3010`). On the relay, a device key acts for its
owner for the allowlist, trust level and zone-write only; sanctions apply to both keys
and admin status stays the signing key's own. The read path
(`nip_handlers.rs:1917`) does grant admin READS to a device key via `access_pubkey`
while admin WRITES stay on the signing key; this is intended and predates the
write-path rules above.

### Key lifecycle

Root rotation, subkey re-derivation and device revocation compose into one
lifecycle (legacy ADR-100), owned across `nostr-bbs-core` (`derive_subkey`), the
auth worker (device registry) and the relay worker (AUTH-time attribution).
Rotating a root re-derives every purpose-scoped subkey; because subkeys are
root-recoverable (above), rotation — not per-subkey secrecy — is the compromise
boundary.

### Agent identity provisioning

Agents are commonly **derived** keys (via `derive_subkey`), not freshly generated
ones (legacy ADR-097). Provisioning is consolidated across the auth worker's
governance API (`/api/governance/agents/register`) and the relay worker, which owns
the `whitelist` cohort table and the `agent_registry` table in the
`nostr-bbs-relay` D1.

### DM delivery & gift-wrap admission

DMs use NIP-17/NIP-59 gift-wrap. On the **send** side, multi-device delivery
(legacy ADR-101) fans a DM out to a recipient's registered device keys — this is
the explicitly **deferred phase-2** work of ADR-099 and is **not yet implemented**.
On the **admission** side (legacy ADR-104, implemented), the relay extracts the
gift-wrap (kind 1059) recipient from the first `["p", <hex>]` tag — the recipient,
not the ephemeral author — and accepts only if that recipient is a whitelisted
member (`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:103-110,510-516`).

A recipient declared under `[[ingress]]` in `forum.toml` (ADR-2022) is admitted without a whitelist
row: the deploy renders the list into the relay's `INGRESS_RECIPIENTS` binding and the gate checks it
first, in the gift-wrap branch only (`crates/nostr-bbs-relay-worker/src/ingress.rs`,
`crates/nostr-bbs-config/src/ingress.rs`). A missing or malformed binding fails closed to the
whitelist rule above, and declaring a recipient grants it no cohort, admin right or zone key.

On the **read** side (ADR-2025), every reader verifies the kind-1059's own id and signature
before either NIP-44 layer is opened, then verifies the seal and binds `rumor.pubkey ==
seal.pubkey` (`crates/nostr-bbs-core/src/gift_wrap.rs`, `unwrap_gift_kind` and
`unwrap_gift_with_signer_kind`; the forum client's `zone_crypto::unwrap_any` and the
migrator's `grants::open_gift_wrap` apply the same order). Every error on that path is a fixed
string naming the layer, never serde's or the cipher's text. A rumor carrying a `sig`, or a seal
with tags, is tolerated: the relay admits wraps from clients outside this workspace and stored
DMs must keep opening.

### Onboarding & recovery

- **Recovery/device-onboarding sheet** (legacy ADR-095) — additive to the one-time
  `NsecBackup` card; does not replace it.
- **`/connect` magic-link onboarding** (legacy ADR-098) — adds a magic-link QR to
  the recovery sheet plus a route to consume it.

### Trust levels & inactivity demotion

Trust is a four-level ladder (TL0–TL3) (`crates/nostr-bbs-relay-worker/src/trust.rs`).
Demotion uses **hysteresis**: TL2 is demoted at 90 % of threshold combined with
~6-month inactivity; **TL3 is never auto-demoted** (`trust.rs:9-10,70-85`). The
inactivity-decay sweep is inherently time-driven, so it runs on the **scheduled
(cron) trigger** alongside the profile backfill sweep, not inline
(`crates/nostr-bbs-relay-worker/src/cron.rs:264-272`; legacy ADR-102). Reads tally
at EOSE to drive promotion; the cron sweep drives demotion.

## Known divergences & open items

- **Multi-device DM delivery not implemented.** Legacy ADR-101 is *Accepted* but
  its implementation is the deferred ADR-099 phase-2 work; the send path does not
  yet fan out to device keys. Gift-wrap admission (ADR-104) is unaffected.
- **Device keys default-off.** `DEVICE_KEYS_ENABLED` is off unless the Worker var is
  exactly `"true"`; with it off, device→owner mappings are ignored and revocation
  has no effect at AUTH — the entire ADR-099/100 device story is dormant in a
  default deployment.
- **Subkeys are not compromise-isolated.** `derive_subkey` gives domain separation
  only (`keys.rs:240`); a leaked root exposes every child. Any design that assumes a
  compromised subkey is contained is wrong — rotation of the root is the only
  boundary.
- **Anomaly O1 "unreachable" claim is stale.** The register's O1/R10 claim that
  `check_demotion` / `increment_posts_read` were unreachable is resolved: reads
  tally at EOSE and demotion runs from the cron sweep
  (`crates/nostr-bbs-relay-worker/src/cron.rs:264-272`). Kept here so a reader does
  not re-open a closed finding.
- **BBS client holds key material directly.** The retro client's `BbsSigner` parses
  and holds a `SecretKey` (zeroized on drop) rather than delegating to a forum
  `sign()` seam (`crates/nostr-bbs-bbs-client/src/signer.rs:64,209,224`) — see
  `BASELINE-architecture.md` for the ADR-105 §2.3 divergence.

## Invariants (must not silently change)

1. **`derive_subkey` is a byte-for-byte cross-stack contract** with agentbox's JS
   mirror derivation — the JS-parity known-answer vector (`keys.rs:478-486`) must
   keep passing; changing the HKDF construction silently forks every derived
   identity across both stacks.
2. **`derive_from_prf` and `derive_subkey` are distinct** and must never be
   substituted for one another — different inputs, different security properties.
3. **`DEVICE_KEYS_ENABLED` enables only on exact `"true"`** and is checked
   identically in both workers; any looser parse widens the auth surface.
4. **Gift-wrap admission keys on the recipient `p` tag**, never the ephemeral
   author (`nip_handlers.rs:103-110`). On read, the wrap's own signature is verified before
   decryption and no unwrap error ever carries decrypted bytes (ADR-2025).
   An `[[ingress]]` recipient widens only this branch; it is never consulted for
   the author of a non-gift-wrap event, and the `agent` cohort is never how it is
   named (ADR-2022).
5. **TL3 is never auto-demoted**; demotion stays time-driven on the cron trigger,
   never inline on the hot admission path.
6. **A derived subkey is root-recoverable** — this disclaimer must survive any
   refactor of the key model; removing it invites a false compromise-isolation
   assumption.

## Change process

Any change to a derivation construction, the device-key gate, the trust ladder, or
the gift-wrap admission rule requires: (1) updating the affected section with the
new `file:line`; (2) confirming the touched invariant still holds (and, for
`derive_subkey`, that the JS-parity vector still passes); (3) bumping `version` and
re-recording `verified_commit` from `git rev-parse --short HEAD`; (4) recording the
decision as a new `docs/adr/` ledger entry (copy `docs/adr/TEMPLATE.md`) in the same
change and regenerating the index (`node scripts/adr-index-gen.js docs/adr`). Legacy
ADR prose is evidence, not authority — cite it, do not defer to it.

## Estate closeout qualification — 2026-09-04

The native key suite passes 22 tests including its JS-parity known-answer fixture; executing the current JS implementation remains a separate acceptance task. Exact device gates do not prove deployed revocation. The trust sweep can move TL2 directly to TL0; UPDATE and audit INSERT errors are ignored before returning the planned level, and advancing OFFSET over a shrinking eligible set can skip rows. ADR-2006 is therefore partial. Require committed outcome reporting, stable pagination and recoverable audit/state consistency. Recipient admission and Rust key zeroisation do not establish private delivery or browser-storage erasure.

See the [forum review](../../VisionFlow/docs/estate-review/forum-decisions.md) for scoped evidence and acceptance requirements. Historical verified commits and activation claims are not refreshed by this source review.

## Source qualification — 2026-09-07

Device keys remain default-off under the exact string `"true"`, with a gate at both worker entrypoints. The current implementation shares the pure `core_device_keys_enabled` predicate (`nostr-bbs-core/src/feature_gate.rs`) while the auth worker (`devices.rs:91-104`) and relay worker (`nip_handlers.rs:1649-1663`) independently read and enforce their environment value. Read older “duplicated rather than shared” descriptions in light of [ADR-2004's dated qualification](adr/ADR-2004-device-keys-default-off-dual-worker-gate.md#source-qualification--2026-09-07). Sharing the predicate does not prove live revocation, reconnect or session-cache behaviour; deployment acceptance remains separate.

## Pending: relay group-signing key and group admission — ADR-2030, ADR-2031 (proposed)

Not live. The relay worker holds no signing key at `0065dd9` and publishes an empty NIP-11
`pubkey` (`crates/nostr-bbs-relay-worker/src/nip11.rs:140,191`). ADR-2030 has the relay sign
NIP-29 39000-39003 and ADR-2031 pins a space to that key, so adopting them adds a long-lived
relay key whose pubkey is the home identity of every space it homes. The proposed rules:

- **Custody (ADR-2031 decision 6).** The signing key is separate from the administrator contact
  (NIP-11 `pubkey`) and from the relay-to-relay federation AUTH key (archived ADR-073 D4). It is
  held in Worker secrets, never in the repository or `wrangler.toml`.
- **Pinning (decision 1).** The operator pins the home key in configuration, out of band. It is
  never adopted on first use from NIP-11 `self`, which is advertised for discovery only; a
  mismatch with the pin is an error.
- **Rotation (decisions 6 and 8).** The key is rotated only by a deliberate re-home, which is a
  fork: a new space with fresh membership. Compromise lets the holder sign state until the
  operators re-home; there is no revocation or move.
- **Freshness (decision 4).** Trust in a mirrored membership list lasts L + S = 70 s from the
  home's `created_at` on its last 39002 (L = 60 s lease, S = 10 s clock-error budget); after that
  the list is stale and access is denied. Presence sessions and dataspace streams close within
  D = 90 s of removal at the home. Voice needs a reachable LiveKit API and is bound by
  D_voice = 150 s, with a documented partition exception that needs operator sign-off.
  State order uses the home's monotonic `rev`; `created_at` is wall-clock only and orders
  only equal-`rev` heartbeats (identical content).
- **Coherence (decision 10).** For a zone-backed group the home signs 39002 only while the
  projection is coherent with the cohort authority (`["proj", <cohort-rev>]`); on lag or failure
  it stops signing, so a removed cohort member cannot be kept fresh.
- **One key per role.** The group-signing key is not the VisionClaw node federation key, which
  agentbox holds (round-2 C5), and VisionClaw holds no group-signing key.
- **Bridge read grant (ADR-2030 decision 5).** VisionClaw's bridge key reads private groups under
  a forum-issued grant that is separate from membership: it confers no write, never appears in
  39002, and is revoked by the forum.

Group admission has two layers: for a zone-backed group it is derived from zone cohorts
(ADR-2014); a standalone group takes membership from the home's admitted NIP-29 event stream. The
home signs the authoritative 39002 either way. Neither adds a new trust level; gift-wrap
admission (invariant 4) is unchanged. No invariant is added until the ADRs are accepted and
implemented.
