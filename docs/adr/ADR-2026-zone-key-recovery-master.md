---
id: ADR-2026
title: Derive zone epoch keys from a 12-word recovery master so a lost admin device does not lose a zone
date: 2026-10-19
decision_status: superseded
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: [ADR-2028]
verified_commit: fb9ef30 (proposal only; nothing implemented to verify)
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: An admin losing every device holding a zone key, or a second admin joining an encrypted zone
repo: nostr-rust-forum
---

# ADR-2026 — Derive zone epoch keys from a 12-word recovery master so a lost admin device does not lose a zone

## Context

ADR-2016 makes each `(zone, epoch)` keypair random and keeps it only in key-holders' IndexedDB;
its consequences list recovery as follow-on work. lnbits/anagram's NIP-171 draft derives a group's
epoch keys from a 128-bit master shown once as 12 BIP-39 words: HKDF-SHA256 over the BIP-39 seed,
with a domain salt and per-epoch info, rejection-sampling a counter when the output is not a
valid scalar, and a random per-rotation revision so concurrent rotations to the same epoch number
never share a key. The advisor review of a first adaptation (2026-10-19) found that dropping the
revision lets an out-of-sync admin device re-derive an epoch secret that removed members still
hold, which today's random keys can never do. This record keeps the corrected design so it is not
re-derived from scratch.

## Decision

Proposed, not adopted. If adopted, the construction is:

- One master per zone, generated at "Create key (epoch 1)", shown once as 12 words, never stored
  in plaintext in the shared `members-forum` IndexedDB (either not stored at all and asked for at
  rotate time, or stored NIP-44-encrypted to the admin's own pubkey through the signer).
- `epoch_secret = HKDF-SHA256(ikm = bip39_seed(master, ""), salt = "nostr-bbs/zone-recovery/v1",
  info = "zone/" + len(zone_id) + "/" + zone_id + "/epoch/" + n + "/rev/" + r + "/" + counter)`,
  32 bytes, counter incremented only while the output is zero or at or above the curve order.
  The zone id is length-prefixed so a "/" in an id cannot alias another zone.
- `r` is a small bounded revision (0..k). Rotation takes the first `r` whose derived pubkey has
  not been seen in any `zk` tag for `(zone, n)`, and refuses to rotate unless `n` exceeds the
  highest epoch seen on the relay for that zone. Recovery derives `r` in 0..k for each `(zone,
  n)` seen and accepts only when the pubkey matches the `zk` tag. No NIP-78 recovery records are
  needed because the `zk` tag already publishes `(zone, epoch, zone-pubkey)` on every message.
- Recovery never overwrites a held key whose pubkey differs for the same `(zone, epoch)`.
- Existing random epochs stay valid and unrecoverable; grants and the `zk` tag are unchanged.
- Dependencies: `bip39` (already in the lockfile via `nostr`) and `hkdf`, in the unpublished
  client crate only, per the rule that project-specific constructions are never published.

## Consequences

- A master holder can derive every future epoch; rotation no longer evicts an admin. Replacing a
  master means a new zone identity, which this record does not design.
- Two admins sharing a master converge on the same key, but each grants it to their own audience;
  concurrent removals can leave both removed members holding the new key unwarned.
- Recovery has to fetch every kind-42 in the zone's channels (relays cannot filter on `zk`);
  an epoch with no messages cannot be recovered.
- ADR-2016's "random per epoch" sentence would need amending in the same change.

## Verification

None: no implementation. Adoption requires a known-answer test vector pinned in the client crate
(anagram publishes one for its construction), a test that rotation refuses a seen pubkey, and a
test that recovery leaves a differing held key untouched.
