---
id: ADR-2028
title: Zones adopt the NIP-171 key plane and ticket format; board transport stays signed kind 42; one owner per zone
date: 2026-10-20
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: [ADR-2026]
superseded_by: []
verified_commit: fb9ef30 plus the uncommitted ADR-2025 working tree (design only; nothing implemented to verify)
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: NIP-171 merging or changing its derivation; a zone owner leaving; a request to open a zone to Anagram or nostr.chat members; any proposal to move zone posts off kind 42
repo: nostr-rust-forum
---

# ADR-2028 — Zones adopt the NIP-171 key plane and ticket format; board transport stays signed kind 42; one owner per zone

## Context

`docs/interop/zone-redesign-and-lossy-reset-2026-10-20.md` compared our ADR-2016 zones with the
two group designs in the nostr.chat cluster. Iris's double-ratchet groups use unsigned rumors over
pairwise sessions and remove relay moderation and signed provenance; they do not fit a board.
Anagram's NIP-171 epoch-ticketed groups are structurally our zones, with a standard ticket, a
group identity per zone, and the per-group recovery master that ADR-2026 proposed and could not
finish because concurrent rotations collided. NIP-171's random per-rotation revision resolves
that, and our single relay can enforce one key per zone and epoch, which the draft cannot promise
across relays.

Production holds 502 zone-encrypted posts across 3 zones, 430 of them already sealed under
ADR-2017, and the epoch secrets live only in admin browsers. Posts encrypted from the start are
signed over their ciphertext, so re-sealing them is impossible; the ADR-2017 migrator refuses an
inner event that carries `zk`.

## Decision

Proposed:

1. **Key plane.** Per-zone group identity keypair; epoch keys derived per NIP-171 from a 12-word
   recovery master (BIP-39, PBKDF2, HKDF-SHA256, salt `nip171/group-recovery/v1`, info
   `epoch/<n>/<revision>/<counter>`, random revision per rotation, scalar rejection via
   `k256::SecretKey::from_slice`); group-signed, NIP-44 self-encrypted kind 30078 recovery
   records chained by parent. Composition of `bip39`, `hkdf`, `sha2`, `k256` and `nostr` only.
   The code lives in the unpublished forum-client crate until NIP-171 merges; nothing of the draft
   ticket or record format ships in `nostr-bbs-core`.
2. **Tickets.** `kind:1014`, sealed by the group identity, gift-wrapped to the member, replaces
   rumor kind 21453. The forum client, `nostr-bbs-zone-migrate` grant fetch and the agentbox
   zone-key module read 1014 before issuance switches; 21453 issuance stops one release later.
3. **Legacy epochs are imported.** Each zone's existing random epoch keys go into one
   project-private kind 30078 record under its own `d` namespace, group-signed and NIP-44
   self-encrypted, outside the recovery chain. Written by a person who holds every legacy key and
   the master. No re-sealing.
4. **Binding.** Zone to group pubkey is bound in `ZONE_CONFIG` and served by the relay. The `zk`
   tag may carry the group pubkey as a fifth element as a hint; readers check it against the
   binding and never trust it alone.
5. **Transport.** Board posts and kanban stay signed kind 42, 30301 and 30302 with `zk`
   encryption. Relay zone gate, ban gate, channel scoping, threads and sealed history are
   unchanged.
6. **Epoch numbering.** One number space per zone. Genesis epoch 0 is record-only; the first live
   derived epoch is n+1 after legacy n. The client store is keyed by zone, group pubkey, epoch and
   pubkey and refuses to send while two keys claim an epoch. The relay refuses a `zk` whose pubkey
   differs from the first stored for that zone and epoch.
7. **Ownership.** One owner per zone holds the master and group identity. Auto-grant runs only in
   the owner's browser. Other admins keep moderation and cohort rights. Owner change is a re-key:
   new master, new identity, new tickets. History for a new member comes from the imported-epoch
   record and the current ticket. Owner backup per the draft, kind 30078 self-encrypted to the
   owner, plus a printed copy.
8. **Anagram-visible mode**, per-zone opt-in, off by default: zone chat additionally as NIP-171
   kind 14 rumors to the epoch pubkey with `h`, `epoch`, `invited_at`, `invitation_proof`. Relay:
   admin-maintained recipient-only set of current epoch pubkeys, never the author whitelist or
   environment config; a cohort read rule so no member authenticates as the epoch key; explicit
   note that kind 1059 is outside the ban gate. Core: a rumor parse path that keeps the signature,
   a recorded departure from NIP-59. The group identity pubkey is never an author; a bare kind
   1014 from any whitelisted author is refused.
9. **Not adopted.** Iris sender-key groups for the board. Reconsider for the agent mesh only.

## Consequences

- Zone history becomes recoverable from the mnemonic plus the relay, including legacy epochs,
  retiring the standing risk that a lost admin browser loses three zones.
- No forward secrecy within an epoch and none against master compromise; a master holder cannot
  be revoked by rotation. Stated to zone owners in the UI.
- The project-private grant kind disappears in favour of a published draft format; message
  transport for the board remains ours, so Anagram reads a zone only in the opt-in mode and never
  the kanban.
- ADR-2016 history grants (earlier epochs sent to new members) are replaced by the imported-epoch
  record. ADR-2016 and ADR-2017 are amended; ADR-2026 is superseded. IDENTITY invariants on grant
  acceptance ("seal author is admin") change to "seal author is the zone's bound group identity".

## Verification

None: no implementation. Adoption requires, in order: the NIP-171 test vector green in the client
crate; a relay test that a `zk` with a second pubkey for a stored zone and epoch is refused; a
client test that a ticket sealed by a key other than the bound group identity is rejected even
when the `zk` hint names that key; a test that a derived epoch below the legacy maximum is never
selected for writing; one zone migrated end to end on a scratch deployment with the L0 export
taken first and the event-tag count compared after.

## Amendment (ADR-2029, proposed)

In the `room` deployment profile, decision 8's Anagram-visible kind-14 transport is the only
private transport, there is no `zk`-tagged kind 9, and the kind-42 zone gate of decision 5 does
not exist. `ZONE_CONFIG` cohorts, the zone-to-group binding of decision 4 and `zk`-encrypted
kanban and calendar remain in both profiles. The DreamLab board, on the `forum` profile, is
unaffected.
