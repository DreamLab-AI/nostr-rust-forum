---
id: ADR-2027
title: Reach the nostr.chat cluster by NIP-17 routing changes only; keep NIP-28 channels; consume, never port, the double ratchet
date: 2026-10-20
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: fb9ef30 plus the uncommitted ADR-2025 working tree (assessment only; nothing implemented to verify)
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: A member asking to DM a nostr.chat or Iris user; nostr-double-ratchet reaching a stable minor; any proposal to move public channels off kind 42
repo: nostr-rust-forum
---

# ADR-2027 — Reach the nostr.chat cluster by NIP-17 routing changes only; keep NIP-28 channels; consume, never port, the double ratchet

## Context

`docs/interop/nostr-chat-interop-assessment-2026-10-20.md` compared the deployed board against the
nostr.chat interoperability profile and the Nostr Double Ratchet draft. Our NIP-17 gift wraps are
wire-compatible with the profile; what blocks interop is that DM-relay lists and DMs are published
only to our relay, and that rumor kinds other than 14 are dropped. Public rooms use incompatible
kinds on both sides. The ratchet is a published Rust crate using NIP-44 v2 from the `nostr` crate
plus HKDF-SHA256 from RustCrypto, with no cipher code of its own; a port
would mean maintaining our own ratchet. A full D1 export and a Time Travel bookmark were confirmed
on the production databases, so the board can be backed up without a reset.

## Decision

Proposed:

1. **Option C, NIP-17 overlay.** Resolve the recipient's kind 10050 (fallback 10002) and publish
   each wrap to those relays as well as ours, except that a non-member recipient's copy skips our
   relay, whose recipient gate would refuse it. Publish members' 10050 and 10002 to the public
   indexers only behind an explicit per-member `public_inbox` opt-in, default off. Accept rumor
   kinds 7 (reaction), 5 (deletion) and 15 (file message, received only) on receive; add
   `["e", id, "", "reply"]` and `imeta` on send. Add a requests inbox per profile section 8.1.
   Wire format of rumor, seal, wrap and the `zk` tag is unchanged.
2. **Before any opt-in ships**, zone-key grants (rumor kind 21453) and the agentbox session mirror
   move to their own inbox keys, so a member's other NIP-17 client cannot decrypt them. This
   changes how grants are addressed and requires a relay change first: the gift-wrap gate checks
   the raw `p` key against the whitelist with no device-to-owner lookup (`nip_handlers.rs:1139-1143`),
   so inbox keys must be resolved to their owner, whitelisted or ingress-declared. The inbox key
   needs a cross-device home. Grants already addressed to identity keys remain readable by other
   clients until the subscription changes.
3. **Public channels stay NIP-28 kind 40/41/42.** Option B (kind 34550 + kind 9) is rejected: the
   kind sits inside the signed id, re-signing loses provenance, kind 9 is not ban-gated, and the
   zone gate and sealed history key on kind 42. Option A (a bridge key mirroring unencrypted
   channels) is deferred until a reach requirement exists.
4. **The double ratchet is consumed, not ported, and not yet.** When adopted: depend on
   `nostr-double-ratchet` pinned exact in the unpublished client crate, write our own IndexedDB
   session store, use the `Signer` trait only for the owner-signed kind 37368 roster, generate the
   device key locally and never from the identity key. Preconditions: a stable upstream minor, and a
   relay admission lane keyed on the AUTH'd session principal, because kind 1060 is signed by a
   fresh key each step and carries no recipient tag the whitelist can read. It stays off the agent
   mesh; IS-Envelope remains inside gift wraps.
5. **No reset.** The disaster-recovery runbook in the assessment's section 6 is written and one
   restore into a scratch D1 is exercised before step 1 ships.

## Consequences

- A nostr.chat user can DM an opted-in member and receive replies; nothing a member has not opted
  into leaves our relay.
- Membership of opted-in members becomes visible on the public indexers. The opt-in text must say so.
- Our relay keeps gating inbound wraps on recipient; outbound to foreign relays never consults the
  whitelist. ADR-2023 push wakes a member for an outsider's DM, which is the intended behaviour of
  an open inbox.
- IDENTITY invariant 4 and the baseline's admission citation (`nip_handlers.rs:1135`, not
  `:103-110`) are amended in the same change as step 1.
- Blossom media and Negentropy sync have no counterpart and are not planned.

## Verification

None: no implementation. Adoption requires a test that a wrap published to a foreign relay is
byte-identical to the one published to ours, a test that a kind 21453 grant is never addressed to a
`public_inbox` key, a relay test that an outsider's AUTH plus a wrap to a non-member is still
refused, a relay test that a wrap to a registered inbox key of a member is admitted, and one
exercised D1 restore with the `event_tags` count compared before and after.
