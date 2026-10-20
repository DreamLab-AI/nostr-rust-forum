---
title: Lossy reset tolerance, and zones redesigned around the ecosystem's group schemes
date: 2026-10-20
status: assessment and design (no code changed)
inputs: production D1 counts (read-only, 2026-10-20); nostr-chat-interop-assessment-2026-10-20.md; lnbits/anagram nips/nip171.md and docs/private-groups.md; nostr-double-ratchet 0.0.170 group_wire.rs, sender_key.rs; ADR-2016, ADR-2017, ADR-2026
method: build-with-quality; advisor consulted at plan checkpoint (ADR-2134) before this text was locked
---

# Lossy reset tolerance, and zones redesigned around the ecosystem's group schemes

## Part A. Is a lossy reset acceptable for the forum?

### What the board actually holds

| Measure | Count | Source |
|---|---|---|
| Members | 17 | auth D1 `members` |
| Channels | 12 | kind 40 |
| Channel posts | 597 | kind 42 |
| Posts that are zone-encrypted (`zk` tag) | 502 | `event_tags` |
| Posts that are sealed re-issues from the ADR-2017 migration | 430 | `event_tags` |
| Plaintext posts | about 95 | difference |
| Encrypted zones | 3 | distinct `zk` zone values |
| Kanban boards and cards | 2 and 24 | kinds 30301, 30302 |
| Governance records | 72 | kinds 31400 to 31405 |
| DM gift wraps | 1,286 | kind 1059 |
| Of which older than 30 days | 205 | |
| Of which in the last 30 days | 1,083 | mostly the per-turn agentbox session mirror |

Two facts dominate. Five posts in six are encrypted, so "the posts" are the zone keys. And
nearly three posts in four have already been through one lossy transformation: the ADR-2017
migrator replaced them with admin-authored sealed envelopes carrying the original inside.

### Levels of loss, and whether each is acceptable

| Level | What is lost | Acceptable? | Why |
|---|---|---|---|
| L0, byte-exact restore | Nothing | Baseline | D1 export plus import, or D1 Time Travel. Available today. |
| L1, operational metadata | Relay receipt times, admin log (301 rows), broker cases (254), push subscriptions | Yes, with the D1 export kept as an archive | None of it is member-visible. Governance receipts (60) must survive, and they are in the same export. |
| L2, history re-authored as sealed envelopes | Original events replaced by admin-sealed copies. Original id, author, timestamp and reply tags survive inside and are substituted on read, so reactions, replies and deletions still attach. The relay-level author becomes the migrator. | Yes, for plaintext originals only | This is the ADR-2017 precedent, already applied to 430 posts in production. It cannot be applied to posts that were zone-encrypted from the start: their author signatures cover the ciphertext, so no sealed plaintext can be produced for them. |
| L3, encrypted history unreadable | All 502 encrypted posts, if the epoch secrets are lost | No, unless the three zones' members agree in writing | Unrecoverable by construction. There is no key escrow today; the secrets live in admin IndexedDB only. This is the single largest risk on the board and it exists now, reset or no reset. |
| L4, DMs lost | 1,286 wraps | Yes for the mirror traffic, with notice for the rest | About 1,083 wraps are the operator's own session mirror and are reproducible from the agentbox transcripts. The 205 older wraps are member DMs and would need notice. No other client holds them, because our relay is the only one they were ever published to. |
| L5, identities reset | Members re-onboard under new keys. Authorship detaches from 35 profiles, trust levels and cohorts reset, every signed post becomes orphaned provenance | No | Nothing in either interop path requires it. Signatures bind author keys; content cannot be re-authored without forging. |
| L6, full wipe | Everything | No | Survivable for a 17-member board in raw effort, but pointless when L0 costs one command. |

### Verdict

A lossy reset is acceptable only at levels L1, L2 and the mirror part of L4. L2 is bounded: it
applies to plaintext originals, and the board has already absorbed it once. It does not let the
zone redesign in Part B rewrite encrypted history, which is why Part B imports the legacy epoch
keys instead. L3 is not a reset question at all; it is the standing risk the redesign should
retire by giving zone keys a recorded home. Levels L5 and L6 are rejected: no protocol pivot
under consideration needs them, and the byte-exact path is exercised.

Preconditions for any reset, in order: the two D1 exports with checksums, the Time Travel
bookmark, the three zones' current epoch secrets exported from an admin browser into the
recovery format of Part B, and one restore rehearsed into a scratch D1 with the event-tag
count compared.

## Part B. Zones and epochs redesigned around the ecosystem

### The ecosystem has two group designs, and only one is a ratchet

| | Iris, Nostr Double Ratchet groups | Anagram, NIP-171 epoch-ticketed groups | Our zones (ADR-2016) |
|---|---|---|---|
| Key plane | Per-sender key chains (sender keys) distributed over pairwise double-ratchet sessions; kind 37368 roster facts, 10446 distribution, 10447 repair | One epoch keypair shared by current members; rotated on removal; derived from a per-group 12-word recovery master with HKDF and a random per-rotation revision | One random epoch keypair per zone and epoch; rotated on removal; no derivation, no recovery |
| Membership proof | Device roster signed by owner | `kind:1014` ticket signed by the group identity; each rumor carries the ticket's signature as `invitation_proof` | Relay whitelist and cohort; grant accepted only if the seal author is an admin |
| Transport | Unsigned kind 14 rumors, one-to-many outer events | NIP-17 gift-wrapped kind 14 rumors addressed to the epoch pubkey, `h` tag = group identity | Signed kind 42 with `zk` tag, content NIP-44 encrypted author-to-epoch-key |
| Relay sees | Ratchet envelopes; nothing about group or sender | Gift wraps to the epoch pubkey; nothing about sender or channel | Author, channel, kind, zone id, epoch; not the text |
| Forward secrecy | Per message | None within an epoch; none against master compromise | None within an epoch |
| Recovery | Device re-link; no history for new devices | Mnemonic restores identity and all recorded epochs | None |
| Fit for a board | Poor: removes relay moderation and signed provenance, needs a pairwise session with every member and device | Close: same shape as ours, adds the recovery plane we lack | Current |

NIP-171 is not a double ratchet. It is our design with a standard ticket format, a group
identity per zone, and the recovery master that ADR-2026 proposed yesterday, including the random
revision that makes concurrent rotations safe, which was the reason ADR-2026 stopped at proposed.

### Decision shape: NIP-171 key plane, our transport, Anagram transport as an opt-in

1. **Key plane adopts NIP-171 verbatim, in the client crate.** Each zone gets a group identity
   keypair. Epoch keys are derived from a per-zone recovery master: BIP-39 12 words, PBKDF2 seed,
   HKDF-SHA256 with salt `nip171/group-recovery/v1` and info `epoch/<n>/<revision>/<counter>`,
   revision random per rotation, scalar rejection through `k256::SecretKey::from_slice`. The
   draft's test vector must pass before anything else lands. Recovery records are group-signed
   kind 30078, NIP-44 self-encrypted, chained by parent ids. All of this is composition of the
   `bip39`, `hkdf`, `sha2`, `k256` and `nostr` crates; no primitive is written here. It lives in
   the unpublished forum-client crate, as ADR-2016 and ADR-2026 required, until NIP-171 merges;
   nothing of a draft ticket or record format ships in the published core crate.
2. **Grants become `kind:1014` tickets** sealed by the group identity and gift-wrapped to the
   member. The project-private rumor kind 21453 stays readable for one release, then issuance
   stops. Three readers of 21453 must switch first: the forum client, the zone migrator's grant
   fetch, and the agentbox management API's zone-key module in its own repository.
3. **Legacy epochs are imported, never re-sealed.** Today's random epoch keys cannot be derived
   from a master. Re-sealing their posts is impossible: a post encrypted from the start is signed
   over its ciphertext, and the ADR-2017 migrator refuses an inner event that carries `zk`. So
   each zone's legacy keys go into one project-private record, kind 30078 under a `d` namespace
   of its own, signed by the group identity and NIP-44 self-encrypted, outside the NIP-171
   recovery chain so other clients never see an unknown field. It must be written by someone who
   holds every legacy epoch key and the new master; that person must exist per zone before the
   migration starts. After it, the mnemonic plus the relay recover every epoch, legacy and
   derived.
4. **Board transport stays signed kind 42 with the `zk` tag.** The relay keeps the zone gate, the
   ban gate, channel scoping, threads, reactions and sealed history. Kanban kinds 30301 and 30302
   stay as they are with `zk` encryption, because addressable events cannot live inside gift
   wraps. The zone-to-group binding lives in `ZONE_CONFIG`, which admins control and the relay
   serves; it never comes from a tag, because any zone writer can author a tag. The `zk` tag may
   carry the group pubkey as a fifth element purely as a hint that readers check against the
   binding. This is wire-compatible with Anagram for keys and tickets, not for messages.
5. **Epoch numbering shares one space per zone.** The relay accepts only epochs of 1 and above,
   and the client store takes the highest epoch per zone, so a derived epoch 0 would lose to
   legacy epoch n and writers would keep encrypting to the old key. The genesis epoch 0 is
   record-only and never posted; the first live derived epoch is n+1. The client store is keyed by
   zone, group pubkey, epoch and pubkey, and refuses to send while two keys claim one epoch, as the
   draft requires. The relay, being the single authority our deployment has, additionally refuses a
   `zk` whose pubkey differs from the first it stored for that zone and epoch. That is the real fix
   for concurrent rotation, and it is one NIP-171 cannot offer across many relays.
6. **Per-zone opt-in "Anagram-visible" mode.** A zone may additionally publish its chat as NIP-171
   rumors: gift-wrapped kind 14 to the epoch pubkey with `h`, `epoch`, `invited_at` and
   `invitation_proof` tags. An Anagram or nostr.chat member holding a ticket then reads the zone as
   a private group. Relay requirements: a recipient-only set of current epoch pubkeys that admins
   update, never the author whitelist and never environment config; a cohort rule that serves
   wraps addressed to a current epoch key to sessions in the zone's cohort, so no member has to
   authenticate as the epoch key; and the explicit statement that kind 1059 is outside the ban
   gate, so rotation becomes the only moderation tool for that stream. Core gains a parse path
   that keeps a rumor's signature, because `invitation_proof` needs the ticket's own signature;
   that is a recorded departure from NIP-59's unsigned-rumor rule. Off by default.
7. **Iris sender-key groups are not adopted for the board.** Unsigned rumor transport removes
   relay moderation and signed provenance; pairwise sessions with every member and device are
   heavy for 17 members; the kinds are in flux. Reconsider for the agent mesh only.
8. **One owner per zone.** The recovery master and group identity belong to a single owner, as the
   draft recommends. Auto-grant runs only in that owner's browser. Other admins keep moderation and
   the relay cohort, but do not issue tickets. This is chosen over "the admin cohort is the owner
   set" because co-owners cannot be revoked by rotation, so demoting an admin would mean a new
   master, a new identity and re-ticketing every member, and because two admins sweeping at once
   would fork the recovery chain and suspend ticket delivery until reconciled. History for a new
   member comes from the imported-epoch record and the current ticket, not from old-epoch tickets,
   which the draft's highest-epoch rule makes meaningless. Backup per the draft: kind 30078
   self-encrypted to the owner, alongside the owner's IndexedDB and a printed copy.
9. **Identity elsewhere unchanged.** Member keys, ADR-099 device keys, NIP-05 and did:nostr are
   untouched. No member re-onboards. The group identity pubkey is never whitelisted as an author;
   if it ever were, the relay refuses a bare kind 1014, whose content is an epoch key in plaintext.

### Migration, each step shippable alone

1. Client crate: NIP-171 derivation and record types, test vector green; store re-keyed by zone,
   group pubkey, epoch and pubkey; inconsistent-epoch refusal.
2. Relay: `ZONE_CONFIG` carries the group pubkey per zone; the zone gate refuses a conflicting
   pubkey for a stored zone and epoch; test both.
3. Client, migrator and agentbox zone-key module: build and parse `kind:1014` alongside 21453,
   checking the group seal against the `ZONE_CONFIG` binding; readers accept both.
4. Per zone, smallest first: the owner generates the master, writes the imported-epoch record for
   epochs 1..n, publishes the genesis record at epoch 0, derives and posts epoch n+1 with a random
   revision, issues 1014 tickets to current holders.
5. Flip grant issuance to 1014. Remove 21453 issuance one release later.
6. Relay: recipient-only set of current epoch pubkeys, cohort read rule, kind-1014 refusal for any
   whitelisted author. Core: signature-keeping rumor parse.
7. Anagram-visible mode, last, behind the per-zone flag.

### What this gains

- Zone history becomes recoverable from 12 words plus the relay, retiring loss level L3, with
  legacy epochs carried in the imported-epoch record.
- Concurrent rotations can no longer silently converge on one key, enforced at the relay, which is
  stronger than the draft's cross-relay best effort.
- Tickets and recovery records are a published draft other clients implement, so our private
  grant format disappears.
- A zone can be opened to Anagram and nostr.chat members as a private group without moving the
  board off kind 42.

### What it does not gain, stated plainly

- No forward secrecy within an epoch and none against master compromise. The draft says so and so
  does this document. A member who held a ticket can reveal everything that epoch carried.
- No message-level wire compatibility for board posts. Anagram reads a zone only in the opt-in
  mode, and only its chat, never the kanban.
- The recovery master is a new high-value secret. Whoever holds it holds every epoch, past and
  future, and ordinary rotation cannot revoke a holder.

### Risks, by severity

1. **Master handling.** Twelve words that unlock a zone's entire history, legacy epochs included,
   and a holder cannot be revoked by rotation. Mitigation: one owner per zone, the draft's owner
   backup plus a printed copy, and a documented re-key procedure for the day an owner leaves.
2. **Binding spoofing.** If readers ever took the zone-to-group mapping from a tag, any zone writer
   could name their own key and have every client encrypt to it. Mitigation: the binding is
   `ZONE_CONFIG` only; the tag is a hint that is checked, never trusted.
3. **Epoch collision.** A derived epoch 0 below legacy epoch n would lose silently in today's
   store. Mitigation: genesis record-only, first live epoch n+1, store keyed by pubkey too, relay
   refuses a second key for one epoch.
4. **Owner as single point.** One browser issues every ticket for a zone. Mitigation: the owner
   backup record means a lost browser is a mnemonic away from recovery; a second admin can be
   promoted to owner only by the re-key procedure, which is the price of revocability.
5. **Anagram-visible mode weakens moderation.** The relay sees neither author nor channel, and
   kind 1059 is outside the ban gate, so rotation is the only lever. Mitigation: off by default,
   per-zone, with that sentence in the admin UI.
6. **Draft stability.** NIP-171 is a draft with one implementation. Pin the version of the text
   the derivation was tested against and keep the vector in the test suite.

Decision record: ADR-2028 (proposed) carries this design and supersedes ADR-2026. The advisor's
checkpoint review that produced the corrections above is kept in the session scratchpad.
