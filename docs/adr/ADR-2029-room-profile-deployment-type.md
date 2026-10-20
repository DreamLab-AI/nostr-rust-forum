---
id: ADR-2029
title: Offer a second deployment profile, "room", that speaks Anagram public rooms, NIP-171 private groups and NIP-17 DMs; the forum profile and the DreamLab board stay on NIP-28
date: 2026-10-20
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: fb9ef30 plus the uncommitted ADR-2025 working tree (design only; nothing implemented to verify)
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: First operator asking to stand up a room-profile deployment; the nostr.chat profile changing section 4; NIP-171 merging; any request to flip the DreamLab board
repo: nostr-rust-forum
---

# ADR-2029 — Offer a second deployment profile, "room", that speaks Anagram public rooms, NIP-171 private groups and NIP-17 DMs; the forum profile and the DreamLab board stay on NIP-28

## Context

`docs/interop/nostr-chat-interop-assessment-2026-10-20.md` found our public channels (NIP-28
kinds 40/41/42) and the nostr.chat cluster's rooms (kind 34550 definition plus kind 9 messages)
share no wire surface, and rejected migrating the live board because the kind sits inside the
signed id. A greenfield deployment has no history to re-sign, so the same wire shape is a
deployment choice rather than a migration.

What the code says today. Kinds 40/41/42 are hard-coded at the ban gate (`nip_handlers.rs:69`),
zone gate (`:1414`), post counters (`:1556`), profile stats (`profile_stats.rs:11`), creator
lookup (`:2549`) and zone read decision (`:2354`); the client takes the channel from the first `e`
tag (`core/src/thread.rs:69`, `pages/message_jump.rs:68`). Core carries NIP-29 kind-9 builders
(`groups.rs`, `h`-scoped) with no callers, and the relay advertises NIP-29 while gating only its
admin kinds (`nip11.rs:207`, `nip_handlers.rs:52`, "NIP-29 TODO" at `:1299`). Addressable events
are replaced by deleting older rows then inserting, with no guard against a late older event or
a same-second tie (`storage.rs:119-133`). The 7-day timestamp window (`:44`) exempts only sealed
kind 42 (`:1718`). The protected-read set is a compiled constant and requires any authenticated
key, not a member (`nip42.rs:44,102`). The config validator is a `forum.toml` parser with no
database access (`ci.yml:122`). CI type-checks the client once for wasm32 and never builds it
(`ci.yml:187`). The relay already serves a `nostr_bbs` block in its NIP-11 document, and the
client already reads a runtime `window.__ENV__` block.

What nostr.chat does, from its source. A room edit is a new kind 9 signed with the original
message's `created_at` and an `e` tag marked `edit` (`nostr.js:672`). `q` names the message being
replied to, or the first version of an edited one, and the client renders a flat chat with an
inline quote (`nostr.js:684`, `app.js:1129`). It publishes room traffic to the definition's `relay`
tags plus five public app relays and counts success if any one accepts (`transport.js:46`). It
enforces `blocked` on read and uses `trusted` to gate links and media only (`app.js:1110,1155`).

## Decision

Proposed:

1. **Two named deployment profiles.** `forum` (today's behaviour, the default) and `room`. The
   profile is one key, `[deployment] profile = "forum" | "room"` in `forum.toml`, projected by
   `nostr-bbs-config` to the relay as `CHANNEL_DIALECT = "nip28" | "anagram"`. The relay is the
   single authority for the dialect: it publishes it in the `nostr_bbs` block of its NIP-11
   document, and the client, which compiles both dialects behind one `ChannelDialect` trait,
   reads it at runtime from there, with `window.__ENV__` as the offline fallback. There is no
   client build-time projection and therefore no "projections disagree" failure class.
2. **The relay pins its dialect in the database.** On first write under a dialect the relay
   records it in a D1 settings row and refuses to start under the other. The config validator
   cannot see the database and does not claim to. Inference from stored kinds is not used,
   because a `forum` database may legitimately hold NIP-29 kind 9 or NIP-72 kind 34550.
3. **What `room` speaks.**
   - Public channels: Anagram public rooms per the interoperability profile section 4. Definition
     kind 34550 with `d`, `anagram-room`, `name`, `relay`, optional `pinned`, `successor`,
     `predecessor`, `trusted`, `blocked`; unknown tags preserved verbatim on edit; newest wins
     with `created_at = max(now, prev + 1)`. Messages kind 9 with exactly one `a` tag naming a
     34550 address that carries `anagram-room`. Replies by `q` to the message replied to, or the
     first version of an edited message. Edits by the Anagram convention, carrying the original
     `created_at`. Reactions kind 7 and deletions kind 5 with `h` and `k`. Content bound 8,000
     characters and 60 seconds of future skew enforced by our builder and parser, and by the
     relay in `room` so that foreign-invalid events are not served.
   - Private spaces: NIP-171 epoch groups. This amends ADR-2028 sections 5 and 8: in `room` the
     Anagram-visible kind-14 transport is the only private transport, there is no `zk`-tagged
     kind 9, and the kind-42 zone gate does not exist. `ZONE_CONFIG` cohorts, the zone-to-group
     binding and `zk`-encrypted kanban and calendar remain in both profiles.
   - DMs: the NIP-17 overlay of ADR-2027.
   - Kanban, calendar, governance, moderation and poker kinds are unchanged; they bind to zones by
     slug, never to channel ids, and foreign clients ignore them.
4. **Rendering follows nostr.chat.** A room is a flat chat. A kind 9 with `q` renders with an
   inline quote of the quoted message. There is no topic-and-thread model in `room`; nested
   threads exist only in `forum`. `ChannelDialect` owns tag interpretation end to end: channel
   reference, reply reference, edit reference and the reaction and deletion target, not only
   kind numbers. Channel identity in `room` is the address `34550:<owner>:<slug>`, never the
   definition's event id, which changes on every edit; read position, mute list, notifications,
   bookmarks and IndexedDB key on that string.
5. **Relay behaviour in `room`.**
   - Admission by tag shape, not kind number: a kind 9 is a room message only when it carries one
     `a` tag to an `anagram-room` definition; a kind 34550 is a room only when it carries
     `anagram-room`. Other kind 9 and 34550 events are treated as they are today.
   - The 7-day timestamp window gains a past-only exemption for an edit-tagged kind 9 whose
     `created_at` matches a stored message by the same author, mirroring the sealed-original
     exemption. Without it, any edit of a message older than a week is refused.
   - Room creation requires the trust level kind 40 requires today; definition edits are
     self-gated because the owner is the signer.
   - The ban gate, post counters, profile stats and the promotion counter cover kinds 9 and
     34550. The first two are gaps in `forum` today as well and are closed in both profiles.
   - Addressable replacement becomes conditional: an incoming 3xxxx event is stored only when it
     is newer than the stored one, with lowest id as the tie-break. This is a correctness fix
     for every addressable kind, not only 34550.
   - Kind 9 and 34550 are not protected-read kinds. A `room` relay is world-read for rooms and
     members-write for its own replica. No member-only read rule is offered, because nostr.chat
     authenticates with any key and because members' own nostr.chat clients copy their messages
     to public relays.
   - The relay's NIP-11 document stops advertising NIP-29 in both profiles until the relay
     actually implements NIP-29 group admission. It advertises NIP-17 only once the overlay ships.
6. **What the whitelist governs in `room`, stated plainly.** As nostr.chat sees it, a room is
   open-write and world-read across the relays in its definition plus the public app relays; our
   relay curates one replica. A non-whitelisted key, even one the owner marked `trusted`, posts
   successfully to the app relays and is seen by nostr.chat readers but never by ours. A
   whitelisted member marked `blocked` still writes to our relay; our client hides them on read,
   as nostr.chat does. A deletion by an admin or trust level 3 physically removes the message on
   our relay for every reader of our relay, while it survives on the app relays; an author's own
   deletion is honoured everywhere.
7. **Core additions.** Anagram-dialect builders and parsers beside the NIP-29 ones, with section 4
   rules as unit tests: slug grammar, tag cardinality, address form, the content bound, the
   future-skew bound, unknown-tag preservation on edit. Nothing bespoke: every kind and tag is the
   profile's. The NIP-29 builders are removed in a follow-up unless a profile claims them.
8. **The DreamLab board stays `forum`.** This repository adopts the `room` profile as a product
   of the kit and does not consume it. Flipping is refused by decision 2.
9. **Documentation is part of the decision.** The following ship with the first implementation:
   `docs/deployment-profiles.md` with the comparison, three diagrams and the decision tree; a
   profile section in `SETUP.md` before Cloudflare setup; the `[deployment] profile` key in
   `forum.example.toml` with the trade-offs; a README quick-start fork; the diagrams corpus
   gaining a citation-verified room-dialect sequence; the baseline's profile table; and the
   per-profile grant-acceptance note in `IDENTITY-keys-and-trust.md`.

## Consequences

- An operator can stand up a board that nostr.chat and Anagram users read, and that whitelisted
  members write to, with private groups and DMs those clients open natively. Our own board gains
  nothing and loses nothing.
- Two dialects compiled into one client; every channel feature lands behind the trait or does not
  land. CI gains a trunk build and the relay conformance tests run per dialect.
- The relay's audience in `room` is wider than its whitelist, and moderation on the wire is
  weaker: only the author's own deletions travel, and the room's membership policy lives in tags
  other clients interpret. The profiles page says so in the decision tree.
- Three relay changes apply to `forum` too and are improvements there: conditional addressable
  replacement, ban-gate and counter coverage of kind 9, and the removal of the NIP-29
  advertisement.
- ADR-2028 sections 5 and 8 and its consequences are amended by this ADR. ADR-2027 is a
  prerequisite. ADR-2016 and ADR-2017, `channel_zones`, the zone write gate, the zone read
  decision, sealed originals and the channel-creator table are `forum`-only and named as such in
  the baseline.
- Refusing non-room kind 9 as a channel message changes nothing; the relay keeps accepting plain
  kind 9 from members as it does today.

## Verification

None: no implementation. Adoption requires: `cargo test` of the Anagram builders against the
section 4 rules including unknown-tag preservation; a relay test that a kind 9 without the room
`a` tag is not treated as a room message in either profile; a relay test that an edit-tagged
kind 9 older than seven days is admitted and a non-edit one refused; a relay test that a late
older 34550 and a same-second pair resolve to one stored row; a relay test that starting under
the other dialect against a pinned database is refused; a client test that the channel string
survives a definition edit; one scratch `room` deployment read by a nostr.chat tab with a room,
a reply with quote, an edit older than a week, a reaction and a deletion each rendered as the
profile says; and the documentation set in decision 9 present in the same change.
