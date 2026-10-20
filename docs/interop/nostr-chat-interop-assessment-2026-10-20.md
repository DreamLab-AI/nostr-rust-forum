---
title: nostr.chat / Anagram / Iris interoperability assessment
date: 2026-10-20
status: assessment (no code changed)
inputs: melvincarvalho/anagram gh-pages docs/SPEC.md (nostr.chat interoperability profile), melvincarvalho/anagram issue #2 (Nostr Double Ratchet), lnbits/anagram, mmalmi/nostr-double-ratchet, irislib/iris-chat-rs, crates.io nostr-double-ratchet 0.0.170
method: build-with-quality investigation; four read-only workers (protocol, wire delta, backup/restore, federation design) on ruflo swarm swarm-1792486113811-3z3njz; lead spot-checked every claim that drives the recommendation
---

# nostr.chat / Anagram / Iris interoperability assessment

## Verdict

**No reset is required.** The deployed board can become reachable from the nostr.chat cluster by
changing DM *routing*, not DM *format*, and nothing stored has to move. Our NIP-17 gift wraps are
already wire-compatible with the profile (signed-rumor tolerance arrives with the uncommitted
ADR-2025 change). One relay change is needed before the privacy mitigation in section 5 can ship. The gaps are: we publish a member's DM-relay list only to
our own relay, so nobody outside can find it; we publish DMs only to our own relay, so nobody
outside can receive them; and we drop every rumor kind except 14. Public rooms do not overlap at all
(we are NIP-28 kind 40/42, the profile is kind 34550 plus kind 9) and should stay that way.

**The double ratchet should be consumed, not ported.** It exists as a published Rust crate using
NIP-44 v2 from the `nostr` crate plus HKDF-SHA256, with no hand-rolled primitives. It belongs, if
anywhere, as an optional member-to-member DM transport. It must stay off the agent mesh and must not
be hosted by our relay until a new admission lane exists, because ratchet messages are signed by a
fresh key every step and carry no recipient tag our whitelist can read.

**Backup is possible today and was exercised.** Every event lives in D1, not the Durable Object. A
single `wrangler d1 export` per database produced a complete dump. D1 Time Travel is enabled, with a
current bookmark, so a same-account rollback is cheaper still. What no backup can preserve is the
readability of encrypted material whose keys live only in browsers.

## 1. What the external cluster is

| Piece | Owner | Wire |
|---|---|---|
| nostr.chat | melvincarvalho/anagram (gh-pages) | NIP-17 DMs with the Anagram edit convention; Anagram public rooms, kind 34550 definition carrying an `anagram-room` tag plus kind 9 messages scoped by an `a` tag, `q` replies, `h`-tagged reactions and deletions; kind 10050 and 10002 relay lists read from the public indexers; did:nostr identity; Blossom media with `imeta`; optional Nostr Double Ratchet, pinned at npm 0.0.179 in `vendor/` |
| Anagram (lnbits) | lnbits/anagram | Svelte/Tauri messenger; NIP-17 DMs, epoch-keyed private groups (NIP-171 draft), Iroh calls |
| Iris | irislib/iris-chat-rs, mmalmi/nostr-double-ratchet | Rust client and the ratchet reference; kind 37368 device rosters, kind 1060 ratchet envelopes, kind 30078 device invites, Negentropy history sync |

The ratchet: each step derives a NIP-44 conversation key over secp256k1 and chains message keys with
HKDF-SHA256. Outer kind 1060 events are signed by a per-step session key the envelope carries, with a
NIP-44-encrypted `header` tag; a `p` tag appears only during the invite and names the recipient's
*device* key. Inner rumors are unsigned (kind 14 chat, 7 reaction, 15 receipt in the ratchet's own numbering,
25 typing).
Devices are listed in an owner-signed kind 37368 roster. A NIP-17-only client sees none of it. The
profile's rule (section 7.5) is that a chat never downgrades once upgraded.

## 2. Wire delta against the profile

Twenty-seven rows were compared (`scratchpad/reports/wire-delta.md`, kept out of the repo). The
rows that decide the outcome:

| Profile section | Our behaviour | Verdict |
|---|---|---|
| 3.1 to 3.3, 3.10 NIP-17 rumor, seal, wrap, inbox | Kinds 14/13/1059, NIP-44 v2, past-only jitter to 48 h, own-copy wrap, `#p` inbox subscription (`core/src/gift_wrap.rs`, `forum-client/src/dm/mod.rs:587`) | Compatible |
| 2.3 to 2.4 publish to the recipient's 10050 relays | Publish to our relay only (`dm/mod.rs:490`) | Incompatible outbound |
| 2.7 publish 10050 and 10002 | Correct tags, but only to our relay; never to purplepag.es or the other indexers (`dm/mod.rs:1212-1238`, `app.rs:723`) | Shape right, reach absent |
| 3.1 rumor kinds 7 (reaction), 5 (deletion), 15 (file message, received only; rendering file URLs is UI work) | Dropped with `InvalidKind` (`gift_wrap.rs:699-741`) | Incompatible |
| 3.5 to 3.8 reply, edit, reaction, deletion in DMs | Not sent, not read | Absent |
| 3.3 size guard | Relay caps content at 64 KiB; profile allows 200 kB wraps | Large wraps refused |
| 4 rooms (34550 + kind 9) | NIP-28 kind 40/41/42 with kind 1111 comments; kind 9/`h` builders in `core/src/groups.rs` have no callers | Incompatible, by design |
| 2.6 NIP-42 AUTH | Required before any write and before reading protected kinds; the AUTH handler verifies signature, challenge, relay URL and timestamp skew but no whitelist, so any key can authenticate (`relay_do/nip_handlers.rs:2046`, `nip42.rs:184-213`) | Compatible |
| 8.1 trust | Whitelist on author for every kind except 1059, which is gated on the first `p` recipient being a member or an `INGRESS_RECIPIENTS` entry (`nip_handlers.rs:1135-1152`); traced from the top of `handle_event`, nothing else refuses an AUTH'd outsider's wrap to a member | Different model; inbound DMs from outsiders already pass |
| 1.1 to 1.5 did:nostr, NIP-05 | We serve both for our own members; we resolve neither for anyone else | Server-side compatible |
| 5, 6, 10 lists, Blossom, Negentropy | Mute and settings are localStorage; uploads go to the pod worker with bare URLs; no sync | Absent |

Project-private kinds that no external client will understand: moderation 30910 to 30916,
governance 31400 to 31405, kanban 30301/30302/38000, calendar with a `zone` tag, zone-key grants
21453, poker 20779, mesh 30050/30033. The kanban is outside the profile entirely and nostr.chat
ignores it.

## 3. Our federation surfaces

| Surface | State | Alignment |
|---|---|---|
| Forum DMs | Live | Profile section 3; routing is the gap |
| Public channels | Live, NIP-28 | Conflicts with section 4; we also advertise NIP-29 in NIP-11, whose kind 9 is `h`-scoped where Anagram's is `a`-scoped |
| Encrypted zones (ADR-2016/2017) | Live | Nothing in the profile; rooms there are public |
| Pod mesh, IS-Envelope v1 | Library only; relay runs `MESH_MODE = "standalone"` and outbound fan-out is unwired | Section 3.2 in shape; must not adopt the ratchet |
| Device keys (ADR-099/2004) | Dormant table | Section 7.1 in concept; the roster uses random per-browser keys, not derived subkeys |
| agentbox session mirror | Live, gift-wrapped transcripts to the operator on this relay | Section 3; see risk 1 |
| VisionFlow | NIP-98 and did:nostr via solid-pod-rs; pins core beta.16 | Section 1.5; no conflict found |

Drift noticed on the way: the baseline cites the admission gate at `nip_handlers.rs:103-110`, it is
at `:1135`; the single kind 30033 constant in the mesh crate is used with two meanings, anchor in
`transport.rs:278` and services in `envelope.rs`; the baseline says core is at beta.10, HEAD is at
beta.17 and the working tree at beta.18. Anchors in this document are against `fb9ef30` plus the
uncommitted ADR-2025 working tree.

## 4. Options

**C. NIP-17 overlay (recommended).** Resolve the recipient's 10050 (fall back to 10002), publish
wraps to those relays as well as ours, publish members' 10050/10002 to the indexers behind an
opt-in, accept rumor kinds 7, 5 and 15, add reply and `imeta` tags, add a requests inbox. Breaks
nothing stored. Migrates nothing. No relay reset. Inbound already works because the gate is on
recipient. Outbound to a non-member must skip our relay for the recipient copy, because the same
gate refuses it; only the self-copy goes to us. The whitelist is otherwise untouched. The meta CSP added under ADR-2025 has no `connect-src`, so
multi-relay WebSockets need no change.

**A. Bridge.** A gateway key mirrors unencrypted NIP-28 channels to kind 9 under a 34550 it owns.
Breaks nothing, migrates nothing, forward-only. Two moderation planes for reach a private board does
not need; everything the bridge mirrors counts as `plain` trust on the far side.

**B. Adopt kind 9 rooms. Do not build.** The kind is inside the signed id, so turning 42 into 9
means someone else re-signs and provenance is lost. Kind 9 is not ban-gated (`nip_handlers.rs:68`);
the zone gate, sealed history and channel counts all key on kind 42. Requires a relay reset. Rooms on
external relays escape the whitelist entirely.

**Double ratchet.** Consume `nostr-double-ratchet` pinned exact in the client crate, with our own
IndexedDB session store and a bridge to our `Signer` for the roster only. The device key is a
separate local key, never the identity key, because the ratchet needs raw ECDH secrets a NIP-07
extension cannot export. Core 0.0.170 compiles for wasm32 once `uuid` and `getrandom` get the `js`
feature; the `-pairwise` (`fs2`), `-runtime` (`uuid`) and `iris-chat-protocol` (`rusqlite`) crates
do not, so the session manager would be ours. Do not vendor yet. Do not clean-room port, that would
be maintaining our own ratchet. Do not publish our binding as a crate. Not before the relay has an
admission lane keyed on the AUTH'd session principal rather than the event author.

## 5. Risks to the live board, by severity

1. **A member's other client decrypts our private material (high, applies to C).** Once our relay
   is in a member's public 10050, nostr.chat pulls every kind 1059 addressed to them. Zone-key
   grants (rumor kind 21453) are decrypted in that tab and discarded (`src/js/store.js:1272-1290`
   keeps kinds 5, 7, 14, 15). Grants carry `p` = the member's identity key
   (`zone_crypto/mod.rs:644`) and the agentbox mirror wraps to the operator's own pubkey. The
   mirror's kind-14 transcripts are kept and shown. Mitigation, before any opt-in: give grants and
   the mirror their own inbox key. That is not client-only: the gate checks the raw `p` key against
   the whitelist with no device-to-owner lookup (`nip_handlers.rs:1139-1143`), so the relay must
   resolve or whitelist inbox keys first, and grants already addressed to identity keys keep leaking
   until the subscription changes.
2. **Membership disclosure (high).** A 10050 naming our relay, published to purplepag.es and
   coracle, is a public roster. AUTH already hands our relay a who-messages-whom graph; indexers
   would see who belongs.
3. **Moderation and trust bypass (high under A and B, low under C).** Kind 9 is not ban-gated;
   trust levels and zone cohorts do not exist on external relays. Under C, DMs from outsiders skip
   the whitelist by design and ADR-2023 push still wakes the member.
4. **Ratchet traffic on third-party relays (medium).** Timing and ratchet-key linkage are visible to
   whichever relay carries kind 1060; the upgrade is one-way.
5. **Operational coupling (medium).** A dead relay in someone's 10050 drops DMs silently;
   the profile's `partial` publish state is the only signal.
6. **Protocol instability (medium).** The ratchet crates are pre-1.0, ship near-daily, and are
   version-skewed with each other; roster and invite kinds have moved (30078 vs 37368). Kind 30078
   already collides three ways: nostr.chat settings, Iris invite and roster, and our
   `MESH_FEDERATED_KINDS`.
7. **Data loss (medium, B only).**
8. **ADR drift (low, already present).** Any option amends IDENTITY invariant 4 and the baseline's
   admission citation.

## 6. Backup and restore of the deployed board

Where things live, verified read-only against production on 2026-10-20:

| Store | Holds | Export |
|---|---|---|
| D1 `nostr-bbs-relay` (23 tables) | every event plus `event_tags`, `whitelist`, `channel_zones`, `channel_creators`, `profiles`, `governance_receipts`, `broker_*`, `push_*`, `admin_log`, `pubkey_aliases` | `wrangler d1 export --remote`, 6.1 MB, 7,964 inserts, succeeded |
| D1 `nostr-bbs-auth` (25 tables) | `members`, `invitations`, `instance_settings`, credentials | `wrangler d1 export --remote`, 33 KB, succeeded |
| Durable Object | AUTH challenges, subscriptions, session ids and the session-counter mark | nothing to export |
| R2 `nostr-bbs-pods` | media and pod data | not enumerated |
| Admin browsers (IndexedDB) | zone epoch secrets, admin nsec | manual; single point of failure |

Event counts: 597 channel posts (kind 42), 12 channels, 1,286 DM wraps, 2 kanban boards and 24
cards, 72 governance records, 353 deletions, 35 profiles.

Restore paths. Two exist. Direct D1 import (`wrangler d1 execute --remote --file`) restores
signed events byte for byte with every table intact. Replay through the relay's EVENT path is the
second: the 7-day timestamp drift check (`nip_handlers.rs:44`) is our own constant, so a
maintenance flag can waive it for an admin-authenticated replay session. Replay keeps signatures
and ids but rebuilds `received_at` and tag rows, re-runs the whitelist and author gates against the
current roster, and re-applies kind-5 deletions, so it must run in `created_at` order with the
roster as it was. It restores events only; the non-event tables still come from the D1 export.
Replay is the path to prefer when the schema has changed under the data, since the relay rebuilds
the derived rows itself. D1 Time Travel is enabled and has a current bookmark,
so a same-account rollback needs no file at all. The relay's `reset-db` deletes `events` and
`whitelist`, and `event_tags` with them through the `trg_event_tags_ad` trigger, leaving
`channel_zones`, `profiles` and the broker tables orphaned; a real reset needs explicit drops.

What a reset or re-key cannot preserve: zone-encrypted posts and sealed originals without the epoch
secrets; DMs without the recipient keys; attribution, because signatures bind author keys and
content cannot be re-authored without forging. A Workers relay URL change invalidates cached AUTH
and NIP-42 relay tags, not stored events.

Procedure draft (SAFE-READ unless marked WRITE):

```
# 1-2  export both databases
cd crates/nostr-bbs-relay-worker && wrangler d1 export nostr-bbs-relay --remote --output <dir>/relay.sql
cd crates/nostr-bbs-auth-worker  && wrangler d1 export nostr-bbs-auth  --remote --output <dir>/auth.sql
# 3    record the bookmark, per-kind counts and checksums
wrangler d1 time-travel info nostr-bbs-relay
sha256sum <dir>/*.sql
# 4    copy R2 nostr-bbs-pods (rclone or per-object get)        -- not yet done
# 5    export zone epoch secrets and the admin key from the admin browser  -- manual
# 6    wrangler secret list   (names only; values from the operator's store)
# 7    WRITE  drop the target tables only; do NOT recreate them. The export creates tables first
#             and triggers last; a pre-existing trg_event_tags_ai_v2 would double every
#             event_tags row (no primary key, so silently)
# 8    WRITE  wrangler d1 execute <db> --remote --file <dir>/<db>.sql ; re-run step 3 and
#             compare the event_tags count (4,515 today)
# 9    WRITE  redeploy workers; ensure_schema fills missing indexes
```

Gaps: R2 and KV unaudited; exports are plaintext at rest; a restore into a scratch D1 has never
been run; no disaster-recovery runbook or schedule exists; zone keys have no second home
(ADR-2026, proposed, is the candidate).

## 7. Recommended order of work

1. Write the disaster-recovery runbook from section 6 and run one restore into a scratch D1.
2. Give zone-key grants and the agentbox mirror their own inbox keys (closes risk 1). Needs a relay
   change first: resolve inbox keys to their owner, or whitelist or ingress-declare them, plus a
   cross-device home for the key. Not client-only.
3. Accept rumor kinds 7, 5 and 15 on receive, with file-message rendering for 15; add reply and
   `imeta` tags on send.
4. Publish members' 10050/10002 to the indexers behind an explicit `public_inbox` opt-in.
5. Resolve recipients' 10050 and publish wraps to several relays, skipping our relay for a
   non-member recipient's copy; add the requests inbox.
6. Fix the drift: admission citation in the baseline, duplicate kind 30033, core version.
7. Revisit the ratchet when the crates reach a stable minor and the relay has a session-principal
   admission lane; pin exact, consume, never port.

Decision record: ADR-2027 (proposed) carries option C. The ratchet and option B are recorded there
as rejected for now with the reasons above.
