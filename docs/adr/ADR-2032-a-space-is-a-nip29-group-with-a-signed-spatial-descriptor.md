---
id: ADR-2032
title: A space is a NIP-29 group with a relay-signed spatial descriptor, a NIP-53 interactive room and NIP-78 claims, using no new event kinds
date: 2026-10-30
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 0065dd9fb0e98ccacfd29e344a3d00bb80b58a69
owner: jjohare
review_trigger: Any commit that parses a space descriptor or emits 30312 or 10312; a client reporting two claimants for one spot; NIP-53 or NIP-78 changing the cited kinds; a change to the content-ref set; the first request for in-world apps
repo: nostr-rust-forum
---

# ADR-2032 — A space is a NIP-29 group with a relay-signed spatial descriptor, a NIP-53 interactive room and NIP-78 claims, using no new event kinds

## Context

Depends on ADR-2030 (the home signs 39000) and ADR-2031 (the home is pinned). The model is obelisk-sky: a group is a place, and chat and calls are scoped to where you stand.
obelisk-sky places groups on each client from a 30-day message snapshot, so two clients can disagree. It has no licence, so it yields ideas and wire facts only; its private kinds and 30078 d-tags are not adopted.
NIP-53 defines kind 30312 (interactive room: `service` URL, status, Host/Moderator/Speaker roles) and kind 10312 (presence). NIP-78 kind 30078 is application data. The forum handles none of them, and 10312 is replaceable, so it passes through the storage branch ADR-2031 corrects.
A descriptor can name content, so what it may name is a security surface: the audit fixed a closed set of references (AUDIT-DECISIONS, cross-set).
Evidence: VisionClaw `docs/proposals/spatial-rooms/PLAN.md`, `research/01`, `research/03`, `AUDIT-DECISIONS.md`.

## Decision

Proposed:

1. **The descriptor is extra tags on the home-signed 39000.** `["space","1"]`; `["place", x, y, z]` in metres in the home's own frame (round-2 C10); `["extent", w, h, d]`; optionally `["scene", <content-ref>]`; and `["volume", <content-ref>, <bounds-hint>]` once per volume the space shows. An admin sets them through an edit-metadata event (9002), and the engine validates them (finite numbers, bounded, refs per decision 2) before folding them into 39000. Because the home signs 39000, placement is canonical and operator-authored. Other NIP-29 clients ignore unknown tags. When the descriptor is absent, default placement is a pure function of `(home pubkey, group id)`, defined with test vectors in the first implementation.
2. **`<content-ref>` is a closed set (audit cross-set rule D1).** It is exactly one of:
   - `urn:visionclaw:dataspace:<node-key-hex>:<space-id>`, where `<node-key-hex>` is 64 lowercase hex characters and the form is defined by VisionClaw ADR-2161;
   - `urn:visionclaw:codescape:<scene>`, where `<scene>` is a non-empty identifier of letters, digits, `-`, `_` and `.`;
   - a relative path on the home's own node: it begins with a single `/`, has no scheme, no `//`, no `\`, no `.` or `..` segment, and no query or fragment.
   Anything else is an unknown ref. A client ignores a tag whose ref is unknown and renders the rest of the space. The engine refuses a 9002 that carries one, so the home never signs it, and a client ignores one that appears anyway. Adding a member to the set is a change to this ADR. The set is closed so that a descriptor cannot make a client fetch an arbitrary URL.
3. **A space is not a volume.** A space may describe the volumes it shows; each client lays them out on its own device.
   - **Frames (round-2 C10).** The descriptor's frame is the home's own frame. Each consuming node applies its own placement transform, and no cross-node frame is shared in v1.
   - **Volume fit.** A consumer scales a volume's content to the `bounds-hint` with scale = min over axes of (bounds_i / content_i), ignoring any axis whose content extent is below 1e-6. This is the rule VisionClaw ADR-2158 implements; the forum only validates the hint as finite and bounded.
   - **Rev.** The 39000 that carries the descriptor carries `["rev", <u64>]` like every 3900x (ADR-2031 decision 2). A consumer takes the descriptor from the 39000 with the highest `rev` it has verified. `created_at` never orders different revisions; it orders only equal-`rev` heartbeats, which carry identical content.
4. **Media is one NIP-53 kind 30312 per space, signed by the home. Deferred with voice (operator, 2026-10-30):** the 30312 publisher is not built or enabled until VisionClaw ADR-2160's voice deferral is lifted; spaces work without it. `d` is the group id; `status` is derived from the group flags; `service` is the call endpoint; `p` tags with the Host role are the group admins from 39001. The flag-to-status table is fixed, with tests, in the first implementation. The relay stores 30312 by `rev` under the D1 migration of ADR-2031 decision 7 (final-audit ruling 9), so a higher-`rev` 30312 is never discarded in favour of a lower one. This publisher is a **prerequisite of voice activation** (VisionClaw ADR-2160 D4 consumes only a validated home-signed 30312): it goes live with the forum chain at estate step 3 and must be in place before step 5. It is not a prerequisite of `public` or `dids` dataspace federation.
   - **SFU authority (round-2 C4).** Server configuration is authoritative for the SFU. The home writes `service` from its configured SFU URL and nothing else. The 30312 carries `["rev", <u64>]` from the same sequence as the 3900x it derives from. A consumer uses a 30312 only if it validates: signature by the pinned home key, the right group, and the highest `rev` held. The consumer's `service` must also equal its own configured URL, or it refuses the event. The binding to the SFU is the per-SFU API key and secret (VisionClaw ADR-2160), not any claim in the event.
5. **Coarse presence is NIP-53 kind 10312** with an `a` tag to the space's 30312. Fine-grained poses stay on VisionClaw's presence socket (0x43) and never enter a relay.
6. **Seat and spot claims are NIP-78 kind 30078, advisory display state only.** Claims are namespaced by full space identity (round-2 C10). The d-tag is `visionflow:claim:<home-key-hex>:<group>:<spot>`, with the home's 64 lowercase hex pubkey, and a NIP-40 expiry of 90 seconds. Two spaces with the same group id on different homes never collide. Arbitration is the earliest `created_at`, then the lowest event id, computed by readers from the events they hold.
   - The claimant must be a member of the group. The home and every mirror refuse a claim whose author is not in the current 39002, and a reader ignores one that reaches it anyway. A consumer drops a claimant's claims as soon as it observes the removal or loses fresh membership authority (a 39002 stale after L + S). Propagation from the home is not instantaneous: a remote consumer may hold a fresh pre-removal 39002 until its lease ends.
   - No access, admission, voice or moderation decision may depend on a claim. A claim confers nothing but a place in a display.
   - This relay refuses an already-expired claim at admission and filters expired rows at read, and a mirror applies the same rule.
7. **No new event kinds.** Obelisk's private kinds (20390, 31313, 31314, 25050-25052) and its 30078 d-tags are not adopted. The 30078 d-tag namespaces in use are listed in `docs/BASELINE-architecture.md`.
8. **Out of scope: in-world apps.** The obelisk-apps pattern (opaque-origin iframe, `connect-src 'none'`, host-built signed events, apps never hold a signer) is the model to evaluate in a later ADR.

## Consequences

- Easy: any NIP-29 or NIP-53 client sees a space as an ordinary group and room; placement agrees across clients on the home's frame (E11); VisionClaw reads two events from one signer, the 39002 for membership and the 39000 for layout, each ordered by its own `rev` (a correction of the round-1 wording "one signed event for both"); a client has a short, testable list of things a descriptor may reference.
- Hard: the relay gains a 30312 publisher and a descriptor validator; the home's metadata event grows with each volume; a new reference type needs an ADR amendment.
- Known weaknesses of claims, recorded rather than fixed: arbitration by `created_at` loses to backdating, which admission allows up to seven days; a holder's refresh loses to anyone who claimed in between. These are tolerable only because claims are advisory (decision 6).
- Presence staleness (a 10312 that is never replaced) and who may publish a 10312 for a space are not decided here.
- Activation follows ADR-2031 (estate step 3); this ADR adds no activation prerequisite to the forum chain, and VisionClaw ADR-2161 `public` and `dids` do not depend on it (round-2 C9). Its 30312 publisher (decision 4) is a prerequisite of VisionClaw ADR-2160 voice, live from step 3.
- The d-tag `visionflow:claim:` uses a superseded product name and, once on the wire, is permanent; a rename needs a new namespace.
- Foreclosed: per-client canonical placement; a new kind for presence, claims or placement; relaying poses; content references outside the closed set; access decisions based on claims.
- Rejected: (a) a private kind for placement or claims, as obelisk does: it gives up interoperability and the registry-only rule; (b) placement in a separate addressable event: two events to keep consistent where one signed event already exists; (c) computing placement on each client from activity: the obelisk-sky behaviour, which disagrees across clients; (d) free-form URLs in `volume` and `scene`: a descriptor could point a client at any host; (e) binding claims to access control: backdating defeats the arbitration.
- Revisit if two claimants are seen for one spot in practice, if NIP-53 changes 30312 or 10312, if VisionClaw ADR-2161 changes the dataspace URN, or if in-world apps are scheduled.

## Verification

None: no implementation. At `0065dd9fb0e98ccacfd29e344a3d00bb80b58a69`: a grep over `crates` finds no handling of 30312, 10312 or 30078 (only 30033 in the mesh crate); the replaceable branch is `crates/nostr-bbs-relay-worker/src/relay_do/storage.rs:98-118`; NIP-40 is enforced at admission (`relay_do/filter.rs:375`, `nip_handlers.rs:1068-1073`), at read (`storage.rs:342-349`) and by the cron sweep (`cron.rs:338,411`); the seven-day bound is `nip_handlers.rs:44,1731`. The content-ref forms are specified by VisionClaw ADR-2161, which is not verified here.
Adoption requires: a unit test that a 39000 carrying the descriptor parses, a malformed one is refused, and a client that ignores unknown tags still reads the group; a table test over `<content-ref>` accepting each of the three forms and rejecting `https://` and `javascript:` URLs, `file:` paths, `//host/x`, `/a/../b`, `a/b`, a short node key, an uppercase node key and an empty scene, with the tag ignored by the client and the 9002 refused by the engine; a pure-function test that two clients with different histories place the same space at the same coordinates (E11); a test that a late older 10312 does not replace a newer one; a test over the 30312 status table; a test that a claim from a non-member is refused at the home and ignored by a reader, and that a consumer drops a member's claims when it observes their removal or its 39002 goes stale; a test that two claims with the same group and spot on different homes do not collide; a test that a 30312 whose `service` differs from the configured URL, is unsigned by the pinned home, or has a lower `rev` than one held is refused; a test that a consumer takes the descriptor from the highest `rev`; a table test of the volume-fit rule (anisotropic content, an axis below 1e-6 ignored); a reader test that two claims resolve by earliest `created_at` then lowest event id and an expired claim is not served.
