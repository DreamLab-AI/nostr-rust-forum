---
id: ADR-2023
title: Content-free Web Push delivers reply, DM and new-message alerts to the PWA
date: 2026-10-19
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 97a935e344b8a7c2ce66f0df5b32a04c3b4fd2ae
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: An operator setting `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT` on the production relay and a push round trip on a real device (the activation step); any request to carry message text in a push payload (RFC 8291), or a second service worker (the BBS) wanting its own push subscription
repo: nostr-rust-forum
---

# ADR-2023 — Content-free Web Push delivers reply, DM and new-message alerts to the PWA

## Context
- Alerts exist only in-app (`stores/notifications.rs`) and only while a tab holds the relay WebSocket. A closed or backgrounded PWA, the normal mobile state, gets nothing. `NotificationKind::DM` is rendered but nothing ever produces it.
- `sw.js` has no `push` / `notificationclick` handler; the relay fans out to live sessions only (`relay_do/broadcast.rs`).
- Gift-wrapped DMs (kind 1059) and E2E zones (ADR-2016) reach the relay as ciphertext plus a visible recipient `p` tag. The nsec lives in `localStorage`, which a service worker cannot read, and moving it to IndexedDB would breach the ADR-109 threat model.
- Push payloads transit Google, Apple and Mozilla. Cryptography must come from audited RustCrypto crates, never a bespoke envelope.

## Decision
1. **Option A, payload-less Web Push.** The relay POSTs an empty, VAPID-signed (RFC 8292, ES256 via `p256`) request to each subscription endpoint. No message text, author, channel or recipient detail crosses a push service. RFC 8291 encrypted payloads are explicitly out of scope; adopting them needs a new ADR.
2. **The service worker drains counts on wake.** Each subscription holds a random 256-bit bearer token (only its SHA-256 is stored). On `push` the SW calls `POST /api/push/drain {id, token}` and receives content-free counters (`dm`, `reply`, `topic`, `post`) plus at most one `/go/<event-id>` deep link per category, then shows one notification per non-zero category. A zero or failed drain shows a generic notification so `userVisibleOnly` is honoured.
3. **The relay fans out after `save_event`** (`nip_handlers.rs`), resolving recipients and then sending inside `state.wait_until`, so the sender's OK is never delayed. No Queues binding is added.
   - kind 1059: recipient is the `p` tag; skipped when the submitting session is authenticated as that same pubkey (the NIP-17 self-copy), which needs no protocol change.
   - kind 42: `p`-tagged members receive a *reply* alert; opted-in members receive a *post* alert. kind 40: opted-in members receive a *topic* alert.
   - Every kind 40/42 recipient passes the same `resolve_viewer_context` + `authorize_event` gate as live delivery, so a push never reveals a post the recipient cannot read.
4. **Server-side preferences** (`push_prefs`, per pubkey): replies, dms, new_topics, new_posts, muted channels, quiet hours. Defaults: replies and dms on; topics and posts off. Counts for suppressed categories are not accumulated.
5. **Subscription hygiene.** Register and unsubscribe require NIP-98 and a whitelisted pubkey; endpoints must be `https` on an allow-listed push-service host (SSRF guard); a device can also unsubscribe with its own drain credentials (no signer), which is how logout stops that device waking for the account that left; at most 10 subscriptions per pubkey; a 404/410 from the push service deletes the row, repeated failures delete it too.
6. **The forum service worker (`/community/sw.js`) owns push.** The BBS SW (`bbs-sw.js`, scope `/community/bbs/`) does not subscribe in v1.
7. **Default off.** The relay needs `PUSH_ENABLED="true"`, `VAPID_PUBLIC_KEY`, `VAPID_SUBJECT` and the secret `VAPID_PRIVATE_KEY`. The client learns of the feature from `GET /api/push/config`, so no client rebuild or `window.__ENV__` change is needed to switch it on.
8. **Tier 0 ships with it, and needs no server push.**
   - A layout-level watcher (`dm::start_incoming_watcher`, mounted by the notification bell once the relay session is authenticated) opens each gift wrap not yet announced and creates a `DM` notification. The per-page `DMStore` only subscribes while a DM screen is open, so it cannot do this. The sync baseline and a persisted per-wrap id make it announce a DM once.
   - While the page is hidden, permission is granted and server push is not active on the device, addressed notifications (DMs, mentions, join and RSVP notices) are also raised as generic system notifications through the service worker registration. Generic channel chatter (`Message`) stays in-app, matching the server defaults where new posts are opt-in.
   - With server push off, Settings offers a minimal "Browser alerts" permission control, so Tier 0 is reachable on a deployment that has not set up VAPID.

## Consequences
- Alerts reach closed PWAs on desktop and Android, and on iOS 16.4+ once installed to the Home Screen, with permission requested from a tap.
- Notification text is necessarily generic ("New direct message", "3 new replies"). Richer text means RFC 8291 and a new ADR.
- A new D1 migration (`0010_push.sql`; also applied idempotently by `ensure_schema`) adds `push_subscriptions` and `push_prefs`. Fan-out costs one D1 read per event and one subrequest per notified device; it is capped per event (`PUSH_MAX_FANOUT`, default 100) and pushes are throttled per device (5 s for DMs and replies, 60 s for topics and posts), because gift-wrap admission only requires a whitelisted *recipient* and a stranger's burst must not buzz a phone. Counters keep accumulating while throttled and the 5-minute cron's trailing flush wakes any device still holding undelivered counters, so a quick second DM is delayed, never lost.
- Operators must generate a VAPID key pair (P-256) and set the secret; the kit repin follows the dual-pin rule.
- WebKit (iOS) can revoke a subscription after repeated pushes that show no notification. The only path that skips one is a visible window inside the forum scope (the retro BBS and any same-origin marketing tab do not count), and the service worker otherwise always shows something, generic if it must.
- A repeated submission of an already stored event (a client republishing after a reconnect) does not alert twice.
- Each installed instance has its own subscription; an instance that never reopens leaves a stale row until the push service reports 404/410.

## Verification
- `cargo test -p nostr-bbs-relay-worker push` covers: the RFC 8292 §2 example JWT verifying under its published key, VAPID round-trip, endpoint allow-list, token hashing, fan-out classification and the self-copy skip, and every SQL statement run on SQLite. `cargo test -p nostr-bbs-core push` covers preferences and quiet hours.
- `cargo test -p nostr-bbs-forum-client` covers the Tier 0 DM gating and system-notification predicate.
- At `verified_commit`: relay-worker, core and forum-client suites pass (1,737 Rust tests across the three crates), the service-worker suite passes (`node --test crates/nostr-bbs-forum-client/tests/sw-push.test.mjs`, 11 tests), clippy is clean, and both wasm32 builds succeed.
- The release Trunk build (`trunk build --release --public-url /community/`) succeeds and emits `snippets/*/js/push.js` and the push handlers in `sw.js`. `deepsec revalidate` over the diff's findings leaves no unfixed HIGH or HIGH_BUG that this work introduced.
- Not verified here: a live Cloudflare deploy, a real push service round trip, and device behaviour on iOS. `activation_status` stays `staged` until an operator sets the VAPID pair and tests on devices.

## Close-out 2026-10-30

No status change; `review_trigger` now names the activation event. The live client (`curl -sL https://dreamlab-ai.com/community/`, 2026-10-30T19:30Z) exposes no `VAPID_*` key in `window.__ENV__`, and the relay-side secrets cannot be read from here. `activation_status` stays staged until the VAPID pair is set and a device round trip is recorded.
