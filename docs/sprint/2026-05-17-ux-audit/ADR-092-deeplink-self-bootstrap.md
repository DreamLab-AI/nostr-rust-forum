# ADR-092 — Deep-link entry must self-bootstrap

**Date:** 2026-05-17
**Status:** Accepted

## Context
A direct `GET /community/chat/<id>` shows "0 messages · 0 members" while the same channel entered via click-from-hub renders 3 real messages. `ChannelPage` (`pages/channel.rs`) is a **passive** consumer of `ChannelStore.channel_messages`; the kind-42 subscription lives in App-root `start_msg_sync` triggered after the kind-40 channel-list EOSE. On direct deep-link, when the page mounts the resolver maps (`by_id` / `by_name` / `by_section`) are still empty, so any kind-42 events whose `e` tag points to the requested channel get dropped.

Same architectural cause underlies the persistent "Loading…" h1 (channel_info filtered by id-only never matches slug-based URLs).

## Decision
Add `ChannelStore::ensure_subscribed(cid_or_slug)` — idempotent — called from `ChannelPage::on_mount`:

1. Await `start_sync` EOSE (kind-40 channel list).
2. Resolve `cid_or_slug` to a concrete `cid` via `by_id`/`by_name`/`by_section`. Block until first resolution OR a timeout (~4 s) elapses.
3. Open a narrow kind-42 subscription `#e: [cid]` (complementary to the broad one — relay handles duplicate REQs).
4. Mark this cid as "subscribed" in a set so the second call is a no-op.

Header h1 derivation moves to a `Memo` that re-runs when either `channels` or `channel_info` changes:
```rust
let title = Memo::new(move |_| {
    channel_info.get().map(|c| c.name)
        .or_else(|| store.channels.with(|ch| ch.iter().find(|c| matches(c, &cid)).map(|c| c.name.clone())))
        .unwrap_or_else(|| "Loading…".into())
});
```

## Consequences
- Direct deep-link parity with click-nav. Eliminates Bugs #8, #9, #16.
- Slight increase in relay subscriptions on multi-tab use; relay-worker DO already handles dedup.
- Future principle: **any page reachable by URL must boot its own data**; do not rely on side-effects from a sibling page that may never have mounted.
