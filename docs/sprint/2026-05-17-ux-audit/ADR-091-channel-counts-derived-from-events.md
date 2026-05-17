# ADR-091 — Channel post counts must be derived, not accumulated

**Date:** 2026-05-17
**Status:** Accepted
**Supersedes:** `ChannelStore.message_counts: HashMap<String, u32>` mutated by `+= 1`.

## Context
Live audit showed channel post counts inflate on every visit (4 → 14 → 22 → … for the same channel). Root cause in `src/stores/channels.rs:232-272`:
- `message_counts.update(|m| *m.entry(cid).or_insert(0) += 1)` runs on every kind-42 delivery with **no event-id dedup**.
- `channel_messages: HashMap<String, Vec<NostrEvent>>` in the same closure **does** dedup.
- Counts are persisted to localStorage, rehydrated on next mount, and then the broad kind-42 subscription replays history → counts grow.
- Two pipelines from the same source data caused additional UI divergence (Bug #12: header summary "0 messages" vs tile "96 Messages").

## Decision
Delete the standalone `message_counts` field. Expose count as a **memoised derivation** of `channel_messages`:

```rust
pub fn count_for(&self, cid: &str) -> usize {
    self.channel_messages.with(|m| m.get(cid).map_or(0, Vec::len))
}
```

For the sum used in the chat-hub total tile, derive equivalently:

```rust
pub fn total_messages(&self) -> usize {
    self.channel_messages.with(|m| m.values().map(Vec::len).sum())
}
```

## Consequences
- Bugs #2, #12, #15 collapse: single source of truth, no sparse map, no inflation.
- `CachedData` schema bumps (`message_counts` removed). Forward-compat: deserialize ignores unknown fields; old caches just don't populate counts — re-derived on first kind-42 EOSE.
- Slight memory overhead: full event Vec instead of just a counter. Acceptable: the events were already cached for rendering.
- Future invariant: any new aggregation MUST be a `Memo` derived from `channel_messages`. Reject PRs that introduce parallel counters.
