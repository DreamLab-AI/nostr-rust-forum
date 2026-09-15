---
id: EXP-FB-006
parent_spec: forum-member-feedback-2026-09 item 6
linked_adrs: []
priority: critical
regression_critical: true
evidence_category: executable
status: accepted
authored_by: pair
---

## Expectation: search can return a result, and can be reached on a phone

Member feedback, verbatim: *"Search seems completely broken - unclear if just on
mobile..."*. Both halves were true, for different reasons.

**It could only ever return `[]`.** `pages/channel.rs` ingested every message
with `public: false` hardcoded. The worker fail-closes on that flag
(`is_search_visible`), so every vector the client ever indexed was filtered out
of every response. `public` is now derived from the owning zone's read policy —
`required_cohorts.is_empty()`, the kit's definition of unauthenticated read —
and falls back to `false` for any zone that cannot be resolved. The fail-closed
worker default is deliberately KEPT: `/search` is unauthenticated, so a
default-visible index would turn any ingest bug into disclosure of gated
content. `/ingest` now rejects an all-private batch with a 400 rather than
silently writing unreachable vectors; deliberate private ingest opts in with
`allowPrivate`.

**Results were truncated before being filtered.** The store truncated to `k`,
then the visibility filter ran, so a top-`k` dominated by private vectors
yielded far fewer than `k` hits, or none. The worker now over-fetches
(`OVERFETCH_FACTOR`, capped) and takes `k` *after* filtering.

**The base URL was an unresolvable placeholder.** `search_client.rs` defaulted
to `https://search.example.com` (RFC 2606 reserved), so `search_similar()` and
`get_search_status()` could never work, while `global_search.rs` used a
different constant — the two files disagreed. One resolver now reads
`window.__ENV__` at runtime, then the compile-time value, then a reachable
default; `SETUP.md`'s documented variable name is reconciled with the code's.

**`limit` vs `k`.** Both clients sent `"limit"`; the worker only reads `"k"`.
Masked by `default_k() == 10`, and locked in by a BBS-client test that asserted
the wrong field. Fixed in all three places.

**Mobile had no entry point.** The nav search button sits in the `hidden sm:flex`
desktop block, the hamburger's Search item is inside `<Show when=is_authed>`,
`MobileBottomNav` has no search entry, and Ctrl/Cmd+K does not exist on touch —
so a signed-out mobile visitor could not open search at all. A search button now
sits beside the hamburger, outside any auth gate.

Also fixed: whitespace-only queries (which produced an all-zero embedding that
matched the entire index at score 0 under the `>=` minScore default) are trimmed
and rejected; `SearchResult.score` gained `#[serde(default)]` so one score-less
row no longer fails the whole parse.

### In scope
- Ingest visibility derivation, over-fetch-then-filter, base-URL resolution,
  the `k` wire contract, query trimming, the mobile entry point
- 20 tests across the three crates covering the wire contract and the filter

### Out of scope (intentionally)
- The `channel` filter was a silent no-op (the worker never read it) and has been
  REMOVED client-side rather than implemented: the index is a flat
  `(label, vector)` store with no per-vector channel metadata, so a real filter
  means a schema change plus a full re-ingest — a feature, not a bug fix.
- **Vectors already ingested with `public: false` stay invisible.** The flag is
  only ever written at ingest time; existing entries need re-ingesting. No
  backfill job exists, and writing one was out of scope.
- The mobile keyboard possibly occluding the `15vh`-offset results panel
  (`style.css:587-599`) — needs a device to confirm.

### Counter-examples (must NOT happen)
- A gated zone's message indexed as publicly searchable
- The visibility filter running after truncation
- A client sending `limit` where the worker reads `k`
- Any build resolving the search API to `example.com`
