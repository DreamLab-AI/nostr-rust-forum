# ADR-091 — Channel post counts must be derived, not accumulated

- **Status:** Accepted (sprint-resident — canonical full text lives with the sprint
  that authored it)
- **Canonical location:**
  [`../sprint/2026-05-17-ux-audit/ADR-091-channel-counts-derived-from-events.md`](../sprint/2026-05-17-ux-audit/ADR-091-channel-counts-derived-from-events.md)

## Why this stub exists

ADR numbers are allocated in this directory (`docs/adr/` is the canonical register),
but this decision was authored inline with the 2026-05-17 UX-audit sprint and is
cited directly by `nostr-bbs-forum-client` code from its sprint location. This stub
reserves the number here and completes the canonical directory (closeout 2026-07-03).
The full context, decision, and consequences are in the canonical file linked above.

**Summary:** channel post counts are derived from the event set on demand, never
accumulated in a mutable counter — accumulation drifts against deletions and
replaceable events; derivation cannot.
