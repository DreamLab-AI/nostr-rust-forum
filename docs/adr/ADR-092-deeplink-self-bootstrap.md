# ADR-092 — Deep-link entry must self-bootstrap

- **Status:** Accepted (sprint-resident — canonical full text lives with the sprint
  that authored it)
- **Canonical location:**
  [`../sprint/2026-05-17-ux-audit/ADR-092-deeplink-self-bootstrap.md`](../sprint/2026-05-17-ux-audit/ADR-092-deeplink-self-bootstrap.md)

## Why this stub exists

ADR numbers are allocated in this directory (`docs/adr/` is the canonical register),
but this decision was authored inline with the 2026-05-17 UX-audit sprint and is
cited directly by `nostr-bbs-forum-client` code from its sprint location. This stub
reserves the number here and completes the canonical directory (closeout 2026-07-03).
The full context, decision, and consequences are in the canonical file linked above.

**Summary:** a deep-link entry (arriving directly at a nested route) must bootstrap
its own required state rather than assuming an earlier screen already ran — otherwise
a shared/bookmarked URL lands on an unpopulated view.
