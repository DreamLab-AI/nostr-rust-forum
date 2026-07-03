# ADR-090 — Path discipline at the FORUM_BASE boundary

- **Status:** Accepted (sprint-resident — canonical full text lives with the sprint
  that authored it)
- **Canonical location:**
  [`../sprint/2026-05-17-ux-audit/ADR-090-forum-base-path-discipline.md`](../sprint/2026-05-17-ux-audit/ADR-090-forum-base-path-discipline.md)

## Why this stub exists

ADR numbers are allocated in this directory (`docs/adr/` is the canonical register),
but this decision was authored inline with the 2026-05-17 UX-audit sprint and is
cited directly by `nostr-bbs-forum-client` code from its sprint location. This stub
reserves the number here and completes the canonical directory (closeout 2026-07-03)
so no reader has to discover the record is elsewhere. The full context, decision, and
consequences are in the canonical file linked above.

**Summary:** internal app paths are always base-relative; the `FORUM_BASE` prefix is
added in exactly two places (`<Router base=>` and `base_href()`). Fixes the
double-prefix, self-referential `returnTo`, and service-worker deep-route 404 bugs.
