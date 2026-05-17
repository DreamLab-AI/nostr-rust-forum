# PRD — Forum UX Triage 2026-05-17

## Context
Live audit of `dreamlab-ai.com/community` on 2026-05-17 catalogued **27 UX/UI defects** across 6 cross-cutting patterns. Catalogue: `bugs.md`. Code attribution: `codebase-findings.md`.

## Goals
1. **Zero P0 user-visible defects** on the next deploy.
2. **Posts that exist must render** on every entry path (direct deep-link, click-from-hub, reload).
3. **Single source of truth for channel counts** — chat hub, channel page, summary tile must agree.
4. **PWA installs from every route**, not only `/community/`.
5. **Auth state never lies** — UI either authenticated and working, or unambiguously logged out.

## Non-goals (this sprint)
- Profile activity feed (#13)
- New zone-landing renderer (#21)
- Encrypted local-key storage (#5 mitigation only, not full fix)
- Wrangler route rebranding (#26)

## Success criteria (acceptance)
Each test must pass on the live deploy:

| Test | P |
|------|---|
| Login from `/community/login` lands on `/community/forums` (no doubled prefix) | 0 |
| Reload `/community/chat` three times — `messages` tile stays constant | 0 |
| Direct GET `/community/chat/<channel-id>` renders the channel's existing messages within 4 s | 0 |
| `/community/forums/home/home-lobby` registers a service worker (`navigator.serviceWorker.controller` non-null) | 0 |
| Hit `/community/admin` as non-admin → toast "Admin access required" then redirect | 0 |
| Channel page h1 transitions Loading → channel name within 2 s (no "Loading…" stuck state) | 1 |
| Console contains **no** `[Relay] AUTH sync signing failed` on normal flow | 1 |
| Profile page `<h1>` is non-empty for any pubkey (falls back to npub short form) | 1 |
| `webgpu-particles.js` snippet appears with exactly **one** content hash in `dist/community/` | 2 |

## Out of scope warnings
Local-key (paste-nsec) login remains sessionStorage-only this sprint; we will explicitly surface "session expired — re-paste key" rather than fix the persistence story. Full fix tracked separately.

## Rollout
Single deploy after PRs 1–5 land + automated browser check passes. No feature flags — these are bug fixes.
