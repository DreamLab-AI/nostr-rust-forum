# ADR-090 — Path discipline at the FORUM_BASE boundary

**Date:** 2026-05-17
**Status:** Accepted
**Supersedes:** ad-hoc usage of `base_href` / `location.pathname.get()` in `app.rs`.

## Context
Forum is deployed at sub-paths (production `/community/`, dev `/`). Compile-time `FORUM_BASE` is passed to `<Router base=>`. Multiple call sites independently compose paths with the base, producing inconsistencies:
- `main.rs:49` registered SW at `./sw.js` (browser-relative).
- `AuthGatedChat`/`AuthGatedChannel`/etc. fed `location.pathname.get()` (which returns the prefixed path) into `login_redirect_target`, which then went back through `use_navigate(…)` — and the router re-prefixed → `/community/community/forums`.
- `login.rs::return_to` only rejected `"/login"`, not the prefixed `"/community/login"`.

## Decision
Adopt the following invariant **everywhere**:

> Internal paths inside the app are always **base-relative** (start with `/`, do not contain the `FORUM_BASE` prefix). The prefix is added in exactly two places: `<Router base=>` (automatic) and `base_href()` for `<A>` / `window.location.set_href`.

Concrete rules:
1. **Never** pass `location.pathname.get()` to `use_navigate(...)`. Always strip `FORUM_BASE` first via the new helper `current_app_path()`.
2. **Never** include `FORUM_BASE` in a `returnTo` query string.
3. Service worker registration uses `format!("{FORUM_BASE}/sw.js")` (absolute) and an explicit `scope = format!("{FORUM_BASE}/")`.
4. `return_to` validators reject any path that starts with `FORUM_BASE` (after stripping, re-validate).

## Consequences
- Eliminates Bug #1 (double prefix) and Bug #6 (self-referential `returnTo`).
- Eliminates Bug #3 (SW 404 on deep routes) and unblocks PWA installation.
- One helper, one rule — future routes can't reintroduce the class.
- Trivial unit-testable: `current_app_path("/community/forums")` ≡ `"/forums"`; with `FORUM_BASE=""`, identity.
