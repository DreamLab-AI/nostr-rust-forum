---
id: ADR-2018
title: Make relay read cost scale with requests, not delivered events — per-DO lookup caches and a coalesced trust ledger
date: 2026-09-29
decision_status: accepted
implementation_status: complete
activation_status: live
supersedes: []
superseded_by: []
verified_commit: HEAD
owner: jjohare
review_trigger: a change to LOOKUP_TTL_SECS or ACTIVITY_FLUSH_SECS; a new per-event D1 lookup on any read path; moving off the D1 free tier; a relay feature that needs cohort or zone changes honoured in under a minute
repo: nostr-rust-forum
domain: BASELINE-architecture.md
---

# ADR-2018 — Make relay read cost scale with requests, not delivered events

## Context

Cloudflare D1's free tier allows 5 M row reads a day. On a production instance
the relay database read 3.3–3.6 M rows on quiet days with no humans present and
5.2 M on one busy evening, after which D1 returned error 7500 and the relay
served nothing to anyone until midnight UTC. The cause was structural, not
volume: `authorize_event` issued two D1 queries per delivered kind-40/42 event
(`channel_zones`, then the viewer's whitelist row again via
`trust::has_zone_access`), `resolve_viewer_context` re-read device-owner and
cohort rows on every REQ, COUNT and live broadcast, and every REQ that delivered
anything wrote `posts_read`, `last_active_at` and ran `check_promotion`. A tab
opening a 50-message channel cost ~110 queries; one client re-sending its
subscription every 15 s cost seven reads and three writes a time.

## Decision

Read paths decide from state the Durable Object already holds. The DO carries
three 60-second memos and a write throttle (`relay_do/read_cache.rs`;
fields at `relay_do/mod.rs:97`):

- `cached_channel_zone` (`nip_handlers.rs:1821`) memoises channel → zone.
  Only a bound zone is cached; an unbound channel is re-read every time so a
  channel bound moments after its first read is never served as unscoped.
- `cached_viewer_cohorts` (`:1835`) memoises pubkey → (cohorts, whitelist
  admin), including the empty result for a non-member.
- `cached_device_owner` (`:1848`) memoises device key → owner for ADR-099.
- Zone membership on the read gate is the pure `zone_read_permitted`
  (`:1746`, used at `:1988`): public read, or whitelist admin, or a required
  cohort, from the cohorts already in `ViewerContext`. It is the rule
  `trust::has_zone_access` applied; that function is deleted.
- `ActivityLedger` coalesces the trust-ledger writes. `note_read_activity`
  (`:1860`, called at `:1547`) accumulates delivered reads in memory and
  flushes them with the `last_active_at` stamp and promotion check at most
  once per pubkey per `ACTIVITY_FLUSH_SECS` (300 s), or once 50 reads are
  pending. `note_write_activity` (`:1870`, called at `:1226`) throttles the
  stamp and check on the EVENT path; `posts_created` stays exact because it is
  the promotion counter itself.

The TTL equals the moderation cache's (`mod_cache.rs`), so a cohort revocation
or zone re-binding is honoured within the same minute a ban already is.

## Consequences

A REQ costs one D1 query per filter plus at most three cache-miss reads a
minute per viewer, whatever it delivers; live broadcast costs no D1 reads on a
warm DO. Cohort and zone changes take up to 60 s to apply on reads (admin
status already took 300 s). `last_active_at` and `posts_read` lag by up to five
minutes, and a DO eviction drops at most one window of pending reads; both are
signals for the six-month inactivity sweep and TL0→TL1 promotion, neither is
an audit field. Any new per-event lookup on a read path must go through a memo
or derive from `ViewerContext`; adding a raw D1 read there reopens this ADR.
Client-side, a subscriber that re-sends its filter every few seconds still
costs one query a time: the relay restores subscriptions from DO storage after
hibernation (`session.rs` `recover_session`), so such keep-warm loops are
unnecessary and should be pings.

## Verification

`cargo test -p nostr-bbs-relay-worker --lib` (357 tests, including
`read_cache::tests` for the memo and ledger and `zone_read_rule_tests` for the
gate rule), `cargo clippy -p nostr-bbs-relay-worker --all-targets -D warnings`
and `cargo check --target wasm32-unknown-unknown` all pass at the verified
commit. Live evidence is the D1 analytics floor after deploy: the pre-change
quiet-hour floor was ~13.5 k read queries and ~1,440 writes an hour.
