---
id: ADR-2034
title: A deep-linked page reports "not found" only after an authenticated answer from the relay
date: 2026-11-22
decision_status: accepted
implementation_status: partial
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 3c48e26
verified_paths: [crates/nostr-bbs-forum-client/src/utils/lookup.rs, crates/nostr-bbs-forum-client/src/relay/receipt.rs, crates/nostr-bbs-forum-client/src/relay.rs, crates/nostr-bbs-forum-client/src/pages/thread.rs, crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs]
owner: jjohare
review_trigger: the zone-key wait on cold deep links landing (branch fix/cold-link-wait-for-zone-keys); the first browser run of a cold deep link into an encrypted zone; a change to the relay's AUTH or subscription-cap handling
repo: nostr-rust-forum
domain: BASELINE-architecture.md
evidence_class: source+ci
acceptance_boundary: Established at 3c48e26 - the receipt logic and the page decisions exist as described (read by line) and the CI run for that commit concluded success. Not established - any browser run; the PR thread for #91 records that none had been made. implementation_status is partial because the operator observed on 2026-11-22 that in an encrypted zone a cold link can still show "Topic Not Found" for about 12 to 29 seconds before correcting itself; this ADR's rule does not yet cover the wait for zone keys.
---

# ADR-2034 — A deep-linked page reports "not found" only after an authenticated answer from the relay

## Context

A topic, section or zone URL opened cold showed "Topic Not Found", "Section Not Found", "No topics yet" or "No sections
yet" until the message sync finished. The pages decided from `ChannelStore::loading`, which clears on the channel list's
first EOSE, after six seconds, or at once from cache, none of which says the kind-42 history had been requested. NIP-42
made it worse: the relay answers a REQ that began before AUTH with the anonymous view and still sends its EOSE, and for
a members-only zone that view omits the very events the page waits for. The client also marked itself authenticated when
the AUTH frame was sent, not when the relay accepted it, and the relay's 20-subscription cap counted a REQ that reused a
held id as new, so the replay after AUTH was refused at a full session.

## Decision

**Absence is a receipt, or a deadline, never a flag.** A page may say "not found" only when the relay's EOSE for the
subscription that would have carried the thing has arrived and, for a zone that is not public, that EOSE was an
authenticated answer (`SyncReceipt::settles`, `utils/lookup.rs:62`; `Lookup::decide`, `:91`). Presence beats everything and
a receipt beats the clock. No receipt within `LOOKUP_DEADLINE_MS` (15 s, `:37`) shows a separate "Unavailable" message,
so the page never claims an absence it did not observe (`pages/thread.rs:638`, `section.rs:305`, `category.rs:148`).

**AUTH counts when the relay accepts it.** The client keeps the kind-22242 event it sent; only the relay's `OK true` for
that event id counts. On acceptance it replays every subscription, flushes held writes, then sets
`authenticated` (`relay.rs`). A rate-limited AUTH is re-sent up to `AUTH_RETRY_LIMIT` (3) times; an AUTH that is refused,
cannot be signed within `AUTH_SIGN_TIMEOUT_MS` (60 s) or is not answered within `AUTH_ANSWER_TIMEOUT_MS` (10 s) releases
held writes so the relay's refusal reaches each publish callback (`relay/receipt.rs:42-67`).

**A per-subscription REQ ledger decides which answers are authenticated.** Each subscription counts REQs sent and not yet
answered and records whether the latest went out after acceptance; an EOSE or CLOSED is an authenticated answer only
when nothing is outstanding and that latest REQ was authenticated, whatever order the relay answers in (`ReqLedger`,
`receipt.rs:71`). The socket's state when an EOSE lands is not consulted, because the relay reads the session's auth at
the start of each REQ. A REQ unanswered after `REQ_ANSWER_TIMEOUT_MS` (8 s) is re-sent at most `REQ_RESEND_LIMIT` (2)
times, each under a fresh wire subscription id after a CLOSE of the old one, and an answer under a retired id is
discarded (`wire_id`, `:158`), so an answer is never credited to a REQ sent after it.

**The relay's cap exempts a replacement.** A REQ that reuses a subscription id the session already holds replaces it, so
`subscription_cap_reached(held, replaces_existing)` does not count it (`nip_handlers.rs:52`, applied at `:1862`).

## Consequences

- A cold deep link into a members-only zone waits for AUTH instead of flashing "not found"; a relay that never answers
  is reported as unavailable after 15 s, not as absent. Logged-out visitors never reach these pages: the routes are
  auth-gated and the relay connects only while signed in.
- Gap: the decision has no input for zone-key readiness. In an encrypted zone the authenticated answer can arrive before
  the keys do, and the page can say "Topic Not Found" until they load (`pages/thread.rs:638-655` takes the channel, the
  history receipt and the deadline only). Tracked as KF-23.
- Known limits: the cap check at `nip_handlers.rs:1858-1869` precedes `wrap_read_set(...).await` at `:1907` and the
  insert at `:1931`, so concurrent REQs on one socket can both pass it (KF-22); a post made while the socket is closed is
  flushed on reopen before AUTH (KF-24).

## Verification

Run in the worktree at `3c48e26`, reading code only; no cargo test or build was run.

- `grep -n "pub fn settles\|pub fn decide\|pub const LOOKUP_DEADLINE_MS" crates/nostr-bbs-forum-client/src/utils/lookup.rs` returns `:62`, `:91`, `:37`.
- `grep -n "pub const AUTH_RETRY_LIMIT\|REQ_ANSWER_TIMEOUT_MS\|REQ_RESEND_LIMIT\|AUTH_SIGN_TIMEOUT_MS\|AUTH_ANSWER_TIMEOUT_MS\|pub struct ReqLedger\|pub fn wire_id" crates/nostr-bbs-forum-client/src/relay/receipt.rs` returns the constants at `:42`, `:50`, `:55`, `:60`, `:67`, the ledger at `:71` and `wire_id` at `:158`.
- `grep -n "Lookup::decide" crates/nostr-bbs-forum-client/src/pages/{thread,section,category}.rs` shows the three pages deciding from `settles(gated)` and the deadline; `thread.rs:638-655` has no zone-key input. `grep -n "Unavailable" crates/nostr-bbs-forum-client/src/pages/{thread,section,category}.rs` returns the messages at `thread.rs:1188`, `section.rs:574`, `:578`, `category.rs:538`.
- `grep -n "subscription_cap_reached\|subscriptions.insert\|wrap_read_set(&session_pubkey)" crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` returns `:52`, `:1862`, `:1907`, and the `.insert(sub_id.to_string()` at `:1931`.
- The line `crates/nostr-bbs-forum-client/src/relay.rs:507-536` flushes `pending_messages` on connect before the AUTH exchange; the comment at `:1021-1023` says so.
- CI: run 45056144222, conclusion `success`, for `3c48e2656d7cabefa894a59b827f5f0d3a8b32b7`.
