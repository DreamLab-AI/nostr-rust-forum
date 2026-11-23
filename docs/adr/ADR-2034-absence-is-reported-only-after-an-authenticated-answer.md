---
id: ADR-2034
title: A deep-linked page reports "not found" only after an authenticated answer from the relay
date: 2026-11-22
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: 4a73a7a (zone-key wait from fd31193 and the 2026-11-23 note, read 2026-11-23; tests not run for the note); 3c48e26 (Context, Decision and Verification text)
verified_paths: [crates/nostr-bbs-forum-client/src/utils/lookup.rs, crates/nostr-bbs-forum-client/src/zone_crypto/grant_backlog.rs, crates/nostr-bbs-forum-client/src/pages/section.rs, crates/nostr-bbs-forum-client/src/relay/receipt.rs, crates/nostr-bbs-forum-client/src/relay.rs, crates/nostr-bbs-forum-client/src/pages/thread.rs, crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs]
owner: jjohare
review_trigger: a change to the zone-key grant sync or its stall window and cap (zone_crypto/grant_backlog.rs); a change to the relay's AUTH or subscription-cap handling
repo: nostr-rust-forum
domain: BASELINE-architecture.md
evidence_class: source+ci+runtime
acceptance_boundary: Established at 3c48e26 - the receipt logic and the page decisions exist as described (read by line) and the CI run for that commit concluded success. Not established - any browser run; the thread of PR 91 records that none had been made. implementation_status is partial because the operator observed on 2026-11-22 that in an encrypted zone a cold link can still show "Topic Not Found" for about 12 to 29 seconds before correcting itself; this ADR's rule does not yet cover the wait for zone keys. Added 2026-11-23 - kit PR #98 (fd31193) added the zone-key wait, and the operator's live run of 2026-11-22 on the deployed build at fd31193 (a cold device opening an encrypted-zone topic link) showed "Fetching your keys for this zone…" from 9.2 s and the topic at 28.4 s with no "Topic Not Found"; that is the first browser run (operator-reported, not repeated by the recorder) and, with CI run 45068503736 for fd31193 concluding success, the reason implementation_status is now complete. The concurrency limits KF-22 and KF-24 stay open and are not part of the rule.
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

  > Note 2026-11-23: this gap is closed. Kit PR #98 (`fd31193`) added `Lookup::decide_with_keys` (`utils/lookup.rs:134`),
  > fed by the zone-key store's grant-backlog phase (`ZoneKeyStore::key_phase_for`, `zone_crypto/store.rs:173`;
  > `zone_crypto/grant_backlog.rs`, 20 s stall window at `:35`, 120 s cap at `:42`). After the relay's authenticated
  > answer, an encrypted zone's topic page (`pages/thread.rs:645-675`) and section topic list (`pages/section.rs:318-340`)
  > show "Fetching your keys for this zone…" while the backlog is pending or moving, a reload message once it stalls, and
  > an absence only once the keys have settled. The no-answer path (15 s) and unencrypted zones are unchanged. Live check
  > by the operator on 2026-11-22: "Fetching your keys for this zone…" from 9.2 s, the topic at 28.4 s, no "Topic Not
  > Found". KF-23 is closed. Line numbers in the Decision and Verification sections are as of `3c48e26`.
- Known limits: the cap check at `nip_handlers.rs:1858-1869` precedes `wrap_read_set(...).await` at `:1907` and the
  insert at `:1931`, so concurrent REQs on one socket can both pass it (KF-22); a post made while the socket is closed is
  flushed on reopen before AUTH (KF-24).

## Verification

Run from the repository root of the worktree at `3c48e26`, reading code only; no cargo test or build was run.

- `grep -n "pub fn settles\|pub fn decide\|pub const LOOKUP_DEADLINE_MS" crates/nostr-bbs-forum-client/src/utils/lookup.rs` returned `:37`, `:62`, `:91`.
- `grep -n "pub const AUTH_RETRY_LIMIT\|pub const REQ_ANSWER_TIMEOUT_MS\|pub const REQ_RESEND_LIMIT\|pub const AUTH_SIGN_TIMEOUT_MS\|pub const AUTH_ANSWER_TIMEOUT_MS\|pub struct ReqLedger\|pub fn wire_id" crates/nostr-bbs-forum-client/src/relay/receipt.rs` returned `:42`, `:50`, `:55`, `:60`, `:67`, `:71`, `:158`.
- `grep -n "Lookup::decide" crates/nostr-bbs-forum-client/src/pages/thread.rs crates/nostr-bbs-forum-client/src/pages/section.rs crates/nostr-bbs-forum-client/src/pages/category.rs` returned `thread.rs:642`, `:649`, `section.rs:305`, `:315`, `category.rs:148`; the `Memo` at `thread.rs:638-655` takes the channel, `history_receipt` and the deadline, and no zone-key input. `grep -n "Unavailable\"" ...` over the same three files returned `thread.rs:1188`, `section.rs:574`, `:578`, `category.rs:538`.
- `grep -n "subscription_cap_reached\|\.insert(sub_id.to_string()\|wrap_read_set(&session_pubkey)" crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs` returned `:52` (definition), `:1862` (check), `:1907` (the await), `:1931` (insert), `:2787`, and tests at `:7666-7677`.
- `sed -n 507,512p crates/nostr-bbs-forum-client/src/relay.rs` shows `pending_messages` drained on connect, and `sed -n 1021,1024p crates/nostr-bbs-forum-client/src/relay.rs` shows the comment that a closed socket's queue "is flushed on reconnect BEFORE the next AUTH".
- CI: `.github/workflows/ci.yml:113` runs `cargo test --workspace --all-targets --all-features`; run 45056144222 for `3c48e2656d7cabefa894a59b827f5f0d3a8b32b7` concluded `success` (not inspected beyond that).
