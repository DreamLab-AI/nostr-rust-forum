---
id: ADR-2038
title: One SECTION-STATS request returns every topic's last activity and reply count for a section
date: 2026-11-28
decision_status: accepted
implementation_status: complete
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 34fa898 (branch feat/section-topic-stats, stacked on fix/topic-list-stability ef41392); later commits on the branch touch docs and evidence only
verified_paths: [crates/nostr-bbs-relay-worker/migrations/0017_topic_root_channel_index.sql, crates/nostr-bbs-relay-worker/src/relay_do/section_stats.rs, crates/nostr-bbs-relay-worker/src/relay_do/section_stats_tests.rs, crates/nostr-bbs-relay-worker/src/relay_do/mod.rs, crates/nostr-bbs-relay-worker/src/nip11.rs, crates/nostr-bbs-client-core/src/topics/section_stats.rs, crates/nostr-bbs-client-core/src/topics/board.rs, crates/nostr-bbs-client-core/src/relay.rs, crates/nostr-bbs-client-core/src/relay/info.rs, crates/nostr-bbs-client-core/src/stores/channels.rs, crates/nostr-bbs-client-core/src/zone_crypto/tickets.rs, crates/nostr-bbs-forum-client/src/pages/section.rs, crates/nostr-bbs-bbs-client/src/views/thread.rs]
owner: jjohare
review_trigger: the first deployment of a relay carrying it; any change to the channel read rule (channel_read_decision_for), to the topic, reply, edit or sealed tag shapes, to event_tags or its indexes; the subscriptions feature (kit PR #131) asking for cross-section unread counts
repo: nostr-rust-forum
domain: BASELINE-architecture.md
evidence_class: source+test
acceptance_boundary: Established by native tests on the branch - the relay's exact SQL run against SQLite with the relay schema and indexes and compared with the clients' own classify_topics over 12 seeded sections (deletions, edits, reactions, quotes, expired events, sealed and dual-present roots, a legacy unmarked root, crafted cross-channel events), the caps and truncation, query-plan and VM-step cost assertions, the admission matrix against channel_read_decision_for, the client's frame routing (answer, CLOSED, an old relay's NOTICE, a cancelled request), the fold and parse, and a 300-seed FrozenBoard invariant with section stats answered, failed and capped; plus cargo fmt, clippy -D warnings, the wasm32 workspace check, the workspace test suite and rustdoc -D warnings. Amended after the PR #134 review: single flight and a concurrency cap, visit-bounded walks, migration 0017 (a partial index, run on local SQLite and a local D1 via wrangler/miniflare with identical results), the REQ expiry rule, a live reply growing its topic's count, and a cap-freeze baseline clamped at the paint time, each with tests (cost and baseline tests run failing first). Not established - behaviour on the hosted Cloudflare D1 (timing, the index build on the live table), in a deployed Durable Object, against the live relay or its data, in a browser (first paint, layout), or with old client builds; costs are measured on native SQLite only. activation_status stays inactive until a relay carrying this is deployed and both clients are repinned.
---

# ADR-2038 — One SECTION-STATS request returns every topic's last activity and reply count for a section

## Context

A section (kind-40 channel) lists its topics (kind-42 roots) newest activity first. The clients learn each topic's last
activity and reply count per topic: a pump sends one REQ (`#e:[root]`, `limit:1`) and one COUNT per topic in batches of five.
On the live relay a 168-topic section takes about 30 s. PR #130 (`topics::FrozenBoard`) freezes the list at first paint so
rows never move, but then only topics active in the newest-100-message window are in true order; every other row is ordered
by root creation for the whole visit. Load testing at message scale needs the whole list in true order at first paint,
without one request per topic, and without breaking the stored message database.

## Decision

1. **A new frame on the existing socket.** `["SECTION-STATS", <id>, {"channel": "<64 lowercase hex>"}]`. The relay answers
   once with `["SECTION-STATS", <id>, <payload>]` or `["CLOSED", <id>, "<prefix>: <reason>"]`. It holds no subscription,
   so the 20-subscription cap does not apply; it passes the per-IP frame limiter like COUNT
   (`relay_do/section_stats.rs` `handle_section_stats`, dispatch in `relay_do/mod.rs`).

2. **Wire contract (version 1).**

   ```text
   ["SECTION-STATS", "stats_7", {"channel": "c0c0…c0"}]
   ["SECTION-STATS", "stats_7", {
       "channel": "c0c0…c0", "as_of": 1764331200, "truncated": false,
       "fields": ["id", "created_at", "last_at", "last_pubkey", "replies", "original"],
       "topics": [["<root id>", 1764000000, 1764330000, "<pubkey>", 12, null],
                  ["<envelope id>", 1763000000, 1764100000, null, 3, "<original id>"], …]}]
   ["CLOSED", "stats_7", "auth-required: section stats need an authenticated reader"]
   ["CLOSED", "stats_7", "restricted: section not readable"]
   ["CLOSED", "stats_7", "error: section stats unavailable, try again"]
   ["CLOSED", "stats_7", "invalid: expected {\"channel\": <64-character lowercase hex id>}"]
   ["CLOSED", "stats_7", "rate-limited: slow down"]
   ```

   `topics` rows follow `fields` (clients read by name, so added fields are ignored), in the clients' `board_order`: newest
   activity first, ties by id. `last_at` is the root or its newest reply, `null` when not determined. `last_pubkey` is that
   activity's author, `null` when unknown or when the newest reply is a sealed envelope (its outer author is the migrator).
   `replies` is exact, `null` past the caps below. `original` is a sealed root's original id. `truncated` is true when the
   section has more marked roots than the answer lists. NIP-11 advertises it:
   `"nostr_bbs": {"section_stats": {"verb": "SECTION-STATS", "version": 1, "max_topics": 1000, "count_visit_cap": 1000,
   "memo_secs": 30}}` (`relay_do/mod.rs` `section_stats_advert`, `nip11.rs`).

3. **Admission is the REQ/COUNT rule, not a copy of it.** The answer describes the channel's kind-42 messages, so it is
   admitted exactly as each of them is on REQ, COUNT and broadcast: `channel_read_decision_for(42, …)` on the zone
   `cached_channel_zone` resolves (the ADR-2037 pin first, then the 60 s memo, then D1), for the viewer
   `resolve_viewer_context` builds (device→owner, admin flag, cohorts). Admin bypass, public read, cohorts, encrypted
   zones, a pin and a failed zone lookup (withhold) all come from that function; `section_stats::admission` only picks the
   refusal text. Admission runs before the answer memo is read.

4. **Absence and refusal (ADR-2034).** A refused reader gets `CLOSED`, never an answer, so no caller reads a refusal as
   "0 topics". The refusal is `auth-required:` for a socket without accepted AUTH and `restricted:` otherwise, and an
   admitted request for a section with no stored kind-40 and no `channel_creators` row gets the same text, so a refusal does
   not reveal which ids are gated channels (a REQ for a hidden channel returns nothing, indistinguishable from an unknown
   id). A D1 failure is `error:`, never an empty answer.

5. **What is counted**, `classify_topics` restricted to what tags show (the relay never sees plaintext):
   - a topic root is a stored kind-42 with the marker `["t","topic"]` whose `root`-marked `e` tag is the channel and which
     has no `reply`-marked `e` tag (sealed roots carry this outer shape);
   - a reply to root `R` is a stored kind-42 whose own channel (first `root`-marked `e`, else first `e`) is the channel, whose
     first `reply`-marked `e` is `R`, and which has no `edit`-marked `e` (an edit is never activity, as in `classify_topics`;
     the per-topic pump now skips edits too, `stores/channels.rs` `note_topic_latest`);
   - NIP-40 expired events are neither (the REQ path's rule); an honoured kind-5 removes the row, so deleted roots and
     replies are never seen; a crafted event filed in another channel never counts, so another zone's activity cannot leak.

6. **Sealed roots (ADR-2017).** A sealed root is reported under its **envelope id** (the stored event, the id the root list
   returns) with `original` set; replies naming either id count for it (sealed and live replies name the original). When the
   plaintext original is still stored beside its envelope, the original is the topic and the envelope is not listed; replies
   naming the envelope count for the original. Clients index each row under both ids (`SectionStats::get`), so the stats
   follow the row whether it is shown under its envelope or, once opened, its original.

7. **Bounded cost, one additive index.** All statements bound the rows they *visit*, not only the rows that qualify
   (`relay_do/section_stats.rs`; amended after the PR #134 review, below):
   - roots: through migration 0017's partial expression index `idx_events_topic_root_channel` (topic roots only, keyed by
     the first tag's value, the channel for every root the forum and the migrator write), so only this channel's roots are
     read. Until 0017 is applied the index is missing (`no such index`), the relay remembers that for 10 minutes and walks at
     most 20,000 topic-marked tag rows newest first instead, setting `truncated` when the walk stops at its cap;
   - one statement per 100 ids (bound as one JSON array) gives each id its last activity (a walk of at most 256 `e`-tag rows
     naming it, newest first on `idx_event_tags_time`, stopping at the first reply; `last_at: null` when the walk runs out)
     and its reply count (a walk of at most 1,000 `e`-tag rows naming it, reactions and other references included;
     `replies: null` when the walk reaches the cap). Once 20,000 count rows have been visited the remaining statements carry
     activity only (`replies: null`);
   - the existence check (`events` kind-40 or `channel_creators`) runs only when no root was found.

   A section of 300 topics costs 4 statements per uncached answer (was 34). The payload is memoised per channel for 30 s
   in the Durable Object (`section_stats_cache`) and shared by every admitted reader (admission is per channel and
   all-or-nothing for kind-42s). One computation per channel runs at a time and every concurrent reader of that channel
   waits for its answer after its own admission (`SingleFlight`); at most two computations run at once in the isolate,
   and a third channel is answered `error: … try again` (the client falls back) if it exists, or with the reader's
   missing-section refusal if it does not (`busy_answer`), so filling the slots does not make the refusal an existence
   oracle (re-review). Counts are as of the answer's `as_of` (`created_at <= now` on the count walk, like COUNT's
   `until`), so a reply dated ahead of the relay's clock is not counted twice with the client's own additions. An
   `INDEXED BY` failure reading "no such index" or "no query solution" falls back to the walk.

   **Migration 0017** (`crates/nostr-bbs-relay-worker/migrations/0017_topic_root_channel_index.sql`, additive and
   idempotent, not in `ensure_schema`, applied by the operator):

   ```sql
   CREATE INDEX IF NOT EXISTS idx_events_topic_root_channel
     ON events (json_extract(tags, '$[0][1]'), created_at)
     WHERE kind = 42 AND instr(tags, '["t","topic"]') > 0;
   -- rollback: DROP INDEX IF EXISTS idx_events_topic_root_channel;
   ```

   It holds one entry per topic root only; every insert evaluates the partial predicate (an `instr` over the tags text);
   building it is one pass over `events`. The relay stores tags as compact JSON (`storage.rs`, `serde_json::to_string`), so
   the marker test matches every root it stored; a row written with spaced JSON by another tool is not found through it.

8. **Clients** (shared in client-core; forum `pages/section.rs`, BBS `views/thread.rs`):
   - ask once per visit, with the root list and under its AUTH rule (after AUTH in a gated zone), only when the relay's NIP-11
     advertises it (`relay/info.rs` fetches NIP-11 once per session, started when the channel store begins syncing so the
     first visit does not wait on it, and shared with the zone-group bindings); not advertised,
     any `CLOSED`, an old relay's `NOTICE "Unknown message type: SECTION-STATS"` (no toast), a malformed answer or no answer
     within 8 s counts as failed (`SectionStatsState::from_answer`, `ChannelStore::request_section_stats`);
   - the answer is folded into the structure the board orders by with `max` (`fold_section_stats`): it only raises a figure;
   - first paint waits for window, root list and section stats within the existing 1.5 s hold (`first_paint_ready`); the
     freeze waits for all three to answer or fail, capped at 20 s as before (`freeze_ready`); after the freeze nothing moves;
   - the per-topic pump runs only once the section stats have settled, and only for topics whose count or activity the
     answer lacks (all topics when it failed). It never enters the order;
   - `FrozenBoard` (coordinator review of PR #130): "↻ N updated" also counts a row appended after the freeze that sits below
     a row of strictly lower activity when both rows' activity is known from section stats (an older page's genuinely older
     topic never counts); a freeze forced by the cap before the window or the section stats answered takes a provisional
     baseline, re-taken once when the first of them lands (or one more 20 s cap later if neither ever does), never past
     the paint time, so a reply that arrives after the paint is still offered (PR #134 review finding 4); the control stays
     hidden until then;
   - a section stats answer seeds each counted topic's total (`section_stats_totals`, as of the answer), and a live reply,
     never an edit, adds to its topic's total (`reply_topic`, `ChannelStore::note_inserted`), so a row's count follows new
     replies during the visit (PR #134 review finding 3).

## Consequences

**Compatibility.**
- *Old client, new relay:* the client never sends the frame; nothing changes.
- *New client, old relay:* the NIP-11 document has no `section_stats` block, so the frame is never sent; the board behaves
  exactly as at PR #130 (freeze on window and root list, per-topic pump for figures). Should a stale NIP-11 answer let it
  through, the old relay's `NOTICE` fails the request quietly, and the 8 s timeout covers anything else.
- *Relay without the NIP-11 fetch reachable* (CORS, network): treated as not advertised.

**Failure modes.** Relay refusal, D1 error, timeout or a socket drop before the answer: the request fails, the board freezes
on window and root list as before (the 20 s cap is unchanged), and the per-topic pump fills every figure. A late answer
after the timeout is dropped (`cancel_section_stats`, request generations in the store).

**Scale.** Measured on native SQLite (bundled with `rusqlite`, release build, in-memory), not D1. PR #134 review scenarios,
before (b2d2c7d) and after (`08-review-before.log`, `12-review-after.log`):

| Scenario | Statements before → after | VM steps before → after | Wall before → after |
|---|---|---|---|
| Common: 300 topics × 30 replies, 2,000 roots elsewhere | 34 → 4 | 1.82 M → 1.82 M | 130 → 123 ms |
| Worst: 20 topics, one with 3 replies and 50,000 reactions | 4 → 2 | 382 k → 56 k | 32 → 5 ms |
| Worst: 10-topic section, 50,000 topic roots elsewhere | 3 → 2 | 2.76 M → 16 k | 171 → 3 ms |

The common case's work is counting its ~9,000 replies, now in 4 statements instead of 34; several members opening the same
section within 30 s cost one computation. In the second case the reacted topic reports `replies` and `last_at` as `null`
(the client's pump fills them) and the rest stay exact. Tests assert the bounds: doubling every topic's replies past the caps,
quadrupling a topic's reactions and multiplying other channels' roots leave the work unchanged. The earlier table
(`02-scale-measurement.log`) predates the review. On D1, by the relay's own measurement of about 40 ms per 2,000
index-plus-row reads (`relay_do/read_cache.rs`, `COUNT_WINDOW_ROWS`), the common uncached answer is estimated at roughly
0.1–0.3 s of D1 time; this is an estimate, not a measurement. The same statements and migration ran on a local D1
(wrangler/miniflare) with results identical to SQLite (`11-local-d1-check.log`).

**Limits (honest).**
- Legacy roots without the `["t","topic"]` marker are not listed (the root list has the same gap); they keep the window's
  figures and are never treated as having known activity.
- Kind-1111 comments are not counted (their admission follows the target, not the channel); the `max` fold keeps any the
  client holds.
- A locked sealed edit carries its `edit` marker inside the ciphertext and counts as a reply, as it does in
  `classify_topics` while locked.
- Replies naming a root in a case other than the stored id's, or only through an unmarked `e` tag (legacy), are not counted;
  the relay is a lower bound and the fold never lowers a figure.
- A section with more than 1,000 marked roots lists the 1,000 most recently created (`truncated`). Without migration 0017 a
  section whose roots are older than the relay's newest 20,000 topic roots gets `truncated` and may list fewer topics.
- Reply counts in a batch past the 20,000-row budget are `null` even for small topics; batches go in root-creation order,
  not activity order. The budget is checked between statements, so one answer can overshoot it by up to one statement's
  count walks (100 ids × 1,000 rows; the reviewer's worst-case estimate is about 120,000 rows visited). Accepted.
- An unknown id holds a computation slot only for an empty indexed roots lookup and the existence check.
- `last_at` relies on `event_tags.created_at` mirroring `events.created_at` (migration 0015 backfill), as paging does.
- The answer may be up to 30 s old; the window's newest messages are folded in by the client anyway.
- D1: the statements and migration 0017 ran on a local D1 (wrangler/miniflare) with results identical to SQLite, and
  the missing-index error text matched; not run on the hosted D1. If it refuses them, every answer is `CLOSED error:` and
  both clients fall back to the PR #130 behaviour.

**Accepted, recorded from the PR #134 review (not fixed).**
- (5, fixed) Expiry now parses as the REQ path's `u64::parse` does (`+1`, long zero-padded values).
- (6) A refusal is never asked again in the visit, including an `auth-required:` that the relay says the client re-asks
  after AUTH. Clients send in gated zones only after AUTH, so this needs client and relay to disagree about gating; the
  next visit asks again. Follow-up.
- (7a) For an authenticated reader admitted to an unscoped id with no roots, a missing section costs one more D1
  statement than a gated one; the timing difference is accepted.
- (7b) `last_at: null` tells an admitted reader that 256 or more `e`-tag references to that topic exist, some of which
  (in other channels) it may not be able to read. Accepted: a count of references, no ids or times.
- (7c) `activity_known` treats the relay's figure as exact, but the relay ignores kind-1111 comments, reply-to-reply
  chains and replies without a `reply` marker that `classify_topics` follows; the worst effect is a wrong "1 updated"
  on a row whose true activity is higher than the relay knows. Accepted.

**Rollback.** Revert the relay change: NIP-11 drops the block, new clients stop asking and behave as before. Reverting a
client alone is equally safe. Migration 0017 adds one index and rewrites no data: `DROP INDEX IF EXISTS
idx_events_topic_root_channel;` removes it, and the relay falls back to the bounded walk.

**Alternatives rejected.**
- *NIP-98 HTTP endpoint.* AUTH is already established on the socket; HTTP would need a signature per request (a prompt for
  NIP-07 signers), a second copy of viewer resolution outside the Durable Object's caches, and per-viewer responses defeat
  HTTP caching. The socket form reuses the DO's memos and limiter and holds no subscription slot.
- *Extend NIP-45 COUNT.* COUNT answers one number; a new filter key would reach an old relay's COUNT fast path as
  `{"kinds":[42],"#e":[cid]}` and start a full windowed count of the channel, then answer a misleading number.
- *A materialised `topic_stats` table maintained by triggers on `events`* (reconsidered once database changes were
  allowed). Exact at O(page), but a trigger on the hot write path that can fail writes and a backfill over every message;
  the operator asked for the smallest change that bounds the worst case, which the 0017 index and visit caps are.
- *A per-channel snapshot in DO storage* (as message counts do). Deletions would drift the counts (ADR-2033 requires they
  are not counted) and seven deletion paths would need hooks.

**Subscriptions (kit PR #131).** Unread counts for a member's subscribed threads across sections are a different question
(per topic, since a read position, across channels), so this request does not serve it. The sibling would be
`["TOPIC-STATS", <id>, {"topics": [[<root>, <since>], …]}]` answering `[<root>, <replies since>, <last_at>]` per topic,
each topic admitted by its own channel through the same `channel_read_decision_for(42, …)` (channel from the stored root),
counted by a `since`-bounded walk of `idx_event_tags_time` (cheap: only rows newer than the read position), capped per
request. Recorded as follow-up; not implemented here.

## Verification

From the worktree root at the head of the PR #134 review fixes (see the report and `07`/`13` gate logs):

- `cargo test -p nostr-bbs-relay-worker --lib section_stats`: oracle against `classify_topics` over 12 seeds on the index
  path and the fallback walk, deletion, sealed and dual-present, cross-channel leak, edits and reactions, expiry (including
  `+1` and zero-padded values), truncation, the count visit cap, the budget, walk exhaustion, the missing-index fallback,
  bounded cost under reactions and under other channels' roots, plan assertions, the admission matrix with pin, missing
  section, request validation, NIP-11, and single flight (shared answer, cap, abandoned leader). The three cost and expiry
  tests were run failing before the fix (`09-review-relay-red.log`).
- `cargo test --release -p nostr-bbs-relay-worker --lib measure_review_scenarios -- --ignored --nocapture` for the table.
- Local D1: `emit_local_d1_check` writes the statements, a seeded section and SQLite's results; run with
  `wrangler d1 execute --local` (`11-local-d1-check.log`).
- `cargo test -p nostr-bbs-client-core --lib`: section-stats parse, fold, freeze readiness, answer mapping, frame routing,
  seeded totals and `reply_topic`, the FrozenBoard tests (late rows, cap baseline, a reply after a cap freeze, a baseline
  that settles one cap later; the last two run failing first, `10-review-board-red.log`) and the 300-seed invariant.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo check --workspace --target wasm32-unknown-unknown`, `cargo test --workspace --all-targets --all-features`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`, `node scripts/adr-index-gen.js docs/adr --check`.

Not verified: hosted D1, a deployed Durable Object (the handler's single-flight wiring is read, not run), the live relay, a
browser, old client builds; the store's live-reply total and timeout paths run only in wasm. Rollout checks: apply 0017 and
see `SEARCH ev USING INDEX idx_events_topic_root_channel` in its plan; the relay's NIP-11 shows `nostr_bbs.section_stats`; a
member opening a large section sees the whole list in true order at first paint and no row moves; a live reply bumps its row's
count; a non-member's frame is refused with `restricted:`; signed out, a gated section's frame gets `auth-required:`; first
paint is not slower than before (3.4–4.5 s); D1 rows read per section open, from the D1 dashboard.
