# PRD — Section topic lists (forum and BBS)

**Owner:** jjohare
**Status:** Accepted (operator, in session, 2026-11-28: "new relay feature is fine, just get it implemented, these are
necessary and useful as we load test the system at message scale")
**Date:** 2026-11-28
**Decisions:** [ADR-2034](../adr/ADR-2034-absence-is-reported-only-after-an-authenticated-answer.md) (absence),
[ADR-2037](../adr/ADR-2037-pin-a-section-to-a-zone-from-zone-config.md) (pins),
[ADR-2038](../adr/ADR-2038-one-request-returns-a-section-s-topic-stats.md) (section stats)
**Code:** client-core `topics::board` (`FrozenBoard`, `classify_topics`), `topics::section_stats`, `stores::channels`;
forum `pages/section.rs`; BBS `views/thread.rs`; relay `relay_do/section_stats.rs`

No earlier PRD covered topic lists: `prd-bbs-retro-client.md` names the board only as a parity item and
`prd-gap-close-forum.md` covers governance. This document holds the requirements both clients' section list meets.

## Problem

A section (kind-40 channel) lists its topics (kind-42 roots) with last activity, last participant and reply count, newest
activity first. Before ADR-2038 the client learned these per topic (one REQ and one COUNT per topic, five at a time): about
30 s for 168 topics on the live relay, and the list reshuffled as answers landed. PR #130 froze the list, but only the topics
active in the newest-100-message window were in true order.

## Requirements

| Id | Requirement | How it is met | Evidence |
|---|---|---|---|
| TL-1 | The whole list is in true order (newest activity first, ties by id) when it freezes, for every topic the relay can attribute. | One `SECTION-STATS` answer per visit, folded into the order before the freeze (ADR-2038 §8). | client-core seeded test `section_stats_freeze_the_true_order_and_nothing_moves_after`; relay oracle test against `classify_topics` |
| TL-2 | After the freeze no row moves; figures may change. | `FrozenBoard` (PR #130), unchanged rule. | seeded tests in `topics::board` |
| TL-3 | First paint is no slower than before (3.4–4.5 s on the live relay). | The section stats are asked with the root list and wait only within the existing 1.5 s paint hold. | `first_paint_ready` test; live timing is a rollout check |
| TL-4 | No layout shift; row heights unchanged. | No new row content or control; "↻ N updated" keeps its reserved space. | unchanged markup |
| TL-5 | "↻ N updated" counts real activity newer than the freeze, and a row that arrived late below a row of lower known activity; 0 on a quiet section, including while older pages append genuinely older topics. | `FrozenBoard::updated` (ADR-2038 §8). | `a_late_row_below_a_lower_known_row_counts_as_updated`, `genuinely_older_late_rows_and_unknown_activity_count_nothing`, seeded test |
| TL-6 | A freeze forced by the 20 s cap before the window or the section stats answered does not show a false "updated" on a quiet section. | Provisional baseline, re-taken once when the first of them lands. | `a_cap_freeze_before_window_or_stats_retakes_the_baseline_once`, seeded test |
| TL-7 | Access to the figures is exactly access to the section by REQ: zone cohorts, admin bypass, encrypted zones, the ADR-2037 pin, AUTH state. An unauthenticated or unauthorised reader learns nothing (no counts, ids or timestamps) and never sees "0 topics" for a refusal. | Admission through `channel_read_decision_for(42, …)`; refusals are `CLOSED`; a missing section is refused with the same text. | relay `admission_matrix_matches_the_channel_read_rule`, `a_missing_section_is_refused_like_an_unreadable_one` |
| TL-8 | Deleted roots and replies are not counted; edits are not activity; another channel's events never count. | Relay rules (ADR-2038 §5). | relay oracle and targeted tests |
| TL-9 | Encrypted zones: the relay never needs plaintext; sealed roots are reported under their envelope id with the original id, and the client folds both. | ADR-2038 §6; `SectionStats::get`. | `sealed_root_reports_envelope_id_with_original_and_hides_the_migrator`, `dual_present_original_is_the_topic_and_counts_replies_to_either_id` |
| TL-10 | Holds at message scale: sections of thousands of topics, channels of 10^5–10^6 messages; bounded work per request; an explicit truncation signal; no full scans; no D1 schema change. | Capped index walks, count budget, `truncated`, 30 s memo (ADR-2038 §7). | cost and plan tests; `measure_section_stats_cost` (native SQLite, not D1) |
| TL-11 | Old client with new relay and new client with old relay both work; the client never hangs on an absent or refusing relay. | NIP-11 advertisement; any refusal, `NOTICE` or 8 s timeout falls back to the PR #130 behaviour. | client `relay::section_stats_tests`, `advertised` tests |
| TL-12 | The per-topic pump is a fallback and fills only figures the answer lacks; it never reorders. | Pump waits for the section stats and skips topics they cover. | page wiring (both clients) |

## Out of scope / follow-up

- Unread counts for a member's subscribed threads across sections (kit PR #131): a sibling `TOPIC-STATS` request, designed in
  ADR-2038, not built.
- Legacy roots without the topic marker are listed from the window only (ADR-2038 limits).
- Pagination past 1,000 marked roots per section.

## Acceptance (rollout)

On a deployment with the relay and both clients at this change: the relay's NIP-11 advertises `nostr_bbs.section_stats`; a
member opening the 168-topic section sees every row in true order at first paint, with no reorder after; first paint at or
under the previous 3.4–4.5 s; a non-member gets no figures; signed out, nothing for a gated section; D1 rows read per section
open within the ADR-2038 estimate.
