//! A section (kind-40 channel) as a list of TOPICS.
//!
//! A *topic* is a kind-42 ROOT message in the channel (a thread starter): its
//! e-tags reference the channel id as the root and it is not itself a reply
//! to another in-channel message. A *reply* is a kind-42 (or NIP-22
//! kind-1111) event that e-tags a topic root, directly or through another
//! reply. The board lists topics newest activity first with their reply
//! count and last poster. Shared by the forum's section page and the BBS
//! board view so both list the same topics in the same order.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use nostr_bbs_core::NostrEvent;

use super::thread::edit_target_of;

/// A single topic (kind-42 root) plus its derived thread stats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicSummary {
    /// The kind-42 root event id (the thread anchor).
    pub id: String,
    /// Author pubkey of the root post.
    pub pubkey: String,
    /// First line / full content of the root post (the topic title/body).
    pub content: String,
    /// Root post creation time.
    pub created_at: u64,
    /// Number of replies (kind-42 / kind-1111) e-tagging this root.
    pub reply_count: u32,
    /// Most recent activity timestamp across the root and all its replies.
    pub last_activity: u64,
    /// Pubkey of the most recent participant (root author if no replies).
    pub last_pubkey: String,
}

/// Extract the root e-tag value of a kind-42, preferring the explicit "root"
/// marker, then the first `e` tag. Returns `None` when the event has no e-tag.
fn root_e_tag(event: &NostrEvent) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
        .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
        .map(|t| t[1].clone())
}

/// All `e`/`E`-tag values referenced by an event, lowercased, EXCLUDING the
/// channel id itself (so a reply's channel-anchor `e` tag isn't mistaken for a
/// reference to the topic it replies to).
fn referenced_event_ids(event: &NostrEvent, channel_id_lower: &str) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && (t[0] == "e" || t[0] == "E"))
        .map(|t| t[1].to_lowercase())
        .filter(|v| v != channel_id_lower)
        .collect()
}

/// The reply parent of an event, if it is a reply rather than a topic root.
///
/// Returns the id of the message this event replies to, or `None` when the
/// event is a topic root (anchored only to the channel) or has no usable e-tag.
///
/// Logic (handles both reply shapes the client emits):
/// - A `"reply"`-marked `e` tag pointing at a non-channel event → that target.
/// - Otherwise, an `e`/`E` tag referencing a non-channel event (e.g. NIP-22
///   kind-1111 `E` root, or a legacy reply whose only e-tag is the parent) →
///   that target.
/// - An event whose every e-tag is the channel id (a topic root anchored to the
///   section) → `None`.
fn reply_parent(event: &NostrEvent, channel_id_lower: &str) -> Option<String> {
    // Explicit "reply" marker wins.
    if let Some(t) = event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && (t[0] == "e" || t[0] == "E") && t[3] == "reply")
    {
        let target = t[1].to_lowercase();
        if target != channel_id_lower {
            return Some(target);
        }
    }
    // Otherwise the first non-channel referenced event (skipping self).
    let self_lower = event.id.to_lowercase();
    referenced_event_ids(event, channel_id_lower)
        .into_iter()
        .find(|v| v != &self_lower)
}

/// Classify the events in a section channel into topic roots and reply counts.
///
/// Purely client-side over the channel's kind-42 stream plus any NIP-22
/// kind-1111 comments the store grouped under the channel.
///
/// - A **topic root** is a kind-42 anchored to the section channel and NOT a
///   reply to anything else: it carries the channel as its root `e` tag and has
///   no reply target other than the channel. This is exactly what
///   `category.rs::publish_topic_root` / `section.rs::publish_topic_root` emit,
///   and the shape legacy flat-chat root posts already have.
/// - A **reply** is any kind-42/kind-1111 that has a reply parent (a
///   non-channel referenced event). Replies fold into their parent root,
///   bumping its reply count and last-activity.
///
/// Note the store anchors a reply to the channel (its `"root"`-marked tag points
/// at the channel id), so a reply DOES appear in this event list and DOES carry
/// the channel root tag — the discriminator is whether it ALSO has a non-channel
/// reply parent. A reply whose parent root is not (yet) in this list is still
/// excluded from the topic roots (it is not a thread starter) but cannot be
/// folded; it simply does not inflate the list.
pub fn classify_topics(channel_id: &str, events: &[NostrEvent]) -> Vec<TopicSummary> {
    let cid_lower = channel_id.to_lowercase();

    // Pass 1: seed topic roots — kind-42 anchored to the channel with no
    // non-channel reply parent.
    let mut roots: HashMap<String, TopicSummary> = HashMap::new();
    let mut root_order: Vec<String> = Vec::new();
    for ev in events {
        if ev.kind != 42 {
            continue;
        }
        let anchored_to_channel = root_e_tag(ev)
            .map(|r| r.to_lowercase() == cid_lower)
            // No e-tag at all → defensive root (legacy / malformed).
            .unwrap_or(true);
        let is_reply = reply_parent(ev, &cid_lower).is_some();
        if anchored_to_channel && !is_reply {
            roots.entry(ev.id.clone()).or_insert_with(|| {
                root_order.push(ev.id.clone());
                TopicSummary {
                    id: ev.id.clone(),
                    pubkey: ev.pubkey.clone(),
                    content: ev.content.clone(),
                    created_at: ev.created_at,
                    reply_count: 0,
                    last_activity: ev.created_at,
                    last_pubkey: ev.pubkey.clone(),
                }
            });
        }
    }

    // Pass 2: fold replies into their parent root.
    // Lower-cased views for the parent walk: the root ids, and every event
    // by id, so each hop is a lookup and not a scan of the channel.
    let root_lower: HashSet<String> = roots.keys().map(|k| k.to_lowercase()).collect();
    // Lower-cased id -> stored id, so attributing a reply is a lookup rather
    // than a scan of every root (quadratic over a paged-in channel).
    let root_by_lower: HashMap<String, String> = roots
        .keys()
        .map(|k| (k.to_lowercase(), k.clone()))
        .collect();
    let by_id: HashMap<String, &NostrEvent> =
        events.iter().map(|e| (e.id.to_lowercase(), e)).collect();

    for ev in events {
        if ev.kind != 42 && ev.kind != 1111 {
            continue;
        }
        // An edit re-publishes an existing post: neither a reply nor a new
        // participant, so it must not move the topic or name its byline.
        if edit_target_of(ev).is_some() {
            continue;
        }
        let parent = match reply_parent(ev, &cid_lower) {
            Some(p) => p,
            None => continue, // a root (or unanchored) — not a reply
        };
        // Match the parent against a known root (case-insensitive keys). A
        // reply to a reply names its parent, not the topic; walk up to the
        // root so it counts and can be the latest participant.
        let mut root_key = parent;
        let mut hops = 0;
        while !root_lower.contains(&root_key) && hops < 64 {
            hops += 1;
            match by_id
                .get(&root_key)
                .and_then(|e| reply_parent(e, &cid_lower))
            {
                Some(p) => root_key = p,
                None => break,
            }
        }
        if !root_lower.contains(&root_key) {
            continue; // orphaned reply: its chain never reaches a root here
        }
        if let Some(summary) = root_by_lower
            .get(&root_key)
            .and_then(|id| roots.get_mut(id))
        {
            summary.reply_count += 1;
            if ev.created_at > summary.last_activity {
                summary.last_activity = ev.created_at;
                summary.last_pubkey = ev.pubkey.clone();
            }
        }
    }

    // Newest activity first — the BBS convention (bumped threads rise).
    let mut out: Vec<TopicSummary> = root_order
        .into_iter()
        .filter_map(|id| roots.remove(&id))
        .collect();
    out.sort_by(board_order);
    out
}

/// The board's true order: newest activity first, ties broken by id so
/// two topics active in the same second always list the same way round.
pub fn board_order(a: &TopicSummary, b: &TopicSummary) -> Ordering {
    b.last_activity
        .cmp(&a.last_activity)
        .then_with(|| a.id.cmp(&b.id))
}

/// Fold the relay's per-topic stats into window-derived summaries: the
/// reply count becomes the exact total when that is larger (the window may
/// hold a fraction of the topic), and a newer reply than any held sets the
/// last activity and last participant. Re-sorted by [`board_order`].
/// `stats` returns (exact total, newest reply as (created_at, author)).
pub fn with_topic_stats(
    mut topics: Vec<TopicSummary>,
    mut stats: impl FnMut(&TopicSummary) -> (u32, Option<(u64, String)>),
) -> Vec<TopicSummary> {
    for t in &mut topics {
        let (total, latest) = stats(t);
        t.reply_count = t.reply_count.max(total);
        if let Some((ts, pk)) = latest {
            if ts > t.last_activity {
                t.last_activity = ts;
                t.last_pubkey = pk;
            }
        }
    }
    topics.sort_by(board_order);
    topics
}

/// How long a board waits for its root list and first stats before it
/// paints anyway, in milliseconds (see [`first_paint_ready`]).
pub const FIRST_PAINT_TIMEOUT_MS: i32 = 1_500;

/// Topics whose stats a board waits for before its first paint: the first
/// two stats batches (`stores::channels::TOPIC_STATS_BATCH` is 5).
pub const FIRST_PAINT_STATS: usize = 10;

/// Whether a board that has found its topics may paint them: once the
/// section's root list has answered (dormant topics are in, so none lands
/// mid-list later) and the stats of the first [`FIRST_PAINT_STATS`] listed
/// topics (or all of them, when fewer) are in, or once `timed_out`
/// ([`FIRST_PAINT_TIMEOUT_MS`] after the topics were found). A board whose
/// store already holds all of that paints at once.
pub fn first_paint_ready(
    roots_answered: bool,
    stats_answered: usize,
    listed: usize,
    timed_out: bool,
) -> bool {
    timed_out || (roots_answered && stats_answered >= listed.min(FIRST_PAINT_STATS))
}

/// Whether a painted board pages older history automatically: not when
/// its root list is complete (paging would add no topic), and otherwise
/// only once that list has answered, so dormant roots do not land in a list
/// already on screen. A root list that failed (timed out, or refused by the
/// relay) or a first-paint hold that expired releases the gate as well, so
/// a slow or refusing relay never switches paging off for the session.
pub fn older_paging_armed(
    roots_complete: bool,
    roots_answered: bool,
    roots_failed: bool,
    hold_expired: bool,
) -> bool {
    !roots_complete && (roots_answered || roots_failed || hold_expired)
}

/// The sealed originals among `events`, as (envelope id, original id). A
/// sealed topic root is listed under its envelope's id until its key
/// arrives, then under the original's own id (and back if the key is
/// dropped); [`stable_order`] uses these pairs to keep the row in place.
pub fn sealed_aliases(events: &[NostrEvent]) -> Vec<(String, String)> {
    events
        .iter()
        .filter(|e| e.kind == 42)
        .filter_map(|e| {
            nostr_bbs_core::sealed::parse_sealed(&e.tags).map(|r| (e.id.clone(), r.inner_id))
        })
        .collect()
}

/// The order a painted board shows its topics in, given the order it shows
/// now (`shown`, topic ids) and the true order (`sorted`, by
/// [`board_order`]).
///
/// - A topic already shown keeps its place, however its activity changed;
///   one that is gone is dropped.
/// - A shown topic that is gone but whose alias (`aliases`, both ways
///   between a sealed envelope and its original, see [`sealed_aliases`]) is
///   now listed and not shown elsewhere is replaced in place by it.
/// - A shown topic in `reposition` (its first stats have just landed) moves
///   once to its true place among the rows that stay: before the first of
///   them that sorts after it.
/// - A topic not shown yet goes to the top when it sorts ahead of the first
///   topic still shown (a brand-new topic, or one the window brings back),
///   otherwise to the bottom (an older page), each group in true order.
///
/// With nothing shown the true order is used. The result never holds an id
/// twice.
pub fn stable_order(
    shown: &[String],
    sorted: &[String],
    aliases: &HashMap<String, String>,
    reposition: &HashSet<String>,
) -> Vec<String> {
    let rank: HashMap<&str, usize> = sorted
        .iter()
        .enumerate()
        .rev()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let shown_set: HashSet<&str> = shown.iter().map(String::as_str).collect();
    let mut seen: HashSet<&str> = HashSet::with_capacity(sorted.len());
    let mut kept: Vec<&str> = Vec::with_capacity(shown.len());
    let mut moving: Vec<&str> = Vec::new();
    for id in shown.iter().map(String::as_str) {
        let id = if rank.contains_key(id) {
            id
        } else {
            match aliases.get(id).map(String::as_str) {
                Some(a) if rank.contains_key(a) && !shown_set.contains(a) => a,
                _ => continue,
            }
        };
        if !seen.insert(id) {
            continue;
        }
        if reposition.contains(id) {
            moving.push(id);
        } else {
            kept.push(id);
        }
    }
    moving.sort_by_key(|id| rank[id]);
    for id in moving {
        let r = rank[id];
        let at = kept.iter().position(|k| rank[k] > r).unwrap_or(kept.len());
        kept.insert(at, id);
    }
    let Some(first) = kept.first().map(|id| rank[id]) else {
        let mut once = HashSet::with_capacity(sorted.len());
        return sorted
            .iter()
            .filter(|id| once.insert(id.as_str()))
            .cloned()
            .collect();
    };
    let mut top = Vec::new();
    let mut bottom = Vec::new();
    for (i, id) in sorted.iter().enumerate() {
        if seen.insert(id.as_str()) {
            if i < first {
                top.push(id.clone());
            } else {
                bottom.push(id.clone());
            }
        }
    }
    top.into_iter()
        .chain(kept.into_iter().map(str::to_string))
        .chain(bottom)
        .collect()
}

/// The topics whose first stats have landed since the last call: in
/// `answered` now, never answered before (`before`, every id answered so
/// far this visit), and not the other half of a sealed pair (`aliases`,
/// both ways) that was. Then records them in `before`, with their aliases.
///
/// A sealed root that opens is listed under a new id, whose stats are asked
/// afresh; its row was already placed under the envelope's id, so its
/// stats landing must not move it again (nor after the key is dropped and
/// it reverts to the envelope).
pub fn first_stats_landed(
    answered: &HashSet<String>,
    before: &mut HashSet<String>,
    aliases: &HashMap<String, String>,
) -> HashSet<String> {
    let landed: HashSet<String> = answered
        .iter()
        .filter(|id| !before.contains(*id) && !aliases.get(*id).is_some_and(|a| before.contains(a)))
        .cloned()
        .collect();
    for id in answered {
        before.insert(id.clone());
        if let Some(a) = aliases.get(id) {
            before.insert(a.clone());
        }
    }
    landed
}

/// Whether the reader is at the top of a list: the list's first row lies
/// wholly inside the viewport (`row_*` and `view_*` are top and bottom
/// edges in the same coordinates). A new topic is then inserted in view
/// rather than above it; a reader further down keeps their place.
pub fn first_row_in_full_view(
    row_top: f64,
    row_bottom: f64,
    view_top: f64,
    view_bottom: f64,
) -> bool {
    row_top >= view_top - 0.5 && row_bottom <= view_bottom + 0.5
}

/// How many shown topics are out of their true place: the fewest rows that
/// would have to move for `shown` to read in `sorted` order (the length of
/// `shown` less its longest run already in true order). One topic bumped
/// by a reply counts one, not every row it would push down. Ids missing
/// from `sorted` are ignored.
pub fn out_of_order(shown: &[String], sorted: &[String]) -> usize {
    let rank: HashMap<&str, usize> = sorted
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let ranks: Vec<usize> = shown
        .iter()
        .filter_map(|id| rank.get(id.as_str()).copied())
        .collect();
    // Longest strictly increasing subsequence, patience sorting.
    let mut tails: Vec<usize> = Vec::new();
    for r in &ranks {
        let at = tails.partition_point(|t| t < r);
        if at == tails.len() {
            tails.push(*r);
        } else {
            tails[at] = *r;
        }
    }
    ranks.len() - tails.len()
}

/// Text of the control that re-sorts a board shown out of order: "↻ N
/// updated", N from [`out_of_order`].
pub fn updated_label(n: usize) -> String {
    format!("\u{21bb} {n} updated")
}

/// Accessible name of the same control: its visible text (WCAG 2.5.3,
/// so a voice user can say what they see), then what it does.
pub fn updated_accessible_name(n: usize) -> String {
    format!("{n} updated: re-sort topics by latest activity")
}

/// Derive a one-line topic title from the root post content.
///
/// Uses the first non-empty line, trimmed and clipped to a sane length so the
/// list stays scannable. Falls back to a placeholder for empty content.
pub fn topic_title(content: &str) -> String {
    let first_line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .trim();
    if first_line.is_empty() {
        return "(untitled topic)".to_string();
    }
    const MAX: usize = 120;
    if first_line.chars().count() > MAX {
        let clipped: String = first_line.chars().take(MAX).collect();
        format!("{}\u{2026}", clipped.trim_end())
    } else {
        first_line.to_string()
    }
}

/// The events a board classifies: channel `window` (its history window:
/// replies, live posts, roots of older channels without the topic marker)
/// plus the section's root list `roots` (every marked topic root, one
/// unwindowed REQ), deduplicated by id. Without the root list a window full
/// of replies to older topics would list no topics at all.
pub fn board_events(window: &[NostrEvent], roots: &[NostrEvent]) -> Vec<NostrEvent> {
    let mut all = window.to_vec();
    if roots.is_empty() {
        return all;
    }
    let held: HashSet<&str> = window.iter().map(|e| e.id.as_str()).collect();
    all.extend(
        roots
            .iter()
            .filter(|r| !held.contains(r.id.as_str()))
            .cloned(),
    );
    all
}

/// Messages of a channel newer than its read position `last_read` (a
/// kind-42 `created_at`; `0` when the channel was never opened, so every
/// message counts), as the forum index's "N new" chip counts them.
pub fn unread_count(events: &[NostrEvent], last_read: u64) -> u32 {
    events.iter().filter(|e| e.created_at > last_read).count() as u32
}

/// The newest kind-42 in `events` as (id, created_at), tie-broken by id:
/// the position a board or topic view marks its channel read at.
pub fn latest_post(events: &[NostrEvent]) -> Option<(String, u64)> {
    events
        .iter()
        .filter(|e| e.kind == 42)
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        })
        .map(|e| (e.id.clone(), e.created_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        id: &str,
        pk: &str,
        content: &str,
        ts: u64,
        kind: u64,
        tags: Vec<Vec<&str>>,
    ) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: pk.to_string(),
            created_at: ts,
            kind,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: content.to_string(),
            sig: String::new(),
        }
    }

    #[test]
    fn roots_and_replies_classified() {
        let cid = "channel0000000000000000000000000000000000000000000000000000000000";
        let t1 = "topic1111111111111111111111111111111111111111111111111111111111";
        let t2 = "topic2222222222222222222222222222222222222222222222222222222222";
        let r1 = "reply1111111111111111111111111111111111111111111111111111111111";

        let events = vec![
            // Two topic roots anchored to the channel.
            ev(
                t1,
                "alice",
                "First topic",
                100,
                42,
                vec![vec!["e", cid, "", "root"]],
            ),
            ev(
                t2,
                "bob",
                "Second topic",
                110,
                42,
                vec![vec!["e", cid, "", "root"]],
            ),
            // A reply to t1 in the EXACT shape ThreadPage emits: channel-anchored
            // root tag PLUS a "reply"-marked tag at the topic root. Must NOT be
            // mistaken for a topic root.
            ev(
                r1,
                "carol",
                "A reply",
                200,
                42,
                vec![
                    vec!["e", cid, "", "root"],
                    vec!["e", t1, "", "reply"],
                    vec!["p", "alice"],
                ],
            ),
            // A NIP-22 reply to t2.
            ev(
                "c1",
                "dave",
                "comment",
                150,
                1111,
                vec![vec!["E", t2, "", "root"], vec!["e", t2]],
            ),
            // A legacy reply whose only e-tag is the parent root id (no marker).
            ev("c2", "erin", "legacy reply", 120, 42, vec![vec!["e", t1]]),
        ];

        let topics = classify_topics(cid, &events);
        assert_eq!(
            topics.len(),
            2,
            "exactly two topic roots (replies excluded)"
        );

        // Sorted by last activity desc: t1 (last 200) before t2 (last 150).
        assert_eq!(topics[0].id, t1);
        assert_eq!(topics[0].reply_count, 2, "carol + erin reply to t1");
        assert_eq!(topics[0].last_activity, 200);
        assert_eq!(topics[0].last_pubkey, "carol");

        assert_eq!(topics[1].id, t2);
        assert_eq!(topics[1].reply_count, 1);
        assert_eq!(topics[1].last_activity, 150);
    }

    #[test]
    fn nested_replies_reach_the_topic_and_edits_do_not_move_it() {
        let cid = "channel0000000000000000000000000000000000000000000000000000000000";
        let t1 = "topic1111111111111111111111111111111111111111111111111111111111";
        let r1 = "reply1111111111111111111111111111111111111111111111111111111111";
        let r2 = "reply2222222222222222222222222222222222222222222222222222222222";
        let e1 = "edit11111111111111111111111111111111111111111111111111111111111";
        let events = vec![
            ev(
                t1,
                "alice",
                "First topic",
                100,
                42,
                vec![vec!["e", cid, "", "root"]],
            ),
            ev(
                r1,
                "carol",
                "A reply",
                120,
                42,
                vec![vec!["e", cid, "", "root"], vec!["e", t1, "", "reply"]],
            ),
            ev(
                r2,
                "dave",
                "A reply to the reply",
                130,
                42,
                vec![vec!["e", cid, "", "root"], vec!["e", r1, "", "reply"]],
            ),
            ev(
                e1,
                "alice",
                "First topic (edited)",
                140,
                42,
                vec![vec!["e", cid, "", "root"], vec!["e", t1, "", "edit"]],
            ),
        ];
        let topics = classify_topics(cid, &events);
        assert_eq!(topics.len(), 1, "the edit is not a topic of its own");
        assert_eq!(topics[0].reply_count, 2, "the nested reply counts");
        assert_eq!(
            topics[0].last_pubkey, "dave",
            "the nested reply is the latest participant"
        );
        assert_eq!(
            topics[0].last_activity, 130,
            "the edit does not move the topic"
        );
    }

    #[test]
    fn title_is_first_line_clipped() {
        assert_eq!(topic_title("Hello world\nrest"), "Hello world");
        assert_eq!(topic_title("   \n\n  Trimmed  \n"), "Trimmed");
        assert_eq!(topic_title(""), "(untitled topic)");
        let long: String = "x".repeat(200);
        assert!(topic_title(&long).ends_with('\u{2026}'));
    }

    fn summary(id: &str, replies: u32, last: u64, last_pk: &str) -> TopicSummary {
        TopicSummary {
            id: id.into(),
            pubkey: "root".into(),
            content: id.into(),
            created_at: 1,
            reply_count: replies,
            last_activity: last,
            last_pubkey: last_pk.into(),
        }
    }

    #[test]
    fn exact_totals_and_newest_reply_replace_window_figures() {
        // Wartracker: 26 replies held in the window, ~24k on the relay, its
        // newest reply newer than anything held; a quiet topic is untouched.
        let topics = vec![
            summary("quiet", 3, 500, "ann"),
            summary("wartracker", 26, 100, "bob"),
        ];
        let out = with_topic_stats(topics, |t| match t.id.as_str() {
            "wartracker" => (24_013, Some((900, "cat".to_string()))),
            _ => (3, Some((400, "old".to_string()))),
        });
        assert_eq!(out[0].id, "wartracker", "re-sorted by true activity");
        assert_eq!(
            (
                out[0].reply_count,
                out[0].last_activity,
                out[0].last_pubkey.as_str()
            ),
            (24_013, 900, "cat")
        );
        assert_eq!(
            (
                out[1].reply_count,
                out[1].last_activity,
                out[1].last_pubkey.as_str()
            ),
            (3, 500, "ann"),
            "an older relay answer never replaces a newer held reply"
        );
    }

    #[test]
    fn stats_not_in_yet_leave_the_window_figures() {
        let out = with_topic_stats(vec![summary("t", 5, 50, "dan")], |_| (0, None));
        assert_eq!((out[0].reply_count, out[0].last_activity), (5, 50));
    }

    /// The BBS defect: a big channel's history window holds only replies to
    /// topics older than the window. Every reply was listed as its own
    /// topic with 0 replies. With the section's root list merged in, the
    /// board lists the roots, the replies fold into them, and a reply whose
    /// root is nowhere is not a topic.
    #[test]
    fn window_of_replies_lists_the_roots_from_the_root_list() {
        let cid = "chan";
        let root = |id: &str, ts| ev(id, "op", id, ts, 42, vec![vec!["e", cid, "", "root"]]);
        let reply = |id: &str, to: &str, pk: &str, ts| {
            ev(
                id,
                pk,
                id,
                ts,
                42,
                vec![vec!["e", cid, "", "root"], vec!["e", to, "", "reply"]],
            )
        };
        let window = vec![
            reply("am-i", "general", "ann", 900),
            reply("why-agent", "general", "bob", 910),
            reply("usa-1", "usa", "cat", 905),
            reply("lost", "never-loaded", "dan", 920),
        ];
        let roots = vec![root("general", 10), root("usa", 20), root("quiet", 30)];
        let all = board_events(&window, &roots);
        let topics = classify_topics(cid, &all);
        let ids: Vec<&str> = topics.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(
            ids,
            ["general", "usa", "quiet"],
            "roots only, newest activity first"
        );
        assert_eq!(
            (topics[0].reply_count, topics[0].last_pubkey.as_str()),
            (2, "bob")
        );
        assert_eq!(topics[1].reply_count, 1);
        assert_eq!(topics[2].reply_count, 0);
        // Without the root list nothing in the window is a topic: never the
        // replies themselves.
        assert!(classify_topics(cid, &window).is_empty());
    }

    #[test]
    fn board_events_dedupe_roots_already_in_the_window() {
        let r = ev("r", "op", "t", 1, 42, vec![vec!["e", "chan", "", "root"]]);
        assert_eq!(
            board_events(std::slice::from_ref(&r), std::slice::from_ref(&r)).len(),
            1
        );
        assert_eq!(board_events(&[], std::slice::from_ref(&r)).len(), 1);
        assert_eq!(board_events(std::slice::from_ref(&r), &[]).len(), 1);
    }

    #[test]
    fn a_new_reply_brings_its_topic_to_the_top() {
        let cid = "chan";
        let mut events = vec![
            ev("old", "a", "old", 10, 42, vec![vec!["e", cid, "", "root"]]),
            ev("new", "b", "new", 20, 42, vec![vec!["e", cid, "", "root"]]),
        ];
        assert_eq!(classify_topics(cid, &events)[0].id, "new");
        events.push(ev(
            "r",
            "c",
            "bump",
            30,
            42,
            vec![vec!["e", cid, "", "root"], vec!["e", "old", "", "reply"]],
        ));
        let topics = classify_topics(cid, &events);
        assert_eq!(
            (topics[0].id.as_str(), topics[0].last_pubkey.as_str()),
            ("old", "c")
        );
    }

    #[test]
    fn unread_and_latest_post() {
        let es = vec![
            ev("a", "x", "", 10, 42, vec![]),
            ev("b", "x", "", 30, 42, vec![]),
            ev("c", "x", "", 20, 7, vec![]),
        ];
        assert_eq!(unread_count(&es, 0), 3);
        assert_eq!(unread_count(&es, 15), 2);
        assert_eq!(unread_count(&es, 30), 0);
        assert_eq!(latest_post(&es), Some(("b".into(), 30)));
        assert_eq!(latest_post(&[]), None);
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ties_in_activity_break_by_id_in_both_sorts() {
        let cid = "chan";
        let root = |id: &str| ev(id, "op", id, 50, 42, vec![vec!["e", cid, "", "root"]]);
        // Same second, delivered in either order: always b before c.
        for events in [vec![root("c"), root("b")], vec![root("b"), root("c")]] {
            let order: Vec<String> = classify_topics(cid, &events)
                .into_iter()
                .map(|t| t.id)
                .collect();
            assert_eq!(order, ids(&["b", "c"]));
        }
        let out = with_topic_stats(
            vec![summary("z", 0, 10, "a"), summary("y", 0, 5, "a")],
            |t| match t.id.as_str() {
                "y" => (0, Some((10, "b".into()))),
                _ => (0, None),
            },
        );
        let order: Vec<&str> = out.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, ["y", "z"], "tied at 10: by id");
    }

    #[test]
    fn nothing_shown_takes_the_true_order() {
        assert_eq!(order(&[], &ids(&["a", "b"])), ids(&["a", "b"]));
        // Every shown topic gone (another section's ids): the true order.
        assert_eq!(order(&ids(&["x"]), &ids(&["a", "b"])), ids(&["a", "b"]));
    }

    #[test]
    fn shown_topics_keep_their_place_when_their_activity_changes() {
        // c was bumped by a reply: true order c, a, b. The rows stay.
        let shown = ids(&["a", "b", "c"]);
        assert_eq!(order(&shown, &ids(&["c", "a", "b"])), shown);
        assert_eq!(out_of_order(&shown, &ids(&["c", "a", "b"])), 1);
    }

    #[test]
    fn new_topics_go_to_the_top_and_older_pages_to_the_bottom() {
        let shown = ids(&["b", "c", "d"]);
        // n is newer than everything shown; o and p come from an older page.
        let sorted = ids(&["n", "b", "c", "d", "o", "p"]);
        assert_eq!(order(&shown, &sorted), sorted);
        // A late dormant topic that belongs mid-list goes to the bottom,
        // where it reads out of order rather than pushing rows down.
        let sorted = ids(&["b", "m", "c", "d"]);
        let next = order(&shown, &sorted);
        assert_eq!(next, ids(&["b", "c", "d", "m"]));
        assert_eq!(out_of_order(&next, &sorted), 1);
    }

    #[test]
    fn a_new_topic_is_compared_with_the_first_row_still_shown() {
        // Shown b, a; a has since been bumped above b, and x arrives
        // between them. x sorts ahead of b, the row at the top of the
        // screen, so it goes on top: the rows below it do not move.
        let shown = ids(&["b", "a"]);
        let sorted = ids(&["a", "x", "b"]);
        assert_eq!(order(&shown, &sorted), ids(&["x", "b", "a"]));
    }

    #[test]
    fn gone_topics_are_dropped_and_nothing_is_listed_twice() {
        let shown = ids(&["a", "gone", "b", "a"]);
        let sorted = ids(&["b", "a", "new", "b"]);
        let next = order(&shown, &sorted);
        assert_eq!(next, ids(&["a", "b", "new"]));
        let unique: HashSet<&String> = next.iter().collect();
        assert_eq!(unique.len(), next.len());
        // Duplicates in the true order alone are dropped as well.
        assert_eq!(order(&[], &ids(&["a", "a"])), ids(&["a"]));
    }

    #[test]
    fn re_sorting_on_request_is_the_true_order() {
        // The "updated" control clears the shown order: the next order is
        // the true one and nothing reads out of order.
        let sorted = ids(&["c", "a", "b"]);
        let next = order(&[], &sorted);
        assert_eq!(out_of_order(&next, &sorted), 0);
    }

    #[test]
    fn out_of_order_counts_the_rows_that_would_move() {
        let sorted = ids(&["a", "b", "c", "d", "e"]);
        assert_eq!(out_of_order(&sorted, &sorted), 0);
        assert_eq!(out_of_order(&ids(&["e", "a", "b", "c", "d"]), &sorted), 1);
        assert_eq!(out_of_order(&ids(&["b", "a", "d", "c", "e"]), &sorted), 2);
        assert_eq!(out_of_order(&ids(&["e", "d", "c", "b", "a"]), &sorted), 4);
        assert_eq!(out_of_order(&ids(&["zz", "b", "a"]), &sorted), 1);
        assert_eq!(out_of_order(&[], &sorted), 0);
    }

    #[test]
    fn first_paint_waits_for_the_root_list_and_the_first_stats() {
        // Found, but the root list has not answered: hold.
        assert!(!first_paint_ready(false, 40, 40, false));
        // Root list in, first stats batch only: hold.
        assert!(!first_paint_ready(true, 5, 40, false));
        // Root list and the first two batches: paint.
        assert!(first_paint_ready(true, FIRST_PAINT_STATS, 40, false));
        // A small board needs only its own topics' stats.
        assert!(first_paint_ready(true, 3, 3, false));
        // An empty board needs only the root list.
        assert!(first_paint_ready(true, 0, 0, false));
        // The timeout always paints: never an indefinite wait.
        assert!(first_paint_ready(false, 0, 40, true));
    }

    #[test]
    fn updated_control_wording() {
        assert_eq!(updated_label(3), "\u{21bb} 3 updated");
        assert_eq!(
            updated_accessible_name(4),
            "4 updated: re-sort topics by latest activity"
        );
        // The visible words are part of the accessible name.
        let visible = updated_label(4);
        let words = visible.trim_start_matches('\u{21bb}').trim();
        assert!(updated_accessible_name(4).starts_with(words));
    }

    fn order(shown: &[String], sorted: &[String]) -> Vec<String> {
        stable_order(shown, sorted, &HashMap::new(), &HashSet::new())
    }

    fn both_ways(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .flat_map(|(e, o)| {
                [
                    (e.to_string(), o.to_string()),
                    (o.to_string(), e.to_string()),
                ]
            })
            .collect()
    }

    #[test]
    fn a_sealed_root_opens_in_place() {
        // The envelope "env" is shown second; its key arrives and the
        // original "orig" (older, so it sorts last) replaces it.
        let shown = ids(&["a", "env", "b"]);
        let sorted = ids(&["a", "b", "orig"]);
        let aliases = both_ways(&[("env", "orig")]);
        let next = stable_order(&shown, &sorted, &aliases, &HashSet::new());
        assert_eq!(next, ids(&["a", "orig", "b"]));
        // And back to the placeholder when the key is dropped.
        let back = stable_order(&next, &ids(&["env", "a", "b"]), &aliases, &HashSet::new());
        assert_eq!(back, shown);
        // Without the alias the original would land at the bottom.
        assert_eq!(order(&shown, &sorted), ids(&["a", "b", "orig"]));
    }

    #[test]
    fn an_envelope_whose_original_is_already_shown_is_dropped() {
        let shown = ids(&["orig", "env", "b"]);
        let sorted = ids(&["orig", "b"]);
        let next = stable_order(
            &shown,
            &sorted,
            &both_ways(&[("env", "orig")]),
            &HashSet::new(),
        );
        assert_eq!(next, ids(&["orig", "b"]));
    }

    #[test]
    fn a_row_whose_first_stats_land_moves_once_to_its_true_place() {
        // Frozen after the first stats batches; "d" was dormant-looking and
        // its stats now show a newer reply: true order a, d, b, c.
        let shown = ids(&["a", "b", "c", "d"]);
        let sorted = ids(&["a", "d", "b", "c"]);
        let first_stats: HashSet<String> = ["d".to_string()].into_iter().collect();
        let next = stable_order(&shown, &sorted, &HashMap::new(), &first_stats);
        assert_eq!(next, sorted);
        assert_eq!(out_of_order(&next, &sorted), 0, "not counted as updated");
        // A later change to the same row is a real update: it stays put.
        let sorted = ids(&["b", "a", "d", "c"]);
        let later = order(&next, &sorted);
        assert_eq!(later, next);
        assert_eq!(out_of_order(&later, &sorted), 1);
    }

    #[test]
    fn a_repositioned_row_that_sorts_last_goes_to_the_end() {
        let shown = ids(&["x", "a", "b"]);
        let sorted = ids(&["a", "b", "x"]);
        let first_stats: HashSet<String> = ["x".to_string()].into_iter().collect();
        assert_eq!(
            stable_order(&shown, &sorted, &HashMap::new(), &first_stats),
            sorted
        );
    }

    fn set(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn first_stats_land_once_per_topic() {
        let mut before = HashSet::new();
        let none = HashMap::new();
        assert_eq!(
            first_stats_landed(&set(&["a"]), &mut before, &none),
            set(&["a"])
        );
        assert_eq!(
            first_stats_landed(&set(&["a", "b"]), &mut before, &none),
            set(&["b"])
        );
        // A topic leaving the list (paged out) and coming back is not new.
        first_stats_landed(&set(&["b"]), &mut before, &none);
        assert!(first_stats_landed(&set(&["a", "b"]), &mut before, &none).is_empty());
    }

    #[test]
    fn a_sealed_root_keeps_its_placement_across_the_swap() {
        let aliases = both_ways(&[("env", "orig")]);
        let mut before = HashSet::new();
        // The envelope's stats landed: placed.
        first_stats_landed(&set(&["env", "a"]), &mut before, &aliases);
        // Opened: the original's stats land later under its own id.
        assert!(first_stats_landed(&set(&["a"]), &mut before, &aliases).is_empty());
        assert!(first_stats_landed(&set(&["orig", "a"]), &mut before, &aliases).is_empty());
        // The key is dropped: back to the envelope, still not new.
        assert!(first_stats_landed(&set(&["env", "a"]), &mut before, &aliases).is_empty());
    }

    #[test]
    fn a_swap_and_the_original_s_stats_in_one_update_do_not_move_the_row() {
        let aliases = both_ways(&[("env", "orig")]);
        let mut before = HashSet::new();
        first_stats_landed(&set(&["env", "a", "b"]), &mut before, &aliases);
        let landed = first_stats_landed(&set(&["orig", "a", "b"]), &mut before, &aliases);
        assert!(landed.is_empty());
        // So stable_order swaps it in place and leaves it there.
        let shown = ids(&["a", "env", "b"]);
        let sorted = ids(&["orig", "a", "b"]);
        assert_eq!(
            stable_order(&shown, &sorted, &aliases, &landed),
            ids(&["a", "orig", "b"])
        );
    }

    #[test]
    fn an_envelope_never_placed_is_placed_when_its_original_s_stats_land() {
        // The envelope's stats never came in before it opened: the
        // original's are its first, so the row is placed (once).
        let aliases = both_ways(&[("env", "orig")]);
        let mut before = HashSet::new();
        first_stats_landed(&set(&["a"]), &mut before, &aliases);
        assert_eq!(
            first_stats_landed(&set(&["orig", "a"]), &mut before, &aliases),
            set(&["orig"])
        );
    }

    #[test]
    fn sealed_aliases_pair_envelopes_with_their_originals() {
        let inner = "ab".repeat(32);
        let env = ev(
            "env",
            "migrator",
            "sealed",
            5,
            42,
            vec![vec!["sealed", inner.as_str(), "1"]],
        );
        let plain = ev("p", "a", "t", 5, 42, vec![]);
        assert_eq!(
            sealed_aliases(&[env, plain]),
            vec![("env".to_string(), inner)]
        );
    }

    #[test]
    fn older_paging_is_armed_by_an_answer_a_failure_or_the_hold() {
        // Complete: never (paging would add no topic).
        assert!(!older_paging_armed(true, true, false, true));
        // Not answered yet, hold running: not yet.
        assert!(!older_paging_armed(false, false, false, false));
        assert!(older_paging_armed(false, true, false, false));
        // A failed root list or an expired hold never leaves paging off.
        assert!(older_paging_armed(false, false, true, false));
        assert!(older_paging_armed(false, false, false, true));
    }

    #[test]
    fn at_top_only_when_the_first_row_is_wholly_in_view() {
        // Viewport 0..800.
        assert!(first_row_in_full_view(10.0, 90.0, 0.0, 800.0));
        assert!(first_row_in_full_view(0.0, 80.0, 0.0, 800.0));
        // Partly scrolled off the top: the reader is further down.
        assert!(!first_row_in_full_view(-20.0, 60.0, 0.0, 800.0));
        // Wholly above.
        assert!(!first_row_in_full_view(-200.0, -120.0, 0.0, 800.0));
        // A pane whose top is at 64 px.
        assert!(!first_row_in_full_view(40.0, 120.0, 64.0, 700.0));
        assert!(first_row_in_full_view(64.0, 140.0, 64.0, 700.0));
    }
}
