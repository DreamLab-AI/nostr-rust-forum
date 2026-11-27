//! A section (kind-40 channel) as a list of TOPICS.
//!
//! A *topic* is a kind-42 ROOT message in the channel (a thread starter): its
//! e-tags reference the channel id as the root and it is not itself a reply
//! to another in-channel message. A *reply* is a kind-42 (or NIP-22
//! kind-1111) event that e-tags a topic root, directly or through another
//! reply. The board lists topics newest activity first with their reply
//! count and last poster. Shared by the forum's section page and the BBS
//! board view so both list the same topics in the same order.

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
    out.sort_by_key(|b| std::cmp::Reverse(b.last_activity));
    out
}

/// Fold the relay's per-topic stats into window-derived summaries: the
/// reply count becomes the exact total when that is larger (the window may
/// hold a fraction of the topic), and a newer reply than any held sets the
/// last activity and last participant. Re-sorted, newest activity first.
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
    topics.sort_by_key(|b| std::cmp::Reverse(b.last_activity));
    topics
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
}
