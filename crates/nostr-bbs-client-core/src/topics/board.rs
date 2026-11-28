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
    // A sealed root still listed under its envelope's id: its replies name
    // the ORIGINAL id (a sealed reply's outer `reply` tag), so fold them
    // into the envelope's row (original id -> envelope id, lower-case).
    // When the original is listed too (opened, while the envelope is still
    // held), the original is the topic and the envelope is not listed.
    let mut sealed_root: HashMap<String, String> = HashMap::new();
    let mut shadowed: HashSet<String> = HashSet::new();
    for t in roots.values() {
        let env = t.id.to_lowercase();
        if let Some(r) = by_id
            .get(&env)
            .and_then(|e| nostr_bbs_core::sealed::parse_sealed(&e.tags))
        {
            if root_lower.contains(&r.inner_id) {
                shadowed.insert(env);
            } else {
                sealed_root.insert(r.inner_id, env);
            }
        }
    }
    // Only a key that is not itself a listed root is redirected.
    let resolve = |k: String| {
        if root_lower.contains(&k) {
            k
        } else {
            sealed_root.get(&k).cloned().unwrap_or(k)
        }
    };

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
        let mut root_key = resolve(parent);
        let mut hops = 0;
        while !root_lower.contains(&root_key) && hops < 64 {
            hops += 1;
            match by_id
                .get(&root_key)
                .and_then(|e| reply_parent(e, &cid_lower))
            {
                Some(p) => root_key = resolve(p),
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
        .filter(|id| !shadowed.contains(&id.to_lowercase()))
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

/// How long a board waits for its history window and root list before it
/// paints anyway, in milliseconds (see [`first_paint_ready`]).
pub const FIRST_PAINT_TIMEOUT_MS: i32 = 1_500;

/// Whether a board that has found its topics may paint them: once its
/// history window (the channel's newest messages) has its settled answer
/// and its root list has answered or failed, or once `timed_out`
/// ([`FIRST_PAINT_TIMEOUT_MS`] after the topics were found). Stats are not
/// waited for: they never move a painted row.
///
/// The settled window is the complete newest prefix of the channel, so
/// every topic active since its oldest message has its exact last
/// activity, and every other topic's last activity is older: the order at
/// paint already has its final cut between the two, and the rest (topics
/// whose newest reply lies outside the window) is frozen as painted.
pub fn first_paint_ready(window_settled: bool, roots_settled: bool, timed_out: bool) -> bool {
    timed_out || (window_settled && roots_settled)
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
/// dropped); [`FrozenBoard`] uses these pairs to keep the row in place.
pub fn sealed_aliases(events: &[NostrEvent]) -> Vec<(String, String)> {
    events
        .iter()
        .filter(|e| e.kind == 42)
        .filter_map(|e| {
            nostr_bbs_core::sealed::parse_sealed(&e.tags).map(|r| (e.id.clone(), r.inner_id))
        })
        .collect()
}

/// What a board knows at each update besides the topics themselves.
pub struct BoardInputs<'a> {
    /// The reader's pubkey, for their own new topic.
    pub me: Option<&'a str>,
    /// Whether the history window has its settled answer and holds the
    /// channel's newest messages (not detached by older paging).
    pub window_settled: bool,
    /// The oldest message of that window, when it is settled: a topic
    /// active since then has its exact last activity.
    pub window_oldest: Option<u64>,
    /// Whether the board may be re-painted once now (see
    /// [`FrozenBoard::update`]): the reader is at the top of the list and
    /// has not scrolled.
    pub may_reorder: bool,
    /// Whether a topic id is deleted (a kind-5 names it). A topic that is
    /// missing but not deleted was only evicted from the window and keeps
    /// its row.
    pub deleted: &'a dyn Fn(&str) -> bool,
}

/// A board's display order, frozen when it paints.
///
/// It paints in the true order ([`board_order`] over what is known then).
/// After that no row changes place on its own: stats, reply counts and
/// decrypted titles change a row's figures only. What can change the list:
///
/// - nothing is frozen while there is nothing to show: an empty paint
///   follows the true order until the first topic arrives;
/// - a board painted before its history window settled (the paint hold
///   expired) is re-painted once in the true order when it settles, if the
///   reader is still at the top; otherwise it keeps its order and takes the
///   settled window's newest activity as its baseline, so nothing reads as
///   new that is not;
/// - a sealed root that opens (or reverts) swaps in place, by the pairs of
///   [`FrozenBoard::note_aliases`];
/// - a topic that is deleted is dropped; one that is merely missing (evicted
///   from the window by older paging, or between two halves of a swap)
///   keeps its row;
/// - a topic not shown yet whose activity is no newer than the baseline (a
///   late root list, an older page) is appended at the bottom;
/// - the reader's own topic, not known at paint, goes on top;
/// - any other activity newer than the baseline is not shown: it is counted
///   by [`FrozenBoard::updated`] until the reader asks for it
///   ([`FrozenBoard::repaint`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FrozenBoard {
    shown: Vec<String>,
    newest: u64,
    aliases: HashMap<String, String>,
    settled: bool,
    known_at_paint: HashSet<String>,
    appended: HashSet<String>,
    window_oldest: Option<u64>,
}

impl FrozenBoard {
    /// Paint `sorted` (the true order, by [`board_order`]) as it is now;
    /// `window_settled` as in [`BoardInputs`].
    pub fn paint(sorted: &[TopicSummary], window_settled: bool) -> Self {
        let mut seen = HashSet::new();
        let shown: Vec<String> = sorted
            .iter()
            .filter(|t| seen.insert(t.id.as_str()))
            .map(|t| t.id.clone())
            .collect();
        FrozenBoard {
            known_at_paint: shown.iter().cloned().collect(),
            shown,
            newest: sorted.iter().map(|t| t.last_activity).max().unwrap_or(0),
            aliases: HashMap::new(),
            settled: window_settled,
            appended: HashSet::new(),
            window_oldest: None,
        }
    }

    /// Paint again (the reader asked for the true order), keeping the
    /// sealed pairs already seen.
    pub fn repaint(&mut self, sorted: &[TopicSummary]) {
        let aliases = std::mem::take(&mut self.aliases);
        let settled = self.settled;
        let window_oldest = self.window_oldest;
        *self = FrozenBoard::paint(sorted, settled);
        self.aliases = aliases;
        self.window_oldest = window_oldest;
    }

    /// The topic ids shown, in order.
    pub fn shown(&self) -> &[String] {
        &self.shown
    }

    /// The newest activity of the baseline: anything newer is new.
    pub fn newest_at_paint(&self) -> u64 {
        self.newest
    }

    /// Record sealed (envelope, original) pairs, both ways. An envelope
    /// leaves the list when it opens, so pairs are kept for the visit.
    pub fn note_aliases(&mut self, pairs: impl IntoIterator<Item = (String, String)>) {
        for (envelope, original) in pairs {
            self.aliases.insert(envelope.clone(), original.clone());
            self.aliases.insert(original, envelope);
        }
    }

    /// Follow the true list `sorted` (see the type's docs). Returns whether
    /// the shown list changed.
    pub fn update(&mut self, sorted: &[TopicSummary], inputs: &BoardInputs<'_>) -> bool {
        let before = self.shown.clone();
        if inputs.window_settled {
            self.window_oldest = inputs.window_oldest;
        }
        if self.shown.is_empty() {
            // Nothing painted yet: never freeze an empty board.
            self.repaint(sorted);
            self.settled = inputs.window_settled;
            return self.shown != before;
        }
        if !self.settled && inputs.window_settled {
            // The paint hold expired before the window settled: re-base once.
            self.settled = true;
            if inputs.may_reorder {
                self.repaint(sorted);
                return self.shown != before;
            }
            self.newest = self
                .newest
                .max(sorted.iter().map(|t| t.last_activity).max().unwrap_or(0));
        }
        let listed: HashMap<&str, &TopicSummary> =
            sorted.iter().map(|t| (t.id.as_str(), t)).collect();
        let shown_set: HashSet<&str> = self.shown.iter().map(String::as_str).collect();
        let mut seen: HashSet<String> = HashSet::with_capacity(sorted.len());
        let mut kept: Vec<String> = Vec::with_capacity(self.shown.len());
        for id in &self.shown {
            let id = if listed.contains_key(id.as_str()) {
                id.as_str()
            } else {
                match self.aliases.get(id).map(String::as_str) {
                    Some(a) if listed.contains_key(a) && !shown_set.contains(a) => a,
                    // Gone: dropped only when deleted; an evicted topic (or
                    // one between two halves of a swap) keeps its row.
                    _ if (inputs.deleted)(id) => continue,
                    _ => id.as_str(),
                }
            };
            if seen.insert(id.to_string()) {
                kept.push(id.to_string());
            }
        }
        let mut top = Vec::new();
        for t in sorted {
            if seen.contains(&t.id) {
                continue;
            }
            let own_new =
                inputs.me.is_some_and(|m| t.pubkey == m) && !self.known_at_paint.contains(&t.id);
            if own_new {
                seen.insert(t.id.clone());
                top.push(t.id.clone());
            } else if t.last_activity <= self.newest {
                seen.insert(t.id.clone());
                self.appended.insert(t.id.clone());
                kept.push(t.id.clone());
            }
        }
        top.extend(kept);
        self.shown = top;
        self.shown != before
    }

    /// How many topics the "↻ N updated" control offers: those with
    /// activity newer than the baseline that are not already, in order, at
    /// the top of the list, plus topics appended at the bottom after paint
    /// (a late root list, an older page) that are active within the settled
    /// window, so belong higher. The reader's own topics never count. Stats
    /// that arrive late never count: a topic's activity outside the window
    /// is older than the window.
    pub fn updated(&self, sorted: &[TopicSummary], me: Option<&str>) -> usize {
        let own: HashSet<&str> = sorted
            .iter()
            .filter(|t| me.is_some_and(|m| t.pubkey == m))
            .map(|t| t.id.as_str())
            .collect();
        let others = || sorted.iter().filter(|t| !own.contains(t.id.as_str()));
        let fresh: Vec<&str> = others()
            .filter(|t| t.last_activity > self.newest)
            .map(|t| t.id.as_str())
            .collect();
        let in_place = fresh
            .iter()
            .zip(
                self.shown
                    .iter()
                    .map(String::as_str)
                    .filter(|id| !own.contains(id)),
            )
            .take_while(|(f, s)| **f == *s)
            .count();
        let misplaced = self.window_oldest.map_or(0, |oldest| {
            others()
                .filter(|t| {
                    self.appended.contains(&t.id)
                        && t.last_activity >= oldest
                        && t.last_activity <= self.newest
                })
                .count()
        });
        fresh.len() - in_place + misplaced
    }
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

/// Text of the control that re-sorts a board shown out of order: "↻ N
/// updated", N from [`FrozenBoard::updated`].
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

    fn topic(id: &str, author: &str, created: u64, last: u64) -> TopicSummary {
        TopicSummary {
            id: id.into(),
            pubkey: author.into(),
            content: id.into(),
            created_at: created,
            reply_count: 0,
            last_activity: last,
            last_pubkey: author.into(),
        }
    }

    fn sorted(mut ts: Vec<TopicSummary>) -> Vec<TopicSummary> {
        ts.sort_by(board_order);
        ts
    }

    fn never_deleted(_: &str) -> bool {
        false
    }

    /// Inputs for a settled window whose oldest message is `oldest`.
    fn settled<'a>(me: Option<&'a str>, oldest: u64) -> BoardInputs<'a> {
        BoardInputs {
            me,
            window_settled: true,
            window_oldest: Some(oldest),
            may_reorder: true,
            deleted: &never_deleted,
        }
    }

    /// Small deterministic generator for the invariant test (no new
    /// dependency).
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    /// The invariant: once a board is painted from a settled window (or
    /// has been re-based when its window settled after a paint from the
    /// root list alone, or first frozen after an empty paint), whatever
    /// arrives (stats raising a tail topic's activity up to the window's
    /// oldest message, COUNTs including 0 then the real count, sealed swaps
    /// both ways, late roots no newer than the paint, figure-only changes),
    /// the shown order is the frozen order (sealed pairs read as one) with
    /// rows only appended at the end, and nothing counts as updated.
    #[test]
    fn nothing_after_paint_moves_a_row_or_counts_as_updated() {
        const WINDOW_OLDEST: u64 = 1_000;
        for seed in 1..=300u64 {
            let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut topics: Vec<TopicSummary> = Vec::new();
            // In-window topics: exact activity newer than the window's
            // oldest message; the root list alone only knows their start.
            let mut window_last = Vec::new();
            for i in 0..8 {
                let created = rng.below(WINDOW_OLDEST);
                window_last.push(WINDOW_OLDEST + 1 + rng.below(500));
                topics.push(topic(&format!("w{i}"), "a", created, created));
            }
            for i in 0..20 {
                let created = rng.below(WINDOW_OLDEST);
                topics.push(topic(&format!("t{i}"), "b", created, created));
            }
            topics.push(topic("env", "m", 400, 400));
            let apply_window = |ts: &mut Vec<TopicSummary>| {
                for (i, last) in window_last.iter().enumerate() {
                    if let Some(t) = ts.iter_mut().find(|t| t.id == format!("w{i}")) {
                        t.last_activity = *last;
                    }
                }
            };
            // Three ways to paint: from the settled window, from the root
            // list alone (the hold expired), or with nothing at all.
            let mode = seed % 3;
            let mut board = match mode {
                0 => {
                    apply_window(&mut topics);
                    FrozenBoard::paint(&sorted(topics.clone()), true)
                }
                1 => FrozenBoard::paint(&sorted(topics.clone()), false),
                _ => FrozenBoard::paint(&[], false),
            };
            board.note_aliases([("env".to_string(), "orig".to_string())]);
            if mode != 0 {
                // The window settles: re-based (the reader is at the top),
                // or first frozen after the empty paint.
                apply_window(&mut topics);
                board.update(
                    &sorted(topics.clone()),
                    &settled(Some("reader"), WINDOW_OLDEST),
                );
            }
            let frozen: Vec<String> = board.shown().to_vec();
            assert_eq!(frozen.len(), topics.len(), "seed {seed}: nothing hidden");
            assert_eq!(
                board.updated(&sorted(topics.clone()), Some("reader")),
                0,
                "seed {seed}: no phantom updates after the window settles"
            );
            let canon = |id: &str| {
                if id == "orig" {
                    "env".to_string()
                } else {
                    id.to_string()
                }
            };
            let mut late = 0;
            for _ in 0..60 {
                let n = topics.len() as u64;
                match rng.below(5) {
                    0 => {
                        let t = &mut topics[rng.below(n) as usize];
                        if t.last_activity <= WINDOW_OLDEST {
                            t.last_activity = t.last_activity.max(rng.below(WINDOW_OLDEST));
                            t.last_pubkey = "z".into();
                        }
                    }
                    1 => {
                        let t = &mut topics[rng.below(n) as usize];
                        t.reply_count = if rng.below(2) == 0 {
                            0
                        } else {
                            1 + rng.below(30) as u32
                        };
                    }
                    2 => {
                        for t in topics.iter_mut() {
                            if t.id == "env" {
                                t.id = "orig".into();
                            } else if t.id == "orig" {
                                t.id = "env".into();
                            }
                        }
                    }
                    3 => {
                        let created = rng.below(WINDOW_OLDEST);
                        topics.push(topic(&format!("late{late}"), "c", created, created));
                        late += 1;
                    }
                    _ => {
                        let t = &mut topics[rng.below(n) as usize];
                        t.content.push('!');
                    }
                }
                let now = sorted(topics.clone());
                board.update(&now, &settled(Some("reader"), WINDOW_OLDEST));
                let shown: Vec<String> = board.shown().iter().map(|id| canon(id)).collect();
                assert_eq!(&shown[..frozen.len()], &frozen[..], "seed {seed}");
                assert!(
                    shown[frozen.len()..]
                        .iter()
                        .all(|id| id.starts_with("late")),
                    "seed {seed}: only late roots are appended"
                );
                assert_eq!(board.updated(&now, Some("reader")), 0, "seed {seed}");
                let unique: HashSet<&String> = board.shown().iter().collect();
                assert_eq!(unique.len(), board.shown().len(), "seed {seed}");
            }
        }
    }

    #[test]
    fn a_paint_before_the_window_settled_is_re_based_once() {
        // Painted from the root list alone (creation order) on the hold.
        let mut ts = vec![
            topic("old-busy", "x", 5, 5),
            topic("new-quiet", "x", 50, 50),
        ];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), false);
        assert_eq!(board.shown(), &ids(&["new-quiet", "old-busy"])[..]);
        // The window settles: old-busy had a reply at 900.
        ts[0].last_activity = 900;
        ts.push(topic("window-only", "x", 3, 800));
        let now = sorted(ts.clone());
        assert!(board.update(&now, &settled(None, 700)));
        assert_eq!(
            board.shown(),
            &ids(&["old-busy", "window-only", "new-quiet"])[..]
        );
        assert_eq!(board.updated(&now, None), 0);
        // Only once: later activity is counted, not re-sorted.
        ts[2].last_activity = 950;
        let now = sorted(ts.clone());
        assert!(!board.update(&now, &settled(None, 700)));
        assert_eq!(board.updated(&now, None), 1);
    }

    #[test]
    fn a_scrolled_reader_keeps_the_order_and_sees_no_phantom_updates() {
        let mut ts = vec![
            topic("old-busy", "x", 5, 5),
            topic("new-quiet", "x", 50, 50),
        ];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), false);
        ts[0].last_activity = 900;
        ts.push(topic("window-only", "x", 3, 800));
        let now = sorted(ts.clone());
        let scrolled = BoardInputs {
            may_reorder: false,
            ..settled(None, 700)
        };
        board.update(&now, &scrolled);
        assert_eq!(
            board.shown(),
            &ids(&["new-quiet", "old-busy", "window-only"])[..]
        );
        // Nothing was posted: the baseline is the settled window. The
        // window-only topic belongs higher and is offered by the control.
        assert_eq!(board.updated(&now, None), 1);
    }

    #[test]
    fn an_empty_paint_is_never_frozen() {
        let mut board = FrozenBoard::paint(&[], false);
        let ts = sorted(vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)]);
        assert!(board.update(&ts, &settled(None, 30)));
        assert_eq!(board.shown(), &ids(&["a", "b"])[..]);
        assert_eq!(board.updated(&ts, None), 0);
    }

    #[test]
    fn an_evicted_topic_keeps_its_row_and_a_deleted_one_is_dropped() {
        let ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 30),
        ];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        // b paged out of the window: still shown, in place.
        let without_b = sorted(vec![ts[0].clone(), ts[2].clone()]);
        assert!(!board.update(&without_b, &settled(None, 20)));
        assert_eq!(board.shown(), &ids(&["a", "b", "c"])[..]);
        // Paged back in: same place, not appended.
        assert!(!board.update(&sorted(ts.clone()), &settled(None, 20)));
        assert_eq!(board.shown(), &ids(&["a", "b", "c"])[..]);
        // Deleted (a kind-5 names it): dropped.
        let deleted = |id: &str| id == "b";
        let inputs = BoardInputs {
            deleted: &deleted,
            ..settled(None, 20)
        };
        assert!(board.update(&without_b, &inputs));
        assert_eq!(board.shown(), &ids(&["a", "c"])[..]);
    }

    #[test]
    fn a_count_of_zero_then_the_real_count_changes_neither_order_nor_count() {
        let mut ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 1),
        ];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        let painted = board.shown().to_vec();
        for count in [0, 25, 0, 3] {
            ts[2].reply_count = count;
            let now = sorted(ts.clone());
            assert!(!board.update(&now, &settled(None, 20)));
            assert_eq!(board.shown(), &painted[..]);
            assert_eq!(board.updated(&now, None), 0);
        }
    }

    #[test]
    fn one_reply_newer_than_the_paint_counts_one_and_moves_nothing() {
        let mut ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 30),
        ];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        ts[2].last_activity = 60;
        let now = sorted(ts.clone());
        board.update(&now, &settled(None, 20));
        assert_eq!(board.shown(), &ids(&["a", "b", "c"])[..]);
        assert_eq!(board.updated(&now, None), 1);
        // A new reply in the topic already at the top is already in place.
        let mut ts = vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)];
        let board = FrozenBoard::paint(&sorted(ts.clone()), true);
        ts[0].last_activity = 70;
        assert_eq!(board.updated(&sorted(ts), None), 0);
    }

    #[test]
    fn someone_else_s_new_topic_waits_for_the_control() {
        let mut ts = vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        ts.push(topic("n", "other", 80, 80));
        let now = sorted(ts.clone());
        assert!(!board.update(&now, &settled(Some("me"), 20)));
        assert_eq!(board.shown(), &ids(&["a", "b"])[..]);
        assert_eq!(board.updated(&now, Some("me")), 1);
    }

    #[test]
    fn the_reader_s_own_new_topic_goes_on_top_whatever_its_clock() {
        let mut ts = vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        // Their clock is behind: created_at older than the newest at paint.
        ts.push(topic("mine", "me", 30, 30));
        let now = sorted(ts.clone());
        assert!(board.update(&now, &settled(Some("me"), 20)));
        assert_eq!(board.shown(), &ids(&["mine", "a", "b"])[..]);
        assert_eq!(board.updated(&now, Some("me")), 0, "own topics never count");
        // And a newer one of theirs does not count either.
        ts.push(topic("mine2", "me", 90, 90));
        let now = sorted(ts.clone());
        board.update(&now, &settled(Some("me"), 20));
        assert_eq!(board.shown()[0], "mine2");
        assert_eq!(board.updated(&now, Some("me")), 0);
    }

    #[test]
    fn the_control_paints_the_true_order() {
        let mut ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 30),
        ];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        board.note_aliases([("e".to_string(), "o".to_string())]);
        ts[2].last_activity = 60;
        ts.push(topic("n", "other", 80, 80));
        let now = sorted(ts.clone());
        board.update(&now, &settled(None, 20));
        board.repaint(&now);
        assert_eq!(board.shown(), &ids(&["n", "c", "a", "b"])[..]);
        assert_eq!(board.updated(&now, None), 0);
        assert_eq!(board.newest_at_paint(), 80);
        assert_eq!(
            board.aliases.get("e").map(String::as_str),
            Some("o"),
            "pairs kept"
        );
    }

    #[test]
    fn a_late_root_active_in_the_window_is_offered_by_the_control() {
        let mut ts = vec![topic("a", "x", 10, 900), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        // A late root with a reply at 800, inside the window (oldest 700):
        // appended at the bottom, but it belongs higher.
        ts.push(topic("late", "x", 3, 800));
        let now = sorted(ts.clone());
        board.update(&now, &settled(None, 700));
        assert_eq!(board.shown(), &ids(&["a", "b", "late"])[..]);
        assert_eq!(board.updated(&now, None), 1);
        // A late root known only by its start is where it belongs.
        let mut ts = vec![topic("a", "x", 10, 900), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::paint(&sorted(ts.clone()), true);
        ts.push(topic("late", "x", 3, 3));
        let now = sorted(ts.clone());
        board.update(&now, &settled(None, 700));
        assert_eq!(board.updated(&now, None), 0);
    }

    #[test]
    fn an_envelope_and_its_opened_original_are_one_row() {
        // Classification: E (sealed, naming O) and O both listed. One row,
        // O; replies to O are credited to O.
        let cid = "chan";
        let inner = "ab".repeat(32);
        let envelope = ev(
            "env",
            "migrator",
            "sealed",
            5,
            42,
            vec![
                vec!["e", cid, "", "root"],
                vec!["sealed", inner.as_str(), "1"],
            ],
        );
        let original = ev(
            &inner,
            "ann",
            "Topic",
            5,
            42,
            vec![vec!["e", cid, "", "root"]],
        );
        let reply = ev(
            "r",
            "bob",
            "reply",
            50,
            42,
            vec![
                vec!["e", cid, "", "root"],
                vec!["e", inner.as_str(), "", "reply"],
            ],
        );
        let topics = classify_topics(cid, &[envelope.clone(), original.clone(), reply.clone()]);
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].id, inner);
        assert_eq!((topics[0].reply_count, topics[0].last_activity), (1, 50));
        // The board showed E: it swaps to O in place, with no duplicate,
        // and keeps the row when E's copy then goes.
        let before = classify_topics(cid, &[envelope, reply.clone()]);
        let mut rest = vec![topic("a", "x", 10, 100), topic("b", "x", 1, 1)];
        rest.extend(before);
        let mut board = FrozenBoard::paint(&sorted(rest.clone()), true);
        board.note_aliases([("env".to_string(), inner.clone())]);
        let shown_before = board.shown().to_vec();
        let mut after: Vec<TopicSummary> = rest.into_iter().filter(|t| t.id != "env").collect();
        after.extend(topics);
        board.update(&sorted(after.clone()), &settled(None, 20));
        let swapped: Vec<String> = shown_before
            .iter()
            .map(|id| {
                if id == "env" {
                    inner.clone()
                } else {
                    id.clone()
                }
            })
            .collect();
        assert_eq!(board.shown(), &swapped[..]);
        // A tick with neither copy listed keeps the row in place.
        let neither: Vec<TopicSummary> = after.iter().filter(|t| t.id != inner).cloned().collect();
        board.update(&sorted(neither), &settled(None, 20));
        assert_eq!(board.shown(), &swapped[..]);
        board.update(&sorted(after), &settled(None, 20));
        assert_eq!(board.shown(), &swapped[..]);
    }

    #[test]
    fn the_paint_order_puts_every_window_topic_above_every_tail_topic() {
        // A window whose oldest message is at 100: the topics with replies
        // in it (exact activity) sort above every root known only by its
        // creation, which is what the final order does too, since a tail
        // topic's newest reply is older than the window.
        let cid = "chan";
        let root = |id: &str, ts| ev(id, "op", id, ts, 42, vec![vec!["e", cid, "", "root"]]);
        let reply = |id: &str, to: &str, ts| {
            ev(
                id,
                "p",
                id,
                ts,
                42,
                vec![vec!["e", cid, "", "root"], vec!["e", to, "", "reply"]],
            )
        };
        let window = vec![
            reply("r1", "old-busy", 150),
            reply("r2", "older", 120),
            reply("r3", "x", 100),
        ];
        let roots = vec![
            root("old-busy", 5),
            root("older", 3),
            root("recent-root", 90),
            root("x", 1),
        ];
        let order: Vec<String> = classify_topics(cid, &board_events(&window, &roots))
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(order, ids(&["old-busy", "older", "x", "recent-root"]));
    }

    #[test]
    fn replies_to_a_sealed_root_fold_into_its_envelope_row() {
        let cid = "chan";
        let inner = "ab".repeat(32);
        let envelope = ev(
            "env",
            "migrator",
            "sealed",
            5,
            42,
            vec![
                vec!["e", cid, "", "root"],
                vec!["sealed", inner.as_str(), "1"],
            ],
        );
        let reply = ev(
            "r",
            "ann",
            "sealed reply",
            50,
            42,
            vec![
                vec!["e", cid, "", "root"],
                vec!["e", inner.as_str(), "", "reply"],
            ],
        );
        let topics = classify_topics(cid, &[envelope, reply]);
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].id, "env");
        assert_eq!((topics[0].reply_count, topics[0].last_activity), (1, 50));
    }

    #[test]
    fn first_paint_waits_for_the_window_and_the_root_list_not_stats() {
        assert!(!first_paint_ready(false, true, false));
        assert!(!first_paint_ready(true, false, false));
        assert!(first_paint_ready(true, true, false));
        assert!(
            first_paint_ready(false, false, true),
            "the timeout always paints"
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
