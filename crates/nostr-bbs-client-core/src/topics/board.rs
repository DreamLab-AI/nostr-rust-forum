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
    // Envelope id -> its listed original (the envelope is not listed).
    let mut shadowed: HashMap<String, String> = HashMap::new();
    for t in roots.values() {
        let env = t.id.to_lowercase();
        if let Some(r) = by_id
            .get(&env)
            .and_then(|e| nostr_bbs_core::sealed::parse_sealed(&e.tags))
        {
            if root_lower.contains(&r.inner_id) {
                shadowed.insert(env, r.inner_id);
            } else {
                sealed_root.insert(r.inner_id, env);
            }
        }
    }
    // A reply naming a shadowed envelope counts for its original; one naming
    // an original listed only as its envelope counts for the envelope; any
    // other listed root is itself.
    let resolve = |k: String| {
        if let Some(inner) = shadowed.get(&k) {
            inner.clone()
        } else if root_lower.contains(&k) {
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
        .filter(|id| !shadowed.contains_key(&id.to_lowercase()))
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
/// history window (the channel's newest messages) has its settled answer,
/// its root list has answered or failed and its section stats (ADR-2038)
/// have answered or failed, or once `timed_out` ([`FIRST_PAINT_TIMEOUT_MS`]
/// after the topics were found). The section stats never hold the paint
/// past that same timeout; the per-topic stats are not waited for at all.
///
/// The settled window is the complete newest prefix of the channel, so
/// every topic active since its oldest message has its exact last
/// activity; the section stats give every other marked topic its exact
/// last activity too, so a list painted with them is in true order from
/// its first frame.
pub fn first_paint_ready(
    window_settled: bool,
    roots_settled: bool,
    section_stats_settled: bool,
    timed_out: bool,
) -> bool {
    timed_out || (window_settled && roots_settled && section_stats_settled)
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

/// How long after a list first shows rows it freezes whatever has or has
/// not arrived, in milliseconds (see [`FrozenBoard`]).
pub const FREEZE_CAP_MS: i32 = 20_000;

/// How recent the reader's own topic must be (seconds before the freeze,
/// on the same device clock) to go on top rather than at the bottom.
pub const OWN_TOPIC_GRACE_SECS: u64 = 120;

/// What a board knows at each update besides the topics themselves.
pub struct BoardInputs<'a> {
    /// The reader's pubkey, for their own just-posted topic.
    pub me: Option<&'a str>,
    /// Whether the board may freeze now: its history window has settled
    /// (and holds the channel's newest messages) and its root list has
    /// answered or failed, or [`FREEZE_CAP_MS`] has passed since the list
    /// first showed rows.
    pub ready_to_freeze: bool,
    /// The newest activity known now: the newest last activity of every
    /// topic (stats included) and the newest message in the window (edits
    /// included, which can come back as a topic's newest reply).
    pub newest_known: u64,
    /// The wall clock, in seconds.
    pub now_secs: u64,
    /// Whether a topic's deletion is honoured (the store's admission
    /// decision). A topic that is missing but not deleted keeps its row.
    pub deleted: &'a dyn Fn(&str) -> bool,
    /// Whether the newest activity known now can be trusted as the
    /// baseline: the history window has settled, or the section stats
    /// (ADR-2038) have answered. A freeze forced by [`FREEZE_CAP_MS`]
    /// before either takes a provisional baseline and re-takes it once,
    /// when the first of them lands.
    pub baseline_settled: bool,
    /// Whether a topic's true last activity is known: the section stats
    /// answered for it (ADR-2038). Lets [`FrozenBoard::updated`] count a
    /// row that arrived after the freeze below a row of lower activity.
    pub activity_known: &'a dyn Fn(&str) -> bool,
}

/// A board's display order: provisional while it loads, then frozen once
/// for the visit.
///
/// **Provisional** until the history window has settled and the root list
/// has answered or failed (or [`FREEZE_CAP_MS`] after rows first show). Its
/// order is the true order from structure only, the list the caller passes
/// to [`FrozenBoard::update`]: topics with activity in the window by that
/// activity, the rest below by root creation, ties by id. Stats never enter
/// it, so it moves only when the window or the root list lands. Nothing is
/// counted as updated, and an empty list never freezes.
///
/// **Frozen** at the first update that may freeze: the order is the
/// provisional order then, the baseline the newest activity known, the
/// paint time the wall clock. From then on no row moves:
///
/// - stats, counts and decrypts change a row's figures only;
/// - a sealed root swaps in place, by the pairs of
///   [`FrozenBoard::note_aliases`];
/// - a row leaves only when its deletion is honoured; one merely missing
///   (evicted from the window, or between two halves of a swap) stays;
/// - a topic not shown goes on top only if it is the reader's own and was
///   created at most [`OWN_TOPIC_GRACE_SECS`] before the paint (or after);
///   otherwise it is appended at the bottom, always shown.
///
/// [`FrozenBoard::updated`] counts real activity newer than the baseline;
/// [`FrozenBoard::repaint`] (the reader pressing the control) re-sorts by
/// the full true order and stays frozen.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FrozenBoard {
    shown: Vec<String>,
    frozen: bool,
    baseline: u64,
    painted_at: u64,
    aliases: HashMap<String, String>,
    /// Rows appended after the freeze (not the reader's own on top).
    late: HashSet<String>,
    /// Rows whose true last activity was known at the last update.
    known: HashSet<String>,
    /// The freeze took its baseline before the window or the section stats
    /// had answered; it is re-taken once when the first of them lands.
    baseline_provisional: bool,
}

impl FrozenBoard {
    /// A provisional board with nothing shown.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the board has frozen.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// The topic ids shown, in order.
    pub fn shown(&self) -> &[String] {
        &self.shown
    }

    /// The baseline: activity newer than this is new.
    pub fn baseline(&self) -> u64 {
        self.baseline
    }

    /// Record sealed (envelope, original) pairs, both ways. An envelope
    /// leaves the list when it opens, so pairs are kept for the visit.
    pub fn note_aliases(&mut self, pairs: impl IntoIterator<Item = (String, String)>) {
        for (envelope, original) in pairs {
            self.aliases.insert(envelope.clone(), original.clone());
            self.aliases.insert(original, envelope);
        }
    }

    /// Follow `structure`, the true order from structure only (see the
    /// type's docs). Returns whether the shown list changed.
    pub fn update(&mut self, structure: &[TopicSummary], inputs: &BoardInputs<'_>) -> bool {
        let changed = self.follow(structure, inputs);
        self.known = self
            .shown
            .iter()
            .filter(|id| (inputs.activity_known)(id))
            .cloned()
            .collect();
        changed
    }

    fn follow(&mut self, structure: &[TopicSummary], inputs: &BoardInputs<'_>) -> bool {
        let before = std::mem::take(&mut self.shown);
        let structure_newest = structure.iter().map(|t| t.last_activity).max().unwrap_or(0);
        if !self.frozen {
            let mut seen = HashSet::new();
            self.shown = structure
                .iter()
                .filter(|t| seen.insert(t.id.as_str()))
                .map(|t| t.id.clone())
                .collect();
            if inputs.ready_to_freeze && !self.shown.is_empty() {
                self.frozen = true;
                self.baseline = inputs.newest_known.max(structure_newest);
                self.baseline_provisional = !inputs.baseline_settled;
                self.painted_at = inputs.now_secs;
            }
            return self.shown != before;
        }
        // A cap freeze before the window or the section stats: the first of
        // them to land sets the baseline, once (the order does not move).
        if self.baseline_provisional && inputs.baseline_settled {
            self.baseline = self
                .baseline
                .max(inputs.newest_known)
                .max(structure_newest);
            self.baseline_provisional = false;
        }
        let listed: HashSet<&str> = structure.iter().map(|t| t.id.as_str()).collect();
        let shown_set: HashSet<&str> = before.iter().map(String::as_str).collect();
        let mut seen: HashSet<String> = HashSet::with_capacity(structure.len());
        let mut kept: Vec<String> = Vec::with_capacity(before.len());
        for id in &before {
            let alias = self.aliases.get(id);
            let id = if listed.contains(id.as_str()) {
                id.clone()
            } else if let Some(a) =
                alias.filter(|a| listed.contains(a.as_str()) && !shown_set.contains(a.as_str()))
            {
                // A sealed row swaps in place; a late row stays late.
                if self.late.remove(id) {
                    self.late.insert(a.clone());
                }
                a.clone()
            } else if (inputs.deleted)(id) || alias.is_some_and(|a| (inputs.deleted)(a)) {
                continue;
            } else {
                id.clone()
            };
            if seen.insert(id.clone()) {
                kept.push(id);
            }
        }
        let mut top = Vec::new();
        for t in structure {
            if seen.insert(t.id.clone()) {
                if self.just_posted_by(t, inputs.me) {
                    top.push(t.id.clone());
                } else {
                    self.late.insert(t.id.clone());
                    kept.push(t.id.clone());
                }
            }
        }
        top.extend(kept);
        self.shown = top;
        let shown: HashSet<&str> = self.shown.iter().map(String::as_str).collect();
        self.late.retain(|id| shown.contains(id.as_str()));
        self.shown != before
    }

    /// The reader's own topic, created at most [`OWN_TOPIC_GRACE_SECS`]
    /// before the paint.
    fn just_posted_by(&self, t: &TopicSummary, me: Option<&str>) -> bool {
        me.is_some_and(|m| t.pubkey == m)
            && t.created_at.saturating_add(OWN_TOPIC_GRACE_SECS) >= self.painted_at
    }

    /// "↻ N updated": the topics of `sorted` (the full true order, stats
    /// included) with activity newer than the baseline that are not already
    /// in place as the top of the list, leaving out only the reader's own
    /// just-posted topic. Any author's activity counts, other people's
    /// replies to the reader's topics included. Also counted: a row
    /// appended after the freeze that sits below a row of strictly lower
    /// activity, when the true activity of both is known (section stats,
    /// ADR-2038); a topic from an older page, older than every row, never
    /// counts. Zero while provisional, and while the baseline of a cap
    /// freeze is still provisional.
    pub fn updated(&self, sorted: &[TopicSummary], me: Option<&str>) -> usize {
        if !self.frozen || self.baseline_provisional {
            return 0;
        }
        // The reader's just-posted topic is left out only while its newest
        // activity is still the reader's own root: a reply to it counts.
        let mine: HashSet<&str> = sorted
            .iter()
            .filter(|t| self.just_posted_by(t, me) && t.last_activity <= t.created_at)
            .map(|t| t.id.as_str())
            .collect();
        let listed: HashSet<&str> = sorted.iter().map(|t| t.id.as_str()).collect();
        let fresh: Vec<&str> = sorted
            .iter()
            .filter(|t| t.last_activity > self.baseline && !mine.contains(t.id.as_str()))
            .map(|t| t.id.as_str())
            .collect();
        // The top of the list as compared: rows kept for topics no longer
        // listed (evicted) are not part of it.
        let in_place = fresh
            .iter()
            .zip(
                self.shown
                    .iter()
                    .map(String::as_str)
                    .filter(|id| listed.contains(id) && !mine.contains(id)),
            )
            .take_while(|(f, s)| **f == *s)
            .count();
        let mut counted: HashSet<&str> = fresh[in_place..].iter().copied().collect();
        // Late rows out of order: below a known row of lower activity.
        let activity: HashMap<&str, u64> = sorted
            .iter()
            .map(|t| (t.id.as_str(), t.last_activity))
            .collect();
        let mut lowest_above: Option<u64> = None;
        for id in self.shown.iter().map(String::as_str) {
            if mine.contains(id) || !self.known.contains(id) {
                continue;
            }
            let Some(&a) = activity.get(id) else {
                continue;
            };
            if self.late.contains(id) && lowest_above.is_some_and(|low| low < a) {
                counted.insert(id);
            }
            lowest_above = Some(lowest_above.map_or(a, |low| low.min(a)));
        }
        counted.len()
    }

    /// The reader pressed the control: show `sorted` (the full true order,
    /// stats included), then the rows kept for topics that are missing but
    /// not deleted (evicted from the window) in their order; take
    /// `newest_known` as the new baseline (never lower than the old one),
    /// stay frozen. Sealed pairs are kept.
    pub fn repaint(
        &mut self,
        sorted: &[TopicSummary],
        newest_known: u64,
        now_secs: u64,
        deleted: &dyn Fn(&str) -> bool,
    ) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut shown: Vec<String> = sorted
            .iter()
            .filter(|t| seen.insert(t.id.clone()))
            .map(|t| t.id.clone())
            .collect();
        for id in std::mem::take(&mut self.shown) {
            let alias_listed = self.aliases.get(&id).is_some_and(|a| seen.contains(a));
            let gone = deleted(&id) || self.aliases.get(&id).is_some_and(|a| deleted(a));
            if !alias_listed && !gone && seen.insert(id.clone()) {
                shown.push(id);
            }
        }
        self.shown = shown;
        self.frozen = true;
        self.late.clear();
        self.baseline_provisional = false;
        // Never lower: a kept (evicted) row's activity is not in `sorted`,
        // and must not read as new when it is paged back in.
        self.baseline = self
            .baseline
            .max(newest_known)
            .max(sorted.iter().map(|t| t.last_activity).max().unwrap_or(0));
        self.painted_at = now_secs;
    }
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

    fn newest(ts: &[TopicSummary]) -> u64 {
        ts.iter().map(|t| t.last_activity).max().unwrap_or(0)
    }

    /// Inputs for an update at wall clock `now`.
    fn inputs<'a>(
        me: Option<&'a str>,
        ready: bool,
        newest_known: u64,
        now: u64,
        deleted: &'a dyn Fn(&str) -> bool,
    ) -> BoardInputs<'a> {
        BoardInputs {
            me,
            ready_to_freeze: ready,
            newest_known,
            now_secs: now,
            deleted,
            baseline_settled: true,
            activity_known: &never_known,
        }
    }

    fn never_known(_: &str) -> bool {
        false
    }

    fn always_known(_: &str) -> bool {
        true
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

    /// One topic of the seeded model: what the root list knows (`created`),
    /// what the window knows (`window_last`, for topics active in it) and
    /// what stats would add (`stats_last`, never past the window's oldest
    /// message for a topic outside it).
    #[derive(Clone)]
    struct Model {
        id: String,
        author: &'static str,
        created: u64,
        window_last: Option<u64>,
        stats_last: Option<u64>,
        replies: u32,
        in_window_list: bool,
        evicted: bool,
    }

    /// The invariant, over 300 seeds:
    /// - provisional: the order changes only when the window or the root
    ///   list lands, never on stats, and nothing counts as updated;
    /// - frozen: under any mix of stats, COUNTs (0 then real), decrypts,
    ///   sealed swaps, evictions and their return, late roots, older
    ///   pages and the reader's old topics arriving late, no frozen row
    ///   changes place, rows are only appended at the end, and a quiet
    ///   section counts nothing as updated.
    #[test]
    fn provisional_moves_only_on_window_or_roots_and_frozen_never_moves() {
        const W: u64 = 1_000; // the window's oldest message
        const ME: &str = "me";
        for seed in 1..=300u64 {
            let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut model: Vec<Model> = Vec::new();
            for i in 0..8 {
                model.push(Model {
                    id: format!("w{i}"),
                    author: "a",
                    created: rng.below(W),
                    window_last: Some(W + 1 + rng.below(500)),
                    stats_last: None,
                    replies: 0,
                    in_window_list: true,
                    evicted: false,
                });
            }
            for i in 0..20 {
                let created = rng.below(W);
                model.push(Model {
                    id: format!("t{i}"),
                    author: if i < 3 { ME } else { "b" },
                    created,
                    window_last: None,
                    stats_last: Some(created + rng.below(W - created)),
                    replies: 0,
                    in_window_list: false,
                    evicted: false,
                });
            }
            model.push(Model {
                id: "env".into(),
                author: "m",
                created: 400,
                window_last: None,
                stats_last: None,
                replies: 0,
                in_window_list: false,
                evicted: false,
            });
            let (mut window, mut roots, mut stats_in) = (false, false, false);
            // Structure only (no stats), and the full list (with the stats
            // that are in), as a page derives them.
            let structure = |m: &[Model], window: bool, roots: bool| -> Vec<TopicSummary> {
                sorted(
                    m.iter()
                        .filter(|t| !t.evicted)
                        .filter(|t| roots || (window && t.in_window_list))
                        .map(|t| {
                            let last = window
                                .then_some(t.window_last)
                                .flatten()
                                .unwrap_or(t.created);
                            let mut s = topic(&t.id, t.author, t.created, last);
                            s.reply_count = t.replies;
                            s
                        })
                        .collect(),
                )
            };
            let full = |m: &[Model], window: bool, roots: bool, stats_in: bool| {
                sorted(
                    structure(m, window, roots)
                        .into_iter()
                        .map(|mut s| {
                            if stats_in {
                                if let Some(st) =
                                    m.iter().find(|t| t.id == s.id).and_then(|t| t.stats_last)
                                {
                                    s.last_activity = s.last_activity.max(st);
                                }
                            }
                            s
                        })
                        .collect(),
                )
            };
            let cap_freeze = seed % 5 == 0;
            let mut board = FrozenBoard::new();
            board.note_aliases([("env".to_string(), "orig".to_string())]);
            let window_first = rng.below(2) == 0;
            let mut now = 2_000u64;
            // Provisional phase: arrivals interleaved with stats answers.
            for step in 0..6 {
                let before = board.shown().to_vec();
                let landing = match step {
                    1 if window_first => {
                        window = true;
                        true
                    }
                    1 => {
                        roots = true;
                        true
                    }
                    3 if window_first => {
                        roots = true;
                        true
                    }
                    3 => {
                        window = true;
                        true
                    }
                    _ => {
                        stats_in = true;
                        false
                    }
                };
                let ready = (window && roots && step == 5) || (cap_freeze && step == 2);
                let st = structure(&model, window, roots);
                let fl = full(&model, window, roots, stats_in);
                let changed = board.update(
                    &st,
                    &inputs(Some(ME), ready, newest(&fl), now, &never_deleted),
                );
                if !landing && !board.is_frozen() {
                    assert!(
                        !changed,
                        "seed {seed} step {step}: stats moved a provisional row"
                    );
                    assert_eq!(board.shown(), &before[..]);
                }
                if !board.is_frozen() {
                    assert_eq!(
                        board.updated(&fl, Some(ME)),
                        0,
                        "seed {seed}: hidden while provisional"
                    );
                }
            }
            assert!(board.is_frozen(), "seed {seed}");
            let mut frozen: Vec<String> = board.shown().to_vec();
            let canon = |id: &str| {
                if id == "orig" {
                    "env".to_string()
                } else {
                    id.to_string()
                }
            };
            let mut late = 0;
            for _ in 0..80 {
                now += 1;
                let n = model.len() as u64;
                match rng.below(7) {
                    0 => stats_in = true,
                    1 => {
                        let t = &mut model[rng.below(n) as usize];
                        t.replies = if rng.below(2) == 0 {
                            0
                        } else {
                            1 + rng.below(30) as u32
                        };
                    }
                    2 => {
                        for t in model.iter_mut() {
                            if t.id == "env" {
                                t.id = "orig".into();
                            } else if t.id == "orig" {
                                t.id = "env".into();
                            }
                        }
                    }
                    3 => {
                        // Eviction by older paging, or its return.
                        let t = &mut model[rng.below(n) as usize];
                        t.evicted = !t.evicted;
                    }
                    4 => {
                        // A late root or an older page: old, quiet.
                        let created = rng.below(W);
                        model.push(Model {
                            id: format!("late{late}"),
                            author: if rng.below(3) == 0 { ME } else { "c" },
                            created,
                            window_last: None,
                            stats_last: Some(created),
                            replies: 0,
                            in_window_list: false,
                            evicted: false,
                        });
                        late += 1;
                    }
                    5 => {
                        // A decrypt: figures only.
                        let t = &mut model[rng.below(n) as usize];
                        t.replies = t.replies.saturating_add(0);
                    }
                    _ => {}
                }
                // Window and roots stay landed (a cap freeze lands them now).
                window = true;
                roots = true;
                let st = structure(&model, window, roots);
                let fl = full(&model, window, roots, stats_in);
                board.update(
                    &st,
                    &inputs(Some(ME), true, newest(&fl), now, &never_deleted),
                );
                let shown: Vec<String> = board.shown().iter().map(|id| canon(id)).collect();
                assert_eq!(
                    &shown[..frozen.len()],
                    &frozen[..],
                    "seed {seed}: a frozen row moved"
                );
                assert!(
                    shown[frozen.len()..]
                        .iter()
                        .all(|id| id.starts_with("late")),
                    "seed {seed}: only late roots are appended"
                );
                let unique: HashSet<&String> = board.shown().iter().collect();
                assert_eq!(unique.len(), board.shown().len(), "seed {seed}");
                if !cap_freeze {
                    assert_eq!(
                        board.updated(&fl, Some(ME)),
                        0,
                        "seed {seed}: quiet section"
                    );
                }
                // Now and then the reader presses the control: the full
                // true order, and no row lost (evicted topics included).
                if rng.below(10) == 0 {
                    board.repaint(&fl, newest(&fl), now, &never_deleted);
                    let after: Vec<String> = board.shown().iter().map(|id| canon(id)).collect();
                    assert!(
                        shown.iter().all(|id| after.contains(id)),
                        "seed {seed}: a repaint dropped a kept row"
                    );
                    assert_eq!(board.updated(&fl, Some(ME)), 0, "seed {seed}");
                    frozen = after;
                }
            }
        }
    }

    #[test]
    fn a_repaint_keeps_rows_of_evicted_topics() {
        let ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 30),
        ];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(None, true, 50, 10, &never_deleted),
        );
        // b is evicted by older paging (not deleted), then c gets a reply.
        let mut now = sorted(vec![ts[0].clone(), ts[2].clone()]);
        now[1].last_activity = 60;
        let now = sorted(now);
        board.update(&now, &inputs(None, true, 60, 11, &never_deleted));
        board.repaint(&now, 60, 12, &never_deleted);
        assert_eq!(board.shown(), &ids(&["c", "a", "b"])[..]);
        // A deleted one does not come back.
        let deleted = |id: &str| id == "b";
        board.repaint(&now, 60, 13, &deleted);
        assert_eq!(board.shown(), &ids(&["c", "a"])[..]);
    }

    #[test]
    fn a_reply_to_the_reader_s_just_posted_topic_counts() {
        let mut ts = vec![topic("a", "x", 10, 50)];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(Some("me"), true, 50, 1_000, &never_deleted),
        );
        ts.push(topic("mine", "me", 1_005, 1_005));
        let now = sorted(ts.clone());
        board.update(
            &now,
            &inputs(Some("me"), true, 1_005, 1_005, &never_deleted),
        );
        assert_eq!(board.updated(&now, Some("me")), 0, "the reader's own root");
        // Someone replies to it: real activity. It is already on top, so
        // in place; a reply to a, below, is not.
        ts[1].last_activity = 1_010;
        ts[0].last_activity = 1_020;
        let now = sorted(ts.clone());
        board.update(
            &now,
            &inputs(Some("me"), true, 1_020, 1_020, &never_deleted),
        );
        assert_eq!(board.shown(), &ids(&["mine", "a"])[..]);
        assert_eq!(
            board.updated(&now, Some("me")),
            2,
            "both count, neither in place"
        );
    }

    #[test]
    fn an_evicted_row_does_not_break_the_top_of_the_list() {
        let mut ts = vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(None, true, 50, 10, &never_deleted),
        );
        // a is evicted (kept on top), b gets a reply: b is the top of the
        // listed rows, so in place.
        ts.remove(0);
        ts[0].last_activity = 70;
        let now = sorted(ts.clone());
        board.update(&now, &inputs(None, true, 70, 11, &never_deleted));
        assert_eq!(board.shown(), &ids(&["a", "b"])[..]);
        assert_eq!(board.updated(&now, None), 0);
    }

    #[test]
    fn a_revisit_after_a_failed_root_list_waits_for_the_new_answer() {
        // The page passes `ready_to_freeze` = window settled and the root
        // list answered or failed. A new request clears the failure
        // (`ChannelStore::request_topic_roots`), so on the revisit the
        // board stays provisional until the new answer, then freezes in
        // the true order.
        let window_only = sorted(vec![topic("w", "x", 1, 900)]);
        let mut board = FrozenBoard::new();
        board.update(&window_only, &inputs(None, false, 900, 10, &never_deleted));
        assert!(
            !board.is_frozen(),
            "the failure from the last visit was cleared"
        );
        let with_roots = sorted(vec![
            topic("w", "x", 1, 900),
            topic("busy", "x", 2, 950),
            topic("quiet", "x", 3, 3),
        ]);
        board.update(&with_roots, &inputs(None, true, 950, 11, &never_deleted));
        assert!(board.is_frozen());
        assert_eq!(board.shown(), &ids(&["busy", "w", "quiet"])[..]);
        assert_eq!(board.updated(&with_roots, None), 0);
    }

    /// Inputs with the ADR-2038 fields set.
    fn inputs_with<'a>(
        ready: bool,
        newest_known: u64,
        now: u64,
        baseline_settled: bool,
        known: &'a dyn Fn(&str) -> bool,
    ) -> BoardInputs<'a> {
        BoardInputs {
            me: None,
            ready_to_freeze: ready,
            newest_known,
            now_secs: now,
            deleted: &never_deleted,
            baseline_settled,
            activity_known: known,
        }
    }

    #[test]
    fn a_late_row_below_a_lower_known_row_counts_as_updated() {
        // Coordinator gap (a): a topic known only after the freeze, with
        // activity at or below the baseline, is appended at the bottom; with
        // true activity known it sits below a row of lower activity, so the
        // control must offer the re-sort.
        let ts = vec![topic("a", "x", 10, 500), topic("b", "x", 5, 100)];
        let mut board = FrozenBoard::new();
        board.update(&sorted(ts.clone()), &inputs_with(true, 500, 10, true, &always_known));
        let mut now = ts.clone();
        now.push(topic("late", "x", 1, 300)); // 300 <= baseline 500, above b
        let now = sorted(now);
        board.update(&now, &inputs_with(true, 500, 11, true, &always_known));
        assert_eq!(board.shown(), &ids(&["a", "b", "late"])[..]);
        assert_eq!(board.updated(&now, None), 1, "late sits below b (100 < 300)");
        board.repaint(&now, 500, 12, &never_deleted);
        assert_eq!(board.shown(), &ids(&["a", "late", "b"])[..]);
        assert_eq!(board.updated(&now, None), 0);
    }

    #[test]
    fn genuinely_older_late_rows_and_unknown_activity_count_nothing() {
        let ts = vec![topic("a", "x", 10, 500), topic("b", "x", 5, 100)];
        // An older page appends a topic older than every row: quiet.
        let mut board = FrozenBoard::new();
        board.update(&sorted(ts.clone()), &inputs_with(true, 500, 10, true, &always_known));
        let mut now = ts.clone();
        now.push(topic("older", "x", 1, 50));
        let now = sorted(now);
        board.update(&now, &inputs_with(true, 500, 11, true, &always_known));
        assert_eq!(board.updated(&now, None), 0);
        // Without section stats (activity not known) a late row's activity
        // is a lower bound: it is never counted on that basis.
        let mut board = FrozenBoard::new();
        board.update(&sorted(ts.clone()), &inputs_with(true, 500, 10, true, &never_known));
        let mut now = ts.clone();
        now.push(topic("late", "x", 1, 300));
        let now = sorted(now);
        board.update(&now, &inputs_with(true, 500, 11, true, &never_known));
        assert_eq!(board.updated(&now, None), 0);
    }

    #[test]
    fn a_cap_freeze_before_window_or_stats_retakes_the_baseline_once() {
        // Coordinator gap (b): frozen by the cap from the root list alone
        // (creation times), the window then lands on a quiet section.
        let roots_only = sorted(vec![topic("a", "x", 10, 10), topic("b", "x", 5, 5)]);
        let mut board = FrozenBoard::new();
        board.update(&roots_only, &inputs_with(true, 10, 100, false, &never_known));
        assert!(board.is_frozen());
        assert_eq!(board.baseline(), 10);
        // Pump figures arriving before either: nothing counts yet.
        let pumped = sorted(vec![topic("a", "x", 10, 40), topic("b", "x", 5, 400)]);
        board.update(&pumped, &inputs_with(true, 400, 101, false, &never_known));
        assert_eq!(board.updated(&pumped, None), 0, "baseline still provisional");
        // The window lands: activity from before the freeze is not new.
        let landed = sorted(vec![topic("a", "x", 10, 40), topic("b", "x", 5, 400)]);
        board.update(&landed, &inputs_with(true, 400, 102, true, &never_known));
        assert_eq!(board.baseline(), 400);
        assert_eq!(board.shown(), &ids(&["a", "b"])[..], "the order does not move");
        assert_eq!(board.updated(&landed, None), 0, "a quiet section shows nothing");
        // Re-taken once only: real activity afterwards counts.
        let later = sorted(vec![topic("a", "x", 10, 450), topic("b", "x", 5, 400)]);
        board.update(&later, &inputs_with(true, 450, 103, true, &never_known));
        assert_eq!(board.baseline(), 400);
        assert_eq!(board.updated(&later, None), 0, "a is on top: in place");
        let later = sorted(vec![topic("a", "x", 10, 450), topic("b", "x", 5, 460)]);
        board.update(&later, &inputs_with(true, 460, 104, true, &never_known));
        assert_eq!(board.updated(&later, None), 2);
    }

    #[test]
    fn a_freeze_with_section_stats_answered_takes_their_baseline() {
        // The window is not in, the section stats are: the structure the
        // board gets already carries their activity.
        let with_stats = sorted(vec![topic("a", "x", 10, 900), topic("b", "x", 5, 700)]);
        let mut board = FrozenBoard::new();
        board.update(&with_stats, &inputs_with(true, 900, 100, true, &always_known));
        assert_eq!(board.baseline(), 900);
        assert_eq!(board.shown(), &ids(&["a", "b"])[..]);
        assert_eq!(board.updated(&with_stats, None), 0);
    }

    /// One topic of the ADR-2038 seeded model.
    #[derive(Clone)]
    struct Live {
        id: String,
        created: u64,
        /// True last activity (what the section stats report).
        last: u64,
        /// Carries the topic marker: in the root list and the section stats.
        marked: bool,
        /// Delivered by the root list (a late root list answer adds more).
        in_roots: bool,
    }

    /// The section stats payload the relay would send for `model`.
    fn stats_for(model: &[Live]) -> crate::topics::SectionStats {
        let topics: Vec<serde_json::Value> = model
            .iter()
            .filter(|t| t.marked)
            .map(|t| serde_json::json!([t.id, t.created, t.last, "p", 0, null]))
            .collect();
        crate::topics::SectionStats::parse(&serde_json::json!({
            "fields": ["id", "created_at", "last_at", "last_pubkey", "replies", "original"],
            "topics": topics,
        }))
        .unwrap()
    }

    /// The ADR-2038 invariant, over 300 seeds:
    /// - provisional: the order moves only when the window, the root list
    ///   or the section stats land, never on the per-topic pump;
    /// - with section stats answered, the order at freeze is the true order
    ///   of every listed topic; with them failed, the order from structure;
    /// - frozen: no row moves, rows are only appended; on a quiet section
    ///   "updated" is exactly the late rows that sit below a known row of
    ///   lower activity (0 for older pages), and a cap freeze before the
    ///   window and the stats re-takes its baseline (0 once they land).
    #[test]
    fn section_stats_freeze_the_true_order_and_nothing_moves_after() {
        const W: u64 = 10_000; // the window's oldest message
        // Coverage: cap freezes taken before the window or the stats, and
        // late rows the control counted, must both occur.
        let (mut unsettled_caps, mut late_counted) = (0, 0);
        for seed in 1..=300u64 {
            let mut rng = XorShift(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
            let mut model: Vec<Live> = Vec::new();
            for i in 0..30 {
                let created = rng.below(W / 2);
                let last = if rng.below(4) == 0 {
                    W + rng.below(5_000) // active in the window
                } else {
                    created + rng.below(W - created) // dormant: stats only
                };
                model.push(Live {
                    id: format!("t{i:02}"),
                    created,
                    last,
                    marked: i % 10 != 9, // a few legacy roots
                    in_roots: rng.below(6) != 0,
                });
            }
            let answers = seed % 4 != 0; // section stats answered or failed
            let cap_freeze = seed % 5 == 0;
            let quiet = seed % 3 != 0;
            let (mut window, mut roots, mut section, mut pump) = (false, false, false, false);
            let structure = |m: &[Live], window: bool, roots: bool, section: bool| {
                let listed: Vec<TopicSummary> = m
                    .iter()
                    .filter(|t| (roots && t.marked && t.in_roots) || (window && t.last >= W))
                    .map(|t| {
                        let seen = if window && t.last >= W { t.last } else { t.created };
                        topic(&t.id, "a", t.created, seen)
                    })
                    .collect();
                let st = (section && answers).then(|| stats_for(m));
                crate::topics::fold_section_stats(sorted(listed), st.as_ref())
            };
            let full = |m: &[Live], window: bool, roots: bool, section: bool, pump: bool| {
                let st = structure(m, window, roots, section);
                if !pump {
                    return st;
                }
                with_topic_stats(st, |t| {
                    let last = m.iter().find(|x| x.id == t.id).map_or(0, |x| x.last);
                    (0, Some((last, "p".to_string())))
                })
            };
            let mut board = FrozenBoard::new();
            let order = [0u64, 1, 2];
            let mut landing_order = order.to_vec();
            for i in (1..landing_order.len()).rev() {
                landing_order.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let mut now = 1_000u64;
            let mut froze_settled = false;
            let mut at_freeze: Vec<String> = Vec::new();
            for step in 0..7u64 {
                now += 1;
                let before = board.shown().to_vec();
                let landing = step % 2 == 1 && step / 2 < 3;
                if landing {
                    match landing_order[(step / 2) as usize] {
                        0 => window = true,
                        1 => roots = true,
                        _ => section = true,
                    }
                } else {
                    pump = true;
                }
                let capped = cap_freeze && step == 2;
                let ready = capped || (window && roots && section);
                let st = structure(&model, window, roots, section);
                let fl = full(&model, window, roots, section, pump);
                let known_set: HashSet<String> = model
                    .iter()
                    .filter(|t| section && answers && t.marked)
                    .map(|t| t.id.clone())
                    .collect();
                let known = |id: &str| known_set.contains(id);
                let was_frozen = board.is_frozen();
                let settled = window || (section && answers);
                board.update(&st, &inputs_with(ready, newest(&fl), now, settled, &known));
                if !was_frozen && board.is_frozen() {
                    froze_settled = settled;
                    at_freeze = board.shown().to_vec();
                }
                if !landing && !was_frozen {
                    assert_eq!(board.shown(), &before[..], "seed {seed}: pump moved a row");
                }
                if !board.is_frozen() {
                    assert_eq!(board.updated(&fl, None), 0, "seed {seed}");
                }
                if board.is_frozen() && !was_frozen && !capped {
                    // The freeze order is the true order when the stats answered.
                    let expect: Vec<String> = if answers {
                        let mut v: Vec<&Live> = model
                            .iter()
                            .filter(|t| (t.marked && t.in_roots) || t.last >= W)
                            .collect();
                        v.sort_by(|a, b| b.last.cmp(&a.last).then(a.id.cmp(&b.id)));
                        // A legacy root is listed with its true activity only
                        // when it is in the window; otherwise it is not listed.
                        v.into_iter().map(|t| t.id.clone()).collect()
                    } else {
                        st.iter().map(|t| t.id.clone()).collect()
                    };
                    assert_eq!(board.shown(), &expect[..], "seed {seed}: freeze order");
                }
            }
            assert!(board.is_frozen(), "seed {seed}");
            // Rows appended after the freeze (during the provisional loop's
            // later landings too) are late; the rows shown at freeze are not.
            let frozen = at_freeze;
            if cap_freeze && !froze_settled {
                unsettled_caps += 1;
            }
            let mut late = 0u64;
            for round in 0..60u64 {
                now += 1;
                match rng.below(5) {
                    0 => {
                        // A late root-list answer: a marked root not shown yet.
                        if let Some(t) = model.iter_mut().find(|t| t.marked && !t.in_roots) {
                            t.in_roots = true;
                        }
                    }
                    1 => {
                        // An older page: a legacy topic older than every row.
                        let floor = model.iter().map(|t| t.last).min().unwrap_or(1);
                        let at = floor.saturating_sub(1 + rng.below(5)).max(1);
                        model.push(Live {
                            id: format!("old{late}"),
                            created: at.saturating_sub(1),
                            last: at,
                            marked: false,
                            in_roots: false,
                        });
                        late += 1;
                    }
                    2 if !quiet && round % 7 == 0 => {
                        // Real activity after the freeze.
                        let n = model.len() as u64;
                        let t = &mut model[rng.below(n) as usize];
                        t.last = W + 6_000 + now;
                    }
                    3 => pump = true,
                    _ => {}
                }
                // Everything lands (a cap freeze lands it now).
                window = true;
                roots = true;
                section = true;
                let st = structure(&model, window, roots, section);
                // Older pages bring their legacy topics in through the window.
                let mut st = st;
                for t in model.iter().filter(|t| t.id.starts_with("old")) {
                    if !st.iter().any(|s| s.id == t.id) {
                        st.push(topic(&t.id, "a", t.created, t.last));
                    }
                }
                let st = sorted(st);
                let mut fl = full(&model, window, roots, section, pump);
                for t in st.iter().filter(|t| t.id.starts_with("old")) {
                    if !fl.iter().any(|f| f.id == t.id) {
                        fl.push(t.clone());
                    }
                }
                let fl = sorted(fl);
                let known_set: HashSet<String> = model
                    .iter()
                    .filter(|t| answers && t.marked)
                    .map(|t| t.id.clone())
                    .collect();
                let known = |id: &str| known_set.contains(id);
                board.update(&st, &inputs_with(true, newest(&fl), now, true, &known));
                let shown = board.shown().to_vec();
                assert_eq!(&shown[..frozen.len()], &frozen[..], "seed {seed}: a frozen row moved");
                let unique: HashSet<&String> = shown.iter().collect();
                assert_eq!(unique.len(), shown.len(), "seed {seed}");
                if quiet {
                    // Independent count: late rows below a known lower row.
                    let act: HashMap<&str, u64> =
                        fl.iter().map(|t| (t.id.as_str(), t.last_activity)).collect();
                    let mut low: Option<u64> = None;
                    let mut expect = 0;
                    for (i, id) in shown.iter().enumerate() {
                        if !known(id) {
                            continue;
                        }
                        let a = act[id.as_str()];
                        if i >= frozen.len() && low.is_some_and(|l| l < a) {
                            expect += 1;
                        }
                        low = Some(low.map_or(a, |l| l.min(a)));
                    }
                    assert_eq!(
                        board.updated(&fl, None),
                        expect,
                        "seed {seed} round {round}: baseline {} shown {shown:?}",
                        board.baseline(),
                    );
                    late_counted += usize::from(expect > 0);
                }
            }
        }
        assert!(unsettled_caps > 5, "cap freezes before window/stats: {unsettled_caps}");
        assert!(late_counted > 20, "rounds with late rows counted: {late_counted}");
    }

    #[test]
    fn an_empty_list_is_never_frozen() {
        let mut board = FrozenBoard::new();
        board.update(&[], &inputs(None, true, 0, 10, &never_deleted));
        assert!(!board.is_frozen());
        let ts = sorted(vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)]);
        board.update(&ts, &inputs(None, true, 50, 10, &never_deleted));
        assert!(board.is_frozen());
        assert_eq!(board.shown(), &ids(&["a", "b"])[..]);
        assert_eq!(board.updated(&ts, None), 0);
    }

    #[test]
    fn provisional_follows_structure_and_freezes_once() {
        let mut board = FrozenBoard::new();
        // Root list first: creation order.
        let roots_only = sorted(vec![topic("busy", "x", 5, 5), topic("quiet", "x", 50, 50)]);
        board.update(&roots_only, &inputs(None, false, 50, 10, &never_deleted));
        assert_eq!(board.shown(), &ids(&["quiet", "busy"])[..]);
        // The window lands (busy replied at 900) and the board may freeze.
        let settled = sorted(vec![
            topic("busy", "x", 5, 900),
            topic("quiet", "x", 50, 50),
        ]);
        board.update(&settled, &inputs(None, true, 900, 10, &never_deleted));
        assert!(board.is_frozen());
        assert_eq!(board.shown(), &ids(&["busy", "quiet"])[..]);
        assert_eq!(board.baseline(), 900);
        // Frozen: a later structure change does not re-order.
        let later = sorted(vec![
            topic("busy", "x", 5, 900),
            topic("quiet", "x", 50, 950),
        ]);
        assert!(!board.update(&later, &inputs(None, true, 950, 11, &never_deleted)));
        assert_eq!(board.shown(), &ids(&["busy", "quiet"])[..]);
        assert_eq!(board.updated(&later, None), 1);
    }

    #[test]
    fn a_count_of_zero_then_the_real_count_changes_neither_order_nor_count() {
        let mut ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 1),
        ];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(None, true, 50, 10, &never_deleted),
        );
        let painted = board.shown().to_vec();
        for count in [0, 25, 0, 3] {
            ts[2].reply_count = count;
            let now = sorted(ts.clone());
            assert!(!board.update(&now, &inputs(None, true, 50, 11, &never_deleted)));
            assert_eq!(board.shown(), &painted[..]);
            assert_eq!(board.updated(&now, None), 0);
        }
    }

    #[test]
    fn another_user_s_reply_to_the_reader_s_topic_counts() {
        // The reader's old topic sits below b; someone replies to it.
        let mut ts = vec![topic("b", "x", 5, 60), topic("mine", "me", 10, 50)];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(Some("me"), true, 60, 1_000, &never_deleted),
        );
        ts[1].last_activity = 70;
        let now = sorted(ts.clone());
        board.update(&now, &inputs(Some("me"), true, 70, 1_001, &never_deleted));
        assert_eq!(
            board.updated(&now, Some("me")),
            1,
            "a reply to the reader's topic counts"
        );
    }

    #[test]
    fn the_reader_s_dormant_topic_arriving_late_goes_to_the_bottom() {
        let mut ts = vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(Some("me"), true, 50, 1_000, &never_deleted),
        );
        ts.push(topic("old-mine", "me", 20, 45));
        let now = sorted(ts.clone());
        board.update(&now, &inputs(Some("me"), true, 50, 1_001, &never_deleted));
        assert_eq!(board.shown(), &ids(&["a", "b", "old-mine"])[..]);
        assert_eq!(board.updated(&now, Some("me")), 0);
    }

    #[test]
    fn the_reader_s_just_posted_topic_goes_on_top_and_does_not_count() {
        let mut ts = vec![topic("a", "x", 10, 50), topic("b", "x", 5, 40)];
        let mut board = FrozenBoard::new();
        board.update(
            &sorted(ts.clone()),
            &inputs(Some("me"), true, 50, 1_000, &never_deleted),
        );
        // Posted just now on the same device clock.
        ts.push(topic("mine", "me", 1_010, 1_010));
        let now = sorted(ts.clone());
        board.update(
            &now,
            &inputs(Some("me"), true, 1_010, 1_010, &never_deleted),
        );
        assert_eq!(board.shown(), &ids(&["mine", "a", "b"])[..]);
        assert_eq!(board.updated(&now, Some("me")), 0);
        // Someone else's new topic is appended at the bottom, shown, counted.
        ts.push(topic("theirs", "x", 1_020, 1_020));
        let now = sorted(ts.clone());
        board.update(
            &now,
            &inputs(Some("me"), true, 1_020, 1_020, &never_deleted),
        );
        assert_eq!(board.shown(), &ids(&["mine", "a", "b", "theirs"])[..]);
        assert_eq!(board.updated(&now, Some("me")), 1);
    }

    #[test]
    fn rows_leave_only_on_an_honoured_deletion() {
        let ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("orig", "x", 1, 30),
        ];
        let mut board = FrozenBoard::new();
        board.note_aliases([("env".to_string(), "orig".to_string())]);
        board.update(
            &sorted(ts.clone()),
            &inputs(None, true, 50, 10, &never_deleted),
        );
        let without = |gone: &str| sorted(ts.iter().filter(|t| t.id != gone).cloned().collect());
        // Evicted, or named by an unhonoured kind-5: the row stays.
        assert!(!board.update(&without("b"), &inputs(None, true, 50, 11, &never_deleted)));
        assert_eq!(board.shown(), &ids(&["a", "b", "orig"])[..]);
        // Honoured: it leaves.
        let honoured = |id: &str| id == "b";
        assert!(board.update(&without("b"), &inputs(None, true, 50, 12, &honoured)));
        assert_eq!(board.shown(), &ids(&["a", "orig"])[..]);
        // A moderator's honoured deletion of the envelope removes the
        // restored original's row once the original is gone too.
        let envelope_deleted = |id: &str| id == "env";
        let rest = sorted(vec![ts[0].clone()]);
        assert!(board.update(&rest, &inputs(None, true, 50, 13, &envelope_deleted)));
        assert_eq!(board.shown(), &ids(&["a"])[..]);
    }

    #[test]
    fn the_control_paints_the_full_true_order() {
        let mut ts = vec![
            topic("a", "x", 10, 50),
            topic("b", "x", 5, 40),
            topic("c", "x", 1, 30),
        ];
        let mut board = FrozenBoard::new();
        board.note_aliases([("e".to_string(), "o".to_string())]);
        board.update(
            &sorted(ts.clone()),
            &inputs(None, true, 50, 10, &never_deleted),
        );
        ts[2].last_activity = 60;
        ts.push(topic("n", "other", 80, 80));
        let now = sorted(ts.clone());
        board.update(&now, &inputs(None, true, 80, 11, &never_deleted));
        assert_eq!(board.updated(&now, None), 2);
        board.repaint(&now, 80, 12, &never_deleted);
        assert_eq!(board.shown(), &ids(&["n", "c", "a", "b"])[..]);
        assert!(board.is_frozen());
        assert_eq!(board.updated(&now, None), 0);
        assert_eq!(board.baseline(), 80);
        assert_eq!(
            board.aliases.get("e").map(String::as_str),
            Some("o"),
            "pairs kept"
        );
    }

    #[test]
    fn an_envelope_and_its_opened_original_are_one_row() {
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
        let to_original = ev(
            "r1",
            "bob",
            "reply",
            50,
            42,
            vec![
                vec!["e", cid, "", "root"],
                vec!["e", inner.as_str(), "", "reply"],
            ],
        );
        // A reply naming the (shadowed) envelope id counts for the original.
        let to_envelope = ev(
            "r2",
            "cat",
            "reply",
            60,
            42,
            vec![vec!["e", cid, "", "root"], vec!["e", "env", "", "reply"]],
        );
        let topics = classify_topics(cid, &[envelope, original, to_original, to_envelope]);
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].id, inner);
        assert_eq!(
            (
                topics[0].reply_count,
                topics[0].last_activity,
                topics[0].last_pubkey.as_str()
            ),
            (2, 60, "cat")
        );
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
    fn first_paint_waits_for_the_window_roots_and_section_stats_within_the_hold() {
        assert!(!first_paint_ready(false, true, true, false));
        assert!(!first_paint_ready(true, false, true, false));
        assert!(!first_paint_ready(true, true, false, false));
        assert!(first_paint_ready(true, true, true, false));
        assert!(
            first_paint_ready(false, false, false, true),
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
}
