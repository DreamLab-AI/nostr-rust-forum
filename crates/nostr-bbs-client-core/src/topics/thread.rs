//! One topic's posts: which events are its replies, how edits fold into the
//! post they replace, which sibling a reply quotes, and the tags a new reply
//! or edit carries.
//!
//! A topic is a kind-42 ROOT in a section channel. A reply is a kind-42 (or
//! NIP-22 kind-1111) that references the root or, transitively, another
//! reply in the topic. Replies read oldest first. Shared by the forum's
//! thread page and the BBS thread view so both show the same posts.

use nostr_bbs_core::NostrEvent;

use super::board::board_events;

/// A single rendered reply within a thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyView {
    /// The ORIGINAL event id (the reply users reply to / thread against). Stays
    /// stable across edits so reply threading and the edit target never drift.
    pub id: String,
    /// Author of the original post.
    pub pubkey: String,
    /// The latest content (original, or the most recent edit's content).
    pub content: String,
    /// Original post timestamp (preserved even when an edit supersedes it).
    pub created_at: u64,
    /// `true` when an edit replaced the original content.
    pub edited: bool,
    /// When this reply quote-targets a specific sibling (not the topic root),
    /// the quoted parent's author + snippet for an inline quote block. `None`
    /// for a plain top-level reply to the topic.
    pub quote: Option<QuotedRef>,
    /// The post's own event tags, carried so `MentionText` can resolve a typed
    /// `@handle` against this post's `["p", pubkey]` tags. Without them a
    /// mention only renders as a link if the author happens to be in this
    /// session's NameCache already.
    pub tags: Vec<Vec<String>>,
}

/// A quoted parent shown inline above a quote-reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotedRef {
    /// Author of the quoted post.
    pub pubkey: String,
    /// First line of the quoted post's latest version.
    pub snippet: String,
}

/// Marker placed on a kind-42 that REPLACES (edits) an earlier post by the same
/// author: `["e", <original_id>, "", "edit"]`. Pragmatic, NIP-10-compatible
/// (the relay treats it as an ordinary `e` tag) and visible to the existing
/// kind-42 store stream with no relay-side support required.
pub const EDIT_MARKER: &str = "edit";

/// Marker placed on a kind-42 reply's `e` tag identifying the SIBLING it quotes:
/// `["e", <sibling_id>, "", "quote"]`. The reply's "reply" marker always points
/// at the topic root (so the topic list folds it and the reply list matches it);
/// the quote marker is a separate, purely presentational reference the card
/// renders inline. Non-standard but NIP-10-compatible (an ordinary `e` tag to any
/// relay/other client).
pub const QUOTE_MARKER: &str = "quote";

/// If `event` is an edit, return the id of the post it replaces.
///
/// An edit is a kind-42 carrying `["e", <target>, _, "edit"]`. The target must
/// not be the channel root (those carry the "root" marker), so a normal topic
/// or reply post is never mistaken for an edit.
pub fn edit_target(event: &NostrEvent) -> Option<String> {
    if event.kind != 42 {
        return None;
    }
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == EDIT_MARKER)
        .map(|t| t[1].to_lowercase())
}

/// The post this event is an edit of (`["e", id, "", "edit"]`), as tagged
/// (case kept) and whatever its kind. Board classification and post links use
/// this; [`edit_target`] is the kind-42-only, lower-cased form the reply
/// derivation indexes by.
pub fn edit_target_of(ev: &NostrEvent) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == EDIT_MARKER)
        .map(|t| t[1].clone())
}

/// The channel an event is filed in: its `root`-marked `e` tag, else its
/// first unmarked `e` tag, lowercased. An `edit`, `reply` or other marked
/// `e` tag names a post, never the channel.
fn channel_anchor(ev: &NostrEvent) -> Option<String> {
    let e_tags = || ev.tags.iter().filter(|t| t.len() >= 2 && t[0] == "e");
    e_tags()
        .find(|t| t.get(3).map(String::as_str) == Some("root"))
        .or_else(|| e_tags().find(|t| t.get(3).is_none_or(|m| m.is_empty())))
        .map(|t| t[1].to_lowercase())
}

/// Whether `edit` may replace the text of `original` (ADR-2037 review):
/// same author, and filed in the same channel. An edit posted in another
/// channel, which may sit in another zone with other readers and writers,
/// is ignored, so moving a channel to another zone cannot be undone for its
/// posts by editing them from outside.
fn edit_applies_to(edit: &NostrEvent, original: &NostrEvent) -> bool {
    edit.pubkey.eq_ignore_ascii_case(&original.pubkey)
        && channel_anchor(edit) == channel_anchor(original)
}

/// Resolve the latest authored version of `original` from `events`.
///
/// Walks every edit that the SAME author published against `original.id`
/// (directly or transitively via an edit-of-an-edit) and returns the content +
/// timestamp of the newest one. The returned `(content, latest_ts, edited)`
/// uses the original's content/timestamp when no edit exists. Edits by anyone
/// other than the original author are ignored — only the author can edit.
pub fn latest_version(original: &NostrEvent, events: &[NostrEvent]) -> (String, u64, bool) {
    let mut current_id = original.id.to_lowercase();
    let mut content = original.content.clone();
    let mut newest_edit_ts = 0u64;
    let mut edited = false;

    // Iteratively follow edit pointers: id -> latest edit of id -> ... The bound
    // on iterations guards against a cyclic/self-referential tag set.
    for _ in 0..64 {
        let next = events
            .iter()
            .filter(|e| {
                edit_applies_to(e, original)
                    && edit_target(e).as_deref() == Some(current_id.as_str())
            })
            // Most recent edit of this id wins (last-write-wins by created_at,
            // tie-broken by id for determinism).
            .max_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
        match next {
            Some(e) => {
                content = e.content.clone();
                newest_edit_ts = e.created_at;
                edited = true;
                current_id = e.id.to_lowercase();
            }
            None => break,
        }
    }
    let _ = newest_edit_ts;
    (content, original.created_at, edited)
}

/// Every event id in the edit-chain rooted at `original` (the original plus all
/// transitive edits by its author). Used to exclude edit events from the reply
/// list so an edit never shows up as its own reply.
#[cfg(test)]
fn edit_chain_ids(original: &NostrEvent, events: &[NostrEvent]) -> Vec<String> {
    let mut ids = vec![original.id.to_lowercase()];
    let mut frontier = vec![original.id.to_lowercase()];
    for _ in 0..64 {
        let mut next_frontier = Vec::new();
        for target in &frontier {
            for e in events.iter().filter(|e| {
                e.pubkey.eq_ignore_ascii_case(&original.pubkey)
                    && edit_target(e).as_deref() == Some(target.as_str())
            }) {
                let lid = e.id.to_lowercase();
                if !ids.contains(&lid) {
                    ids.push(lid.clone());
                    next_frontier.push(lid);
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }
    ids
}

/// The `["e", <id>, "", "quote"]` sibling this reply quotes, if any. Rendered as
/// an inline quote block; distinct from the "reply" marker, which always points
/// at the topic root so the topic list folds the reply correctly.
pub fn quoted_e_tag(event: &NostrEvent) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == QUOTE_MARKER)
        .map(|t| t[1].clone())
}

/// All `e`/`E`-tag values referenced by an event, lowercased.
fn referenced_event_ids(event: &NostrEvent) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && (t[0] == "e" || t[0] == "E"))
        .map(|t| t[1].to_lowercase())
        .collect()
}

/// The replies of the topic `root` among `events`, oldest first, in one
/// O(n) pass with id, edit-target and reverse-reference indexes:
///
/// - candidates: kind-42/1111 that are not the root, not in the root's edit
///   chain, and not themselves edits;
/// - membership is transitive: a candidate referencing the root or any reply
///   already in the topic (a reply to a reply, as JunkieJarvis threads);
/// - each reply shows its author's latest edit, and a `quote` marker to a
///   sibling resolves the sibling's author and first line.
///
/// Same result as the previous fixpoint (kept as the test reference
/// `thread_replies_reference`), which rescanned all events per pass and per
/// reply.
pub fn thread_replies(root: &NostrEvent, events: &[NostrEvent]) -> Vec<ReplyView> {
    use std::collections::{HashMap, HashSet, VecDeque};

    let lower = |s: &str| s.to_lowercase();
    let mut by_id: HashMap<String, &NostrEvent> = HashMap::with_capacity(events.len());
    let mut edits_of: HashMap<String, Vec<&NostrEvent>> = HashMap::new();
    for e in events {
        by_id.entry(lower(&e.id)).or_insert(e);
        if let Some(target) = edit_target(e) {
            edits_of.entry(target).or_default().push(e);
        }
    }
    // The newest same-author, same-channel edit of `id`, as
    // `latest_version` picks it.
    let newest_edit = |id: &str, original: &NostrEvent| -> Option<&NostrEvent> {
        edits_of.get(id).and_then(|v| {
            v.iter()
                .copied()
                .filter(|e| edit_applies_to(e, original))
                .max_by(|a, b| {
                    a.created_at
                        .cmp(&b.created_at)
                        .then_with(|| a.id.cmp(&b.id))
                })
        })
    };
    let latest = |original: &NostrEvent| -> (String, u64, bool) {
        let mut current = lower(&original.id);
        let mut content = &original.content;
        let mut edited = false;
        for _ in 0..64 {
            match newest_edit(&current, original) {
                Some(e) => {
                    content = &e.content;
                    edited = true;
                    current = lower(&e.id);
                }
                None => break,
            }
        }
        (content.clone(), original.created_at, edited)
    };
    // The root's edit chain (every transitive same-author edit).
    let mut root_chain: HashSet<String> = HashSet::new();
    root_chain.insert(lower(&root.id));
    let mut frontier = vec![lower(&root.id)];
    for _ in 0..64 {
        let mut next = Vec::new();
        for target in &frontier {
            for e in edits_of.get(target).into_iter().flatten() {
                if e.pubkey.eq_ignore_ascii_case(&root.pubkey) && root_chain.insert(lower(&e.id)) {
                    next.push(lower(&e.id));
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    let is_candidate = |e: &NostrEvent| -> bool {
        !e.id.eq_ignore_ascii_case(&root.id)
            && (e.kind == 42 || e.kind == 1111)
            && !root_chain.contains(&lower(&e.id))
            && edit_target(e).is_none()
    };
    // Reverse references: id -> candidates that reference it.
    let mut referenced_by: HashMap<String, Vec<String>> = HashMap::new();
    for e in events.iter().filter(|e| is_candidate(e)) {
        let id = lower(&e.id);
        for r in referenced_event_ids(e) {
            referenced_by.entry(r).or_default().push(id.clone());
        }
    }
    let root_id = lower(&root.id);
    let mut thread: HashSet<String> = HashSet::new();
    thread.insert(root_id.clone());
    let mut queue: VecDeque<String> = VecDeque::from([root_id.clone()]);
    while let Some(id) = queue.pop_front() {
        for child in referenced_by.get(&id).into_iter().flatten() {
            if thread.insert(child.clone()) {
                queue.push_back(child.clone());
            }
        }
    }
    let mut out: Vec<ReplyView> = events
        .iter()
        .filter(|e| !e.id.eq_ignore_ascii_case(&root.id) && thread.contains(&lower(&e.id)))
        .map(|e| {
            let (content, created_at, edited) = latest(e);
            let quote = quoted_e_tag(e)
                .map(|id| lower(&id))
                .filter(|id| *id != root_id)
                .and_then(|target| by_id.get(&target).copied())
                .map(|tgt| QuotedRef {
                    pubkey: tgt.pubkey.clone(),
                    snippet: first_line(&latest(tgt).0),
                });
            ReplyView {
                id: e.id.clone(),
                pubkey: e.pubkey.clone(),
                content,
                created_at,
                edited,
                quote,
                tags: e.tags.clone(),
            }
        })
        .collect();
    out.sort_by_key(|r| r.created_at);
    out
}

/// A fingerprint of what a reply card shows, for its list key.
pub fn view_key(r: &ReplyView) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    r.content.hash(&mut h);
    r.edited.hash(&mut h);
    r.quote
        .as_ref()
        .map(|q| (&q.pubkey, &q.snippet))
        .hash(&mut h);
    h.finish()
}

/// The previous O(n^2) derivation, kept verbatim as the reference
/// `thread_replies` is tested against.
#[cfg(test)]
fn thread_replies_reference(root: &NostrEvent, events: &[NostrEvent]) -> Vec<ReplyView> {
    let root = root.clone();
    let channel_events: &[NostrEvent] = events;
    let mut out: Vec<ReplyView> = {
        let events = channel_events;
        let root_id_lower = root.id.to_lowercase();
        // Ids that belong to the ROOT's edit chain — never replies.
        let root_chain = edit_chain_ids(&root, events);
        // First pass: the genuine replies (reference the root, are not edits
        // of anything, and are not part of the root's edit chain).
        // A reply candidate: a kind-42/1111 that is neither the root, an edit
        // of the root, nor an edit of another reply.
        let is_candidate = |e: &NostrEvent| -> bool {
            if e.id.eq_ignore_ascii_case(&root.id) {
                return false; // the root itself is not a reply
            }
            if e.kind != 42 && e.kind != 1111 {
                return false;
            }
            if root_chain.contains(&e.id.to_lowercase()) {
                return false; // an edit of the root
            }
            edit_target(e).is_none() // an edit of another reply is not a reply
        };
        // Transitive thread membership. A reply belongs to this topic if it
        // references the ROOT *or any event already in the topic*. The old
        // one-level test (references-root-directly) silently dropped nested
        // replies — a reply to a reply — most visibly JunkieJarvis, which
        // (per standard NIP-10) threads under the specific message that tagged
        // it rather than the topic root, so its answers never rendered.
        // Fixpoint over the channel's candidate events; converges in
        // max-reply-depth passes.
        let mut thread_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        thread_ids.insert(root_id_lower.clone());
        loop {
            let mut added = false;
            for e in events.iter() {
                let lid = e.id.to_lowercase();
                if thread_ids.contains(&lid) || !is_candidate(e) {
                    continue;
                }
                if referenced_event_ids(e)
                    .iter()
                    .any(|r| thread_ids.contains(r))
                {
                    thread_ids.insert(lid);
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        let originals: Vec<&NostrEvent> = events
            .iter()
            .filter(|e| {
                !e.id.eq_ignore_ascii_case(&root.id) && thread_ids.contains(&e.id.to_lowercase())
            })
            .collect();

        originals
            .into_iter()
            .map(|e| {
                let (content, created_at, edited) = latest_version(e, events);
                // Quote target: a "reply" e-tag pointing at a SIBLING reply
                // (not the topic root). Resolve the quoted author + snippet so
                // the card can show what it is answering, inline, no nesting.
                let quote = quoted_e_tag(e)
                    .map(|id| id.to_lowercase())
                    .filter(|id| *id != root_id_lower)
                    .and_then(|target_id| {
                        events
                            .iter()
                            .find(|ev| ev.id.to_lowercase() == target_id)
                            .map(|tgt| {
                                let (tgt_content, _, _) = latest_version(tgt, events);
                                QuotedRef {
                                    pubkey: tgt.pubkey.clone(),
                                    snippet: first_line(&tgt_content),
                                }
                            })
                    });
                ReplyView {
                    id: e.id.clone(),
                    pubkey: e.pubkey.clone(),
                    content,
                    created_at,
                    edited,
                    quote,
                    tags: e.tags.clone(),
                }
            })
            .collect()
    };

    out.sort_by_key(|r| r.created_at);
    out
}

/// First non-empty line of content, trimmed and length-clipped, for titles.
pub fn first_line(content: &str) -> String {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .trim();
    if line.is_empty() {
        return "(untitled topic)".to_string();
    }
    const MAX: usize = 90;
    if line.chars().count() > MAX {
        let clipped: String = line.chars().take(MAX).collect();
        format!("{}\u{2026}", clipped.trim_end())
    } else {
        line.to_string()
    }
}

/// Root `e`-tag value of a kind-42: the `root`-marked tag, else the first `e`.
pub fn root_e_tag(event: &NostrEvent) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
        .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
        .map(|t| t[1].clone())
}

/// The topic root of channel `channel_id` among `events` whose id satisfies
/// `is_wanted` (a full id, or a forum URL slug that is an id prefix): a
/// kind-42 anchored to the channel (or with no `e` tag at all).
pub fn find_topic_root(
    events: &[NostrEvent],
    channel_id: &str,
    is_wanted: impl Fn(&str) -> bool,
) -> Option<NostrEvent> {
    let cid = channel_id.to_lowercase();
    events
        .iter()
        .find(|e| {
            e.kind == 42
                && root_e_tag(e).is_none_or(|r| r.to_lowercase() == cid)
                && is_wanted(&e.id)
        })
        .cloned()
}

/// The events a topic page derives its root and replies from: the channel's
/// history window and its section's root list ([`board_events`]), plus the
/// topic's own paged list when it has one (`topic`: its events and its
/// cursor's `newer_from`). While the topic list is detached in older
/// replies (`newer_from` set), channel posts from that time on wait for its
/// reload rather than appearing below a gap.
pub fn thread_events(
    channel: &[NostrEvent],
    roots: &[NostrEvent],
    topic: Option<(Vec<NostrEvent>, Option<u64>)>,
) -> Vec<NostrEvent> {
    let channel = board_events(channel, roots);
    let Some((mut events, cutoff)) = topic else {
        return channel;
    };
    let held: std::collections::HashSet<String> = events.iter().map(|e| e.id.clone()).collect();
    events.extend(
        channel
            .into_iter()
            .filter(|e| !held.contains(&e.id) && cutoff.is_none_or(|t| e.created_at < t)),
    );
    events
}

/// The tags of a new topic (a root) in channel `channel_id`, as the forum
/// publishes them: the channel as the `root` anchor and the topic marker
/// (`["t", "topic"]`), which lists the root in the section's root list
/// (`#t:["topic"]`, as sealed roots are) so it is never only reachable by
/// paging the channel's history. Mentions are the caller's to append.
pub fn topic_root_tags(channel_id: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "e".to_string(),
            channel_id.to_string(),
            String::new(),
            "root".to_string(),
        ],
        vec![
            "t".to_string(),
            nostr_bbs_core::sealed::TOPIC_MARKER.to_string(),
        ],
    ]
}

/// The tags of a new reply in topic `root_id` (by `root_pubkey`) of channel
/// `channel_id`, as the forum publishes them: the channel as the `root`
/// anchor, the TOPIC ROOT as the `reply` parent (so the topic list folds it,
/// the relay's `#e:[root]` topic paging and count find it), the root's
/// author notified. Replying to a particular post (`quote`: its id and
/// author) adds a [`QUOTE_MARKER`] tag to it and notifies its author; the
/// reply still threads under the root. Mentions are the caller's to append.
pub fn topic_reply_tags(
    channel_id: &str,
    root_id: &str,
    root_pubkey: &str,
    quote: Option<(&str, &str)>,
) -> Vec<Vec<String>> {
    let e = |id: &str, marker: &str| {
        vec![
            "e".to_string(),
            id.to_string(),
            String::new(),
            marker.to_string(),
        ]
    };
    let mut tags = vec![e(channel_id, "root"), e(root_id, "reply")];
    if !root_pubkey.is_empty() {
        tags.push(vec!["p".to_string(), root_pubkey.to_string()]);
    }
    if let Some((id, pk)) = quote.filter(|(id, _)| !id.eq_ignore_ascii_case(root_id)) {
        tags.push(e(id, QUOTE_MARKER));
        if !pk.is_empty() && pk != root_pubkey {
            tags.push(vec!["p".to_string(), pk.to_string()]);
        }
    }
    tags
}

/// The tags of an edit replacing post `target_id` in topic `root` (its id
/// and author) of channel `channel_id`, as the forum publishes them: the
/// channel anchor; the topic root as the `reply` parent unless the root
/// itself is being edited (so the edit re-enters the topic's paged list);
/// the [`EDIT_MARKER`] pointer; and the root author's `p` tag, which keeps an
/// edited reply reaching the person it answers.
pub fn edit_tags(
    channel_id: &str,
    root: Option<(&str, &str)>,
    target_id: &str,
) -> Vec<Vec<String>> {
    let e = |id: &str, marker: &str| {
        vec![
            "e".to_string(),
            id.to_string(),
            String::new(),
            marker.to_string(),
        ]
    };
    let mut tags = vec![e(channel_id, "root")];
    if let Some((root_id, _)) = root.filter(|(r, _)| !r.eq_ignore_ascii_case(target_id)) {
        tags.push(e(root_id, "reply"));
    }
    tags.push(e(target_id, EDIT_MARKER));
    if let Some((_, pk)) = root.filter(|(_, pk)| !pk.is_empty()) {
        tags.push(vec!["p".to_string(), pk.to_string()]);
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        id: &str,
        pubkey: &str,
        created_at: u64,
        content: &str,
        tags: Vec<Vec<&str>>,
    ) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            created_at,
            kind: 42,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: content.to_string(),
            sig: String::new(),
        }
    }

    /// The O(n) derivation agrees with the previous fixpoint on a topic with
    /// every case it handles: root edits (author's and another's), direct and
    /// nested replies, reply edits and edits of edits, quotes of siblings and
    /// of the root, kind-1111 comments, mixed-case ids, unrelated topics.
    #[test]
    fn thread_replies_match_the_reference_derivation() {
        let ch = "c".repeat(64);
        let root = ev(
            "ROOT",
            "alice",
            100,
            "topic",
            vec![vec!["e", &ch, "", "root"]],
        );
        let mut events = vec![root.clone()];
        let id = |i: usize| format!("r{i:04}");
        for i in 0..400usize {
            let mut tags = vec![vec![
                "e".to_string(),
                ch.clone(),
                String::new(),
                "root".to_string(),
            ]];
            let parent = match i % 7 {
                0..=2 => "root".to_string(),
                3 if i > 10 => id(i - 5),       // reply to a reply
                4 if i > 3 => id(i - 3),        // reply to a reply
                5 => "OTHER-TOPIC".to_string(), // not in this topic
                _ => "ROOT".to_string(),        // upper-case root ref
            };
            tags.push(vec!["e".into(), parent, String::new(), "reply".into()]);
            if i % 11 == 0 && i > 20 {
                tags.push(vec![
                    "e".into(),
                    id(i - 13),
                    String::new(),
                    QUOTE_MARKER.into(),
                ]);
            }
            if i % 13 == 0 {
                tags.push(vec![
                    "e".into(),
                    "root".into(),
                    String::new(),
                    QUOTE_MARKER.into(),
                ]);
            }
            let author = ["alice", "bob", "carol"][i % 3];
            let mut e = ev(
                &id(i),
                author,
                200 + (i as u64 / 3),
                &format!("line {i}\nmore"),
                vec![],
            );
            e.tags = tags;
            if i % 17 == 0 {
                e.kind = 1111;
            }
            events.push(e);
            // Edits: by the author (and an edit of that edit), and by someone else.
            if i % 5 == 0 {
                let ed = ev(
                    &format!("e{i:04}"),
                    author,
                    900 + i as u64,
                    &format!("edited {i}"),
                    vec![edit_tag(&id(i))],
                );
                events.push(ed);
                if i % 10 == 0 {
                    events.push(ev(
                        &format!("f{i:04}"),
                        author,
                        1900 + i as u64,
                        &format!("edited twice {i}"),
                        vec![edit_tag(&format!("e{i:04}"))],
                    ));
                }
                events.push(ev(
                    &format!("x{i:04}"),
                    "mallory",
                    950 + i as u64,
                    "not yours",
                    vec![edit_tag(&id(i))],
                ));
            }
        }
        events.push(ev(
            "rootedit",
            "alice",
            3000,
            "topic v2",
            vec![edit_tag("root")],
        ));
        events.push(ev(
            "rootedit2",
            "alice",
            3001,
            "topic v3",
            vec![edit_tag("rootedit")],
        ));
        events.push(ev(
            "rootforge",
            "bob",
            3002,
            "forged",
            vec![edit_tag("root")],
        ));
        let root = events[0].clone();
        assert_eq!(
            thread_replies(&root, &events),
            thread_replies_reference(&root, &events)
        );
        assert!(
            thread_replies(&root, &events).len() > 200,
            "the fixture exercises many replies"
        );
    }

    fn edit_tag(target: &str) -> Vec<&str> {
        vec!["e", target, "", EDIT_MARKER]
    }

    #[test]
    fn edit_target_detects_marker() {
        let e = ev("edit1", "alice", 200, "fixed", vec![edit_tag("orig")]);
        assert_eq!(edit_target(&e).as_deref(), Some("orig"));
    }

    #[test]
    fn edit_target_ignores_root_and_reply_markers() {
        let root = ev("r", "alice", 100, "hi", vec![vec!["e", "chan", "", "root"]]);
        assert_eq!(edit_target(&root), None);
        let reply = ev(
            "p",
            "alice",
            100,
            "hi",
            vec![vec!["e", "root", "", "reply"]],
        );
        assert_eq!(edit_target(&reply), None);
    }

    #[test]
    fn quoted_e_tag_extracts_quote_marker_sibling() {
        // A quote-reply threads under the topic root ("reply") and quotes a
        // sibling ("quote"); only the quote marker is the inline-quoted target.
        let quote_reply = ev(
            "q",
            "bob",
            300,
            "quoting you",
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "topicroot", "", "reply"],
                vec!["e", "sibling", "", "quote"],
                vec!["p", "alice"],
            ],
        );
        assert_eq!(quoted_e_tag(&quote_reply).as_deref(), Some("sibling"));
        // A plain reply (reply → root, no quote marker) quotes nothing.
        let plain = ev(
            "p",
            "carol",
            200,
            "hi",
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "topicroot", "", "reply"],
            ],
        );
        assert_eq!(quoted_e_tag(&plain), None);
    }

    #[test]
    fn latest_version_no_edit_returns_original() {
        let orig = ev("orig", "alice", 100, "original", vec![]);
        let (content, ts, edited) = latest_version(&orig, std::slice::from_ref(&orig));
        assert_eq!(content, "original");
        assert_eq!(ts, 100);
        assert!(!edited);
    }

    #[test]
    fn latest_version_picks_newest_author_edit() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        let e1 = ev("e1", "alice", 200, "v2", vec![edit_tag("orig")]);
        let e2 = ev("e2", "alice", 300, "v3", vec![edit_tag("orig")]);
        let events = vec![orig.clone(), e1, e2];
        let (content, ts, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v3");
        // Original timestamp is preserved for display ordering.
        assert_eq!(ts, 100);
        assert!(edited);
    }

    #[test]
    fn latest_version_follows_edit_of_edit() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        let e1 = ev("e1", "alice", 200, "v2", vec![edit_tag("orig")]);
        let e2 = ev("e2", "alice", 300, "v3", vec![edit_tag("e1")]);
        let events = vec![orig.clone(), e1, e2];
        let (content, _ts, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v3");
        assert!(edited);
    }

    #[test]
    fn latest_version_ignores_edits_by_other_authors() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        // mallory cannot edit alice's post.
        let forged = ev("f1", "mallory", 200, "hacked", vec![edit_tag("orig")]);
        let events = vec![orig.clone(), forged];
        let (content, _ts, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v1");
        assert!(!edited);
    }

    #[test]
    fn latest_version_survives_edit_cycle() {
        // a -> b and b -> a forms a cycle; the iteration bound prevents a hang.
        let orig = ev("a", "alice", 100, "v1", vec![]);
        let b = ev("b", "alice", 200, "v2", vec![edit_tag("a")]);
        let a_again = ev("a2", "alice", 300, "v3", vec![edit_tag("b")]);
        let cyc = ev("c", "alice", 400, "loop", vec![edit_tag("a2")]);
        let _ = latest_version(&orig, &[orig.clone(), b, a_again, cyc]);
        // No panic / no hang is the assertion.
    }

    #[test]
    fn edit_chain_ids_collects_transitive_edits() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        let e1 = ev("e1", "alice", 200, "v2", vec![edit_tag("orig")]);
        let e2 = ev("e2", "alice", 300, "v3", vec![edit_tag("e1")]);
        let other = ev(
            "x",
            "alice",
            150,
            "reply",
            vec![vec!["e", "orig", "", "reply"]],
        );
        let events = vec![orig.clone(), e1, e2, other];
        let ids = edit_chain_ids(&orig, &events);
        assert!(ids.contains(&"orig".to_string()));
        assert!(ids.contains(&"e1".to_string()));
        assert!(ids.contains(&"e2".to_string()));
        // A genuine reply is NOT part of the edit chain.
        assert!(!ids.contains(&"x".to_string()));
    }

    #[test]
    fn reply_tags_thread_under_the_root_and_quote_the_sibling() {
        let plain = topic_reply_tags("chan", "root", "op", None);
        assert_eq!(
            plain,
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "root", "", "reply"],
                vec!["p", "op"],
            ]
        );
        let quoted = topic_reply_tags("chan", "root", "op", Some(("sib", "ann")));
        assert_eq!(&quoted[..3], &plain[..]);
        assert_eq!(quoted[3], vec!["e", "sib", "", QUOTE_MARKER]);
        assert_eq!(quoted[4], vec!["p", "ann"]);
        // Quoting the root, or a sibling by the root's author, adds nothing.
        assert_eq!(
            topic_reply_tags("chan", "root", "op", Some(("ROOT", "op"))),
            plain
        );
        assert_eq!(
            topic_reply_tags("chan", "root", "op", Some(("sib", "op"))).len(),
            4
        );
        // An unknown root author never yields an empty `p` tag.
        assert!(!topic_reply_tags("chan", "root", "", None)
            .iter()
            .any(|t| t[0] == "p"));
        // The reply is found by the topic's own paging and folds into it.
        let mut r = ev("r", "ann", 2, "hi", vec![]);
        r.tags = quoted;
        assert_eq!(nostr_bbs_core::sealed::reply_root_of(&r), Some("root"));
        let root = ev("root", "op", 1, "t", vec![vec!["e", "chan", "", "root"]]);
        assert_eq!(
            crate::topics::classify_topics("chan", &[root, r])[0].reply_count,
            1
        );
    }

    #[test]
    fn edit_tags_keep_the_topic_and_its_author() {
        assert_eq!(
            edit_tags("chan", Some(("root", "op")), "r1"),
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "root", "", "reply"],
                vec!["e", "r1", "", EDIT_MARKER],
                vec!["p", "op"],
            ]
        );
        // Editing the root itself: no reply marker.
        assert_eq!(
            edit_tags("chan", Some(("root", "op")), "root"),
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "root", "", EDIT_MARKER],
                vec!["p", "op"],
            ]
        );
        assert_eq!(edit_tags("chan", None, "x").len(), 2);
    }

    #[test]
    fn thread_events_merge_and_hold_back_posts_past_a_detached_window() {
        let chan = vec![
            ev("live-old", "a", 50, "", vec![]),
            ev("live-new", "a", 500, "", vec![]),
        ];
        let roots = vec![ev("root", "op", 1, "", vec![])];
        let ids = |v: Vec<NostrEvent>| {
            let mut ids: Vec<String> = v.into_iter().map(|e| e.id).collect();
            ids.sort();
            ids
        };
        assert_eq!(
            ids(thread_events(&chan, &roots, None)),
            ["live-new", "live-old", "root"]
        );
        let topic = vec![
            ev("t1", "b", 40, "", vec![]),
            ev("live-old", "a", 50, "", vec![]),
        ];
        assert_eq!(
            ids(thread_events(&chan, &roots, Some((topic.clone(), None)))),
            ["live-new", "live-old", "root", "t1"],
            "deduplicated by id"
        );
        assert_eq!(
            ids(thread_events(&chan, &roots, Some((topic, Some(100))))),
            ["live-old", "root", "t1"],
            "posts from the cutoff on wait for the reload"
        );
    }

    #[test]
    fn find_topic_root_wants_a_root_of_this_channel() {
        let es = vec![
            ev("reply", "a", 2, "", vec![vec!["e", "root", "", "root"]]),
            ev("ROOT", "op", 1, "", vec![vec!["e", "CHAN", "", "root"]]),
            ev(
                "elsewhere",
                "op",
                1,
                "",
                vec![vec!["e", "other", "", "root"]],
            ),
        ];
        let found = find_topic_root(&es, "chan", |id| id.eq_ignore_ascii_case("root"));
        assert_eq!(found.map(|e| e.id), Some("ROOT".into()));
        assert!(find_topic_root(&es, "chan", |id| id == "elsewhere").is_none());
        assert!(find_topic_root(&es, "chan", |id| id == "reply").is_none());
    }

    #[test]
    fn topic_root_tags_list_the_root_as_a_topic() {
        let mut root = ev("r", "op", 1, "t", vec![]);
        root.tags = topic_root_tags("chan");
        assert!(nostr_bbs_core::sealed::is_topic_root(&root));
        assert!(root
            .tags
            .iter()
            .any(|t| t == &["t", nostr_bbs_core::sealed::TOPIC_MARKER]));
        assert_eq!(crate::topics::classify_topics("chan", &[root]).len(), 1);
    }

    // -- ADR-2037 review: edits apply only within their channel ---------------

    #[test]
    fn an_edit_posted_in_another_channel_does_not_replace_the_text() {
        let orig = ev(
            "orig",
            "alice",
            100,
            "v1",
            vec![vec!["e", "pinned", "", "root"]],
        );
        let elsewhere = ev(
            "e1",
            "alice",
            200,
            "rewritten from outside",
            vec![vec!["e", "other", "", "root"], edit_tag("orig")],
        );
        let events = vec![orig.clone(), elsewhere.clone()];
        let (content, _, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v1");
        assert!(!edited);
        // The same edit filed in the original's channel applies.
        let here = ev(
            "e2",
            "alice",
            300,
            "v2",
            vec![vec!["e", "pinned", "", "root"], edit_tag("orig")],
        );
        let events = vec![orig.clone(), elsewhere, here];
        let (content, _, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v2");
        assert!(edited);
    }

    #[test]
    fn a_reply_is_not_rewritten_by_an_edit_from_another_channel() {
        let root = ev(
            "root",
            "bob",
            100,
            "topic",
            vec![vec!["e", "pinned", "", "root"]],
        );
        let reply = ev(
            "r1",
            "alice",
            110,
            "reply v1",
            vec![
                vec!["e", "pinned", "", "root"],
                vec!["e", "root", "", "reply"],
            ],
        );
        let outside = ev(
            "x1",
            "alice",
            120,
            "rewritten",
            vec![
                vec!["e", "other", "", "root"],
                vec!["e", "root", "", "reply"],
                edit_tag("r1"),
            ],
        );
        let views = thread_replies(&root, &[root.clone(), reply, outside]);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].content, "reply v1");
        assert!(!views[0].edited);
    }
}
