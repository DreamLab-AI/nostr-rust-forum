//! Topic-list view for a BBS section (#8).
//!
//! A *section* is a kind-40 channel. A *topic* is a kind-42 ROOT message inside
//! it (a thread starter) — its e-tags reference the channel id as the root and
//! it is not itself a reply to another in-channel message. A *reply* is a
//! kind-42 (or NIP-22 kind-1111) event that e-tags a topic root.
//!
//! This component renders the section as a LIST OF TOPICS (title/first line,
//! author, reply count, last activity) — NOT a flat linear chat. Each row links
//! to the [`crate::pages::thread::ThreadPage`] for that topic. All data is
//! sourced from the shared [`crate::stores::channels::ChannelStore`]; this
//! component performs the topic/reply classification locally and adds no relay
//! subscriptions of its own.

use std::collections::HashMap;

use leptos::prelude::*;
use leptos_router::components::A;
use nostr_bbs_core::NostrEvent;

use crate::app::base_href;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::user_display::use_display_name_memo;
use crate::utils::format_relative_time;
use crate::utils::slug_hash::{section_slug, topic_slug};

/// A single topic (kind-42 root) plus its derived thread stats.
#[derive(Clone, Debug)]
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
/// - A **reply** is any kind-42/kind-1111 that has a [`reply_parent`] (a
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
    for ev in events {
        if ev.kind != 42 && ev.kind != 1111 {
            continue;
        }
        let parent = match reply_parent(ev, &cid_lower) {
            Some(p) => p,
            None => continue, // a root (or unanchored) — not a reply
        };
        // Match the parent against a known root (case-insensitive keys).
        if let Some((_, summary)) = roots.iter_mut().find(|(k, _)| k.to_lowercase() == parent) {
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
    out.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
    out
}

/// Render the section as a list of topic rows.
#[component]
pub fn TopicList(
    /// The resolved kind-40 channel id of the section.
    #[prop(into)]
    channel_id: String,
    /// The zone (category) slug for building topic hrefs (readable).
    #[prop(into)]
    category: String,
    /// Reactive topic summaries, newest-activity first.
    topics: Signal<Vec<TopicSummary>>,
) -> impl IntoView {
    let section_hash = section_slug(&channel_id);
    let category = StoredValue::new(category);
    let section_hash = StoredValue::new(section_hash);

    view! {
        <div class="space-y-2">
            {move || {
                let rows = topics.get();
                if rows.is_empty() {
                    view! {
                        <div class="flex flex-col items-center justify-center py-16 text-center">
                            <div class="w-14 h-14 rounded-full bg-gray-800 flex items-center justify-center mb-4 animate-gentle-float">
                                <svg class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <h3 class="text-white font-semibold mb-1">"No topics yet"</h3>
                            <p class="text-gray-500 text-sm">"Start the first topic in this section."</p>
                        </div>
                    }.into_any()
                } else {
                    rows.into_iter().map(|t| {
                        let href = base_href(&format!(
                            "/forums/{}/{}/{}",
                            category.get_value(),
                            section_hash.get_value(),
                            topic_slug(&t.id),
                        ));
                        view! { <TopicRow topic=t href=href /> }
                    }).collect_view().into_any()
                }
            }}
        </div>
    }
}

/// A single topic row: title line, author, reply count, last-activity.
#[component]
fn TopicRow(topic: TopicSummary, href: String) -> impl IntoView {
    let author_name = use_display_name_memo(topic.pubkey.clone());
    let last_name = use_display_name_memo(topic.last_pubkey.clone());
    let title = topic_title(&topic.content);
    let reply_count = topic.reply_count;
    let reply_label = if reply_count == 1 {
        "1 reply".to_string()
    } else {
        format!("{reply_count} replies")
    };
    let activity = format_relative_time(topic.last_activity);
    let has_replies = reply_count > 0;
    let pk = topic.pubkey.clone();

    view! {
        <A href=href attr:class="block bg-gray-800/60 hover:bg-gray-800 border border-gray-700/60 hover:border-amber-500/30 rounded-lg p-4 no-underline text-inherit transition-colors group">
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 mt-0.5">
                    <Avatar pubkey=pk size=AvatarSize::Md />
                </div>
                <div class="flex-1 min-w-0">
                    <h3 class="font-semibold text-white group-hover:text-amber-400 transition-colors line-clamp-1">
                        {title}
                    </h3>
                    <div class="flex items-center gap-2 mt-1 text-xs text-gray-500 flex-wrap">
                        <span>"by "</span>
                        <span class="text-gray-400">{move || author_name.get()}</span>
                        <span class="text-gray-700">"\u{2022}"</span>
                        <span class="flex items-center gap-1">
                            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {reply_label}
                        </span>
                    </div>
                </div>
                <div class="flex-shrink-0 text-right text-xs text-gray-500">
                    <div class="flex items-center gap-1 justify-end">
                        <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12 6 12 12 16 14"/>
                        </svg>
                        {activity}
                    </div>
                    {has_replies.then(|| view! {
                        <div class="mt-1 text-gray-600">
                            "last: "<span class="text-gray-400">{move || last_name.get()}</span>
                        </div>
                    })}
                </div>
            </div>
        </A>
    }
}

/// Derive a one-line topic title from the root post content.
///
/// Uses the first non-empty line, trimmed and clipped to a sane length so the
/// list stays scannable. Falls back to a placeholder for empty content.
fn topic_title(content: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, pk: &str, content: &str, ts: u64, kind: u64, tags: Vec<Vec<&str>>) -> NostrEvent {
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
            ev(t1, "alice", "First topic", 100, 42, vec![vec!["e", cid, "", "root"]]),
            ev(t2, "bob", "Second topic", 110, 42, vec![vec!["e", cid, "", "root"]]),
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
            ev("c1", "dave", "comment", 150, 1111, vec![vec!["E", t2, "", "root"], vec!["e", t2]]),
            // A legacy reply whose only e-tag is the parent root id (no marker).
            ev("c2", "erin", "legacy reply", 120, 42, vec![vec!["e", t1]]),
        ];

        let topics = classify_topics(cid, &events);
        assert_eq!(topics.len(), 2, "exactly two topic roots (replies excluded)");

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
    fn title_is_first_line_clipped() {
        assert_eq!(topic_title("Hello world\nrest"), "Hello world");
        assert_eq!(topic_title("   \n\n  Trimmed  \n"), "Trimmed");
        assert_eq!(topic_title(""), "(untitled topic)");
        let long: String = "x".repeat(200);
        assert!(topic_title(&long).ends_with('\u{2026}'));
    }
}
