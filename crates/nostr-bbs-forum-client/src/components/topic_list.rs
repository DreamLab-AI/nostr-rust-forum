//! Topic-list view for a BBS section (#8).
//!
//! A *section* is a kind-40 channel. A *topic* is a kind-42 ROOT message inside
//! it (a thread starter) — its e-tags reference the channel id as the root and
//! it is not itself a reply to another in-channel message. A *reply* is a
//! kind-42 (or NIP-22 kind-1111) event that e-tags a topic root.
//!
//! This component renders the section as a LIST OF TOPICS (title/first line,
//! author, reply count, last activity) — NOT a flat linear chat. Each row links
//! to the [`crate::pages::ThreadPage`] for that topic. All data is
//! sourced from the shared [`crate::stores::channels::ChannelStore`]; the
//! topic/reply classification is client-core's [`crate::topics`], shared with
//! the BBS client, and this component adds no relay subscriptions of its own.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;
use crate::components::agent_badge::AgentBadge;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::copy_key::KeyName;
use crate::utils::format_relative_time;
use crate::utils::slug_hash::{section_slug, topic_slug};

// The topic model is shared with the BBS client (client-core `topics`).
pub use crate::topics::{classify_topics, topic_title, with_topic_stats, TopicSummary};

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

    // The outer view tracks only EMPTINESS, so it re-renders when the list
    // becomes empty or non-empty, never per change: re-running it per change
    // built a fresh <For> and re-rendered every row on each page of history.
    let is_empty = Memo::new(move |_| topics.with(Vec::is_empty));

    view! {
        <div class="space-y-2">
            {move || {
                if is_empty.get() {
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
                    // Keyed: a page of older topics renders only its own
                    // rows; a row re-renders when what it shows changes.
                    view! {
                        <For
                            each=move || topics.get()
                            key=|t| (t.id.clone(), t.reply_count, t.last_activity, t.content.len(), t.last_pubkey.clone())
                            children=move |t| {
                                let href = base_href(&format!(
                                    "/forums/{}/{}/{}",
                                    category.get_value(),
                                    section_hash.get_value(),
                                    topic_slug(&t.id),
                                ));
                                view! { <TopicRow topic=t href=href /> }
                            }
                        />
                    }.into_any()
                }
            }}
        </div>
    }
}

/// Narrow screens (below `sm`) restack the row: the left column takes the
/// whole width, the title may wrap to two lines, and the byline reads
/// `last by {name} {pill} • N replies • {time} ago`; the right-hand column
/// (activity over "started by") is hidden. From `sm` up the two-column layout
/// is unchanged. Literal class strings, so the Tailwind scan sees them.
///
/// The row under a topic title. One non-wrapping flex row, so an agent pill
/// never makes a row taller than one without.
const BYLINE_ROW_CLASS: &str =
    "flex flex-nowrap items-center gap-2 mt-1 text-xs text-gray-500 min-w-0";
/// "last by", name and pill: the part of the byline that gives way.
const LAST_BY_CLASS: &str =
    "flex flex-1 items-center gap-1 min-w-0 overflow-hidden whitespace-nowrap";
/// The "last by" words never shrink.
const LAST_BY_LABEL_CLASS: &str = "flex-shrink-0";
/// The last poster's name truncates, but only once the pill has given way.
const LAST_BY_NAME_CLASS: &str = "text-gray-400 min-w-0 truncate";
/// Wrapper of the agent pill (`AgentBadge` renders `<span title><Badge/></span>`
/// plus a copy glyph). It shrinks a hundred times faster than the name, so it
/// truncates first. The pill's text sits in an `inline-flex` span, where
/// `text-overflow` does nothing, so its span becomes a truncating block; the
/// copy glyph keeps its size.
const LAST_BY_PILL_CLASS: &str = "flex items-center gap-1 min-w-0 shrink-[100] overflow-hidden \
     [&>span]:min-w-0 [&>span>span]:block [&>span>span]:truncate [&>button]:flex-shrink-0";
/// The topic title: up to two lines on a phone, one from `sm`.
const TITLE_CLASS: &str = "font-semibold text-white group-hover:text-amber-400 \
     transition-colors line-clamp-2 sm:line-clamp-1";
/// `• {time} ago` inside the byline, on a phone only (from `sm` the time is
/// in the right-hand column).
const BYLINE_ACTIVITY_CLASS: &str = "flex-shrink-0 whitespace-nowrap sm:hidden";
/// The right-hand column (activity over "started by"): hidden below `sm`,
/// where "started by" is the least useful field.
const RIGHT_COLUMN_CLASS: &str = "hidden sm:block flex-shrink-0 text-right text-xs text-gray-500";
/// The reply count keeps its width.
const REPLIES_CLASS: &str = "flex items-center gap-1 flex-shrink-0 whitespace-nowrap";

/// A single topic row: title line, latest participant, reply count,
/// last-activity.
///
/// The byline and avatar name the MOST RECENT participant, not the root
/// author: a reader scanning the list wants to know who spoke last before
/// opening the topic. `last_pubkey` already falls back to the root author
/// when there are no replies, and the root author moves to the right-hand
/// column ("started by") only when the two differ.
#[component]
fn TopicRow(topic: TopicSummary, href: String) -> impl IntoView {
    let author_pk = topic.pubkey.clone();
    let last_pk = topic.last_pubkey.clone();
    // Disclosure badges (COM-13/F2): mark the topic's root author and the
    // most-recent participant as agents, naming their authorising principals.
    let root_badge_pubkey = topic.pubkey.clone();
    let last_badge_pubkey = topic.last_pubkey.clone();
    let title = topic_title(&topic.content);
    let reply_count = topic.reply_count;
    let reply_label = if reply_count == 1 {
        "1 reply".to_string()
    } else {
        format!("{reply_count} replies")
    };
    let activity = format_relative_time(topic.last_activity);
    let started_by_someone_else = reply_count > 0 && topic.last_pubkey != topic.pubkey;
    let pk = topic.last_pubkey.clone();

    // "Stretched link" card: the title link's `::after` covers the whole card,
    // so the card stays one click target, while an author's abridged key (no
    // profile name) sits above that overlay as its own click-to-copy button —
    // never a button nested inside a link.
    // Scroll anchor for history paging (utils/scroll_anchor.rs).
    let anchor_id = topic.id.clone();
    view! {
        <div data-anchor-id=anchor_id class="relative block bg-gray-800/60 hover:bg-gray-800 border border-gray-700/60 hover:border-amber-500/30 rounded-lg p-4 text-inherit transition-colors group">
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 mt-0.5">
                    <Avatar pubkey=pk size=AvatarSize::Md />
                </div>
                <div class="flex-1 min-w-0">
                    <h3 class=TITLE_CLASS>
                        <A href=href attr:class="no-underline text-inherit after:absolute after:inset-0 after:rounded-lg">
                            {title}
                        </A>
                    </h3>
                    <div class=BYLINE_ROW_CLASS>
                        <span class=LAST_BY_CLASS>
                            <span class=LAST_BY_LABEL_CLASS>"last by"</span>
                            <span class=LAST_BY_NAME_CLASS><KeyName pubkey=last_pk key_class="relative z-10 font-mono" /></span>
                            <span class=LAST_BY_PILL_CLASS><AgentBadge pubkey=last_badge_pubkey compact=true /></span>
                        </span>
                        <span class="text-gray-700 flex-shrink-0">"\u{2022}"</span>
                        <span class=REPLIES_CLASS>
                            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {reply_label}
                        </span>
                        <span class=BYLINE_ACTIVITY_CLASS>
                            <span class="text-gray-700">"\u{2022} "</span>
                            {activity.clone()}
                        </span>
                    </div>
                </div>
                <div class=RIGHT_COLUMN_CLASS>
                    <div class="flex items-center gap-1 justify-end">
                        <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12 6 12 12 16 14"/>
                        </svg>
                        {activity}
                    </div>
                    {started_by_someone_else.then(|| view! {
                        <div class="mt-1 text-gray-600 flex items-center gap-1 justify-end">
                            "started by "<span class="text-gray-400"><KeyName pubkey=author_pk key_class="relative z-10 font-mono" /></span>
                            <AgentBadge pubkey=root_badge_pubkey compact=true />
                        </div>
                    })}
                </div>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(c: &str) -> Vec<&str> {
        c.split_whitespace().collect()
    }

    #[test]
    fn byline_is_one_row_that_never_wraps() {
        // At 390 px a wrapping byline put "last by", the name, the agent pill,
        // its glyph and the dot on separate lines. One non-wrapping row whose
        // children may shrink keeps a badged row as tall as an unbadged one.
        let row = classes(BYLINE_ROW_CLASS);
        assert!(row.contains(&"flex") && row.contains(&"flex-nowrap"));
        assert!(!row.contains(&"flex-wrap"));
        assert!(row.contains(&"min-w-0"));
        let who = classes(LAST_BY_CLASS);
        assert!(who.contains(&"min-w-0") && who.contains(&"overflow-hidden"));
        assert!(classes(LAST_BY_LABEL_CLASS).contains(&"flex-shrink-0"));
        assert!(classes(LAST_BY_NAME_CLASS).contains(&"truncate"));
        let pill = classes(LAST_BY_PILL_CLASS);
        assert!(pill.contains(&"min-w-0") && pill.contains(&"overflow-hidden"));
        // The pill's text sits in an inline-flex span, where `text-overflow`
        // does nothing: the wrapper turns that span into a truncating block.
        assert!(pill.contains(&"[&>span>span]:truncate"));
        assert!(classes(REPLIES_CLASS).contains(&"flex-shrink-0"));
    }

    #[test]
    fn narrow_rows_restack_into_the_left_column() {
        // Staging at 390 px: the right-hand column kept its full width and
        // crushed the byline to "la". Below `sm` the left column takes the
        // whole row; from `sm` up the two-column layout stays.
        let right = classes(RIGHT_COLUMN_CLASS);
        assert!(right.contains(&"hidden") && right.contains(&"sm:block"));
        // Title: up to two lines on a phone, one line from `sm`.
        let title = classes(TITLE_CLASS);
        assert!(title.contains(&"line-clamp-2") && title.contains(&"sm:line-clamp-1"));
        assert!(!title.contains(&"line-clamp-1"));
        // The activity time moves into the byline on a phone only.
        let time = classes(BYLINE_ACTIVITY_CLASS);
        assert!(time.contains(&"sm:hidden") && time.contains(&"flex-shrink-0"));
        assert!(time.contains(&"whitespace-nowrap"));
        // The agent pill gives way long before the name does.
        assert!(classes(LAST_BY_PILL_CLASS).contains(&"shrink-[100]"));
        assert!(!classes(LAST_BY_NAME_CLASS).contains(&"shrink-[100]"));
        assert!(classes(LAST_BY_CLASS).contains(&"flex-1"));
    }
}
