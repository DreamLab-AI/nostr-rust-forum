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

use std::collections::HashMap;

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;
use crate::components::agent_badge::AgentBadge;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::copy_key::KeyName;
use crate::utils::format_relative_time;
use crate::utils::section_url::topic_path;

// The topic model is shared with the BBS client (client-core `topics`).
pub use crate::topics::{classify_topics, topic_title, with_topic_stats, TopicSummary};

/// Render the section as a list of topic rows.
///
/// Rows are keyed by topic id alone and listed in `order`, which the page
/// keeps stable once it has painted (client-core
/// [`stable_order`](crate::topics::stable_order)): a stats answer or a
/// decrypted title updates a row in place, it never rebuilds or moves it.
#[component]
pub fn TopicList(
    /// The resolved kind-40 channel id of the section.
    #[prop(into)]
    channel_id: String,
    /// The zone (category) slug for building topic hrefs (readable).
    #[prop(into)]
    category: String,
    /// Topic ids in display order.
    order: Signal<Vec<String>>,
    /// Every listed topic by id; each row reads its own entry.
    topics: Memo<HashMap<String, TopicSummary>>,
) -> impl IntoView {
    let category = StoredValue::new(category);
    let channel_id = StoredValue::new(channel_id);

    // The outer view tracks only EMPTINESS, so it re-renders when the list
    // becomes empty or non-empty, never per change: re-running it per change
    // built a fresh <For> and re-rendered every row on each page of history.
    let is_empty = Memo::new(move |_| order.with(Vec::is_empty));

    view! {
        <div class="space-y-2">
            {move || {
                if is_empty.try_get().unwrap_or(false) {
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
                    view! {
                        <For
                            each=move || order.try_get().unwrap_or_default()
                            key=|id| id.clone()
                            children=move |id| {
                                let href = base_href(&topic_path(
                                    &category.get_value(),
                                    &channel_id.get_value(),
                                    &id,
                                ));
                                view! { <TopicRow id=id topics=topics href=href /> }
                            }
                        />
                    }.into_any()
                }
            }}
        </div>
    }
}

/// Skeleton rows shown while a section's topics load: the same row frame,
/// column classes and line heights as [`TopicRow`], so the list does not
/// change height when the real rows replace them.
#[component]
pub fn TopicListSkeleton(
    /// What is being waited for, for screen readers (and shown when
    /// `visible_status`).
    #[prop(into)]
    status: String,
    /// Show `status` as a line above the rows (the zone-key wait, which can
    /// take a while), rather than to screen readers only.
    #[prop(optional)]
    visible_status: bool,
) -> impl IntoView {
    view! {
        <div class="space-y-2" role="status" aria-busy="true" data-topic-skeleton="">
            <p class=if visible_status { SKELETON_STATUS_CLASS } else { "sr-only" }>{status}</p>
            {(0..SKELETON_ROWS).map(|_| view! {
                <div class=ROW_CLASS aria-hidden="true">
                    <div class=ROW_INNER_CLASS>
                        <div class=AVATAR_SLOT_CLASS>
                            <div class=SKELETON_AVATAR_CLASS></div>
                        </div>
                        <div class=LEFT_COLUMN_CLASS>
                            <h3 class=TITLE_CLASS>
                                <span class=SKELETON_TITLE_CLASS>"\u{00a0}"</span>
                            </h3>
                            <div class=BYLINE_ROW_CLASS>
                                <span class=SKELETON_BYLINE_CLASS></span>
                            </div>
                        </div>
                        <div class=RIGHT_COLUMN_CLASS>
                            <div class=ACTIVITY_LINE_CLASS>
                                <span class=SKELETON_ACTIVITY_CLASS></span>
                            </div>
                            <div class=STARTED_BY_CLASS></div>
                        </div>
                    </div>
                </div>
            }).collect_view()}
        </div>
    }
}

/// Skeleton rows: enough to fill a first screen.
const SKELETON_ROWS: usize = 6;

/// Narrow screens (below `sm`) restack the row: the left column takes the
/// whole width, the title may wrap to two lines, and the byline reads
/// `last by {name} {pill} • N replies • {time} ago`; the right-hand column
/// (activity over "started by") is hidden. From `sm` up the two-column layout
/// is unchanged. Literal class strings, so the Tailwind scan sees them.
///
/// Every line of a row has a fixed height, so fields that arrive late (the
/// relay's reply total and newest reply, a decrypted title, an agent pill)
/// never change the row's height.
///
/// The row frame ("stretched link" card).
const ROW_CLASS: &str =
    "relative block bg-gray-800/60 hover:bg-gray-800 border border-gray-700/60 \
     hover:border-amber-500/30 rounded-lg p-4 text-inherit transition-colors group";
/// The row's three columns: avatar, title and byline, right-hand column.
const ROW_INNER_CLASS: &str = "flex items-start gap-3";
/// The avatar's slot (`AvatarSize::Md`, 36 px).
const AVATAR_SLOT_CLASS: &str = "flex-shrink-0 mt-0.5";
/// Title and byline.
const LEFT_COLUMN_CLASS: &str = "flex-1 min-w-0";
/// The row under a topic title. One non-wrapping flex row of fixed height,
/// so an agent pill never makes a row taller than one without.
const BYLINE_ROW_CLASS: &str =
    "flex flex-nowrap items-center gap-2 mt-1 h-4 text-xs text-gray-500 min-w-0";
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
/// The topic title: up to two lines on a phone, one from `sm`. On a phone
/// it always takes two lines' height (`text-base` is 1.5rem a line), so a
/// long encrypted-zone placeholder that decrypts to a short title, or the
/// reverse, does not change the row's height.
const TITLE_CLASS: &str = "font-semibold text-white group-hover:text-amber-400 \
     transition-colors line-clamp-2 min-h-[3rem] sm:line-clamp-1 sm:min-h-0";
/// `• {time} ago` inside the byline, on a phone only (from `sm` the time is
/// in the right-hand column).
const BYLINE_ACTIVITY_CLASS: &str = "flex-shrink-0 whitespace-nowrap sm:hidden";
/// The right-hand column (activity over "started by"): hidden below `sm`,
/// where "started by" is the least useful field.
const RIGHT_COLUMN_CLASS: &str = "hidden sm:block flex-shrink-0 text-right text-xs text-gray-500";
/// The activity line of the right-hand column.
const ACTIVITY_LINE_CLASS: &str = "flex items-center gap-1 justify-end h-4 whitespace-nowrap";
/// The "started by" line: always present and of fixed height, empty when the
/// starter spoke last, so the reply that names someone else does not add a
/// line.
const STARTED_BY_CLASS: &str =
    "mt-1 h-4 text-gray-600 flex items-center gap-1 justify-end whitespace-nowrap";
/// The reply count keeps its width.
const REPLIES_CLASS: &str = "flex items-center gap-1 flex-shrink-0 whitespace-nowrap";
/// Status line above skeleton rows, when shown.
const SKELETON_STATUS_CLASS: &str = "text-gray-400 text-sm";
/// Skeleton avatar: the size of `AvatarSize::Md`.
const SKELETON_AVATAR_CLASS: &str = "w-9 h-9 rounded-full bg-gray-700/60 animate-pulse";
/// Skeleton title bar: a non-breaking space in a title line, so its height
/// is the title's line height.
const SKELETON_TITLE_CLASS: &str = "inline-block w-2/3 rounded bg-gray-700/60 animate-pulse";
/// Skeleton byline bar.
const SKELETON_BYLINE_CLASS: &str = "block w-1/2 h-3 rounded bg-gray-700/40 animate-pulse";
/// Skeleton activity bar.
const SKELETON_ACTIVITY_CLASS: &str = "block w-12 h-3 rounded bg-gray-700/40 animate-pulse";

/// A single topic row: title line, latest participant, reply count,
/// last-activity.
///
/// The byline and avatar name the MOST RECENT participant, not the root
/// author: a reader scanning the list wants to know who spoke last before
/// opening the topic. `last_pubkey` already falls back to the root author
/// when there are no replies, and the root author shows in the right-hand
/// column ("started by") only when the two differ.
///
/// The row reads its topic from `topics` by id, and each field through its
/// own memo, so a stats answer re-renders the reply count and time, and a
/// new last poster re-renders the avatar and name, without rebuilding the
/// rest of the row.
#[component]
fn TopicRow(
    id: String,
    topics: Memo<HashMap<String, TopicSummary>>,
    href: String,
) -> impl IntoView {
    let anchor_id = id.clone();
    // A topic briefly missing from the map (the row is about to go) keeps
    // showing what it showed. `try_with`: see `history_loader::read_cursor`.
    let topic = Memo::new(move |prev: Option<&Option<TopicSummary>>| {
        topics
            .try_with(|m| m.get(&id).cloned())
            .flatten()
            .or_else(|| prev.cloned().flatten())
    });
    let field = move |f: fn(&TopicSummary) -> String| {
        Memo::new(move |_| {
            topic
                .try_with(|t| t.as_ref().map(f))
                .flatten()
                .unwrap_or_default()
        })
    };
    let title = field(|t| topic_title(&t.content));
    let last_pk = field(|t| t.last_pubkey.clone());
    let author_pk = field(|t| t.pubkey.clone());
    let reply_label = field(|t| replies_label(t.reply_count));
    let activity = field(|t| format_relative_time(t.last_activity));
    let started_by_someone_else = Memo::new(move |_| {
        topic
            .try_with(|t| {
                t.as_ref()
                    .is_some_and(|t| t.reply_count > 0 && t.last_pubkey != t.pubkey)
            })
            .unwrap_or(false)
    });

    // "Stretched link" card: the title link's `::after` covers the whole card,
    // so the card stays one click target, while an author's abridged key (no
    // profile name) sits above that overlay as its own click-to-copy button —
    // never a button nested inside a link.
    // Scroll anchor for history paging (utils/scroll_anchor.rs).
    view! {
        <div data-anchor-id=anchor_id class=ROW_CLASS>
            <div class=ROW_INNER_CLASS>
                <div class=AVATAR_SLOT_CLASS>
                    {move || view! { <Avatar pubkey=last_pk.try_get().unwrap_or_default() size=AvatarSize::Md /> }}
                </div>
                <div class=LEFT_COLUMN_CLASS>
                    <h3 class=TITLE_CLASS>
                        <A href=href attr:class="no-underline text-inherit after:absolute after:inset-0 after:rounded-lg">
                            {move || title.try_get().unwrap_or_default()}
                        </A>
                    </h3>
                    <div class=BYLINE_ROW_CLASS>
                        <span class=LAST_BY_CLASS>
                            <span class=LAST_BY_LABEL_CLASS>"last by"</span>
                            {move || {
                                let pk = last_pk.try_get().unwrap_or_default();
                                view! {
                                    <span class=LAST_BY_NAME_CLASS><KeyName pubkey=pk.clone() key_class="relative z-10 font-mono" /></span>
                                    <span class=LAST_BY_PILL_CLASS><AgentBadge pubkey=pk compact=true /></span>
                                }
                            }}
                        </span>
                        <span class="text-gray-700 flex-shrink-0">"\u{2022}"</span>
                        <span class=REPLIES_CLASS>
                            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {move || reply_label.try_get().unwrap_or_default()}
                        </span>
                        <span class=BYLINE_ACTIVITY_CLASS>
                            <span class="text-gray-700">"\u{2022} "</span>
                            {move || activity.try_get().unwrap_or_default()}
                        </span>
                    </div>
                </div>
                <div class=RIGHT_COLUMN_CLASS>
                    <div class=ACTIVITY_LINE_CLASS>
                        <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12 6 12 12 16 14"/>
                        </svg>
                        {move || activity.try_get().unwrap_or_default()}
                    </div>
                    <div class=STARTED_BY_CLASS>
                        {move || started_by_someone_else.try_get().unwrap_or(false).then(|| {
                            let pk = author_pk.try_get().unwrap_or_default();
                            view! {
                                "started by "<span class="text-gray-400"><KeyName pubkey=pk.clone() key_class="relative z-10 font-mono" /></span>
                                <AgentBadge pubkey=pk compact=true />
                            }
                        })}
                    </div>
                </div>
            </div>
        </div>
    }
}

/// "1 reply" / "N replies".
fn replies_label(n: u32) -> String {
    if n == 1 {
        "1 reply".to_string()
    } else {
        format!("{n} replies")
    }
}

/// The "↻ N updated" control beside the topic count: always laid out (and
/// made `invisible` at zero), so its appearing never moves the list.
pub(crate) const UPDATED_CLASS: &str = "inline-block ml-2 mt-2 text-xs whitespace-nowrap \
     za-text hover:opacity-80 underline underline-offset-2";

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

    #[test]
    fn late_fields_never_change_a_row_height() {
        // Every line of the row has a fixed height: the byline, the activity
        // line and the "started by" line (always present, empty when the
        // starter spoke last).
        for line in [BYLINE_ROW_CLASS, ACTIVITY_LINE_CLASS, STARTED_BY_CLASS] {
            assert!(classes(line).contains(&"h-4"), "{line}");
        }
        assert!(classes(STARTED_BY_CLASS).contains(&"whitespace-nowrap"));
        // On a phone the title always takes two lines' height (text-base,
        // 1.5rem a line); from `sm` it is one line.
        let title = classes(TITLE_CLASS);
        assert!(title.contains(&"min-h-[3rem]") && title.contains(&"sm:min-h-0"));
    }

    #[test]
    fn skeleton_rows_are_built_like_real_rows() {
        // The skeleton uses the row's own frame and line classes, so a real
        // row replacing it has the same height; its avatar is Md (36 px).
        assert!(classes(SKELETON_AVATAR_CLASS).contains(&"w-9"));
        assert!(classes(SKELETON_AVATAR_CLASS).contains(&"h-9"));
        // The title bar holds a non-breaking space: one title line high.
        assert!(classes(SKELETON_TITLE_CLASS).contains(&"inline-block"));
        assert!(SKELETON_ROWS >= 4);
    }

    #[test]
    fn updated_control_holds_its_place() {
        let c = classes(UPDATED_CLASS);
        assert!(c.contains(&"inline-block") && c.contains(&"whitespace-nowrap"));
        assert!(!c.contains(&"block") && !c.contains(&"flex"));
    }

    #[test]
    fn reply_labels() {
        assert_eq!(replies_label(0), "0 replies");
        assert_eq!(replies_label(1), "1 reply");
        assert_eq!(replies_label(24_013), "24013 replies");
    }
}
