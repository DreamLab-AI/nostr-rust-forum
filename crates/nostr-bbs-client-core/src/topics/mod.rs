//! The forum's topic model, shared by the modern forum and the BBS client so
//! both list the same topics and show the same posts.
//!
//! - [`board`]: a section channel as topics, newest activity first, with
//!   reply counts and last posters.
//! - [`thread`]: one topic's replies, edits and quotes, and the tags a reply
//!   or edit carries.
//! - [`landing`]: opening a topic at its newest (or a linked) post.
//! - [`jump`]: resolving a link to one post to the topic that holds it.

pub mod board;
pub mod jump;
pub mod landing;
pub mod thread;

pub use board::{
    board_events, board_order, classify_topics, first_paint_ready, first_row_in_full_view,
    latest_post, older_paging_armed, out_of_order, sealed_aliases, stable_order, topic_title,
    unread_count, updated_accessible_name, updated_label, with_topic_stats, TopicSummary,
    FIRST_PAINT_STATS, FIRST_PAINT_TIMEOUT_MS,
};
pub use jump::{channel_events_across, fallback, find_held, parent_of, topic_root_of, Fallback};
pub use landing::{history_settled, landing_target, post_anchor_id, Landing};
pub use thread::{
    edit_tags, edit_target, edit_target_of, find_topic_root, first_line, latest_version,
    quoted_e_tag, root_e_tag, thread_events, thread_replies, topic_reply_tags, topic_root_tags,
    view_key, QuotedRef, ReplyView, EDIT_MARKER, QUOTE_MARKER,
};
