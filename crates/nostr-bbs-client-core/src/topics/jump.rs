//! Resolving a link to one post (`/go/<id>?c=<channel>` in the forum, its
//! BBS equivalent) to the topic that holds it.
//!
//! A reply may sit several hops below its topic root (a reply to a reply, an
//! edit of a post), and in an encrypted zone the relay knows only the
//! sealed envelope, so the post is looked up among the store's decrypted
//! lists and its reply chain walked to the root. Shared by the forum's jump
//! page and the BBS's.

use std::collections::HashMap;

use nostr_bbs_core::NostrEvent;

use crate::utils::post_link::channel_of;

/// Give up waiting for the post's topic to resolve after this long.
pub const RESOLVE_TIMEOUT_MS: i32 = 6_000;

/// With a channel hint whose history is still loading, keep waiting up to
/// this long before giving up.
pub const HINTED_RESOLVE_CEILING_MS: f64 = 20_000.0;

/// The event with id `id` in any list of the channel store (channel lists,
/// `topic:` and `roots:` lists), case-insensitively.
pub fn find_held<'a>(
    id: &str,
    lists: &'a HashMap<String, Vec<NostrEvent>>,
) -> Option<&'a NostrEvent> {
    lists
        .values()
        .flat_map(|v| v.iter())
        .find(|e| e.id.eq_ignore_ascii_case(id))
}

/// Every held event of channel `cid` (by its own channel tag, whatever list
/// holds it), deduplicated by id: the reply chain of a post can sit partly in
/// the channel list and partly in its topic's list.
pub fn channel_events_across(
    cid: &str,
    lists: &HashMap<String, Vec<NostrEvent>>,
) -> Vec<NostrEvent> {
    let mut seen = std::collections::HashSet::new();
    lists
        .values()
        .flat_map(|v| v.iter())
        .filter(|e| channel_of(e).is_some_and(|c| c.eq_ignore_ascii_case(cid)))
        .filter(|e| seen.insert(e.id.to_ascii_lowercase()))
        .cloned()
        .collect()
}

/// What the jump page does when it has not resolved the post yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// Keep waiting.
    Wait,
    /// Show the single-note view (`/view/<id>`).
    NoteView,
    /// Land on the channel's topic list (the value is the channel id).
    Channel(String),
    /// Open the topic the post names as its root, focused on the post (the
    /// value is the caller's `topic` argument as given).
    Topic(String),
}

/// The give-up decision, `elapsed_ms` after the fetch started. Waits
/// [`RESOLVE_TIMEOUT_MS`], or up to [`HINTED_RESOLVE_CEILING_MS`] while a
/// hinted channel's history is still loading (`hint_loading`). Then: the
/// topic the held post names as its root, when known (`topic`, a topic URL
/// focused on the post); else the note view when the relay delivered the
/// post itself (`relay_has_it`, a plaintext post the note view can show);
/// else the channel's topic list when the channel is known; else the note
/// view. Blank values count as unknown.
pub fn fallback(
    elapsed_ms: f64,
    hint_loading: bool,
    relay_has_it: bool,
    topic: Option<&str>,
    channel: Option<&str>,
) -> Fallback {
    if elapsed_ms < f64::from(RESOLVE_TIMEOUT_MS)
        || (hint_loading && elapsed_ms < HINTED_RESOLVE_CEILING_MS)
    {
        return Fallback::Wait;
    }
    fn known(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|v| !v.is_empty())
    }
    if let Some(t) = known(topic) {
        return Fallback::Topic(t.to_string());
    }
    match known(channel) {
        Some(c) if !relay_has_it => Fallback::Channel(c.to_string()),
        _ => Fallback::NoteView,
    }
}

/// Marker (4th element) of an `e` tag, if any.
fn marker(tag: &[String]) -> Option<&str> {
    tag.get(3).map(String::as_str).filter(|m| !m.is_empty())
}

/// The message this one replies to, or `None` for a topic root.
///
/// NIP-10 marked form: the `reply` marker. Legacy positional form (no
/// markers): the last unmarked `e` tag that is not the channel. `quote`,
/// `edit` and `mention` markers are never parents.
pub fn parent_of(ev: &NostrEvent, channel_id: &str) -> Option<String> {
    let e_tags: Vec<&Vec<String>> = ev
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "e")
        .collect();
    if let Some(t) = e_tags.iter().find(|t| marker(t) == Some("reply")) {
        return (!t[1].eq_ignore_ascii_case(channel_id)).then(|| t[1].clone());
    }
    if e_tags.iter().any(|t| marker(t).is_some()) {
        return None;
    }
    e_tags
        .iter()
        .rev()
        .find(|t| !t[1].eq_ignore_ascii_case(channel_id))
        .map(|t| t[1].clone())
}

/// Walk from `start_id` up the reply chain within `events` to the topic root.
///
/// Returns the root id, or `None` while an ancestor is missing from `events`
/// (the caller retries as more history streams in). Cycles and absurd depth
/// are cut off.
pub fn topic_root_of(start_id: &str, channel_id: &str, events: &[NostrEvent]) -> Option<String> {
    let find = |id: &str| events.iter().find(|e| e.id.eq_ignore_ascii_case(id));
    let mut current = find(start_id)?;
    for _ in 0..64 {
        match parent_of(current, channel_id) {
            None => return Some(current.id.clone()),
            Some(parent) => current = find(&parent)?,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topics::thread::edit_target_of;

    fn ev(id: &str, tags: Vec<Vec<&str>>) -> NostrEvent {
        NostrEvent {
            id: id.into(),
            pubkey: "pk".into(),
            created_at: 0,
            kind: 42,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: String::new(),
            sig: String::new(),
        }
    }

    fn lists(entries: Vec<(&str, Vec<NostrEvent>)>) -> HashMap<String, Vec<NostrEvent>> {
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    #[test]
    fn decrypted_post_is_found_in_any_list() {
        // A sealed original restored from its envelope carries the
        // original's id; the relay knows only the envelope's. It may sit in
        // its topic's list rather than the channel's.
        let reply = ev(
            "INNER",
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "root", "", "reply"],
            ],
        );
        let m = lists(vec![
            (
                "chan",
                vec![ev("root", vec![vec!["e", "chan", "", "root"]])],
            ),
            ("topic:root", vec![reply]),
        ]);
        assert_eq!(find_held("inner", &m).map(|e| e.id.as_str()), Some("INNER"));
        assert!(find_held("missing", &m).is_none());
    }

    #[test]
    fn reply_chain_is_gathered_across_lists() {
        let root = ev("root", vec![vec!["e", "chan", "", "root"]]);
        let r1 = ev(
            "r1",
            vec![
                vec!["e", "chan", "", "root"],
                vec!["e", "root", "", "reply"],
            ],
        );
        let other = ev("x", vec![vec!["e", "other", "", "root"]]);
        let m = lists(vec![
            ("chan", vec![root.clone()]),
            ("roots:chan", vec![root.clone()]),
            ("topic:root", vec![r1.clone()]),
            ("other", vec![other]),
        ]);
        let events = channel_events_across("chan", &m);
        let mut ids: Vec<&str> = events.iter().map(|e| e.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["r1", "root"], "deduplicated, channel only");
        assert_eq!(topic_root_of("r1", "chan", &events), Some("root".into()));
    }

    #[test]
    fn fallback_waits_then_prefers_the_channel_over_not_found() {
        let early = f64::from(RESOLVE_TIMEOUT_MS) - 1.0;
        let late = f64::from(RESOLVE_TIMEOUT_MS) + 1.0;
        let chan = Some("chan");
        assert_eq!(fallback(early, false, false, None, chan), Fallback::Wait);
        // A hinted channel still loading its history: keep waiting...
        assert_eq!(fallback(late, true, false, None, chan), Fallback::Wait);
        // ...up to the longer ceiling.
        assert_eq!(
            fallback(HINTED_RESOLVE_CEILING_MS + 1.0, true, false, None, chan),
            Fallback::Channel("chan".into())
        );
        // Unresolved but the channel is known: its topic list, never "Not Found".
        assert_eq!(
            fallback(late, false, false, None, chan),
            Fallback::Channel("chan".into())
        );
        // A plaintext post the relay delivered: the note view shows it.
        assert_eq!(fallback(late, false, true, None, chan), Fallback::NoteView);
        // Nothing known at all.
        assert_eq!(fallback(late, false, false, None, None), Fallback::NoteView);
    }

    #[test]
    fn fallback_opens_the_named_topic_when_the_walk_stalls() {
        // The post is held and names its topic root, but the root is older
        // than the loaded history: open that topic, focused on the post.
        let late = f64::from(RESOLVE_TIMEOUT_MS) + 1.0;
        let topic = Some("/forums/z/s/t?focus=p");
        assert_eq!(
            fallback(late, false, false, topic, Some("chan")),
            Fallback::Topic("/forums/z/s/t?focus=p".into())
        );
        assert_eq!(
            fallback(late, false, true, topic, Some("chan")),
            Fallback::Topic("/forums/z/s/t?focus=p".into())
        );
        // Still waits first.
        assert_eq!(
            fallback(late, true, false, topic, Some("chan")),
            Fallback::Wait
        );
    }

    #[test]
    fn fallback_never_navigates_to_an_empty_channel() {
        let late = f64::from(RESOLVE_TIMEOUT_MS) + 1.0;
        assert_eq!(
            fallback(late, false, false, None, Some("")),
            Fallback::NoteView
        );
        assert_eq!(
            fallback(late, false, false, Some(""), Some(" ")),
            Fallback::NoteView
        );
    }

    #[test]
    fn walks_nested_replies_to_topic_root() {
        let events = vec![
            ev("root", vec![vec!["e", "chan", "", "root"]]),
            ev(
                "r1",
                vec![
                    vec!["e", "chan", "", "root"],
                    vec!["e", "root", "", "reply"],
                ],
            ),
            ev(
                "r2",
                vec![vec!["e", "chan", "", "root"], vec!["e", "r1", "", "reply"]],
            ),
        ];
        assert_eq!(topic_root_of("r2", "chan", &events), Some("root".into()));
        assert_eq!(topic_root_of("root", "chan", &events), Some("root".into()));
    }

    #[test]
    fn quotes_are_not_parents_and_missing_ancestor_defers() {
        let events = vec![
            ev("root", vec![vec!["e", "chan", "", "root"]]),
            ev(
                "q",
                vec![
                    vec!["e", "chan", "", "root"],
                    vec!["e", "root", "", "reply"],
                    vec!["e", "sibling", "", "quote"],
                ],
            ),
            ev(
                "orphan",
                vec![
                    vec!["e", "chan", "", "root"],
                    vec!["e", "gone", "", "reply"],
                ],
            ),
        ];
        assert_eq!(topic_root_of("q", "chan", &events), Some("root".into()));
        assert_eq!(topic_root_of("orphan", "chan", &events), None);
    }

    #[test]
    fn legacy_positional_tags() {
        let e = ev("x", vec![vec!["e", "chan"], vec!["e", "parent"]]);
        assert_eq!(parent_of(&e, "chan"), Some("parent".into()));
        let root = ev("y", vec![vec!["e", "chan"]]);
        assert_eq!(parent_of(&root, "chan"), None);
    }

    #[test]
    fn channel_and_edit_target() {
        let e = ev(
            "e",
            vec![vec!["e", "orig", "", "edit"], vec!["e", "chan", "", "root"]],
        );
        assert_eq!(channel_of(&e), Some("chan".into()));
        assert_eq!(edit_target_of(&e), Some("orig".into()));
    }

    #[test]
    fn cycles_terminate() {
        let events = vec![
            ev(
                "a",
                vec![vec!["e", "chan", "", "root"], vec!["e", "b", "", "reply"]],
            ),
            ev(
                "b",
                vec![vec!["e", "chan", "", "root"], vec!["e", "a", "", "reply"]],
            ),
        ];
        assert_eq!(topic_root_of("a", "chan", &events), None);
    }
}
