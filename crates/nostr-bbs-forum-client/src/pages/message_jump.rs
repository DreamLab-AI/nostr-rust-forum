//! Message deep-link resolver.
//!
//! Route: `/go/:event_id`
//!
//! Search results and other "take me to this message" links carry only an
//! event id. The forum renders messages inside a TOPIC page
//! (`/forums/:zone/:section/:topic`), and a reply may sit several hops below
//! the topic root (NIP-10 replies thread under the specific message they answer,
//! and an edit points at the post it replaces). This page fetches the event,
//! tops up its channel's history, walks the reply chain to the topic root, and
//! replaces itself with the topic URL plus `?focus=<id>` so the thread page
//! scrolls to and flashes the target.
//!
//! If the topic cannot be resolved (unscoped channel, withheld parent, relay
//! timeout) it falls back to the single-note view so the reader always lands
//! on the message itself.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map};
use leptos_router::NavigateOptions;
use nostr_bbs_core::NostrEvent;

use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::channels::use_channel_store;
use crate::stores::zones::{load_zones, section_to_zone, zone_path_for_id};
use crate::utils::set_timeout_once;
use crate::utils::slug_hash::{section_slug, topic_slug};

/// Give up on resolving the topic after this long and show the note view.
const RESOLVE_TIMEOUT_MS: i32 = 6_000;

/// Marker (4th element) of an `e` tag, if any.
fn marker(tag: &[String]) -> Option<&str> {
    tag.get(3).map(String::as_str).filter(|m| !m.is_empty())
}

/// The post this kind-42 is an edit of (`["e", id, "", "edit"]`).
pub(crate) fn edit_target_of(ev: &NostrEvent) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "edit")
        .map(|t| t[1].clone())
}

/// Channel id of a kind-42: the `root`-marked `e` tag, else the first `e`.
pub(crate) fn channel_of(ev: &NostrEvent) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
        .or_else(|| ev.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
        .map(|t| t[1].clone())
}

/// The message this one replies to, or `None` for a topic root.
///
/// NIP-10 marked form: the `reply` marker. Legacy positional form (no
/// markers): the last unmarked `e` tag that is not the channel. `quote`,
/// `edit` and `mention` markers are never parents.
pub(crate) fn parent_of(ev: &NostrEvent, channel_id: &str) -> Option<String> {
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
pub(crate) fn topic_root_of(
    start_id: &str,
    channel_id: &str,
    events: &[NostrEvent],
) -> Option<String> {
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

#[component]
pub fn MessageJumpPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let store = use_channel_store();
    let conn_state = relay.connection_state();
    let params = use_params_map();
    let event_id = move || params.read().get("event_id").unwrap_or_default();
    let navigate = StoredValue::new(use_navigate());

    let target: RwSignal<Option<NostrEvent>> = RwSignal::new(None);
    let sub_id: StoredValue<Option<String>> = StoredValue::new(None);
    let fetch_started = StoredValue::new(false);
    let done = StoredValue::new(false);

    // `try_*`: the fallback timer can fire after a successful redirect has
    // already unmounted this page and disposed its stored values.
    let go = move |path: String| {
        if done.try_get_value().unwrap_or(true) {
            return;
        }
        done.set_value(true);
        navigate.try_with_value(|nav| {
            nav(
                &path,
                NavigateOptions {
                    replace: true,
                    ..Default::default()
                },
            )
        });
    };

    // 1. Fetch the target event once the relay is up.
    let relay_for_fetch = relay.clone();
    Effect::new(move |_| {
        let id = event_id();
        if conn_state.get() != ConnectionState::Connected || id.is_empty() {
            return;
        }
        if fetch_started.get_value() {
            return;
        }
        fetch_started.set_value(true);
        let on_event = Rc::new(move |ev: NostrEvent| {
            let _ = target.try_set(Some(ev));
        });
        let sid = relay_for_fetch.subscribe(
            vec![Filter {
                ids: Some(vec![id]),
                ..Default::default()
            }],
            on_event,
            None,
        );
        sub_id.set_value(Some(sid));
        let fallback_id = event_id();
        set_timeout_once(
            move || go(format!("/view/{fallback_id}")),
            RESOLVE_TIMEOUT_MS,
        );
    });

    let relay_for_cleanup = relay.clone();
    on_cleanup(move || {
        if let Some(sid) = sub_id.try_get_value().flatten() {
            relay_for_cleanup.unsubscribe(&sid);
        }
    });

    // 2. Top up the channel's history, then resolve root → topic URL.
    Effect::new(move |_| {
        let Some(ev) = target.get() else { return };
        let Some(cid) = channel_of(&ev) else {
            go(format!("/view/{}", ev.id));
            return;
        };
        store.ensure_subscribed(&relay, &cid);

        // Focus the post the reader sees: an edit renders as its original.
        let focus = edit_target_of(&ev).unwrap_or_else(|| ev.id.clone());
        let events = store
            .channel_messages
            .with(|m| m.get(&cid).cloned().unwrap_or_default());
        // Include the target itself: it may predate the store's window.
        let mut events = events;
        if !events.iter().any(|e| e.id == ev.id) {
            events.push(ev.clone());
        }
        let Some(root) = topic_root_of(&focus, &cid, &events) else {
            return; // ancestors still streaming in; the effect re-runs
        };
        let zones = load_zones();
        let section = store.channels.with(|chans| {
            chans
                .iter()
                .find(|c| c.id == cid)
                .map(|c| c.section.clone())
        });
        let Some(section) = section else {
            return; // channel metadata not loaded yet
        };
        match section_to_zone(&section, &zones) {
            Some(zone_id) => go(format!(
                "/forums/{}/{}/{}?focus={}",
                zone_path_for_id(&zone_id),
                section_slug(&cid),
                topic_slug(&root),
                focus
            )),
            None => go(format!("/view/{}", ev.id)),
        }
    });

    view! {
        <div class="flex items-center justify-center py-24 text-sm text-gray-400">
            <span class="animate-pulse">"Opening message…"</span>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
