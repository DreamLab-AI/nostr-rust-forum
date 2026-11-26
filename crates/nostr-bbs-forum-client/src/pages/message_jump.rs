//! Message deep-link resolver.
//!
//! Route: `/go/:event_id`, optionally `?c=<channel id>` ([`jump_link`]).
//!
//! Search results and other "take me to this message" links carry only an
//! event id. The forum renders messages inside a TOPIC page
//! (`/forums/:zone/:section/:topic`), and a reply may sit several hops below
//! the topic root (NIP-10 replies thread under the specific message they answer,
//! and an edit points at the post it replaces). This page finds the event,
//! tops up its channel's history, walks the reply chain to the topic root, and
//! replaces itself with the topic URL plus `?focus=<id>` so the thread page
//! scrolls to and flashes the target.
//!
//! In an encrypted zone the relay stores only the sealed envelope, whose id
//! is not the post's id the client knows, so a relay `ids` lookup finds
//! nothing. The page therefore looks in the channel store's decrypted
//! messages first (every loaded list), opens the hinted channel's history
//! and waits for it, and asks the relay for the envelope by the inner id it
//! names (`#sealed`) alongside the plain `ids` lookup.
//!
//! If the topic cannot be resolved it lands on the channel's topic list when
//! the channel is known, and otherwise on the single-note view.

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map, use_query_map};
use leptos_router::NavigateOptions;
use nostr_bbs_core::NostrEvent;

use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::channels::{use_channel_store, ChannelStore};
use crate::stores::zones::{load_zones, section_to_zone, zone_path_for_id};
use crate::utils::lookup::zone_is_gated;
use crate::utils::set_timeout_once;
use crate::utils::slug_hash::{section_slug, topic_slug};

/// Give up on resolving the topic after this long and show the note view.
const RESOLVE_TIMEOUT_MS: i32 = 6_000;

/// With a channel hint whose history is still loading, keep waiting up to
/// this long before giving up.
const HINTED_RESOLVE_CEILING_MS: f64 = 20_000.0;

/// How often the give-up check re-runs after [`RESOLVE_TIMEOUT_MS`].
const GIVE_UP_POLL_MS: i32 = 1_000;

/// Query parameter carrying the post's channel id: `/go/<id>?c=<channel>`.
pub(crate) const CHANNEL_HINT_PARAM: &str = "c";

/// The deep link to post `event_id`, carrying its channel as a hint when
/// known. In an encrypted zone the relay holds only the sealed envelope,
/// whose id is not the post's id, so the jump page resolves from the
/// channel's own (decrypted) history.
///
/// A hint that is not URL-safe as it stands (a legacy slug-style channel
/// tag) is left off rather than escaped: the page still resolves without it.
pub(crate) fn jump_link(event_id: &str, channel_id: Option<&str>) -> String {
    let url_safe = |c: &str| {
        !c.is_empty()
            && c.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    };
    match channel_id.filter(|c| url_safe(c)) {
        Some(c) => format!("/go/{event_id}?{CHANNEL_HINT_PARAM}={c}"),
        None => format!("/go/{event_id}"),
    }
}

/// The deep link for a post held in store list `list_key`. The hint is the
/// post's own channel tag: the store's list keys include `topic:<root>` and
/// `roots:<channel>`, which are not channels. A bare list key stands in only
/// for a post with no channel tag.
pub(crate) fn post_link(ev: &NostrEvent, list_key: &str) -> String {
    let channel =
        channel_of(ev).or_else(|| (!list_key.contains(':')).then(|| list_key.to_string()));
    jump_link(&ev.id, channel.as_deref())
}

/// The event with id `id` in any list of the channel store (channel lists,
/// `topic:` and `roots:` lists), case-insensitively.
pub(crate) fn find_held<'a>(
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
pub(crate) fn channel_events_across(
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
pub(crate) enum Fallback {
    /// Keep waiting.
    Wait,
    /// Show the single-note view (`/view/<id>`).
    NoteView,
    /// Land on the channel's topic list (`/chat/<cid>` redirects there).
    Channel(String),
    /// Open the topic the post names as its root, focused on the post.
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
pub(crate) fn fallback(
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
        Some(c) if !relay_has_it => Fallback::Channel(format!("/chat/{c}")),
        _ => Fallback::NoteView,
    }
}

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

/// Whether the history query `ensure_subscribed` opened for `cid` has its
/// authoritative receipt. A channel whose zone is unknown yet is treated as
/// gated (only the post-AUTH answer counts), so the wait errs long, bounded
/// by [`HINTED_RESOLVE_CEILING_MS`].
fn channel_history_settled(store: ChannelStore, cid: &str) -> bool {
    untrack(|| {
        let zones = load_zones();
        let gated = store
            .channels
            .with(|chans| {
                chans
                    .iter()
                    .find(|c| c.id == cid)
                    .and_then(|c| section_to_zone(&c.section, &zones))
            })
            .is_none_or(|zone| zone_is_gated(&zone, &zones));
        store.history_receipt(cid).settles(gated)
    })
}

/// Run `step` after `delay_ms`, then every [`GIVE_UP_POLL_MS`] until it
/// reports it is finished.
fn poll_until(delay_ms: i32, step: Rc<dyn Fn() -> bool>) {
    set_timeout_once(
        move || {
            if !step() {
                poll_until(GIVE_UP_POLL_MS, step);
            }
        },
        delay_ms,
    );
}

#[component]
pub fn MessageJumpPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let store = use_channel_store();
    let conn_state = relay.connection_state();
    let params = use_params_map();
    let query = use_query_map();
    let event_id = move || params.read().get("event_id").unwrap_or_default();
    let hint = move || {
        query
            .read()
            .get(CHANNEL_HINT_PARAM)
            .filter(|c| !c.trim().is_empty())
    };
    let navigate = StoredValue::new(use_navigate());

    // The post as the relay delivered it under the linked id (a plaintext
    // post, or an envelope linked by its own id, opened here).
    let target: RwSignal<Option<NostrEvent>> = RwSignal::new(None);
    // The relay delivered the linked id itself (the note view can show it).
    let relay_has_it = StoredValue::new(false);
    // The post's channel once any source has named it.
    let known_channel: StoredValue<Option<String>> = StoredValue::new(None);
    // The topic the held post names as its root (its `reply` tag), for when
    // the reply chain cannot be walked because the root predates the loaded
    // history: the thread page fetches a missing root itself.
    let topic_guess: StoredValue<Option<String>> = StoredValue::new(None);
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

    // 1. Once the relay is up: open the hinted channel's history (an
    //    encrypted zone's post is found there, decrypted, under its own id),
    //    and ask the relay for the id itself: a live post by `ids`, a sealed
    //    original by the inner id its envelope names (`#sealed`).
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
        let hinted = hint();
        if let Some(c) = &hinted {
            store.ensure_subscribed(&relay_for_fetch, c);
        }
        let zone_keys = store.zone_store();
        let wanted = id.to_ascii_lowercase();
        let hint_for_events = hinted.clone();
        let on_event = Rc::new(move |ev: NostrEvent| {
            let outer_is_target = ev.id.eq_ignore_ascii_case(&wanted);
            if nostr_bbs_core::sealed::parse_sealed(&ev.tags).is_none() {
                if outer_is_target {
                    // Only a plaintext post is one the note view can show; a
                    // live zone-encrypted post resolves through the store.
                    if !crate::zone_crypto::is_zone_message(&ev) {
                        relay_has_it.try_set_value(true);
                    }
                    let _ = target.try_set(Some(ev));
                }
                return;
            }
            // A sealed envelope: open it through the store's usual admission
            // and decrypt path; the store lookup below then finds the
            // original under its own id. Its outer root tag names the
            // channel when the channel list has not loaded yet.
            let fallback_cid = hint_for_events
                .clone()
                .or_else(|| channel_of(&ev))
                .unwrap_or_default();
            if fallback_cid.is_empty() {
                return;
            }
            let Some((cid, opened)) = store.ingest(zone_keys, ev, &fallback_cid) else {
                return;
            };
            if cid.is_empty() {
                return;
            }
            known_channel.try_set_value(Some(cid.clone()));
            if outer_is_target || opened.id.eq_ignore_ascii_case(&wanted) {
                let _ = target.try_set(Some(opened.clone()));
            }
            store.apply_page(vec![(cid, opened)]);
        });
        let mut sealed = Filter {
            kinds: Some(vec![42]),
            limit: Some(1),
            ..Default::default()
        };
        sealed.sealed_tags = Some(vec![id.to_ascii_lowercase()]);
        let sid = relay_for_fetch.subscribe(
            vec![
                Filter {
                    ids: Some(vec![id]),
                    ..Default::default()
                },
                sealed,
            ],
            on_event,
            None,
        );
        sub_id.set_value(Some(sid));

        // Give up after RESOLVE_TIMEOUT_MS, or later while the hinted
        // channel's history is still arriving; land on the channel's topic
        // list when the channel is known rather than on "Not Found".
        let started = js_sys::Date::now();
        let fallback_id = event_id();
        poll_until(
            RESOLVE_TIMEOUT_MS,
            Rc::new(move || {
                if done.try_get_value().unwrap_or(true) {
                    return true;
                }
                let hint_loading = hinted
                    .as_deref()
                    .is_some_and(|c| !channel_history_settled(store, c));
                let channel = known_channel
                    .try_get_value()
                    .flatten()
                    .or_else(|| hinted.clone());
                let topic = topic_guess.try_get_value().flatten();
                match fallback(
                    js_sys::Date::now() - started,
                    hint_loading,
                    relay_has_it.try_get_value().unwrap_or(false),
                    topic.as_deref(),
                    channel.as_deref(),
                ) {
                    Fallback::Wait => false,
                    Fallback::NoteView => {
                        go(format!("/view/{fallback_id}"));
                        true
                    }
                    Fallback::Channel(path) | Fallback::Topic(path) => {
                        go(path);
                        true
                    }
                }
            }),
        );
    });

    let relay_for_cleanup = relay.clone();
    on_cleanup(move || {
        if let Some(sid) = sub_id.try_get_value().flatten() {
            relay_for_cleanup.unsubscribe(&sid);
        }
    });

    // 2. Find the post (the relay's answer, else the store's decrypted
    //    messages across every loaded list), top up its channel's history,
    //    then resolve root → topic URL. Re-runs as history streams in and as
    //    zone keys open envelopes in place.
    Effect::new(move |_| {
        let id = event_id();
        if id.is_empty() {
            return;
        }
        let ev = target
            .get()
            .or_else(|| store.channel_messages.with(|m| find_held(&id, m).cloned()));
        let Some(ev) = ev else { return };
        let Some(cid) = channel_of(&ev).filter(|c| !c.is_empty()) else {
            go(format!("/view/{}", ev.id));
            return;
        };
        known_channel.set_value(Some(cid.clone()));
        store.ensure_subscribed(&relay, &cid);

        // Focus the post the reader sees: an edit renders as its original.
        let focus = edit_target_of(&ev).unwrap_or_else(|| ev.id.clone());
        let mut events = store
            .channel_messages
            .with(|m| channel_events_across(&cid, m));
        // Include the target itself: it may predate the store's window.
        if !events.iter().any(|e| e.id.eq_ignore_ascii_case(&ev.id)) {
            events.push(ev.clone());
        }
        let zones = load_zones();
        let section = store.channels.with(|chans| {
            chans
                .iter()
                .find(|c| c.id == cid)
                .map(|c| c.section.clone())
        });
        let zone_id = section.as_deref().and_then(|s| section_to_zone(s, &zones));
        let topic_url = |root: &str| {
            zone_id.as_deref().map(|z| {
                format!(
                    "/forums/{}/{}/{}?focus={}",
                    zone_path_for_id(z),
                    section_slug(&cid),
                    topic_slug(root),
                    focus
                )
            })
        };
        let Some(root) = topic_root_of(&focus, &cid, &events) else {
            // Ancestors still streaming in; the effect re-runs. Meanwhile
            // remember the topic the post names, for the give-up path.
            let guess = nostr_bbs_core::sealed::reply_root_of(&ev).and_then(topic_url);
            topic_guess.set_value(guess);
            return;
        };
        if section.is_none() {
            return; // channel metadata not loaded yet
        }
        match topic_url(&root) {
            Some(url) => go(url),
            // No zone for the channel: its own resolver (`/chat/<cid>`)
            // lands on the section, never on a note view that cannot show
            // an encrypted post.
            None => go(format!("/chat/{cid}")),
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

    fn lists(entries: Vec<(&str, Vec<NostrEvent>)>) -> HashMap<String, Vec<NostrEvent>> {
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    #[test]
    fn jump_link_carries_the_channel_hint() {
        assert_eq!(jump_link("abc", Some("chan")), "/go/abc?c=chan");
        assert_eq!(jump_link("abc", None), "/go/abc");
        assert_eq!(jump_link("abc", Some("")), "/go/abc");
        // Old persisted links stay recognisable as post links.
        assert!(jump_link("abc", Some("chan")).starts_with("/go/"));
    }

    #[test]
    fn post_link_hints_the_posts_own_channel() {
        let reply = ev(
            "r1",
            vec![
                vec!["e", "root", "", "reply"],
                vec!["e", "chan", "", "root"],
            ],
        );
        // Held in its topic's list: the hint is still the channel.
        assert_eq!(post_link(&reply, "topic:root"), "/go/r1?c=chan");
        assert_eq!(post_link(&reply, "chan"), "/go/r1?c=chan");
        let untagged = ev("u", vec![]);
        assert_eq!(post_link(&untagged, "chan"), "/go/u?c=chan");
        assert_eq!(post_link(&untagged, "topic:root"), "/go/u");
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
            Fallback::Channel("/chat/chan".into())
        );
        // Unresolved but the channel is known: its topic list, never "Not Found".
        assert_eq!(
            fallback(late, false, false, None, chan),
            Fallback::Channel("/chat/chan".into())
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
