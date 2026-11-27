//! Post-link resolver (`#/go/<id>`, `#/go/<id>/c/<channel>`): the BBS form of
//! the forum's `/go/<id>?c=<channel>` page, which notifications and search
//! results link to.
//!
//! A post is shown inside its topic, and a reply may sit several hops below
//! the root. The post is looked up among the store's decrypted lists (in an
//! encrypted zone the relay knows only the sealed envelope), its channel's
//! history is opened, the reply chain is walked to the topic root, and the
//! view hands over to that [`Route::Thread`] focused on the post. All of the
//! resolution is client-core's ([`nostr_bbs_client_core::topics::jump`]),
//! shared with the forum.

use std::collections::HashMap;

use leptos::prelude::*;
use nostr_bbs_client_core::relay::{ConnectionState, RelayConnection};
use nostr_bbs_client_core::stores::channels::use_channel_store;
use nostr_bbs_client_core::stores::zones::{load_zones, section_to_zone, zone_path_for_id};
use nostr_bbs_client_core::topics::jump::{
    channel_events_across, fallback, find_held, topic_root_of, Fallback, RESOLVE_TIMEOUT_MS,
};
use nostr_bbs_client_core::topics::thread::edit_target_of;
use nostr_bbs_client_core::utils::lookup::zone_is_gated;
use nostr_bbs_client_core::utils::post_link::channel_of;
use nostr_bbs_client_core::utils::set_timeout_once;
use nostr_bbs_core::NostrEvent;

use crate::components::EmptyCard;
use crate::router::{use_router, Route};

/// How often the give-up check re-runs once [`RESOLVE_TIMEOUT_MS`] has passed.
const GIVE_UP_POLL_MS: i32 = 1_000;

/// Where resolving a post stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The topic is known: open it.
    Open(Route),
    /// Not yet: the post's channel and the topic its `reply` tag names,
    /// where known, for the give-up path.
    Pending {
        channel: Option<String>,
        guess: Option<String>,
    },
}

/// The thread route for topic `root` of channel `cid` in zone path `zone`,
/// focused on `focus` unless that is the root itself.
pub fn thread_route(zone: &str, cid: &str, root: &str, focus: &str) -> Route {
    Route::Thread {
        zone: zone.to_string(),
        channel_id: cid.to_string(),
        root_id: root.to_string(),
        focus: (!focus.eq_ignore_ascii_case(root)).then(|| focus.to_string()),
    }
}

/// Resolve post `id` against the store's lists. `zone_of` maps a channel id
/// to its zone's URL path (`None` while the channel's metadata is not in).
pub fn resolve_post(
    id: &str,
    lists: &HashMap<String, Vec<NostrEvent>>,
    zone_of: impl Fn(&str) -> Option<String>,
) -> Resolution {
    let Some(ev) = find_held(id, lists) else {
        return Resolution::Pending {
            channel: None,
            guess: None,
        };
    };
    let guess = nostr_bbs_core::sealed::reply_root_of(ev).map(str::to_string);
    let Some(cid) = channel_of(ev).filter(|c| !c.is_empty()) else {
        return Resolution::Pending {
            channel: None,
            guess,
        };
    };
    // Focus the post the reader sees: an edit renders as its original.
    let focus = edit_target_of(ev).unwrap_or_else(|| ev.id.clone());
    let mut events = channel_events_across(&cid, lists);
    if !events.iter().any(|e| e.id.eq_ignore_ascii_case(&ev.id)) {
        events.push(ev.clone());
    }
    match (zone_of(&cid), topic_root_of(&focus, &cid, &events)) {
        (Some(zone), Some(root)) => Resolution::Open(thread_route(&zone, &cid, &root, &focus)),
        _ => Resolution::Pending {
            channel: Some(cid),
            guess,
        },
    }
}

/// Resolver view for [`Route::Go`].
#[component]
pub fn GoView(event_id: String, channel: Option<String>) -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let store = use_channel_store();
    let conn = relay.connection_state();
    let id = StoredValue::new(event_id);
    let hint = StoredValue::new(channel.filter(|c| !c.trim().is_empty()));
    let done = StoredValue::new(false);
    let not_found = RwSignal::new(false);
    let pending = StoredValue::new((None::<String>, None::<String>));

    let zone_of = move |cid: &str| {
        let zones = load_zones();
        store.channels.with_untracked(|chans| {
            chans
                .iter()
                .find(|c| c.id.eq_ignore_ascii_case(cid))
                .and_then(|c| section_to_zone(&c.section, &zones))
                .map(|z| zone_path_for_id(&z))
        })
    };
    let open = move |route: Route| {
        if done.try_get_value().unwrap_or(true) {
            return;
        }
        done.set_value(true);
        router.replace(route);
    };

    // 1. Once the relay is up: open the hinted channel's history (an
    //    encrypted post is found there, decrypted, under its own id) and
    //    fetch the post by id (a sealed original by the inner id its
    //    envelope names). Then give up after a while, landing on the
    //    named topic or the channel's board where known.
    let started = StoredValue::new(false);
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            if conn.get() != ConnectionState::Connected || started.get_value() {
                return;
            }
            started.set_value(true);
            if let Some(c) = hint.get_value() {
                store.ensure_subscribed(&relay, &c);
            }
            store.fetch_by_id(&relay, &id.get_value());
            let t0 = js_sys::Date::now();
            poll_until(
                RESOLVE_TIMEOUT_MS,
                std::rc::Rc::new(move || {
                    if done.try_get_value().unwrap_or(true) {
                        return true;
                    }
                    let hint_loading = hint.get_value().is_some_and(|c| {
                        let zones = load_zones();
                        let gated = zone_of(&c).is_none_or(|z| zone_is_gated(&z, &zones));
                        !untrack(|| store.history_receipt(&c).settles(gated))
                    });
                    let (channel, guess) = pending.get_value();
                    let channel = channel.or_else(|| hint.get_value());
                    match fallback(
                        js_sys::Date::now() - t0,
                        hint_loading,
                        false,
                        guess.as_deref(),
                        channel.as_deref(),
                    ) {
                        Fallback::Wait => false,
                        Fallback::Topic(root) => {
                            match channel
                                .as_deref()
                                .and_then(|c| zone_of(c).map(|z| (c.to_string(), z)))
                            {
                                Some((cid, zone)) => {
                                    open(thread_route(&zone, &cid, &root, &id.get_value()))
                                }
                                None => not_found.set(true),
                            }
                            true
                        }
                        Fallback::Channel(cid) => {
                            match zone_of(&cid) {
                                Some(zone) => open(Route::Board {
                                    zone,
                                    channel_id: cid,
                                }),
                                None => not_found.set(true),
                            }
                            true
                        }
                        Fallback::NoteView => {
                            not_found.set(true);
                            true
                        }
                    }
                }),
            );
        });
    }

    // 2. Resolve as history and keys arrive.
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            let res = store
                .channel_messages
                .with(|m| resolve_post(&id.get_value(), m, zone_of));
            match res {
                Resolution::Open(route) => open(route),
                Resolution::Pending { channel, guess } => {
                    if let Some(c) = &channel {
                        store.ensure_subscribed(&relay, c);
                    }
                    pending.set_value((channel, guess));
                }
            }
        });
    }

    view! {
        <div class="tui-container">
            {move || if not_found.get() {
                view! {
                    <EmptyCard
                        title="Post not found"
                        body="This post could not be located in any board you can read. It may have been deleted, or it is in a zone whose key you do not hold."
                    />
                }.into_any()
            } else {
                view! { <EmptyCard title="Opening post…" body="Finding the topic this post belongs to." /> }.into_any()
            }}
        </div>
    }
}

/// Run `step` after `delay_ms`, then every [`GIVE_UP_POLL_MS`] until it
/// reports it is finished.
fn poll_until(delay_ms: i32, step: std::rc::Rc<dyn Fn() -> bool>) {
    set_timeout_once(
        move || {
            if !step() {
                poll_until(GIVE_UP_POLL_MS, step);
            }
        },
        delay_ms,
    );
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
    fn a_reply_in_its_topic_list_opens_the_topic_at_the_reply() {
        // A decrypted reply held only in its topic's list, its root in the
        // root list: the notification opens that topic, focused on it.
        let m = lists(vec![
            (
                "roots:chan",
                vec![ev("root", vec![vec!["e", "chan", "", "root"]])],
            ),
            (
                "topic:root",
                vec![ev(
                    "r1",
                    vec![
                        vec!["e", "chan", "", "root"],
                        vec!["e", "root", "", "reply"],
                    ],
                )],
            ),
        ]);
        let zone = |c: &str| (c == "chan").then(|| "mini".to_string());
        assert_eq!(
            resolve_post("R1", &m, zone),
            Resolution::Open(Route::Thread {
                zone: "mini".into(),
                channel_id: "chan".into(),
                root_id: "root".into(),
                focus: Some("r1".into()),
            })
        );
        // The root itself opens unfocused.
        assert_eq!(
            resolve_post("root", &m, zone),
            Resolution::Open(Route::Thread {
                zone: "mini".into(),
                channel_id: "chan".into(),
                root_id: "root".into(),
                focus: None,
            })
        );
    }

    #[test]
    fn missing_root_or_zone_waits_with_what_is_known() {
        let m = lists(vec![(
            "chan",
            vec![ev(
                "r1",
                vec![vec!["e", "chan", "", "root"], vec!["e", "old", "", "reply"]],
            )],
        )]);
        assert_eq!(
            resolve_post("r1", &m, |_| Some("z".into())),
            Resolution::Pending {
                channel: Some("chan".into()),
                guess: Some("old".into())
            }
        );
        let full = lists(vec![(
            "chan",
            vec![
                ev("old", vec![vec!["e", "chan", "", "root"]]),
                ev(
                    "r1",
                    vec![vec!["e", "chan", "", "root"], vec!["e", "old", "", "reply"]],
                ),
            ],
        )]);
        assert!(matches!(
            resolve_post("r1", &full, |_| None),
            Resolution::Pending { .. }
        ));
        assert_eq!(
            resolve_post("nope", &full, |_| Some("z".into())),
            Resolution::Pending {
                channel: None,
                guess: None
            }
        );
    }

    #[test]
    fn an_edit_opens_its_original() {
        let m = lists(vec![(
            "chan",
            vec![
                ev("root", vec![vec!["e", "chan", "", "root"]]),
                ev(
                    "r1",
                    vec![
                        vec!["e", "chan", "", "root"],
                        vec!["e", "root", "", "reply"],
                    ],
                ),
                ev(
                    "ed",
                    vec![
                        vec!["e", "chan", "", "root"],
                        vec!["e", "root", "", "reply"],
                        vec!["e", "r1", "", "edit"],
                    ],
                ),
            ],
        )]);
        assert_eq!(
            resolve_post("ed", &m, |_| Some("z".into())),
            Resolution::Open(thread_route("z", "chan", "root", "r1"))
        );
    }
}
