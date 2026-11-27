//! Message deep-link resolver.
//!
//! Route: `/go/:event_id`, optionally `?c=<channel id>`
//! ([`jump_link`](crate::utils::post_link::jump_link)).
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

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map, use_query_map};
use leptos_router::NavigateOptions;
use nostr_bbs_core::NostrEvent;

use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::channels::{use_channel_store, ChannelStore};
use crate::stores::zones::{load_zones, section_to_zone, zone_path_for_id};
use crate::utils::lookup::zone_is_gated;
// The link helpers live in client-core: the notification store builds them too.
use crate::utils::post_link::{channel_of, CHANNEL_HINT_PARAM};
// The resolution itself is client-core's, shared with the BBS client.
use crate::topics::jump::{
    channel_events_across, fallback, find_held, topic_root_of, Fallback, RESOLVE_TIMEOUT_MS,
};
use crate::topics::thread::edit_target_of;
use crate::utils::set_timeout_once;
use crate::utils::slug_hash::{section_slug, topic_slug};

/// How often the give-up check re-runs after [`RESOLVE_TIMEOUT_MS`].
const GIVE_UP_POLL_MS: i32 = 1_000;

/// Whether the history query `ensure_subscribed` opened for `cid` has its
/// authoritative receipt. A channel whose zone is unknown yet is treated as
/// gated (only the post-AUTH answer counts), so the wait errs long, bounded
/// by [`HINTED_RESOLVE_CEILING_MS`](crate::topics::jump::HINTED_RESOLVE_CEILING_MS).
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
                    Fallback::Channel(cid) => {
                        go(format!("/chat/{cid}"));
                        true
                    }
                    Fallback::Topic(path) => {
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
