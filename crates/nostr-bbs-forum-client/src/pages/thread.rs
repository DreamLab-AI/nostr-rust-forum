//! Thread page -- a single TOPIC (kind-42 root) with its threaded replies (#8).
//!
//! Route: /forums/:category/:section/:topic
//!
//! ## BBS composition
//!
//! - A *zone* (`:category`, readable config id) groups *sections*.
//! - A *section* (`:section`) is a kind-40 channel; the URL carries a HASH of
//!   the channel id (#9), resolved back to the channel via the shared store.
//! - A *topic* (`:topic`) is a kind-42 ROOT message inside that channel; the
//!   URL carries a HASH of the root event id (#9, a prefix of the id itself).
//! - *Replies* are kind-42 events e-tagging the root, plus any NIP-22 kind-1111
//!   comments addressed to the root.
//!
//! All data comes from the shared [`ChannelStore`](crate::stores::channels::ChannelStore) (the same kind-40/kind-42
//! subscriptions that drive the index and the section topic list) — this page
//! adds NO redundant per-page subscription beyond `ensure_subscribed`, which is
//! idempotent and only tops up the per-channel history for a deep-linked
//! channel the broad sub hasn't yet covered. The reply composer publishes a
//! kind-42 e-tagging the topic root (NIP-10 root + reply markers), so the new
//! reply re-enters the same store stream and the count updates live.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::{use_params_map, use_query_map};
use nostr_bbs_core::NostrEvent;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::agent_badge::AgentBadge;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::canonical_address::keep_address_canonical;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::copy_key::KeyName;
use crate::components::link_preview::LinkPreview;
use crate::components::media_embed::MediaEmbed;
use crate::components::mention_text::{normalise_mention_pubkey, MentionText};
use crate::components::message_input::MessageInput;
use crate::components::reaction_bar::ReactionBar;
use crate::components::tip_button::TipControl;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::relay::RelayConnection;
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::read_position::use_read_positions;
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, Zone, ZoneVisibility};
use crate::utils::format_relative_time;
use crate::utils::lookup::{
    deadline_for, key_state_memo, zone_is_encrypted, zone_is_gated, Lookup,
};
use crate::utils::section_url::{canonical_topic_path, find_by_section_slug, section_path};
use crate::utils::slug_hash::matches_topic_slug;
use crate::utils::zone_theme::zone_accent_style_cfg;

use crate::topics::{
    edit_tags, find_topic_root, first_line, history_settled, landing_target, latest_version,
    post_anchor_id, thread_events, thread_replies, topic_reply_tags, view_key, Landing, ReplyView,
};

use super::section::{category_display_name, resolve_channel};

/// The post a new reply is quoting — set when the reader taps "Reply" on a post,
/// consumed by the single bottom composer, and cleared after send/dismiss. A
/// reply always appends to the bottom of the topic; the target only decides which
/// message it quotes and whose author is notified.
#[derive(Clone)]
struct ReplyTarget {
    id: String,
    pubkey: String,
    author: String,
    snippet: String,
}

/// Scroll the landing into place. A focus target is centred (and outlined
/// once when `flash`); otherwise the page goes to the very bottom: the reply
/// composer's bottom edge when it is rendered, else the newest post's.
fn pin_landing(target: &str, is_focus: bool, flash: bool) {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let opts = web_sys::ScrollIntoViewOptions::new();
    if is_focus {
        let Some(el) = doc.get_element_by_id(&post_anchor_id(target)) else {
            return;
        };
        opts.set_block(web_sys::ScrollLogicalPosition::Center);
        el.scroll_into_view_with_scroll_into_view_options(&opts);
        if flash {
            let cl = el.class_list();
            let _ = cl.add_2("ring-2", "ring-amber-400/70");
            crate::utils::set_timeout_once(
                move || {
                    let _ = cl.remove_2("ring-2", "ring-amber-400/70");
                },
                2_500,
            );
        }
        return;
    }
    let Some(el) = doc
        .get_element_by_id("thread-reply-composer")
        .or_else(|| doc.get_element_by_id(&post_anchor_id(target)))
    else {
        return;
    };
    opts.set_block(web_sys::ScrollLogicalPosition::End);
    el.scroll_into_view_with_scroll_into_view_options(&opts);
}

/// The kind-40 channel whose section-hash matches `section_slug_param` within
/// the requested zone. Falls back to the shared plaintext resolver so legacy /
/// seeded plaintext section links keep working.
fn resolve_section_channel(
    channels: &[ChannelMeta],
    category_slug: &str,
    section_slug_param: &str,
    zones: &[Zone],
) -> Option<ChannelMeta> {
    // Hashed form first (#9): the channel-id hash (canonical), or the
    // section-tag hash old Forums index links carry, scoped to the zone.
    if let Some(found) = find_by_section_slug(channels, category_slug, section_slug_param, zones) {
        return Some(found.clone());
    }
    // Legacy plaintext fallback (shared with SectionPage).
    resolve_channel(channels, category_slug, section_slug_param, zones)
}

/// Thread page: topic root + threaded replies + reply composer.
#[component]
pub fn ThreadPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let store = use_channel_store();
    let read_store = use_read_positions();
    let zone_access = use_zone_access();
    // Copy for the zone-first breadcrumb (ADR-107); `ZoneAccess` is `Copy`.
    let za_breadcrumb = zone_access;
    let toasts = use_toasts();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();
    let section_param = move || params.read().get("section").unwrap_or_default();
    let topic_param = move || params.read().get("topic").unwrap_or_default();

    // Canonicalised zone URL slug: the `:category` param may be the zone's
    // configured slug OR its immutable id (both resolve via
    // `resolve_zone_param` so legacy `/zone1/…` links keep working), but every
    // link THIS page emits must read `/welcome/…` — never the raw id — so a
    // user arriving via an id URL never sees it propagate into child links.
    let category_url_slug = move || {
        let raw = category_slug();
        let zs = load_zones();
        crate::stores::zones::resolve_zone_param(&raw, &zs)
            .map(|z| crate::stores::zones::zone_slug(z).to_string())
            .unwrap_or(raw)
    };

    // Zone access gate — identical contract to SectionPage (ADR-022: the relay
    // is the real boundary; unknown zones default accessible).
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        let zs = load_zones();
        let resolved = crate::stores::zones::resolve_zone_param(&cat, &zs).cloned();
        match resolved {
            Some(zone) => {
                zone.visibility == ZoneVisibility::Public || zone_access.is_member_of(&zone)
            }
            None => true,
        }
    });

    // Resolve the section channel from the shared store (hashed slug → channel).
    let resolved_channel = Signal::derive(move || {
        let chans = store.channels.get();
        let zones = load_zones();
        resolve_section_channel(&chans, &category_slug(), &section_param(), &zones)
    });

    // Whether the deep-link walk has restarted the channel's history window
    // from the newest page (see the walk below). Absence is only concluded
    // after the walk covered the newest messages too.
    let restarted = StoredValue::new(false);

    // Pod container for images attached in this thread: the channel's zone.
    let thread_media_target = Signal::derive(move || {
        crate::stores::zones::media_target_for_section(
            resolved_channel.get().map(|c| c.section).as_deref(),
        )
    });

    // Top up the per-channel history once the channel id is known (idempotent).
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            if let Some(ch) = resolved_channel.get() {
                store.ensure_subscribed(&relay, &ch.id);
            }
        });
    }

    // All kind-42/kind-1111 events for the resolved channel from the store.
    // The topic's own paged list (`topic:<root>`), once the root is known.
    // A topic is paged on its own (`#e:[root]`): sealed replies carry the
    // root as an outer `reply` tag. Live posts still arrive through the
    // channel's subscription, into the channel list.
    let topic_list = RwSignal::new(None::<String>);
    let channel_events = Signal::derive(move || {
        let cid = match resolved_channel.get() {
            Some(ch) => ch.id,
            None => return Vec::<NostrEvent>::new(),
        };
        // The channel window, the section's topic roots (one root-list REQ,
        // not windowed, so a root found there survives eviction from the
        // window) and the topic's own list, merged as client-core does for
        // the BBS too. While the topic window is detached in older replies,
        // newer live posts wait for its reload (as the channel window does).
        let channel = store.list_events(&cid);
        let roots = store.list_events(&crate::stores::channels::roots_key(&cid));
        let topic = topic_list.get().map(|key| {
            (
                store.list_events(&key),
                store.history_cursor(&key).newer_from,
            )
        });
        thread_events(&channel, &roots, topic)
    });

    // Mark the channel read when a topic in it is opened (BBS reading flow).
    //
    // Deep-linking straight into a thread (without passing through the section
    // topic list) must also clear the index "N new" chip, so this mirrors the
    // section page: record the LATEST kind-42 message's id + created_at via
    // ReadPositionStore::mark_read. The index Memo subscribes to
    // `read_timestamps()` and re-runs to clear the chip on return.
    //
    // Gated on the latest message id so it only re-fires when a newer message
    // actually arrives — never on every render.
    {
        let last_marked = RwSignal::new(String::new());
        Effect::new(move |_| {
            let cid = match resolved_channel.get() {
                Some(ch) => ch.id,
                None => return,
            };
            let latest = channel_events.with(|events| crate::topics::latest_post(events));
            if let Some((last_id, last_ts)) = latest {
                if last_marked.get_untracked() != last_id {
                    read_store.mark_read(&cid, &last_id, last_ts);
                    last_marked.set(last_id);
                }
            }
        });
    }

    // The topic root event whose id maps to the :topic slug.
    // The root, once seen, is kept: the bounded history window evicts the
    // channel's oldest messages as the reader pages towards newer replies,
    // and a topic root is usually the oldest message of its topic.
    let pinned_root = StoredValue::new(None::<NostrEvent>);
    let topic_root = Signal::derive(move || {
        let cid = match resolved_channel.get() {
            Some(ch) => ch.id,
            None => return Option::<NostrEvent>::None,
        };
        let slug = topic_param();
        // Must be a root anchored to this channel (not itself a reply).
        let found = channel_events
            .with(|events| find_topic_root(events, &cid, |id| matches_topic_slug(id, &slug)));
        match found {
            Some(root) => {
                pinned_root.set_value(Some(root.clone()));
                Some(root)
            }
            None => pinned_root
                .get_value()
                .filter(|r| matches_topic_slug(&r.id, &slug)),
        }
    });

    // One URL per topic: an old form (section-tag hash, `/forums/…`, zone id,
    // full root id) is replaced in place by the canonical one.
    keep_address_canonical(move || {
        let ch = resolved_channel.get()?;
        let root = topic_root.get().map(|r| r.id);
        canonical_topic_path(&ch, &topic_param(), root.as_deref(), &load_zones())
    });

    // "Continue where you left off" (utils::resume): remember this topic.
    // Route plus zone and section names; the topic title only for an
    // unencrypted zone (`point_for` drops it otherwise), never content.
    Effect::new(move |_| {
        if !has_zone_access.get() {
            return;
        }
        let (Some(pk), Some(ch)) = (auth.pubkey().get(), resolved_channel.get()) else {
            return;
        };
        let root = topic_root.get();
        // Always the canonical ids (see `utils::section_url`), whichever form
        // the address had: an old form is about to be replaced. A full-id
        // topic link waits for its root.
        let section = crate::utils::slug_hash::section_slug(&ch.id);
        let param = topic_param();
        let topic = match root.as_ref() {
            Some(r) => crate::utils::slug_hash::topic_slug(&r.id),
            None if crate::utils::slug_hash::is_topic_slug(&param) => param.to_lowercase(),
            None => return,
        };
        let title = root.as_ref().map(|r| first_line(&r.content));
        let name = if ch.name.trim().is_empty() {
            "Section".to_string()
        } else {
            ch.name.clone()
        };
        let visit = crate::utils::resume::TopicVisit {
            slug: &topic,
            title: title.as_deref(),
            is_zone_message: root
                .as_ref()
                .is_some_and(crate::zone_crypto::is_zone_message),
        };
        if let Some(point) = crate::utils::resume::point_for(
            &load_zones(),
            &category_slug(),
            Some((&section, &name)),
            Some(visit),
        ) {
            crate::utils::resume::remember(&pk, &point);
        }
    });

    // Replies: kind-42 / kind-1111 events that reference the topic root id.
    //
    // Edit events are folded into the post they replace rather than shown as
    // their own replies: the root's edits are dropped outright, and each
    // surviving reply renders its latest authored version (see `latest_version`).
    // A Memo over one O(n) pass (see `thread_replies`): with paged history a
    // topic can hold thousands of replies, and the derivation used to rescan
    // every event per reply (O(n^2)) once per reader per store change.
    let replies = Memo::new(move |_| {
        let Some(root) = topic_root.get() else {
            return Vec::<ReplyView>::new();
        };
        channel_events.with(|events| thread_replies(&root, events))
    });

    // Start the topic's own paged list once its root is known: register it,
    // load its newest page, and ask the relay for its true reply count.
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            let (Some(ch), Some(root)) = (resolved_channel.get(), topic_root.get()) else {
                return;
            };
            let key = store.register_topic(&ch.id, &root.id);
            if topic_list.get_untracked().as_deref() != Some(key.as_str()) {
                topic_list.set(Some(key.clone()));
            }
            let gated = zone_is_gated(&category_slug(), &load_zones());
            let cursor = store.history_cursor(&key);
            if !cursor.started && !cursor.loading {
                store.reload_newest(&relay, &key, vec![root.id.to_lowercase()], gated);
            }
            store.request_total_of(&relay, &key, &root.id.to_lowercase());
        });
    }

    // The root post's latest content + edited flag, folding in any author edits.
    let root_view = Signal::derive(move || {
        let root = topic_root.get()?;
        let (content, created_at, edited) =
            channel_events.with(|events| latest_version(&root, events));
        Some(ReplyView {
            id: root.id.clone(),
            pubkey: root.pubkey.clone(),
            content,
            created_at,
            edited,
            quote: None,
            tags: root.tags.clone(),
        })
    });

    // Found / loading / not found. Absence is only reported on the relay's
    // EOSE for the subscription that would have carried the thing — the
    // channel list for the section, this channel's history query for the
    // topic — or after the deadline. `store.loading` is NOT an input: it
    // clears on the channel list's first EOSE (or at once from cache), before
    // this channel's kind-42 history has even been requested.
    // Re-armed per topic: the route component is reused across topics.
    let deadline = deadline_for(move || (category_slug(), section_param(), topic_param()));
    // In an encrypted zone the root may be a sealed original still under its
    // envelope id until the member's keys arrive. No zone-key store means
    // nothing here can decrypt, so there is nothing to wait for.
    let zone_keys = crate::zone_crypto::store::try_use_zone_key_store();
    let auth_pubkey = auth.pubkey();
    let keys = key_state_memo(
        move || {
            zone_keys.is_some()
                && zone_is_encrypted(
                    &category_slug(),
                    &load_zones(),
                    crate::zone_crypto::encryption_enabled(),
                )
        },
        move |now| zone_keys.and_then(|z| z.key_phase_for(auth_pubkey.get().as_deref(), now)),
        deadline,
    );
    let lookup = Memo::new(move |_| {
        let gated = zone_is_gated(&category_slug(), &load_zones());
        let deadline_passed = deadline.get();
        let channel = resolved_channel.get();
        Lookup::decide(
            channel.is_some(),
            store.channel_receipt.get().settles(gated),
            deadline_passed,
        )
        .then(|| {
            let cid = channel.map(|c| c.id).unwrap_or_default();
            // With paged history a receipt only means the NEWEST page is in:
            // the topic is absent only once the walk below has reached the
            // start of the channel's history.
            let cursor = store.history_cursor(&cid);
            let settled = store.history_receipt(&cid).settles(gated)
                && cursor.exhausted
                && (cursor.newer_from.is_none() || restarted.get_value());
            Lookup::decide_with_keys(
                topic_root.with(Option::is_some),
                settled,
                keys.get(),
                deadline_passed,
            )
        })
    });
    let loading = Memo::new(move |_| lookup.get().is_loading());

    // Deep links into history not loaded yet.
    //
    // - A `?focus=<reply>` in a known topic: page the TOPIC's own list back
    //   (restarting from its newest page once if it is detached) until that
    //   reply is loaded or the topic's history is exhausted.
    // - A missing root: a topic slug is a prefix of the root's id, which the
    //   relay cannot match, but any loaded reply names the full root id in
    //   its topic (`reply`) tag; fetch the root by that id (a sealed root by
    //   the inner id in its `sealed` tag). Failing that, page the CHANNEL
    //   back until the root appears (slow on a channel holding many topics:
    //   roots carry no outer marker).
    let fetched_root = StoredValue::new(None::<String>);
    let topic_restarted = StoredValue::new(false);
    {
        let relay = relay.clone();
        let focus_query = use_query_map();
        Effect::new(move |_| {
            let Some(cid) = resolved_channel.get().map(|c| c.id) else {
                return;
            };
            let gated = zone_is_gated(&category_slug(), &load_zones());
            let focus = focus_query.read().get("focus");
            if let Some(root) = topic_root.get() {
                let Some(f) = focus else {
                    return;
                };
                let loaded = f.eq_ignore_ascii_case(&root.id)
                    || replies.with(|rs| rs.iter().any(|r| r.id.eq_ignore_ascii_case(&f)));
                let Some(key) = topic_list.get() else {
                    return;
                };
                if loaded {
                    return;
                }
                let cursor = store.history_cursor(&key);
                let needles = vec![root.id.to_lowercase()];
                if cursor.newer_from.is_some() && !cursor.loading && !topic_restarted.get_value() {
                    topic_restarted.set_value(true);
                    store.reload_newest(&relay, &key, needles, gated);
                } else if cursor.next_request().is_some() {
                    store.load_older(&relay, &key, needles, gated, Rc::new(|| {}), Rc::new(|| {}));
                }
                return;
            }
            // The root is missing. First the section's root list: one REQ,
            // then the slug (an id prefix) matches against it client-side.
            if !store.topic_roots_answered(&cid) {
                if store.history_receipt(&cid).settles(gated) {
                    store.request_topic_roots(&relay, &cid, gated);
                }
                return;
            }
            // Not a marked root: a loaded reply may name it in full.
            let slug = topic_param();
            let named = channel_events.with(|events| {
                events.iter().find_map(|e| {
                    nostr_bbs_core::sealed::reply_root_of(e)
                        .filter(|r| matches_topic_slug(r, &slug))
                        .map(str::to_lowercase)
                })
            });
            if let Some(root_id) = named {
                if fetched_root.get_value().as_deref() != Some(root_id.as_str()) {
                    fetched_root.set_value(Some(root_id.clone()));
                    store.fetch_by_id(&relay, &root_id);
                }
                return;
            }
            if !store.history_receipt(&cid).settles(gated) {
                return;
            }
            store.settle_first_page(&cid, gated);
            let cursor = store.history_cursor(&cid);
            // The window may be detached in older history (the section view
            // paged far back and evicted the newest topics): a topic newer
            // than the window would never be found walking older, so start
            // again from the newest page first, once.
            if cursor.newer_from.is_some() && !cursor.loading && !restarted.get_value() {
                restarted.set_value(true);
                store.reload_newest(&relay, &cid, vec![cid.clone()], gated);
                return;
            }
            if cursor.next_request().is_some() {
                store.load_older(
                    &relay,
                    &cid,
                    vec![cid.clone()],
                    gated,
                    Rc::new(|| {}),
                    Rc::new(|| {}),
                );
            }
        });
    }

    // The channel whose history window holds this topic, for the loaders.
    // The loaders page the topic's own list by its root (`#e:[root]`).
    let history_cid = Signal::derive(move || topic_list.get());
    let history_needles = Signal::derive(move || {
        topic_root
            .get()
            .map(|r| vec![r.id.to_lowercase()])
            .unwrap_or_default()
    });
    let history_gated = Signal::derive(move || zone_is_gated(&category_slug(), &load_zones()));
    // The topic's true reply count: the relay's count plus replies seen since
    // (live posts arrive through the channel list, so note them here).
    Effect::new(move |_| {
        let Some(key) = topic_list.get() else {
            return;
        };
        replies.with(|rs| {
            for r in rs {
                store.note_inserted(&key, &r.id, r.created_at);
            }
        });
    });
    let reply_total = Signal::derive(move || {
        let shown = replies.with(Vec::len) as u32;
        topic_list
            .get()
            .map_or(shown, |key| store.total_for(&key).max(shown))
    });

    // -- Landing position ---------------------------------------------------
    //
    // Opening a topic lands at the very bottom: the newest post with the reply
    // composer under it, since scrolling up to read back is easier than
    // hunting down. A `?focus=<event id>` deep link (search results,
    // notifications via `/go/:id`) centres that post instead and flashes it.
    // Replies stream in and media expands posts after first paint, so the pin
    // re-applies on every reply and every layout resize, loading or not,
    // until the ceiling (30 s from the first pin) or until the reader
    // scrolls, taps or types — then it never moves under them again. A
    // ceiling reached while the history is still loading owes one final pin
    // when it settles, if the reader has not touched the page.
    let query = use_query_map();
    let focus_param = move || query.read().get("focus");
    let landing = StoredValue::new(Landing::default());

    // Re-pin a moment after growth so the new layout has been painted
    // (`final_pin`: the one owed when history settles after the ceiling).
    let schedule_pin = move |final_pin: bool| {
        crate::utils::set_timeout_once(
            move || {
                let Some(state) = landing.try_get_value() else {
                    return;
                };
                if !state.may_pin(final_pin) {
                    return;
                }
                let Some((target, is_focus)) = state.target else {
                    return;
                };
                let flash = is_focus && !state.flashed;
                if flash {
                    landing.try_update_value(|l| l.flashed = true);
                }
                pin_landing(&target, is_focus, flash);
            },
            60,
        );
    };

    // Whether the topic's history is still arriving: the landing must not
    // settle on a quiet spell before it is in.
    let landing_history_settled = Memo::new(move |_| {
        let Some(cid) = resolved_channel.get().map(|c| c.id) else {
            return false;
        };
        let gated = zone_is_gated(&category_slug(), &load_zones());
        let topic = topic_list.get().map(|key| store.history_cursor(&key));
        history_settled(store.history_receipt(&cid).settles(gated), topic.as_ref())
    });

    Effect::new(move |_| {
        if loading.get() {
            return;
        }
        let Some(root) = topic_root.get() else { return };
        let reply_ids: Vec<String> = replies.get().iter().map(|r| r.id.clone()).collect();
        let settled = landing_history_settled.get();
        let focus = focus_param();
        let target = landing_target(focus.as_deref(), &root.id, &reply_ids);
        let now = js_sys::Date::now();
        let (repin, final_pin) = landing
            .try_update_value(|l| {
                if l.touched {
                    return (false, false);
                }
                l.target = target;
                let final_pin = l.note_history(settled);
                (l.grow(now), final_pin)
            })
            .unwrap_or((false, false));
        if repin || final_pin {
            schedule_pin(final_pin);
        }
    });

    // Layout growth (images, embeds, link previews, avatars) re-pins too.
    if let Some(body) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.body())
    {
        let on_resize = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
            let now = js_sys::Date::now();
            if landing.try_update_value(|l| l.grow(now)).unwrap_or(false) {
                schedule_pin(false);
            }
        });
        if let Ok(observer) = web_sys::ResizeObserver::new(on_resize.as_ref().unchecked_ref()) {
            observer.observe(&body);
            let guard = send_wrapper::SendWrapper::new((observer, on_resize));
            on_cleanup(move || {
                let (observer, on_resize) = guard.take();
                observer.disconnect();
                drop(on_resize);
            });
        }
    }

    // Any deliberate input by the reader ends the landing phase.
    let end_landing = move || {
        let now = js_sys::Date::now();
        landing.try_update_value(|l| l.reader_input(now));
    };
    let input_listeners = [
        window_event_listener(leptos::ev::wheel, move |_| end_landing()),
        window_event_listener(leptos::ev::touchmove, move |_| end_landing()),
        window_event_listener(leptos::ev::keydown, move |_| end_landing()),
        window_event_listener(leptos::ev::pointerdown, move |_| end_landing()),
    ];
    on_cleanup(move || input_listeners.into_iter().for_each(|h| h.remove()));

    // Section href (hashed) for breadcrumb back-link — REAL section name shown.
    let section_href = move || {
        match resolved_channel.get() {
            Some(ch) => section_path(&category_url_slug(), &ch.id),
            // Preserve whatever section param brought us here.
            None => format!("/{}/{}", category_url_slug(), section_param()),
        }
    };
    let section_name = move || {
        resolved_channel
            .get()
            .map(|c| c.name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Section".to_string())
    };
    let topic_title = move || {
        topic_root
            .get()
            .map(|r| first_line(&r.content))
            .unwrap_or_else(|| "Topic".to_string())
    };

    let is_authed = auth.is_authenticated();
    let restore_failed = RwSignal::<Option<String>>::new(None);

    // Quote-and-append: the post the next reply quotes (None = a plain reply to
    // the topic). Set by the "Reply" affordance on any post, shown as a chip
    // above the composer, cleared on send/dismiss. Replies always append to the
    // bottom — the target only decides which message is quoted and notified.
    let reply_target = RwSignal::<Option<ReplyTarget>>::new(None);

    // Reply composer → kind-42 e-tagging the topic root (NIP-10 root+reply).
    let relay_for_send = relay;
    let relay_for_edit = relay_for_send.clone();
    let relay_for_delete = relay_for_send.clone();

    // Admin gate for the delete affordance (author-or-admin; the relay is the
    // real boundary — see the kind-5 gate). `ZoneAccess::is_admin` is a signal.
    let is_admin = Signal::derive(move || zone_access.is_admin.get());
    // Captured during setup: the publish tasks below have no reactive owner.
    let zone_writer = crate::zone_crypto::store::ZoneWriter::capture();
    let do_send_reply = {
        let relay = relay_for_send;
        move |(content, mention_pubkeys): (String, Vec<String>)| {
            let root = match topic_root.get_untracked() {
                Some(r) => r,
                None => return,
            };
            let cid = match resolved_channel.get_untracked() {
                Some(ch) => ch.id,
                None => return,
            };
            let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
            if pubkey.is_empty() {
                toasts.show("Not authenticated".to_string(), ToastVariant::Error);
                return;
            }

            let original = content.clone();
            let now = (js_sys::Date::now() / 1000.0) as u64;
            // Quote-and-append: the reply appends at the bottom of the topic. If
            // the reader tapped "Reply" on a specific post, the NIP-10 reply
            // marker points at THAT post (quoted inline in the card) and its
            // author is notified; otherwise the reply parent is the topic root.
            let target = reply_target.get_untracked();
            // NIP-10: channel as root anchor, the TOPIC ROOT as the reply parent
            // (so the topic list folds it and the reply list matches it), notify
            // the topic-root author; a tapped sibling is quoted with a separate
            // "quote" marker and its author notified (client-core builds these
            // tags for the BBS too). Then mentions.
            let quote = target.as_ref().map(|t| (t.id.as_str(), t.pubkey.as_str()));
            let mut tags = topic_reply_tags(&cid, &root.id, &root.pubkey, quote);
            for pk in mention_pubkeys {
                if let Some(hex) = normalise_mention_pubkey(&pk) {
                    if !tags.iter().any(|t| t[0] == "p" && t[1] == hex) {
                        tags.push(vec!["p".to_string(), hex]);
                    }
                }
            }
            // Also resolve @handles typed directly into the reply (not picked
            // from the dropdown) so e.g. @junkiejarvis still gets a ["p", pubkey]
            // tag and the relay routes it to the agent's #p-filtered subscription.
            for hex in crate::components::mention_autocomplete::resolve_content_mentions(&content) {
                if !tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == hex)
                {
                    tags.push(vec!["p".to_string(), hex]);
                }
            }
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 42,
                tags,
                content,
            };
            // Consumed — the next reply defaults back to the topic unless the
            // reader taps "Reply" on another post.
            reply_target.set(None);

            let relay = relay.clone();
            spawn_local(async move {
                // Encrypted zone (ADR-2016): encrypt to the zone key, or refuse
                // without one and hand the draft back.
                let unsigned = match zone_writer.prepare(&cid, auth.get_signer(), unsigned).await {
                    Ok(u) => u,
                    Err(e) => {
                        toasts.show(e, ToastVariant::Error);
                        restore_failed.set(Some(original.clone()));
                        return;
                    }
                };
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        let original_for_ack = original.clone();
                        let on_ok = Rc::new(move |accepted: bool, message: String| {
                            if !accepted {
                                let reason = if let Some(why) =
                                    crate::zone_crypto::explain_relay_rejection(&message)
                                {
                                    why
                                } else if message.trim().is_empty() {
                                    "Reply rejected by relay".to_string()
                                } else {
                                    format!("Reply rejected: {message}")
                                };
                                toasts.show(reason, ToastVariant::Error);
                                restore_failed.set(Some(original_for_ack.clone()));
                            }
                        });
                        if let Err(e) = relay.publish_with_ack(&signed, Some(on_ok)) {
                            toasts.show(format!("Send failed: {e}"), ToastVariant::Error);
                            restore_failed.set(Some(original.clone()));
                        }
                    }
                    Err(e) => {
                        toasts.show(format!("Failed to sign reply: {e}"), ToastVariant::Error);
                        restore_failed.set(Some(original.clone()));
                    }
                }
            });
        }
    };
    let send_callback = Callback::new(do_send_reply);
    let noop_send = Callback::new(|_: String| {});

    // Tap "Reply" on any post → quote it, then bring the single bottom composer
    // into view. The reply still appends to the bottom of the topic
    // (quote-and-append), never nests.
    let on_reply = Callback::new(move |t: ReplyTarget| {
        reply_target.set(Some(t));
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id("thread-reply-composer"))
        {
            el.scroll_into_view();
        }
    });

    // -- Edit flow --------------------------------------------------------
    //
    // The id of the post currently being edited (original event id), or `None`.
    // Author-gated at the affordance level (only the post's author sees Edit).
    let editing_id = RwSignal::<Option<String>>::new(None);
    let my_pubkey = Signal::derive(move || auth.pubkey().get().unwrap_or_default());

    // Publish an edit: a kind-42 replacing `target_id` with `new_content`. The
    // edit re-anchors to the same channel root and reply parent so it stays in
    // the thread's event stream, and carries `["e", target_id, "", "edit"]` so
    // the render path folds it into the post being edited.
    let publish_edit = {
        let relay = relay_for_edit;
        Callback::new(move |(target_id, new_content): (String, String)| {
            let cid = match resolved_channel.get_untracked() {
                Some(ch) => ch.id,
                None => return,
            };
            let root = topic_root.get_untracked();
            let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
            if pubkey.is_empty() {
                toasts.show("Not authenticated".to_string(), ToastVariant::Error);
                return;
            }
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let cid_for_zone = cid.clone();
            // Channel root anchor (NIP-10), then the edit pointer. When editing a
            // reply we also keep the topic root as the reply parent so the edit
            // re-enters the same thread query; editing the root omits that.
            //
            // The topic author's `p` tag is preserved across the edit. A reply
            // carries `["p", root.pubkey]` when first published, and that p-tag
            // is what makes the reply reach its recipient: notification ingress
            // treats "addressed to me by name" as the signal that a channel-wide
            // read position does not cover this event. Rebuilding the tag list
            // without it made an edited reply invisible to the person it
            // answered. (Client-core builds these tags for the BBS too.)
            let root_ref = root.as_ref().map(|r| (r.id.as_str(), r.pubkey.as_str()));
            let mut tags = edit_tags(&cid, root_ref, &target_id);
            // Preserve @-mention routing on the edited content.
            for hex in
                crate::components::mention_autocomplete::resolve_content_mentions(&new_content)
            {
                if !tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == hex)
                {
                    tags.push(vec!["p".to_string(), hex]);
                }
            }
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 42,
                tags,
                content: new_content,
            };
            let relay = relay.clone();
            spawn_local(async move {
                // An edit in an encrypted zone is itself encrypted (ADR-2016):
                // the relay refuses a plaintext kind-42 there, edits included.
                let unsigned = match zone_writer
                    .prepare(&cid_for_zone, auth.get_signer(), unsigned)
                    .await
                {
                    Ok(u) => u,
                    Err(e) => {
                        toasts.show(e, ToastVariant::Error);
                        return;
                    }
                };
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        let on_ok = Rc::new(move |accepted: bool, message: String| {
                            if !accepted {
                                let reason = if let Some(why) =
                                    crate::zone_crypto::explain_relay_rejection(&message)
                                {
                                    why
                                } else if message.trim().is_empty() {
                                    "Edit rejected by relay".to_string()
                                } else {
                                    format!("Edit rejected: {message}")
                                };
                                toasts.show(reason, ToastVariant::Error);
                            } else {
                                toasts.show("Post edited".to_string(), ToastVariant::Success);
                            }
                        });
                        if let Err(e) = relay.publish_with_ack(&signed, Some(on_ok)) {
                            toasts.show(format!("Edit failed: {e}"), ToastVariant::Error);
                        }
                    }
                    Err(e) => {
                        toasts.show(format!("Failed to sign edit: {e}"), ToastVariant::Error);
                    }
                }
            });
            editing_id.set(None);
        })
    };

    // -- Delete flow ------------------------------------------------------
    //
    // Publish a NIP-09 kind-5 deletion for `target_id`. The relay gates WHO may
    // delete (own posts always; others' posts admin/TL3+); the store's kind-5
    // fold removes it when the relay echoes, and we optimistically remove on OK
    // so the deleter never waits on the echo. Author/admin gating happens at the
    // affordance level (`DeleteControls`).
    let publish_delete = {
        let relay = relay_for_delete;
        Callback::new(move |target_id: String| {
            let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
            if pubkey.is_empty() {
                toasts.show("Not authenticated".to_string(), ToastVariant::Error);
                return;
            }
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 5,
                tags: vec![vec!["e".to_string(), target_id.clone()]],
                content: String::new(),
            };
            let relay = relay.clone();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        let on_ok = Rc::new(move |accepted: bool, message: String| {
                            if accepted {
                                store.remove_message(&target_id);
                                toasts.show("Post deleted".to_string(), ToastVariant::Success);
                            } else {
                                let reason = if message.trim().is_empty() {
                                    "Delete rejected by relay".to_string()
                                } else {
                                    format!("Delete rejected: {message}")
                                };
                                toasts.show(reason, ToastVariant::Error);
                            }
                        });
                        if let Err(e) = relay.publish_with_ack(&signed, Some(on_ok)) {
                            toasts.show(format!("Delete failed: {e}"), ToastVariant::Error);
                        }
                    }
                    Err(e) => {
                        toasts.show(format!("Failed to sign deletion: {e}"), ToastVariant::Error);
                    }
                }
            });
        })
    };

    view! {
        <Show
            when=move || has_zone_access.get()
            fallback=move || view! { <AccessDenied zone_id=category_slug() /> }
        >
        // Carry the zone accent through to this page (#29): `:category` IS the
        // zone id, so expose its signature colour as `--zone-accent` on the root
        // (mirrors category.rs). The accent elements below read it via
        // `var(--zone-accent)`.
        <div class="max-w-4xl mx-auto p-4 sm:p-6" style=move || {
            let slug = category_slug();
            let zs = load_zones();
            let accent = crate::stores::zones::resolve_zone_param(&slug, &zs)
                .and_then(|z| z.accent_hex.clone());
            zone_accent_style_cfg(&slug, accent.as_deref())
        }>
            // Zone-first breadcrumb (ADR-107): single-locked-zone members drop
            // the global "Forums" crumb but keep the zone as the landing link;
            // everyone else keeps Home › Forums › {Zone} › {Section} › {Topic}.
            {move || {
                // `try_with`: this closure can re-run after the route has
                // disposed the page (see `history_loader::read_cursor`).
                let Some(slug) = params.try_with(|p| p.get("category").unwrap_or_default()) else {
                    return ().into_any();
                };
                let zone_label = category_display_name(&slug);
                let zone_href = format!("/{}", category_url_slug());
                let sec_name = section_name();
                let sec_href = section_href();
                let topic = topic_title();
                if za_breadcrumb.home_zone().is_some() {
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link(zone_label, zone_href),
                            BreadcrumbItem::link(sec_name, sec_href),
                            BreadcrumbItem::current(topic),
                        ] />
                    }
                    .into_any()
                } else {
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link("Forums", "/forums"),
                            BreadcrumbItem::link(zone_label, zone_href),
                            BreadcrumbItem::link(sec_name, sec_href),
                            BreadcrumbItem::current(topic),
                        ] />
                    }
                    .into_any()
                }
            }}

            // Topic heading: the breadcrumb alone is small grey text, so the
            // topic title and its section are repeated here, large and
            // wrapping, where a member looks first. While the topic is still
            // loading the title slot shows a muted placeholder instead of the
            // stand-in "Topic" the breadcrumb falls back to.
            {move || {
                // `try_with`: see the breadcrumb above.
                let loaded = topic_root.try_with(Option::is_some)?;
                let title = if loaded {
                    view! { <h1 class="topic-heading-title">{topic_title()}</h1> }.into_any()
                } else {
                    view! {
                        <h1 class="topic-heading-title topic-heading-placeholder">
                            "Loading topic\u{2026}"
                        </h1>
                    }
                    .into_any()
                };
                Some(view! {
                    <header class="topic-heading">
                        {title}
                        <p class="topic-heading-section">
                            "In section "
                            <A href=base_href(&section_href()) attr:class="za-hover-text">
                                {section_name()}
                            </A>
                        </p>
                    </header>
                })
            }}

            // `try_*` in the nested closures below: Leptos 0.7 drops them a
            // task hop after the route disposed this page, and a store write
            // in between re-runs them (see `history_loader::read_cursor`).
            {move || {
                let Some(loading) = loading.try_get() else {
                    return ().into_any();
                };
                if loading {
                    view! {
                        <div class="flex flex-col items-center justify-center py-20 gap-3">
                            <div class="animate-spin w-6 h-6 border-2 border-[color:var(--zone-accent)] border-t-transparent rounded-full"></div>
                            <span class="text-gray-400 text-sm">{move || if lookup.try_get() == Some(Lookup::KeysLoading) {
                                "Fetching your keys for this zone\u{2026}"
                            } else {
                                "Loading topic..."
                            }}</span>
                        </div>
                    }.into_any()
                } else if let Some((heading, detail)) = match lookup.get() {
                    Lookup::NotFound => Some((
                        "Topic Not Found",
                        "This topic could not be found in this section.",
                    )),
                    Lookup::TimedOut => Some((
                        "Topic Unavailable",
                        "This topic did not finish loading. Check your connection and try again.",
                    )),
                    Lookup::KeysTimedOut => Some((
                        "Topic Unavailable",
                        "Your keys for this zone could not all be fetched or checked: the relay or the admin check did not answer, or they are taking too long. Nothing here is missing for certain. Reload to try again.",
                    )),
                    Lookup::Loading | Lookup::KeysLoading | Lookup::Found => None,
                } {
                    let back = section_href();
                    view! {
                        <div class="glass-card p-8 text-center mt-4">
                            <h2 class="text-xl font-bold text-white mb-2">{heading}</h2>
                            <p class="text-gray-400 text-sm mb-4">{detail}</p>
                            <A href=base_href(&back) attr:class="text-[color:var(--zone-accent)] hover:opacity-80 text-sm underline">
                                "Back to section"
                            </A>
                        </div>
                    }.into_any()
                } else if let Some(root) = root_view.get() {
                    view! {
                        <RootPost
                            post=root
                            media_target=thread_media_target
                            my_pubkey=my_pubkey
                            editing_id=editing_id
                            on_save_edit=publish_edit
                            on_reply=on_reply
                            can_reply=is_authed.into()
                            is_admin=is_admin
                            on_delete=publish_delete
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            // Replies
            <Show when=move || {
                topic_root.try_with(Option::is_some).unwrap_or(false) && loading.try_get() == Some(false)
            }>
                <div class="mt-6">
                    <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
                        {move || {
                            let n = reply_total.try_get().unwrap_or_default();
                            if n == 0 {
                                "No replies yet".to_string()
                            } else if n == 1 {
                                "1 reply".to_string()
                            } else {
                                format!("{n} replies")
                            }
                        }}
                    </h3>
                    <div class="space-y-3">
                        // Keyed: a new page or post renders only its own
                        // cards, and a card re-renders when what it shows
                        // changes (an edit, a decrypt, a resolved quote).
                        // Bounded history window: older replies load above
                        // the list as the reader scrolls up, evicted newer
                        // ones below it on the way back down.
                        <crate::components::history_loader::HistoryLoader
                            channel_id=history_cid
                            gated=history_gated
                            label="Load older replies"
                            needles=history_needles
                        />
                        <For
                            each=move || replies.try_get().unwrap_or_default()
                            key=|r| (r.id.clone(), view_key(r))
                            children=move |r| view! {
                                <ReplyCard
                                    reply=r
                                    media_target=thread_media_target
                                    my_pubkey=my_pubkey
                                    editing_id=editing_id
                                    on_save_edit=publish_edit
                                    on_reply=on_reply
                                    can_reply=is_authed.into()
                                    is_admin=is_admin
                                    on_delete=publish_delete
                                />
                            }
                        />
                        <crate::components::history_loader::HistoryLoader
                            channel_id=history_cid
                            gated=history_gated
                            label="Load newer replies"
                            direction=crate::components::history_loader::HistoryDirection::Newer
                            needles=history_needles
                        />
                    </div>
                </div>
            </Show>

            // Reply composer (always appends at the bottom; shows a quote chip
            // when the reader tapped "Reply" on a specific post).
            <Show when=move || {
                is_authed.try_get().unwrap_or(false)
                    && topic_root.try_with(Option::is_some).unwrap_or(false)
                    && loading.try_get() == Some(false)
            }>
                <div id="thread-reply-composer" class="mt-6 bg-gray-800 border border-gray-700 rounded-lg p-3">
                    {move || reply_target.get().map(|t| view! {
                        <div class="flex items-center gap-2 mb-2 px-2 py-1.5 rounded bg-gray-900/60 border-l-2 border-[color:var(--zone-accent)] text-xs">
                            <span class="text-gray-400 shrink-0">"Replying to"</span>
                            <span class="text-[color:var(--zone-accent)] font-medium shrink-0">{t.author.clone()}</span>
                            <span class="text-gray-500 truncate flex-1 min-w-0 italic">{t.snippet.clone()}</span>
                            <button
                                class="text-gray-500 hover:text-gray-300 shrink-0 px-1"
                                aria-label="Cancel reply target"
                                on:click=move |_| reply_target.set(None)
                            >"\u{2715}"</button>
                        </div>
                    })}
                    <MessageInput
                        on_send=noop_send
                        on_send_with_mentions=send_callback
                        enable_image_upload=true
                        media_target=thread_media_target
                        restore_failed=restore_failed
                    />
                </div>
            </Show>
        </div>
        </Show>
    }
}

/// Extract bare http(s) URLs from post text (mirrors message_bubble.rs).
fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for word in text.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '[' || c == ']' || c == '<' || c == '>' || c == ','
        });
        if (trimmed.starts_with("https://") || trimmed.starts_with("http://")) && trimmed.len() > 10
        {
            urls.push(trimmed.to_string());
        }
    }
    urls
}

/// Whether a URL is an inline-media resource (image, direct video, or YouTube).
fn is_media_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    let media_exts = [
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".mp4", ".webm", ".ogg", ".ogv", ".mov",
        ".m4v",
    ];
    for ext in &media_exts {
        if path.ends_with(ext) {
            return true;
        }
    }
    lower.contains("youtube.com/watch") || lower.contains("youtu.be/")
}

/// Body of a post: mention-rendered text, inline media embeds for media URLs,
/// and a link-preview card for the first non-media URL.
#[component]
fn PostBody(
    content: String,
    /// The post's own tags. `MentionText` resolves a typed `@handle` to a
    /// pubkey by pairing it with the event's `["p", pubkey]` tags; without them
    /// it falls back to the NameCache and, failing that, renders the mention as
    /// plain text. Forum posts were rendered WITHOUT their tags, so a mention
    /// of anyone not already cached in this session degraded to grey text
    /// instead of a link — "can't @ other members in posts", from the reader's
    /// side rather than the writer's.
    #[prop(optional, into)]
    tags: Option<Vec<Vec<String>>>,
) -> impl IntoView {
    let urls = extract_urls(&content);
    let (media_urls, link_urls): (Vec<_>, Vec<_>) = urls.into_iter().partition(|u| is_media_url(u));
    // No link preview for a zone-encrypted post (ADR-2016): fetching one would
    // hand the URL to the preview worker, outside the zone. The `zk` tag
    // survives decryption, so the post's own tags say whether it was sealed.
    let zone_encrypted = tags.as_deref().is_some_and(crate::zone_crypto::has_zk_tag);
    let first_link = if zone_encrypted {
        None
    } else {
        link_urls.into_iter().next()
    };
    // Hide embedded media URLs from the visible text — the embed below (with its
    // own hover "open full" icon) is the representation.
    let text = crate::components::mention_text::strip_media_urls(&content, &media_urls);
    let tags = tags.unwrap_or_default();
    view! {
        <>
            {(!text.is_empty()).then(|| view! { <MentionText content=text tags=tags /> })}
            {media_urls
                .into_iter()
                .enumerate()
                .map(|(position, u)| view! { <MediaEmbed url=u position=position /> })
                .collect_view()}
            {first_link.map(|u| view! { <LinkPreview url=u /> })}
        </>
    }
}

/// Whether the signed-in member (`my_pubkey`, hex; empty while signed out)
/// wrote the post signed by `post_pubkey`.
fn is_own_post(my_pubkey: &str, post_pubkey: &str) -> bool {
    !my_pubkey.is_empty() && my_pubkey.eq_ignore_ascii_case(post_pubkey)
}

/// Whether a reply card mounts its per-card controls (edit, delete, tip).
/// Others' posts wait for the reader to engage with the card; the reader's
/// own posts never do, so a just-sent post shows Edit and Delete at once.
fn reply_controls_shown(engaged: bool, editing: bool, own: bool) -> bool {
    engaged || editing || own
}

/// Author-only edit affordance: an inline pencil button that opens the composer
/// in-place for `post_id`. Returns nothing when the viewer is not the author.
#[component]
fn EditControls(
    post_id: String,
    post_pubkey: String,
    my_pubkey: Signal<String>,
    editing_id: RwSignal<Option<String>>,
) -> impl IntoView {
    let pid = post_id.clone();
    let is_author = Signal::derive(move || is_own_post(&my_pubkey.get(), &post_pubkey));
    let pid_click = pid.clone();
    move || {
        if !is_author.get() {
            return None;
        }
        let pid = pid_click.clone();
        Some(view! {
            <button
                class="ml-auto opacity-60 hover:opacity-100 text-xs text-gray-400 hover:text-[color:var(--zone-accent)] transition-colors flex items-center gap-1"
                title="Edit post"
                on:click=move |_| editing_id.set(Some(pid.clone()))
            >
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                "Edit"
            </button>
        })
    }
}

/// Delete affordance: a quiet trash button shown when the viewer is the post's
/// author OR an admin. Opens a [`ConfirmDialog`] (deletion is permanent and
/// removes the post for everyone; a topic ROOT additionally warns that its
/// replies become unreachable) and fires `on_delete` with the post id.
#[component]
fn DeleteControls(
    post_id: String,
    post_pubkey: String,
    /// The topic ROOT deletes the whole topic — the confirm copy warns so.
    is_root: bool,
    my_pubkey: Signal<String>,
    is_admin: Signal<bool>,
    on_delete: Callback<String>,
) -> impl IntoView {
    let can_delete =
        Signal::derive(move || is_admin.get() || is_own_post(&my_pubkey.get(), &post_pubkey));
    let show_confirm = RwSignal::new(false);
    let pid = StoredValue::new(post_id);
    let on_confirm = Callback::new(move |()| on_delete.run(pid.get_value()));
    let (dialog_title, dialog_message) = if is_root {
        (
            "Delete topic".to_string(),
            "Delete this topic? This is permanent and removes it for everyone. \
             Its replies will become unreachable."
                .to_string(),
        )
    } else {
        (
            "Delete post".to_string(),
            "Delete this post? This is permanent and removes it for everyone.".to_string(),
        )
    };

    view! {
        <Show when=move || can_delete.get()>
            <button
                class="ml-auto opacity-60 hover:opacity-100 text-xs text-gray-500 hover:text-red-400 transition-colors flex items-center gap-1"
                title="Delete post"
                on:click=move |_| show_confirm.set(true)
            >
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m2 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6M10 11v6M14 11v6" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                "Delete"
            </button>
            <ConfirmDialog
                is_open=show_confirm
                title=dialog_title.clone()
                message=dialog_message.clone()
                confirm_label="Delete".to_string()
                on_confirm=on_confirm
            />
        </Show>
    }
}

/// The topic root post, rendered prominently at the top of the thread.
#[component]
fn RootPost(
    post: ReplyView,
    my_pubkey: Signal<String>,
    editing_id: RwSignal<Option<String>>,
    on_save_edit: Callback<(String, String)>,
    on_reply: Callback<ReplyTarget>,
    can_reply: Signal<bool>,
    is_admin: Signal<bool>,
    on_delete: Callback<String>,
    /// Pod container for an image attached while editing (the channel zone).
    media_target: Signal<crate::utils::restricted_media::MediaTarget>,
) -> impl IntoView {
    let author_pk = post.pubkey.clone();
    // The name as a string, for the composer's quote line.
    let author = use_display_name_memo(post.pubkey.clone());
    // Quote-and-append: tapping Reply focuses the bottom composer. A StoredValue
    // keeps the target Copy so the inline on:click handler stays `Fn`.
    let reply_info = StoredValue::new((
        post.id.clone(),
        post.pubkey.clone(),
        first_line(&post.content),
    ));
    let time = format_relative_time(post.created_at);
    let pk = post.pubkey.clone();
    // Disclosure badge (COM-13/F2): marks the topic-root author as an agent.
    let author_badge_pubkey = post.pubkey.clone();
    let content = post.content.clone();
    // Carried into PostBody so typed @handles resolve against this post's p-tags.
    let tags = post.tags.clone();
    let edited = post.edited;
    let post_id = post.id.clone();
    let post_pubkey = post.pubkey.clone();
    // NIP-25 reaction bar targets: the topic-root event id + its author.
    let react_id = post.id.clone();
    let react_pk = post.pubkey.clone();

    let is_editing = {
        let pid = post_id.clone();
        Signal::derive(move || editing_id.get().as_deref() == Some(pid.as_str()))
    };
    let edit_initial = content.clone();
    let edit_target_id = post_id.clone();
    let save_edit = Callback::new(move |(text, _mentions): (String, Vec<String>)| {
        on_save_edit.run((edit_target_id.clone(), text));
    });
    let cancel_edit = Callback::new(move |()| editing_id.set(None));
    let noop = Callback::new(|_: String| {});

    view! {
        // Topic-root card: its frame is the most prominent accent on the thread
        // page, so it wears the zone colour (#29) via the inherited
        // `--zone-accent` custom property set on the page root.
        <article
            id=post_anchor_id(&post.id)
            class="bg-gray-800/70 border rounded-xl p-5 mt-4 scroll-mt-20 transition-shadow"
            style="border-color:color-mix(in srgb, var(--zone-accent) 25%, transparent)"
        >
            <div class="flex items-start gap-3">
                <Avatar pubkey=pk size=AvatarSize::Lg />
                <div class="flex-1 min-w-0">
                    <div class="flex items-baseline gap-2 flex-wrap">
                        <span class="font-semibold text-[color:var(--zone-accent)]"><KeyName pubkey=author_pk key_class="font-mono" /></span>
                        <AgentBadge pubkey=author_badge_pubkey compact=true />
                        <span class="text-xs text-gray-500">{time}</span>
                        {edited.then(|| view! {
                            <span class="text-xs text-gray-600 italic">"(edited)"</span>
                        })}
                        <EditControls
                            post_id=post_id.clone()
                            post_pubkey=post_pubkey.clone()
                            my_pubkey=my_pubkey
                            editing_id=editing_id
                        />
                        <DeleteControls
                            post_id=post_id.clone()
                            post_pubkey=post_pubkey.clone()
                            is_root=true
                            my_pubkey=my_pubkey
                            is_admin=is_admin
                            on_delete=on_delete
                        />
                        // The reply row: Reply, then tips at the far right
                        // (ADR-2021), away from the emoji reactions below.
                        <div class="ml-auto flex items-center gap-3">
                            <Show when=move || can_reply.get()>
                                <button
                                    class="text-xs text-gray-500 hover:text-[color:var(--zone-accent)] transition-colors"
                                    on:click=move |_: leptos::ev::MouseEvent| {
                                        let (id, pubkey, snippet) = reply_info.get_value();
                                        on_reply.run(ReplyTarget { id, pubkey, author: author.get_untracked(), snippet });
                                    }
                                    aria-label="Reply to this topic"
                                >"\u{21A9} Reply"</button>
                            </Show>
                            <TipControl event_id=post_id.clone() author_pubkey=post_pubkey.clone() open_down=true />
                        </div>
                    </div>
                    <Show
                        when=move || is_editing.get()
                        fallback={
                            let content = content.clone();
                            let tags = tags.clone();
                            move || view! {
                                <div class="text-gray-200 mt-2 leading-relaxed whitespace-pre-wrap break-words">
                                    <PostBody content=content.clone() tags=tags.clone() />
                                </div>
                            }
                        }
                    >
                        <div class="mt-2">
                            <MessageInput
                                on_send=noop
                                on_send_with_mentions=save_edit
                                initial_content=edit_initial.clone()
                                is_editing=true
                                enable_image_upload=true
                                media_target=media_target
                                on_cancel_edit=cancel_edit
                            />
                        </div>
                    </Show>
                    // NIP-25 emoji reactions on the topic root.
                    <ReactionBar event_id=react_id author_pubkey=react_pk />
                </div>
            </div>
        </article>
    }
}

/// A single reply card in the thread.
#[component]
fn ReplyCard(
    reply: ReplyView,
    my_pubkey: Signal<String>,
    editing_id: RwSignal<Option<String>>,
    on_save_edit: Callback<(String, String)>,
    on_reply: Callback<ReplyTarget>,
    can_reply: Signal<bool>,
    is_admin: Signal<bool>,
    on_delete: Callback<String>,
    /// Pod container for an image attached while editing (the channel zone).
    media_target: Signal<crate::utils::restricted_media::MediaTarget>,
) -> impl IntoView {
    let author_pk = reply.pubkey.clone();
    // The name as a string, for the composer's quote line.
    let author = use_display_name_memo(reply.pubkey.clone());
    // Quote-and-append: tapping Reply quotes THIS post and focuses the composer.
    // StoredValue keeps the target Copy so the inline on:click handler stays `Fn`.
    let reply_info = StoredValue::new((
        reply.id.clone(),
        reply.pubkey.clone(),
        first_line(&reply.content),
    ));
    // Inline quote of the sibling this reply targets (never the topic root).
    let quote = reply.quote.clone();
    let time = format_relative_time(reply.created_at);
    let pk = reply.pubkey.clone();
    // Disclosure badge (COM-13/F2): marks the reply author as an agent.
    let author_badge_pubkey = reply.pubkey.clone();
    let content = reply.content.clone();
    // Carried into PostBody so typed @handles resolve against this reply's p-tags.
    let tags = reply.tags.clone();
    let edited = reply.edited;
    let post_id = reply.id.clone();
    let post_pubkey = reply.pubkey.clone();
    // NIP-25 reaction bar targets: this reply's event id + its author.
    let react_id = reply.id.clone();
    let react_pk = reply.pubkey.clone();

    let is_editing = {
        let pid = post_id.clone();
        Signal::derive(move || editing_id.get().as_deref() == Some(pid.as_str()))
    };
    let edit_initial = content.clone();
    let edit_target_id = post_id.clone();
    let save_edit = Callback::new(move |(text, _mentions): (String, Vec<String>)| {
        on_save_edit.run((edit_target_id.clone(), text));
    });
    let cancel_edit = Callback::new(move |()| editing_id.set(None));
    let noop = Callback::new(|_: String| {});

    // The per-card controls (edit, delete, tip) mount only once the reader
    // engages with the card (hover, keyboard focus or a tap), then stay: a
    // thread window holds up to THREAD_WINDOW cards and most are only read.
    // An open edit keeps them mounted, and so does authorship: the reader's
    // own post may appear (or remount on a decrypt) under a resting pointer
    // that never fires `mouseenter`.
    let engaged = RwSignal::new(false);
    let own_pubkey = post_pubkey.clone();
    let is_own = Signal::derive(move || is_own_post(&my_pubkey.get(), &own_pubkey));
    let controls_shown =
        move || reply_controls_shown(engaged.get(), is_editing.get(), is_own.get());
    let edit_post_id = post_id.clone();
    let edit_post_pubkey = post_pubkey.clone();
    let delete_post_id = post_id.clone();
    let delete_post_pubkey = post_pubkey.clone();
    let tip_post_id = post_id.clone();
    let tip_post_pubkey = post_pubkey.clone();
    view! {
        <div
            id=post_anchor_id(&post_id)
            data-anchor-id=post_id.clone()
            class="bg-gray-800/40 border border-gray-700/50 rounded-lg p-4 scroll-mt-20 transition-shadow"
            on:mouseenter=move |_| engaged.set(true)
            on:focusin=move |_| engaged.set(true)
            on:touchstart=move |_| engaged.set(true)
        >
            <div class="flex items-start gap-3">
                <Avatar pubkey=pk size=AvatarSize::Sm />
                <div class="flex-1 min-w-0">
                    <div class="flex items-baseline gap-2 flex-wrap">
                        <span class="font-semibold text-sm text-[color:var(--zone-accent)]"><KeyName pubkey=author_pk key_class="font-mono" /></span>
                        <AgentBadge pubkey=author_badge_pubkey compact=true />
                        <span class="text-xs text-gray-600">{time}</span>
                        {edited.then(|| view! {
                            <span class="text-xs text-gray-600 italic">"(edited)"</span>
                        })}
                        <Show when=controls_shown>
                            <EditControls
                                post_id=edit_post_id.clone()
                                post_pubkey=edit_post_pubkey.clone()
                                my_pubkey=my_pubkey
                                editing_id=editing_id
                            />
                            <DeleteControls
                                post_id=delete_post_id.clone()
                                post_pubkey=delete_post_pubkey.clone()
                                is_root=false
                                my_pubkey=my_pubkey
                                is_admin=is_admin
                                on_delete=on_delete
                            />
                        </Show>
                        // The reply row: Reply, then tips at the far right
                        // (ADR-2021), away from the emoji reactions below.
                        <div class="ml-auto flex items-center gap-3">
                            <Show when=move || can_reply.get()>
                                <button
                                    class="text-xs text-gray-600 hover:text-[color:var(--zone-accent)] transition-colors"
                                    on:click=move |_: leptos::ev::MouseEvent| {
                                        let (id, pubkey, snippet) = reply_info.get_value();
                                        on_reply.run(ReplyTarget { id, pubkey, author: author.get_untracked(), snippet });
                                    }
                                    aria-label="Reply to this post"
                                >"\u{21A9} Reply"</button>
                            </Show>
                            <Show when=controls_shown>
                                <TipControl event_id=tip_post_id.clone() author_pubkey=tip_post_pubkey.clone() open_down=true />
                            </Show>
                        </div>
                    </div>
                    {quote.map(|q| {
                        view! {
                            <div class="mt-1 mb-0.5 pl-2 border-l-2 border-gray-600 text-xs text-gray-500 truncate">
                                <span class="text-[color:var(--zone-accent)] opacity-80"><KeyName pubkey=q.pubkey.clone() key_class="font-mono" /></span>
                                ": "
                                <span class="italic">{q.snippet.clone()}</span>
                            </div>
                        }
                    })}
                    <Show
                        when=move || is_editing.get()
                        fallback={
                            let content = content.clone();
                            let tags = tags.clone();
                            move || view! {
                                <div class="text-sm text-gray-300 mt-1 leading-relaxed whitespace-pre-wrap break-words">
                                    <PostBody content=content.clone() tags=tags.clone() />
                                </div>
                            }
                        }
                    >
                        <div class="mt-2">
                            <MessageInput
                                on_send=noop
                                on_send_with_mentions=save_edit
                                initial_content=edit_initial.clone()
                                is_editing=true
                                enable_image_upload=true
                                media_target=media_target
                                on_cancel_edit=cancel_edit
                            />
                        </div>
                    </Show>
                    // NIP-25 emoji reactions on this reply.
                    <ReactionBar event_id=react_id author_pubkey=react_pk />
                </div>
            </div>
        </div>
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_media_url_classifies_correctly() {
        assert!(is_media_url("https://pod.example.com/a/photo.jpg"));
        assert!(is_media_url("https://pod.example.com/a/clip.mp4?v=2"));
        assert!(is_media_url("https://youtu.be/abc123"));
        assert!(!is_media_url("https://example.com/article"));
    }

    // ── Own-post controls (Edit/Delete on a just-sent post) ─────────────────

    #[test]
    fn own_post_is_judged_by_pubkey_case_insensitively() {
        let me = "ab".repeat(32);
        assert!(is_own_post(&me, &me));
        assert!(is_own_post(&me.to_uppercase(), &me));
        assert!(!is_own_post(&me, &"cd".repeat(32)));
        assert!(!is_own_post("", ""), "signed out owns nothing");
        assert!(!is_own_post("", &me));
    }

    #[test]
    fn own_posts_show_their_controls_without_engagement() {
        // A just-sent post can mount (or remount, when a decrypt or resolved
        // quote changes its list key) under a resting pointer, so no
        // `mouseenter` ever arrives: the author's own controls must not wait
        // for one.
        assert!(reply_controls_shown(false, false, true));
        assert!(reply_controls_shown(true, false, false));
        assert!(reply_controls_shown(false, true, false));
        assert!(
            !reply_controls_shown(false, false, false),
            "others' posts stay lazy"
        );
    }
}
