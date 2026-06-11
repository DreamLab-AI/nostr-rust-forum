//! Section page -- messages within a specific forum section.
//! Route: /forums/:category/:section
//!
//! Messages are sourced exclusively from the shared `ChannelStore` — the same
//! global kind-40 / kind-42 subscriptions that drive the Forums index tiles.
//! This eliminates the previous local two-stage subscription, which raced the
//! NIP-42 AUTH handshake: an unauthenticated reader is zone-filtered to public
//! zones, so the friends/family/business kind-40 def never arrived, the local
//! `section_info` stayed `None`, and the gated kind-42 sub never started.
//! By reading from the store (which subscribes ONCE at app root and survives
//! the AUTH replay), the page is independent of AUTH timing.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use std::rc::Rc;

use wasm_bindgen_futures::spawn_local;

use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::mention_text::normalise_mention_pubkey;
use crate::components::message_bubble::{MessageBubble, MessageData};
use crate::components::message_input::MessageInput;
use crate::components::reaction_bar::Reaction;
use crate::components::swipeable_message::SwipeableMessage;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::typing_indicator::TypingIndicator;
use crate::relay::RelayConnection;
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, Zone, ZoneVisibility};
use crate::utils::{capitalize, set_timeout_once};

/// Map a zone slug to its display name. Config-driven: resolves against the
/// live `ZONE_CONFIG` zone list, falling back to a capitalised slug for unknown
/// zones. Bug #22: avoid showing URL slug "Private" when the zone has a
/// configured display name.
fn category_display_name(slug: &str) -> String {
    load_zones()
        .into_iter()
        .find(|z| z.id == slug)
        .map(|z| z.label())
        .unwrap_or_else(|| capitalize(slug))
}

/// Humanise a section slug for breadcrumb display. `home-lobby` → `Lobby`.
/// Bug #24: avoid breadcrumb leaf reading `Home-lobby` (kebab-cased URL).
fn humanize_section_slug(slug: &str) -> String {
    let suffix = slug.split_once('-').map(|(_, s)| s).unwrap_or(slug);
    suffix
        .split('-')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Resolve the channel `section` tag to the id of the owning config zone.
///
/// Mirrors `forums.rs::section_to_zone`: exact id match, then `<zone-id>-`
/// prefix match, then the first zone as a catch-all so channels never silently
/// disappear from routing.
fn section_to_zone(section: &str, zones: &[Zone]) -> Option<String> {
    let sec = section.to_lowercase();
    if let Some(z) = zones.iter().find(|z| z.id.to_lowercase() == sec) {
        return Some(z.id.clone());
    }
    if let Some(z) = zones
        .iter()
        .find(|z| sec.starts_with(&format!("{}-", z.id.to_lowercase())))
    {
        return Some(z.id.clone());
    }
    zones.first().map(|z| z.id.clone())
}

/// Slugify a channel name the same way the route slug is generated.
fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Find the channel whose section/name maps to `(category_slug, section_slug)`,
/// using the SAME config-zone logic the Forums index uses.
///
/// A channel matches when its `section` tag routes to the requested category
/// zone (or the category is empty) AND its `section` tag equals the section
/// slug, OR its name/name-slug equals the section slug, OR its id is prefixed
/// by the slug (deep-link by id-prefix). This re-implements the resolution the
/// old local kind-40 handler did, but against the already-populated store.
fn resolve_channel(
    channels: &[ChannelMeta],
    category_slug: &str,
    section_slug: &str,
    zones: &[Zone],
) -> Option<ChannelMeta> {
    let cat = category_slug.to_lowercase();
    let sec = section_slug.to_lowercase();
    channels
        .iter()
        .find(|c| {
            let routes_to_category = cat.is_empty()
                || section_to_zone(&c.section, zones)
                    .map(|z| z.to_lowercase() == cat)
                    .unwrap_or(false);
            let section_matches = c.section.to_lowercase() == sec
                || slugify(&c.name) == section_slug
                || c.name.to_lowercase() == sec
                || c.id.starts_with(section_slug);
            routes_to_category && section_matches
        })
        .cloned()
}

/// Convert a stored kind-42 [`NostrEvent`] into the page's [`MessageData`].
fn event_to_message(event: &nostr_bbs_core::NostrEvent) -> MessageData {
    let reply_to = event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "reply")
        .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
        .map(|t| t[1].clone());
    let reply_pk = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].clone());
    MessageData {
        id: event.id.clone(),
        pubkey: event.pubkey.clone(),
        content: event.content.clone(),
        created_at: event.created_at,
        reply_to_id: reply_to,
        reply_to_pubkey: reply_pk,
        reply_to_content: None,
        reactions: RwSignal::new(Vec::<Reaction>::new()),
        is_hidden: false,
        channel_id: String::new(),
        thread_replies: RwSignal::new(Vec::new()),
    }
}

#[component]
pub fn SectionPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let store = use_channel_store();
    let zone_access = use_zone_access();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();
    let section_slug = move || params.read().get("section").unwrap_or_default();

    // Zone access gate: the category slug IS the zone ID. Config-driven —
    // resolves against the live zone list. A public zone is always readable;
    // otherwise membership (admin OR matching cohort) is required. Unknown
    // zones default to accessible so relay-created channels never 403 the
    // client UX (the relay remains the real boundary, ADR-022).
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        match load_zones().into_iter().find(|z| z.id == cat) {
            Some(zone) => {
                zone.visibility == ZoneVisibility::Public || zone_access.is_member_of(&zone)
            }
            None => true,
        }
    });

    // Resolve the channel for this route reactively from the shared store. The
    // store's broad kind-40 sub survives the AUTH replay, so a friends/family/
    // business channel resolves here regardless of when AUTH completed.
    //
    // `Signal::derive` (not `Memo`) because `ChannelMeta` is not `PartialEq`.
    let resolved_channel = Signal::derive(move || {
        let chans = store.channels.get();
        let zones = load_zones();
        resolve_channel(&chans, &category_slug(), &section_slug(), &zones)
    });

    // Top up the per-channel subscription once the channel id is known, so a
    // channel the broad kind-42 sub hasn't yet covered still loads its history.
    {
        let relay = relay.clone();
        Effect::new(move |_| {
            if let Some(ch) = resolved_channel.get() {
                store.ensure_subscribed(&relay, &ch.id);
            }
        });
    }

    // Messages rendered reactively from the shared channel_messages map. Dedup
    // and created_at sort are already maintained by the store; we re-sort
    // defensively after mapping so render order is deterministic.
    //
    // `Signal::derive` (not `Memo`) because `MessageData` holds `RwSignal`
    // fields and is therefore not `PartialEq`.
    let messages = Signal::derive(move || {
        let cid = match resolved_channel.get() {
            Some(ch) => ch.id,
            None => return Vec::<MessageData>::new(),
        };
        store.channel_messages.with(|m| {
            let mut msgs: Vec<MessageData> = m
                .get(&cid)
                .map(|events| events.iter().map(event_to_message).collect())
                .unwrap_or_default();
            msgs.sort_by_key(|x| x.created_at);
            msgs
        })
    });

    // Loading is true while the global store is still fetching AND we have not
    // resolved a channel yet. Once the store finishes (eose/loading=false) or a
    // channel resolves, the empty-state can render honestly.
    let store_loading = store.loading;
    let loading = Memo::new(move |_| store_loading.get() && resolved_channel.get().is_none());

    let error_msg = RwSignal::<Option<String>>::new(None);
    let typing_pubkeys = RwSignal::new(Vec::<String>::new());
    let messages_container = NodeRef::<leptos::html::Div>::new();
    let relay_for_send = relay;

    // Resolve the toast store at component construction (calling use_toasts()
    // inside the async send closure would panic — the reactive owner is gone).
    let toasts = use_toasts();
    // Restore channel: a rejected publish pushes the failed text back here so
    // MessageInput can re-fill the textarea (content is never lost on failure).
    let restore_failed = RwSignal::<Option<String>>::new(None);

    // Surface relay NOTICEs (e.g. rate-limit / policy messages) as warn toasts.
    // The relay layer already rate-limits duplicate notice text; `seq` makes
    // each surfaced notice distinct so none are missed.
    let notices = relay_for_send.notices();
    Effect::new(move |prev: Option<u64>| {
        let current = notices.get();
        let seq = current.as_ref().map(|n| n.seq).unwrap_or(0);
        if let Some(notice) = current {
            // Skip the initial None→first read only when it is genuinely new.
            if prev != Some(notice.seq) {
                toasts.show(notice.message, ToastVariant::Warning);
            }
        }
        seq
    });

    // Auto-scroll to the latest message whenever the count changes.
    Effect::new(move |_| {
        let _count = messages.get().len();
        if let Some(container) = messages_container.get() {
            let el: web_sys::HtmlElement = container.into();
            set_timeout_once(
                move || {
                    el.set_scroll_top(el.scroll_height());
                },
                50,
            );
        }
    });

    let do_send_text = {
        let relay = relay_for_send;
        move |(content, mention_pubkeys): (String, Vec<String>)| {
            let cid = resolved_channel
                .get_untracked()
                .map(|ch| ch.id)
                .unwrap_or_default();
            if cid.is_empty() {
                return;
            }

            let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
            if pubkey.is_empty() {
                error_msg.set(Some("Not authenticated".to_string()));
                return;
            }

            // Keep the original text so a rejected publish can restore it.
            let original = content.clone();

            let now = (js_sys::Date::now() / 1000.0) as u64;
            // Root e-tag first, then one ["p", pubkey] per @-mention selected
            // in the composer so mentioned users are addressable per NIP-10.
            let mut tags = vec![vec![
                "e".to_string(),
                cid,
                String::new(),
                "root".to_string(),
            ]];
            for pk in mention_pubkeys {
                if let Some(hex) = normalise_mention_pubkey(&pk) {
                    if !tags.iter().any(|t| t[0] == "p" && t[1] == hex) {
                        tags.push(vec!["p".to_string(), hex]);
                    }
                }
            }
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 42,
                tags,
                content,
            };

            let relay = relay.clone();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        // Publish WITH ack so relay rejections (e.g. zone access
                        // denied) surface to the user instead of vanishing.
                        let original_for_ack = original.clone();
                        let on_ok = Rc::new(move |accepted: bool, message: String| {
                            if !accepted {
                                let reason = if message.trim().is_empty() {
                                    "Message rejected by relay".to_string()
                                } else {
                                    format!("Message rejected: {message}")
                                };
                                toasts.show(reason, ToastVariant::Error);
                                // Re-fill the composer — do not lose the text.
                                restore_failed.set(Some(original_for_ack.clone()));
                            }
                        });
                        if let Err(e) = relay.publish_with_ack(&signed, Some(on_ok)) {
                            toasts.show(format!("Send failed: {e}"), ToastVariant::Error);
                            restore_failed.set(Some(original.clone()));
                        }
                    }
                    Err(e) => {
                        toasts.show(format!("Failed to sign message: {e}"), ToastVariant::Error);
                        restore_failed.set(Some(original.clone()));
                    }
                }
            });
        }
    };

    let send_callback = Callback::new(do_send_text);
    // MessageInput fires `on_send` alongside `on_send_with_mentions`; all
    // publish work lives in the mentions path, so the plain path is a no-op.
    let noop_send = Callback::new(|_: String| {});
    let is_authed = auth.is_authenticated();

    // Header name/description sourced from the resolved channel.
    let header_name = move || {
        resolved_channel
            .get()
            .map(|c| c.name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| humanize_section_slug(&section_slug()))
    };
    let header_desc = move || resolved_channel.get().map(|c| c.description);

    view! {
        <Show
            when=move || has_zone_access.get()
            fallback=move || view! {
                <AccessDenied zone_id=category_slug() />
            }
        >
        <div class="flex flex-col h-[calc(100vh-64px)]">
            <div class="bg-gray-800 border-b border-gray-700 relative">
                <div class="absolute inset-0 bg-gradient-to-r from-amber-500/5 via-transparent to-purple-500/5"></div>
                <div class="relative p-4">
                    <div class="max-w-4xl mx-auto">
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link("Forums", "/forums"),
                            BreadcrumbItem::link(
                                category_display_name(&category_slug()),
                                format!("/forums/{}", category_slug()),
                            ),
                            BreadcrumbItem::current(header_name()),
                        ] />

                        <h1 class="text-2xl font-bold text-white">
                            {header_name}
                        </h1>
                        {move || header_desc().and_then(|d| {
                            if d.is_empty() { None } else {
                                Some(view! { <p class="text-sm text-gray-400 mt-1">{d}</p> })
                            }
                        })}

                        <div class="flex items-center gap-2 mt-2">
                            <span class="text-xs text-gray-500 border border-gray-600 rounded px-1.5 py-0.5">
                                {move || format!("{} messages", messages.get().len())}
                            </span>
                        </div>
                    </div>
                </div>
                <div class="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-amber-500/20 to-transparent"></div>
            </div>

            {move || error_msg.get().map(|msg| view! {
                <div class="max-w-4xl mx-auto p-2">
                    <div class="bg-yellow-900/50 border border-yellow-700 rounded-lg px-4 py-2 flex items-center justify-between">
                        <span class="text-yellow-200 text-sm">{msg}</span>
                        <button class="text-yellow-400 hover:text-yellow-200 text-xs ml-4" on:click=move |_| error_msg.set(None)>"dismiss"</button>
                    </div>
                </div>
            })}

            <div class="flex-1 overflow-y-auto bg-gray-900 relative virtual-scroll" node_ref=messages_container>
                <div class="sticky top-0 left-0 right-0 h-6 bg-gradient-to-b from-gray-900 to-transparent z-10 pointer-events-none"></div>
                <div class="max-w-4xl mx-auto px-4 pb-4">
                    {move || {
                        if loading.get() {
                            view! {
                                <div class="flex flex-col items-center justify-center py-20 gap-3">
                                    <div class="animate-spin w-6 h-6 border-2 border-amber-400 border-t-transparent rounded-full"></div>
                                    <span class="text-gray-400 text-sm">"Loading messages..."</span>
                                </div>
                            }.into_any()
                        } else {
                            let msgs = messages.get();
                            if msgs.is_empty() {
                                view! {
                                    <div class="flex flex-col items-center justify-center py-20 text-center">
                                        <div class="w-14 h-14 rounded-full bg-gray-800 flex items-center justify-center mb-4 animate-gentle-float">
                                            <span class="text-2xl text-gray-500">"#"</span>
                                        </div>
                                        <h3 class="text-white font-semibold mb-1">"No messages yet"</h3>
                                        <p class="text-gray-500 text-sm">"Be the first to start this conversation."</p>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="space-y-1">
                                        {msgs.into_iter().map(|msg| view! {
                                            <SwipeableMessage>
                                                <MessageBubble message=msg/>
                                            </SwipeableMessage>
                                        }).collect_view()}
                                    </div>
                                }.into_any()
                            }
                        }
                    }}
                </div>
            </div>

            <Show when=move || is_authed.get()>
                <div class="bg-gray-800 border-t border-gray-700 p-3">
                    <div class="max-w-4xl mx-auto">
                        <TypingIndicator typing_pubkeys=typing_pubkeys />
                        <MessageInput
                            on_send=noop_send
                            on_send_with_mentions=send_callback
                            restore_failed=restore_failed
                        />
                    </div>
                </div>
            </Show>
        </div>
        </Show>
    }
}
