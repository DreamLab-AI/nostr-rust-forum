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
//! All data comes from the shared [`ChannelStore`] (the same kind-40/kind-42
//! subscriptions that drive the index and the section topic list) — this page
//! adds NO redundant per-page subscription beyond `ensure_subscribed`, which is
//! idempotent and only tops up the per-channel history for a deep-linked
//! channel the broad sub hasn't yet covered. The reply composer publishes a
//! kind-42 e-tagging the topic root (NIP-10 root + reply markers), so the new
//! reply re-enters the same store stream and the count updates live.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use nostr_bbs_core::NostrEvent;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::mention_text::{normalise_mention_pubkey, MentionText};
use crate::components::message_input::MessageInput;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::relay::RelayConnection;
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, Zone, ZoneVisibility};
use crate::utils::format_relative_time;
use crate::utils::slug_hash::{matches_section_slug, matches_topic_slug, section_slug};

use super::section::{category_display_name, resolve_channel};

/// A single rendered reply within a thread.
#[derive(Clone, Debug)]
struct ReplyView {
    id: String,
    pubkey: String,
    content: String,
    created_at: u64,
}

/// Root e-tag value of a kind-42 (prefer the "root" marker, else first `e`).
fn root_e_tag(event: &NostrEvent) -> Option<String> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
        .or_else(|| event.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
        .map(|t| t[1].clone())
}

/// All `e`/`E`-tag values referenced by an event, lowercased.
fn referenced_event_ids(event: &NostrEvent) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && (t[0] == "e" || t[0] == "E"))
        .map(|t| t[1].to_lowercase())
        .collect()
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
    // Hashed form first (#9): match the channel-id hash OR the section-tag hash
    // (CategoryCard links group by section tag), scoped to the zone.
    if let Some(found) = channels.iter().find(|c| {
        let routes = section_routes_to_zone(&c.section, category_slug, zones);
        routes
            && (matches_section_slug(&c.id, section_slug_param)
                || (!c.section.is_empty()
                    && matches_section_slug(&c.section, section_slug_param)))
    }) {
        return Some(found.clone());
    }
    // Legacy plaintext fallback (shared with SectionPage).
    resolve_channel(channels, category_slug, section_slug_param, zones)
}

/// Whether a channel's `section` tag routes to the given zone id.
fn section_routes_to_zone(section: &str, category_slug: &str, zones: &[Zone]) -> bool {
    let cat = category_slug.to_lowercase();
    if cat.is_empty() {
        return true;
    }
    let sec = section.to_lowercase();
    // Exact zone id match.
    if zones.iter().any(|z| z.id.to_lowercase() == sec) {
        return sec == cat;
    }
    // Prefix match "<zone>-...".
    if let Some(z) = zones
        .iter()
        .find(|z| sec.starts_with(&format!("{}-", z.id.to_lowercase())))
    {
        return z.id.to_lowercase() == cat;
    }
    // Catch-all: first zone owns unrouted channels.
    zones
        .first()
        .map(|z| z.id.to_lowercase() == cat)
        .unwrap_or(false)
}

/// Thread page: topic root + threaded replies + reply composer.
#[component]
pub fn ThreadPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let store = use_channel_store();
    let zone_access = use_zone_access();
    let toasts = use_toasts();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();
    let section_param = move || params.read().get("section").unwrap_or_default();
    let topic_param = move || params.read().get("topic").unwrap_or_default();

    // Zone access gate — identical contract to SectionPage (ADR-022: the relay
    // is the real boundary; unknown zones default accessible).
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        match load_zones().into_iter().find(|z| z.id == cat) {
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
    let channel_events = Signal::derive(move || {
        let cid = match resolved_channel.get() {
            Some(ch) => ch.id,
            None => return Vec::<NostrEvent>::new(),
        };
        store
            .channel_messages
            .with(|m| m.get(&cid).cloned().unwrap_or_default())
    });

    // The topic root event whose id maps to the :topic slug.
    let topic_root = Signal::derive(move || {
        let cid = match resolved_channel.get() {
            Some(ch) => ch.id.to_lowercase(),
            None => return Option::<NostrEvent>::None,
        };
        let slug = topic_param();
        channel_events.with(|events| {
            events
                .iter()
                .find(|e| {
                    if e.kind != 42 {
                        return false;
                    }
                    // Must be a root anchored to this channel (not itself a reply)
                    let is_root = root_e_tag(e)
                        .map(|r| r.to_lowercase() == cid)
                        .unwrap_or(true);
                    is_root && matches_topic_slug(&e.id, &slug)
                })
                .cloned()
        })
    });

    // Replies: kind-42 / kind-1111 events that reference the topic root id.
    let replies = Signal::derive(move || {
        let root = match topic_root.get() {
            Some(r) => r,
            None => return Vec::<ReplyView>::new(),
        };
        let root_id_lower = root.id.to_lowercase();
        let mut out: Vec<ReplyView> = channel_events.with(|events| {
            events
                .iter()
                .filter(|e| {
                    if e.id.eq_ignore_ascii_case(&root.id) {
                        return false; // the root itself is not a reply
                    }
                    if e.kind != 42 && e.kind != 1111 {
                        return false;
                    }
                    referenced_event_ids(e).iter().any(|r| r == &root_id_lower)
                })
                .map(|e| ReplyView {
                    id: e.id.clone(),
                    pubkey: e.pubkey.clone(),
                    content: e.content.clone(),
                    created_at: e.created_at,
                })
                .collect()
        });
        out.sort_by_key(|r| r.created_at);
        out
    });

    let store_loading = store.loading;
    // Loading while the store is still fetching and we have not located either
    // the channel or the root post yet.
    let loading = Memo::new(move |_| {
        store_loading.get() && (resolved_channel.get().is_none() || topic_root.get().is_none())
    });

    // Topic-not-found: store finished, channel resolved, but no matching root.
    let not_found = Memo::new(move |_| {
        !store_loading.get() && resolved_channel.get().is_some() && topic_root.get().is_none()
    });

    // Section href (hashed) for breadcrumb back-link — REAL section name shown.
    let section_href = move || {
        match resolved_channel.get() {
            Some(ch) => format!("/forums/{}/{}", category_slug(), section_slug(&ch.id)),
            // Preserve whatever section param brought us here.
            None => format!("/forums/{}/{}", category_slug(), section_param()),
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

    // Reply composer → kind-42 e-tagging the topic root (NIP-10 root+reply).
    let relay_for_send = relay;
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
            // NIP-10: channel as root anchor, the topic root as the reply parent,
            // notify the root author, then per-mention p tags.
            let mut tags = vec![
                vec!["e".to_string(), cid, String::new(), "root".to_string()],
                vec![
                    "e".to_string(),
                    root.id.clone(),
                    String::new(),
                    "reply".to_string(),
                ],
                vec!["p".to_string(), root.pubkey.clone()],
            ];
            for pk in mention_pubkeys {
                if let Some(hex) = normalise_mention_pubkey(&pk) {
                    if !tags.iter().any(|t| t[0] == "p" && t[1] == hex) {
                        tags.push(vec!["p".to_string(), hex]);
                    }
                }
            }
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: 42,
                tags,
                content,
            };

            let relay = relay.clone();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        let original_for_ack = original.clone();
                        let on_ok = Rc::new(move |accepted: bool, message: String| {
                            if !accepted {
                                let reason = if message.trim().is_empty() {
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

    view! {
        <Show
            when=move || has_zone_access.get()
            fallback=move || view! { <AccessDenied zone_id=category_slug() /> }
        >
        <div class="max-w-4xl mx-auto p-4 sm:p-6">
            <Breadcrumb items=vec![
                BreadcrumbItem::link("Home", "/"),
                BreadcrumbItem::link("Forums", "/forums"),
                BreadcrumbItem::link(
                    category_display_name(&category_slug()),
                    format!("/forums/{}", category_slug()),
                ),
                BreadcrumbItem::link(section_name(), section_href()),
                BreadcrumbItem::current(topic_title()),
            ] />

            {move || {
                if loading.get() {
                    view! {
                        <div class="flex flex-col items-center justify-center py-20 gap-3">
                            <div class="animate-spin w-6 h-6 border-2 border-amber-400 border-t-transparent rounded-full"></div>
                            <span class="text-gray-400 text-sm">"Loading topic..."</span>
                        </div>
                    }.into_any()
                } else if not_found.get() {
                    let back = section_href();
                    view! {
                        <div class="glass-card p-8 text-center mt-4">
                            <h2 class="text-xl font-bold text-white mb-2">"Topic Not Found"</h2>
                            <p class="text-gray-400 text-sm mb-4">
                                "This topic could not be found in this section."
                            </p>
                            <A href=base_href(&back) attr:class="text-amber-400 hover:text-amber-300 text-sm underline">
                                "Back to section"
                            </A>
                        </div>
                    }.into_any()
                } else if let Some(root) = topic_root.get() {
                    view! { <RootPost root=root /> }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            // Replies
            <Show when=move || topic_root.get().is_some() && !loading.get()>
                <div class="mt-6">
                    <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
                        {move || {
                            let n = replies.get().len();
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
                        {move || replies.get().into_iter().map(|r| {
                            view! { <ReplyCard reply=r /> }
                        }).collect_view()}
                    </div>
                </div>
            </Show>

            // Reply composer
            <Show when=move || is_authed.get() && topic_root.get().is_some() && !loading.get()>
                <div class="mt-6 bg-gray-800 border border-gray-700 rounded-lg p-3">
                    <MessageInput
                        on_send=noop_send
                        on_send_with_mentions=send_callback
                        restore_failed=restore_failed
                    />
                </div>
            </Show>
        </div>
        </Show>
    }
}

/// The topic root post, rendered prominently at the top of the thread.
#[component]
fn RootPost(root: NostrEvent) -> impl IntoView {
    let author = use_display_name_memo(root.pubkey.clone());
    let time = format_relative_time(root.created_at);
    let pk = root.pubkey.clone();
    let content = root.content.clone();

    view! {
        <article class="bg-gray-800/70 border border-amber-500/20 rounded-xl p-5 mt-4">
            <div class="flex items-start gap-3">
                <Avatar pubkey=pk size=AvatarSize::Lg />
                <div class="flex-1 min-w-0">
                    <div class="flex items-baseline gap-2 flex-wrap">
                        <span class="font-semibold text-amber-400">{move || author.get()}</span>
                        <span class="text-xs text-gray-500">{time}</span>
                    </div>
                    <div class="text-gray-200 mt-2 leading-relaxed whitespace-pre-wrap break-words">
                        <MentionText content=content />
                    </div>
                </div>
            </div>
        </article>
    }
}

/// A single reply card in the thread.
#[component]
fn ReplyCard(reply: ReplyView) -> impl IntoView {
    let author = use_display_name_memo(reply.pubkey.clone());
    let time = format_relative_time(reply.created_at);
    let pk = reply.pubkey.clone();
    let content = reply.content.clone();

    view! {
        <div class="bg-gray-800/40 border border-gray-700/50 rounded-lg p-4">
            <div class="flex items-start gap-3">
                <Avatar pubkey=pk size=AvatarSize::Sm />
                <div class="flex-1 min-w-0">
                    <div class="flex items-baseline gap-2 flex-wrap">
                        <span class="font-semibold text-sm text-amber-400">{move || author.get()}</span>
                        <span class="text-xs text-gray-600">{time}</span>
                    </div>
                    <div class="text-sm text-gray-300 mt-1 leading-relaxed whitespace-pre-wrap break-words">
                        <MentionText content=content />
                    </div>
                </div>
            </div>
        </div>
    }
}

/// First non-empty line of content, trimmed and length-clipped, for titles.
fn first_line(content: &str) -> String {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .trim();
    if line.is_empty() {
        return "(untitled topic)".to_string();
    }
    const MAX: usize = 90;
    if line.chars().count() > MAX {
        let clipped: String = line.chars().take(MAX).collect();
        format!("{}\u{2026}", clipped.trim_end())
    } else {
        line.to_string()
    }
}
