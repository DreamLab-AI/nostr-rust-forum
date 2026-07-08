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
use leptos_router::hooks::use_params_map;
use nostr_bbs_core::NostrEvent;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::agent_badge::AgentBadge;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::link_preview::LinkPreview;
use crate::components::media_embed::MediaEmbed;
use crate::components::mention_text::{normalise_mention_pubkey, MentionText};
use crate::components::message_input::MessageInput;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::relay::RelayConnection;
use crate::stores::channels::{use_channel_store, ChannelMeta};
use crate::stores::read_position::use_read_positions;
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, section_routes_to_zone, Zone, ZoneVisibility};
use crate::utils::format_relative_time;
use crate::utils::slug_hash::{matches_section_slug, matches_topic_slug, section_slug};
use crate::utils::zone_theme::zone_accent_style_cfg;

use super::section::{category_display_name, resolve_channel};

/// A single rendered reply within a thread.
#[derive(Clone, Debug)]
struct ReplyView {
    /// The ORIGINAL event id (the reply users reply to / thread against). Stays
    /// stable across edits so reply threading and the edit target never drift.
    id: String,
    pubkey: String,
    /// The latest content (original, or the most recent edit's content).
    content: String,
    /// Original post timestamp (preserved even when an edit supersedes it).
    created_at: u64,
    /// `true` when an edit replaced the original content.
    edited: bool,
}

/// Marker placed on a kind-42 that REPLACES (edits) an earlier post by the same
/// author: `["e", <original_id>, "", "edit"]`. Pragmatic, NIP-10-compatible
/// (the relay treats it as an ordinary `e` tag) and visible to the existing
/// kind-42 store stream with no relay-side support required.
const EDIT_MARKER: &str = "edit";

/// If `event` is an edit, return the id of the post it replaces.
///
/// An edit is a kind-42 carrying `["e", <target>, _, "edit"]`. The target must
/// not be the channel root (those carry the "root" marker), so a normal topic
/// or reply post is never mistaken for an edit.
fn edit_target(event: &NostrEvent) -> Option<String> {
    if event.kind != 42 {
        return None;
    }
    event
        .tags
        .iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == EDIT_MARKER)
        .map(|t| t[1].to_lowercase())
}

/// Resolve the latest authored version of `original` from `events`.
///
/// Walks every edit that the SAME author published against `original.id`
/// (directly or transitively via an edit-of-an-edit) and returns the content +
/// timestamp of the newest one. The returned `(content, latest_ts, edited)`
/// uses the original's content/timestamp when no edit exists. Edits by anyone
/// other than the original author are ignored — only the author can edit.
fn latest_version(original: &NostrEvent, events: &[NostrEvent]) -> (String, u64, bool) {
    let mut current_id = original.id.to_lowercase();
    let mut content = original.content.clone();
    let mut newest_edit_ts = 0u64;
    let mut edited = false;

    // Iteratively follow edit pointers: id -> latest edit of id -> ... The bound
    // on iterations guards against a cyclic/self-referential tag set.
    for _ in 0..64 {
        let next = events
            .iter()
            .filter(|e| {
                e.pubkey.eq_ignore_ascii_case(&original.pubkey)
                    && edit_target(e).as_deref() == Some(current_id.as_str())
            })
            // Most recent edit of this id wins (last-write-wins by created_at,
            // tie-broken by id for determinism).
            .max_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
        match next {
            Some(e) => {
                content = e.content.clone();
                newest_edit_ts = e.created_at;
                edited = true;
                current_id = e.id.to_lowercase();
            }
            None => break,
        }
    }
    let _ = newest_edit_ts;
    (content, original.created_at, edited)
}

/// Every event id in the edit-chain rooted at `original` (the original plus all
/// transitive edits by its author). Used to exclude edit events from the reply
/// list so an edit never shows up as its own reply.
fn edit_chain_ids(original: &NostrEvent, events: &[NostrEvent]) -> Vec<String> {
    let mut ids = vec![original.id.to_lowercase()];
    let mut frontier = vec![original.id.to_lowercase()];
    for _ in 0..64 {
        let mut next_frontier = Vec::new();
        for target in &frontier {
            for e in events.iter().filter(|e| {
                e.pubkey.eq_ignore_ascii_case(&original.pubkey)
                    && edit_target(e).as_deref() == Some(target.as_str())
            }) {
                let lid = e.id.to_lowercase();
                if !ids.contains(&lid) {
                    ids.push(lid.clone());
                    next_frontier.push(lid);
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }
    ids
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
                || (!c.section.is_empty() && matches_section_slug(&c.section, section_slug_param)))
    }) {
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
            let latest = channel_events.with(|events| {
                events
                    .iter()
                    .filter(|e| e.kind == 42)
                    .max_by(|a, b| {
                        a.created_at
                            .cmp(&b.created_at)
                            .then_with(|| a.id.cmp(&b.id))
                    })
                    .map(|e| (e.id.clone(), e.created_at))
            });
            if let Some((last_id, last_ts)) = latest {
                if last_marked.get_untracked() != last_id {
                    read_store.mark_read(&cid, &last_id, last_ts);
                    last_marked.set(last_id);
                }
            }
        });
    }

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
    //
    // Edit events are folded into the post they replace rather than shown as
    // their own replies: the root's edits are dropped outright, and each
    // surviving reply renders its latest authored version (see `latest_version`).
    let replies = Signal::derive(move || {
        let root = match topic_root.get() {
            Some(r) => r,
            None => return Vec::<ReplyView>::new(),
        };
        let root_id_lower = root.id.to_lowercase();
        let mut out: Vec<ReplyView> = channel_events.with(|events| {
            // Ids that belong to the ROOT's edit chain — never replies.
            let root_chain = edit_chain_ids(&root, events);
            // First pass: the genuine replies (reference the root, are not edits
            // of anything, and are not part of the root's edit chain).
            let originals: Vec<&NostrEvent> = events
                .iter()
                .filter(|e| {
                    if e.id.eq_ignore_ascii_case(&root.id) {
                        return false; // the root itself is not a reply
                    }
                    if e.kind != 42 && e.kind != 1111 {
                        return false;
                    }
                    let lid = e.id.to_lowercase();
                    if root_chain.contains(&lid) {
                        return false; // an edit of the root
                    }
                    if edit_target(e).is_some() {
                        return false; // an edit of some other reply
                    }
                    referenced_event_ids(e).iter().any(|r| r == &root_id_lower)
                })
                .collect();

            originals
                .into_iter()
                .map(|e| {
                    let (content, created_at, edited) = latest_version(e, events);
                    ReplyView {
                        id: e.id.clone(),
                        pubkey: e.pubkey.clone(),
                        content,
                        created_at,
                        edited,
                    }
                })
                .collect()
        });
        out.sort_by_key(|r| r.created_at);
        out
    });

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
        })
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
    let relay_for_edit = relay_for_send.clone();
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
            // Channel root anchor (NIP-10), then the edit pointer. When editing a
            // reply we also keep the topic root as the reply parent so the edit
            // re-enters the same thread query; editing the root omits that.
            let mut tags = vec![vec![
                "e".to_string(),
                cid,
                String::new(),
                "root".to_string(),
            ]];
            if let Some(ref r) = root {
                if !r.id.eq_ignore_ascii_case(&target_id) {
                    tags.push(vec![
                        "e".to_string(),
                        r.id.clone(),
                        String::new(),
                        "reply".to_string(),
                    ]);
                }
            }
            tags.push(vec![
                "e".to_string(),
                target_id.clone(),
                String::new(),
                EDIT_MARKER.to_string(),
            ]);
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
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        let on_ok = Rc::new(move |accepted: bool, message: String| {
                            if !accepted {
                                let reason = if message.trim().is_empty() {
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
            let accent = load_zones().into_iter().find(|z| z.id == slug).and_then(|z| z.accent_hex);
            zone_accent_style_cfg(&slug, accent.as_deref())
        }>
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
                            <div class="animate-spin w-6 h-6 border-2 border-[color:var(--zone-accent)] border-t-transparent rounded-full"></div>
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
                            <A href=base_href(&back) attr:class="text-[color:var(--zone-accent)] hover:opacity-80 text-sm underline">
                                "Back to section"
                            </A>
                        </div>
                    }.into_any()
                } else if let Some(root) = root_view.get() {
                    view! {
                        <RootPost
                            post=root
                            my_pubkey=my_pubkey
                            editing_id=editing_id
                            on_save_edit=publish_edit
                        />
                    }.into_any()
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
                            view! {
                                <ReplyCard
                                    reply=r
                                    my_pubkey=my_pubkey
                                    editing_id=editing_id
                                    on_save_edit=publish_edit
                                />
                            }
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
                        enable_image_upload=true
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
fn PostBody(content: String) -> impl IntoView {
    let urls = extract_urls(&content);
    let (media_urls, link_urls): (Vec<_>, Vec<_>) = urls.into_iter().partition(|u| is_media_url(u));
    let first_link = link_urls.into_iter().next();
    let text = content.clone();
    view! {
        <>
            <MentionText content=text />
            {media_urls.into_iter().map(|u| view! { <MediaEmbed url=u /> }).collect_view()}
            {first_link.map(|u| view! { <LinkPreview url=u /> })}
        </>
    }
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
    let is_author = Signal::derive(move || {
        let mine = my_pubkey.get();
        !mine.is_empty() && mine.eq_ignore_ascii_case(&post_pubkey)
    });
    let pid_click = pid.clone();
    move || {
        if !is_author.get() {
            return None;
        }
        let pid = pid_click.clone();
        Some(view! {
            <button
                class="ml-auto opacity-60 hover:opacity-100 text-xs text-gray-400 hover:text-amber-400 transition-colors flex items-center gap-1"
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

/// The topic root post, rendered prominently at the top of the thread.
#[component]
fn RootPost(
    post: ReplyView,
    my_pubkey: Signal<String>,
    editing_id: RwSignal<Option<String>>,
    on_save_edit: Callback<(String, String)>,
) -> impl IntoView {
    let author = use_display_name_memo(post.pubkey.clone());
    let time = format_relative_time(post.created_at);
    let pk = post.pubkey.clone();
    // Disclosure badge (COM-13/F2): marks the topic-root author as an agent.
    let author_badge_pubkey = post.pubkey.clone();
    let content = post.content.clone();
    let edited = post.edited;
    let post_id = post.id.clone();
    let post_pubkey = post.pubkey.clone();

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
            class="bg-gray-800/70 border rounded-xl p-5 mt-4"
            style="border-color:color-mix(in srgb, var(--zone-accent) 25%, transparent)"
        >
            <div class="flex items-start gap-3">
                <Avatar pubkey=pk size=AvatarSize::Lg />
                <div class="flex-1 min-w-0">
                    <div class="flex items-baseline gap-2 flex-wrap">
                        <span class="font-semibold text-[color:var(--zone-accent)]">{move || author.get()}</span>
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
                    </div>
                    <Show
                        when=move || is_editing.get()
                        fallback={
                            let content = content.clone();
                            move || view! {
                                <div class="text-gray-200 mt-2 leading-relaxed whitespace-pre-wrap break-words">
                                    <PostBody content=content.clone() />
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
                                on_cancel_edit=cancel_edit
                            />
                        </div>
                    </Show>
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
) -> impl IntoView {
    let author = use_display_name_memo(reply.pubkey.clone());
    let time = format_relative_time(reply.created_at);
    let pk = reply.pubkey.clone();
    // Disclosure badge (COM-13/F2): marks the reply author as an agent.
    let author_badge_pubkey = reply.pubkey.clone();
    let content = reply.content.clone();
    let edited = reply.edited;
    let post_id = reply.id.clone();
    let post_pubkey = reply.pubkey.clone();

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
        <div class="bg-gray-800/40 border border-gray-700/50 rounded-lg p-4">
            <div class="flex items-start gap-3">
                <Avatar pubkey=pk size=AvatarSize::Sm />
                <div class="flex-1 min-w-0">
                    <div class="flex items-baseline gap-2 flex-wrap">
                        <span class="font-semibold text-sm text-amber-400">{move || author.get()}</span>
                        <AgentBadge pubkey=author_badge_pubkey compact=true />
                        <span class="text-xs text-gray-600">{time}</span>
                        {edited.then(|| view! {
                            <span class="text-xs text-gray-600 italic">"(edited)"</span>
                        })}
                        <EditControls
                            post_id=post_id.clone()
                            post_pubkey=post_pubkey.clone()
                            my_pubkey=my_pubkey
                            editing_id=editing_id
                        />
                    </div>
                    <Show
                        when=move || is_editing.get()
                        fallback={
                            let content = content.clone();
                            move || view! {
                                <div class="text-sm text-gray-300 mt-1 leading-relaxed whitespace-pre-wrap break-words">
                                    <PostBody content=content.clone() />
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
                                on_cancel_edit=cancel_edit
                            />
                        </div>
                    </Show>
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

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        id: &str,
        pubkey: &str,
        created_at: u64,
        content: &str,
        tags: Vec<Vec<&str>>,
    ) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            created_at,
            kind: 42,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: content.to_string(),
            sig: String::new(),
        }
    }

    fn edit_tag(target: &str) -> Vec<&str> {
        vec!["e", target, "", EDIT_MARKER]
    }

    #[test]
    fn edit_target_detects_marker() {
        let e = ev("edit1", "alice", 200, "fixed", vec![edit_tag("orig")]);
        assert_eq!(edit_target(&e).as_deref(), Some("orig"));
    }

    #[test]
    fn edit_target_ignores_root_and_reply_markers() {
        let root = ev("r", "alice", 100, "hi", vec![vec!["e", "chan", "", "root"]]);
        assert_eq!(edit_target(&root), None);
        let reply = ev(
            "p",
            "alice",
            100,
            "hi",
            vec![vec!["e", "root", "", "reply"]],
        );
        assert_eq!(edit_target(&reply), None);
    }

    #[test]
    fn latest_version_no_edit_returns_original() {
        let orig = ev("orig", "alice", 100, "original", vec![]);
        let (content, ts, edited) = latest_version(&orig, std::slice::from_ref(&orig));
        assert_eq!(content, "original");
        assert_eq!(ts, 100);
        assert!(!edited);
    }

    #[test]
    fn latest_version_picks_newest_author_edit() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        let e1 = ev("e1", "alice", 200, "v2", vec![edit_tag("orig")]);
        let e2 = ev("e2", "alice", 300, "v3", vec![edit_tag("orig")]);
        let events = vec![orig.clone(), e1, e2];
        let (content, ts, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v3");
        // Original timestamp is preserved for display ordering.
        assert_eq!(ts, 100);
        assert!(edited);
    }

    #[test]
    fn latest_version_follows_edit_of_edit() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        let e1 = ev("e1", "alice", 200, "v2", vec![edit_tag("orig")]);
        let e2 = ev("e2", "alice", 300, "v3", vec![edit_tag("e1")]);
        let events = vec![orig.clone(), e1, e2];
        let (content, _ts, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v3");
        assert!(edited);
    }

    #[test]
    fn latest_version_ignores_edits_by_other_authors() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        // mallory cannot edit alice's post.
        let forged = ev("f1", "mallory", 200, "hacked", vec![edit_tag("orig")]);
        let events = vec![orig.clone(), forged];
        let (content, _ts, edited) = latest_version(&orig, &events);
        assert_eq!(content, "v1");
        assert!(!edited);
    }

    #[test]
    fn latest_version_survives_edit_cycle() {
        // a -> b and b -> a forms a cycle; the iteration bound prevents a hang.
        let orig = ev("a", "alice", 100, "v1", vec![]);
        let b = ev("b", "alice", 200, "v2", vec![edit_tag("a")]);
        let a_again = ev("a2", "alice", 300, "v3", vec![edit_tag("b")]);
        let cyc = ev("c", "alice", 400, "loop", vec![edit_tag("a2")]);
        let _ = latest_version(&orig, &[orig.clone(), b, a_again, cyc]);
        // No panic / no hang is the assertion.
    }

    #[test]
    fn edit_chain_ids_collects_transitive_edits() {
        let orig = ev("orig", "alice", 100, "v1", vec![]);
        let e1 = ev("e1", "alice", 200, "v2", vec![edit_tag("orig")]);
        let e2 = ev("e2", "alice", 300, "v3", vec![edit_tag("e1")]);
        let other = ev(
            "x",
            "alice",
            150,
            "reply",
            vec![vec!["e", "orig", "", "reply"]],
        );
        let events = vec![orig.clone(), e1, e2, other];
        let ids = edit_chain_ids(&orig, &events);
        assert!(ids.contains(&"orig".to_string()));
        assert!(ids.contains(&"e1".to_string()));
        assert!(ids.contains(&"e2".to_string()));
        // A genuine reply is NOT part of the edit chain.
        assert!(!ids.contains(&"x".to_string()));
    }

    #[test]
    fn is_media_url_classifies_correctly() {
        assert!(is_media_url("https://pod.example.com/a/photo.jpg"));
        assert!(is_media_url("https://pod.example.com/a/clip.mp4?v=2"));
        assert!(is_media_url("https://youtu.be/abc123"));
        assert!(!is_media_url("https://example.com/article"));
    }
}
