//! Single channel view page -- the FLAT, linear chat of one channel (kind-42).
//! Route: /chat/:channel_id
//!
//! ## Relationship to the BBS section view (#8 reconciliation)
//!
//! A *section* (kind-40 channel) is presented two ways:
//! - `/forums/:category/:section` ([`crate::pages::section::SectionPage`]) — the
//!   BBS TOPIC LIST: kind-42 roots with reply counts, the canonical browse view.
//! - `/chat/:channel_id` (this page) — the flat, real-time chat log of every
//!   message in the channel, retained as a deep-link target for search results,
//!   bookmarks, note-view links, and the channel-list dashboard (`chat.rs`).
//!
//! These no longer DUPLICATE each other: the old `SectionPage` was itself a flat
//! chat (a second copy of this view). It is now a topic list, so the only flat
//! chat surface is here. To keep the two connected (not orphaned), this page
//! offers a "View as topics" link that jumps to the channel's BBS section view
//! (with the privacy-hashed section slug, #9). The link is omitted when the
//! channel's owning zone cannot be resolved from the store.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use nostr_bbs_core::NostrEvent;
use std::rc::Rc;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::badge::{Badge, BadgeVariant};
use crate::components::channel_stats::ChannelStats;
use crate::components::export_modal::ExportModal;
use crate::components::mention_text::normalise_mention_pubkey;
use crate::components::message_bubble::{MessageBubble, MessageData};
use crate::components::message_input::MessageInput;
use crate::components::pinned_messages::{PinnedMessage, PinnedMessages};
use crate::components::thread_view::ThreadReply;
use crate::relay::{ConnectionState, Filter, RelayConnection};
#[allow(unused_imports)]
use crate::stores::channels::ChannelStore;
use crate::stores::read_position::use_read_positions;
use crate::stores::zones::{load_zones, section_to_zone};
use crate::utils::slug_hash::section_slug;
use crate::utils::zone_theme::zone_accent_style;
use crate::utils::{arrow_left_svg, set_timeout_once};

/// Parsed channel metadata from the kind 40 event.
#[derive(Clone, Debug)]
struct ChannelHeader {
    name: String,
    description: String,
    /// Whether the channel is archived (no new messages allowed).
    archived: bool,
}

/// Single channel view: message list + compose input.
#[component]
pub fn ChannelPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let conn_state = relay.connection_state();

    let params = use_params_map();
    let channel_id = move || params.read().get("channel_id").unwrap_or_default();

    // BBS topic-list href for this channel: resolve the channel (and thus its
    // owning zone) from the shared store, then build the privacy-hashed section
    // URL (#9). `None` when the channel/zone is not yet known — the link is then
    // hidden rather than pointing somewhere broken.
    let section_topics_href = {
        let store = use_context::<ChannelStore>();
        Signal::derive(move || {
            let raw = channel_id();
            if raw.is_empty() {
                return None;
            }
            let store = store?;
            let zones = load_zones();
            let needle_lower = raw.to_lowercase();
            store.channels.with(|list| {
                list.iter()
                    .find(|c| {
                        c.id == raw
                            || c.name.to_lowercase() == needle_lower
                            || c.section.to_lowercase() == needle_lower
                    })
                    .and_then(|c| {
                        let section = if c.section.is_empty() {
                            zones.first().map(|z| z.id.clone()).unwrap_or_default()
                        } else {
                            c.section.clone()
                        };
                        section_to_zone(&section, &zones).map(|zone| {
                            base_href(&format!("/forums/{}/{}", zone, section_slug(&c.id)))
                        })
                    })
            })
        })
    };

    // Zone accent carry-through (issue #29): /chat/:channel_id has no :category
    // route param, so resolve the channel's owning zone from its `section` tag
    // via the canonical resolver and expose its signature colour as the
    // `--zone-accent` CSS custom property on the page root. The prominent accent
    // elements below read it through `var(--zone-accent)`, so the chat page wears
    // the same colour as its zone hero / category page. Defaults to the neutral
    // accent until the channel resolves from the store.
    let zone_accent = {
        let store = use_context::<ChannelStore>();
        Signal::derive(move || {
            let raw = channel_id();
            let zones = load_zones();
            let resolved_zone = store.and_then(|store| {
                let needle_lower = raw.to_lowercase();
                store.channels.with(|list| {
                    list.iter()
                        .find(|c| {
                            c.id == raw
                                || c.name.to_lowercase() == needle_lower
                                || c.section.to_lowercase() == needle_lower
                        })
                        .and_then(|c| {
                            let section = if c.section.is_empty() {
                                raw.clone()
                            } else {
                                c.section.clone()
                            };
                            section_to_zone(&section, &zones)
                        })
                })
            });
            // Fall back to resolving the raw param as a section, then to the
            // first zone, so the root always carries a coherent accent.
            let zone = resolved_zone
                .or_else(|| section_to_zone(&raw, &zones))
                .unwrap_or_default();
            zone_accent_style(&zone)
        })
    };

    // Read-position store for mark-as-read
    let read_store = use_read_positions();

    // State
    let messages = RwSignal::new(Vec::<MessageData>::new());
    let channel_info: RwSignal<Option<ChannelHeader>> = RwSignal::new(None);
    let pinned = RwSignal::new(Vec::<PinnedMessage>::new());
    let loading = RwSignal::new(true);
    let last_read_event_id = read_store.last_read_event_id(&channel_id());
    let error_msg: RwSignal<Option<String>> = RwSignal::new(None);
    let show_export = RwSignal::new(false);

    // Derived signals for ChannelStats
    let message_count = Signal::derive(move || messages.get().len() as u32);
    let member_count = Signal::derive(move || {
        let msgs = messages.get();
        let mut unique = std::collections::HashSet::new();
        for m in &msgs {
            unique.insert(m.pubkey.as_str());
        }
        unique.len() as u32
    });
    let messages_container = NodeRef::<leptos::html::Div>::new();

    // Track subscription IDs for cleanup. `channel_sub_id` is the kind-40
    // by-id query; `replay_sub_ids` collects narrow kind-42 subs opened by
    // the on-discovery replay path so they get torn down on unmount —
    // without this, leaked subs from previous channel pages keep firing
    // into the global ChannelStore signals and trigger
    // "Tried to access a reactive value that has already been disposed"
    // panics under fast navigation.
    let channel_sub_id: RwSignal<Option<String>> = RwSignal::new(None);
    let replay_sub_ids: RwSignal<Vec<String>> = RwSignal::new(Vec::new());

    // Clone relay for each closure that needs it
    let relay_for_sub = relay.clone();
    let relay_for_send = relay.clone();
    let relay_for_cleanup = relay;

    // Reactive header fallback (ADR-092): re-run whenever `store.channels`
    // changes, so a deep-link that arrives BEFORE the channel list has
    // loaded still transitions out of "Loading…" once metadata streams in.
    //
    // Also matches by `section` so slug-style URLs (e.g. /chat/home-lobby)
    // resolve as well as hex-id URLs.
    //
    // Note: the previous `ensure_subscribed` Effect was removed in favour of
    // the kind-40 by-id query below — that path already replays the channel's
    // kind-42 history once metadata arrives, and the duplicate Effect was
    // implicated in "Tried to access a reactive value that has already been
    // disposed" panics on deep-link unmount.
    if let Some(store) = use_context::<ChannelStore>() {
        Effect::new(move |_| {
            // Don't clobber a header already populated by the kind-40 query.
            if channel_info.with_untracked(|c| c.is_some()) {
                return;
            }
            let cid = channel_id();
            if cid.is_empty() {
                return;
            }
            let needle_lower = cid.to_lowercase();
            store.channels.with(|list| {
                if let Some(found) = list.iter().find(|c| {
                    c.id == cid
                        || c.name.to_lowercase() == needle_lower
                        || c.section.to_lowercase() == needle_lower
                }) {
                    channel_info.set(Some(ChannelHeader {
                        name: found.name.clone(),
                        description: found.description.clone(),
                        archived: false,
                    }));
                }
            });
        });
    }

    // Subscribe to channel metadata (kind 40) when connected.
    // Messages come from ChannelStore's shared kind-42 subscription — the
    // Cloudflare DO relay ignores duplicate REQs on the same WebSocket, so
    // we cannot create a second kind-42 subscription.
    Effect::new(move |_| {
        let state = conn_state.get();
        let cid = channel_id();
        if state != ConnectionState::Connected || cid.is_empty() {
            return;
        }

        // Already subscribed
        if channel_sub_id.get_untracked().is_some() {
            return;
        }

        error_msg.set(None);

        // Fetch channel metadata (kind 40, by event id)
        let channel_filter = Filter {
            ids: Some(vec![cid.clone()]),
            kinds: Some(vec![40]),
            ..Default::default()
        };

        let channel_info_sig = channel_info;
        let store_for_kind40 = use_context::<ChannelStore>();
        let relay_for_retry = relay_for_sub.clone();
        let on_channel_event = Rc::new(move |event: NostrEvent| {
            if event.kind == 40 {
                let header = parse_channel_metadata(&event.content);
                channel_info_sig.set(Some(header));

                // ADR-092: seed the channel into the global store so the
                // shared kind-42 resolver can match historical events. Also
                // open a *retry* kind-42 sub keyed on all known identifiers
                // (hex id + name + section) — the broad kind-42 sub fires
                // before this kind-40-by-id query completes, so any events
                // for this channel that arrived earlier were dropped by the
                // resolver (channel wasn't in store.channels yet). The retry
                // sub replays them.
                if let Some(store) = store_for_kind40.as_ref() {
                    let (name, description, picture) =
                        crate::stores::channels::parse_channel_content(&event.content);
                    let section = event
                        .tags
                        .iter()
                        .find(|t| t.len() >= 2 && t[0] == "section")
                        .map(|t| t[1].clone())
                        .unwrap_or_default();
                    let meta = crate::stores::channels::ChannelMeta {
                        id: event.id.clone(),
                        name: name.clone(),
                        description,
                        section: section.clone(),
                        picture,
                        created_at: event.created_at,
                    };
                    store.channels.update(|list| {
                        if !list.iter().any(|c| c.id == meta.id) {
                            list.push(meta);
                        }
                    });

                    // Replay historical kind-42 events for this channel via a
                    // narrow filter on all identifier variants. The store's
                    // on_msg resolver (channels-reactive) will route them.
                    let last_active = store.last_active;
                    let channel_msgs = store.channel_messages;
                    let channels_sig = store.channels;
                    let cid_for_replay = event.id.clone();
                    let on_replay = Rc::new(move |ev: NostrEvent| {
                        if ev.kind != 42 {
                            return;
                        }
                        let tag_val = ev
                            .tags
                            .iter()
                            .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "root")
                            .or_else(|| ev.tags.iter().find(|t| t.len() >= 2 && t[0] == "e"))
                            .map(|t| t[1].clone());
                        let tag_val = match tag_val {
                            Some(v) => v,
                            None => return,
                        };
                        let tag_lower = tag_val.to_lowercase();
                        let resolved = channels_sig.with_untracked(|list| {
                            list.iter()
                                .find(|c| {
                                    c.id == tag_val
                                        || c.name.to_lowercase() == tag_lower
                                        || c.section.to_lowercase() == tag_lower
                                })
                                .map(|c| c.id.clone())
                        });
                        let cid_match = resolved.unwrap_or_else(|| cid_for_replay.clone());
                        let mut newly_added = false;
                        let event_ts = ev.created_at;
                        channel_msgs.update(|m| {
                            let events = m.entry(cid_match.clone()).or_insert_with(Vec::new);
                            if !events.iter().any(|e| e.id == ev.id) {
                                events.push(ev);
                                events.sort_by_key(|e| e.created_at);
                                newly_added = true;
                            }
                        });
                        if newly_added {
                            last_active.update(|m| {
                                let ts = m.entry(cid_match).or_insert(0);
                                if event_ts > *ts {
                                    *ts = event_ts;
                                }
                            });
                        }
                    });
                    let mut needles: Vec<String> = vec![event.id.clone()];
                    if !name.is_empty() {
                        needles.push(name);
                    }
                    if !section.is_empty() {
                        needles.push(section);
                    }
                    let sub_id = relay_for_retry.subscribe(
                        vec![Filter {
                            kinds: Some(vec![42]),
                            e_tags: Some(needles),
                            ..Default::default()
                        }],
                        on_replay,
                        None,
                    );
                    replay_sub_ids.update(|ids| ids.push(sub_id));
                }
            }
        });

        let id1 = relay_for_sub.subscribe(vec![channel_filter], on_channel_event, None);
        channel_sub_id.set(Some(id1));
    });

    // Read messages from ChannelStore's shared kind-42 subscription.
    // The store resolves each event's channel identity and groups them by ID.
    // This Effect re-runs whenever channel_messages changes (new events arrive).
    Effect::new(move |_| {
        let raw_cid = channel_id();
        if raw_cid.is_empty() {
            return;
        }

        let store = match use_context::<ChannelStore>() {
            Some(s) => s,
            None => return,
        };

        // Resolve slug/section/id to a concrete cid using the store's lookup.
        // ADR-092: deep-links via slug must still locate their events.
        let cid = store.resolve_channel(&raw_cid).unwrap_or(raw_cid.clone());

        let all_msgs = store.channel_messages.get();
        let channel_events = match all_msgs.get(&cid).or_else(|| all_msgs.get(&raw_cid)) {
            Some(events) => events.clone(),
            None => {
                // No messages yet — check if EOSE has been received
                if store.eose_received.get_untracked() {
                    loading.set(false);
                }
                return;
            }
        };

        loading.set(false);
        messages.update(|list| {
            for event in &channel_events {
                if list.iter().any(|m| m.id == event.id) {
                    continue;
                }
                let reply_to = event
                    .tags
                    .iter()
                    .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "reply")
                    .or_else(|| {
                        event
                            .tags
                            .iter()
                            .filter(|t| t.len() >= 2 && t[0] == "e")
                            .nth(1)
                    })
                    .map(|t| t[1].clone());
                let reply_pk = event
                    .tags
                    .iter()
                    .find(|t| t.len() >= 2 && t[0] == "p")
                    .map(|t| t[1].clone());
                list.push(MessageData {
                    id: event.id.clone(),
                    pubkey: event.pubkey.clone(),
                    content: event.content.clone(),
                    created_at: event.created_at,
                    reply_to_id: reply_to,
                    reply_to_pubkey: reply_pk,
                    reply_to_content: None,
                    reactions: RwSignal::new(Vec::new()),
                    is_hidden: false,
                    channel_id: cid.clone(),
                    thread_replies: RwSignal::new(Vec::<ThreadReply>::new()),
                });
            }
            list.sort_by_key(|m| m.created_at);
        });
    });

    // Loading timeout fallback
    set_timeout_once(
        move || {
            if loading.get_untracked() {
                loading.set(false);
            }
        },
        8000,
    );

    // Auto-scroll to bottom when new messages arrive + mark as read
    Effect::new(move |_| {
        let msgs = messages.get();
        let count = msgs.len();
        if let Some(container) = messages_container.get() {
            let el: web_sys::HtmlElement = container.into();
            set_timeout_once(
                move || {
                    el.set_scroll_top(el.scroll_height());
                },
                50,
            );
        }
        // Mark channel as read when messages load or new ones arrive
        if count > 0 {
            if let Some(last) = msgs.last() {
                let cid = channel_id();
                read_store.mark_read(&cid, &last.id, last.created_at);
            }
        }
    });

    // Cleanup on unmount: tear down the kind-40 by-id sub AND every
    // narrow kind-42 replay sub opened during this page's lifetime. Leaked
    // subs would otherwise keep firing into global ChannelStore signals
    // from disposed reactive scopes, surfacing as
    // "Tried to access a reactive value that has already been disposed"
    // panics on subsequent navigations.
    on_cleanup(move || {
        if let Some(id) = channel_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
        let ids = replay_sub_ids.get_untracked();
        for id in ids {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    // Send message handler
    let do_send_text = move |(content, mention_pubkeys): (String, Vec<String>)| {
        let cid = channel_id();
        if cid.is_empty() {
            return;
        }

        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            error_msg.set(Some("Not authenticated".to_string()));
            return;
        }

        let now = (js_sys::Date::now() / 1000.0) as u64;
        let content_for_index = content.clone();
        // Root e-tag first, then one ["p", pubkey] per @-mention selected in
        // the composer so mentioned users are addressable per NIP-10.
        let mut tags = vec![vec![
            "e".to_string(),
            cid.clone(),
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
        // Also resolve @handles typed directly into the content (not picked from
        // the dropdown) so e.g. @junkiejarvis still gets a ["p", pubkey] tag and
        // the relay delivers the message to the agent's #p-filtered subscription.
        for hex in crate::components::mention_autocomplete::resolve_content_mentions(&content) {
            if !tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == hex)
            {
                tags.push(vec!["p".to_string(), hex]);
            }
        }
        let unsigned = nostr_bbs_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 42,
            tags,
            content,
        };

        let relay = relay_for_send.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    let event_id = signed.id.clone();
                    relay.publish(&signed);

                    // Auto-index for semantic search in background
                    let channel_for_index = cid;
                    if let Some(signer) = auth.get_signer() {
                        let _ = crate::utils::search_client::ingest_message_signer(
                            &event_id,
                            &content_for_index,
                            Some(&channel_for_index),
                            &*signer,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    error_msg.set(Some(e));
                }
            }
        });
    };

    let send_callback = Callback::new(do_send_text);
    // MessageInput fires `on_send` alongside `on_send_with_mentions`; all
    // publish work lives in the mentions path, so the plain path is a no-op.
    let noop_send = Callback::new(|_: String| {});
    let is_authed = auth.is_authenticated();

    // Channel archived state (derived from metadata)
    let is_archived = Memo::new(move |_| channel_info.get().map(|c| c.archived).unwrap_or(false));

    // Derive avatar letter from channel name
    let avatar_letter = move || {
        channel_info
            .get()
            .map(|c| {
                c.name
                    .chars()
                    .next()
                    .unwrap_or('#')
                    .to_uppercase()
                    .to_string()
            })
            .unwrap_or_else(|| "#".to_string())
    };

    view! {
        <div class="flex flex-col h-[calc(100vh-64px)]" style=move || zone_accent.get()>
            // Channel header
            <div class="bg-gray-800 border-b border-gray-700 relative">
                <div class="p-4">
                    <div class="max-w-4xl mx-auto">
                        <div class="flex items-center gap-3 mb-1">
                            <A href=base_href("/chat") attr:class="text-gray-400 hover:text-white transition-colors p-1 rounded hover:bg-gray-700">
                                {arrow_left_svg()}
                            </A>
                            // Channel avatar — tinted with the zone accent (#29)
                            <div
                                class="w-8 h-8 rounded-full text-[color:var(--zone-accent)] flex items-center justify-center text-sm font-bold flex-shrink-0"
                                style="background:color-mix(in srgb, var(--zone-accent) 20%, transparent)"
                            >
                                {avatar_letter}
                            </div>
                            <h1 class="text-2xl font-bold text-white">
                                {move || {
                                    channel_info.get()
                                        .map(|c| c.name)
                                        .unwrap_or_else(|| "Loading...".to_string())
                                }}
                            </h1>
                            // "View as topics": jump to the BBS topic-list view
                            // of this same channel (#8 reconciliation). Hidden
                            // until the owning zone resolves from the store.
                            {move || section_topics_href.get().map(|href| view! {
                                <A
                                    href=href
                                    attr:class="ml-auto flex items-center gap-1.5 text-xs text-[color:var(--zone-accent)] hover:opacity-80 border rounded-lg px-2.5 py-1 transition-colors"
                                    attr:style="border-color:color-mix(in srgb, var(--zone-accent) 30%, transparent)"
                                >
                                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <line x1="8" y1="6" x2="21" y2="6" stroke-linecap="round"/>
                                        <line x1="8" y1="12" x2="21" y2="12" stroke-linecap="round"/>
                                        <line x1="8" y1="18" x2="21" y2="18" stroke-linecap="round"/>
                                        <circle cx="3.5" cy="6" r="1" fill="currentColor"/>
                                        <circle cx="3.5" cy="12" r="1" fill="currentColor"/>
                                        <circle cx="3.5" cy="18" r="1" fill="currentColor"/>
                                    </svg>
                                    "View as topics"
                                </A>
                            })}
                        </div>
                        {move || {
                            channel_info.get().and_then(|c| {
                                if c.description.is_empty() {
                                    None
                                } else {
                                    Some(view! {
                                        <p class="text-sm text-gray-400 ml-14">
                                            {c.description}
                                        </p>
                                    })
                                }
                            })
                        }}
                        <div class="flex items-center gap-2 mt-1 ml-14">
                            <ChannelStats
                                message_count=message_count
                                member_count=member_count
                            />
                            // Export button
                            <button
                                class="text-gray-500 hover:text-amber-400 transition-colors p-1 rounded hover:bg-gray-700/50"
                                title="Export messages"
                                on:click=move |_| show_export.set(true)
                            >
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" stroke-linecap="round" stroke-linejoin="round"/>
                                    <polyline points="7 10 12 15 17 10" stroke-linecap="round" stroke-linejoin="round"/>
                                    <line x1="12" y1="15" x2="12" y2="3" stroke-linecap="round"/>
                                </svg>
                            </button>
                            // Connection indicator
                            {move || {
                                let state = conn_state.get();
                                match state {
                                    ConnectionState::Connected => view! {
                                        <Badge text="Connected".to_string() variant=BadgeVariant::Success />
                                    }.into_any(),
                                    ConnectionState::Reconnecting => view! {
                                        <Badge text="Reconnecting".to_string() variant=BadgeVariant::Warning pulse=true />
                                    }.into_any(),
                                    _ => view! {
                                        <Badge text="Disconnected".to_string() variant=BadgeVariant::Error />
                                    }.into_any(),
                                }
                            }}
                        </div>
                    </div>
                </div>
                // Subtle bottom gradient line
                <div class="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-amber-500/20 to-transparent"></div>
            </div>

            // Error banner
            {move || {
                error_msg.get().map(|msg| view! {
                    <div class="max-w-4xl mx-auto p-2">
                        <div class="bg-yellow-900/50 border border-yellow-700 rounded-lg px-4 py-2 flex items-center justify-between">
                            <span class="text-yellow-200 text-sm">{msg}</span>
                            <button class="text-yellow-400 hover:text-yellow-200 text-xs ml-4"
                                on:click=move |_| error_msg.set(None)
                            >
                                "dismiss"
                            </button>
                        </div>
                    </div>
                })
            }}

            // Archive banner
            <Show when=move || is_archived.get()>
                <div class="max-w-4xl mx-auto px-4 pt-2">
                    <div class="bg-gray-800/80 border border-gray-600/50 rounded-lg px-4 py-3 flex items-center gap-3">
                        <svg class="w-5 h-5 text-gray-500 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="21 8 21 21 3 21 3 8" stroke-linecap="round" stroke-linejoin="round"/>
                            <rect x="1" y="3" width="22" height="5" rx="1" stroke-linecap="round" stroke-linejoin="round"/>
                            <line x1="10" y1="12" x2="14" y2="12" stroke-linecap="round"/>
                        </svg>
                        <span class="text-sm text-gray-400">
                            "This channel is archived. No new messages can be posted."
                        </span>
                    </div>
                </div>
            </Show>

            // Messages area
            <div
                class="flex-1 overflow-y-auto bg-gray-900 relative"
                node_ref=messages_container
            >
                // Top fade gradient to indicate scrollability
                <div class="sticky top-0 left-0 right-0 h-6 bg-gradient-to-b from-gray-900 to-transparent z-10 pointer-events-none"></div>

                <div class="max-w-4xl mx-auto px-4 pb-4">
                    // Pinned messages banner
                    {
                        let cid = channel_id();
                        view! { <PinnedMessages channel_id=cid pinned=pinned /> }
                    }

                    {move || {
                        if loading.get() {
                            view! {
                                <div class="flex flex-col items-center justify-center py-20 gap-3">
                                    <svg class="w-6 h-6 text-[color:var(--zone-accent)] animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    <span class="text-gray-400 text-sm">"Loading messages..."</span>
                                </div>
                            }.into_any()
                        } else {
                            let msgs = messages.get();
                            if msgs.is_empty() {
                                view! {
                                    <div class="flex flex-col items-center justify-center py-20 text-center">
                                        <div class="w-14 h-14 rounded-full bg-gray-800 flex items-center justify-center mb-4">
                                            <svg class="w-7 h-7 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M12 20.25c4.97 0 9-3.694 9-8.25s-4.03-8.25-9-8.25S3 7.444 3 12c0 2.104.859 4.023 2.273 5.48.432.447.74 1.04.586 1.641a4.483 4.483 0 01-.923 1.785A5.969 5.969 0 006 21c1.282 0 2.47-.402 3.445-1.087.81.22 1.668.337 2.555.337z"/>
                                            </svg>
                                        </div>
                                        <h3 class="text-white font-semibold mb-1">"No messages yet"</h3>
                                        <p class="text-gray-500 text-sm">"Be the first to start this conversation."</p>
                                    </div>
                                }.into_any()
                            } else {
                                let last_read = last_read_event_id.clone();
                                let mut found_divider = false;
                                view! {
                                    <div class="space-y-1">
                                        {msgs.into_iter().map(|msg| {
                                            let show_divider = if !found_divider && !last_read.is_empty() && msg.id == last_read {
                                                found_divider = true;
                                                false
                                            } else {
                                                std::mem::take(&mut found_divider)
                                            };
                                            view! {
                                                <>
                                                    {show_divider.then(|| view! {
                                                        <div class="flex items-center gap-3 py-2">
                                                            <div class="flex-1 h-px" style="background:color-mix(in srgb, var(--zone-accent) 35%, transparent)"></div>
                                                            <span class="text-xs font-medium text-[color:var(--zone-accent)]">"New messages"</span>
                                                            <div class="flex-1 h-px" style="background:color-mix(in srgb, var(--zone-accent) 35%, transparent)"></div>
                                                        </div>
                                                    })}
                                                    <MessageBubble message=msg/>
                                                </>
                                            }
                                        }).collect_view()}
                                    </div>
                                }.into_any()
                            }
                        }
                    }}
                </div>
            </div>

            // Compose area (only when authenticated and channel is not archived)
            <Show when=move || is_authed.get() && !is_archived.get()>
                <div class="bg-gray-800 border-t border-gray-700 p-3">
                    <div class="max-w-4xl mx-auto">
                        <MessageInput
                            on_send=noop_send
                            on_send_with_mentions=send_callback
                            channel_id=channel_id()
                        />
                    </div>
                </div>
            </Show>

            // Export modal
            <Show when=move || show_export.get()>
                {move || {
                    let cid = channel_id();
                    let msgs = messages.get();
                    view! {
                        <ExportModal
                            channel_id=cid
                            messages=msgs
                            on_close=Callback::new(move |()| show_export.set(false))
                        />
                    }
                }}
            </Show>
        </div>
    }
}

/// Parse kind 40 event content JSON into channel name, description, and archived status.
fn parse_channel_metadata(content: &str) -> ChannelHeader {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => ChannelHeader {
            name: val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed Channel")
                .to_string(),
            description: val
                .get("about")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            archived: val
                .get("archived")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        },
        Err(_) => ChannelHeader {
            name: "Unnamed Channel".to_string(),
            description: String::new(),
            archived: false,
        },
    }
}
