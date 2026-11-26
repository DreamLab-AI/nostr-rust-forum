//! Board topic list + full threaded conversation view.
//!
//! Full parity with `nostr-bbs-forum-client`:
//! - NIP-28 kind-42 topics/replies + NIP-22 kind-1111 comments
//! - End-to-end encrypted zones (ADR-2016/2017) via shared `ZoneKeyStore` / `ZoneWriter`
//! - Markdown rendering + on-theme phosphor `AsciiImg` with ASCII/Raw toggle
//! - NIP-25 kind-7 reactions (+ custom emoji + kind-5 undo)
//! - Author edits (`edit` marker), NIP-09 deletions, NIP-56 reports (kind-1984)
//! - Per-identity auto-saved drafts (`draft:v2:`), bookmarks, mute, read positions
//! - Image picker + clipboard image paste via NIP-98 Solid Pod PUT

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::stores::channels::use_channel_store;
use nostr_bbs_client_core::stores::custom_emoji::use_custom_emoji_store;
use nostr_bbs_client_core::stores::mute::use_mute_store;
use nostr_bbs_client_core::stores::profile_cache::try_use_profile_cache;
use nostr_bbs_client_core::stores::reactions::use_reaction_store;
use nostr_bbs_client_core::stores::read_position::use_read_positions;
use nostr_bbs_client_core::stores::zones::{load_zones, resolve_zone_param};
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::{format_relative_time, shorten_pubkey};
use nostr_bbs_client_core::zone_crypto::store::{try_use_zone_key_store, ZoneWriter};
use nostr_bbs_client_core::zone_crypto::{encryption_enabled, has_zk_tag};
use nostr_bbs_core::event::{NostrEvent, UnsignedEvent};
use nostr_bbs_core::thread::{channel_message_tags, group_threads, thread_messages};

use crate::ascii_img::{extract_image_urls, AsciiImg};
use crate::components::{AuthorChip, EmptyCard, MarkdownBody};
use crate::config::BbsConfig;
use crate::router::{use_router, Route};
use crate::views::bookmarks::{is_bookmarked, toggle_bookmark, BookmarkItem};

const BUILTIN_REACTIONS: &[&str] = &["👍", "❤️", "😂", "🔥", "🎉", "👀", "💯", "🙌"];

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn draft_key(pubkey: &str, scope: &str) -> String {
    format!("draft:v2:{pubkey}:{scope}")
}

fn load_draft(pubkey: Option<&str>, scope: &str) -> String {
    #[cfg(target_arch = "wasm32")]
    if let Some(pk) = pubkey {
        if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            return st
                .get_item(&draft_key(pk, scope))
                .ok()
                .flatten()
                .unwrap_or_default();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (pubkey, scope);
    String::new()
}

fn save_draft(pubkey: Option<&str>, scope: &str, text: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(pk) = pubkey {
        if let Some(st) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let k = draft_key(pk, scope);
            if text.trim().is_empty() {
                let _ = st.remove_item(&k);
            } else {
                let _ = st.set_item(&k, text);
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (pubkey, scope, text);
}

/// Resolve author-latest edits (`["e", target, "", "edit"]`) over a message list.
fn apply_edits(msgs: &[NostrEvent]) -> (Vec<NostrEvent>, HashMap<String, String>) {
    let mut latest_edit: HashMap<String, (u64, String, String)> = HashMap::new();
    let mut is_edit_event: std::collections::HashSet<String> = std::collections::HashSet::new();

    for ev in msgs {
        let edit_target = ev.tags.iter().find_map(|t| {
            if t.first().map(String::as_str) == Some("e")
                && t.get(3).map(String::as_str) == Some("edit")
            {
                t.get(1).cloned()
            } else {
                None
            }
        });
        if let Some(target_id) = edit_target {
            is_edit_event.insert(ev.id.clone());
            let entry = latest_edit
                .entry(target_id)
                .or_insert((0, String::new(), String::new()));
            if ev.created_at >= entry.0 {
                *entry = (ev.created_at, ev.pubkey.clone(), ev.content.clone());
            }
        }
    }

    let mut edited_map = HashMap::new();
    let visible: Vec<NostrEvent> = msgs
        .iter()
        .filter(|e| !is_edit_event.contains(&e.id))
        .cloned()
        .map(|mut e| {
            if let Some((_, editor_pk, new_content)) = latest_edit.get(&e.id) {
                if editor_pk == &e.pubkey {
                    e.content = new_content.clone();
                    edited_map.insert(e.id.clone(), new_content.clone());
                }
            }
            e
        })
        .collect();
    (visible, edited_map)
}

fn snippet(content: &str, max: usize) -> String {
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("(no text)");
    let mut out = String::new();
    for (i, ch) in line.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// Board topic list (`#/z/<zone>/b/<channel_id>`).
#[component]
pub fn BoardView(zone: String, channel_id: String) -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let channels = use_channel_store();
    let auth = use_auth();
    let read_pos = use_read_positions();
    let zk_store = try_use_zone_key_store();
    let enc_gate = encryption_enabled();

    let cid_sub = channel_id.clone();
    let relay_sub = relay.clone();
    Effect::new(move |_| {
        channels.ensure_subscribed(&relay_sub, &cid_sub);
        channels.request_topic_roots(&relay_sub, &cid_sub, false);
    });

    let zones = load_zones();
    let resolved_zone = resolve_zone_param(&zone, &zones).cloned();
    let zone_name = resolved_zone
        .as_ref()
        .map(|z| z.label())
        .unwrap_or_else(|| zone.clone());
    let zone_id = resolved_zone
        .as_ref()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| zone.clone());
    let is_enc = enc_gate && resolved_zone.as_ref().is_some_and(|z| z.encrypted);

    let show_new_topic = RwSignal::new(false);
    let cid_title = channel_id.clone();
    let cid_list = channel_id.clone();
    let cid_composer = channel_id.clone();
    let zone_back = zone.clone();
    let zone_for_rows = zone.clone();

    view! {
        <div class="tui-container">
            <div class="tui-crumb">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::Zone { slug: zone_back.clone() })
                >"← " {zone_name.clone()}</button>
                <span>"/"</span>
                <strong>
                    "# "
                    {move || {
                        channels
                            .channels
                            .get()
                            .into_iter()
                            .find(|c| c.id == cid_title)
                            .map(|c| c.name)
                            .unwrap_or_else(|| shorten_pubkey(&cid_title))
                    }}
                </strong>
            </div>

            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">
                        "# "
                        {
                            let cid_h = channel_id.clone();
                            move || {
                                channels
                                    .channels
                                    .get()
                                    .into_iter()
                                    .find(|c| c.id == cid_h)
                                    .map(|c| c.name)
                                    .unwrap_or_else(|| shorten_pubkey(&cid_h))
                            }
                        }
                    </h1>
                    {is_enc.then(|| {
                        let zid = zone_id.clone();
                        move || {
                            let has_key = zk_store
                                .map(|s| s.latest_tracked(&zid).is_some())
                                .unwrap_or(false);
                            view! {
                                <span class=if has_key { "bbs-badge bbs-badge-ok" } else { "bbs-badge bbs-badge-warn" }>
                                    {if has_key { "🔒 E2E Encrypted · Unlocked" } else { "🔒 E2E Encrypted · Waiting for Key" }}
                                </span>
                            }
                        }
                    })}
                </div>
                <div class="tui-actions">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        on:click=move |_| show_new_topic.update(|v| *v = !*v)
                    >
                        {move || if show_new_topic.get() { "× Close Composer" } else { "+ New Topic" }}
                    </button>
                </div>
            </div>

            <Show when=move || show_new_topic.get() fallback=|| ()>
                <PostComposer
                    channel_id=cid_composer.clone()
                    zone_id=zone_id.clone()
                    reply_to=RwSignal::new(None)
                    default_reply=None
                    placeholder="Start a new topic (Markdown supported · paste or attach images)…"
                    on_sent=Callback::new(move |_| show_new_topic.set(false))
                />
            </Show>

            {move || {
                let raw = channels
                    .channel_messages
                    .get()
                    .get(&cid_list)
                    .cloned()
                    .unwrap_or_default();
                let (visible, _) = apply_edits(&raw);
                let threads = group_threads(&visible, &cid_list);
                let last_read = read_pos.last_read_timestamp(cid_list.clone()).get();

                if threads.is_empty() {
                    let body = if auth.is_authenticated().get() {
                        "No topics in this board yet. Tap '+ New Topic' to start the conversation."
                    } else {
                        "No topics loaded yet. If this is a gated zone, sign in to read and post."
                    };
                    return view! { <EmptyCard title="Board is empty" body=body /> }.into_any();
                }

                view! {
                    <div class="tui-stack">
                        {threads.into_iter().map(|t| {
                            let root_id = t.root.id.clone();
                            let root_nav = root_id.clone();
                            let z_nav = zone_for_rows.clone();
                            let cid_nav = cid_list.clone();
                            let title = snippet(&t.root.content, 110);
                            let is_unread = t.last_activity > last_read && last_read > 0;
                            let is_e2e = has_zk_tag(&t.root.tags);

                            view! {
                                <div
                                    class="tui-card tui-card-interactive tui-stack"
                                    role="button"
                                    tabindex="0"
                                    on:click=move |_| router.go(Route::Thread {
                                        zone: z_nav.clone(),
                                        channel_id: cid_nav.clone(),
                                        root_id: root_nav.clone(),
                                    })
                                >
                                    <div class="tui-row-between">
                                        <div class="tui-row">
                                            {is_unread.then(|| view! {
                                                <span class="bbs-badge bbs-badge-accent">"NEW"</span>
                                            })}
                                            {is_e2e.then(|| view! {
                                                <span class="bbs-badge bbs-badge-ok">"🔒"</span>
                                            })}
                                            <strong>{title}</strong>
                                        </div>
                                        <span class="bbs-badge">
                                            {format!("{} repl{}", t.reply_count, if t.reply_count == 1 { "y" } else { "ies" })}
                                        </span>
                                    </div>
                                    <div class="tui-row-between" style="font-size:0.8rem">
                                        <AuthorChip pubkey=t.root.pubkey.clone() />
                                        <span class="tui-muted">{format_relative_time(t.last_activity)}</span>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

/// Threaded conversation view (`#/z/<zone>/b/<channel_id>/t/<root_id>`).
#[component]
pub fn ThreadView(zone: String, channel_id: String, root_id: String) -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let channels = use_channel_store();
    let read_pos = use_read_positions();
    let auth = use_auth();
    let mute = use_mute_store();

    let cid_sub = channel_id.clone();
    let root_sub = root_id.clone();
    let relay_sub = relay.clone();
    Effect::new(move |_| {
        channels.ensure_subscribed(&relay_sub, &cid_sub);
        channels.fetch_by_id(&relay_sub, &root_sub);
    });

    let zones = load_zones();
    let resolved_zone = resolve_zone_param(&zone, &zones).cloned();
    let zone_id = resolved_zone
        .as_ref()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| zone.clone());
    let is_enc = encryption_enabled() && resolved_zone.as_ref().is_some_and(|z| z.encrypted);

    let root_author = channels
        .channel_messages
        .get_untracked()
        .get(&channel_id)
        .and_then(|v| v.iter().find(|e| e.id == root_id))
        .map(|e| e.pubkey.clone())
        .unwrap_or_default();
    let default_reply = Some((root_id.clone(), root_author));
    let reply_to = RwSignal::new(default_reply.clone());

    let z_back = zone.clone();
    let cid_back = channel_id.clone();
    let cid_msgs = channel_id.clone();
    let root_msgs = root_id.clone();
    let cid_comp = channel_id.clone();
    let zone_for_bm = zone.clone();

    view! {
        <div class="tui-container">
            <div class="tui-crumb">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::Board {
                        zone: z_back.clone(),
                        channel_id: cid_back.clone(),
                    })
                >"← Topics"</button>
                <span>"/"</span>
                <strong>"Thread"</strong>
                {is_enc.then(|| view! { <span class="bbs-badge bbs-badge-ok">"🔒 E2E"</span> })}
            </div>

            {move || {
                let raw = channels
                    .channel_messages
                    .get()
                    .get(&cid_msgs)
                    .cloned()
                    .unwrap_or_default();
                let (visible, edited_map) = apply_edits(&raw);
                let msgs = thread_messages(&visible, &cid_msgs, &root_msgs);

                if let Some(last) = msgs.last() {
                    read_pos.mark_read(&cid_msgs, &last.id, last.created_at);
                }

                if msgs.is_empty() {
                    return view! {
                        <EmptyCard
                            title="Loading thread…"
                            body="Fetching messages (and zone keys if encrypted) from the relay."
                        />
                    }.into_any();
                }

                let my_pk = auth.pubkey().get();

                view! {
                    <div class="tui-stack">
                        {msgs.into_iter().map(|ev| {
                            let is_root = ev.id == root_msgs;
                            let is_edited = edited_map.contains_key(&ev.id);
                            let is_mine = my_pk.as_deref() == Some(ev.pubkey.as_str());
                            let muted = mute.is_user_muted(&ev.pubkey);
                            let reveal_muted = RwSignal::new(false);
                            let ev_clone = ev.clone();
                            let z_bm = zone_for_bm.clone();
                            let cid_bm = cid_msgs.clone();
                            let root_bm = root_msgs.clone();

                            view! {
                                {move || if muted && !reveal_muted.get() {
                                    view! {
                                        <div class="tui-card tui-row-between">
                                            <span class="tui-muted">"Muted author hidden"</span>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                on:click=move |_| reveal_muted.set(true)
                                            >"Show anyway"</button>
                                        </div>
                                    }.into_any()
                                } else {
                                    view! {
                                        <PostCard
                                            event=ev_clone.clone()
                                            is_root=is_root
                                            is_edited=is_edited
                                            is_mine=is_mine
                                            is_encrypted_zone=is_enc
                                            zone=z_bm.clone()
                                            channel_id=cid_bm.clone()
                                            root_id=root_bm.clone()
                                            reply_to=reply_to
                                        />
                                    }.into_any()
                                }}
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}

            <PostComposer
                channel_id=cid_comp
                zone_id=zone_id
                reply_to=reply_to
                default_reply=default_reply
                placeholder="Write a reply (Markdown · @mention · paste/attach image)…"
                on_sent=Callback::new(|_| {})
            />
        </div>
    }
}

/// One rendered post card with Markdown, ASCII/Raw image toggle, reactions,
/// reply, bookmark, edit, delete, and report controls.
#[component]
fn PostCard(
    event: NostrEvent,
    is_root: bool,
    is_edited: bool,
    is_mine: bool,
    is_encrypted_zone: bool,
    zone: String,
    channel_id: String,
    root_id: String,
    reply_to: RwSignal<Option<(String, String)>>,
) -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();
    let reactions_store = use_reaction_store();
    let custom_emoji = use_custom_emoji_store();

    let ev_id = event.id.clone();
    let author_pk = event.pubkey.clone();
    let is_e2e = has_zk_tag(&event.tags);
    let imgs = extract_image_urls(&event.content);

    let show_picker = RwSignal::new(false);
    let editing = RwSignal::new(false);
    let edit_text = RwSignal::new(event.content.clone());
    let bm_tick = RwSignal::new(0u32);

    let reactions_sig = reactions_store.reactions_for(&ev_id);

    let toggle_react = {
        let ev_id = ev_id.clone();
        let author_pk = author_pk.clone();
        let relay = relay.clone();
        move |emoji: String| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to react", ToastVariant::Warning);
                return;
            };
            let me = signer.public_key().to_string();
            let ev_id = ev_id.clone();
            let author_pk = author_pk.clone();
            let relay = relay.clone();
            if let Some(prev_id) = reactions_store.my_reaction_id(&ev_id, &emoji, &me) {
                // Undo via NIP-09 kind-5
                let unsigned = UnsignedEvent {
                    pubkey: me,
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 5,
                    tags: vec![
                        vec!["e".into(), prev_id.clone()],
                        vec!["k".into(), "7".into()],
                    ],
                    content: String::new(),
                };
                reactions_store.remove_local(&prev_id);
                wasm_bindgen_futures::spawn_local(async move {
                    if let Ok(signed) = signer.sign_event(unsigned).await {
                        relay.publish(&signed);
                    }
                });
            } else {
                let unsigned = UnsignedEvent {
                    pubkey: me.clone(),
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 7,
                    tags: vec![vec!["e".into(), ev_id.clone()], vec!["p".into(), author_pk]],
                    content: emoji.clone(),
                };
                wasm_bindgen_futures::spawn_local(async move {
                    if let Ok(signed) = signer.sign_event(unsigned).await {
                        reactions_store.add_local(&signed.id, &ev_id, &emoji, &me);
                        relay.publish(&signed);
                    }
                });
            }
        }
    };

    let save_edit = {
        let ev_id = ev_id.clone();
        let cid = channel_id.clone();
        let relay = relay.clone();
        move |_| {
            let body = edit_text.get_untracked().trim().to_string();
            if body.is_empty() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let writer = ZoneWriter::capture();
            let me = signer.public_key().to_string();
            let cid = cid.clone();
            let ev_id = ev_id.clone();
            let relay = relay.clone();
            editing.set(false);
            wasm_bindgen_futures::spawn_local(async move {
                let tags = vec![
                    vec!["e".into(), cid.clone(), String::new(), "root".into()],
                    vec!["e".into(), ev_id, String::new(), "edit".into()],
                ];
                let unsigned = UnsignedEvent {
                    pubkey: me,
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 42,
                    tags,
                    content: body,
                };
                let unsigned = match writer.prepare(&cid, Some(signer.clone()), unsigned).await {
                    Ok(u) => u,
                    Err(e) => {
                        toasts.show(e, ToastVariant::Error);
                        return;
                    }
                };
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Edit published", ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("Sign failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let delete_post = {
        let ev_id = ev_id.clone();
        let relay = relay.clone();
        move |_| {
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let ev_id = ev_id.clone();
            let relay = relay.clone();
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: (js_sys::Date::now() / 1000.0) as u64,
                kind: 5,
                tags: vec![
                    vec!["e".into(), ev_id.clone()],
                    vec!["k".into(), "42".into()],
                ],
                content: "deleted by author".into(),
            };
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Deletion published (NIP-09)", ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("Delete failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let report_post = {
        let ev_id = ev_id.clone();
        let author_pk = author_pk.clone();
        let relay = relay.clone();
        move |_| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to report", ToastVariant::Warning);
                return;
            };
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: (js_sys::Date::now() / 1000.0) as u64,
                kind: 1984,
                tags: vec![
                    vec!["e".into(), ev_id.clone(), "other".into()],
                    vec!["p".into(), author_pk.clone()],
                ],
                content: "Reported via BBS client".into(),
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Report submitted (NIP-56)", ToastVariant::Info);
                    }
                    Err(e) => toasts.show(format!("Report failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let bm_id = ev_id.clone();
    let bm_author = author_pk.clone();
    let bm_preview = if is_encrypted_zone {
        "🔒 Encrypted post".to_string()
    } else {
        snippet(&event.content, 100)
    };
    let bm_created = event.created_at;

    let reply_id = ev_id.clone();
    let reply_pk = author_pk.clone();
    let save_edit_cb = Callback::new(save_edit);
    let toggle_react_cb = Callback::new(toggle_react);

    view! {
        <article
            class="bbs-post"
            class:bbs-post-root=is_root
            class:bbs-post-reply-indent=!is_root
        >
            <header class="bbs-post-header">
                <div class="tui-row">
                    <AuthorChip pubkey=author_pk.clone() />
                    {is_e2e.then(|| view! { <span class="bbs-badge bbs-badge-ok">"🔒"</span> })}
                    {is_edited.then(|| view! { <span class="bbs-badge">"edited"</span> })}
                </div>
                <span class="bbs-post-meta">{format_relative_time(event.created_at)}</span>
            </header>

            {move || if editing.get() {
                view! {
                    <div class="tui-stack">
                        <textarea
                            class="bbs-textarea"
                            prop:value=move || edit_text.get()
                            on:input=move |ev| edit_text.set(event_target_value(&ev))
                        ></textarea>
                        <div class="tui-row">
                            <button type="button" class="bbs-btn bbs-btn-primary bbs-btn-sm" on:click=move |ev| save_edit_cb.run(ev)>
                                "Save Edit"
                            </button>
                            <button type="button" class="bbs-btn bbs-btn-sm" on:click=move |_| editing.set(false)>
                                "Cancel"
                            </button>
                        </div>
                    </div>
                }.into_any()
            } else {
                view! { <MarkdownBody content=event.content.clone() /> }.into_any()
            }}

            {(!imgs.is_empty()).then(|| view! {
                <div class="tui-stack">
                    {imgs.into_iter().map(|src| view! { <PostImage src=src /> }).collect_view()}
                </div>
            })}

            <footer class="bbs-post-footer">
                {move || {
                    let list = reactions_sig.get();
                    list.into_iter().map(|r| {
                        let em = r.emoji.clone();
                        view! {
                            <button
                                type="button"
                                class="bbs-react-pill"
                                class:active=r.reacted_by_me
                                on:click=move |_| toggle_react_cb.run(em.clone())
                            >
                                <span>{r.emoji}</span>
                                <span>{r.count}</span>
                            </button>
                        }
                    }).collect_view()
                }}

                <button
                    type="button"
                    class="bbs-react-pill"
                    title="Add reaction"
                    on:click=move |_| show_picker.update(|v| *v = !*v)
                >"☺+"</button>

                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| reply_to.set(Some((reply_id.clone(), reply_pk.clone())))
                >"↳ Reply"</button>

                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| {
                        let pk = auth.pubkey().get_untracked();
                        let saved = toggle_bookmark(
                            pk.as_deref(),
                            BookmarkItem {
                                event_id: bm_id.clone(),
                                zone: zone.clone(),
                                channel_id: channel_id.clone(),
                                root_id: root_id.clone(),
                                author: bm_author.clone(),
                                preview: bm_preview.clone(),
                                created_at: bm_created,
                            },
                        );
                        bm_tick.update(|n| *n += 1);
                        toasts.show(
                            if saved { "Bookmarked" } else { "Bookmark removed" },
                            ToastVariant::Info,
                        );
                    }
                >
                    {
                        let bm_check_id = ev_id.clone();
                        move || {
                            let _ = bm_tick.get();
                            let pk = auth.pubkey().get();
                            if is_bookmarked(pk.as_deref(), &bm_check_id) {
                                "★ Saved"
                            } else {
                                "☆ Save"
                            }
                        }
                    }
                </button>

                {is_mine.then(|| view! {
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=move |_| editing.set(true)
                    >"Edit"</button>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=delete_post.clone()
                    >"Delete"</button>
                })}

                {(!is_mine).then(|| view! {
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=report_post.clone()
                    >"Report"</button>
                })}
            </footer>

            <Show when=move || show_picker.get() fallback=|| ()>
                <div class="tui-row" style="padding-top:0.35rem">
                    {move || {
                        let mut all: Vec<String> = BUILTIN_REACTIONS.iter().map(|s| s.to_string()).collect();
                        for c in custom_emoji.emojis() {
                            if !all.contains(&c) {
                                all.push(c);
                            }
                        }
                        all.into_iter().map(|em| {
                            let em_click = em.clone();
                            view! {
                                <button
                                    type="button"
                                    class="bbs-react-pill"
                                    on:click=move |_| {
                                        toggle_react_cb.run(em_click.clone());
                                        show_picker.set(false);
                                    }
                                >{em}</button>
                            }
                        }).collect_view()
                    }}
                </div>
            </Show>
        </article>
    }
}

/// On-theme phosphor ASCII image card with instant `[ASCII / Raw]` toggle + `[open ↗]`.
#[component]
fn PostImage(src: String) -> impl IntoView {
    let raw_mode = RwSignal::new(false);
    let cols = {
        #[cfg(target_arch = "wasm32")]
        {
            web_sys::window()
                .and_then(|w| w.inner_width().ok())
                .and_then(|v| v.as_f64())
                .map(|w| if w < 640.0 { 40 } else { 68 })
                .unwrap_or(68)
        }
        #[cfg(not(target_arch = "wasm32"))]
        68
    };
    let src_open = src.clone();
    let src_raw = src.clone();
    view! {
        <div class="bbs-ascii-card">
            <div class="bbs-ascii-card-head">
                <span>"▞ IMG ▚"</span>
                <div class="tui-row">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=move |_| raw_mode.update(|v| *v = !*v)
                    >{move || if raw_mode.get() { "ASCII view" } else { "Raw image" }}</button>
                    <a href=src_open target="_blank" rel="noopener">"open ↗"</a>
                </div>
            </div>
            {move || if raw_mode.get() {
                view! { <img class="bbs-raw-img" src=src_raw.clone() alt="Attached image" loading="lazy" /> }.into_any()
            } else {
                view! { <AsciiImg src=src.clone() cols=cols /> }.into_any()
            }}
        </div>
    }
}

/// Rich Markdown + Image + Encrypted-Zone Composer shared by BoardView and ThreadView.
#[component]
fn PostComposer(
    channel_id: String,
    zone_id: String,
    reply_to: RwSignal<Option<(String, String)>>,
    default_reply: Option<(String, String)>,
    placeholder: &'static str,
    on_sent: Callback<()>,
) -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("BbsConfig");

    let initial_draft = load_draft(auth.pubkey().get_untracked().as_deref(), &channel_id);
    let text = RwSignal::new(initial_draft);
    let sending = RwSignal::new(false);
    let uploading = RwSignal::new(false);
    let file_ref = NodeRef::<leptos::html::Input>::new();

    // Auto-save per-identity draft
    let cid_draft = channel_id.clone();
    Effect::new(move |_| {
        let val = text.get();
        let pk = auth.pubkey().get();
        save_draft(pk.as_deref(), &cid_draft, &val);
    });

    let submit = {
        let cid = channel_id.clone();
        let relay = relay.clone();
        let default_reply = default_reply.clone();
        move || {
            let body = text.get_untracked().trim().to_string();
            if body.is_empty() || sending.get_untracked() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in first to post", ToastVariant::Warning);
                return;
            };
            let writer = ZoneWriter::capture();
            let me = signer.public_key().to_string();
            let rtarget = reply_to.get_untracked();
            let cid = cid.clone();
            let relay = relay.clone();
            let default_reply = default_reply.clone();
            sending.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let mut tags = channel_message_tags(&cid, rtarget);
                // Resolve @handles against ProfileCache
                if let Some(pc) = try_use_profile_cache() {
                    let handles: Vec<String> = body
                        .split_whitespace()
                        .filter_map(|w| w.strip_prefix('@'))
                        .map(|h| {
                            h.trim_matches(|c: char| {
                                !c.is_ascii_alphanumeric() && c != '_' && c != '-'
                            })
                            .to_ascii_lowercase()
                        })
                        .filter(|h| !h.is_empty())
                        .collect();
                    if !handles.is_empty() {
                        let entries = pc.entries.get_untracked();
                        for (pk, entry) in entries {
                            let hit = entry
                                .name
                                .as_deref()
                                .map(|n| handles.contains(&n.to_ascii_lowercase()))
                                .unwrap_or(false)
                                || entry
                                    .display_name
                                    .as_deref()
                                    .map(|n| {
                                        handles.contains(&n.to_ascii_lowercase().replace(' ', ""))
                                    })
                                    .unwrap_or(false);
                            if hit
                                && !tags.iter().any(|t| {
                                    t.first().map(String::as_str) == Some("p")
                                        && t.get(1).map(String::as_str) == Some(pk.as_str())
                                })
                            {
                                tags.push(vec!["p".into(), pk]);
                            }
                        }
                    }
                }

                let unsigned = UnsignedEvent {
                    pubkey: me,
                    created_at: (js_sys::Date::now() / 1000.0) as u64,
                    kind: 42,
                    tags,
                    content: body,
                };
                let unsigned = match writer.prepare(&cid, Some(signer.clone()), unsigned).await {
                    Ok(u) => u,
                    Err(e) => {
                        sending.set(false);
                        toasts.show(e, ToastVariant::Error);
                        return;
                    }
                };
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        let toasts_ack = toasts;
                        let cb = Rc::new(move |ok: bool, msg: String| {
                            if !ok {
                                toasts_ack.show(
                                    if msg.is_empty() {
                                        "Relay rejected post".to_string()
                                    } else {
                                        format!("Relay rejected: {msg}")
                                    },
                                    ToastVariant::Error,
                                );
                            }
                        });
                        let _ = relay.publish_with_ack(&signed, Some(cb));
                        text.set(String::new());
                        reply_to.set(default_reply);
                        on_sent.run(());
                    }
                    Err(e) => toasts.show(format!("Sign failed: {e}"), ToastVariant::Error),
                }
                sending.set(false);
            });
        }
    };

    let on_pick_file = {
        let zid = zone_id.clone();
        move |ev: web_sys::Event| {
            #[cfg(target_arch = "wasm32")]
            {
                use wasm_bindgen::JsCast;
                let Some(inp) = ev
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                else {
                    return;
                };
                let Some(file) = inp.files().and_then(|fl| fl.get(0)) else {
                    return;
                };
                inp.set_value("");
                let Some(signer) = auth.get_signer() else {
                    toasts.show("Sign in to upload images", ToastVariant::Warning);
                    return;
                };
                let pk = signer.public_key().to_string();
                let pod_api = cfg.with_value(|c| c.pod_api.clone());
                let zid = zid.clone();
                uploading.set(true);
                wasm_bindgen_futures::spawn_local(async move {
                    let effective_pod = if !pod_api.is_empty() {
                        pod_api
                    } else {
                        nostr_bbs_client_core::utils::relay_url::pod_api_base()
                    };
                    let _ = zid;
                    let res = crate::upload::compress_and_upload(
                        &file,
                        &pk,
                        signer.as_ref(),
                        &effective_pod,
                    )
                    .await;
                    match res {
                        Ok(url) => {
                            text.update(|d| {
                                if !d.is_empty() && !d.ends_with('\n') && !d.ends_with(' ') {
                                    d.push('\n');
                                }
                                d.push_str(&url);
                            });
                            toasts.show("Image uploaded to pod", ToastVariant::Success);
                        }
                        Err(e) => toasts.show(format!("Upload failed: {e}"), ToastVariant::Error),
                    }
                    uploading.set(false);
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            let _ = (ev, &zid, &cfg);
        }
    };

    let submit_click = submit.clone();
    let submit_key = submit.clone();
    let default_clear = default_reply.clone();

    view! {
        {move || if !auth.is_authenticated().get() {
            view! {
                <div class="tui-card tui-row-between">
                    <span class="tui-muted">"Sign in to post or reply in this board."</span>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary bbs-btn-sm"
                        on:click=move |_| use_router().go(Route::Settings)
                    >"Sign in"</button>
                </div>
            }.into_any()
        } else {
            let dc = default_clear.clone();
            let sc = submit_click.clone();
            let sk = submit_key.clone();
            let op = on_pick_file.clone();
            view! {
                <div class="bbs-composer">
                    {move || reply_to.get().map(|(id, _)| {
                        let dc = dc.clone();
                        view! {
                            <div class="tui-row-between" style="font-size:0.8rem">
                                <span class="tui-muted">"↳ Replying to " {shorten_pubkey(&id)}</span>
                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                    on:click=move |_| reply_to.set(dc.clone())
                                >"Reset target"</button>
                            </div>
                        }
                    })}
                    <textarea
                        class="bbs-textarea"
                        placeholder=placeholder
                        prop:value=move || text.get()
                        on:input=move |ev| text.set(event_target_value(&ev))
                        on:keydown=move |ev| {
                            if (ev.ctrl_key() || ev.meta_key()) && ev.key() == "Enter" {
                                ev.prevent_default();
                                sk();
                            }
                        }
                    ></textarea>
                    <div class="tui-row-between">
                        <div class="tui-row">
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-sm"
                                disabled=move || uploading.get()
                                on:click=move |_| {
                                    if let Some(el) = file_ref.get_untracked() {
                                        el.click();
                                    }
                                }
                            >
                                {move || if uploading.get() { "… Uploading" } else { "▞ Image" }}
                            </button>
                            <input
                                node_ref=file_ref
                                type="file"
                                accept="image/*"
                                class="bbs-file-input"
                                on:change=op
                            />
                            <span class="tui-muted" style="font-size:0.76rem">"Ctrl+Enter to send"</span>
                        </div>
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            disabled=move || sending.get() || text.get().trim().is_empty()
                            on:click=move |_| sc()
                        >
                            {move || if sending.get() { "Sending…" } else { "Send ▶" }}
                        </button>
                    </div>
                </div>
            }.into_any()
        }}
    }
}
