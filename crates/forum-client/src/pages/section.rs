//! Section page -- messages within a specific forum section.
//! Route: /forums/:category/:section

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use nostr_core::NostrEvent;
use std::rc::Rc;

use wasm_bindgen_futures::spawn_local;

use crate::auth::use_auth;
use crate::components::access_denied::AccessDenied;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::message_bubble::{MessageBubble, MessageData};
use crate::components::message_input::MessageInput;
use crate::components::reaction_bar::Reaction;
use crate::components::swipeable_message::SwipeableMessage;
use crate::components::typing_indicator::TypingIndicator;
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::zone_access::use_zone_access;
use crate::utils::{capitalize, set_timeout_once};

#[derive(Clone, Debug)]
struct SectionHeader {
    name: String,
    description: String,
    channel_id: String,
}

#[component]
pub fn SectionPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let conn_state = relay.connection_state();
    let zone_access = use_zone_access();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();
    let section_slug = move || params.read().get("section").unwrap_or_default();

    // Zone access gate: the category slug IS the zone ID
    let has_zone_access = Memo::new(move |_| {
        let cat = category_slug();
        match cat.as_str() {
            "home" => zone_access.home.get(),
            "members" => zone_access.members.get(),
            "private" => zone_access.private_zone.get(),
            _ => true, // unknown zones default to accessible
        }
    });

    let (messages, section_info) = (
        RwSignal::new(Vec::<MessageData>::new()),
        RwSignal::<Option<SectionHeader>>::new(None),
    );
    let (loading, error_msg) = (RwSignal::new(true), RwSignal::<Option<String>>::new(None));
    let typing_pubkeys = RwSignal::new(Vec::<String>::new());
    let messages_container = NodeRef::<leptos::html::Div>::new();
    let (ch_sub_id, msg_sub_id) = (
        RwSignal::<Option<String>>::new(None),
        RwSignal::<Option<String>>::new(None),
    );
    let relay_for_send = relay.clone();
    let (relay_for_ch, relay_for_msgs, relay_for_cleanup) = (relay.clone(), relay.clone(), relay);

    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if ch_sub_id.get_untracked().is_some() {
            return;
        }

        loading.set(true);
        error_msg.set(None);

        let filter = Filter {
            kinds: Some(vec![40]),
            ..Default::default()
        };

        let sec_slug = section_slug();
        let cat_slug = category_slug();
        let section_info_sig = section_info;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 40 {
                return;
            }

            // Check if this channel matches the section slug
            let (name, description) = parse_content(&event.content);
            let name_slug = slugify(&name);
            let section_tag = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "section")
                .map(|t| t[1].clone())
                .unwrap_or_default();

            let tag_matches = section_tag.contains(&cat_slug)
                || section_tag
                    .to_lowercase()
                    .contains(&cat_slug.to_lowercase());
            let name_matches = name_slug == sec_slug
                || name.to_lowercase() == sec_slug.to_lowercase()
                || event.id.starts_with(&sec_slug);

            if (tag_matches || cat_slug.is_empty()) && name_matches {
                section_info_sig.set(Some(SectionHeader {
                    name,
                    description,
                    channel_id: event.id.clone(),
                }));
            }
        });

        let loading_sig = loading;
        let section_info_for_eose = section_info;
        let on_eose = Rc::new(move || {
            if section_info_for_eose.get_untracked().is_none() {
                loading_sig.set(false);
            }
        });

        let id = relay_for_ch.subscribe(vec![filter], on_event, Some(on_eose));
        ch_sub_id.set(Some(id));

        set_timeout_once(
            move || {
                if loading_sig.get_untracked() {
                    loading_sig.set(false);
                }
            },
            8000,
        );
    });

    Effect::new(move |_| {
        let info = section_info.get();
        let info = match info {
            Some(i) => i,
            None => return,
        };
        if msg_sub_id.get_untracked().is_some() {
            return;
        }

        let msg_filter = Filter {
            kinds: Some(vec![42]),
            e_tags: Some(vec![info.channel_id.clone()]),
            ..Default::default()
        };

        let messages_sig = messages;
        let on_msg = Rc::new(move |event: NostrEvent| {
            if event.kind != 42 {
                return;
            }
            // Parse reply info from tags
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
            let msg = MessageData {
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
            };
            messages_sig.update(|list| {
                if !list.iter().any(|m| m.id == msg.id) {
                    list.push(msg);
                    list.sort_by_key(|m| m.created_at);
                }
            });
        });

        let loading_sig = loading;
        let on_eose = Rc::new(move || {
            loading_sig.set(false);
        });

        let id = relay_for_msgs.subscribe(vec![msg_filter], on_msg, Some(on_eose));
        msg_sub_id.set(Some(id));
    });

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

    on_cleanup(move || {
        if let Some(id) = ch_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
        if let Some(id) = msg_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    let do_send_text = {
        let relay = relay_for_send;
        move |content: String| {
            let cid = section_info
                .get_untracked()
                .map(|i| i.channel_id)
                .unwrap_or_default();
            if cid.is_empty() {
                return;
            }

            let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
            if pubkey.is_empty() {
                error_msg.set(Some("Not authenticated".to_string()));
                return;
            }

            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_core::UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 42,
                tags: vec![vec![
                    "e".to_string(),
                    cid,
                    String::new(),
                    "root".to_string(),
                ]],
                content,
            };

            let relay = relay.clone();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                    }
                }
            });
        }
    };

    let send_callback = Callback::new(do_send_text);
    let is_authed = auth.is_authenticated();

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
                            BreadcrumbItem::link(capitalize(&category_slug()), format!("/forums/{}", category_slug())),
                            BreadcrumbItem::current(
                                section_info.get_untracked().map(|i| i.name).unwrap_or_else(|| capitalize(&section_slug()))
                            ),
                        ] />

                        <h1 class="text-2xl font-bold text-white">
                            {move || section_info.get().map(|i| i.name).unwrap_or_else(|| "Loading...".to_string())}
                        </h1>
                        {move || section_info.get().and_then(|i| {
                            if i.description.is_empty() { None } else {
                                Some(view! { <p class="text-sm text-gray-400 mt-1">{i.description}</p> })
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
                        <MessageInput on_send=send_callback />
                    </div>
                </div>
            </Show>
        </div>
        </Show>
    }
}

fn parse_content(content: &str) -> (String, String) {
    serde_json::from_str::<serde_json::Value>(content)
        .map(|v| {
            let n = v
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed")
                .to_string();
            let d = v
                .get("about")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (n, d)
        })
        .unwrap_or_else(|_| ("Unnamed".to_string(), String::new()))
}

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
