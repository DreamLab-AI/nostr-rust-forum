//! DM conversation view page.
//!
//! Route: `/dm/:pubkey`
//! Displays decrypted messages with a counterparty in chronological order,
//! provides a compose box for sending NIP-44 encrypted kind 4 events, and
//! auto-scrolls on new messages.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;

use crate::app::base_href;
use wasm_bindgen::JsCast;

use crate::auth::use_auth;
use crate::components::image_upload::ImageUpload;
use crate::components::swipeable_message::SwipeableMessage;
use crate::dm::{provide_dm_store, use_dm_store, DMMessage};
use crate::relay::{ConnectionState, RelayConnection};
use crate::components::user_display::use_display_name_memo;
use crate::utils::{
    arrow_left_svg, format_relative_time, pubkey_color, set_timeout_once,
};

/// DM chat view component for a single conversation.
#[component]
pub fn DmChatPage() -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    // Provide DM store for this subtree
    provide_dm_store();
    let dm_store = use_dm_store();

    let params = use_params_map();
    let recipient_pubkey = move || params.read().get("pubkey").unwrap_or_default();

    // State
    let message_input = RwSignal::new(String::new());
    let sending = RwSignal::new(false);
    let send_error: RwSignal<Option<String>> = RwSignal::new(None);
    let messages_container = NodeRef::<leptos::html::Div>::new();
    let fetch_started = RwSignal::new(false);
    let show_image_upload = RwSignal::new(false);

    // Subscribe to conversation messages when connected
    let relay_for_sub = relay.clone();
    Effect::new(move |_| {
        let state = conn_state.get();
        let rpk = recipient_pubkey();
        if state != ConnectionState::Connected || rpk.is_empty() {
            return;
        }
        if fetch_started.get_untracked() {
            return;
        }

        let privkey = auth.get_privkey_bytes();
        let pubkey = auth.pubkey().get_untracked();

        if let (Some(sk), Some(pk)) = (privkey, pubkey) {
            fetch_started.set(true);
            dm_store.select_conversation(&rpk);
            dm_store.load_conversation_messages(&relay_for_sub, &sk, &pk, &rpk);
            dm_store.subscribe_incoming(&relay_for_sub, &sk, &pk);
        }
    });

    // Auto-scroll to bottom when messages change
    let messages = dm_store.messages();
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

    // Cleanup on unmount
    let relay_for_cleanup = relay.clone();
    on_cleanup(move || {
        dm_store.cleanup(&relay_for_cleanup);
    });

    // Send message handler
    let relay_for_send = relay;
    let on_send = move |_: ()| {
        let content = message_input.get_untracked();
        let content = content.trim().to_string();
        if content.is_empty() || sending.get_untracked() {
            return;
        }

        let rpk = recipient_pubkey();
        if rpk.is_empty() {
            return;
        }

        let privkey = auth.get_privkey_bytes();
        let my_pubkey = auth.pubkey().get_untracked();

        match (privkey, my_pubkey) {
            (Some(sk), Some(pk)) => {
                sending.set(true);
                send_error.set(None);
                message_input.set(String::new());

                match dm_store.send_message(&relay_for_send, &rpk, &content, &sk, &pk) {
                    Ok(()) => {
                        sending.set(false);
                    }
                    Err(e) => {
                        web_sys::console::error_1(&format!("[DM] Send failed: {}", e).into());
                        send_error.set(Some(e));
                        sending.set(false);
                        message_input.set(content);
                    }
                }
            }
            _ => {
                send_error.set(Some(
                    "Signing key not available. Please re-authenticate.".to_string(),
                ));
            }
        }
    };

    // Handle Enter key
    let on_send_clone = on_send.clone();
    let on_keydown = move |ev: leptos::ev::KeyboardEvent| {
        if ev.key() == "Enter" && !ev.shift_key() {
            ev.prevent_default();
            on_send_clone(());
        }
    };

    let on_input = move |ev: leptos::ev::Event| {
        let target = ev.target().unwrap();
        let input: web_sys::HtmlInputElement = target.unchecked_into();
        message_input.set(input.value());
    };

    let is_loading = dm_store.is_loading();
    let my_pubkey = auth.pubkey();

    // Short display name for recipient (resolved from NameCache)
    let recipient_display_memo = {
        let rpk = recipient_pubkey();
        use_display_name_memo(rpk)
    };

    view! {
        <div class="flex flex-col h-[calc(100vh-64px)]">
            // Header
            <div class="bg-gray-800 border-b border-gray-700 p-4">
                <div class="max-w-2xl mx-auto">
                    <div class="flex items-center gap-3">
                        <A href=base_href("/dm") attr:class="text-gray-400 hover:text-white transition-colors p-1 rounded hover:bg-gray-700">
                            {arrow_left_svg()}
                        </A>

                        // Avatar
                        <div
                            class="w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0"
                            style=move || {
                                let rpk = recipient_pubkey();
                                format!("background-color: {}", pubkey_color(&rpk))
                            }
                        >
                            {move || {
                                let rpk = recipient_pubkey();
                                if rpk.len() >= 2 { rpk[..2].to_uppercase() } else { "??".to_string() }
                            }}
                        </div>

                        <div class="flex-1 min-w-0">
                            <h1 class="text-lg font-bold text-white truncate">
                                {move || recipient_display_memo.get()}
                            </h1>
                            <p class="text-[10px] font-mono text-gray-500 truncate -mt-0.5 mb-0.5">
                                {move || {
                                    let rpk = recipient_pubkey();
                                    crate::utils::shorten_pubkey(&rpk)
                                }}
                            </p>
                            <div class="flex items-center gap-2">
                                // Connection indicator
                                {move || {
                                    let state = conn_state.get();
                                    match state {
                                        ConnectionState::Connected => view! {
                                            <span class="text-xs text-green-400 flex items-center gap-1">
                                                <span class="w-1.5 h-1.5 rounded-full bg-green-400"></span>
                                                "Connected"
                                            </span>
                                        }.into_any(),
                                        ConnectionState::Reconnecting => view! {
                                            <span class="text-xs text-yellow-400 flex items-center gap-1">
                                                <span class="animate-pulse w-1.5 h-1.5 rounded-full bg-yellow-400"></span>
                                                "Reconnecting"
                                            </span>
                                        }.into_any(),
                                        _ => view! {
                                            <span class="text-xs text-red-400 flex items-center gap-1">
                                                <span class="w-1.5 h-1.5 rounded-full bg-red-400"></span>
                                                "Disconnected"
                                            </span>
                                        }.into_any(),
                                    }
                                }}

                                <span class="text-xs text-gray-600">"|"</span>
                                <span class="text-xs text-green-400/50 flex items-center gap-1">
                                    {lock_icon_tiny()}
                                    "End-to-end encrypted"
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            // Error banner
            {move || {
                send_error.get().map(|msg| view! {
                    <div class="max-w-2xl mx-auto p-2">
                        <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-2 flex items-center justify-between">
                            <span class="text-red-200 text-sm">{msg}</span>
                            <button class="text-red-400 hover:text-red-200 text-xs ml-4"
                                on:click=move |_| send_error.set(None)
                            >
                                "dismiss"
                            </button>
                        </div>
                    </div>
                })
            }}

            // Messages area
            <div
                class="flex-1 overflow-y-auto p-4 bg-gray-900"
                node_ref=messages_container
            >
                <div class="max-w-2xl mx-auto">
                    {move || {
                        if is_loading.get() {
                            view! {
                                <div class="flex items-center justify-center py-20">
                                    <div class="animate-pulse text-gray-400">"Loading messages..."</div>
                                </div>
                            }.into_any()
                        } else {
                            let msgs = messages.get();
                            if msgs.is_empty() {
                                view! {
                                    <div class="flex flex-col items-center justify-center py-20">
                                        <div class="animate-gentle-float mb-4">
                                            {chat_bubble_icon_large()}
                                        </div>
                                        <p class="text-center text-gray-400">"No messages yet. Send the first one!"</p>
                                        <p class="text-xs text-green-400/40 mt-2 flex items-center gap-1">
                                            {lock_icon_tiny()}
                                            "Messages are encrypted with NIP-44"
                                        </p>
                                    </div>
                                }.into_any()
                            } else {
                                let my_pk = my_pubkey.get().unwrap_or_default();
                                view! {
                                    <div class="space-y-1">
                                        <MessageListWithDateSeparators msgs=msgs my_pk=my_pk />
                                    </div>
                                }.into_any()
                            }
                        }
                    }}
                </div>
            </div>

            // Compose area
            <div class="bg-gray-800 border-t border-gray-700 p-4">
                <div class="max-w-2xl mx-auto">
                    // Image upload panel (collapsed by default)
                    <Show when=move || show_image_upload.get()>
                        <div class="mb-3">
                            <ImageUpload on_upload=Callback::new(move |url: String| {
                                // Insert the image URL into the message input
                                message_input.update(|v| {
                                    if !v.is_empty() { v.push(' '); }
                                    v.push_str(&url);
                                });
                                show_image_upload.set(false);
                            }) />
                        </div>
                    </Show>

                    <div class="flex gap-2 items-end">
                        // Image upload toggle button
                        <button
                            class=move || {
                                if show_image_upload.get() {
                                    "w-10 h-10 rounded-full flex items-center justify-center bg-amber-500/20 text-amber-400 transition-colors flex-shrink-0 border border-amber-500/30"
                                } else {
                                    "w-10 h-10 rounded-full flex items-center justify-center bg-gray-700 text-gray-400 hover:text-amber-400 transition-colors flex-shrink-0"
                                }
                            }
                            on:click=move |_| show_image_upload.update(|v| *v = !*v)
                            title="Attach image"
                        >
                            <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <rect x="3" y="3" width="18" height="18" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <circle cx="8.5" cy="8.5" r="1.5"/>
                                <polyline points="21 15 16 10 5 21" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </button>
                        <input
                            type="text"
                            class="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2.5 text-white placeholder-gray-400 focus:outline-none focus:border-amber-500 transition-colors"
                            placeholder="Type a message..."
                            prop:value=move || message_input.get()
                            on:input=on_input
                            on:keydown=on_keydown
                            prop:disabled=move || sending.get()
                        />
                        <button
                            class=move || {
                                if sending.get() || message_input.get().trim().is_empty() {
                                    "w-10 h-10 rounded-full flex items-center justify-center bg-gray-600 text-gray-400 transition-colors flex-shrink-0"
                                } else {
                                    "w-10 h-10 rounded-full flex items-center justify-center bg-amber-500 hover:bg-amber-400 text-white transition-colors flex-shrink-0"
                                }
                            }
                            on:click=move |_| on_send(())
                            disabled=move || sending.get() || message_input.get().trim().is_empty()
                        >
                            {send_arrow_icon()}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}

/// Render messages with date separators between days.
#[component]
fn MessageListWithDateSeparators(msgs: Vec<DMMessage>, my_pk: String) -> impl IntoView {
    let mut fragments: Vec<leptos::tachys::view::any_view::AnyView> = Vec::new();
    let mut prev_timestamp: u64 = 0;

    for msg in msgs.into_iter() {
        // Insert date separator if day changed
        if prev_timestamp > 0 && should_show_date_separator(prev_timestamp, msg.timestamp) {
            let label = format_date_label(msg.timestamp);
            fragments.push(
                view! {
                    <div class="flex items-center gap-3 my-4">
                        <div class="flex-1 border-t border-gray-800"></div>
                        <span class="text-xs text-gray-600">{label}</span>
                        <div class="flex-1 border-t border-gray-800"></div>
                    </div>
                }
                .into_any(),
            );
        }
        prev_timestamp = msg.timestamp;

        let is_mine = msg.sender_pubkey == my_pk;
        fragments.push(view! {
            <SwipeableMessage>
                <DmBubble message=msg is_mine=is_mine/>
            </SwipeableMessage>
        }.into_any());
    }

    fragments.collect_view()
}

/// A single DM message bubble with alignment based on sender.
#[component]
fn DmBubble(message: DMMessage, is_mine: bool) -> impl IntoView {
    let time_display = format_relative_time(message.timestamp);
    let content = message.content.clone();

    view! {
        <div class=move || {
            if is_mine {
                "flex justify-end py-1 animate-fadeIn"
            } else {
                "flex justify-start py-1 animate-fadeIn"
            }
        }>
            <div class=move || {
                if is_mine {
                    "max-w-[75%] bg-amber-500/20 border border-amber-500/30 rounded-2xl rounded-br-md px-4 py-2"
                } else {
                    "max-w-[75%] bg-gray-800 border border-gray-700 rounded-2xl rounded-bl-md px-4 py-2"
                }
            }>
                <p class="text-sm text-gray-200 break-words whitespace-pre-wrap">
                    {content}
                </p>
                <div class=move || {
                    if is_mine {
                        "flex items-center justify-end gap-1 mt-1"
                    } else {
                        "flex items-center gap-1 mt-1"
                    }
                }>
                    <span class="text-xs text-gray-500">{time_display}</span>
                </div>
            </div>
        </div>
    }
}

/// Check if a date separator should be shown between two timestamps.
fn should_show_date_separator(prev: u64, current: u64) -> bool {
    // Compare day boundaries rather than raw diff
    let prev_day = prev / 86400;
    let current_day = current / 86400;
    prev_day != current_day
}

/// Format a timestamp into a human-readable date label.
fn format_date_label(timestamp: u64) -> String {
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let today_start = now - (now % 86400);
    let yesterday_start = today_start - 86400;

    if timestamp >= today_start {
        "Today".to_string()
    } else if timestamp >= yesterday_start {
        "Yesterday".to_string()
    } else {
        let date = js_sys::Date::new_0();
        date.set_time((timestamp as f64) * 1000.0);
        let month = date.get_month();
        let day = date.get_date();
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month_name = months.get(month as usize).unwrap_or(&"???");
        format!("{} {}", month_name, day)
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn lock_icon_tiny() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
    }
}

fn send_arrow_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="12" y1="19" x2="12" y2="5"/>
            <polyline points="5 12 12 5 19 12"/>
        </svg>
    }
}

fn chat_bubble_icon_large() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-16 h-16 text-amber-400/20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
        </svg>
    }
}
