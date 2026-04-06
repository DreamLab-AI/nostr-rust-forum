//! DM conversation list page.
//!
//! Route: `/dm`
//! Auth-gated. On mount, fetches conversations from the relay, displays them
//! sorted by most recent, and provides a "New Message" input for starting
//! conversations by pubkey.

use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::dm::{provide_dm_store, use_dm_store, DMConversation};
use crate::relay::{ConnectionState, RelayConnection};
use crate::utils::{format_relative_time, pubkey_color};

/// DM conversation list page component.
#[component]
pub fn DmListPage() -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    // Provide DM store for this subtree
    provide_dm_store();
    let dm_store = use_dm_store();

    // New conversation input
    let new_pubkey_input = RwSignal::new(String::new());
    let show_new_dm = RwSignal::new(false);
    let new_dm_error: RwSignal<Option<String>> = RwSignal::new(None);

    // Track whether we've already started fetching
    let fetch_started = RwSignal::new(false);

    // Fetch conversations when connected
    let relay_for_fetch = relay.clone();
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if fetch_started.get_untracked() {
            return;
        }

        let privkey = auth.get_privkey_bytes();
        let pubkey = auth.pubkey().get_untracked();

        if let (Some(sk), Some(pk)) = (privkey, pubkey) {
            fetch_started.set(true);
            dm_store.fetch_conversations(&relay_for_fetch, &sk, &pk);
            dm_store.subscribe_incoming(&relay_for_fetch, &sk, &pk);
        }
    });

    // Cleanup on unmount
    let relay_for_cleanup = relay;
    on_cleanup(move || {
        dm_store.cleanup(&relay_for_cleanup);
    });

    // Navigate to a new DM conversation
    let on_start_conversation = move |_| {
        let pk = new_pubkey_input.get_untracked();
        let pk = pk.trim().to_lowercase();

        if pk.is_empty() {
            new_dm_error.set(Some("Enter a pubkey to start a conversation".to_string()));
            return;
        }

        // Validate hex pubkey (64 chars, valid hex)
        if pk.len() != 64 || hex::decode(&pk).is_err() {
            new_dm_error.set(Some(
                "Invalid pubkey. Must be 64 hex characters.".to_string(),
            ));
            return;
        }

        // Don't DM yourself
        let my_pk = auth.pubkey().get_untracked().unwrap_or_default();
        if pk == my_pk {
            new_dm_error.set(Some("You cannot send a DM to yourself.".to_string()));
            return;
        }

        new_dm_error.set(None);
        new_pubkey_input.set(String::new());
        show_new_dm.set(false);

        // Navigate to the DM chat page
        if let Some(window) = web_sys::window() {
            let _ = window
                .location()
                .set_href(&base_href(&format!("/dm/{}", pk)));
        }
    };

    let on_new_pubkey_input = move |ev: leptos::ev::Event| {
        let target = ev.target().unwrap();
        let input: web_sys::HtmlInputElement = target.unchecked_into();
        new_pubkey_input.set(input.value());
    };

    let on_new_pubkey_keydown = {
        let on_start = on_start_conversation;
        move |ev: leptos::ev::KeyboardEvent| {
            if ev.key() == "Enter" {
                ev.prevent_default();
                on_start(());
            }
        }
    };

    let conversations = dm_store.conversations();
    let is_loading = dm_store.is_loading();
    let error = dm_store.error();

    view! {
        <div class="max-w-2xl mx-auto p-4 sm:p-6">
            // Header
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h1 class="text-3xl font-bold text-white mb-1 flex items-center gap-2">
                        {shield_icon()}
                        "Direct Messages"
                    </h1>
                    <p class="text-gray-400 text-sm">"Private encrypted conversations"</p>
                    <div class="text-xs text-green-400/60 flex items-center gap-1 mt-1">
                        {lock_icon_small()}
                        "NIP-44 Encrypted"
                    </div>
                </div>
                <button
                    class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm flex items-center gap-1.5"
                    on:click=move |_| {
                        show_new_dm.update(|v| *v = !*v);
                        new_dm_error.set(None);
                    }
                >
                    {move || if show_new_dm.get() {
                        view! { <>{x_icon_small()}" Cancel"</> }.into_any()
                    } else {
                        view! { <>{plus_icon()}" New Message"</> }.into_any()
                    }}
                </button>
            </div>

            // New DM input
            <Show when=move || show_new_dm.get()>
                <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 mb-4">
                    <label class="block text-sm text-gray-300 mb-1">"Send to"</label>
                    <p class="text-xs text-gray-500 mb-2">"Enter their pubkey (64 hex characters)"</p>
                    <div class="flex gap-2">
                        <input
                            type="text"
                            class="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-amber-500 transition-colors text-sm font-mono"
                            placeholder="e.g. a1b2c3d4..."
                            prop:value=move || new_pubkey_input.get()
                            on:input=on_new_pubkey_input
                            on:keydown=on_new_pubkey_keydown
                        />
                        <button
                            class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:text-gray-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm"
                            on:click=move |_| on_start_conversation(())
                            disabled=move || new_pubkey_input.get().trim().is_empty()
                        >
                            "Start"
                        </button>
                    </div>
                    {move || {
                        new_dm_error.get().map(|msg| view! {
                            <p class="text-red-400 text-sm mt-2">{msg}</p>
                        })
                    }}
                </div>
            </Show>

            // Connection banner
            {move || {
                let state = conn_state.get();
                match state {
                    ConnectionState::Reconnecting => Some(view! {
                        <div class="bg-yellow-900/50 border border-yellow-700 rounded-lg px-4 py-3 mb-4 flex items-center gap-2">
                            <span class="animate-pulse w-2 h-2 rounded-full bg-yellow-400"></span>
                            <span class="text-yellow-200 text-sm">"Reconnecting to relay..."</span>
                        </div>
                    }.into_any()),
                    ConnectionState::Error => Some(view! {
                        <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 mb-4">
                            <span class="text-red-200 text-sm">"Connection error. Retrying..."</span>
                        </div>
                    }.into_any()),
                    ConnectionState::Disconnected => Some(view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 mb-4">
                            <span class="text-gray-300 text-sm">"Disconnected from relay."</span>
                        </div>
                    }.into_any()),
                    _ => None,
                }
            }}

            // Error from DM store
            {move || {
                error.get().map(|msg| view! {
                    <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 mb-4 flex items-center justify-between">
                        <span class="text-red-200 text-sm">{msg}</span>
                        <button
                            class="text-red-400 hover:text-red-200 text-xs ml-4"
                            on:click=move |_| dm_store.clear_error()
                        >
                            "dismiss"
                        </button>
                    </div>
                })
            }}

            // Conversation list
            {move || {
                if is_loading.get() {
                    view! {
                        <div class="space-y-3">
                            <ConversationSkeleton/>
                            <ConversationSkeleton/>
                            <ConversationSkeleton/>
                        </div>
                    }.into_any()
                } else {
                    let convos = conversations.get();
                    if convos.is_empty() {
                        let empty_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                            <svg class="w-7 h-7 text-amber-400/60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke-linecap="round" stroke-linejoin="round"/>
                                <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        }.into_any());
                        view! {
                            <crate::components::empty_state::EmptyState
                                icon=empty_icon
                                title="No conversations yet".to_string()
                                description="Start a new encrypted conversation by clicking \"New Message\" above.".to_string()
                            />
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-2">
                                {convos.into_iter().map(|convo| {
                                    view! { <ConversationRow convo=convo/> }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }
            }}
        </div>
    }
}

/// A single conversation row in the DM list.
#[component]
fn ConversationRow(convo: DMConversation) -> impl IntoView {
    let href = base_href(&format!("/dm/{}", convo.pubkey));
    let has_unread = convo.unread_count > 0;
    let unread_count = convo.unread_count;
    let time_display = format_relative_time(convo.last_timestamp);
    let avatar_text = convo.pubkey[..2].to_uppercase();
    let avatar_bg = pubkey_color(&convo.pubkey);
    let name = convo.name.clone();
    let short_pk = crate::utils::shorten_pubkey(&convo.pubkey);
    // Show pubkey separately only when name differs from shortened pubkey
    let _name_is_pubkey = name == short_pk || name == convo.pubkey;
    let last_message = convo.last_message.clone();
    let has_message = !last_message.is_empty();

    view! {
        <A href=href attr:class="block bg-gray-800 hover:bg-gray-750 border border-gray-700 hover:border-amber-500/30 rounded-lg hover:-translate-y-px hover:shadow-md transition-all duration-200 no-underline text-inherit">
            <div class="p-4">
                <div class="flex gap-3 items-center">
                    // Avatar
                    <div
                        class="w-10 h-10 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0"
                        style=format!("background-color: {}", avatar_bg)
                    >
                        {avatar_text}
                    </div>

                    // Content
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center justify-between gap-2">
                            <div class="min-w-0">
                                <span class=move || {
                                    if has_unread {
                                        "font-bold text-sm text-white truncate block"
                                    } else {
                                        "font-semibold text-sm text-gray-200 truncate block"
                                    }
                                }>
                                    {name}
                                </span>
                                <span class="text-[10px] font-mono text-gray-500 truncate block">
                                    {short_pk}
                                </span>
                            </div>
                            <span class="text-xs text-gray-500 flex-shrink-0">
                                {time_display}
                            </span>
                        </div>
                        <div class="flex items-center justify-between gap-2 mt-0.5">
                            <p class=move || {
                                if has_unread {
                                    "text-sm text-gray-200 truncate"
                                } else {
                                    "text-sm text-gray-400 truncate"
                                }
                            }>
                                {if has_message {
                                    last_message
                                } else {
                                    "No messages yet".to_string()
                                }}
                            </p>
                            {has_unread.then(|| view! {
                                <span class="bg-amber-500 text-gray-900 text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center flex-shrink-0">
                                    {unread_count.to_string()}
                                </span>
                            })}
                        </div>
                    </div>
                </div>
            </div>
        </A>
    }
}

/// Loading skeleton for a conversation row.
#[component]
fn ConversationSkeleton() -> impl IntoView {
    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 animate-pulse">
            <div class="flex gap-3 items-center">
                <div class="w-10 h-10 rounded-full bg-gray-700"></div>
                <div class="flex-1 space-y-2">
                    <div class="h-4 bg-gray-700 rounded w-1/3"></div>
                    <div class="h-3 bg-gray-700 rounded w-2/3"></div>
                </div>
            </div>
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn shield_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-7 h-7 text-amber-400/80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
    }
}

fn lock_icon_small() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
    }
}

fn plus_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
    }
}

fn x_icon_small() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
    }
}

#[allow(dead_code)]
fn mail_icon_large() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-16 h-16 text-amber-400/20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
            <polyline points="22,6 12,13 2,6"/>
        </svg>
    }
}
