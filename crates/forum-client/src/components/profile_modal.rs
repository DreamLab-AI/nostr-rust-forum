//! User profile modal component.
//!
//! Displays a user's profile details in a glass-panel modal overlay. Fetches
//! kind 0 metadata from the relay on open. Provides DM, copy pubkey, and
//! mute actions.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;

use crate::components::avatar::{Avatar, AvatarSize};
use crate::relay::{Filter, RelayConnection};
use crate::components::user_display::use_display_name;
use crate::stores::mute::use_mute_store;
use crate::utils::shorten_pubkey;

/// Parsed kind 0 metadata fields.
#[derive(Clone, Debug, Default)]
struct ProfileMeta {
    name: Option<String>,
    about: Option<String>,
    #[allow(dead_code)]
    picture: Option<String>,
    nip05: Option<String>,
}

#[component]
pub(crate) fn ProfileModal(
    /// Hex pubkey of the user to display.
    pubkey: String,
    /// Controls modal visibility.
    is_open: RwSignal<bool>,
) -> impl IntoView {
    let navigate = StoredValue::new(use_navigate());
    let meta = RwSignal::new(ProfileMeta::default());
    let is_loading = RwSignal::new(false);
    let copied = RwSignal::new(false);
    let mute_store = use_mute_store();

    // Store pubkey in StoredValue so it can be captured in Fn closures
    let pk_stored = StoredValue::new(pubkey.clone());
    let short_pk = StoredValue::new(shorten_pubkey(&pubkey));
    let pk_for_avatar = pubkey.clone();

    // Fetch kind 0 metadata when modal opens
    Effect::new(move |_| {
        if !is_open.get() {
            return;
        }

        is_loading.set(true);
        meta.set(ProfileMeta::default());

        let relay = expect_context::<RelayConnection>();
        let pk = pk_stored.get_value();
        let filter = Filter {
            kinds: Some(vec![0]),
            authors: Some(vec![pk]),
            limit: Some(1),
            ..Default::default()
        };

        let on_event = Rc::new(move |event: nostr_core::NostrEvent| {
            if event.kind == 0 {
                if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    meta.set(ProfileMeta {
                        name: obj.get("name").and_then(|v| v.as_str()).map(String::from),
                        about: obj.get("about").and_then(|v| v.as_str()).map(String::from),
                        picture: obj
                            .get("picture")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        nip05: obj.get("nip05").and_then(|v| v.as_str()).map(String::from),
                    });
                }
            }
        });

        let on_eose = Rc::new(move || {
            is_loading.set(false);
        });

        let sub_id = relay.subscribe(vec![filter], on_event, Some(on_eose));

        let relay_cleanup = relay.clone();
        crate::utils::set_timeout_once(
            move || {
                relay_cleanup.unsubscribe(&sub_id);
                is_loading.set(false);
            },
            5_000,
        );
    });

    let on_dm = move |_| {
        is_open.set(false);
        let pk = pk_stored.get_value();
        let href = format!("/dm/{}", pk);
        navigate.with_value(|nav| nav(&href, NavigateOptions::default()));
    };

    let on_copy = move |_| {
        let pk = pk_stored.get_value();
        if let Some(window) = web_sys::window() {
            let nav = window.navigator();
            if let Ok(clipboard) = js_sys::Reflect::get(&nav, &"clipboard".into()) {
                if !clipboard.is_undefined() {
                    if let Ok(write_fn) = js_sys::Reflect::get(&clipboard, &"writeText".into()) {
                        if let Ok(func) = write_fn.dyn_into::<js_sys::Function>() {
                            let _ = func.call1(&clipboard, &pk.into());
                            copied.set(true);
                            crate::utils::set_timeout_once(move || copied.set(false), 2_000);
                        }
                    }
                }
            }
        }
    };

    let display_name = Memo::new(move |_| {
        let pk = pk_stored.get_value();
        meta.get().name.unwrap_or_else(|| use_display_name(&pk))
    });

    view! {
        <Show when=move || is_open.get()>
            <div class="modal-backdrop" on:click=move |_| is_open.set(false)>
                <div class="modal-panel p-6 space-y-5" on:click=move |ev: web_sys::MouseEvent| ev.stop_propagation()>
                    // Close button
                    <div class="flex justify-end">
                        <button
                            on:click=move |_| is_open.set(false)
                            class="text-gray-500 hover:text-gray-300 transition-colors p-1"
                        >
                            {close_icon_svg()}
                        </button>
                    </div>

                    // Avatar with gradient ring
                    <div class="flex flex-col items-center gap-3">
                        <div class="profile-avatar-ring">
                            <Avatar pubkey=pk_for_avatar.clone() size=AvatarSize::Xl />
                        </div>

                        // Name + NIP-05
                        <div class="text-center space-y-1">
                            <Show
                                when=move || is_loading.get()
                                fallback=move || view! {
                                    <h2 class="text-xl font-bold text-white">
                                        {move || display_name.get()}
                                    </h2>
                                }
                            >
                                <div class="skeleton w-32 h-6 mx-auto"></div>
                            </Show>

                            {move || meta.get().nip05.map(|nip| view! {
                                <div class="flex items-center justify-center gap-1 text-xs text-green-400">
                                    {check_badge_svg()}
                                    <span>{nip}</span>
                                </div>
                            })}
                        </div>
                    </div>

                    // Pubkey
                    <div class="bg-gray-800/50 border border-gray-700/30 rounded-lg p-3">
                        <div class="text-xs text-gray-500 mb-1">"Public Key"</div>
                        <div class="font-mono text-xs text-amber-400/70 break-all">
                            {move || short_pk.get_value()}
                        </div>
                    </div>

                    // About
                    <Show when=move || meta.get().about.is_some()>
                        <div class="space-y-1">
                            <div class="text-xs text-gray-500 font-medium">"About"</div>
                            <p class="text-sm text-gray-300 leading-relaxed">
                                {move || meta.get().about.unwrap_or_default()}
                            </p>
                        </div>
                    </Show>

                    // Loading skeleton for about
                    <Show when=move || is_loading.get()>
                        <div class="space-y-2">
                            <div class="skeleton w-full h-4"></div>
                            <div class="skeleton w-3/4 h-4"></div>
                        </div>
                    </Show>

                    // Action buttons
                    <div class="space-y-2 pt-2">
                        <button
                            on:click=on_dm
                            class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-2.5 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm"
                        >
                            {dm_icon_svg()}
                            "Send DM"
                        </button>

                        <div class="flex gap-2">
                            <button
                                on:click=on_copy
                                class="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 py-2.5 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm border border-gray-700"
                            >
                                <Show
                                    when=move || copied.get()
                                    fallback=|| view! {
                                        {copy_icon_svg()}
                                        "Copy Pubkey"
                                    }
                                >
                                    {check_icon_svg()}
                                    "Copied!"
                                </Show>
                            </button>

                            <button
                                on:click=move |_| {
                                    let pk = pk_stored.get_value();
                                    mute_store.toggle_mute_user(&pk);
                                }
                                class=move || {
                                    if mute_store.is_user_muted(&pk_stored.get_value()) {
                                        "flex-1 bg-red-900/30 hover:bg-red-900/50 text-red-400 py-2.5 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm border border-red-700/30"
                                    } else {
                                        "flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 py-2.5 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm border border-gray-700"
                                    }
                                }
                            >
                                {move || if mute_store.is_user_muted(&pk_stored.get_value()) {
                                    view! { <span>"Unmute"</span> }.into_any()
                                } else {
                                    view! { <span>"Mute"</span> }.into_any()
                                }}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </Show>
    }
}

// -- SVG icons ----------------------------------------------------------------

fn close_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
        </svg>
    }
}

fn dm_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"
                stroke-linecap="round" stroke-linejoin="round"/>
            <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn copy_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn check_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-4 h-4 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn check_badge_svg() -> impl IntoView {
    view! {
        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
