//! Profile page -- displays a user's public Nostr profile.
//!
//! Route: /profile/:pubkey
//!
//! Fetches kind 0 metadata from the relay and displays avatar, display name,
//! NIP-05 verification, about text, and pubkey. Provides DM and copy actions.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map};
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;

use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::badge_display::BadgeGrid;
use crate::components::user_display::use_display_name;
use crate::relay::{Filter, RelayConnection};
use crate::stores::badges::{use_badges, EarnedBadge};
use crate::utils::shorten_pubkey;

/// Parsed kind 0 metadata.
#[derive(Clone, Debug, Default)]
struct ProfileMeta {
    name: Option<String>,
    display_name: Option<String>,
    about: Option<String>,
    #[allow(dead_code)]
    picture: Option<String>,
    banner: Option<String>,
    nip05: Option<String>,
    website: Option<String>,
    lud16: Option<String>,
}

/// Public profile page for a given pubkey.
#[component]
pub fn ProfilePage() -> impl IntoView {
    let params = use_params_map();
    let pubkey = Memo::new(move |_| params.read().get("pubkey").unwrap_or_default());
    let navigate = StoredValue::new(use_navigate());

    let meta = RwSignal::new(ProfileMeta::default());
    let is_loading = RwSignal::new(true);
    let copied = RwSignal::new(false);

    // Validate pubkey format (must be 64 hex characters)
    let is_valid_pubkey = Memo::new(move |_| {
        let pk = pubkey.get();
        pk.len() == 64 && pk.chars().all(|c| c.is_ascii_hexdigit())
    });

    // Fetch kind 0 metadata
    Effect::new(move |_| {
        let pk = pubkey.get();
        if pk.is_empty() || !is_valid_pubkey.get() {
            is_loading.set(false);
            return;
        }

        is_loading.set(true);
        meta.set(ProfileMeta::default());

        let relay = expect_context::<RelayConnection>();
        let filter = Filter {
            kinds: Some(vec![0]),
            authors: Some(vec![pk.clone()]),
            limit: Some(1),
            ..Default::default()
        };

        let on_event = Rc::new(move |event: nostr_core::NostrEvent| {
            if event.kind == 0 {
                if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    meta.set(ProfileMeta {
                        name: obj.get("name").and_then(|v| v.as_str()).map(String::from),
                        display_name: obj.get("display_name").and_then(|v| v.as_str()).map(String::from),
                        about: obj.get("about").and_then(|v| v.as_str()).map(String::from),
                        picture: obj.get("picture").and_then(|v| v.as_str()).map(String::from),
                        banner: obj.get("banner").and_then(|v| v.as_str()).map(String::from),
                        nip05: obj.get("nip05").and_then(|v| v.as_str()).map(String::from),
                        website: obj.get("website").and_then(|v| v.as_str()).map(String::from),
                        lud16: obj.get("lud16").and_then(|v| v.as_str()).map(String::from),
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

    // Fetch badges for this profile's pubkey
    let profile_badges: RwSignal<Vec<EarnedBadge>> = RwSignal::new(Vec::new());
    {
        let _badge_store = use_badges();
        Effect::new(move |_| {
            let pk = pubkey.get();
            if pk.is_empty() || !is_valid_pubkey.get() {
                return;
            }
            // Fetch badge awards (kind-8) for this profile pubkey
            let relay = expect_context::<RelayConnection>();
            let filter = Filter {
                kinds: Some(vec![8]),
                p_tags: Some(vec![pk.clone()]),
                limit: Some(100),
                ..Default::default()
            };
            let badges_sig = profile_badges;
            let on_event = Rc::new(move |event: nostr_core::NostrEvent| {
                if event.kind != 8 {
                    return;
                }
                let badge_id = event
                    .tags
                    .iter()
                    .find(|t| t.len() >= 2 && t[0] == "a")
                    .and_then(|t| t[1].rsplit(':').next())
                    .map(String::from);
                if let Some(bid) = badge_id {
                    badges_sig.update(|list| {
                        if !list.iter().any(|b| b.badge_id == bid) {
                            list.push(EarnedBadge {
                                badge_id: bid,
                                awarded_at: event.created_at,
                                event_id: event.id.clone(),
                            });
                        }
                    });
                }
            });
            let on_eose = Rc::new(|| {});
            let sub_id = relay.subscribe(vec![filter], on_event, Some(on_eose));
            let relay_cleanup = relay.clone();
            crate::utils::set_timeout_once(
                move || { relay_cleanup.unsubscribe(&sub_id); },
                5_000,
            );
        });
    }
    let badges_signal = Signal::derive(move || profile_badges.get());

    let display_name = Memo::new(move |_| {
        let pk = pubkey.get();
        let m = meta.get();
        m.display_name
            .or(m.name)
            .unwrap_or_else(|| use_display_name(&pk))
    });

    let on_dm = move |_| {
        let pk = pubkey.get();
        let href = format!("/dm/{}", pk);
        navigate.with_value(|nav| nav(&href, NavigateOptions::default()));
    };

    let on_copy = move |_| {
        let pk = pubkey.get();
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

    view! {
        <Show
            when=move || is_valid_pubkey.get()
            fallback=|| view! {
                <div class="max-w-lg mx-auto p-8 text-center">
                    <div class="glass-card p-8">
                        <h2 class="text-xl font-bold text-white mb-2">"Invalid Profile"</h2>
                        <p class="text-gray-400 text-sm mb-4">"The public key in the URL is not valid."</p>
                        <a href="/" class="text-amber-400 hover:text-amber-300 text-sm underline">"Go home"</a>
                    </div>
                </div>
            }
        >
        <div class="max-w-3xl mx-auto p-4 sm:p-6 space-y-6">
            // Banner
            <Show when=move || meta.get().banner.is_some()>
                <div class="w-full h-40 sm:h-56 rounded-xl overflow-hidden bg-gray-800">
                    <img
                        src=move || meta.get().banner.unwrap_or_default()
                        alt="Profile banner"
                        class="w-full h-full object-cover"
                    />
                </div>
            </Show>

            // Avatar + name section
            <div class="flex flex-col items-center gap-4 -mt-12 relative z-10">
                <div class="profile-avatar-ring">
                    <Avatar pubkey=pubkey.get_untracked() size=AvatarSize::Xl />
                </div>

                <div class="text-center space-y-1">
                    <Show
                        when=move || !is_loading.get()
                        fallback=|| view! {
                            <div class="skeleton w-40 h-7 mx-auto"></div>
                        }
                    >
                        <h1 class="text-2xl font-bold text-white">{move || display_name.get()}</h1>
                    </Show>

                    {move || meta.get().nip05.map(|nip| view! {
                        <div class="flex items-center justify-center gap-1 text-sm text-green-400">
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"
                                    stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            <span>{nip}</span>
                        </div>
                    })}
                </div>
            </div>

            // About
            <Show when=move || is_loading.get()>
                <div class="space-y-2">
                    <div class="skeleton w-full h-4"></div>
                    <div class="skeleton w-3/4 h-4"></div>
                </div>
            </Show>
            <Show when=move || meta.get().about.is_some()>
                <div class="bg-gray-800/50 border border-gray-700/30 rounded-xl p-4">
                    <h2 class="text-xs text-gray-500 font-medium mb-2">"About"</h2>
                    <p class="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
                        {move || meta.get().about.unwrap_or_default()}
                    </p>
                </div>
            </Show>

            // Badges
            <div class="bg-gray-800/50 border border-gray-700/30 rounded-xl p-4">
                <BadgeGrid badges=badges_signal />
            </div>

            // Details card
            <div class="bg-gray-800/50 border border-gray-700/30 rounded-xl p-4 space-y-3">
                // Pubkey
                <div>
                    <div class="text-xs text-gray-500 mb-1">"Public Key"</div>
                    <div class="font-mono text-xs text-amber-400/70 break-all">
                        {move || shorten_pubkey(&pubkey.get())}
                    </div>
                </div>

                // Website
                {move || meta.get().website.map(|url| {
                    let url_display = url.clone();
                    view! {
                        <div>
                            <div class="text-xs text-gray-500 mb-1">"Website"</div>
                            <a
                                href=url
                                target="_blank"
                                rel="noopener noreferrer"
                                class="text-sm text-amber-400 hover:text-amber-300 transition-colors"
                            >
                                {url_display}
                            </a>
                        </div>
                    }
                })}

                // Lightning address
                {move || meta.get().lud16.map(|addr| view! {
                    <div>
                        <div class="text-xs text-gray-500 mb-1">"Lightning"</div>
                        <span class="text-sm text-gray-300">{addr}</span>
                    </div>
                })}
            </div>

            // Action buttons
            <div class="flex gap-3">
                <button
                    on:click=on_dm
                    class="flex-1 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-2.5 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm"
                >
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"
                            stroke-linecap="round" stroke-linejoin="round"/>
                        <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    "Send DM"
                </button>

                <button
                    on:click=on_copy
                    class="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 py-2.5 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm border border-gray-700"
                >
                    <Show
                        when=move || copied.get()
                        fallback=|| view! {
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"
                                    stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            "Copy Pubkey"
                        }
                    >
                        <svg class="w-4 h-4 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        "Copied!"
                    </Show>
                </button>
            </div>
        </div>
        </Show>
    }
}
