//! Pending approval waiting page.
//!
//! Shown when a user has registered but is not yet approved by an admin.
//! Periodically checks for approval by querying the relay for kind 0 events
//! authored by the user's pubkey.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::relay::{Filter, RelayConnection};
use crate::utils::shorten_pubkey;

/// Interval in milliseconds between approval status checks.
const CHECK_INTERVAL_MS: i32 = 10_000;

#[component]
pub fn PendingPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = StoredValue::new(use_navigate());

    let pubkey_display = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .map(|pk| shorten_pubkey(&pk))
            .unwrap_or_else(|| "unknown".to_string())
    });

    let check_count = RwSignal::new(0u32);
    let is_checking = RwSignal::new(false);

    // Approval check logic, captured as a closure over signals
    let do_check = move || {
        let pubkey = match auth.pubkey().get_untracked() {
            Some(pk) => pk,
            None => return,
        };

        is_checking.set(true);
        let relay = expect_context::<RelayConnection>();

        let filter = Filter {
            kinds: Some(vec![0]),
            authors: Some(vec![pubkey]),
            limit: Some(1),
            ..Default::default()
        };

        let on_event = Rc::new(move |event: nostr_core::NostrEvent| {
            if event.kind == 0 && !event.content.is_empty() {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    let nickname = meta.get("name").and_then(|v| v.as_str()).map(String::from);
                    let avatar = meta
                        .get("picture")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    if nickname.is_some() {
                        auth.set_profile(nickname, avatar);
                        auth.complete_signup();
                        navigate.with_value(|nav| {
                            nav("/chat", NavigateOptions::default());
                        });
                    }
                }
            }
        });

        let on_eose = Rc::new(move || {
            is_checking.set(false);
            check_count.update(|c| *c += 1);
        });

        let sub_id = relay.subscribe(vec![filter], on_event, Some(on_eose));

        let relay_cleanup = relay.clone();
        crate::utils::set_timeout_once(
            move || {
                relay_cleanup.unsubscribe(&sub_id);
                is_checking.set(false);
            },
            5_000,
        );
    };

    // Set up the repeating interval check
    Effect::new(move |_| {
        // Run first check immediately
        do_check();

        // Schedule recurring checks via setInterval
        let interval_cb = Closure::wrap(Box::new(move || {
            do_check();
        }) as Box<dyn FnMut()>);

        let interval_id = web_sys::window()
            .and_then(|w| {
                w.set_interval_with_callback_and_timeout_and_arguments_0(
                    interval_cb.as_ref().unchecked_ref(),
                    CHECK_INTERVAL_MS,
                )
                .ok()
            })
            .unwrap_or(0);

        // Keep closure alive for the interval
        interval_cb.forget();

        on_cleanup(move || {
            if let Some(window) = web_sys::window() {
                window.clear_interval_with_handle(interval_id);
            }
        });
    });

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4 relative overflow-hidden">
            // Ambient orbs
            <div class="ambient-orb ambient-orb-1" aria-hidden="true"></div>
            <div class="ambient-orb ambient-orb-2" aria-hidden="true"></div>

            <div class="w-full max-w-md relative z-10">
                <div class="glass-card p-8 space-y-6">
                    // Animated icon
                    <div class="text-center">
                        <div class="animate-gentle-float inline-block mb-4">
                            {hourglass_icon_svg()}
                        </div>
                        <h1 class="text-2xl font-bold text-white">
                            "Account Pending Approval"
                        </h1>
                        <p class="mt-3 text-gray-400 text-sm leading-relaxed">
                            "Your account has been created and is awaiting admin approval. "
                            "You will be redirected automatically once approved."
                        </p>
                    </div>

                    // Pubkey info box
                    <div class="bg-gray-800/50 border border-gray-700/50 rounded-xl p-4 space-y-2">
                        <div class="flex items-center gap-2 text-xs text-gray-500 uppercase tracking-wide font-medium">
                            {key_icon_svg()}
                            "Your Identity"
                        </div>
                        <div class="font-mono text-sm text-amber-400/80 break-all">
                            {move || pubkey_display.get()}
                        </div>
                    </div>

                    // Status indicator
                    <div class="flex items-center justify-center gap-3 py-2">
                        <Show
                            when=move || is_checking.get()
                            fallback=move || view! {
                                <div class="w-2 h-2 rounded-full bg-amber-500/60 animate-pulse"></div>
                                <span class="text-xs text-gray-500">
                                    {move || format!("Checked {} time{}", check_count.get(), if check_count.get() == 1 { "" } else { "s" })}
                                </span>
                            }
                        >
                            <div class="animate-spin w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full"></div>
                            <span class="text-xs text-gray-400">"Checking status..."</span>
                        </Show>
                    </div>

                    // Info steps
                    <div class="bg-gray-800/30 border border-gray-700/30 rounded-xl p-4 space-y-3">
                        <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                            "What happens next"
                        </h3>
                        <div class="space-y-2 text-xs text-gray-500 leading-relaxed">
                            <div class="flex items-start gap-2">
                                <span class="text-amber-400/60 mt-0.5">"1."</span>
                                <span>"An admin will review your registration"</span>
                            </div>
                            <div class="flex items-start gap-2">
                                <span class="text-amber-400/60 mt-0.5">"2."</span>
                                <span>"Once approved, your profile will be published"</span>
                            </div>
                            <div class="flex items-start gap-2">
                                <span class="text-amber-400/60 mt-0.5">"3."</span>
                                <span>"You will be automatically redirected to chat"</span>
                            </div>
                        </div>
                    </div>

                    // Back to home link
                    <div class="text-center pt-2">
                        <A href=base_href("/") attr:class="text-gray-500 hover:text-gray-300 text-sm transition-colors">
                            "\u{2190} Back to Home"
                        </A>
                    </div>
                </div>
            </div>
        </div>
    }
}

// -- SVG icons ----------------------------------------------------------------

fn hourglass_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-16 h-16 text-amber-400/50" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
            <path d="M5 3h14M5 21h14M7 3v3.4a4 4 0 001.17 2.83L10 11.06a2 2 0 010 1.88l-1.83 1.83A4 4 0 007 17.6V21m10-18v3.4a4 4 0 01-1.17 2.83L14 11.06a2 2 0 000 1.88l1.83 1.83A4 4 0 0117 17.6V21"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn key_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
