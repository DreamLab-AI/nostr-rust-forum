//! Signup page: generate a Nostr keypair, show private key for backup, continue.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_query_map};
use leptos_router::NavigateOptions;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::nsec_backup::NsecBackup;

/// Signup flow phases.
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Name,
    Backup,
}

#[component]
pub fn SignupPage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let error = auth.error();
    let navigate = StoredValue::new(use_navigate());

    let display_name = RwSignal::new(String::new());
    let phase = RwSignal::new(Phase::Name);
    let privkey_hex = RwSignal::new(String::new());

    // Read returnTo query parameter — default to /forums, reject non-path values and loops
    let query = use_query_map();
    let return_to = move || {
        let r = query.read().get("returnTo").unwrap_or_default();
        if r.is_empty() || !r.starts_with('/') || r == "/login" || r == "/signup" {
            "/forums".to_string()
        } else {
            r
        }
    };

    // Redirect if already authenticated and past backup
    Effect::new(move |_| {
        if is_authed.get() && phase.get() != Phase::Backup {
            let dest = return_to();
            navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
        }
    });

    let do_create = move || {
        let name = display_name.get_untracked();
        let trimmed = name.trim().to_string();
        if trimmed.is_empty() || trimmed.len() < 2 {
            auth.set_error("Display name must be at least 2 characters");
            return;
        }
        if trimmed.len() > 50 {
            auth.set_error("Display name must be 50 characters or fewer");
            return;
        }
        auth.clear_error();

        match auth.register_with_generated_key(&trimmed) {
            Ok(hex) => {
                privkey_hex.set(hex);
                phase.set(Phase::Backup);
            }
            Err(e) => auth.set_error(&e),
        }
    };

    let on_backup_done = Callback::new(move |()| {
        auth.confirm_nsec_backup();
        let dest = return_to();
        navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
    });

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4">
            <div class="w-full max-w-md">
                <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-8 space-y-6">

                    // Phase 1: Enter name
                    <Show when=move || phase.get() == Phase::Name>
                        <div class="text-center">
                            <h1 class="text-3xl font-bold text-white">"Create Account"</h1>
                            <p class="mt-2 text-gray-400 text-sm">
                                "We'll create a secure identity for you. Back up your key so you can always access your account."
                            </p>
                        </div>

                        <Show when=move || error.get().is_some()>
                            <div class="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
                                {move || error.get().unwrap_or_default()}
                            </div>
                        </Show>

                        <div class="space-y-4">
                            <div class="space-y-2">
                                <label for="display-name" class="block text-sm font-medium text-gray-300">
                                    "Display Name"
                                </label>
                                <input
                                    id="display-name"
                                    type="text"
                                    placeholder="Your display name"
                                    on:input=move |ev| display_name.set(event_target_value(&ev))
                                    on:keydown=move |ev: web_sys::KeyboardEvent| {
                                        if ev.key() == "Enter" {
                                            ev.prevent_default();
                                            do_create();
                                        }
                                    }
                                    prop:value=move || display_name.get()
                                    maxlength="50"
                                    class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                                />
                            </div>

                            <button
                                on:click=move |_: web_sys::MouseEvent| do_create()
                                class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2"
                            >
                                {key_icon_svg()}
                                <span>"Create Account"</span>
                            </button>
                        </div>
                    </Show>

                    // Phase 2: Backup private key
                    <Show when=move || phase.get() == Phase::Backup>
                        <NsecBackup nsec=privkey_hex.get_untracked() on_dismiss=on_backup_done />
                    </Show>

                </div>

                <p class="text-center text-gray-500 text-sm mt-6">
                    "Already have an account? "
                    <A href=base_href("/login") attr:class="text-amber-400 hover:text-amber-300 underline">
                        "Sign in"
                    </A>
                </p>
            </div>
        </div>
    }
}

fn key_icon_svg() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
        </svg>
    }
}
