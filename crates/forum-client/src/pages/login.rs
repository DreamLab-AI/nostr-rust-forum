//! Login page with smart auth defaults and progressive disclosure.
//!
//! Detects available auth methods and shows the most appropriate one as primary.
//! Protocol terminology (NIP-07, nsec, PRF) is hidden behind "More options"
//! unless `show_technical_details` is enabled in preferences.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_query_map};
use leptos_router::NavigateOptions;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::nip07;
use crate::auth::use_auth;
use crate::stores::preferences::use_preferences;

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let error = auth.error();
    let navigate = StoredValue::new(use_navigate());

    let key_input = RwSignal::new(String::new());
    let is_pending = RwSignal::new(false);
    let nip07_pending = RwSignal::new(false);
    let has_nip07 = RwSignal::new(nip07::has_nip07_extension());
    let show_more = RwSignal::new(false);
    let show_tech = Memo::new(move |_| use_preferences().get().show_technical_details);

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

    // Redirect if already authenticated
    Effect::new(move |_| {
        if is_authed.get() {
            let dest = return_to();
            navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
        }
    });

    // Private key login
    let do_key_login = move || {
        let input = key_input.get_untracked();
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            auth.set_error("Paste your recovery key to sign in");
            return;
        }
        auth.clear_error();
        match auth.login_with_local_key(&trimmed) {
            Ok(()) => {
                let dest = return_to();
                navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
            }
            Err(e) => auth.set_error(&e),
        }
    };

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4">
            <div class="w-full max-w-md">
                <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-8 space-y-6">
                    <div class="text-center">
                        <h1 class="text-3xl font-bold text-white">"Welcome Back"</h1>
                        <p class="mt-2 text-gray-400 text-sm">"Sign in to continue to Nostr BBS"</p>
                    </div>

                    // Error display
                    <Show when=move || error.get().is_some()>
                        <div class="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
                            {move || error.get().unwrap_or_default()}
                        </div>
                    </Show>

                    // Smart primary auth: extension if detected, key input otherwise
                    <Show
                        when=move || has_nip07.get()
                        fallback=move || {
                            // Key input as primary
                            view! {
                                <div class="space-y-3">
                                    <div class="space-y-2">
                                        <label class="block text-sm font-medium text-gray-300">
                                            {move || if show_tech.get() { "Private key (nsec/hex)" } else { "Your recovery key" }}
                                        </label>
                                        <input
                                            type="password"
                                            placeholder="Paste your key here"
                                            on:input=move |ev| key_input.set(event_target_value(&ev))
                                            on:keydown=move |ev: web_sys::KeyboardEvent| {
                                                if ev.key() == "Enter" {
                                                    ev.prevent_default();
                                                    do_key_login();
                                                }
                                            }
                                            prop:value=move || key_input.get()
                                            class="w-full bg-gray-900 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 text-sm font-mono"
                                        />
                                        <p class="text-xs text-gray-500">
                                            {move || if show_tech.get() { "Key stored in sessionStorage, zeroed on pagehide" } else { "Your key never leaves your browser" }}
                                        </p>
                                    </div>
                                    <button
                                        on:click=move |_: web_sys::MouseEvent| do_key_login()
                                        class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl transition-colors text-sm"
                                    >
                                        "Sign In"
                                    </button>
                                </div>
                            }
                        }
                    >
                        // Extension detected — show as primary CTA
                        <div class="space-y-3">
                            <button
                                on:click=move |_: web_sys::MouseEvent| {
                                    let auth = auth;
                                    let dest = return_to();
                                    nip07_pending.set(true);
                                    spawn_local(async move {
                                        let result = auth.login_with_nip07().await;
                                        nip07_pending.set(false);
                                        if result.is_ok() {
                                            navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
                                        }
                                    });
                                }
                                disabled=move || nip07_pending.get()
                                class="w-full bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 rounded-xl transition-colors text-sm flex items-center justify-center gap-2"
                            >
                                <Show
                                    when=move || nip07_pending.get()
                                    fallback=move || view! {
                                        {extension_icon()}
                                        <span>{move || if show_tech.get() { "Sign in with NIP-07 extension" } else { "Sign in with browser extension" }}</span>
                                    }
                                >
                                    <span class="animate-spin inline-block w-4 h-4 border-2 border-gray-900 border-t-transparent rounded-full"></span>
                                    <span>"Connecting..."</span>
                                </Show>
                            </button>
                            <p class="text-xs text-gray-500 text-center">
                                {move || nip07::get_extension_name().unwrap_or_else(|| "Extension".to_string())}
                                " detected"
                            </p>
                        </div>
                    </Show>

                    // Divider with "More options" toggle
                    <div class="relative">
                        <div class="absolute inset-0 flex items-center">
                            <div class="w-full border-t border-gray-700"></div>
                        </div>
                        <div class="relative flex justify-center">
                            <button
                                on:click=move |_| show_more.update(|v| *v = !*v)
                                class="px-3 py-1 text-xs text-gray-400 hover:text-gray-300 bg-gray-900/80 rounded-full transition-colors"
                            >
                                {move || if show_more.get() { "Fewer options" } else { "More options" }}
                            </button>
                        </div>
                    </div>

                    // Expanded alternative auth methods
                    <Show when=move || show_more.get()>
                        <div class="space-y-3">
                            // Key input (only shown here if extension was primary above)
                            <Show when=move || has_nip07.get()>
                                <div class="bg-gray-800/50 border border-gray-700 rounded-xl p-4 space-y-3">
                                    <div class="flex items-center gap-2">
                                        {key_icon_svg()}
                                        <span class="text-sm font-medium text-gray-200">"Sign in with your key"</span>
                                    </div>
                                    <input
                                        type="password"
                                        placeholder="Paste your key here"
                                        on:input=move |ev| key_input.set(event_target_value(&ev))
                                        on:keydown=move |ev: web_sys::KeyboardEvent| {
                                            if ev.key() == "Enter" {
                                                ev.prevent_default();
                                                do_key_login();
                                            }
                                        }
                                        prop:value=move || key_input.get()
                                        class="w-full bg-gray-900 border border-gray-600 focus:border-amber-500 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 text-sm font-mono"
                                    />
                                    <button
                                        on:click=move |_: web_sys::MouseEvent| do_key_login()
                                        class="w-full bg-gray-700 hover:bg-gray-600 text-white py-2.5 rounded-lg transition-colors text-sm font-semibold"
                                    >
                                        "Sign In"
                                    </button>
                                    <p class="text-xs text-gray-500">
                                        {move || if show_tech.get() { "Key stored in sessionStorage, zeroed on pagehide" } else { "Your key never leaves your browser" }}
                                    </p>
                                </div>
                            </Show>

                            // Extension (only shown when not detected / not primary)
                            <Show when=move || !has_nip07.get()>
                                <div class="bg-gray-800/50 border border-gray-700/50 rounded-xl p-4 space-y-2 opacity-60">
                                    <div class="flex items-center gap-2">
                                        {extension_icon()}
                                        <span class="text-sm font-medium text-gray-200">
                                            {move || if show_tech.get() { "Sign in with NIP-07 extension" } else { "Sign in with browser extension" }}
                                        </span>
                                        <span class="text-xs text-gray-500 ml-auto">"Not detected"</span>
                                    </div>
                                    <p class="text-xs text-gray-500">"Install a signing extension to use this option."</p>
                                </div>
                            </Show>

                            // Biometrics / Passkey
                            <div class="bg-gray-800/50 border border-gray-700 rounded-xl p-4 space-y-3">
                                <div class="flex items-center gap-2">
                                    {biometric_icon()}
                                    <span class="text-sm font-medium text-gray-200">
                                        {move || if show_tech.get() { "Sign in with Passkey (WebAuthn PRF)" } else { "Sign in with biometrics" }}
                                    </span>
                                </div>
                                <p class="text-xs text-gray-500">"Use fingerprint, face recognition, or a security key."</p>
                                <button
                                    on:click=move |_: web_sys::MouseEvent| {
                                        let auth = auth;
                                        let dest = return_to();
                                        is_pending.set(true);
                                        spawn_local(async move {
                                            let stored_pubkey = auth.pubkey().get_untracked();
                                            let result = auth.login_with_passkey(stored_pubkey.as_deref()).await;
                                            is_pending.set(false);
                                            if result.is_ok() {
                                                navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
                                            }
                                        });
                                    }
                                    disabled=move || is_pending.get()
                                    class="w-full bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:cursor-not-allowed text-white py-2.5 rounded-lg transition-colors text-sm font-semibold flex items-center justify-center gap-2"
                                >
                                    <Show
                                        when=move || is_pending.get()
                                        fallback=|| view! { <span>"Sign In with Biometrics"</span> }
                                    >
                                        <span class="animate-spin inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full"></span>
                                        <span>"Authenticating..."</span>
                                    </Show>
                                </button>
                            </div>
                        </div>
                    </Show>
                </div>

                <p class="text-center text-gray-500 text-sm mt-6">
                    "Don\u{2019}t have an account? "
                    <A href=base_href("/signup") attr:class="text-amber-400 hover:text-amber-300 underline">
                        "Create one"
                    </A>
                </p>
            </div>
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn key_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn extension_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a2 2 0 012 2v3a1 1 0 01-1 1 2 2 0 100 4 1 1 0 011 1v3a2 2 0 01-2 2h-3a1 1 0 01-1-1 2 2 0 10-4 0 1 1 0 01-1 1H7a2 2 0 01-2-2v-3a1 1 0 00-1-1 2 2 0 110-4 1 1 0 001-1V8a2 2 0 012-2h3a1 1 0 001-1V4z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn biometric_icon() -> impl IntoView {
    view! {
        <svg class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
