//! Nickname setup page — shown after first-time registration.
//!
//! Publishes a kind 0 (metadata) event to the relay with the chosen nickname
//! and optional bio, then updates the auth store and navigates to `/forums`.

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use leptos_router::NavigateOptions;
use nostr_core::UnsignedEvent;

use crate::auth::use_auth;
use crate::relay::RelayConnection;
use crate::utils::shorten_pubkey;

// -- Validation ---------------------------------------------------------------

fn validate_nickname(name: &str) -> Result<String, String> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err("Nickname cannot be empty".into());
    }
    if trimmed.len() < 2 {
        return Err("Nickname must be at least 2 characters".into());
    }
    if trimmed.len() > 50 {
        return Err("Nickname must be 50 characters or fewer".into());
    }
    if trimmed != name {
        return Err("Nickname must not have leading or trailing whitespace".into());
    }
    Ok(trimmed)
}

// -- Component ----------------------------------------------------------------

#[component]
pub fn SetupPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = StoredValue::new(use_navigate());
    // Capture relay at component level — reactive context is unavailable
    // inside event handler closures and spawn_local in Leptos 0.7.
    let relay = expect_context::<RelayConnection>();

    let nickname = RwSignal::new(String::new());
    let about = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let is_submitting = RwSignal::new(false);
    let nick_valid = RwSignal::new(false);

    // Read returnTo query parameter — default to /forums, reject loops
    let query = use_query_map();
    let return_to = move || {
        let r = query.read().get("returnTo").unwrap_or_default();
        if r.is_empty() || !r.starts_with('/') || r == "/login" || r == "/signup" || r == "/setup" {
            "/forums".to_string()
        } else {
            r
        }
    };

    // Validate nickname on every keystroke
    let on_nick_input = move |ev: leptos::ev::Event| {
        let val = event_target_value(&ev);
        nickname.set(val.clone());
        match validate_nickname(&val) {
            Ok(_) => {
                nick_valid.set(true);
                error.set(None);
            }
            Err(e) => {
                nick_valid.set(false);
                // Only show error if user has typed something
                if !val.is_empty() {
                    error.set(Some(e));
                } else {
                    error.set(None);
                }
            }
        }
    };

    let on_about_input = move |ev: leptos::ev::Event| {
        let val = event_target_value(&ev);
        if val.len() <= 256 {
            about.set(val);
        }
    };

    let pubkey_display = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .map(|pk| shorten_pubkey(&pk))
            .unwrap_or_else(|| "unknown".to_string())
    });

    let on_submit = move |_| {
        let name = nickname.get_untracked();
        let trimmed = match validate_nickname(&name) {
            Ok(n) => n,
            Err(e) => {
                error.set(Some(e));
                return;
            }
        };

        let bio = about.get_untracked().trim().to_string();
        let pubkey_hex = match auth.pubkey().get_untracked() {
            Some(pk) => pk,
            None => {
                error.set(Some("No pubkey available — please log in again".into()));
                return;
            }
        };

        is_submitting.set(true);
        error.set(None);

        // Build kind 0 metadata event
        let mut metadata = serde_json::Map::new();
        metadata.insert("name".into(), serde_json::Value::String(trimmed.clone()));
        if !bio.is_empty() {
            metadata.insert("about".into(), serde_json::Value::String(bio));
        }

        let content =
            serde_json::to_string(&serde_json::Value::Object(metadata)).unwrap_or_default();

        let unsigned = UnsignedEvent {
            pubkey: pubkey_hex,
            created_at: (js_sys::Date::now() / 1000.0) as u64,
            kind: 0,
            tags: vec![],
            content,
        };

        let trimmed_for_ack = trimmed.clone();
        let relay = relay.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    relay.publish(&signed);

                    auth.set_profile(Some(trimmed_for_ack), None);
                    auth.complete_signup();

                    let dest = return_to();
                    navigate.with_value(|nav| {
                        nav(&dest, NavigateOptions::default());
                    });
                }
                Err(e) => {
                    is_submitting.set(false);
                    error.set(Some(format!("Failed to sign event: {}", e)));
                }
            }
        });
    };

    let about_chars = Memo::new(move |_| about.get().len());

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4 relative overflow-hidden">
            // Ambient orbs
            <div class="ambient-orb ambient-orb-1" aria-hidden="true"></div>
            <div class="ambient-orb ambient-orb-2" aria-hidden="true"></div>
            <div class="ambient-orb ambient-orb-3" aria-hidden="true"></div>

            <div class="w-full max-w-md relative z-10">
                <div class="glass-card p-8 space-y-6">
                    // Header
                    <div class="text-center space-y-2">
                        <h1 class="text-3xl font-bold candy-gradient">
                            "Welcome to Nostr BBS"
                        </h1>
                        <p class="text-gray-400 text-sm">
                            "Set up your profile to join the community"
                        </p>
                        <div class="inline-flex items-center gap-1.5 bg-gray-800/60 rounded-full px-3 py-1 text-xs text-gray-500 mt-2">
                            {pubkey_icon_svg()}
                            <span class="font-mono">{move || pubkey_display.get()}</span>
                        </div>
                    </div>

                    // Error display
                    <Show when=move || error.get().is_some()>
                        <div class="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
                            {move || error.get().unwrap_or_default()}
                        </div>
                    </Show>

                    // Nickname field
                    <div class="space-y-2">
                        <label for="nickname" class="block text-sm font-medium text-gray-300">
                            "Nickname"
                            <span class="text-red-400 ml-0.5">"*"</span>
                        </label>
                        <input
                            id="nickname"
                            type="text"
                            placeholder="Choose a nickname (2-50 characters)"
                            on:input=on_nick_input
                            prop:value=move || nickname.get()
                            maxlength="50"
                            class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                        />
                        <div class="flex justify-between text-xs">
                            <Show when=move || nick_valid.get()>
                                <span class="text-green-400">"Looks good!"</span>
                            </Show>
                            <Show when=move || !nick_valid.get()>
                                <span></span>
                            </Show>
                            <span class="text-gray-600">
                                {move || format!("{}/50", nickname.get().len())}
                            </span>
                        </div>
                    </div>

                    // Bio / About field (optional)
                    <div class="space-y-2">
                        <label for="about" class="block text-sm font-medium text-gray-300">
                            "About "
                            <span class="text-gray-600 font-normal">"(optional)"</span>
                        </label>
                        <textarea
                            id="about"
                            placeholder="Tell people a bit about yourself"
                            on:input=on_about_input
                            prop:value=move || about.get()
                            rows="3"
                            maxlength="256"
                            class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 resize-none"
                        />
                        <div class="text-right text-xs text-gray-600">
                            {move || format!("{}/256", about_chars.get())}
                        </div>
                    </div>

                    // Submit button
                    <button
                        on:click=on_submit
                        disabled=move || !nick_valid.get() || is_submitting.get()
                        class="w-full bg-amber-500 hover:bg-amber-400 disabled:bg-amber-700 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2"
                    >
                        <Show
                            when=move || is_submitting.get()
                            fallback=|| view! {
                                {arrow_right_icon_svg()}
                                <span>"Continue"</span>
                            }
                        >
                            <span class="animate-spin inline-block w-5 h-5 border-2 border-gray-900 border-t-transparent rounded-full"></span>
                            <span>"Publishing profile..."</span>
                        </Show>
                    </button>

                    // Security note
                    <div class="flex items-center justify-center gap-2 text-xs text-gray-500 pt-1">
                        {shield_icon_svg()}
                        <span>"Your nickname and bio are visible to other community members"</span>
                    </div>
                </div>
            </div>
        </div>
    }
}

// -- SVG icons ----------------------------------------------------------------

fn pubkey_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn arrow_right_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

fn shield_icon_svg() -> impl IntoView {
    view! {
        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
        </svg>
    }
}
