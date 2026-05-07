//! Onboarding modal — claim-username flow shown after first login.
//!
//! Displayed when the authenticated user has no claimed username yet and
//! has not skipped the prompt within the last 7 days. The component
//! self-gates via localStorage flags keyed on the first 8 chars of the
//! pubkey:
//!
//! - `nostr_bbs_username_claimed_{pubkey8}` — claim succeeded; never re-prompt
//! - `nostr_bbs_username_skipped_until_{pubkey8}` — UNIX-ms timestamp; suppress until
//!
//! The legacy `members:onboarded` localStorage key is still honoured so
//! pre-existing users who already completed v1 onboarding are not nagged.
//!
//! Validation is two-stage:
//! 1. Local regex `^[a-z0-9][a-z0-9_-]{2,29}$`
//! 2. Debounced (300 ms) `GET /api/username/check?name=` against auth-worker.
//!
//! On submit the client sends a NIP-98 authed `POST /api/username/claim`
//! with body `{"username": "..."}`. On success we publish a kind-0 update
//! containing the chosen `name` and `nip05` fields and update auth state.
//!
//! All network errors are surfaced as a graceful "service temporarily
//! unavailable" string so the page never crashes when the worker has not
//! yet been deployed (Sprint v10 STREAM-N1 dependency).

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::auth::nip98::fetch_with_nip98_post_signer;
use crate::auth::use_auth;
use crate::utils::relay_url::auth_api_base;

// -- localStorage helpers -----------------------------------------------------

/// Legacy v1 onboarding flag.
const LEGACY_ONBOARDED_KEY: &str = "nostrbbs:onboarded";
/// Suppress duration when user clicks "I'll choose later" (7 days, ms).
const SKIP_DURATION_MS: f64 = 7.0 * 24.0 * 60.0 * 60.0 * 1000.0;
/// NIP-05 host that backs successful claims.
const NIP05_HOST: &str = "example.test";

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

fn pubkey8(pubkey: &str) -> String {
    pubkey.chars().take(8).collect()
}

fn claimed_key(pubkey: &str) -> String {
    format!("nostr_bbs_username_claimed_{}", pubkey8(pubkey))
}

fn skipped_key(pubkey: &str) -> String {
    format!("nostr_bbs_username_skipped_until_{}", pubkey8(pubkey))
}

/// Has the user already claimed (locally cached)?
fn has_claimed_locally(pubkey: &str) -> bool {
    local_storage()
        .and_then(|s| s.get_item(&claimed_key(pubkey)).ok().flatten())
        .is_some()
}

/// Mark the username as claimed locally so we never re-prompt this user.
fn mark_claimed_locally(pubkey: &str, username: &str) {
    if let Some(s) = local_storage() {
        let _ = s.set_item(&claimed_key(pubkey), username);
    }
}

/// Clear the local claim cache (used on release).
fn clear_claimed_locally(pubkey: &str) {
    if let Some(s) = local_storage() {
        let _ = s.remove_item(&claimed_key(pubkey));
    }
}

/// Read the "skip until" timestamp from localStorage, returning `true`
/// if the user has skipped recently and the suppression has not expired.
fn is_skipping(pubkey: &str) -> bool {
    let Some(s) = local_storage() else {
        return false;
    };
    let Some(raw) = s.get_item(&skipped_key(pubkey)).ok().flatten() else {
        return false;
    };
    raw.parse::<f64>()
        .map(|until| js_sys::Date::now() < until)
        .unwrap_or(false)
}

fn set_skipped(pubkey: &str) {
    if let Some(s) = local_storage() {
        let until = js_sys::Date::now() + SKIP_DURATION_MS;
        let _ = s.set_item(&skipped_key(pubkey), &format!("{:.0}", until));
    }
}

fn clear_skipped(pubkey: &str) {
    if let Some(s) = local_storage() {
        let _ = s.remove_item(&skipped_key(pubkey));
    }
}

// -- Username validation ------------------------------------------------------

/// Client-side regex check matching the auth-worker rule
/// `^[a-z0-9][a-z0-9_-]{2,29}$`. Length 3..=30, lowercase alnum + `_` + `-`,
/// no leading hyphen/underscore.
fn is_valid_format(name: &str) -> bool {
    let len = name.chars().count();
    if !(3..=30).contains(&len) {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CheckState {
    Idle,
    Pending,
    Available,
    Taken,
    InvalidFormat,
    Unavailable, // service temporarily unavailable
}

#[derive(Deserialize, Debug)]
struct CheckResponse {
    available: bool,
    #[allow(dead_code)]
    #[serde(default)]
    claimed_by: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ClaimResponse {
    #[allow(dead_code)]
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

async fn check_username_available(name: &str) -> Result<bool, String> {
    let url = format!(
        "{}/api/username/check?name={}",
        auth_api_base(),
        urlencoding_encode(name)
    );
    let win = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    let req = web_sys::Request::new_with_str_and_init(&url, &init)
        .map_err(|e| format!("request build failed: {:?}", e))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("fetch failed: {:?}", e))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "bad response type".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let txt_promise = resp.text().map_err(|e| format!("text() failed: {:?}", e))?;
    let txt_val = JsFuture::from(txt_promise)
        .await
        .map_err(|e| format!("await text failed: {:?}", e))?;
    let txt = txt_val
        .as_string()
        .ok_or_else(|| "non-string body".to_string())?;
    let parsed: CheckResponse =
        serde_json::from_str(&txt).map_err(|e| format!("parse failed: {}", e))?;
    Ok(parsed.available)
}

/// Minimal URI-encoder for query-string values (RFC 3986 unreserved set).
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// -- Component ----------------------------------------------------------------

/// Optional pre-fill — used by the Settings "Change username" flow.
#[derive(Clone, Copy, Debug)]
pub struct OnboardingPrefill {
    pub initial: RwSignal<Option<String>>,
    pub force_open: RwSignal<bool>,
}

/// Provide an `OnboardingPrefill` context so other pages (Settings) can
/// open the modal pre-filled with an existing value.
pub fn provide_onboarding_prefill() {
    provide_context(OnboardingPrefill {
        initial: RwSignal::new(None),
        force_open: RwSignal::new(false),
    });
}

/// Open the onboarding modal in "change username" mode pre-filled with `current`.
pub fn open_onboarding_with_prefill(current: Option<String>) {
    if let Some(prefill) = use_context::<OnboardingPrefill>() {
        prefill.initial.set(current);
        prefill.force_open.set(true);
    }
}

#[component]
pub fn OnboardingModal() -> impl IntoView {
    let auth = use_auth();
    let prefill = use_context::<OnboardingPrefill>();

    let is_open = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let check_state = RwSignal::new(CheckState::Idle);
    let submit_error = RwSignal::new(Option::<String>::None);
    let is_submitting = RwSignal::new(false);
    // Generation counter to invalidate in-flight debounced checks when the
    // user keeps typing.
    let check_seq = RwSignal::new(0u32);

    // Decide whether to open on auth-state change.
    Effect::new(move |_| {
        let state = auth.state.get();
        if !state.is_authenticated {
            is_open.set(false);
            return;
        }

        // Force-opened from Settings ("Change username")
        if let Some(p) = prefill {
            if p.force_open.get() {
                if let Some(initial) = p.initial.get_untracked() {
                    username.set(initial);
                } else {
                    username.set(String::new());
                }
                is_open.set(true);
                return;
            }
        }

        // Auto-open when user has no nickname AND has not claimed AND not skipping.
        let pubkey = match state.pubkey.as_ref() {
            Some(pk) => pk.clone(),
            None => return,
        };
        if state.nickname.is_some() {
            return;
        }
        if has_claimed_locally(&pubkey) {
            return;
        }
        if is_skipping(&pubkey) {
            return;
        }
        // Honour legacy v1 flag — pre-existing onboarded users are not pestered.
        if let Some(s) = local_storage() {
            if s.get_item(LEGACY_ONBOARDED_KEY).ok().flatten().is_some() {
                return;
            }
        }
        is_open.set(true);
    });

    // Debounced live validation.
    let debounce_handle: RwSignal<Option<i32>> = RwSignal::new(None);
    Effect::new(move |_| {
        let value = username.get();
        // Cancel any pending check.
        if let Some(h) = debounce_handle.get_untracked() {
            if let Some(w) = web_sys::window() {
                w.clear_timeout_with_handle(h);
            }
            debounce_handle.set(None);
        }

        if value.trim().is_empty() {
            check_state.set(CheckState::Idle);
            return;
        }
        if !is_valid_format(value.trim()) {
            check_state.set(CheckState::InvalidFormat);
            return;
        }

        check_state.set(CheckState::Pending);
        let seq_now = check_seq.get_untracked().wrapping_add(1);
        check_seq.set(seq_now);

        let cb = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
            // Schedule the actual fetch.
            let value = username.get_untracked().trim().to_string();
            if value.is_empty() {
                check_state.set(CheckState::Idle);
                return;
            }
            if !is_valid_format(&value) {
                check_state.set(CheckState::InvalidFormat);
                return;
            }
            spawn_local(async move {
                match check_username_available(&value).await {
                    Ok(true) => {
                        if check_seq.get_untracked() == seq_now {
                            check_state.set(CheckState::Available);
                        }
                    }
                    Ok(false) => {
                        if check_seq.get_untracked() == seq_now {
                            check_state.set(CheckState::Taken);
                        }
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("[onboarding] username check failed: {}", e).into(),
                        );
                        if check_seq.get_untracked() == seq_now {
                            check_state.set(CheckState::Unavailable);
                        }
                    }
                }
            });
        }) as Box<dyn FnMut()>);

        if let Some(w) = web_sys::window() {
            if let Ok(h) = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                300,
            ) {
                debounce_handle.set(Some(h));
            }
        }
        cb.forget();
    });

    // Submit handler.
    let on_submit = move |_: web_sys::MouseEvent| {
        let name = username.get_untracked().trim().to_string();
        if !is_valid_format(&name) {
            submit_error.set(Some(
                "Please enter a valid username (3-30 chars, a-z, 0-9, _, -, no leading -/_)".into(),
            ));
            return;
        }
        let pubkey = match auth.pubkey().get_untracked() {
            Some(pk) => pk,
            None => {
                submit_error.set(Some("Not authenticated".into()));
                return;
            }
        };
        // Sprint v11: route signing through the Signer trait so NIP-07 and
        // future hardware-bunker backends work alongside PRF/local keys.
        let signer = match auth.get_signer() {
            Some(s) => s,
            None => {
                submit_error.set(Some("No signer available — please sign in again.".into()));
                return;
            }
        };

        is_submitting.set(true);
        submit_error.set(None);

        let url = format!("{}/api/username/claim", auth_api_base());
        let body = serde_json::json!({ "username": name }).to_string();
        let pubkey_for_meta = pubkey.clone();
        let name_for_meta = name.clone();

        spawn_local(async move {
            let result = fetch_with_nip98_post_signer(&url, &body, signer.as_ref()).await;

            match result {
                Ok(text) => {
                    // Optimistically treat any 2xx body as success; surface error string only if present.
                    let parsed: ClaimResponse =
                        serde_json::from_str(&text).unwrap_or(ClaimResponse {
                            success: Some(true),
                            error: None,
                        });
                    if let Some(err) = parsed.error.filter(|e| !e.is_empty()) {
                        submit_error.set(Some(err));
                        is_submitting.set(false);
                        return;
                    }

                    // Persist + update auth state.
                    mark_claimed_locally(&pubkey_for_meta, &name_for_meta);
                    clear_skipped(&pubkey_for_meta);
                    auth.set_profile(Some(name_for_meta.clone()), None);

                    // Publish a kind-0 update with name + nip05 fields so other clients
                    // see the new identity. Best-effort; failures are logged.
                    let nip05 = format!("{}@{}", name_for_meta, NIP05_HOST);
                    let meta = serde_json::json!({
                        "name": name_for_meta,
                        "display_name": name_for_meta,
                        "nip05": nip05,
                    })
                    .to_string();
                    let now = (js_sys::Date::now() / 1000.0) as u64;
                    let unsigned = nostr_core::UnsignedEvent {
                        pubkey: pubkey_for_meta.clone(),
                        created_at: now,
                        kind: 0,
                        tags: vec![],
                        content: meta,
                    };
                    // Use async signing so the kind-0 publish works for both
                    // PRF/local-key and NIP-07 sessions.
                    if let Ok(signed) = auth.sign_event_async(unsigned).await {
                        if let Some(relay) = use_context::<crate::relay::RelayConnection>() {
                            relay.publish(&signed);
                        }
                    }

                    is_submitting.set(false);
                    is_open.set(false);
                    if let Some(p) = prefill {
                        p.force_open.set(false);
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    web_sys::console::warn_1(
                        &format!("[onboarding] username claim failed: {}", msg).into(),
                    );
                    // Distinguish "service unavailable" from "already taken" / validation.
                    let user_msg = if msg.contains("HTTP 409") {
                        "That username has just been taken. Please pick another.".to_string()
                    } else if msg.contains("HTTP 400") {
                        "Invalid username format.".to_string()
                    } else if msg.contains("HTTP") {
                        format!("Server rejected the request ({})", msg)
                    } else {
                        "Username service is temporarily unavailable. Please try again later."
                            .to_string()
                    };
                    submit_error.set(Some(user_msg));
                    is_submitting.set(false);
                }
            }
        });
    };

    // Skip / close handlers.
    let on_skip = move |_: web_sys::MouseEvent| {
        if let Some(pk) = auth.pubkey().get_untracked() {
            set_skipped(&pk);
        }
        is_open.set(false);
        if let Some(p) = prefill {
            p.force_open.set(false);
        }
    };

    // Allow close from Settings ("Change username" cancel) — but never auto-close
    // if this is a forced first-login prompt without a nickname.
    let on_close = move |_: web_sys::MouseEvent| {
        if let Some(p) = prefill {
            if p.force_open.get_untracked() {
                p.force_open.set(false);
                is_open.set(false);
                return;
            }
        }
        // For the auto-prompt path, treat the X as "skip for 7 days".
        if let Some(pk) = auth.pubkey().get_untracked() {
            set_skipped(&pk);
        }
        is_open.set(false);
    };

    // Status indicator below the input.
    let status_view = move || {
        match check_state.get() {
        CheckState::Idle => view! {
            <p class="text-xs text-gray-500">"3-30 chars: a-z, 0-9, _ or -"</p>
        }
        .into_any(),
        CheckState::Pending => view! {
            <p class="text-xs text-gray-400">"Checking availability\u{2026}"</p>
        }
        .into_any(),
        CheckState::Available => view! {
            <p class="text-xs text-emerald-400">"\u{2713} available"</p>
        }
        .into_any(),
        CheckState::Taken => view! {
            <p class="text-xs text-red-400">"\u{2717} already taken"</p>
        }
        .into_any(),
        CheckState::InvalidFormat => view! {
            <p class="text-xs text-red-400">
                "\u{2717} invalid format \u{2014} 3-30 chars: a-z, 0-9, _ or -, must start with letter or digit"
            </p>
        }
        .into_any(),
        CheckState::Unavailable => view! {
            <p class="text-xs text-amber-400">
                "Username service is temporarily unavailable. You may submit anyway \u{2014} the server will validate."
            </p>
        }
        .into_any(),
    }
    };

    let can_submit = move || {
        !is_submitting.get()
            && matches!(
                check_state.get(),
                CheckState::Available | CheckState::Unavailable
            )
            && is_valid_format(username.get().trim())
    };

    let nip05_preview = move || {
        let name = username.get();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("{}@{}", trimmed, NIP05_HOST)
        }
    };

    view! {
        <Show when=move || is_open.get()>
            <div
                class="fixed inset-0 z-[70] flex items-center justify-center p-4"
                style="animation: fadeIn 0.3s ease-out"
            >
                <div class="absolute inset-0 bg-black/70 backdrop-blur-sm" />

                <div
                    class="relative bg-gray-900/95 backdrop-blur-xl border border-white/10 rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-2xl shadow-amber-500/10"
                    style="animation: scaleIn 0.3s ease-out"
                    on:click=|e: web_sys::MouseEvent| e.stop_propagation()
                >
                    <div class="absolute inset-0 rounded-2xl bg-gradient-to-r from-amber-500/20 via-orange-500/20 to-amber-500/20 -z-10 blur-sm" />

                    // Close button (top-right)
                    <button
                        on:click=on_close
                        class="absolute top-3 right-3 text-gray-500 hover:text-white transition-colors p-1 rounded"
                        aria-label="Close"
                    >
                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                    </button>

                    <div class="text-center mb-5">
                        <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-amber-500/10 border border-amber-500/20 mb-3">
                            {handle_icon()}
                        </div>
                        <h2 class="text-2xl font-bold bg-gradient-to-r from-amber-400 via-orange-400 to-rose-400 bg-clip-text text-transparent">
                            "Pick your username"
                        </h2>
                        <p class="text-gray-400 text-sm mt-2">
                            "Choose a unique handle so others can mention and find you. You can change it later in settings."
                        </p>
                    </div>

                    <div class="space-y-3">
                        <div class="space-y-1">
                            <label for="onboard-username" class="block text-sm font-medium text-gray-300">
                                "Username"
                            </label>
                            <div class="flex items-center bg-gray-800 border border-gray-600 focus-within:border-amber-500 focus-within:ring-1 focus-within:ring-amber-500 rounded-xl overflow-hidden">
                                <span class="pl-3 text-gray-500 select-none">"@"</span>
                                <input
                                    id="onboard-username"
                                    type="text"
                                    placeholder="alice"
                                    autocomplete="off"
                                    spellcheck="false"
                                    on:input=move |ev| {
                                        let v = event_target_value(&ev).to_lowercase();
                                        username.set(v);
                                    }
                                    prop:value=move || username.get()
                                    maxlength="30"
                                    class="flex-1 bg-transparent text-white placeholder-gray-500 px-2 py-3 text-sm focus:outline-none"
                                />
                            </div>
                            {status_view}
                        </div>

                        <div class="bg-gray-800/40 rounded-lg px-3 py-2 text-xs text-gray-400 border border-gray-700/40">
                            "NIP-05 handle: "
                            <code class="text-amber-300 font-mono">
                                {move || nip05_preview()}
                            </code>
                        </div>

                        {move || submit_error.get().map(|err| view! {
                            <div class="bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 text-xs text-red-300">
                                {err}
                            </div>
                        })}
                    </div>

                    <div class="flex gap-3 mt-5">
                        <button
                            on:click=on_skip
                            disabled=move || is_submitting.get()
                            class="flex-1 border border-gray-600 hover:border-gray-500 text-gray-300 py-3 rounded-xl transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            "I\u{2019}ll choose later"
                        </button>
                        <button
                            on:click=on_submit
                            disabled=move || !can_submit()
                            class="flex-1 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 disabled:from-gray-600 disabled:to-gray-700 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 rounded-xl transition-all duration-200 shadow-lg shadow-amber-500/25 text-sm"
                        >
                            {move || if is_submitting.get() { "Claiming\u{2026}" } else { "Claim username" }}
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}

/// Public helper used by the Settings "Release username" button.
///
/// Sends a NIP-98 authed `POST /api/username/release` with no body. On
/// success the local claim flag is cleared and the auth-state nickname is
/// reset to `None`. Errors are surfaced via the `Result`.
pub async fn release_username() -> Result<(), String> {
    let auth = use_auth();
    let pubkey = auth
        .pubkey()
        .get_untracked()
        .ok_or_else(|| "Not authenticated".to_string())?;
    // Sprint v11: route through the Signer trait so NIP-07 / hardware-bunker
    // backends can release usernames. PRF-derived keys still work transparently
    // because PrfSigner is the active signer for those sessions.
    let signer = auth
        .get_signer()
        .ok_or_else(|| "No signer available — please sign in again.".to_string())?;

    let url = format!("{}/api/username/release", auth_api_base());
    let body = "{}".to_string();
    let result = fetch_with_nip98_post_signer(&url, &body, signer.as_ref()).await;
    match result {
        Ok(_) => {
            clear_claimed_locally(&pubkey);
            auth.set_profile(None, None);
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("HTTP") {
                Err(format!("Server rejected the request ({})", msg))
            } else {
                Err(
                    "Username service is temporarily unavailable. Please try again later."
                        .to_string(),
                )
            }
        }
    }
}

// -- Icons --------------------------------------------------------------------

fn handle_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="12" cy="12" r="9" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M16 9a4 4 0 11-4-4M16 9v3a2 2 0 002 2"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_format_basic() {
        assert!(is_valid_format("alice"));
        assert!(is_valid_format("alice_99"));
        assert!(is_valid_format("a-b-c"));
        assert!(is_valid_format("0xb33f"));
        assert!(is_valid_format("abc")); // min length 3
        assert!(is_valid_format(&"a".repeat(30))); // max length 30
    }

    #[test]
    fn invalid_format_too_short_or_long() {
        assert!(!is_valid_format(""));
        assert!(!is_valid_format("ab"));
        assert!(!is_valid_format(&"a".repeat(31)));
    }

    #[test]
    fn invalid_format_uppercase() {
        assert!(!is_valid_format("Alice"));
        assert!(!is_valid_format("ALICE"));
    }

    #[test]
    fn invalid_format_leading_special() {
        assert!(!is_valid_format("-alice"));
        assert!(!is_valid_format("_alice"));
    }

    #[test]
    fn invalid_format_disallowed_chars() {
        assert!(!is_valid_format("alice!"));
        assert!(!is_valid_format("alice.bob"));
        assert!(!is_valid_format("alice bob"));
        assert!(!is_valid_format("alice@bob"));
    }

    #[test]
    fn url_encode_passthrough() {
        assert_eq!(urlencoding_encode("alice"), "alice");
        assert_eq!(urlencoding_encode("a_b-c.d"), "a_b-c.d");
    }

    #[test]
    fn url_encode_special() {
        assert_eq!(urlencoding_encode("a b"), "a%20b");
        assert_eq!(urlencoding_encode("a+b"), "a%2Bb");
        assert_eq!(urlencoding_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn pubkey8_truncates() {
        assert_eq!(pubkey8("0123456789abcdef"), "01234567");
        assert_eq!(pubkey8("abc"), "abc");
    }

    #[test]
    fn claimed_key_format() {
        assert_eq!(
            claimed_key("0123456789abcdef"),
            "nostr_bbs_username_claimed_01234567"
        );
    }

    #[test]
    fn skipped_key_format() {
        assert_eq!(
            skipped_key("0123456789abcdef"),
            "nostr_bbs_username_skipped_until_01234567"
        );
    }
}
