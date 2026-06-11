//! `/connect` magic-link onboarding page (ADR-098).
//!
//! A QR printed on the recovery sheet (ADR-095) encodes
//! `{origin}{FORUM_BASE}/connect#k=<nsec1…>`. A phone-camera scan opens that
//! HTTPS URL, which loads the forum PWA and lands here. This page reads the
//! secret key out of the URL *fragment*, imports it through the EXISTING
//! local-key auth path (the same `login_with_local_key` the login page uses for
//! a pasted recovery key), and signs the device in.
//!
//! ## Hard security invariants
//!
//! * **Fragment only.** The key lives ONLY after `#`. Fragments are never sent
//!   to the server in an HTTP request, so the relay/host never sees the nsec.
//!   It is never placed in a query string nor transmitted anywhere.
//! * **History strip happens FIRST.** Immediately on mount — *before* any
//!   `await`, before validation, before import — we call
//!   `history.replaceState` to rewrite the URL to a clean
//!   `{FORUM_BASE}/connect` so the nsec never lingers in the address bar,
//!   browser history, or the back button. Only after the URL is sanitised do we
//!   touch the key.
//! * **Bearer credential.** Whoever held that QR/link can sign in as this user.
//!   On success the page shows a red warning to that effect.
//! * **Validate, then import.** Accepts `nsec1…` (bech32, decoded via the
//!   existing NIP-19 path inside `login_with_local_key`) or 64-hex; anything
//!   else is rejected with a clear error and no import. We do NOT hand-roll
//!   bech32 or signer logic here.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

use crate::app::{base_href, current_app_path};
use crate::auth::use_auth;
use crate::utils::set_timeout_once;

/// Outcome of the on-mount import attempt.
#[derive(Clone, PartialEq)]
enum ConnectState {
    /// Reading + importing the key (the brief synchronous window on mount).
    Working,
    /// Imported and signed in — show the success + bearer warning, then redirect.
    Success,
    /// No `#k=` fragment, or the key failed validation/import.
    Error(String),
}

/// Pull the raw key out of `window.location().hash()`.
///
/// Accepts `#k=<key>`, `#<key>`, and a `k=` prefix with or without the leading
/// `#`. Returns `None` when there is no usable fragment.
fn read_key_from_hash() -> Option<String> {
    let window = web_sys::window()?;
    let hash = window.location().hash().ok()?;
    // `hash()` includes the leading '#'. Strip it.
    let frag = hash.strip_prefix('#').unwrap_or(&hash).trim();
    if frag.is_empty() {
        return None;
    }
    // Canonical form is `k=<key>`; tolerate a bare `<key>` too.
    let key = frag.strip_prefix("k=").unwrap_or(frag).trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

/// Replace the current history entry with a fragment-free URL.
///
/// MUST run before the key is imported so the nsec is gone from the address
/// bar, history, and back button regardless of what happens next. Best-effort:
/// if the History API is unavailable we still proceed (the key is already only
/// in memory at this point), but on every supported browser this strips it.
fn strip_fragment_from_history() {
    if let Some(window) = web_sys::window() {
        if let Ok(history) = window.history() {
            let clean = base_href("/connect");
            // `replace_state` with the same data and an explicit URL rewrites the
            // visible URL (dropping the fragment) without adding a history entry.
            let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&clean));
        }
    }
}

#[component]
pub fn ConnectPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = StoredValue::new(use_navigate());
    let state = RwSignal::new(ConnectState::Working);

    // ── On-mount sequence (synchronous, ordered) ─────────────────────────────
    // 1. read the key from the fragment
    // 2. STRIP THE FRAGMENT FROM HISTORY (before any import / await)
    // 3. validate + import via the reused local-key auth path
    // 4. on success, schedule a redirect to /forums
    //
    // Steps 1-3 run synchronously inside this Effect so there is no `await`
    // between reading the key and stripping the fragment.
    Effect::new(move |_| {
        // (1) read first — we need the value before we wipe the URL.
        let key = read_key_from_hash();

        // (2) strip immediately, unconditionally, before any import.
        strip_fragment_from_history();

        // (3) validate + import.
        match key {
            Some(k) => {
                auth.clear_error();
                match auth.login_with_local_key(&k) {
                    Ok(()) => {
                        state.set(ConnectState::Success);
                        // (4) brief pause so the user reads the bearer warning,
                        // then SPA-navigate into the forum.
                        let nav = navigate;
                        set_timeout_once(
                            move || {
                                let dest = current_app_path("/forums");
                                nav.with_value(|n| n(&dest, NavigateOptions::default()));
                            },
                            1500,
                        );
                    }
                    Err(e) => state.set(ConnectState::Error(e)),
                }
            }
            None => state.set(ConnectState::Error(
                "No sign-in key found in this link. Open it from the QR on your recovery sheet, \
                 or sign in manually."
                    .to_string(),
            )),
        }
    });

    let continue_now = move |_: web_sys::MouseEvent| {
        let dest = current_app_path("/forums");
        navigate.with_value(|n| n(&dest, NavigateOptions::default()));
    };

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4">
            <div class="w-full max-w-md">
                <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-8 space-y-6">
                    {move || match state.get() {
                        ConnectState::Working => view! {
                            <div class="text-center space-y-4">
                                <div class="animate-spin w-8 h-8 mx-auto border-2 border-amber-400 border-t-transparent rounded-full"></div>
                                <p class="text-gray-400 text-sm">"Signing you in…"</p>
                            </div>
                        }.into_any(),

                        ConnectState::Success => view! {
                            <div class="space-y-5 text-center">
                                <div class="text-3xl">"✓"</div>
                                <h1 class="text-2xl font-bold text-white">"This device is now signed in"</h1>
                                // Red bearer-credential warning.
                                <div class="bg-red-900/30 border border-red-700 rounded-lg p-4 text-left">
                                    <p class="text-sm font-semibold text-red-300 mb-1">
                                        "⚠ This link is your account"
                                    </p>
                                    <p class="text-xs text-red-300/90">
                                        "Anyone who had that QR or link can sign in as you. "
                                        "Keep your recovery sheet private and don\u{2019}t share the link."
                                    </p>
                                </div>
                                <p class="text-xs text-gray-500">"Taking you to the forum…"</p>
                                <button
                                    on:click=continue_now
                                    class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl transition-colors text-sm"
                                >
                                    "Continue"
                                </button>
                            </div>
                        }.into_any(),

                        ConnectState::Error(msg) => view! {
                            <div class="space-y-5 text-center">
                                <h1 class="text-2xl font-bold text-white">"Couldn\u{2019}t sign in"</h1>
                                <div class="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300 text-sm text-left">
                                    {msg}
                                </div>
                                <A
                                    href=base_href("/login")
                                    attr:class="inline-block w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl transition-colors text-sm"
                                >
                                    "Go to sign-in"
                                </A>
                            </div>
                        }.into_any(),
                    }}
                </div>
            </div>
        </div>
    }
}
