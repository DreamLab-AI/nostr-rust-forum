//! Onboarding modal — post-first-login profile capture.
//!
//! ## Current flow (operator simplification, 2026-06)
//!
//! The modal no longer asks the user to *claim a username* / mint a
//! `username@host` NIP-05 handle — the operator found that flow confusing.
//! It now captures two plain fields after first login:
//!
//! - **Display name** (public) — published to the user's kind-0 profile as
//!   both `name` and `display_name`.
//! - **Real name** (private, admin-only) — POSTed NIP-98-authed to
//!   `POST /api/profile/real-name` (handler `handle_set_own_real_name`). Never
//!   published to a relay; only admins can read it.
//!
//! A short line points the user at **Settings** to download their keys +
//! identity data (the existing recovery / `/connect` device-onboarding surface
//! that produces the printable identity sheet — see
//! `components/recovery_sheet.rs`). This modal does NOT reimplement that PDF;
//! it only links to it.
//!
//! ## Dormant (still compiled & exported) — DO NOT remove
//!
//! The username-claim / NIP-05 helpers below
//! (`claimed_username_cached`, `cache_claimed_username`, `nip05_for`,
//! `username_from_nip05`, `release_username`, the `ClaimedUsername` context,
//! `use_claimed_username`, `NIP05_HOST`) are retained because other modules
//! (`app.rs` kind-0 auto-whitelist, `pages/settings.rs`) still import and call
//! them. They are NOT exercised by the modal UI any more, but the kind-0
//! `nip05` probe-suppression still consumes them so a user who claimed a
//! handle on a previous build is not re-prompted.
//!
//! ## Auto-open gating (preserved)
//!
//! The component self-gates via localStorage flags keyed on the first 8 chars
//! of the pubkey:
//!
//! - `nostr_bbs_username_claimed_{pubkey8}` — a legacy/remote handle exists;
//!   never re-prompt (still honoured for back-compat)
//! - `nostr_bbs_username_skipped_until_{pubkey8}` — UNIX-ms timestamp; suppress
//!   until it elapses
//! - `nostrbbs:onboarded` — legacy v1 flag; once set the modal never
//!   auto-pops. A successful profile submit (or "I'll do this later") sets it.
//!
//! All network errors are surfaced as a graceful inline error string so the
//! page never crashes when the worker has not yet been deployed.

use leptos::prelude::*;
use leptos_router::components::A;
use serde::Deserialize;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::app::base_href;
use crate::auth::nip98::fetch_with_nip98_post_signer;
use crate::auth::use_auth;
use crate::utils::relay_url::auth_api_base;

// -- localStorage helpers -----------------------------------------------------

/// Legacy v1 onboarding flag — also used as the "onboarding complete" marker
/// so the modal stops auto-popping once the user has submitted (or deferred).
const LEGACY_ONBOARDED_KEY: &str = "nostrbbs:onboarded";
/// Suppress duration when user clicks "I'll do this later" (7 days, ms).
const SKIP_DURATION_MS: f64 = 7.0 * 24.0 * 60.0 * 60.0 * 1000.0;
/// Maximum real-name length (mirrors the auth-worker `REAL_NAME_MAX_LEN` rule;
/// the server is authoritative — this is only a friendly client-side cap).
const REAL_NAME_MAX_LEN: usize = 100;
/// Maximum display-name length (kind-0 `name`/`display_name`).
const DISPLAY_NAME_MAX_LEN: usize = 50;
/// NIP-05 host that backs legacy claimed usernames. Baked at build time from
/// `NOSTR_BBS_NIP05_DOMAIN`; placeholder only for un-configured local builds.
/// Retained for the dormant `nip05_for` / `username_from_nip05` helpers and the
/// kind-0 probe — never surfaced in the modal UI any more.
const NIP05_HOST: &str = match option_env!("NOSTR_BBS_NIP05_DOMAIN") {
    Some(d) => d,
    None => "example.test",
};

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

/// Has the user already claimed a legacy handle (locally cached)?
fn has_claimed_locally(pubkey: &str) -> bool {
    claimed_username_cached(pubkey).is_some()
}

/// Read the locally-cached claimed username (the legacy claim flow stored the
/// username string as the flag value).
///
/// Dormant in the modal UI but still consumed by `app.rs` (kind-0
/// auto-whitelist) and `pages/settings.rs`.
pub fn claimed_username_cached(pubkey: &str) -> Option<String> {
    local_storage()
        .and_then(|s| s.get_item(&claimed_key(pubkey)).ok().flatten())
        .filter(|v| !v.is_empty())
}

/// Mark the username as claimed locally so we never re-prompt this user.
/// Retained for the dormant `cache_claimed_username` write-through.
fn mark_claimed_locally(pubkey: &str, username: &str) {
    if let Some(s) = local_storage() {
        let _ = s.set_item(&claimed_key(pubkey), username);
    }
}

/// Clear the local claim cache (used on `release_username`).
fn clear_claimed_locally(pubkey: &str) {
    if let Some(s) = local_storage() {
        let _ = s.remove_item(&claimed_key(pubkey));
    }
}

/// Set the device-wide "onboarding complete" marker so the modal never
/// auto-pops again for any pubkey on this device.
fn mark_onboarded() {
    if let Some(s) = local_storage() {
        let _ = s.set_item(LEGACY_ONBOARDED_KEY, "1");
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
        // ALSO set the legacy "onboarded" flag so the modal stops auto-popping
        // for any pubkey on this device. Clicking "I'll do this later" should
        // mean "stop pestering me", not "ask again in 7 days". Users can still
        // edit their profile from Settings any time.
        let _ = s.set_item(LEGACY_ONBOARDED_KEY, "1");
    }
}

fn clear_skipped(pubkey: &str) {
    if let Some(s) = local_storage() {
        let _ = s.remove_item(&skipped_key(pubkey));
    }
}

// -- Dormant username/NIP-05 helpers (still compiled & exported) --------------

/// Client-side regex check matching the auth-worker rule
/// `^[a-z0-9][a-z0-9_-]{2,29}$`. Length 3..=30, lowercase alnum + `_` + `-`,
/// no leading hyphen/underscore.
///
/// Dormant: kept for back-compat and unit-test coverage of the legacy rule;
/// the modal no longer prompts for a username.
#[allow(dead_code)]
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

/// Minimal URI-encoder for query-string values (RFC 3986 unreserved set).
/// Dormant; retained for unit-test coverage and any future query use.
#[allow(dead_code)]
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

// -- Real-name submit response ------------------------------------------------

/// Response of `POST /api/profile/real-name`
/// (`{"ok": true, "real_name": ...}` on success, `{"error": "..."}` on failure).
#[derive(Deserialize, Debug)]
struct RealNameResponse {
    #[allow(dead_code)]
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

// -- Component context types --------------------------------------------------

/// Optional pre-fill — used by the Settings "Edit profile" flow.
///
/// `initial` carries the current display name to seed the field when the modal
/// is force-opened from Settings.
#[derive(Clone, Copy, Debug)]
pub struct OnboardingPrefill {
    pub initial: RwSignal<Option<String>>,
    pub force_open: RwSignal<bool>,
}

/// Reactive holder for the user's legacy CLAIMED username / NIP-05 handle.
///
/// Dormant in the modal but still provided and read by `pages/settings.rs`.
/// Deliberately separate from `AuthState::nickname` (the kind-0 display name):
/// a profile nickname must never be presented as a claimed handle.
#[derive(Clone, Copy, Debug)]
pub struct ClaimedUsername(pub RwSignal<Option<String>>);

/// Provide an `OnboardingPrefill` context so other pages (Settings) can
/// open the modal pre-filled, plus the shared (dormant) `ClaimedUsername`
/// signal.
pub fn provide_onboarding_prefill() {
    provide_context(OnboardingPrefill {
        initial: RwSignal::new(None),
        force_open: RwSignal::new(false),
    });
    provide_context(ClaimedUsername(RwSignal::new(None)));
}

/// Read the shared claimed-username signal (None outside the app tree).
/// Dormant in the modal; consumed by Settings.
pub fn use_claimed_username() -> Option<ClaimedUsername> {
    use_context::<ClaimedUsername>()
}

/// Write-through to the localStorage claim cache (no context access, safe
/// to call from relay callbacks). Dormant in the modal; called by `app.rs`.
pub fn cache_claimed_username(pubkey: &str, username: &str) {
    mark_claimed_locally(pubkey, username);
}

/// Format the NIP-05 identifier for a claimed username.
/// Dormant in the modal; consumed by `app.rs` kind-0 auto-whitelist.
pub fn nip05_for(username: &str) -> String {
    format!("{}@{}", username, NIP05_HOST)
}

/// Extract `name` from a kind-0 `nip05` value when it belongs to our host.
/// Dormant in the modal UI; still used by the kind-0 probe below and Settings.
pub fn username_from_nip05(nip05: &str) -> Option<String> {
    nip05
        .strip_suffix(&format!("@{}", NIP05_HOST))
        .filter(|n| !n.is_empty())
        .map(|n| n.to_string())
}

/// Open the onboarding modal pre-filled with `current` (the existing display
/// name). Invoked by the Settings "Edit profile" entry.
pub fn open_onboarding_with_prefill(current: Option<String>) {
    if let Some(prefill) = use_context::<OnboardingPrefill>() {
        prefill.initial.set(current);
        prefill.force_open.set(true);
    }
}

/// Probe the relay for the user's own kind-0 and return the username from
/// its `nip05` field (our host only). Waits up to 2.5s; the REQ is queued
/// by the relay client if the socket is still connecting.
///
/// Retained so a user who claimed a handle on a *previous* build (and so has a
/// kind-0 `nip05` but no local cache entry on this device) is recognised and
/// not re-prompted — the auto-open gate suppresses the modal when a remote
/// handle exists.
async fn probe_remote_claim(relay: &crate::relay::RelayConnection, pubkey: &str) -> Option<String> {
    use std::rc::Rc;

    let found: RwSignal<Option<String>> = RwSignal::new(None);
    let cb = Rc::new(move |ev: nostr_bbs_core::NostrEvent| {
        if ev.kind != 0 {
            return;
        }
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&ev.content) {
            if let Some(nip05) = obj.get("nip05").and_then(|v| v.as_str()) {
                if let Some(name) = username_from_nip05(nip05) {
                    found.set(Some(name));
                }
            }
        }
    });
    let sid = relay.subscribe(
        vec![crate::relay::Filter {
            kinds: Some(vec![0]),
            authors: Some(vec![pubkey.to_string()]),
            limit: Some(1),
            ..Default::default()
        }],
        cb,
        None,
    );
    let delay = js_sys::Promise::new(&mut |resolve, _| {
        let _ = web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 2_500);
    });
    let _ = JsFuture::from(delay).await;
    relay.unsubscribe(&sid);
    found.get_untracked()
}

// -- Component ----------------------------------------------------------------

#[component]
pub fn OnboardingModal() -> impl IntoView {
    let auth = use_auth();
    let prefill = use_context::<OnboardingPrefill>();

    let is_open = RwSignal::new(false);
    let display_name = RwSignal::new(String::new());
    let real_name = RwSignal::new(String::new());
    let submit_error = RwSignal::new(Option::<String>::None);
    let is_submitting = RwSignal::new(false);

    // Pubkey for which the remote claim probe has already run this session.
    let probed_pubkey: RwSignal<Option<String>> = RwSignal::new(None);

    // Decide whether to open on auth-state change.
    Effect::new(move |_| {
        let state = auth.state.get();
        if !state.is_authenticated {
            is_open.set(false);
            return;
        }

        // Force-opened from Settings ("Edit profile"): seed the display-name
        // field from the prefill (or the current kind-0 nickname).
        if let Some(p) = prefill {
            if p.force_open.get() {
                let seed = p
                    .initial
                    .get_untracked()
                    .or_else(|| state.nickname.clone())
                    .unwrap_or_default();
                display_name.set(seed);
                real_name.set(String::new());
                submit_error.set(None);
                is_open.set(true);
                return;
            }
        }

        let pubkey = match state.pubkey.as_ref() {
            Some(pk) => pk.clone(),
            None => return,
        };

        // Hydrate the shared (dormant) ClaimedUsername signal from the local
        // cache so Settings shows the legacy handle even before any network
        // access.
        let claimed_sig = use_claimed_username();
        if let Some(claimed) = claimed_sig {
            if claimed.0.get_untracked().is_none() {
                if let Some(cached) = claimed_username_cached(&pubkey) {
                    claimed.0.set(Some(cached));
                }
            }
        }

        // Auto-open only when no legacy claim exists AND not skipping.
        if has_claimed_locally(&pubkey) {
            return;
        }
        if is_skipping(&pubkey) {
            return;
        }
        // Honour the "onboarded" marker — a user who has already completed
        // (or deferred) onboarding is not pestered.
        if let Some(s) = local_storage() {
            if s.get_item(LEGACY_ONBOARDED_KEY).ok().flatten().is_some() {
                return;
            }
        }

        // The local cache is per-device: a user who claimed on another device
        // (or in a fresh browser context) has no cache entry. Before
        // prompting, probe the user's own kind-0 for a `nip05` minted by a
        // previous-build claim — if one exists, record it and suppress the
        // modal (a previously-claimed user must not be re-prompted).
        if probed_pubkey.get_untracked().as_deref() == Some(pubkey.as_str()) {
            return;
        }
        probed_pubkey.set(Some(pubkey.clone()));

        // Seed the display-name field from any existing kind-0 nickname so a
        // returning user sees their current name rather than a blank field.
        if display_name.get_untracked().is_empty() {
            if let Some(nick) = state.nickname.clone() {
                display_name.set(nick);
            }
        }

        let Some(relay) = use_context::<crate::relay::RelayConnection>() else {
            is_open.set(true);
            return;
        };
        spawn_local(async move {
            let remote = probe_remote_claim(&relay, &pubkey).await;
            match remote {
                Some(name) => {
                    // A legacy handle exists remotely — record it and suppress.
                    mark_claimed_locally(&pubkey, &name);
                    if let Some(claimed) = claimed_sig {
                        claimed.0.set(Some(name));
                    }
                    is_open.set(false);
                }
                None => {
                    // Re-check the gates — the user may have onboarded or
                    // skipped while the probe was in flight.
                    if !has_claimed_locally(&pubkey) && !is_skipping(&pubkey) {
                        is_open.set(true);
                    }
                }
            }
        });
    });

    // Submit handler: publish kind-0 (display name) + POST real name (private).
    let on_submit = move |_: web_sys::MouseEvent| {
        let display = display_name.get_untracked().trim().to_string();
        let real = real_name.get_untracked().trim().to_string();

        if display.is_empty() {
            submit_error.set(Some("Please enter a display name.".into()));
            return;
        }
        if display.chars().count() > DISPLAY_NAME_MAX_LEN {
            submit_error.set(Some(format!(
                "Display name is too long (max {DISPLAY_NAME_MAX_LEN} characters)."
            )));
            return;
        }
        if real.is_empty() {
            submit_error.set(Some("Please enter your real name.".into()));
            return;
        }
        if real.chars().count() > REAL_NAME_MAX_LEN {
            submit_error.set(Some(format!(
                "Real name is too long (max {REAL_NAME_MAX_LEN} characters)."
            )));
            return;
        }

        let pubkey = match auth.pubkey().get_untracked() {
            Some(pk) => pk,
            None => {
                submit_error.set(Some("Not authenticated".into()));
                return;
            }
        };
        // Route signing through the Signer trait so NIP-07 and future
        // hardware-bunker backends work alongside PRF/local keys.
        let signer = match auth.get_signer() {
            Some(s) => s,
            None => {
                submit_error.set(Some("No signer available — please sign in again.".into()));
                return;
            }
        };

        is_submitting.set(true);
        submit_error.set(None);

        let url = format!("{}/api/profile/real-name", auth_api_base());
        let body = serde_json::json!({ "real_name": real }).to_string();
        let pubkey_for_meta = pubkey.clone();
        let display_for_meta = display.clone();

        spawn_local(async move {
            // 1. POST the private real name (NIP-98 authed, admin-only visibility).
            let real_name_result = fetch_with_nip98_post_signer(&url, &body, signer.as_ref()).await;

            match real_name_result {
                Ok(text) => {
                    // Treat any 2xx body as success; surface an error string only if present.
                    let parsed: RealNameResponse =
                        serde_json::from_str(&text).unwrap_or(RealNameResponse {
                            ok: Some(true),
                            error: None,
                        });
                    if let Some(err) = parsed.error.filter(|e| !e.is_empty()) {
                        submit_error.set(Some(err));
                        is_submitting.set(false);
                        return;
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    web_sys::console::warn_1(
                        &format!("[onboarding] real-name submit failed: {}", msg).into(),
                    );
                    let user_msg = if msg.contains("HTTP 400") {
                        "That name could not be saved (invalid). Please try again.".to_string()
                    } else if msg.contains("HTTP") {
                        format!("Server rejected the request ({})", msg)
                    } else {
                        "Profile service is temporarily unavailable. Please try again later."
                            .to_string()
                    };
                    submit_error.set(Some(user_msg));
                    is_submitting.set(false);
                    return;
                }
            }

            // 2. Publish the public display name to the kind-0 profile.
            //    The kind-0 is replaceable; we set both `name` and
            //    `display_name` so other clients render the chosen name. We do
            //    NOT emit a `nip05` field — usernames/handles are no longer
            //    minted here. Avatar is preserved.
            let current = auth.get();
            auth.set_profile(Some(display_for_meta.clone()), current.avatar.clone());

            let meta = serde_json::json!({
                "name": display_for_meta,
                "display_name": display_for_meta,
            })
            .to_string();
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey: pubkey_for_meta.clone(),
                created_at: now,
                kind: 0,
                tags: vec![],
                content: meta,
            };
            // Async signing so the kind-0 publish works for PRF/local-key and
            // NIP-07 sessions alike. Best-effort; failures are logged.
            if let Ok(signed) = auth.sign_event_async(unsigned).await {
                if let Some(relay) = use_context::<crate::relay::RelayConnection>() {
                    relay.publish(&signed);
                }
            } else {
                web_sys::console::warn_1(
                    &"[onboarding] kind-0 display-name publish failed to sign".into(),
                );
            }

            // 3. Mark onboarding complete so the modal never re-prompts.
            clear_skipped(&pubkey_for_meta);
            mark_onboarded();

            is_submitting.set(false);
            is_open.set(false);
            if let Some(p) = prefill {
                p.force_open.set(false);
            }
        });
    };

    // "I'll do this later" — suppress (and set the onboarded marker).
    let on_skip = move |_: web_sys::MouseEvent| {
        if let Some(pk) = auth.pubkey().get_untracked() {
            set_skipped(&pk);
        }
        is_open.set(false);
        if let Some(p) = prefill {
            p.force_open.set(false);
        }
    };

    // Close (X). From Settings ("Edit profile" cancel) just close; from the
    // auto-prompt path, treat the X as "skip".
    let on_close = move |_: web_sys::MouseEvent| {
        if let Some(p) = prefill {
            if p.force_open.get_untracked() {
                p.force_open.set(false);
                is_open.set(false);
                return;
            }
        }
        if let Some(pk) = auth.pubkey().get_untracked() {
            set_skipped(&pk);
        }
        is_open.set(false);
    };

    // The "download your keys + identity data" link closes the modal first so
    // the route navigation (to Settings, which hosts the recovery / identity
    // surface) is not obscured by the overlay.
    let on_keys_link = move |_: web_sys::MouseEvent| {
        is_open.set(false);
        if let Some(p) = prefill {
            p.force_open.set(false);
        }
    };

    let can_submit = move || {
        !is_submitting.get()
            && !display_name.get().trim().is_empty()
            && !real_name.get().trim().is_empty()
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
                            "Complete your profile"
                        </h2>
                        <p class="text-gray-400 text-sm mt-2">
                            "Tell us how to show your name. You can change this later in settings."
                        </p>
                    </div>

                    <div class="space-y-4">
                        // Display name (public)
                        <div class="space-y-1">
                            <label for="onboard-display-name" class="block text-sm font-medium text-gray-300">
                                "Display name "
                                <span class="text-gray-500 font-normal">"(public)"</span>
                            </label>
                            <input
                                id="onboard-display-name"
                                type="text"
                                placeholder="e.g. Alice Cooper"
                                autocomplete="name"
                                spellcheck="false"
                                on:input=move |ev| display_name.set(event_target_value(&ev))
                                prop:value=move || display_name.get()
                                maxlength="50"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 rounded-xl px-3 py-3 text-sm text-white placeholder-gray-500 focus:outline-none"
                            />
                            <p class="text-xs text-gray-500">
                                "Shown next to your posts and mentions."
                            </p>
                        </div>

                        // Real name (private)
                        <div class="space-y-1">
                            <label for="onboard-real-name" class="block text-sm font-medium text-gray-300">
                                "Real name "
                                <span class="text-gray-500 font-normal">"(private)"</span>
                            </label>
                            <input
                                id="onboard-real-name"
                                type="text"
                                placeholder="Your full name"
                                autocomplete="off"
                                spellcheck="false"
                                on:input=move |ev| real_name.set(event_target_value(&ev))
                                prop:value=move || real_name.get()
                                maxlength="100"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 rounded-xl px-3 py-3 text-sm text-white placeholder-gray-500 focus:outline-none"
                            />
                            <p class="text-xs text-gray-500">
                                "Visible to administrators only \u{2014} never published publicly."
                            </p>
                        </div>

                        // Keys / identity data link (existing recovery surface)
                        <div class="bg-gray-800/40 rounded-lg px-3 py-2.5 text-xs text-gray-400 border border-gray-700/40">
                            "Need your backup again? You can download your recovery sheet anytime from "
                            <A
                                href=base_href("/settings")
                                on:click=on_keys_link
                                attr:class="text-amber-300 hover:text-amber-200 underline underline-offset-2"
                            >
                                "Settings"
                            </A>
                            "."
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
                            "I\u{2019}ll do this later"
                        </button>
                        <button
                            on:click=on_submit
                            disabled=move || !can_submit()
                            class="flex-1 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 disabled:from-gray-600 disabled:to-gray-700 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 rounded-xl transition-all duration-200 shadow-lg shadow-amber-500/25 text-sm"
                        >
                            {move || if is_submitting.get() { "Saving\u{2026}" } else { "Save profile" }}
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}

/// Public helper used by the Settings "Release username" button.
///
/// Dormant relative to the onboarding modal but still called by
/// `pages/settings.rs`. Sends a NIP-98 authed `POST /api/username/release`
/// with no body. On success the local claim flag is cleared and the shared
/// `ClaimedUsername` signal is reset. Errors are surfaced via the `Result`.
pub async fn release_username() -> Result<(), String> {
    let auth = use_auth();
    let pubkey = auth
        .pubkey()
        .get_untracked()
        .ok_or_else(|| "Not authenticated".to_string())?;
    // Route through the Signer trait so NIP-07 / hardware-bunker backends can
    // release. PRF-derived keys still work transparently.
    let signer = auth
        .get_signer()
        .ok_or_else(|| "No signer available — please sign in again.".to_string())?;

    let url = format!("{}/api/username/release", auth_api_base());
    let body = "{}".to_string();
    // Capture the claimed-username signal before the await so the context
    // lookup happens while the reactive owner is still current.
    let claimed_sig = use_claimed_username();
    let result = fetch_with_nip98_post_signer(&url, &body, signer.as_ref()).await;
    match result {
        Ok(_) => {
            clear_claimed_locally(&pubkey);
            // Clear the claimed handle only — the kind-0 display name
            // (nickname/avatar) is a separate concern and stays intact.
            if let Some(claimed) = claimed_sig {
                claimed.0.set(None);
            }
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

    #[test]
    fn nip05_for_uses_host() {
        // Dormant helper still produces a host-qualified handle.
        assert_eq!(nip05_for("alice"), format!("alice@{}", NIP05_HOST));
    }

    #[test]
    fn username_from_nip05_roundtrip() {
        let n = nip05_for("bob");
        assert_eq!(username_from_nip05(&n), Some("bob".to_string()));
        assert_eq!(username_from_nip05("carol@other.example"), None);
    }
}
