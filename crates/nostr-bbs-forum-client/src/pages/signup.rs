//! Signup wizard — 3 phases:
//!
//! 1. **Identity**: display name + REQUIRED NIP-05 username/handle (validates
//!    availability against the auth-worker as the user types) + an OPTIONAL,
//!    admin-only real name (stored server-side in D1, never published).
//! 2. **Profile**: generate keypair, register as local-key user, publish
//!    kind-0 metadata, optionally claim the username via auth-worker
//!    (`POST /api/username/claim` with NIP-98 auth). Surface the resulting
//!    identity bundle — npub short, NIP-05 handle, WebID URL, git-pod
//!    clone command (per ADR-089).
//! 3. **Backup**: present nsec for offline backup. Required before exit.
//!
//! Uses the JSS-derived primitives shipped in solid-pod-rs 0.4.0-alpha.12:
//! provision-keys (pod is provisioned on first authed request), federated
//! NIP-05 endpoint (`<auth_api>/.well-known/nostr.json`), JSON-LD WebID
//! export (`<pod_url>/profile/card`), and git-auto-init (`git clone
//! <pod_url>`).

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_query_map};
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use solid_pod_rs::webid::{pod_git_clone_url, webid_url};

use crate::app::{base_href, current_app_path};
use crate::auth::use_auth;
use crate::components::nsec_backup::NsecBackup;
use crate::components::recovery_sheet::RecoverySheet;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::utils::relay_url::relay_url;
use crate::utils::shorten_pubkey;

const POD_API: &str = match option_env!("VITE_POD_API_URL") {
    Some(u) => u,
    None => "https://pod.example.com",
};
const AUTH_API: &str = match option_env!("VITE_AUTH_API_URL") {
    Some(u) => u,
    None => "https://auth.example.com",
};

/// Write `text` to the system clipboard and pop a success toast labelled
/// "{what} copied". Helper inlined here (instead of a per-handler closure
/// factory) to keep all on:click handlers `FnMut` for Leptos.
fn clipboard_copy(text: &str, what: &str, toasts: crate::components::toast::ToastStore) {
    if let Some(window) = web_sys::window() {
        let nav = window.navigator().clipboard();
        let _ = nav.write_text(text);
    }
    toasts.show(format!("{what} copied"), ToastVariant::Success);
}
/// NIP-05 host that backs claimed usernames (mirrors onboarding_modal::NIP05_HOST).
/// Baked from `NOSTR_BBS_NIP05_DOMAIN` at build time; placeholder only for
/// un-configured local builds.
const NIP05_USERNAME_HOST: &str = match option_env!("NOSTR_BBS_NIP05_DOMAIN") {
    Some(d) => d,
    None => "example.test",
};

/// Signup wizard phases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Identity,
    Profile,
    Backup,
}

/// Real-time username availability state.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NameState {
    Idle,
    InvalidFormat,
    Checking,
    Available,
    Taken,
    NetworkError,
}

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

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn check_username(name: &str) -> Result<bool, String> {
    let url = format!("{}/api/username/check?name={}", AUTH_API, urlencode(name));
    let win = web_sys::window().ok_or("no window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "bad response".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let txt_promise = resp.text().map_err(|e| format!("{e:?}"))?;
    let txt = JsFuture::from(txt_promise)
        .await
        .map_err(|e| format!("{e:?}"))?
        .as_string()
        .ok_or("non-string body")?;
    let v: serde_json::Value = serde_json::from_str(&txt).map_err(|e| format!("{e}"))?;
    Ok(v.get("available")
        .and_then(|x| x.as_bool())
        .unwrap_or(false))
}

async fn claim_username(
    name: &str,
    real_name: Option<&str>,
    auth: crate::auth::AuthStore,
) -> Result<(), String> {
    let url = format!("{}/api/username/claim", AUTH_API);
    let signer = auth.get_signer().ok_or("no signer")?;
    // The handle is published; the OPTIONAL real_name is admin-only and the
    // worker stores it in D1 — it is NEVER written to kind-0 / the relay.
    let body = match real_name {
        Some(r) if !r.trim().is_empty() => {
            serde_json::json!({ "username": name, "real_name": r.trim() }).to_string()
        }
        _ => serde_json::json!({ "username": name }).to_string(),
    };
    // Hash the body for the NIP-98 payload tag.
    let token = crate::auth::nip98::create_nip98_token_with_signer(
        &*signer,
        &url,
        "POST",
        Some(body.as_bytes()),
    )
    .await
    .map_err(|e| format!("nip98: {e}"))?;

    let win = web_sys::window().ok_or("no window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    init.set_body(&body.into());
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "bad response".to_string())?;
    if !resp.ok() {
        return Err(format!("claim failed: HTTP {}", resp.status()));
    }
    Ok(())
}

/// Eagerly provision the caller's Solid pod at signup (`POST {POD_API}/.provision`,
/// NIP-98 authed — the pod owner is the authed pubkey). Previously the pod was
/// only created lazily on first pod access; provisioning here means every new
/// account gets its WebID/TypeIndex/inbox/media containers immediately. 201 =
/// created, 409 = already exists; both are success. Fire-and-forget — a failure
/// is non-fatal because the lazy first-access path still provisions later.
async fn provision_pod(auth: crate::auth::AuthStore) -> Result<(), String> {
    let url = format!("{}/.provision", POD_API);
    let signer = auth.get_signer().ok_or("no signer")?;
    let token = crate::auth::nip98::create_nip98_token_with_signer(&*signer, &url, "POST", None)
        .await
        .map_err(|e| format!("nip98: {e}"))?;
    let win = web_sys::window().ok_or("no window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "bad response".to_string())?;
    match resp.status() {
        201 | 409 => Ok(()),
        s => Err(format!("HTTP {s}")),
    }
}

#[component]
pub fn SignupPage() -> impl IntoView {
    let auth = use_auth();
    let pubkey = auth.pubkey();
    let is_authed = auth.is_authenticated();
    let error = auth.error();
    let navigate = StoredValue::new(use_navigate());
    let toasts = use_toasts();

    let display_name = RwSignal::new(String::new());
    let username = RwSignal::new(String::new());
    let real_name = RwSignal::new(String::new());
    let username_state = RwSignal::new(NameState::Idle);
    let phase = RwSignal::new(Phase::Identity);
    let privkey_hex = RwSignal::new(String::new());
    let claimed_username = RwSignal::new(Option::<String>::None);
    let is_busy = RwSignal::new(false);
    // ADR-095 gate: the finish/exit control in the Backup phase stays disabled
    // until the recovery sheet has been printed AND confirmed (`sheet_ready`),
    // unless the user takes the explicit advanced override.
    let sheet_ready = RwSignal::new(false);
    let advanced_override = RwSignal::new(false);

    // returnTo: same base-relative normalisation as login.rs (ADR-090).
    let query = use_query_map();
    let return_to = move || {
        let raw = query.read().get("returnTo").unwrap_or_default();
        if raw.is_empty() || !raw.starts_with('/') {
            return "/forums".to_string();
        }
        let normalised = current_app_path(&raw);
        if normalised == "/" || normalised == "/login" || normalised == "/signup" {
            "/forums".to_string()
        } else {
            normalised
        }
    };

    // Debounced username availability check.
    let check_seq = RwSignal::new(0u32);
    let debounce_handle = RwSignal::new(Option::<i32>::None);
    Effect::new(move |_| {
        let value = username.get();
        if let Some(h) = debounce_handle.get_untracked() {
            if let Some(w) = web_sys::window() {
                w.clear_timeout_with_handle(h);
            }
            debounce_handle.set(None);
        }
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            username_state.set(NameState::Idle);
            return;
        }
        if !is_valid_format(&trimmed) {
            username_state.set(NameState::InvalidFormat);
            return;
        }
        username_state.set(NameState::Checking);
        let seq_now = check_seq.get_untracked().wrapping_add(1);
        check_seq.set(seq_now);
        let cb = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
            let v = username.get_untracked().trim().to_string();
            if v.is_empty() || !is_valid_format(&v) {
                return;
            }
            spawn_local(async move {
                match check_username(&v).await {
                    Ok(true) => {
                        if check_seq.get_untracked() == seq_now {
                            username_state.set(NameState::Available);
                        }
                    }
                    Ok(false) => {
                        if check_seq.get_untracked() == seq_now {
                            username_state.set(NameState::Taken);
                        }
                    }
                    Err(_) => {
                        if check_seq.get_untracked() == seq_now {
                            username_state.set(NameState::NetworkError);
                        }
                    }
                }
            });
        }) as Box<dyn FnMut()>);
        if let Some(w) = web_sys::window() {
            if let Ok(h) = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                350,
            ) {
                debounce_handle.set(Some(h));
            }
        }
        cb.forget();
    });

    // Phase 1 → 2: create identity (generate key, publish kind-0, claim username).
    let do_create = move || {
        let display = display_name.get_untracked().trim().to_string();
        if display.is_empty() || display.len() < 2 {
            auth.set_error("Display name must be at least 2 characters");
            return;
        }
        if display.len() > 50 {
            auth.set_error("Display name must be 50 characters or fewer");
            return;
        }
        // The handle is now REQUIRED — it is the public screen name claimed via
        // the username flow and rendered everywhere. Block progression until a
        // valid, available handle has been entered.
        let want = username.get_untracked().trim().to_string();
        if want.is_empty() {
            auth.set_error("A username (handle) is required — this is your public screen name.");
            return;
        }
        match username_state.get_untracked() {
            NameState::Available => {}
            NameState::Checking => {
                auth.set_error("Still checking username availability — please wait a moment.");
                return;
            }
            NameState::Taken => {
                auth.set_error("That username is already taken — please choose another.");
                return;
            }
            NameState::NetworkError => {
                auth.set_error(
                    "Could not verify the username (network). Please retry before continuing.",
                );
                return;
            }
            _ => {
                auth.set_error("Please choose a valid, available username before continuing.");
                return;
            }
        }
        auth.clear_error();
        is_busy.set(true);

        // The OPTIONAL real name is admin-only — it goes to the auth-worker D1
        // alongside the claim and is NEVER published to kind-0 / the relay.
        let real = real_name.get_untracked().trim().to_string();
        let real_opt = if real.is_empty() { None } else { Some(real) };

        // Generate key + register. This also installs a Signer (see auth/mod.rs).
        match auth.register_with_generated_key(&display) {
            Ok(hex) => {
                privkey_hex.set(hex);
                // Claim the (required) handle, attaching the optional real name.
                let auth_for_pod = auth.clone();
                spawn_local(async move {
                    match claim_username(&want, real_opt.as_deref(), auth).await {
                        Ok(()) => {
                            claimed_username.set(Some(want));
                            toasts.show("Username claimed", ToastVariant::Success);
                        }
                        Err(e) => {
                            toasts.show(
                                format!("Username claim failed (continuing): {e}"),
                                ToastVariant::Warning,
                            );
                        }
                    }
                    // Eagerly provision the Solid pod (non-blocking; lazy path
                    // still covers any failure on first pod access).
                    match provision_pod(auth_for_pod).await {
                        Ok(()) => web_sys::console::log_1(&"[signup] pod provisioned".into()),
                        Err(e) => web_sys::console::warn_1(
                            &format!("[signup] pod provision deferred: {e}").into(),
                        ),
                    }
                    is_busy.set(false);
                    phase.set(Phase::Profile);
                });
            }
            Err(e) => {
                auth.set_error(&e);
                is_busy.set(false);
            }
        }
    };

    // The real exit: confirm backup + navigate away. Performs no gating itself
    // so it can be reused by both the gated finish button and the override.
    let finish_signup = Callback::new(move |()| {
        auth.confirm_nsec_backup();
        let dest = return_to();
        navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
    });

    // Gated dismiss handed to NsecBackup. Clicking "I've saved my backup" only
    // exits once the recovery sheet gate is satisfied (or the advanced override
    // is taken); otherwise we steer the user to the sheet (insist-with-override).
    let on_backup_done = Callback::new(move |()| {
        if sheet_ready.get_untracked() || advanced_override.get_untracked() {
            finish_signup.run(());
        } else {
            toasts.show(
                "Print & confirm your recovery sheet first (or use the advanced override).",
                ToastVariant::Warning,
            );
        }
    });

    // Redirect if already authenticated AND not in the middle of the new
    // wizard. Crucially we hold the user inside Phases 2 and 3 (profile +
    // backup) — they only flow to `/forums` via the explicit on_backup_done
    // callback. Pre-existing returning users (no signup in flight, is_busy
    // never set) still get the redirect.
    Effect::new(move |_| {
        if is_authed.get() && phase.get() == Phase::Identity && !is_busy.get() {
            let dest = return_to();
            navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
        }
    });

    // Derived identity bundle (Phase 2 reveal).
    // NOTE: this is the user being shown THEIR OWN freshly-minted pubkey during
    // signup. There is no kind-0 profile to resolve against yet, and a name would
    // be meaningless — the shortened hex *is* the correct, canonical thing to
    // display. The full key is exposed via the copy affordance below (the reveal
    // card renders a copy button next to this value), so we intentionally do NOT
    // route this through use_display_name_memo.
    let pubkey_short = Memo::new(move |_| {
        pubkey
            .get()
            .map(|pk| shorten_pubkey(&pk))
            .unwrap_or_default()
    });
    // Per-user pod / WebID / git-clone URLs are built upstream
    // (solid-pod-rs::webid). The forum-client inherits these helpers via
    // the `solid-pod-rs` workspace dep so we never hand-roll
    // `format!("{base}/pods/{pk}/…")` in the UI.
    let webid = Memo::new(move |_| {
        pubkey
            .get()
            .map(|pk| webid_url(POD_API, &pk))
            .unwrap_or_default()
    });
    let git_clone = Memo::new(move |_| {
        pubkey
            .get()
            .map(|pk| format!("git clone {}", pod_git_clone_url(POD_API, &pk)))
            .unwrap_or_default()
    });
    let nip05_handle = Memo::new(move |_| {
        claimed_username
            .get()
            .map(|u| format!("{u}@{NIP05_USERNAME_HOST}"))
    });

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4 py-8">
            <div class="w-full max-w-xl">
                <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-8 space-y-6">

                    // Step indicator
                    <div class="flex items-center justify-center gap-2 text-xs" data-testid="signup-stepper">
                        {[("Identity", Phase::Identity), ("Profile", Phase::Profile), ("Backup", Phase::Backup)]
                            .iter().enumerate().map(|(i, &(label, p))| {
                                view! {
                                    <span class=move || {
                                        let active = phase.get() == p;
                                        let done = (phase.get() as u8) > (p as u8);
                                        if active { "text-amber-400 font-semibold".to_string() }
                                        else if done { "text-green-400".to_string() }
                                        else { "text-gray-500".to_string() }
                                    }>
                                        {if i > 0 { Some(view! { <span class="text-gray-600 mx-1">"→"</span> }) } else { None }}
                                        {format!("{}. {}", i + 1, label)}
                                    </span>
                                }
                            }).collect_view()}
                    </div>

                    // ── Phase 1: Identity ─────────────────────────────
                    <Show when=move || phase.get() == Phase::Identity>
                        <div class="text-center">
                            <h1 class="text-3xl font-bold text-white" data-testid="signup-h1">"Create Account"</h1>
                            <p class="mt-2 text-gray-400 text-sm">
                                "We generate a Nostr keypair on-device and provision your pod at first sign-in. Your private key never leaves the browser."
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
                                    data-testid="signup-display-name"
                                    type="text"
                                    placeholder="Your display name"
                                    on:input=move |ev| display_name.set(event_target_value(&ev))
                                    prop:value=move || display_name.get()
                                    maxlength="50"
                                    class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                                />
                            </div>

                            <div class="space-y-2">
                                <label for="username" class="block text-sm font-medium text-gray-300">
                                    "Username "
                                    <span class="text-xs text-amber-400">"(required)"</span>
                                </label>
                                <p class="text-xs text-gray-500 -mt-1">
                                    "This is your public handle — your screen name and federated NIP-05. It is what everyone sees, and it can be anonymous."
                                </p>
                                <div class="flex items-stretch">
                                    <span class="bg-gray-900 border border-gray-600 border-r-0 rounded-l-xl px-3 py-3 text-gray-500 text-sm flex items-center">"@"</span>
                                    <input
                                        id="username"
                                        data-testid="signup-username"
                                        type="text"
                                        placeholder="e.g. ada"
                                        on:input=move |ev| username.set(event_target_value(&ev).to_lowercase())
                                        prop:value=move || username.get()
                                        maxlength="30"
                                        class="flex-1 bg-gray-800 border border-gray-600 focus:border-amber-500 px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                                    />
                                    <span class="bg-gray-900 border border-gray-600 border-l-0 rounded-r-xl px-3 py-3 text-gray-500 text-sm flex items-center">
                                        {format!("@{}", NIP05_USERNAME_HOST)}
                                    </span>
                                </div>
                                <p class="text-xs h-4" data-testid="signup-username-state">
                                    {move || match username_state.get() {
                                        NameState::Idle => view! { <span class="text-gray-500">"3–30 chars: a-z, 0-9, _ or -"</span> }.into_any(),
                                        NameState::InvalidFormat => view! { <span class="text-red-400">"Invalid format — lowercase letters/digits/_/- only, start with letter or digit"</span> }.into_any(),
                                        NameState::Checking => view! { <span class="text-gray-400">"Checking availability…"</span> }.into_any(),
                                        NameState::Available => view! { <span class="text-green-400">"✓ Available"</span> }.into_any(),
                                        NameState::Taken => view! { <span class="text-amber-400">"✕ Already taken"</span> }.into_any(),
                                        NameState::NetworkError => view! { <span class="text-amber-400">"Could not check (network) — you can claim later from Settings"</span> }.into_any(),
                                    }}
                                </p>
                            </div>

                            <div class="space-y-2">
                                <label for="real-name" class="block text-sm font-medium text-gray-300">
                                    "Real name "
                                    <span class="text-xs text-gray-500">"(optional)"</span>
                                </label>
                                <input
                                    id="real-name"
                                    data-testid="signup-real-name"
                                    type="text"
                                    placeholder="e.g. Ada Lovelace"
                                    on:input=move |ev| real_name.set(event_target_value(&ev))
                                    prop:value=move || real_name.get()
                                    maxlength="200"
                                    class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                                />
                                <p class="text-xs text-gray-500">
                                    "Optional. Visible only to administrators and used to provision your access — it is never published, never shown publicly, and never written to the relay. Your handle above is what everyone sees."
                                </p>
                            </div>

                            <button
                                data-testid="signup-submit"
                                on:click=move |_: web_sys::MouseEvent| do_create()
                                disabled=move || {
                                    is_busy.get()
                                        || username_state.get() == NameState::Checking
                                        || username_state.get() != NameState::Available
                                }
                                class="w-full bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2"
                            >
                                {move || if is_busy.get() { "Creating…" } else { "Create Account" }}
                            </button>
                            <p class="text-xs text-gray-500 text-center">
                                "Powered by solid-pod-rs ≥ 0.4.0-alpha.12 (provision-keys + NIP-05 + git-init)."
                            </p>
                        </div>
                    </Show>

                    // ── Phase 2: Profile reveal ───────────────────────
                    <Show when=move || phase.get() == Phase::Profile>
                        <div class="text-center">
                            <h1 class="text-3xl font-bold text-white">"Your identity"</h1>
                            <p class="mt-2 text-gray-400 text-sm">"Keep these handy — back up your private key in the next step."</p>
                        </div>

                        <div class="space-y-3" data-testid="signup-identity-bundle">
                            // npub short
                            <div class="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="flex-1 min-w-0">
                                        <p class="text-xs uppercase tracking-wide text-gray-500">"Public key"</p>
                                        <p class="text-sm text-amber-300 font-mono truncate" data-testid="signup-pubkey">
                                            {move || pubkey_short.get()}
                                        </p>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            let pk = pubkey.get_untracked().unwrap_or_default();
                                            clipboard_copy(&pk, "Pubkey", toasts);
                                        }
                                        class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-100 px-3 py-1.5 rounded-md transition-colors"
                                    >
                                        "Copy"
                                    </button>
                                </div>
                            </div>

                            // NIP-05 (only if claimed)
                            {move || nip05_handle.get().map(|h| view! {
                                <div class="bg-gray-900/80 border border-green-500/30 rounded-lg p-3">
                                    <div class="flex items-center justify-between gap-2">
                                        <div class="flex-1 min-w-0">
                                            <p class="text-xs uppercase tracking-wide text-green-500">"NIP-05 handle"</p>
                                            <p class="text-sm text-green-300 font-mono truncate" data-testid="signup-nip05">{h.clone()}</p>
                                        </div>
                                        <button
                                            on:click={
                                                let h = h.clone();
                                                move |_| clipboard_copy(&h, "NIP-05", toasts)
                                            }
                                            class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-100 px-3 py-1.5 rounded-md transition-colors"
                                        >
                                            "Copy"
                                        </button>
                                    </div>
                                </div>
                            })}

                            // WebID
                            <div class="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="flex-1 min-w-0">
                                        <p class="text-xs uppercase tracking-wide text-gray-500">"Solid WebID"</p>
                                        <p class="text-xs text-amber-300 font-mono truncate" data-testid="signup-webid">
                                            {move || webid.get()}
                                        </p>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            let url = webid.get_untracked();
                                            if let Some(window) = web_sys::window() {
                                                let nav = window.navigator().clipboard();
                                                let _ = nav.write_text(&url);
                                                toasts.show("WebID copied", ToastVariant::Success);
                                            }
                                        }
                                        class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-100 px-3 py-1.5 rounded-md transition-colors"
                                    >
                                        "Copy"
                                    </button>
                                </div>
                            </div>

                            // Git clone
                            <div class="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="flex-1 min-w-0">
                                        <p class="text-xs uppercase tracking-wide text-gray-500">"Git clone"</p>
                                        <p class="text-xs text-amber-300 font-mono truncate" data-testid="signup-git-clone">
                                            {move || git_clone.get()}
                                        </p>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            let cmd = git_clone.get_untracked();
                                            if let Some(window) = web_sys::window() {
                                                let nav = window.navigator().clipboard();
                                                let _ = nav.write_text(&cmd);
                                                toasts.show("Clone command copied", ToastVariant::Success);
                                            }
                                        }
                                        class="text-xs bg-gray-700 hover:bg-gray-600 text-gray-100 px-3 py-1.5 rounded-md transition-colors"
                                    >
                                        "Copy"
                                    </button>
                                </div>
                                <p class="text-xs text-gray-500 mt-2">
                                    "Available on deployments with git-init enabled (ADR-089)."
                                </p>
                            </div>
                        </div>

                        <button
                            data-testid="signup-continue-backup"
                            on:click=move |_: web_sys::MouseEvent| phase.set(Phase::Backup)
                            class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors"
                        >
                            "Continue → Back up key"
                        </button>
                    </Show>

                    // ── Phase 3: nsec backup + recovery sheet (ADR-095) ──
                    <Show when=move || phase.get() == Phase::Backup>
                        <div class="space-y-6">
                            // Plain nsec card (unchanged component, same nsec source).
                            <NsecBackup nsec=privkey_hex.get_untracked() on_dismiss=on_backup_done />

                            // Printable recovery & device-onboarding sheet.
                            // Client-side only: the nsec never leaves the browser.
                            <RecoverySheet
                                privkey_hex=privkey_hex.get_untracked()
                                pubkey_hex=pubkey.get_untracked().unwrap_or_default()
                                relay_url=relay_url()
                                display_name=display_name.get_untracked()
                                nip05=nip05_handle.get_untracked()
                                on_ready=Callback::new(move |()| sheet_ready.set(true))
                            />

                            // Gated finish control + advanced override.
                            <div class="rs-screen-controls space-y-3">
                                <button
                                    data-testid="signup-finish"
                                    prop:disabled=move || {
                                        !(sheet_ready.get() || advanced_override.get())
                                    }
                                    on:click=move |_: web_sys::MouseEvent| finish_signup.run(())
                                    class="w-full bg-amber-500 hover:bg-amber-400 disabled:opacity-40 \
                                           disabled:cursor-not-allowed text-gray-900 font-semibold \
                                           py-3 px-4 rounded-xl transition-colors"
                                >
                                    "Finish — enter the forum"
                                </button>
                                <Show
                                    when=move || !(sheet_ready.get() || advanced_override.get())
                                >
                                    <button
                                        data-testid="signup-advanced-override"
                                        on:click=move |_: web_sys::MouseEvent| {
                                            advanced_override.set(true);
                                        }
                                        class="block w-full text-center text-xs text-gray-500 \
                                               hover:text-gray-300 underline"
                                    >
                                        "I've stored my key elsewhere (advanced)"
                                    </button>
                                </Show>
                            </div>
                        </div>
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
