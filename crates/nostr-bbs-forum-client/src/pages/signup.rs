//! Signup wizard — 3 phases:
//!
//! 1. **Identity**: display name (the public screen name, required) + an
//!    OPTIONAL, admin-only real name (stored server-side in D1 via
//!    `POST /api/profile/real-name`, never published). No NIP-05 handle is
//!    claimed here — the federated `@host` handle is an advanced opt-in that
//!    users can claim later from Settings, so onboarding stays to the two
//!    fields a newcomer actually needs.
//! 2. **Profile**: the freshly-minted identity bundle — npub short, Solid
//!    WebID URL, git-pod clone command (per ADR-089) — surfaced for the
//!    backup sheet. The keypair is generated on-device and the pod is
//!    provisioned eagerly (`POST {POD_API}/.provision`).
//! 3. **Backup**: present nsec for offline backup + a printable recovery
//!    sheet. Required before exit (ADR-095).
//!
//! Uses the JSS-derived primitives shipped in solid-pod-rs 0.5: provision-keys
//! (pod is provisioned on first authed request), JSON-LD WebID export
//! (`<pod_url>/profile/card`), and git-auto-init (`git clone <pod_url>`).

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

/// Signup wizard phases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Identity,
    Profile,
    Backup,
}

/// Slugify a display name into a candidate NIP-05 handle, with a short pubkey
/// suffix so it is unique WITHOUT an availability round-trip and always valid
/// (`^[a-z0-9][a-z0-9_-]{2,29}$`). The user never types this — it is derived so
/// every new account still gets a federated handle AND, crucially, an admin
/// registration record: the auth-worker keys the admin registrations / auth
/// queue and the admin-only real name off the `username_reservations` row that
/// the claim creates. (A real-name-only POST cannot create that row — the table
/// requires a username PK — which is why a username-less signup left new joiners
/// invisible to the admin queue and silently dropped their real name.)
fn derive_username(display: &str, pubkey: &str) -> String {
    let mut slug: String = display
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    // First char must be [a-z0-9]; trim any leading separators.
    while slug
        .chars()
        .next()
        .map(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
        .unwrap_or(false)
    {
        slug.remove(0);
    }
    if slug.is_empty() {
        slug = "user".to_string();
    }
    slug.truncate(22);
    let suffix: String = pubkey.chars().take(6).collect();
    let suffix = if suffix.len() == 6 {
        suffix
    } else {
        "000000".to_string()
    };
    format!("{slug}-{suffix}")
}

/// Claim the (auto-derived) NIP-05 handle for the caller, attaching the OPTIONAL
/// admin-only real name. `POST {AUTH_API}/api/username/claim` (NIP-98). The claim
/// creates the `username_reservations` row the admin registrations / auth queue
/// reads AND stores the admin-only real name (which is NEVER published to kind-0
/// / the relay). Best-effort: a failure is non-fatal (logged, signup continues).
async fn claim_username(
    name: &str,
    real_name: Option<&str>,
    auth: crate::auth::AuthStore,
) -> Result<(), String> {
    let url = format!("{}/api/username/claim", AUTH_API);
    let signer = auth.get_signer().ok_or("no signer")?;
    let body = match real_name {
        Some(r) if !r.trim().is_empty() => {
            serde_json::json!({ "username": name, "real_name": r.trim() }).to_string()
        }
        _ => serde_json::json!({ "username": name }).to_string(),
    };
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
    let real_name = RwSignal::new(String::new());
    let phase = RwSignal::new(Phase::Identity);
    let privkey_hex = RwSignal::new(String::new());
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

    // Phase 1 → 2: create identity (generate key, publish kind-0, store the
    // optional admin-only real name, provision the pod).
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
        auth.clear_error();
        is_busy.set(true);

        // The OPTIONAL real name is admin-only — it goes to the auth-worker D1
        // and is NEVER published to kind-0 / the relay.
        let real = real_name.get_untracked().trim().to_string();
        let real_opt = if real.is_empty() { None } else { Some(real) };

        // Generate key + register. This also installs a Signer (see auth/mod.rs).
        match auth.register_with_generated_key(&display) {
            Ok(hex) => {
                privkey_hex.set(hex);
                let auth_for_pod = auth;
                let display_for_handle = display.clone();
                spawn_local(async move {
                    // Auto-derive a federated handle from the display name (no
                    // prompt) and claim it. The claim creates the auth-worker
                    // registration row that the admin auth queue reads AND stores
                    // the optional admin-only real name. Without a claim there is
                    // no registration row, so new joiners were invisible to the
                    // admin and their real name was silently dropped.
                    let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
                    if !pubkey.is_empty() {
                        let handle = derive_username(&display_for_handle, &pubkey);
                        if let Err(e) = claim_username(&handle, real_opt.as_deref(), auth).await {
                            web_sys::console::warn_1(
                                &format!("[signup] handle claim deferred: {e}").into(),
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
                                <p class="text-xs text-gray-500 -mt-1">
                                    "Your public screen name — this is what everyone sees, and it can be anonymous."
                                </p>
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
                                    "Optional. Visible only to administrators and used to provision your access — it is never published, never shown publicly, and never written to the relay. Your display name above is what everyone sees."
                                </p>
                            </div>

                            <button
                                data-testid="signup-submit"
                                on:click=move |_: web_sys::MouseEvent| do_create()
                                disabled=move || is_busy.get()
                                class="w-full bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2"
                            >
                                {move || if is_busy.get() { "Creating…" } else { "Create Account" }}
                            </button>
                            <p class="text-xs text-gray-500 text-center">
                                "You can claim a federated @-handle later from Settings."
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
                                nip05=None
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
