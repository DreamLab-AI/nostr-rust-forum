//! Landing page with animated constellation hero + login/signup CTAs.
//!
//! When no admin exists (first deploy), shows a prominent "Set Up Admin Account"
//! flow with passkey registration. Once an admin exists, shows the normal
//! login/signup CTAs.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::fx::webgpu_hero::WebGPUHero;

/// Fetch setup status from the relay API.
/// Returns `true` if no admin exists and initial setup is needed.
async fn fetch_needs_setup() -> Result<bool, String> {
    let relay_base = relay_api_base();
    let url = format!("{}/api/setup-status", relay_base);
    let win = web_sys::window().ok_or("No window")?;
    let resp_val = JsFuture::from(win.fetch_with_str(&url))
        .await
        .map_err(|e| format!("fetch error: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let text_str = text.as_string().ok_or("Not a string")?;
    let val: serde_json::Value =
        serde_json::from_str(&text_str).map_err(|e| format!("JSON parse: {e}"))?;
    Ok(val
        .get("needsSetup")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Resolve the relay HTTP base URL.
fn relay_api_base() -> String {
    crate::utils::relay_url::relay_api_base()
}

#[component]
pub fn HomePage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();

    // Setup status: None = loading, Some(true) = needs setup, Some(false) = normal
    let needs_setup: RwSignal<Option<bool>> = RwSignal::new(None);

    // Lifted from AdminSetupCta so they survive reactive re-renders.
    // The match closure re-creates child views when signals change, so any
    // local state inside the child component would be lost.
    let setup_phase = RwSignal::new(SetupPhase::Cta);
    let privkey_hex = RwSignal::new(String::new());

    // Derived: are we in the backup phase?
    let in_backup = Memo::new(move |_| setup_phase.get() == SetupPhase::Backup);

    // Fetch setup status on mount
    wasm_bindgen_futures::spawn_local(async move {
        match fetch_needs_setup().await {
            Ok(val) => needs_setup.set(Some(val)),
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[home] Failed to check setup status: {e}").into(),
                );
                // Default to normal mode if we can't reach the API
                needs_setup.set(Some(false));
            }
        }
    });

    view! {
        <div class="min-h-[80vh] flex flex-col items-center justify-center px-4 relative overflow-hidden">
            // Ambient CSS orbs
            <div class="ambient-orb ambient-orb-1" aria-hidden="true"></div>
            <div class="ambient-orb ambient-orb-2" aria-hidden="true"></div>
            <div class="ambient-orb ambient-orb-3" aria-hidden="true"></div>

            // Tiered hero background
            <WebGPUHero />

            // Content layer
            <div class="max-w-2xl text-center space-y-8 relative z-10">
                // Hero section with glow
                <div class="relative flex flex-col items-center">
                    <div class="absolute -z-10 w-96 h-96 rounded-full bg-amber-500/10 blur-3xl animate-ambient-breathe"></div>

                    <p class="text-amber-400/60 uppercase tracking-widest text-xs font-medium mb-4">
                        ""
                    </p>

                    <h1 class="text-5xl sm:text-6xl font-bold bg-gradient-to-r from-amber-400 to-orange-500 bg-clip-text text-transparent drop-shadow-lg">
                        "MiniMooNoir Forums"
                    </h1>
                </div>

                <div class="space-y-2">
                    <p class="text-xl text-gray-300 leading-relaxed">
                        "Private, secure, multi cohort BBS done the right way"
                    </p>
                    <p class="text-lg text-gray-400 leading-relaxed">
                        "Secure, end to end encrypted with private file stores and distributed identity."
                    </p>
                </div>

                // CTAs — uses <Show> blocks to avoid re-instantiating AdminSetupCta
                // when unrelated signals (is_authed) change.
                <div class="flex flex-col sm:flex-row gap-4 justify-center pt-4">
                    // Loading spinner
                    <Show when=move || needs_setup.get().is_none()>
                        <div class="flex items-center justify-center gap-2 text-gray-500">
                            <span class="animate-spin inline-block w-4 h-4 border-2 border-gray-500 border-t-transparent rounded-full"></span>
                            <span class="text-sm">"Checking status..."</span>
                        </div>
                    </Show>

                    // Admin setup CTA — shown when needs_setup=true AND (not authed OR backup in progress)
                    <Show when=move || needs_setup.get() == Some(true) && (!is_authed.get() || in_backup.get())>
                        <AdminSetupCta setup_phase=setup_phase privkey_hex=privkey_hex needs_setup=needs_setup />
                    </Show>

                    // Normal login/signup — shown when loaded, not authed, and not in setup flow
                    <Show when=move || needs_setup.get().is_some() && !is_authed.get() && needs_setup.get() != Some(true)>
                        <A
                            href=base_href("/signup")
                            attr:class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-8 py-3 rounded-xl text-lg transition-all duration-300 hover:shadow-lg hover:shadow-amber-500/20"
                        >
                            "Create Account"
                        </A>
                        <A
                            href=base_href("/login")
                            attr:class="border border-gray-600 hover:border-amber-500/50 text-gray-200 hover:text-white px-8 py-3 rounded-xl text-lg transition-all duration-300 hover:shadow-lg hover:shadow-amber-500/10"
                        >
                            "Sign In"
                        </A>
                    </Show>

                    // Setup done, authed, no backup pending — show normal buttons
                    <Show when=move || is_authed.get() && !in_backup.get() && needs_setup.get() == Some(true)>
                        <A
                            href=base_href("/signup")
                            attr:class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-8 py-3 rounded-xl text-lg transition-all duration-300 hover:shadow-lg hover:shadow-amber-500/20"
                        >
                            "Create Account"
                        </A>
                        <A
                            href=base_href("/login")
                            attr:class="border border-gray-600 hover:border-amber-500/50 text-gray-200 hover:text-white px-8 py-3 rounded-xl text-lg transition-all duration-300 hover:shadow-lg hover:shadow-amber-500/10"
                        >
                            "Sign In"
                        </A>
                    </Show>

                    // Logged in, normal mode
                    <Show when=move || is_authed.get() && needs_setup.get() == Some(false)>
                        <A
                            href=base_href("/chat")
                            attr:class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-8 py-3 rounded-xl text-lg transition-all duration-300 hover:shadow-lg hover:shadow-amber-500/20"
                        >
                            "Enter Chat"
                        </A>
                    </Show>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-3 gap-6 pt-12 text-left">
                    <FeatureCard
                        icon="\u{1F511}"
                        title="Nostr Identity"
                        description="Instant keypair generation. Sign in with your private key, extension, or passkey."
                    />
                    <FeatureCard
                        icon="\u{1F6E1}"
                        title="End-to-End Encrypted"
                        description="Direct messages use NIP-44 encryption. Only you and the recipient can read them."
                    />
                    <FeatureCard
                        icon="\u{1F5DD}"
                        title="Self-Sovereign"
                        description="Your identity allows you to generate AI agents."
                    />
                </div>

                // Tech badges
                <div class="flex flex-wrap items-center justify-center gap-3 pt-6">
                    <TechBadge label="Nostr Protocol" />
                    <TechBadge label="NIP-44 Encryption" />
                    <TechBadge label="WebAuthn Passkeys" />
                    <TechBadge label="Rust + WASM" />
                </div>
            </div>
        </div>
    }
}

// -- Admin setup CTA & flow ---------------------------------------------------

/// Prominent CTA shown when no admin exists. Offers three registration methods:
/// passkey (preferred), generated key, or existing key import.
///
/// `setup_phase` and `privkey_hex` are owned by the parent `HomePage` so they
/// survive reactive re-renders of the `<Show>` block that gates this component.
#[component]
fn AdminSetupCta(
    setup_phase: RwSignal<SetupPhase>,
    privkey_hex: RwSignal<String>,
    needs_setup: RwSignal<Option<bool>>,
) -> impl IntoView {
    let auth = use_auth();
    let navigate = StoredValue::new(use_navigate());

    let display_name = RwSignal::new(String::new());
    let is_pending = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);

    // Passkey registration
    let on_passkey = move |_: web_sys::MouseEvent| {
        let name = display_name.get_untracked().trim().to_string();
        if name.len() < 2 {
            error.set(Some("Display name must be at least 2 characters".into()));
            return;
        }
        error.set(None);
        is_pending.set(true);

        let auth = auth;
        wasm_bindgen_futures::spawn_local(async move {
            match auth.register_with_passkey(&name).await {
                Ok(()) => {
                    needs_setup.set(Some(false));
                    navigate.with_value(|nav| nav("/setup", NavigateOptions::default()));
                }
                Err(e) => {
                    error.set(Some(e));
                    is_pending.set(false);
                }
            }
        });
    };

    // Generated key registration — sets phase to Backup BEFORE calling register
    // so the parent <Show> keeps us mounted when is_authenticated flips.
    let on_generate_key = move |_: web_sys::MouseEvent| {
        if is_pending.get_untracked() {
            return;
        }
        let name = display_name.get_untracked().trim().to_string();
        if name.len() < 2 {
            error.set(Some("Display name must be at least 2 characters".into()));
            return;
        }
        error.set(None);
        is_pending.set(true);
        // Set phase BEFORE register — the parent's <Show> reads in_backup (derived
        // from setup_phase) to keep this component alive across auth state change.
        setup_phase.set(SetupPhase::Backup);
        match auth.register_with_generated_key(&name) {
            Ok(hex) => {
                privkey_hex.set(hex);
                is_pending.set(false);
                // Don't set needs_setup here — the <Show> condition uses it,
                // and clearing it would unmount us before the backup screen renders.
                // It's set in on_backup_done after the user saves their key.
            }
            Err(e) => {
                setup_phase.set(SetupPhase::Cta);
                error.set(Some(e));
                is_pending.set(false);
            }
        }
    };

    // After backup, navigate to profile setup
    let on_backup_done = Callback::new(move |()| {
        auth.confirm_nsec_backup();
        setup_phase.set(SetupPhase::Done);
        needs_setup.set(Some(false));
        navigate.with_value(|nav| nav("/setup", NavigateOptions::default()));
    });

    view! {
        <div class="w-full max-w-lg mx-auto">
            // Phase: CTA + registration form
            <Show when=move || setup_phase.get() == SetupPhase::Cta>
                <div class="glass-card p-8 space-y-6 border-amber-500/30">
                    <div class="text-center space-y-2">
                        <div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-amber-500/10 border border-amber-500/20 mb-2">
                            {shield_icon()}
                        </div>
                        <h2 class="text-2xl font-bold text-white">"Initial Setup"</h2>
                        <p class="text-gray-400 text-sm">
                            "No admin account exists yet. Create the first account to become the admin."
                        </p>
                    </div>

                    // Error display
                    <Show when=move || error.get().is_some()>
                        <div class="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
                            {move || error.get().unwrap_or_default()}
                        </div>
                    </Show>

                    // Display name input
                    <div class="space-y-2">
                        <label for="admin-name" class="block text-sm font-medium text-gray-300">
                            "Display Name"
                        </label>
                        <input
                            id="admin-name"
                            type="text"
                            placeholder="Your display name"
                            on:input=move |ev| display_name.set(event_target_value(&ev))
                            prop:value=move || display_name.get()
                            maxlength="50"
                            class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500"
                        />
                    </div>

                    // Registration methods
                    <div class="space-y-3">
                        // Passkey (recommended)
                        <button
                            on:click=on_passkey
                            disabled=move || is_pending.get()
                            class="w-full bg-amber-500 hover:bg-amber-400 disabled:bg-amber-700 disabled:cursor-not-allowed text-gray-900 font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2"
                        >
                            <Show
                                when=move || is_pending.get()
                                fallback=|| view! {
                                    {passkey_icon()}
                                    <span>"Create with Passkey"</span>
                                    <span class="text-xs text-gray-700 font-normal ml-1">"(Recommended)"</span>
                                }
                            >
                                <span class="animate-spin inline-block w-5 h-5 border-2 border-gray-900 border-t-transparent rounded-full"></span>
                                <span>"Creating passkey..."</span>
                            </Show>
                        </button>

                        <div class="flex items-center gap-3 text-xs text-gray-600">
                            <div class="flex-1 h-px bg-gray-700"></div>
                            <span>"or"</span>
                            <div class="flex-1 h-px bg-gray-700"></div>
                        </div>

                        // Generate key
                        <button
                            on:click=on_generate_key
                            disabled=move || is_pending.get()
                            class="w-full border border-gray-600 hover:border-amber-500/50 disabled:border-gray-700 disabled:cursor-not-allowed text-gray-200 hover:text-white disabled:text-gray-500 py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm"
                        >
                            {key_icon()}
                            <span>"Generate Key Pair"</span>
                        </button>

                        // Login with existing key
                        <A
                            href=base_href("/login")
                            attr:class="w-full border border-gray-700 hover:border-gray-600 text-gray-400 hover:text-gray-300 py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm"
                        >
                            "Sign in with existing key"
                        </A>
                    </div>

                    <div class="text-xs text-gray-600 text-center space-y-1">
                        <p>"The first account registered will become the admin."</p>
                        <p class="text-gray-700">
                            "Passkey requires device biometrics (Touch ID, fingerprint) or a USB security key. "
                            "Phone-via-QR is not supported."
                        </p>
                    </div>
                </div>
            </Show>

            // Phase: Backup key
            <Show when=move || setup_phase.get() == SetupPhase::Backup>
                <div class="glass-card p-8 space-y-6 border-amber-500/30">
                    <crate::components::nsec_backup::NsecBackup
                        nsec=privkey_hex.get_untracked()
                        on_dismiss=on_backup_done
                    />
                </div>
            </Show>
        </div>
    }
}

#[derive(Clone, Copy, PartialEq)]
enum SetupPhase {
    Cta,
    Backup,
    Done,
}

// -- Sub-components -----------------------------------------------------------

#[component]
fn FeatureCard(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
) -> impl IntoView {
    view! {
        <div class="glass-card p-6 space-y-3 hover:border-amber-500/30 hover:shadow-lg hover:shadow-amber-500/5 hover:-translate-y-0.5 transition-all duration-300 group">
            <h3 class="text-xl font-semibold text-amber-400 flex items-center gap-2">
                <span class="group-hover:scale-110 transition-transform duration-300">{icon}</span>
                <span>{title}</span>
            </h3>
            <p class="text-gray-400 text-sm leading-relaxed">{description}</p>
        </div>
    }
}

#[component]
fn TechBadge(label: &'static str) -> impl IntoView {
    view! {
        <span class="text-xs text-gray-500 border border-gray-800 rounded-full px-3 py-1 hover:border-amber-500/20 hover:text-gray-400 transition-colors duration-300">
            {label}
        </span>
    }
}

// -- SVG icons ----------------------------------------------------------------

fn shield_icon() -> impl IntoView {
    view! {
        <svg class="w-7 h-7 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round"
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
        </svg>
    }
}

fn passkey_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round"
                d="M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.71-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a7.464 7.464 0 01-1.15 3.993m1.989 3.559A11.209 11.209 0 008.25 10.5a3.75 3.75 0 117.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 01-3.6 9.75m6.633-4.596a18.666 18.666 0 01-2.485 5.33"/>
        </svg>
    }
}

fn key_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round"
                d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
        </svg>
    }
}
