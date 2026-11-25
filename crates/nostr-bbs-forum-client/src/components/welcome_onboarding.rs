//! The one onboarding screen shown after a sheet or link sign-in.
//!
//! 1. **Welcome, {name}.** The name is the member's own kind-0 display name,
//!    hydrated from the relay by `login_with_local_key`; until it arrives the
//!    short npub stands in. "Not you? Sign out" is right beside it. The
//!    sheet's step 2 tells the member to check this name.
//! 2. **Install the app** (skipped when already installed, or when the
//!    deployment has `BBS_PWA_ENABLED` off):
//!    * Chromium/Android with a stashed `beforeinstallprompt`: one button.
//!      It first BAKES the key (consent line beside it), because an installed
//!      Android app shares Chrome's IndexedDB but not its sessionStorage
//!      (web.dev/articles/webapks). Then it shows the prompt; if the member
//!      dismisses it, the bake is removed again.
//!    * iOS: Share → Add to Home Screen, with an illustration, then the
//!      scan-again note. iOS gives the installed app separate storage
//!      (webkit.org/tracking-prevention), so nothing is baked here; the app's
//!      "Scan your sheet" signs it in.
//!    * Other browsers: bake on request, then the manual install steps.
//! 3. **No passkey step.** A passkey derives a NEW key from its PRF output
//!    (`auth::passkey`), so it would create a second account rather than
//!    protect this one; device keys are a separate, gated feature.
//! 4. **Continue** to the member's home zone (or first accessible zone, or
//!    the forum index).

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;

use crate::auth::use_auth;
use crate::stores::zone_access::use_zone_access;
use crate::utils::pwa_install::{self, BrowserFamily, PromptOutcome};

/// Which install guidance this browser gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallPath {
    /// Already running as an installed app: no install step.
    AlreadyInstalled,
    /// The deployment turned the app install off.
    Disabled,
    /// iOS / iPadOS Safari: manual Share → Add to Home Screen, then scan again.
    Ios,
    /// A browser that offered `beforeinstallprompt`.
    Prompt,
    /// Anything else: manual steps for this browser family.
    Manual(BrowserFamily),
}

/// Pure choice of install path (unit-tested).
pub(crate) fn choose_install_path(
    standalone: bool,
    enabled: bool,
    ios: bool,
    prompt_available: bool,
    family: BrowserFamily,
) -> InstallPath {
    if standalone {
        InstallPath::AlreadyInstalled
    } else if !enabled {
        InstallPath::Disabled
    } else if ios {
        InstallPath::Ios
    } else if prompt_available {
        InstallPath::Prompt
    } else {
        InstallPath::Manual(family)
    }
}

/// Progress of the install step.
#[derive(Clone, PartialEq)]
enum InstallStep {
    Idle,
    Busy,
    /// Prompt accepted: open the app from the home screen.
    Installed,
    /// Bake done, no prompt: show manual steps.
    ManualReady,
    /// Dismissed or failed, with a message.
    Note(String),
}

/// How long to wait for zone access before baking without one.
const ZONE_WAIT_MS: u32 = 10_000;

#[component]
pub fn WelcomeOnboarding() -> impl IntoView {
    let auth = use_auth();
    let zone_access = use_zone_access();
    let navigate = StoredValue::new(use_navigate());

    let standalone = pwa_install::is_standalone();
    let path = Memo::new(move |_| {
        choose_install_path(
            standalone,
            pwa_install::feature_enabled(),
            pwa_install::platform_is_ios(),
            pwa_install::installable().get() || pwa_install::deferred_prompt_available(),
            pwa_install::browser_family(),
        )
    });
    let step = RwSignal::new(InstallStep::Idle);

    let name = Memo::new(move |_| {
        auth.nickname()
            .get()
            .filter(|n| !n.trim().is_empty())
            .or_else(|| {
                auth.pubkey().get().map(|pk| match nostr_bbs_core::encode_npub(&pk) {
                    Ok(n) if n.len() > 20 => format!("{}…{}", &n[..12], &n[n.len() - 6..]),
                    _ => crate::utils::shorten_pubkey(&pk),
                })
            })
            .unwrap_or_default()
    });

    let home_zone = Signal::derive(move || {
        zone_access
            .home_zone()
            .or_else(|| zone_access.first_accessible_zone())
    });

    let continue_label = move || {
        home_zone
            .get()
            .map(|z| {
                let n = z.display_name.trim();
                if n.is_empty() {
                    "Continue to the forum".to_string()
                } else {
                    format!("Continue to {n}")
                }
            })
            .unwrap_or_else(|| "Continue to the forum".to_string())
    };

    let continue_now = move |_: web_sys::MouseEvent| {
        let dest = home_zone
            .get_untracked()
            .map(|z| format!("/{}", crate::stores::zones::zone_path_for_id(&z.id)))
            .unwrap_or_else(|| "/forums".to_string());
        navigate.with_value(|n| n(&dest, NavigateOptions::default()));
    };

    let sign_out = move |_: web_sys::MouseEvent| {
        auth.logout();
        navigate.with_value(|n| n("/login", NavigateOptions::default()));
    };

    // Bake the key for the installed app, bound to the home zone. Waits for
    // zone access (it loads after the relay connects); returns false when no
    // zone is accessible yet, in which case the app's scanner is the way in.
    let bake_now = move || async move {
        let mut waited = 0u32;
        let zone = loop {
            if let Some(z) = home_zone.get_untracked() {
                break Some(z);
            }
            if zone_access.loaded.get_untracked() || waited >= ZONE_WAIT_MS {
                break None;
            }
            sleep_ms(250).await;
            waited += 250;
        };
        let Some(zone) = zone else { return false };
        let Some(secret) = auth.get_privkey_bytes() else {
            return false;
        };
        crate::utils::bake::bake(&secret, &zone.id).await.is_ok()
    };

    let install_with_prompt = move |_: web_sys::MouseEvent| {
        step.set(InstallStep::Busy);
        leptos::task::spawn_local(async move {
            let baked = bake_now().await;
            match pwa_install::trigger_prompt_outcome().await {
                PromptOutcome::Accepted => step.set(InstallStep::Installed),
                outcome => {
                    // No app was installed: no durable key may stay at rest.
                    if baked {
                        let _ = crate::utils::bake::unbake().await;
                    }
                    step.set(InstallStep::Note(if outcome == PromptOutcome::Unavailable {
                        "Your browser didn\u{2019}t offer the install. Use its menu to install the app, or carry on in the browser.".into()
                    } else {
                        "No problem, you can install the app later from Settings.".into()
                    }));
                }
            }
            if !baked {
                // Signed in, but no zone to bind yet: the app's scanner covers it.
                web_sys::console::info_1(&"[onboarding] app install without bake: zone access not ready".into());
            }
        });
    };

    let keep_signed_in_manual = move |_: web_sys::MouseEvent| {
        step.set(InstallStep::Busy);
        leptos::task::spawn_local(async move {
            if bake_now().await {
                step.set(InstallStep::ManualReady);
            } else {
                step.set(InstallStep::Note(
                    "When the app opens, tap \u{201c}Scan your sheet\u{201d} to sign it in.".into(),
                ));
            }
        });
    };

    view! {
        <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6 space-y-6" data-testid="welcome-onboarding">
            // 1. Welcome
            <div class="space-y-2 text-center">
                <div class="text-3xl">"👋"</div>
                <h1 class="text-2xl font-bold text-white" data-testid="welcome-name">
                    "Welcome, " {move || name.get()}
                </h1>
                <p class="text-sm text-gray-400">
                    "You\u{2019}re signed in on this device. "
                    <button on:click=sign_out class="underline text-gray-300 hover:text-white" data-testid="welcome-not-you">
                        "Not you? Sign out"
                    </button>
                </p>
                <p class="text-xs text-red-300/90 bg-red-900/20 border border-red-800/60 rounded-lg px-3 py-2">
                    "Anyone with your sign-in sheet can use your account. Keep it private, and delete any screenshot of the code."
                </p>
                {standalone.then(|| view! {
                    <p class="text-xs text-gray-400" data-testid="welcome-standalone-note">
                        "This app keeps you signed in on this device. Anyone who can unlock the device can open your account; sign out in Settings to remove it."
                    </p>
                })}
            </div>

            // 2. Install the app
            {move || match path.get() {
                InstallPath::AlreadyInstalled | InstallPath::Disabled => ().into_any(),
                InstallPath::Ios => view! {
                    <section class="border border-gray-700 rounded-xl p-4 space-y-3" data-testid="install-ios">
                        <h2 class="text-lg font-semibold text-white">"Add the forum to your home screen"</h2>
                        <IosShareIllustration />
                        <ol class="list-decimal list-inside text-sm text-gray-200 space-y-1">
                            {pwa_install::ios_instructions().iter().map(|s| view! { <li>{*s}</li> }).collect_view()}
                        </ol>
                        <p class="text-sm font-semibold text-amber-300 bg-amber-900/20 border border-amber-700/60 rounded-lg p-3" data-testid="install-ios-scan-again">
                            {pwa_install::ios_scan_again_note()}
                        </p>
                    </section>
                }.into_any(),
                InstallPath::Prompt => view! {
                    <section class="border border-gray-700 rounded-xl p-4 space-y-3" data-testid="install-prompt">
                        <h2 class="text-lg font-semibold text-white">"Install the app"</h2>
                        <p class="text-xs text-gray-400">
                            "Installing keeps you signed in on this device. Anyone who can unlock the device can open your account."
                        </p>
                        {move || match step.get() {
                            InstallStep::Installed => view! {
                                <p class="text-sm text-green-300" data-testid="install-done">
                                    "Installed. Open the forum from your home screen; it starts signed in."
                                </p>
                            }.into_any(),
                            InstallStep::Note(msg) => view! {
                                <p class="text-sm text-gray-300" data-testid="install-note">{msg}</p>
                            }.into_any(),
                            s => view! {
                                <button
                                    on:click=install_with_prompt
                                    disabled=s == InstallStep::Busy
                                    class="w-full bg-amber-500 hover:bg-amber-400 disabled:opacity-60 text-gray-900 font-semibold py-3 rounded-xl text-sm"
                                    data-testid="install-button"
                                >
                                    {if s == InstallStep::Busy { "Getting the app ready…" } else { "Install the app" }}
                                </button>
                            }.into_any(),
                        }}
                    </section>
                }.into_any(),
                InstallPath::Manual(family) => {
                    let (heading, steps) = pwa_install::manual_install_steps(family);
                    view! {
                        <section class="border border-gray-700 rounded-xl p-4 space-y-3" data-testid="install-manual">
                            <h2 class="text-lg font-semibold text-white">"Install the app"</h2>
                            {move || match step.get() {
                                InstallStep::ManualReady => view! {
                                    <div class="space-y-2">
                                        <p class="text-sm font-semibold text-gray-200">{heading}</p>
                                        <ol class="list-decimal list-inside text-sm text-gray-300 space-y-1">
                                            {steps.iter().map(|s| view! { <li>{*s}</li> }).collect_view()}
                                        </ol>
                                    </div>
                                }.into_any(),
                                InstallStep::Note(msg) => view! {
                                    <p class="text-sm text-gray-300" data-testid="install-note">{msg}</p>
                                }.into_any(),
                                s => view! {
                                    <div class="space-y-2">
                                        <p class="text-xs text-gray-400">
                                            "To open the forum as an app, let this device keep you signed in. Anyone who can unlock the device can open your account."
                                        </p>
                                        <button
                                            on:click=keep_signed_in_manual
                                            disabled=s == InstallStep::Busy
                                            class="w-full border border-amber-500 text-amber-300 hover:bg-amber-500/10 disabled:opacity-60 font-semibold py-3 rounded-xl text-sm"
                                        >
                                            "Keep me signed in for the app"
                                        </button>
                                    </div>
                                }.into_any(),
                            }}
                        </section>
                    }.into_any()
                }
            }}

            // 4. Continue
            <button
                on:click=continue_now
                class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl text-sm"
                data-testid="welcome-continue"
            >
                {continue_label}
            </button>
        </div>
    }
}

/// Resolve after `ms` milliseconds (a `setTimeout` promise).
async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Inline illustration of Safari's Share button and the "Add to Home
/// Screen" menu row (no external assets).
#[component]
fn IosShareIllustration() -> impl IntoView {
    view! {
        <div class="flex items-center justify-center gap-4 py-2" aria-hidden="true">
            // Share icon: square with an upward arrow.
            <svg width="56" height="56" viewBox="0 0 56 56" class="text-sky-400">
                <rect x="1" y="1" width="54" height="54" rx="12" fill="none" stroke="currentColor" stroke-opacity="0.35" />
                <path d="M20 24h-4v20h24V24h-4" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M28 10v22M21 17l7-7 7 7" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
            <span class="text-2xl text-gray-500">"→"</span>
            // Menu row: plus-in-square + label.
            <svg width="150" height="44" viewBox="0 0 150 44">
                <rect x="1" y="1" width="148" height="42" rx="10" fill="#1f2937" stroke="#4b5563" />
                <text x="12" y="27" fill="#e5e7eb" font-size="12" font-family="sans-serif">"Add to Home Screen"</text>
                <rect x="124" y="12" width="18" height="18" rx="4" fill="none" stroke="#e5e7eb" stroke-width="1.6" />
                <path d="M133 16v10M128 21h10" stroke="#e5e7eb" stroke-width="1.6" stroke-linecap="round" />
            </svg>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_path_matrix() {
        let f = BrowserFamily::Chromium;
        assert_eq!(choose_install_path(true, true, true, true, f), InstallPath::AlreadyInstalled);
        assert_eq!(choose_install_path(false, false, false, true, f), InstallPath::Disabled);
        assert_eq!(choose_install_path(false, true, true, false, f), InstallPath::Ios);
        // iOS never uses a prompt, even if one were somehow stashed.
        assert_eq!(choose_install_path(false, true, true, true, f), InstallPath::Ios);
        assert_eq!(choose_install_path(false, true, false, true, f), InstallPath::Prompt);
        assert_eq!(
            choose_install_path(false, true, false, false, BrowserFamily::Firefox),
            InstallPath::Manual(BrowserFamily::Firefox)
        );
    }
}
