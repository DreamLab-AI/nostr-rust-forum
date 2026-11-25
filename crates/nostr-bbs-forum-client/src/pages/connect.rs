//! `/connect`: sign in from a sheet QR, a tapped link or the in-app scanner
//! (ADR-098), then the one-screen onboarding.
//!
//! A sign-in sheet's QR encodes the root-form link `{origin}{FORUM_BASE}/#k=…`
//! (`utils::connect_link`). The `index.html` capture script scrubs the
//! fragment from the address bar before the WASM loads; `App()` takes the key
//! (only on `<base>/` or `<base>/connect`), parks it in a zeroising one-shot
//! slot and points the router here. The in-app "Scan your sheet" scanner
//! parks a scanned key in the same slot and navigates here too.
//!
//! ## Hard security invariants
//!
//! * **Fragment only, never a server.** The key only ever travels in a URL
//!   fragment or in memory. Nothing here logs it.
//! * **Never replace an account silently.** Before importing, the page checks
//!   for ANY identity already on this device (live session, persisted session
//!   of any kind, stored key, installed-app bake; see
//!   [`AuthStore::prior_identity`]). If one belongs to another account, the
//!   member must confirm the switch. A scan usually opens a fresh tab whose
//!   sessionStorage is empty, so a live-session check alone would miss it.
//! * **Import through the existing path.** `login_with_local_key` does the
//!   NIP-19 decode and curve checks; nothing is hand-rolled here.
//! * **Bearer credential.** The welcome screen says plainly that whoever has
//!   the sheet can sign in as this member.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use zeroize::Zeroizing;

use crate::app::base_href;
use crate::auth::{use_auth, PriorIdentity};
use crate::components::welcome_onboarding::WelcomeOnboarding;
use crate::utils::connect_link;

/// Page state.
#[derive(Clone, PartialEq)]
enum ConnectState {
    /// Checking the device and importing.
    Working,
    /// Another account is on this device: ask first.
    Confirm {
        /// Short form of the other account's npub, when known.
        other: Option<String>,
        /// Short form of the npub the code signs in as.
        incoming: String,
    },
    /// Signed in: the onboarding screen.
    Welcome,
    /// No usable key, or the import failed.
    Error(String),
}

/// `npub1abcd…wxyz` for a hex pubkey (public data only).
fn short_npub(pubkey_hex: &str) -> String {
    match nostr_bbs_core::encode_npub(pubkey_hex) {
        Ok(n) if n.len() > 20 => format!("{}…{}", &n[..12], &n[n.len() - 6..]),
        Ok(n) => n,
        Err(_) => crate::utils::shorten_pubkey(pubkey_hex),
    }
}

#[component]
pub fn ConnectPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = StoredValue::new(use_navigate());
    let state = RwSignal::new(ConnectState::Working);
    // The key waiting for the member's confirmation. Zeroised on drop.
    let pending: StoredValue<Option<Zeroizing<String>>> = StoredValue::new(None);

    let go = move |path: &str| {
        let path = path.to_string();
        navigate.with_value(|n| n(&path, NavigateOptions::default()));
    };

    // Import the pending key (after an optional switch clean-up) and show the
    // welcome screen.
    let import = move |switching: bool| {
        let Some(key) = pending.try_update_value(Option::take).flatten() else {
            state.set(ConnectState::Error("The sign-in code has expired. Scan it again.".into()));
            return;
        };
        state.set(ConnectState::Working);
        leptos::task::spawn_local(async move {
            if switching {
                // The other account's installed-app bake must not survive the
                // switch, or the next launch would open it again.
                let _ = crate::utils::bake::unbake().await;
            }
            auth.clear_error();
            match auth.login_with_local_key(&key) {
                Ok(()) => {
                    // Leave the /connect URL (a reload must not land here
                    // again); the welcome screen stays mounted.
                    if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
                        let _ = h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&base_href("/")));
                    }
                    state.set(ConnectState::Welcome);
                }
                Err(e) => state.set(ConnectState::Error(e)),
            }
            drop(key);
        });
    };

    // On mount: take the key once, compare with what is on the device.
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        let key = connect_link::take_stashed()
            .or_else(|| connect_link::take_pending_key(&base_href("")));
        let Some(key) = key else {
            if auth.is_authenticated().get_untracked() {
                go("/forums");
            } else {
                state.set(ConnectState::Error(
                    "No sign-in code found. Scan the code on your sign-in sheet, or sign in another way."
                        .into(),
                ));
            }
            return;
        };
        let Some(incoming) = connect_link::pubkey_for_key(&key) else {
            state.set(ConnectState::Error(
                "That sign-in code isn't valid. Try scanning it again.".into(),
            ));
            return;
        };
        pending.set_value(Some(key));
        leptos::task::spawn_local(async move {
            match auth.prior_identity(&incoming).await {
                PriorIdentity::None | PriorIdentity::Same => import(false),
                PriorIdentity::Other(other) => state.set(ConnectState::Confirm {
                    other: other.as_deref().map(short_npub),
                    incoming: short_npub(&incoming),
                }),
            }
        });
    });

    let keep_current = move |_: web_sys::MouseEvent| {
        pending.set_value(None);
        if auth.is_authenticated().get_untracked() {
            go("/forums");
        } else {
            go("/login");
        }
    };

    view! {
        <div class="min-h-[80vh] flex items-center justify-center px-4 py-8">
            <div class="w-full max-w-md">
                {move || match state.get() {
                    ConnectState::Working => view! {
                        <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-8 text-center space-y-4">
                            <div class="animate-spin w-8 h-8 mx-auto border-2 border-amber-400 border-t-transparent rounded-full"></div>
                            <p class="text-gray-400 text-sm">"Signing you in…"</p>
                        </div>
                    }.into_any(),

                    ConnectState::Confirm { other, incoming } => view! {
                        <div class="bg-gray-800/30 border border-amber-600/60 rounded-2xl p-6 space-y-5" data-testid="connect-confirm">
                            <h1 class="text-xl font-bold text-white">"Switch account on this device?"</h1>
                            <p class="text-sm text-gray-300">
                                "This device is already signed in as "
                                <span class="font-mono text-amber-300">{other.unwrap_or_else(|| "another account".into())}</span>
                                ". The code you used signs in as "
                                <span class="font-mono text-amber-300">{incoming}</span>"."
                            </p>
                            <p class="text-xs text-gray-400">
                                "Switching signs the other account out of this device. Only switch if you have its recovery key or sheet."
                            </p>
                            <div class="flex flex-col gap-3">
                                <button
                                    on:click=move |_| import(true)
                                    class="w-full bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl text-sm"
                                    data-testid="connect-switch"
                                >"Switch to this account"</button>
                                <button
                                    on:click=keep_current
                                    class="w-full border border-gray-600 text-gray-200 hover:bg-gray-700/50 py-3 rounded-xl text-sm"
                                    data-testid="connect-keep"
                                >"Keep the current account"</button>
                            </div>
                        </div>
                    }.into_any(),

                    ConnectState::Welcome => view! { <WelcomeOnboarding /> }.into_any(),

                    ConnectState::Error(msg) => view! {
                        <div class="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-8 space-y-5 text-center">
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_npub_is_public_and_short() {
        let pk = nostr_bbs_core::keys::pubkey_hex(&[1u8; 32]).unwrap();
        let s = short_npub(&pk);
        assert!(s.starts_with("npub1") && s.contains('…') && s.chars().count() < 25);
    }
}
