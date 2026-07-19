//! Zone-bound invite landing page — `/join/:code` (PUBLIC).
//!
//! An invite link (`/join/<code>`) is the single entry a zone owner hands out to
//! bring someone straight into a specific zone. The page is intentionally
//! **not** auth-gated: it fetches a public preview of the invite, then branches
//! on the visitor's auth state.
//!
//! ## Flow
//!
//! 1. On mount, `GET {AUTH_API}/api/invites/:code` for a preview. An
//!    invalid/expired/used code lands on a friendly dead-end.
//! 2. A valid, zone-bound invite renders a hero landing ("You are invited to
//!    `<zone>`"), coloured with the zone accent (read-only, via
//!    [`crate::utils::zone_theme::zone_accent_style_cfg`] +
//!    [`crate::stores::zones::load_zones`] lookup by `zone_id`).
//! 3. Not signed in → "Create my account" → `/signup?returnTo=/join/<code>`
//!    (signup honours `returnTo`, so the flow returns here authed and closes
//!    automatically). A secondary "Sign in" link uses the same `returnTo` carry.
//! 4. Signed in → "Join `<zone>`" → NIP-98 `POST /api/invites/:code/redeem`,
//!    which redeems the invite and grants the zone cohort server-side.
//! 5. On success → a brief "You are in" interstitial, then the user lands IN the
//!    zone via a full reload (`location.set_href`) so cohorts are re-derived and
//!    the newly-granted zone is visible.
//!
//! The relay/auth-worker remain the security boundary: this page only renders
//! and calls the contract. The zone config lookup is READ-ONLY.

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map};
use leptos_router::NavigateOptions;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::app::base_href;
use crate::auth::use_auth;
use crate::stores::zones::{load_zones, zone_path_for_id};
use crate::utils::zone_theme::{resolved_accent_hex, zone_accent_style_cfg};

/// Preview of an invite from `GET {AUTH_API}/api/invites/:code`.
///
/// Serde is deliberately forgiving (every field `#[serde(default)]`) so a
/// backend that ships a slightly different envelope shape never breaks the
/// client. The WI-4 backend signals validity via `state` (`"active"` when the
/// invite is redeemable); `valid`/`ok` are also accepted for any variant that
/// ships a boolean envelope instead.
#[derive(Clone, Debug, Default, Deserialize)]
struct InvitePreview {
    #[serde(default)]
    valid: bool,
    #[serde(default)]
    ok: bool,
    /// Lifecycle state from the WI-4 preview: `"active"` = redeemable;
    /// `"expired"`/`"exhausted"`/`"revoked"` = dead.
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    zone_id: Option<String>,
    #[serde(default)]
    zone_display_name: Option<String>,
    /// Optional server-supplied reason for an invalid invite (expired/used).
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

impl InvitePreview {
    fn is_valid(&self) -> bool {
        self.valid || self.ok || self.state.as_deref() == Some("active")
    }
}

/// Fetch the public invite preview. Any non-200 or parse failure surfaces as an
/// `Err`, which the page treats as "invalid/expired" (a friendly dead-end).
async fn fetch_preview(code: &str) -> Result<InvitePreview, String> {
    let url = format!(
        "{}/api/invites/{}",
        crate::utils::relay_url::auth_api_base(),
        code
    );
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
    let s = text.as_string().ok_or("Response body not a string")?;
    serde_json::from_str::<InvitePreview>(&s).map_err(|e| format!("JSON parse: {e}"))
}

/// Redeem state for the "Join" action.
#[derive(Clone, PartialEq)]
enum RedeemState {
    Idle,
    Working,
    Done,
    Error(String),
}

/// Resolve the display name for a preview: explicit `zone_display_name`, else
/// the config zone's label, else the raw id, else a neutral fallback.
fn zone_display(p: &InvitePreview) -> String {
    if let Some(name) = p
        .zone_display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return name.to_string();
    }
    let zid = p.zone_id.clone().unwrap_or_default();
    if zid.is_empty() {
        return "the community".to_string();
    }
    load_zones()
        .iter()
        .find(|z| z.id == zid)
        .map(|z| z.label())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(zid)
}

/// `--zone-accent: <hex>;` for a preview's zone, config-accent-aware and
/// READ-ONLY against the live zone list.
fn zone_accent_style_for(p: &InvitePreview) -> String {
    let zid = p.zone_id.clone().unwrap_or_default();
    let cfg = load_zones()
        .iter()
        .find(|z| z.id == zid)
        .and_then(|z| z.accent_hex.clone());
    zone_accent_style_cfg(&zid, cfg.as_deref())
}

/// Resolved accent hex for a preview's zone (config first, built-in fallback).
fn zone_accent_hex_for(p: &InvitePreview) -> String {
    let zid = p.zone_id.clone().unwrap_or_default();
    let cfg = load_zones()
        .iter()
        .find(|z| z.id == zid)
        .and_then(|z| z.accent_hex.clone());
    resolved_accent_hex(&zid, cfg.as_deref())
}

#[component]
pub fn JoinPage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let zone_access = crate::stores::zone_access::use_zone_access();
    let navigate = StoredValue::new(use_navigate());

    let params = use_params_map();
    let code = Memo::new(move |_| params.read().get("code").unwrap_or_default());

    // None = loading; Some(Ok) = fetched (maybe invalid); Some(Err) = network.
    let preview: RwSignal<Option<Result<InvitePreview, String>>> = RwSignal::new(None);
    let redeem_state = RwSignal::new(RedeemState::Idle);

    // Fetch the preview on mount and whenever the code changes.
    Effect::new(move |_| {
        let c = code.get();
        if c.is_empty() {
            return;
        }
        preview.set(None);
        spawn_local(async move {
            preview.set(Some(fetch_preview(&c).await));
        });
    });

    // NOT signed in → create an account, carrying the invite via returnTo so the
    // signup flow returns here authed and closes the loop.
    let go_signup = move |_: leptos::ev::MouseEvent| {
        let dest = format!("/signup?returnTo=/join/{}", code.get_untracked());
        navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
    };
    let go_login = move |_: leptos::ev::MouseEvent| {
        let dest = format!("/login?returnTo=/join/{}", code.get_untracked());
        navigate.with_value(|nav| nav(&dest, NavigateOptions::default()));
    };

    // Signed in → redeem the invite (NIP-98 POST). On success, refresh cohorts
    // and flip to the "You are in" interstitial.
    let do_redeem = move |_: leptos::ev::MouseEvent| {
        if redeem_state.get_untracked() == RedeemState::Working {
            return;
        }
        let Some(signer) = auth.get_signer() else {
            redeem_state.set(RedeemState::Error("Please sign in first.".to_string()));
            return;
        };
        let c = code.get_untracked();
        redeem_state.set(RedeemState::Working);
        spawn_local(async move {
            let url = format!(
                "{}/api/invites/{}/redeem",
                crate::utils::relay_url::auth_api_base(),
                c
            );
            match crate::auth::nip98::fetch_with_nip98_post_signer(&url, "{}", &*signer).await {
                Ok(_) => {
                    // The grant landed server-side; pick it up client-side too so
                    // the newly-granted zone shows the moment we navigate.
                    zone_access.refresh();
                    redeem_state.set(RedeemState::Done);
                }
                Err(e) => redeem_state.set(RedeemState::Error(format!("Could not join: {e}"))),
            }
        });
    };

    // "Open <zone>": full reload into the zone so cohorts re-derive and the
    // newly-granted zone is visible (SPA nav would keep the stale cohort read).
    let open_zone = move |_: leptos::ev::MouseEvent| {
        let zid = match preview.get_untracked() {
            Some(Ok(p)) if p.is_valid() => p.zone_id.clone().unwrap_or_default(),
            _ => String::new(),
        };
        let path = if zid.is_empty() {
            base_href("/forums")
        } else {
            base_href(&format!("/{}", zone_path_for_id(&zid)))
        };
        if let Some(w) = web_sys::window() {
            let _ = w.location().set_href(&path);
        }
    };

    let go_settings = move |_: leptos::ev::MouseEvent| {
        navigate.with_value(|nav| nav("/settings", NavigateOptions::default()));
    };

    view! {
        <div class="min-h-screen bg-gray-900 text-white flex items-center justify-center px-4 py-16">
            {move || match preview.get() {
                None => view! {
                    <div class="text-center animate-pulse">
                        <div class="w-12 h-12 rounded-full border-2 border-gray-700 border-t-amber-400 animate-spin mx-auto mb-4"></div>
                        <p class="text-gray-400 text-sm">"Checking your invite…"</p>
                    </div>
                }.into_any(),
                Some(Err(_)) => dead_end_view().into_any(),
                Some(Ok(p)) if !p.is_valid() => dead_end_view().into_any(),
                Some(Ok(p)) => {
                    let display = zone_display(&p);
                    let accent_style = zone_accent_style_for(&p);
                    let accent_hex = zone_accent_hex_for(&p);
                    let can_install = auth.get().is_local_key;

                    // Redeemed → interstitial, regardless of auth branch below.
                    if redeem_state.get() == RedeemState::Done {
                        return interstitial_view(
                            display.clone(),
                            accent_style.clone(),
                            accent_hex.clone(),
                            can_install,
                            open_zone,
                            go_settings,
                        ).into_any();
                    }

                    let btn_style = StoredValue::new(format!(
                        "{accent_style} background-color: {accent_hex}; border-color: {accent_hex};"
                    ));
                    let err = match redeem_state.get() {
                        RedeemState::Error(e) => Some(e),
                        _ => None,
                    };
                    let working = redeem_state.get() == RedeemState::Working;
                    let display_btn = StoredValue::new(display.clone());

                    view! {
                        <div
                            class="max-w-lg w-full bg-gray-800/60 border border-gray-700 rounded-2xl overflow-hidden shadow-2xl"
                            style=accent_style.clone()
                        >
                            // Accent header band
                            <div
                                class="h-2 w-full"
                                style="background-color: var(--zone-accent);"
                            ></div>
                            <div class="p-8 text-center">
                                <p class="text-xs uppercase tracking-widest text-gray-500 mb-3">"You have been invited"</p>
                                <h1 class="text-3xl font-bold mb-2">
                                    "You are invited to "
                                    <span style="color: var(--zone-accent);">{display.clone()}</span>
                                </h1>
                                <p class="text-gray-400 text-sm mb-8">
                                    "This is a private zone. Redeem your invite to be added and step inside."
                                </p>

                                {err.map(|e| view! {
                                    <div class="mb-4 bg-red-900/50 border border-red-700 rounded-lg px-4 py-2 text-red-200 text-sm">
                                        {e}
                                    </div>
                                })}

                                <Show
                                    when=move || is_authed.get()
                                    fallback=move || view! {
                                        <div class="space-y-3">
                                            <button
                                                on:click=go_signup
                                                class="w-full py-3 rounded-lg font-semibold text-gray-900 border transition-transform hover:-translate-y-0.5"
                                                style=btn_style.get_value()
                                            >
                                                "Create my account"
                                            </button>
                                            <button
                                                on:click=go_login
                                                class="w-full py-2.5 rounded-lg text-sm text-gray-300 border border-gray-600 hover:border-gray-400 hover:text-white transition-colors"
                                            >
                                                "Already have an account? Sign in"
                                            </button>
                                        </div>
                                    }
                                >
                                    <button
                                        on:click=do_redeem
                                        disabled=working
                                        class="w-full py-3 rounded-lg font-semibold text-gray-900 border transition-transform hover:-translate-y-0.5 disabled:opacity-60 disabled:translate-y-0"
                                        style=btn_style.get_value()
                                    >
                                        {move || if working { "Joining…".to_string() } else { display_btn.with_value(|d| format!("Join {d}")) }}
                                    </button>
                                </Show>
                            </div>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

/// Friendly dead-end for an invalid/expired/used invite.
fn dead_end_view() -> impl IntoView {
    view! {
        <div class="max-w-md w-full text-center bg-gray-800/60 border border-gray-700 rounded-2xl p-10 shadow-2xl">
            <div class="w-14 h-14 rounded-full bg-gray-700/50 flex items-center justify-center mx-auto mb-5">
                <svg xmlns="http://www.w3.org/2000/svg" class="w-7 h-7 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
            </div>
            <h1 class="text-2xl font-bold mb-2">"This invite is no longer valid"</h1>
            <p class="text-gray-400 text-sm mb-8">
                "This invite has expired or been used — ask for a fresh link."
            </p>
            <a
                href=base_href("/")
                class="inline-block py-2.5 px-6 rounded-lg text-sm text-amber-400 border border-amber-500/30 hover:border-amber-400 hover:text-amber-300 transition-colors"
            >
                "Go to the home page"
            </a>
        </div>
    }
}

/// "You are in" interstitial shown after a successful redeem.
fn interstitial_view(
    display: String,
    accent_style: String,
    accent_hex: String,
    can_install: bool,
    open_zone: impl Fn(leptos::ev::MouseEvent) + 'static,
    go_settings: impl Fn(leptos::ev::MouseEvent) + 'static,
) -> impl IntoView {
    let btn_style =
        format!("{accent_style} background-color: {accent_hex}; border-color: {accent_hex};");
    let open_label = format!("Open {display}");
    view! {
        <div
            class="max-w-lg w-full bg-gray-800/60 border border-gray-700 rounded-2xl overflow-hidden shadow-2xl text-center"
            style=accent_style.clone()
        >
            <div class="h-2 w-full" style="background-color: var(--zone-accent);"></div>
            <div class="p-8">
                <div
                    class="w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-5"
                    style="background-color: color-mix(in srgb, var(--zone-accent) 20%, transparent);"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-8 h-8" style="color: var(--zone-accent);" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20 6 9 17l-5-5"/>
                    </svg>
                </div>
                <h1 class="text-2xl font-bold mb-2">
                    "You are in — "
                    <span style="color: var(--zone-accent);">{display.clone()}</span>
                </h1>
                <p class="text-gray-400 text-sm mb-8">
                    "Your invite is redeemed and you have been added to the zone."
                </p>
                <div class="space-y-3">
                    <button
                        on:click=open_zone
                        class="w-full py-3 rounded-lg font-semibold text-gray-900 border transition-transform hover:-translate-y-0.5"
                        style=btn_style
                    >
                        {open_label}
                    </button>
                    {can_install.then(|| view! {
                        <button
                            on:click=go_settings
                            class="w-full py-2.5 rounded-lg text-sm text-gray-300 border border-gray-600 hover:border-gray-400 hover:text-white transition-colors"
                        >
                            "Install the app"
                        </button>
                        <p class="text-xs text-gray-500 pt-1">
                            "You can install this as an app any time from Settings."
                        </p>
                    })}
                </div>
            </div>
        </div>
    }
}
