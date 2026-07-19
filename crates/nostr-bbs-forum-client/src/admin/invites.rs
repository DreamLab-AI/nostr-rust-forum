//! Admin panel for minting zone-bound invite links.
//!
//! A zone owner picks a **locked** zone, hits Generate, and gets a shareable
//! `/join/<code>` link (with a copy button) that brings the recipient straight
//! into that zone. The panel also lists the admin's existing invites with a
//! revoke action.
//!
//! Contract (auth-worker, all admin calls NIP-98 signed):
//! - `POST {AUTH_API}/api/invites/create` body `{ zone_id, max_uses? }` → `{ code }`
//! - `GET  {AUTH_API}/api/invites/mine` → the caller's invites
//! - `POST {AUTH_API}/api/invites/:code/revoke` → revoke one
//!
//! Serde is forgiving (`#[serde(default)]`, `mine` accepts either a bare array
//! or `{ invites: [...] }`) so a slightly different backend envelope never
//! blanks the UI. Zone lookup is READ-ONLY against [`load_zones`].

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::nip98::{fetch_with_nip98_get_signer, fetch_with_nip98_post_signer};
use crate::auth::use_auth;
use crate::stores::zones::{load_zones, Zone, ZoneVisibility};

/// Response from `POST /api/invites/create`.
#[derive(Clone, Debug, Default, Deserialize)]
struct CreateInviteResp {
    #[serde(default)]
    code: String,
}

/// One invite row from `GET /api/invites/mine`.
#[derive(Clone, Debug, Default, Deserialize)]
struct InviteRow {
    #[serde(default)]
    code: String,
    #[serde(default)]
    zone_id: Option<String>,
    #[serde(default)]
    zone_display_name: Option<String>,
    #[serde(default)]
    max_uses: Option<u32>,
    #[serde(default)]
    uses: Option<u32>,
    #[serde(default)]
    revoked: bool,
}

/// Wrapper for the `{ invites: [...] }` envelope shape.
#[derive(Clone, Debug, Default, Deserialize)]
struct MineEnvelope {
    #[serde(default)]
    invites: Vec<InviteRow>,
}

/// Parse `mine` responses tolerantly: a bare JSON array or `{ invites: [...] }`.
fn parse_mine(body: &str) -> Vec<InviteRow> {
    if let Ok(env) = serde_json::from_str::<MineEnvelope>(body) {
        if !env.invites.is_empty() {
            return env.invites;
        }
    }
    serde_json::from_str::<Vec<InviteRow>>(body).unwrap_or_default()
}

/// Lockable zones the owner can mint invites for: anything non-public. A public
/// zone needs no invite (it is open), so only `Locked`/`Hidden` (or any zone
/// that requires a cohort) are offered.
fn lockable_zones() -> Vec<Zone> {
    load_zones()
        .into_iter()
        .filter(|z| z.visibility != ZoneVisibility::Public || !z.required_cohorts.is_empty())
        .collect()
}

/// Copy `text` to the clipboard (best-effort).
fn copy_to_clipboard(text: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w.navigator().clipboard().write_text(text);
    }
}

#[component]
pub fn InvitesPanel() -> impl IntoView {
    let auth = use_auth();

    let zones = StoredValue::new(lockable_zones());
    let first_zone = zones
        .with_value(|z| z.first().map(|z| z.id.clone()))
        .unwrap_or_default();

    let selected_zone = RwSignal::new(first_zone);
    let max_uses = RwSignal::new(String::new());
    let generating = RwSignal::new(false);
    let last_link: RwSignal<Option<String>> = RwSignal::new(None);
    let invites: RwSignal<Vec<InviteRow>> = RwSignal::new(Vec::new());
    let loaded = RwSignal::new(false);
    let msg: RwSignal<Option<(String, bool)>> = RwSignal::new(None);

    // Load the caller's existing invites on mount.
    let load_mine = move || {
        let Some(signer) = auth.get_signer() else {
            return;
        };
        spawn_local(async move {
            let url = format!(
                "{}/api/invites/mine",
                crate::utils::relay_url::auth_api_base()
            );
            match fetch_with_nip98_get_signer(&url, &*signer).await {
                Ok(body) => invites.set(parse_mine(&body)),
                Err(e) => msg.set(Some((format!("Could not load invites: {e}"), false))),
            }
            loaded.set(true);
        });
    };
    Effect::new(move |_| {
        if auth.get_signer().is_some() {
            load_mine();
        }
    });

    let on_generate = move |_: leptos::ev::MouseEvent| {
        if generating.get_untracked() {
            return;
        }
        let Some(signer) = auth.get_signer() else {
            msg.set(Some(("No signing key — log in first.".to_string(), false)));
            return;
        };
        let zone_id = selected_zone.get_untracked();
        if zone_id.is_empty() {
            msg.set(Some(("Pick a zone first.".to_string(), false)));
            return;
        }
        let max = max_uses
            .get_untracked()
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0);
        generating.set(true);
        msg.set(None);
        spawn_local(async move {
            let url = format!(
                "{}/api/invites/create",
                crate::utils::relay_url::auth_api_base()
            );
            let body = match max {
                Some(n) => serde_json::json!({ "zone_id": zone_id, "max_uses": n }),
                None => serde_json::json!({ "zone_id": zone_id }),
            }
            .to_string();
            match fetch_with_nip98_post_signer(&url, &body, &*signer).await {
                Ok(resp) => {
                    let parsed: CreateInviteResp = serde_json::from_str(&resp).unwrap_or_default();
                    if parsed.code.is_empty() {
                        msg.set(Some(("Server returned no invite code.".to_string(), false)));
                    } else {
                        let link = full_join_link(&parsed.code);
                        last_link.set(Some(link));
                        msg.set(Some(("Invite created.".to_string(), true)));
                        load_mine();
                    }
                }
                Err(e) => msg.set(Some((format!("Create failed: {e}"), false))),
            }
            generating.set(false);
        });
    };

    // Revoke one invite, keyed by code. `Rc<dyn Fn>` so it clones cheaply into
    // each reactive row without turning the list closure into `FnOnce`.
    let revoke = StoredValue::new_local(std::rc::Rc::new(move |code: String| {
        let Some(signer) = auth.get_signer() else {
            msg.set(Some(("No signing key — log in first.".to_string(), false)));
            return;
        };
        spawn_local(async move {
            let url = format!(
                "{}/api/invites/{}/revoke",
                crate::utils::relay_url::auth_api_base(),
                code
            );
            match fetch_with_nip98_post_signer(&url, "{}", &*signer).await {
                Ok(_) => {
                    invites.update(|list| {
                        for row in list.iter_mut() {
                            if row.code == code {
                                row.revoked = true;
                            }
                        }
                    });
                    msg.set(Some(("Invite revoked.".to_string(), true)));
                }
                Err(e) => msg.set(Some((format!("Revoke failed: {e}"), false))),
            }
        });
    }) as std::rc::Rc<dyn Fn(String)>);

    view! {
        <div class="space-y-6">
            <div>
                <h2 class="text-xl font-bold text-white flex items-center gap-2">
                    {invite_icon()}
                    "Create Invite"
                </h2>
                <p class="text-sm text-gray-400 mt-1">
                    "Mint a shareable link that brings someone straight into a locked zone and grants them its cohort when they redeem it."
                </p>
            </div>

            {move || msg.get().map(|(text, ok)| {
                let cls = if ok {
                    "bg-green-900/50 border border-green-700 rounded-lg px-4 py-2 text-green-200 text-sm flex items-center justify-between"
                } else {
                    "bg-red-900/50 border border-red-700 rounded-lg px-4 py-2 text-red-200 text-sm flex items-center justify-between"
                };
                view! {
                    <div class=cls>
                        <span>{text}</span>
                        <button on:click=move |_| msg.set(None) class="text-xs opacity-60 hover:opacity-100 ml-4">"dismiss"</button>
                    </div>
                }
            })}

            // Mint controls
            <div class="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4">
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div class="sm:col-span-2">
                        <label class="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">"Zone"</label>
                        <select
                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:border-amber-500 focus:ring-amber-500"
                            on:change=move |ev| selected_zone.set(event_target_value(&ev))
                            prop:value=move || selected_zone.get()
                        >
                            {zones.with_value(|list| {
                                if list.is_empty() {
                                    view! { <option value="">"No locked zones configured"</option> }.into_any()
                                } else {
                                    list.iter().map(|z| {
                                        let id = z.id.clone();
                                        let label = z.label();
                                        view! { <option value=id>{label}</option> }
                                    }).collect_view().into_any()
                                }
                            })}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">"Max uses"</label>
                        <input
                            type="number"
                            min="1"
                            placeholder="∞"
                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:border-amber-500 focus:ring-amber-500"
                            prop:value=move || max_uses.get()
                            on:input=move |ev| max_uses.set(event_target_value(&ev))
                        />
                    </div>
                </div>
                <button
                    on:click=on_generate
                    disabled=move || generating.get()
                    class="py-2.5 px-6 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold text-sm transition-colors disabled:opacity-60"
                >
                    {move || if generating.get() { "Generating…" } else { "Generate" }}
                </button>

                // Freshly-minted link + copy
                {move || last_link.get().map(|link| {
                    let link_for_copy = link.clone();
                    view! {
                        <div class="mt-2 flex items-center gap-2 bg-gray-900 border border-amber-500/30 rounded-lg px-3 py-2">
                            <input
                                readonly
                                prop:value=link.clone()
                                class="flex-1 bg-transparent text-amber-300 font-mono text-xs outline-none"
                            />
                            <button
                                on:click=move |_| copy_to_clipboard(&link_for_copy)
                                class="text-xs text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-2 py-1 transition-colors"
                            >
                                "Copy"
                            </button>
                        </div>
                    }
                })}
            </div>

            // Existing invites
            <div>
                <h3 class="text-sm font-semibold text-gray-300 mb-3">"Your invites"</h3>
                <Show
                    when=move || loaded.get()
                    fallback=|| view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg p-6 text-center animate-pulse">
                            <p class="text-gray-500 text-sm">"Loading invites…"</p>
                        </div>
                    }
                >
                    {move || {
                        let list = invites.get();
                        if list.is_empty() {
                            view! {
                                <div class="bg-gray-800 border border-gray-700 rounded-lg p-6 text-center">
                                    <p class="text-gray-500 text-sm">"No invites yet. Generate one above."</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="bg-gray-800 border border-gray-700 rounded-lg divide-y divide-gray-700/50">
                                    {list.into_iter().map(|row| {
                                        let code = row.code.clone();
                                        let code_copy = code.clone();
                                        let code_revoke = code.clone();
                                        let link = full_join_link(&code);
                                        let zone_label = row.zone_display_name.clone()
                                            .or_else(|| row.zone_id.clone())
                                            .unwrap_or_else(|| "—".to_string());
                                        let uses_label = match (row.uses, row.max_uses) {
                                            (Some(u), Some(m)) => format!("{u}/{m} used"),
                                            (Some(u), None) => format!("{u} used"),
                                            (None, Some(m)) => format!("0/{m} used"),
                                            (None, None) => "unlimited".to_string(),
                                        };
                                        let revoked = row.revoked;
                                        view! {
                                            <div class="flex items-center gap-3 px-4 py-3 text-sm">
                                                <div class="flex-1 min-w-0">
                                                    <div class="flex items-center gap-2">
                                                        <span class="font-semibold text-white">{zone_label}</span>
                                                        {revoked.then(|| view! {
                                                            <span class="text-xs bg-gray-700 text-gray-400 rounded px-1.5 py-0.5">"revoked"</span>
                                                        })}
                                                    </div>
                                                    <div class="font-mono text-xs text-gray-500 truncate" title=link.clone()>{link.clone()}</div>
                                                </div>
                                                <span class="text-xs text-gray-400 whitespace-nowrap">{uses_label}</span>
                                                <button
                                                    on:click=move |_| copy_to_clipboard(&full_join_link(&code_copy))
                                                    class="text-xs text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-2 py-1 transition-colors"
                                                >
                                                    "Copy"
                                                </button>
                                                <Show when=move || !revoked>
                                                    {
                                                        let code_revoke = code_revoke.clone();
                                                        view! {
                                                            <button
                                                                on:click=move |_| revoke.get_value()(code_revoke.clone())
                                                                class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors"
                                                            >
                                                                "Revoke"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }
                    }}
                </Show>
            </div>
        </div>
    }
}

/// Build the absolute, shareable `/join/<code>` link (origin + base path).
fn full_join_link(code: &str) -> String {
    let path = base_href(&format!("/join/{code}"));
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .map(|origin| format!("{origin}{path}"))
        .unwrap_or(path)
}

fn invite_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 2 11 13"/>
            <path d="M22 2 15 22l-4-9-9-4 20-7z"/>
        </svg>
    }
}
