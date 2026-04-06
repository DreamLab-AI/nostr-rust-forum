//! Admin audit log tab -- displays a history of admin actions.
//!
//! Fetches from `/api/admin/audit-log?limit=50` with NIP-98 auth and renders
//! a filterable table of admin actions (suspend, silence, delete, whitelist, etc.).

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::auth::nip98::fetch_with_nip98_get;
use crate::auth::use_auth;

// -- Types --------------------------------------------------------------------

/// A single audit log entry from the API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: u64,
    #[serde(default)]
    pub actor_pubkey: String,
    #[serde(default)]
    pub actor_name: Option<String>,
    pub action: String,
    #[serde(default)]
    pub target_pubkey: Option<String>,
    #[serde(default)]
    pub target_name: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
}

#[derive(Deserialize)]
struct AuditLogResponse {
    entries: Vec<AuditEntry>,
}

/// Known action types for filtering.
const ACTION_TYPES: &[(&str, &str)] = &[
    ("all", "All Actions"),
    ("suspend", "Suspend"),
    ("unsuspend", "Unsuspend"),
    ("silence", "Silence"),
    ("unsilence", "Unsilence"),
    ("delete_event", "Delete Event"),
    ("hide_event", "Hide Event"),
    ("whitelist_add", "Whitelist Add"),
    ("whitelist_remove", "Whitelist Remove"),
    ("cohort_update", "Cohort Update"),
    ("admin_grant", "Admin Grant"),
    ("admin_revoke", "Admin Revoke"),
    ("settings_update", "Settings Update"),
];

// -- Component ----------------------------------------------------------------

/// Audit log tab. Shows paginated, filterable admin action history.
#[component]
pub fn AuditLogTab() -> impl IntoView {
    let auth = use_auth();

    let entries = RwSignal::new(Vec::<AuditEntry>::new());
    let is_loading = RwSignal::new(true);
    let filter_action = RwSignal::new("all".to_string());

    // Load audit log
    let auth_for_load = auth;
    Effect::new(move |_| {
        if let Some(privkey) = auth_for_load.get_privkey_bytes() {
            spawn_local(async move {
                let url = format!(
                    "{}/api/admin/audit-log?limit=50",
                    crate::utils::relay_url::relay_api_base()
                );
                match fetch_with_nip98_get(&url, &privkey).await {
                    Ok(body) => {
                        if let Ok(resp) = serde_json::from_str::<AuditLogResponse>(&body) {
                            entries.set(resp.entries);
                        }
                    }
                    Err(_) => {
                        // API may not exist yet
                    }
                }
                is_loading.set(false);
            });
        } else {
            is_loading.set(false);
        }
    });

    let filtered_entries = Signal::derive(move || {
        let filter = filter_action.get();
        let all = entries.get();
        if filter == "all" {
            all
        } else {
            all.into_iter().filter(|e| e.action == filter).collect()
        }
    });

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between flex-wrap gap-3">
                <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                    {log_icon()}
                    "Audit Log"
                </h2>

                // Filter dropdown
                <div class="flex items-center gap-2">
                    <label class="text-sm text-gray-400">"Filter:"</label>
                    <select
                        prop:value=move || filter_action.get()
                        on:change=move |ev| {
                            filter_action.set(event_target_value(&ev));
                        }
                        class="bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-amber-500 transition-colors"
                    >
                        {ACTION_TYPES.iter().map(|&(value, label)| {
                            let val = value.to_string();
                            view! {
                                <option value=val>{label}</option>
                            }
                        }).collect_view()}
                    </select>
                </div>
            </div>

            <Show
                when=move || !is_loading.get()
                fallback=|| view! {
                    <div class="space-y-2">
                        <AuditEntrySkeleton />
                        <AuditEntrySkeleton />
                        <AuditEntrySkeleton />
                        <AuditEntrySkeleton />
                        <AuditEntrySkeleton />
                    </div>
                }
            >
                {move || {
                    let list = filtered_entries.get();
                    if list.is_empty() {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                                <p class="text-gray-500 text-sm">"No audit log entries found."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                                // Header
                                <div class="grid grid-cols-12 gap-2 px-4 py-3 border-b border-gray-700 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                    <div class="col-span-2">"Time"</div>
                                    <div class="col-span-2">"Actor"</div>
                                    <div class="col-span-2">"Action"</div>
                                    <div class="col-span-2">"Target"</div>
                                    <div class="col-span-4">"Details"</div>
                                </div>

                                // Rows
                                <div class="divide-y divide-gray-700/50">
                                    {list.into_iter().map(|entry| {
                                        view! { <AuditRow entry=entry /> }
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
        </div>
    }
}

// -- Audit row ----------------------------------------------------------------

#[component]
fn AuditRow(entry: AuditEntry) -> impl IntoView {
    let timestamp = format_timestamp(entry.timestamp);
    let actor = entry
        .actor_name
        .clone()
        .unwrap_or_else(|| truncate_pk(&entry.actor_pubkey));
    let target = entry
        .target_name
        .clone()
        .or_else(|| entry.target_pubkey.as_ref().map(|pk| truncate_pk(pk)))
        .unwrap_or_else(|| "-".to_string());
    let details_raw = entry.details.clone().unwrap_or_default();
    let details = details_raw.clone();
    let details_title = details_raw;
    let action_badge = action_badge_class(&entry.action);
    let action_label = entry.action.replace('_', " ");

    view! {
        <div class="grid grid-cols-12 gap-2 px-4 py-3 items-center text-sm hover:bg-gray-750 transition-colors">
            <div class="col-span-2 text-xs text-gray-500 font-mono">{timestamp}</div>
            <div class="col-span-2 text-gray-300 truncate" title=entry.actor_pubkey.clone()>{actor}</div>
            <div class="col-span-2">
                <span class=action_badge>{crate::utils::capitalize(&action_label)}</span>
            </div>
            <div class="col-span-2 text-gray-400 truncate font-mono text-xs"
                title=entry.target_pubkey.unwrap_or_default()
            >
                {target}
            </div>
            <div class="col-span-4 text-gray-500 text-xs truncate" title=details_title>{details}</div>
        </div>
    }
}

// -- Helpers ------------------------------------------------------------------

fn truncate_pk(pk: &str) -> String {
    if pk.len() <= 16 {
        return pk.to_string();
    }
    format!("{}...{}", &pk[..8], &pk[pk.len() - 4..])
}

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "-".to_string();
    }
    let date = js_sys::Date::new_0();
    date.set_time((ts as f64) * 1000.0);
    let month = date.get_month() + 1;
    let day = date.get_date();
    let hours = date.get_hours();
    let minutes = date.get_minutes();
    format!(
        "{:02}-{:02} {:02}:{:02}",
        month, day, hours, minutes
    )
}

fn action_badge_class(action: &str) -> &'static str {
    match action {
        "suspend" | "delete_event" => {
            "inline-block text-xs rounded px-1.5 py-0.5 bg-red-500/20 text-red-300 border border-red-500/30"
        }
        "unsuspend" | "unsilence" | "whitelist_add" => {
            "inline-block text-xs rounded px-1.5 py-0.5 bg-green-500/20 text-green-300 border border-green-500/30"
        }
        "silence" | "hide_event" => {
            "inline-block text-xs rounded px-1.5 py-0.5 bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
        }
        "admin_grant" | "admin_revoke" => {
            "inline-block text-xs rounded px-1.5 py-0.5 bg-purple-500/20 text-purple-300 border border-purple-500/30"
        }
        "settings_update" => {
            "inline-block text-xs rounded px-1.5 py-0.5 bg-blue-500/20 text-blue-300 border border-blue-500/30"
        }
        _ => {
            "inline-block text-xs rounded px-1.5 py-0.5 bg-gray-500/20 text-gray-300 border border-gray-500/30"
        }
    }
}

#[component]
fn AuditEntrySkeleton() -> impl IntoView {
    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 animate-pulse">
            <div class="flex gap-4">
                <div class="h-4 bg-gray-700 rounded w-20"></div>
                <div class="h-4 bg-gray-700 rounded w-24"></div>
                <div class="h-4 bg-gray-700 rounded w-16"></div>
                <div class="h-4 bg-gray-700 rounded w-24"></div>
                <div class="h-4 bg-gray-700 rounded flex-1"></div>
            </div>
        </div>
    }
}

// -- Icons --------------------------------------------------------------------

fn log_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
            <polyline points="10 9 9 9 8 9"/>
        </svg>
    }
}
