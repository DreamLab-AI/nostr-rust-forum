//! Admin settings tab -- fetch, display, and update forum settings.
//!
//! Settings are grouped by category and fetched from the relay `/api/settings`
//! endpoint. Changes are saved via NIP-98-authenticated POST. A localStorage
//! cache with 5-minute TTL avoids redundant fetches.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::auth::nip98::{fetch_with_nip98_get, fetch_with_nip98_post};
use crate::auth::use_auth;

// -- Types --------------------------------------------------------------------

/// A single setting entry from the API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettingEntry {
    pub key: String,
    pub value: String,
    pub category: String,
    #[serde(default)]
    pub description: String,
}

/// API response shape for GET /api/settings.
#[derive(Deserialize)]
struct SettingsResponse {
    settings: Vec<SettingEntry>,
}

/// Setting type for rendering the correct input widget.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SettingType {
    Text,
    Integer,
    Bool,
    Enum(&'static [&'static str]),
}

/// Definition for a known setting.
struct SettingDef {
    key: &'static str,
    label: &'static str,
    category: &'static str,
    setting_type: SettingType,
    default: &'static str,
}

const SETTING_DEFS: &[SettingDef] = &[
    // General
    SettingDef { key: "community_name", label: "Community Name", category: "General", setting_type: SettingType::Text, default: "Nostr BBS Community" },
    SettingDef { key: "community_description", label: "Community Description", category: "General", setting_type: SettingType::Text, default: "" },
    SettingDef { key: "welcome_message", label: "Welcome Message", category: "General", setting_type: SettingType::Text, default: "Welcome to the community!" },
    // Access
    SettingDef { key: "registration_mode", label: "Registration Mode", category: "Access", setting_type: SettingType::Enum(&["open", "invite", "closed"]), default: "invite" },
    SettingDef { key: "default_zone", label: "Default Zone", category: "Access", setting_type: SettingType::Enum(&["home", "members", "private"]), default: "home" },
    SettingDef { key: "auto_whitelist", label: "Auto-Whitelist New Users", category: "Access", setting_type: SettingType::Bool, default: "false" },
    // Moderation
    SettingDef { key: "auto_hide_threshold", label: "Auto-Hide Report Threshold", category: "Moderation", setting_type: SettingType::Integer, default: "3" },
    SettingDef { key: "max_post_length", label: "Max Post Length", category: "Moderation", setting_type: SettingType::Integer, default: "64000" },
    // Trust
    SettingDef { key: "tl1_days_active", label: "TL1: Days Active Required", category: "Trust", setting_type: SettingType::Integer, default: "3" },
    SettingDef { key: "tl1_posts_read", label: "TL1: Posts Read Required", category: "Trust", setting_type: SettingType::Integer, default: "10" },
    SettingDef { key: "tl1_posts_created", label: "TL1: Posts Created Required", category: "Trust", setting_type: SettingType::Integer, default: "1" },
    SettingDef { key: "tl2_days_active", label: "TL2: Days Active Required", category: "Trust", setting_type: SettingType::Integer, default: "14" },
    SettingDef { key: "tl2_posts_read", label: "TL2: Posts Read Required", category: "Trust", setting_type: SettingType::Integer, default: "50" },
    SettingDef { key: "tl2_posts_created", label: "TL2: Posts Created Required", category: "Trust", setting_type: SettingType::Integer, default: "10" },
    // Engagement
    SettingDef { key: "enable_reactions", label: "Enable Reactions", category: "Engagement", setting_type: SettingType::Bool, default: "true" },
    SettingDef { key: "enable_dms", label: "Enable Direct Messages", category: "Engagement", setting_type: SettingType::Bool, default: "true" },
    SettingDef { key: "enable_calendar", label: "Enable Calendar", category: "Engagement", setting_type: SettingType::Bool, default: "true" },
];

const CATEGORIES: &[&str] = &["General", "Access", "Moderation", "Trust", "Engagement"];

const CACHE_KEY: &str = "admin_settings_cache";
const CACHE_TTL_MS: f64 = 5.0 * 60.0 * 1000.0; // 5 minutes

// -- localStorage cache -------------------------------------------------------

fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
}

#[derive(Serialize, Deserialize)]
struct CachedSettings {
    settings: Vec<SettingEntry>,
    timestamp: f64,
}

fn load_cached_settings() -> Option<Vec<SettingEntry>> {
    let storage = get_local_storage()?;
    let raw = storage.get_item(CACHE_KEY).ok()??;
    let cached: CachedSettings = serde_json::from_str(&raw).ok()?;
    let now = js_sys::Date::now();
    if now - cached.timestamp > CACHE_TTL_MS {
        return None;
    }
    Some(cached.settings)
}

fn save_cached_settings(settings: &[SettingEntry]) {
    if let Some(storage) = get_local_storage() {
        let cached = CachedSettings {
            settings: settings.to_vec(),
            timestamp: js_sys::Date::now(),
        };
        if let Ok(json) = serde_json::to_string(&cached) {
            let _ = storage.set_item(CACHE_KEY, &json);
        }
    }
}

// -- Component ----------------------------------------------------------------

/// Admin settings tab. Fetches settings, displays grouped editors, saves changes.
#[component]
pub fn SettingsTab() -> impl IntoView {
    let auth = use_auth();

    let settings = RwSignal::new(Vec::<SettingEntry>::new());
    let is_loading = RwSignal::new(true);
    let is_saving = RwSignal::new(false);
    let save_error = RwSignal::new(Option::<String>::None);
    let save_success = RwSignal::new(Option::<String>::None);

    // Edited values keyed by setting key
    let edited = RwSignal::new(std::collections::HashMap::<String, String>::new());

    // Load settings on mount
    let auth_for_load = auth;
    Effect::new(move |_| {
        // Try cache first
        if let Some(cached) = load_cached_settings() {
            settings.set(cached);
            is_loading.set(false);
            return;
        }

        if let Some(privkey) = auth_for_load.get_privkey_bytes() {
            spawn_local(async move {
                let url = format!("{}/api/settings", crate::utils::relay_url::relay_api_base());
                match fetch_with_nip98_get(&url, &privkey).await {
                    Ok(body) => {
                        if let Ok(resp) = serde_json::from_str::<SettingsResponse>(&body) {
                            save_cached_settings(&resp.settings);
                            settings.set(resp.settings);
                        } else {
                            // API may not exist yet -- populate with defaults
                            let defaults: Vec<SettingEntry> = SETTING_DEFS
                                .iter()
                                .map(|d| SettingEntry {
                                    key: d.key.to_string(),
                                    value: d.default.to_string(),
                                    category: d.category.to_string(),
                                    description: String::new(),
                                })
                                .collect();
                            settings.set(defaults);
                        }
                    }
                    Err(_) => {
                        // Populate with defaults on fetch failure
                        let defaults: Vec<SettingEntry> = SETTING_DEFS
                            .iter()
                            .map(|d| SettingEntry {
                                key: d.key.to_string(),
                                value: d.default.to_string(),
                                category: d.category.to_string(),
                                description: String::new(),
                            })
                            .collect();
                        settings.set(defaults);
                    }
                }
                is_loading.set(false);
            });
        } else {
            is_loading.set(false);
        }
    });

    // Get current value for a setting (edited value takes precedence)
    let get_value = move |key: &str| -> String {
        let ed = edited.get();
        if let Some(v) = ed.get(key) {
            return v.clone();
        }
        settings
            .get()
            .iter()
            .find(|s| s.key == key)
            .map(|s| s.value.clone())
            .unwrap_or_default()
    };

    // Save handler
    let on_save = move |_| {
        let ed = edited.get_untracked();
        if ed.is_empty() {
            return;
        }
        if let Some(privkey) = auth.get_privkey_bytes() {
            is_saving.set(true);
            save_error.set(None);
            save_success.set(None);

            // Merge edited values into settings
            let mut current = settings.get_untracked();
            for (key, val) in &ed {
                if let Some(entry) = current.iter_mut().find(|s| s.key == *key) {
                    entry.value = val.clone();
                }
            }

            let body = serde_json::json!({ "settings": current });
            let body_json = serde_json::to_string(&body).unwrap_or_default();

            let settings_for_save = current.clone();
            spawn_local(async move {
                let url = format!("{}/api/settings", crate::utils::relay_url::relay_api_base());
                match fetch_with_nip98_post(&url, &body_json, &privkey).await {
                    Ok(_) => {
                        save_cached_settings(&settings_for_save);
                        settings.set(settings_for_save);
                        edited.set(std::collections::HashMap::new());
                        save_success.set(Some("Settings saved successfully".to_string()));
                        is_saving.set(false);
                    }
                    Err(e) => {
                        save_error.set(Some(format!("Failed to save: {}", e)));
                        is_saving.set(false);
                    }
                }
            });
        }
    };

    let has_changes = Signal::derive(move || !edited.get().is_empty());

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                    {settings_icon()}
                    "Forum Settings"
                </h2>
                <button
                    on:click=on_save
                    disabled=move || !has_changes.get() || is_saving.get()
                    class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm flex items-center gap-1.5"
                >
                    {move || if is_saving.get() { "Saving..." } else { "Save Changes" }}
                </button>
            </div>

            // Status messages
            {move || save_error.get().map(|msg| view! {
                <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 text-red-200 text-sm">
                    {msg}
                </div>
            })}
            {move || save_success.get().map(|msg| view! {
                <div class="bg-green-900/50 border border-green-700 rounded-lg px-4 py-3 text-green-200 text-sm">
                    {msg}
                </div>
            })}

            <Show
                when=move || !is_loading.get()
                fallback=|| view! {
                    <div class="space-y-4">
                        <SettingsSkeleton />
                        <SettingsSkeleton />
                        <SettingsSkeleton />
                    </div>
                }
            >
                {CATEGORIES.iter().map(|&category| {
                    let defs: Vec<&SettingDef> = SETTING_DEFS.iter().filter(|d| d.category == category).collect();
                    let cat_icon = category_icon(category);
                    view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                            <div class="px-6 py-4 border-b border-gray-700 flex items-center gap-2">
                                {cat_icon}
                                <h3 class="text-sm font-semibold text-gray-300 uppercase tracking-wider">{category}</h3>
                            </div>
                            <div class="divide-y divide-gray-700/50">
                                {defs.into_iter().map(|def| {
                                    let key = def.key.to_string();
                                    let label = def.label;
                                    let setting_type = def.setting_type;
                                    let default_val = def.default.to_string();
                                    let key_for_input = key.clone();

                                    let on_change = move |new_val: String| {
                                        edited.update(|map| {
                                            map.insert(key_for_input.clone(), new_val);
                                        });
                                    };

                                    let current_value = {
                                        let k = key.clone();
                                        Signal::derive(move || get_value(&k))
                                    };

                                    view! {
                                        <SettingRow
                                            label=label
                                            setting_type=setting_type
                                            value=current_value
                                            default_value=default_val
                                            on_change=on_change
                                        />
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    }
                }).collect_view()}
            </Show>
        </div>
    }
}

// -- Setting row component ----------------------------------------------------

#[component]
fn SettingRow(
    label: &'static str,
    setting_type: SettingType,
    value: Signal<String>,
    default_value: String,
    on_change: impl Fn(String) + 'static + Clone,
) -> impl IntoView {
    let input_class = "w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors";

    view! {
        <div class="px-6 py-4 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
            <div class="sm:w-1/3">
                <label class="text-sm font-medium text-gray-300">{label}</label>
                <p class="text-xs text-gray-500 mt-0.5">
                    "Default: "
                    <span class="text-gray-400">{default_value}</span>
                </p>
            </div>
            <div class="sm:w-2/3">
                {match setting_type {
                    SettingType::Text => {
                        let on_input = on_change.clone();
                        view! {
                            <input
                                type="text"
                                prop:value=move || value.get()
                                on:input=move |ev| {
                                    on_input(event_target_value(&ev));
                                }
                                class=input_class
                            />
                        }.into_any()
                    }
                    SettingType::Integer => {
                        let on_input = on_change.clone();
                        view! {
                            <input
                                type="number"
                                prop:value=move || value.get()
                                on:input=move |ev| {
                                    on_input(event_target_value(&ev));
                                }
                                class=input_class
                            />
                        }.into_any()
                    }
                    SettingType::Bool => {
                        let on_toggle = on_change.clone();
                        view! {
                            <label class="relative inline-flex items-center cursor-pointer">
                                <input
                                    type="checkbox"
                                    prop:checked=move || value.get() == "true"
                                    on:change=move |ev| {
                                        let checked = event_target_checked(&ev);
                                        on_toggle(if checked { "true".to_string() } else { "false".to_string() });
                                    }
                                    class="sr-only peer"
                                />
                                <div class="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-gray-400 after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-amber-500 peer-checked:after:bg-white"></div>
                            </label>
                        }.into_any()
                    }
                    SettingType::Enum(options) => {
                        let on_select = on_change.clone();
                        view! {
                            <select
                                prop:value=move || value.get()
                                on:change=move |ev| {
                                    on_select(event_target_value(&ev));
                                }
                                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            >
                                {options.iter().map(|&opt| {
                                    let opt_str = opt.to_string();
                                    let opt_val = opt_str.clone();
                                    view! {
                                        <option value=opt_val>{crate::utils::capitalize(&opt_str)}</option>
                                    }
                                }).collect_view()}
                            </select>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

// -- Helpers ------------------------------------------------------------------

fn event_target_checked(ev: &leptos::ev::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.checked())
        .unwrap_or(false)
}

#[component]
fn SettingsSkeleton() -> impl IntoView {
    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-6 animate-pulse">
            <div class="h-4 bg-gray-700 rounded w-24 mb-4"></div>
            <div class="space-y-3">
                <div class="h-8 bg-gray-700 rounded"></div>
                <div class="h-8 bg-gray-700 rounded"></div>
                <div class="h-8 bg-gray-700 rounded"></div>
            </div>
        </div>
    }
}

// -- Icons --------------------------------------------------------------------

fn settings_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/>
        </svg>
    }
}

fn category_icon(category: &str) -> impl IntoView {
    match category {
        "General" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        }.into_any(),
        "Access" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0110 0v4"/>
            </svg>
        }.into_any(),
        "Moderation" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        }.into_any(),
        "Trust" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
        }.into_any(),
        _ => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
        }.into_any(),
    }
}
