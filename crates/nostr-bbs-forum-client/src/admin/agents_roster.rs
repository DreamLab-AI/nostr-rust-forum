//! Admin agent-roster tab (F8, WP-5, ADR-106).
//!
//! The client screen for the agent roster the register found unmanageable: nine
//! `/api/governance/*` endpoints existed server-side (auth-worker) with no UI
//! calling any of them. This tab lists the roster and round-trips the roster
//! mutations through the matching endpoints via NIP-98-signed fetch, mirroring
//! the `admin/section_requests.rs` idiom (context captured at component level,
//! passed into the async action closures).
//!
//! Endpoints used (all on the auth-worker, `auth_api_base()`):
//! - `GET  /api/governance/agents`          — list the roster (any authed).
//! - `POST /api/governance/agents/register` — register/edit/reactivate (admin).
//!   `INSERT OR REPLACE … active = 1`, so it doubles as the rate-limit edit and
//!   the reactivate path.
//! - `POST /api/governance/agents/revoke`   — deactivate (`active = 0`, admin).
//!
//! The authorising principal (`registered_by`) is set server-side from the
//! NIP-98 signer, so the register form never sends it — the signing admin *is*
//! the principal. The form surfaces that principal read-only so the operator
//! sees whose authority the registration records (ADR-106 Decision 3).

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;

use crate::auth::nip98::{fetch_with_nip98_get_signer, fetch_with_nip98_post_signer};
use crate::auth::{use_auth, AuthStore};
use crate::components::toast::{use_toasts, ToastStore, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::utils::format_relative_time;

/// One `agent_registry` row as served by `GET /api/governance/agents`. The
/// numeric columns arrive as JSON numbers (D1 `REAL`), so they decode as `f64`,
/// matching the worker-side `AgentRow` shape.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AgentRosterEntry {
    pub pubkey: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub registered_by: String,
    #[serde(default)]
    pub registered_at: f64,
    #[serde(default = "default_rate")]
    pub rate_limit_per_min: f64,
    #[serde(default)]
    pub active: f64,
}

fn default_rate() -> f64 {
    60.0
}

impl AgentRosterEntry {
    /// The `active` flag as a bool (`1` → active, `0` → deactivated).
    pub fn is_active(&self) -> bool {
        self.active != 0.0
    }

    /// The per-minute rate limit as a whole number for display/edit.
    pub fn rate_limit(&self) -> u32 {
        self.rate_limit_per_min.max(0.0) as u32
    }
}

/// Pure parser for the `{ "agents": [ … ] }` roster response. Split out so the
/// decode + ordering contract is unit-testable without a browser or a live
/// endpoint, mirroring `governance_api::parse_decisions_query` server-side.
///
/// Orders active agents first, then by name, so a just-deactivated agent sinks
/// below the live roster rather than vanishing.
pub fn parse_agents(body: &str) -> Result<Vec<AgentRosterEntry>, String> {
    let val: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("roster parse: {e}"))?;
    let arr = val
        .get("agents")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "roster response missing `agents` array".to_string())?;
    let mut out: Vec<AgentRosterEntry> = arr
        .iter()
        .filter_map(|v| serde_json::from_value::<AgentRosterEntry>(v.clone()).ok())
        .collect();
    out.sort_by(|a, b| {
        b.is_active()
            .cmp(&a.is_active())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

fn roster_list_url() -> String {
    format!(
        "{}/api/governance/agents",
        crate::utils::relay_url::auth_api_base()
    )
}

fn register_url() -> String {
    format!(
        "{}/api/governance/agents/register",
        crate::utils::relay_url::auth_api_base()
    )
}

fn revoke_url() -> String {
    format!(
        "{}/api/governance/agents/revoke",
        crate::utils::relay_url::auth_api_base()
    )
}

/// Build the register body. `INSERT OR REPLACE … active = 1` server-side, so the
/// same call registers, edits the rate limit, and reactivates.
fn register_body(pubkey: &str, name: &str, description: &str, rate_limit_per_min: u32) -> String {
    serde_json::json!({
        "pubkey": pubkey,
        "name": name,
        "description": description,
        "rate_limit_per_min": rate_limit_per_min,
    })
    .to_string()
}

/// GET the roster with a NIP-98 signature and parse it.
async fn load_roster(auth: AuthStore) -> Result<Vec<AgentRosterEntry>, String> {
    let signer = auth
        .get_signer()
        .ok_or_else(|| "No signing key available — log in first".to_string())?;
    let body = fetch_with_nip98_get_signer(&roster_list_url(), &*signer)
        .await
        .map_err(|e| e.to_string())?;
    parse_agents(&body)
}

/// POST a roster mutation, then reload the roster so the tab reflects the change
/// without a manual refresh (F8 acceptance: the list reflects the mutation after
/// it returns). Both calls carry a fresh NIP-98 signature.
async fn mutate_then_reload(
    auth: AuthStore,
    url: String,
    body: String,
) -> Result<Vec<AgentRosterEntry>, String> {
    let signer = auth
        .get_signer()
        .ok_or_else(|| "No signing key available — log in first".to_string())?;
    fetch_with_nip98_post_signer(&url, &body, &*signer)
        .await
        .map_err(|e| e.to_string())?;
    load_roster(auth).await
}

/// Fire a GET reload into the roster signal.
fn reload(
    auth: AuthStore,
    toasts: ToastStore,
    roster: RwSignal<Vec<AgentRosterEntry>>,
    loading: RwSignal<bool>,
) {
    loading.set(true);
    spawn_local(async move {
        match load_roster(auth).await {
            Ok(list) => roster.set(list),
            Err(e) => toasts.show(format!("Failed to load roster: {e}"), ToastVariant::Error),
        }
        loading.set(false);
    });
}

/// Fire a mutation (POST) then reload, reporting the outcome via toast.
fn run_mutation(
    auth: AuthStore,
    toasts: ToastStore,
    roster: RwSignal<Vec<AgentRosterEntry>>,
    loading: RwSignal<bool>,
    url: String,
    body: String,
    success_msg: String,
) {
    loading.set(true);
    spawn_local(async move {
        match mutate_then_reload(auth, url, body).await {
            Ok(list) => {
                roster.set(list);
                toasts.show(success_msg, ToastVariant::Success);
            }
            Err(e) => toasts.show(format!("Action failed: {e}"), ToastVariant::Error),
        }
        loading.set(false);
    });
}

/// The agent-roster admin tab.
#[component]
pub fn AgentsRoster() -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();

    let roster = RwSignal::new(Vec::<AgentRosterEntry>::new());
    let loading = RwSignal::new(false);
    let loaded_once = RwSignal::new(false);

    // Register-form fields.
    let f_pubkey = RwSignal::new(String::new());
    let f_name = RwSignal::new(String::new());
    let f_desc = RwSignal::new(String::new());
    let f_rate = RwSignal::new(60u32);
    let form_err = RwSignal::new(Option::<String>::None);

    // The authorising principal recorded on a registration is the signing admin
    // (`registered_by = admin_pk`, server-side). Surface it read-only so the
    // operator sees whose authority the roster row will cite.
    let admin_pk = auth.pubkey().get_untracked().unwrap_or_default();
    let principal_name = use_display_name_memo(admin_pk.clone());

    // Initial load once a signer is available (mirrors AdminPanelInner's
    // signer-gated fetch — the admin flag arrives asynchronously after login).
    Effect::new(move |_| {
        if loaded_once.get_untracked() {
            return;
        }
        if auth.get_signer().is_none() {
            return;
        }
        loaded_once.set(true);
        reload(auth, toasts, roster, loading);
    });

    let on_register = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let pk = f_pubkey.get_untracked().trim().to_string();
        if pk.len() != 64 || !pk.chars().all(|c| c.is_ascii_hexdigit()) {
            form_err.set(Some("Pubkey must be 64 hex characters".into()));
            return;
        }
        let name = f_name.get_untracked().trim().to_string();
        if name.is_empty() {
            form_err.set(Some("Name is required".into()));
            return;
        }
        form_err.set(None);
        let desc = f_desc.get_untracked();
        let rate = f_rate.get_untracked();
        let body = register_body(&pk, &name, &desc, rate);
        run_mutation(
            auth,
            toasts,
            roster,
            loading,
            register_url(),
            body,
            format!("Registered agent {name}"),
        );
        f_pubkey.set(String::new());
        f_name.set(String::new());
        f_desc.set(String::new());
        f_rate.set(60);
    };

    let on_refresh = move |_| reload(auth, toasts, roster, loading);

    view! {
        <div class="space-y-6">
            // Register form
            <div class="bg-gray-800 border border-gray-700 rounded-lg p-6">
                <h3 class="text-lg font-semibold text-white mb-1 flex items-center gap-2">
                    {agent_icon()}
                    "Register Agent"
                </h3>
                <p class="text-xs text-gray-500 mb-4">
                    "Registers a "<span class="font-mono">"did:nostr"</span>" agent pubkey in the roster. "
                    "The same form edits an existing agent's rate limit and reactivates a deactivated one."
                </p>
                <form on:submit=on_register class="space-y-4">
                    <div class="space-y-1">
                        <label for="agent-pubkey" class="block text-sm font-medium text-gray-300">"Agent public key (hex)"</label>
                        <input
                            id="agent-pubkey"
                            type="text"
                            prop:value=move || f_pubkey.get()
                            on:input=move |ev| { f_pubkey.set(event_target_value(&ev)); form_err.set(None); }
                            placeholder="64-character hex public key"
                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white font-mono text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                        />
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="space-y-1">
                            <label for="agent-name" class="block text-sm font-medium text-gray-300">"Name"</label>
                            <input
                                id="agent-name"
                                type="text"
                                prop:value=move || f_name.get()
                                on:input=move |ev| f_name.set(event_target_value(&ev))
                                placeholder="scribe-bot"
                                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                        <div class="space-y-1">
                            <label for="agent-rate" class="block text-sm font-medium text-gray-300">"Rate limit (events/min)"</label>
                            <input
                                id="agent-rate"
                                type="number"
                                min="0"
                                prop:value=move || f_rate.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(v) = event_target_value(&ev).parse::<u32>() { f_rate.set(v); }
                                }
                                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                    </div>
                    <div class="space-y-1">
                        <label for="agent-desc" class="block text-sm font-medium text-gray-300">"Description"</label>
                        <input
                            id="agent-desc"
                            type="text"
                            prop:value=move || f_desc.get()
                            on:input=move |ev| f_desc.set(event_target_value(&ev))
                            placeholder="What this agent does"
                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                        />
                    </div>
                    // Authorising principal — derived server-side from the NIP-98
                    // signer (this admin). Read-only.
                    <div class="text-xs text-gray-500">
                        "Authorising principal: "
                        <span class="text-gray-300">{move || principal_name.get()}</span>
                        " (recorded as "<span class="font-mono">"registered_by"</span>" from your signature)"
                    </div>
                    {move || form_err.get().map(|msg| view! { <p class="text-red-400 text-sm">{msg}</p> })}
                    <button type="submit" disabled=move || loading.get()
                        class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors">
                        {move || if loading.get() { "Working…" } else { "Register Agent" }}
                    </button>
                </form>
            </div>

            // Roster table
            <div>
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-semibold text-white">"Agent Roster"</h3>
                    <div class="flex items-center gap-3">
                        <span class="text-xs text-gray-500">
                            {move || format!("{} agents", roster.get().len())}
                        </span>
                        <button on:click=on_refresh disabled=move || loading.get()
                            class="text-sm text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-3 py-1 transition-colors disabled:opacity-50">
                            {move || if loading.get() { "Refreshing…" } else { "Refresh" }}
                        </button>
                    </div>
                </div>

                {move || {
                    let list = roster.get();
                    if list.is_empty() {
                        return view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
                                <p class="text-gray-400 font-medium">"No agents registered"</p>
                                <p class="text-gray-500 text-sm mt-1">"Register an agent above to populate the roster."</p>
                            </div>
                        }.into_any();
                    }
                    view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-x-auto">
                            <div class="min-w-[720px]">
                                <div class="grid grid-cols-12 gap-2 px-4 py-2 border-b border-gray-700 text-xs font-medium text-gray-400 uppercase tracking-wider">
                                    <div class="col-span-3">"Agent"</div>
                                    <div class="col-span-3">"Authorised by"</div>
                                    <div class="col-span-2">"Rate/min"</div>
                                    <div class="col-span-2">"Status"</div>
                                    <div class="col-span-2 text-right">"Actions"</div>
                                </div>
                                {list.into_iter().map(|entry| {
                                    let entry_for_rate = entry.clone();
                                    let entry_for_toggle = entry.clone();
                                    let on_set_rate = move |new_rate: u32| {
                                        let e = &entry_for_rate;
                                        let body = register_body(&e.pubkey, &e.name, &e.description, new_rate);
                                        run_mutation(
                                            auth, toasts, roster, loading,
                                            register_url(), body,
                                            format!("Rate limit for {} set to {new_rate}/min", e.name),
                                        );
                                    };
                                    let on_toggle_active = move || {
                                        let e = &entry_for_toggle;
                                        if e.is_active() {
                                            let body = serde_json::json!({ "pubkey": e.pubkey }).to_string();
                                            run_mutation(
                                                auth, toasts, roster, loading,
                                                revoke_url(), body,
                                                format!("Deactivated {}", e.name),
                                            );
                                        } else {
                                            let body = register_body(&e.pubkey, &e.name, &e.description, e.rate_limit());
                                            run_mutation(
                                                auth, toasts, roster, loading,
                                                register_url(), body,
                                                format!("Reactivated {}", e.name),
                                            );
                                        }
                                    };
                                    view! {
                                        <RosterRow entry=entry on_set_rate=on_set_rate on_toggle_active=on_toggle_active loading=loading />
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    }.into_any()
                }}
            </div>
        </div>
    }
}

/// A single roster row: agent identity, authorising principal, an inline
/// rate-limit editor, the active/deactivated status, and the activate/deactivate
/// control.
#[component]
fn RosterRow<FR, FT>(
    entry: AgentRosterEntry,
    on_set_rate: FR,
    on_toggle_active: FT,
    loading: RwSignal<bool>,
) -> impl IntoView
where
    FR: Fn(u32) + 'static,
    FT: Fn() + 'static,
{
    let name = entry.name.clone();
    let pubkey = entry.pubkey.clone();
    let pk_short = crate::utils::shorten_pubkey(&entry.pubkey);
    let registered_at = entry.registered_at as u64;
    let active = entry.is_active();
    let principal = use_display_name_memo(entry.registered_by.clone());
    let rate_edit = RwSignal::new(entry.rate_limit());

    let status_class = if active {
        "text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded px-2 py-0.5"
    } else {
        "text-xs bg-gray-500/10 text-gray-400 border border-gray-500/20 rounded px-2 py-0.5"
    };
    let toggle_class = if active {
        "text-xs bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 hover:border-red-500/40 rounded px-2.5 py-1 transition-colors disabled:opacity-50"
    } else {
        "text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 hover:border-emerald-500/40 rounded px-2.5 py-1 transition-colors disabled:opacity-50"
    };
    let toggle_label = if active { "Deactivate" } else { "Activate" };
    let time_display = if registered_at > 0 {
        format_relative_time(registered_at)
    } else {
        String::new()
    };

    view! {
        <div class="grid grid-cols-12 gap-2 px-4 py-3 border-b border-gray-700/50 items-center text-sm">
            // Agent identity
            <div class="col-span-3 min-w-0">
                <div class="text-gray-200 font-medium truncate">{name}</div>
                <div class="text-xs text-gray-500 font-mono truncate" title=pubkey>{pk_short}</div>
            </div>
            // Authorising principal
            <div class="col-span-3 min-w-0">
                <div class="text-gray-300 truncate">{move || principal.get()}</div>
                {(!time_display.is_empty()).then(|| view! {
                    <div class="text-xs text-gray-500">{format!("since {time_display}")}</div>
                })}
            </div>
            // Rate limit editor
            <div class="col-span-2 flex items-center gap-1.5">
                <input
                    type="number"
                    min="0"
                    prop:value=move || rate_edit.get().to_string()
                    on:input=move |ev| {
                        if let Ok(v) = event_target_value(&ev).parse::<u32>() { rate_edit.set(v); }
                    }
                    class="w-16 bg-gray-900 border border-gray-600 rounded px-2 py-1 text-white text-xs focus:outline-none focus:border-amber-500"
                />
                <button
                    on:click=move |_| on_set_rate(rate_edit.get_untracked())
                    disabled=move || loading.get()
                    class="text-xs text-amber-400 hover:text-amber-300 border border-amber-500/20 hover:border-amber-400 rounded px-2 py-1 transition-colors disabled:opacity-50"
                    title="Save rate limit"
                >
                    "Save"
                </button>
            </div>
            // Status
            <div class="col-span-2">
                <span class=status_class>{if active { "active" } else { "deactivated" }}</span>
            </div>
            // Toggle action
            <div class="col-span-2 flex items-center justify-end">
                <button
                    on:click=move |_| on_toggle_active()
                    disabled=move || loading.get()
                    class=toggle_class
                    title=toggle_label
                >
                    {toggle_label}
                </button>
            </div>
        </div>
    }
}

fn agent_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="4" y="8" width="16" height="12" rx="2"/>
            <path d="M12 8V4"/>
            <circle cx="9" cy="14" r="1"/>
            <circle cx="15" cy="14" r="1"/>
        </svg>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    #[test]
    fn parses_and_orders_roster() {
        let body = format!(
            r#"{{"agents":[
                {{"pubkey":"{a}","name":"zeta","description":"d","registered_by":"{b}","registered_at":100.0,"rate_limit_per_min":30.0,"active":0.0}},
                {{"pubkey":"{b}","name":"alpha","description":"","registered_by":"{a}","registered_at":200.0,"rate_limit_per_min":60.0,"active":1.0}}
            ]}}"#,
            a = pk('a'),
            b = pk('b'),
        );
        let list = parse_agents(&body).expect("parses");
        assert_eq!(list.len(), 2);
        // Active first (alpha, active=1), then the deactivated zeta.
        assert_eq!(list[0].name, "alpha");
        assert!(list[0].is_active());
        assert_eq!(list[0].rate_limit(), 60);
        assert_eq!(list[1].name, "zeta");
        assert!(!list[1].is_active());
        assert_eq!(list[1].rate_limit(), 30);
    }

    #[test]
    fn missing_agents_array_is_error() {
        assert!(parse_agents(r#"{"nope":[]}"#).is_err());
        assert!(parse_agents("not json").is_err());
    }

    #[test]
    fn empty_roster_parses_to_empty_vec() {
        let list = parse_agents(r#"{"agents":[]}"#).expect("parses");
        assert!(list.is_empty());
    }

    #[test]
    fn register_body_carries_all_fields() {
        let body = register_body(&pk('c'), "scribe", "notes", 15);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["pubkey"], pk('c'));
        assert_eq!(v["name"], "scribe");
        assert_eq!(v["description"], "notes");
        assert_eq!(v["rate_limit_per_min"], 15);
    }

    #[test]
    fn rate_limit_defaults_when_absent() {
        let body = format!(
            r#"{{"agents":[{{"pubkey":"{a}","name":"n","registered_by":"{a}","active":1.0}}]}}"#,
            a = pk('a')
        );
        let list = parse_agents(&body).expect("parses");
        assert_eq!(list[0].rate_limit(), 60);
    }
}
