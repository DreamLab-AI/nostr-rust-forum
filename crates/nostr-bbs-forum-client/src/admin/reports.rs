//! Moderation reports tab -- view and resolve pending content reports.
//!
//! Fetches reports from `/api/reports?status=pending` and provides action
//! buttons (dismiss, hide, delete, warn) that resolve reports via NIP-98
//! authenticated POST to `/api/reports/resolve`.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::auth::nip98::{fetch_with_nip98_get, fetch_with_nip98_post};
use crate::auth::use_auth;

// -- Types --------------------------------------------------------------------

/// A moderation report from the API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub event_id: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub reporter_pubkey: String,
    #[serde(default)]
    pub reporter_name: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub report_count: u32,
    #[serde(default)]
    pub status: String,
}

#[derive(Deserialize)]
struct ReportsResponse {
    reports: Vec<Report>,
}

/// Resolution action for a report.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ReportAction {
    Dismiss,
    Hide,
    Delete,
    Warn,
}

impl ReportAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::Hide => "hide",
            Self::Delete => "delete",
            Self::Warn => "warn",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Dismiss => "Dismiss",
            Self::Hide => "Hide",
            Self::Delete => "Delete",
            Self::Warn => "Warn User",
        }
    }

    fn button_class(&self) -> &'static str {
        match self {
            Self::Dismiss => "text-xs text-gray-400 hover:text-gray-200 border border-gray-600 hover:border-gray-500 rounded px-2 py-1 transition-colors",
            Self::Hide => "text-xs text-yellow-400 hover:text-yellow-300 border border-yellow-500/30 hover:border-yellow-400 rounded px-2 py-1 transition-colors",
            Self::Delete => "text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors",
            Self::Warn => "text-xs text-orange-400 hover:text-orange-300 border border-orange-500/30 hover:border-orange-400 rounded px-2 py-1 transition-colors",
        }
    }
}

// -- Component ----------------------------------------------------------------

/// Reports/moderation queue tab.
#[component]
pub fn ReportsTab() -> impl IntoView {
    let auth = use_auth();

    let reports = RwSignal::new(Vec::<Report>::new());
    let is_loading = RwSignal::new(true);
    let action_error = RwSignal::new(Option::<String>::None);
    let action_success = RwSignal::new(Option::<String>::None);

    // Load pending reports
    let auth_for_load = auth;
    Effect::new(move |_| {
        if let Some(privkey) = auth_for_load.get_privkey_bytes() {
            spawn_local(async move {
                let url = format!(
                    "{}/api/reports?status=pending",
                    crate::utils::relay_url::relay_api_base()
                );
                match fetch_with_nip98_get(&url, &privkey).await {
                    Ok(body) => {
                        if let Ok(resp) = serde_json::from_str::<ReportsResponse>(&body) {
                            reports.set(resp.reports);
                        }
                    }
                    Err(_) => {
                        // API may not exist yet -- show empty state
                    }
                }
                is_loading.set(false);
            });
        } else {
            is_loading.set(false);
        }
    });

    let resolve_report = move |report_id: String, event_id: String, action: ReportAction| {
        if let Some(privkey) = auth.get_privkey_bytes() {
            action_error.set(None);
            action_success.set(None);

            let body = serde_json::json!({
                "report_id": report_id,
                "event_id": event_id,
                "action": action.as_str(),
            });
            let body_json = serde_json::to_string(&body).unwrap_or_default();
            let action_label = action.label().to_string();
            let rid = report_id.clone();

            spawn_local(async move {
                let url = format!(
                    "{}/api/reports/resolve",
                    crate::utils::relay_url::relay_api_base()
                );
                match fetch_with_nip98_post(&url, &body_json, &privkey).await {
                    Ok(_) => {
                        // Remove resolved report from list
                        reports.update(|list| {
                            list.retain(|r| r.id != rid);
                        });
                        action_success.set(Some(format!("Report resolved: {}", action_label)));
                    }
                    Err(e) => {
                        action_error.set(Some(format!("Failed to resolve: {}", e)));
                    }
                }
            });
        }
    };

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                    {flag_icon()}
                    "Moderation Queue"
                </h2>
                <span class="text-sm text-gray-400">
                    {move || {
                        let count = reports.get().len();
                        format!("{} pending", count)
                    }}
                </span>
            </div>

            // Status messages
            {move || action_error.get().map(|msg| view! {
                <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 text-red-200 text-sm">{msg}</div>
            })}
            {move || action_success.get().map(|msg| view! {
                <div class="bg-green-900/50 border border-green-700 rounded-lg px-4 py-3 text-green-200 text-sm">{msg}</div>
            })}

            <Show
                when=move || !is_loading.get()
                fallback=|| view! {
                    <div class="space-y-3">
                        <ReportSkeleton />
                        <ReportSkeleton />
                        <ReportSkeleton />
                    </div>
                }
            >
                {move || {
                    let report_list = reports.get();
                    if report_list.is_empty() {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                                {check_circle_icon()}
                                <p class="text-gray-400 mt-3 text-sm">"No pending reports. The community is behaving well."</p>
                            </div>
                        }.into_any()
                    } else {
                        let resolve = resolve_report.clone();
                        view! {
                            <div class="space-y-3">
                                {report_list.into_iter().map(move |report| {
                                    let resolve = resolve.clone();
                                    view! { <ReportCard report=report resolve=resolve /> }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
        </div>
    }
}

// -- Report card --------------------------------------------------------------

#[component]
fn ReportCard(
    report: Report,
    resolve: impl Fn(String, String, ReportAction) + Clone + 'static,
) -> impl IntoView {
    let reporter_display = report
        .reporter_name
        .clone()
        .unwrap_or_else(|| truncate_pk(&report.reporter_pubkey));
    let timestamp = format_timestamp(report.created_at);
    let report_count = report.report_count;
    let content_preview = if report.content.len() > 200 {
        format!("{}...", &report.content[..200])
    } else {
        report.content.clone()
    };

    let rid = report.id.clone();
    let eid = report.event_id.clone();

    let make_action = move |action: ReportAction| {
        let resolve = resolve.clone();
        let rid = rid.clone();
        let eid = eid.clone();
        move |_| {
            resolve(rid.clone(), eid.clone(), action);
        }
    };

    let on_dismiss = make_action(ReportAction::Dismiss);
    let on_hide = make_action(ReportAction::Hide);
    let on_delete = make_action(ReportAction::Delete);
    let on_warn = make_action(ReportAction::Warn);

    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors">
            // Header: reporter, timestamp, count
            <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-3">
                    <span class="text-sm text-gray-300 font-medium">"Reported by: "</span>
                    <span class="text-sm text-amber-300 font-mono">{reporter_display}</span>
                </div>
                <div class="flex items-center gap-3">
                    {(report_count > 1).then(|| view! {
                        <span class="bg-red-500/20 text-red-300 text-xs rounded-full px-2 py-0.5 border border-red-500/30">
                            {format!("{} reports", report_count)}
                        </span>
                    })}
                    <span class="text-xs text-gray-500">{timestamp}</span>
                </div>
            </div>

            // Reason
            {(!report.reason.is_empty()).then(|| view! {
                <div class="mb-3">
                    <span class="text-xs text-gray-500 uppercase tracking-wider">"Reason: "</span>
                    <span class="text-sm text-gray-300">{report.reason.clone()}</span>
                </div>
            })}

            // Content preview
            <div class="bg-gray-900 rounded-lg p-3 mb-3 border-l-2 border-gray-600">
                <p class="text-sm text-gray-300 whitespace-pre-wrap break-words">{content_preview}</p>
            </div>

            // Action buttons
            <div class="flex items-center gap-2 justify-end">
                <button on:click=on_dismiss class=ReportAction::Dismiss.button_class()>
                    {ReportAction::Dismiss.label()}
                </button>
                <button on:click=on_hide class=ReportAction::Hide.button_class()>
                    {ReportAction::Hide.label()}
                </button>
                <button on:click=on_delete class=ReportAction::Delete.button_class()>
                    {ReportAction::Delete.label()}
                </button>
                <button on:click=on_warn class=ReportAction::Warn.button_class()>
                    {ReportAction::Warn.label()}
                </button>
            </div>
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
        return "Unknown".to_string();
    }
    let date = js_sys::Date::new_0();
    date.set_time((ts as f64) * 1000.0);
    let month = date.get_month() + 1;
    let day = date.get_date();
    let hours = date.get_hours();
    let minutes = date.get_minutes();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        date.get_full_year(),
        month,
        day,
        hours,
        minutes
    )
}

#[component]
fn ReportSkeleton() -> impl IntoView {
    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 animate-pulse">
            <div class="h-4 bg-gray-700 rounded w-48 mb-3"></div>
            <div class="h-16 bg-gray-700 rounded mb-3"></div>
            <div class="flex gap-2 justify-end">
                <div class="h-6 bg-gray-700 rounded w-16"></div>
                <div class="h-6 bg-gray-700 rounded w-16"></div>
                <div class="h-6 bg-gray-700 rounded w-16"></div>
            </div>
        </div>
    }
}

// -- Icons --------------------------------------------------------------------

fn flag_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>
            <line x1="4" y1="22" x2="4" y2="15"/>
        </svg>
    }
}

fn check_circle_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-12 h-12 text-green-500/50 mx-auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
    }
}
