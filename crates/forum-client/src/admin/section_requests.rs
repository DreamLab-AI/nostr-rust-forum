//! Admin section requests panel.
//!
//! Displays a table of pending kind-9021 join requests with Approve/Deny
//! actions. Approve adds the user to the requested cohort via the whitelist
//! API; Deny deletes the request event (kind-9005).

use leptos::prelude::*;
use nostr_core::NostrEvent;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;

use crate::admin::use_admin;
use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name;
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::utils::format_relative_time;

/// A parsed section access request from a kind-9021 event.
#[derive(Clone, Debug)]
struct SectionRequest {
    /// Event ID of the request.
    event_id: String,
    /// Pubkey of the requester.
    requester: String,
    /// Requested cohort name.
    cohort: String,
    /// Section display name.
    section_name: String,
    /// Section channel event ID.
    #[allow(dead_code)]
    section_id: String,
    /// Timestamp of the request.
    created_at: u64,
}

/// Admin panel component for managing section access requests.
#[component]
pub fn SectionRequests() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    // Capture context at component level — event handler closures lose reactive owner
    let auth = use_auth();
    let admin = use_admin();
    let toasts = use_toasts();
    let conn_state = relay.connection_state();

    let requests = RwSignal::new(Vec::<SectionRequest>::new());
    let loading = RwSignal::new(true);
    let sub_id: RwSignal<Option<String>> = RwSignal::new(None);

    let relay_for_sub = relay.clone();
    let relay_for_cleanup = relay.clone();

    // Subscribe to kind-9021 (join request) events
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if sub_id.get_untracked().is_some() {
            return;
        }

        loading.set(true);

        let filter = Filter {
            kinds: Some(vec![9021]),
            ..Default::default()
        };

        let reqs = requests;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind != 9021 {
                return;
            }

            let cohort = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "cohort")
                .map(|t| t[1].clone())
                .unwrap_or_default();

            let section_name = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "section")
                .map(|t| t[1].clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let section_id = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "e")
                .map(|t| t[1].clone())
                .unwrap_or_default();

            let req = SectionRequest {
                event_id: event.id.clone(),
                requester: event.pubkey.clone(),
                cohort,
                section_name,
                section_id,
                created_at: event.created_at,
            };

            reqs.update(|list| {
                if !list.iter().any(|r| r.event_id == req.event_id) {
                    list.push(req);
                    list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                }
            });
        });

        let loading_sig = loading;
        let on_eose = Rc::new(move || {
            loading_sig.set(false);
        });

        let id = relay_for_sub.subscribe(vec![filter], on_event, Some(on_eose));
        sub_id.set(Some(id));

        // 8-second timeout: if EOSE never arrives, stop showing the loading state
        let loading_timeout = loading;
        crate::utils::set_timeout_once(
            move || {
                if loading_timeout.get_untracked() {
                    loading_timeout.set(false);
                }
            },
            8_000,
        );
    });

    on_cleanup(move || {
        if let Some(id) = sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    view! {
        <div class="space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-white flex items-center gap-2">
                    {request_icon()}
                    "Section Access Requests"
                </h3>
                <span class="text-xs text-gray-500">
                    {move || format!("{} pending", requests.get().len())}
                </span>
            </div>

            <Show when=move || loading.get()>
                <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center animate-pulse">
                    <p class="text-gray-500">"Loading requests..."</p>
                </div>
            </Show>

            <Show when=move || !loading.get()>
                {
                    let admin = admin.clone();
                    let toasts = toasts.clone();
                    let relay = relay.clone();
                    move || {
                    let reqs = requests.get();
                    if reqs.is_empty() {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
                                <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-gray-700 flex items-center justify-center">
                                    <svg class="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                </div>
                                <p class="text-gray-400 font-medium">"No pending requests"</p>
                                <p class="text-gray-500 text-sm mt-1">"Section access requests will appear here."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                                // Table header
                                <div class="grid grid-cols-12 gap-2 px-4 py-2 border-b border-gray-700 text-xs font-medium text-gray-400 uppercase tracking-wider">
                                    <div class="col-span-3">"User"</div>
                                    <div class="col-span-3">"Section"</div>
                                    <div class="col-span-2">"Cohort"</div>
                                    <div class="col-span-2">"Requested"</div>
                                    <div class="col-span-2 text-right">"Actions"</div>
                                </div>

                                // Rows
                                {reqs.into_iter().map(|req| {
                                    let req_for_approve = req.clone();
                                    let req_for_deny = req.clone();
                                    let requests_sig = requests;
                                    let auth_a = auth;
                                    let admin_a = admin.clone();
                                    let toasts_a = toasts.clone();
                                    let relay_a = relay.clone();
                                    let auth_d = auth;
                                    let toasts_d = toasts.clone();
                                    let relay_d = relay.clone();

                                    view! {
                                        <RequestRow
                                            req=req
                                            on_approve=move || {
                                                approve_request(req_for_approve.clone(), requests_sig, auth_a, admin_a.clone(), toasts_a.clone(), relay_a.clone());
                                            }
                                            on_deny=move || {
                                                deny_request(req_for_deny.clone(), requests_sig, auth_d, toasts_d.clone(), relay_d.clone());
                                            }
                                        />
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
        </div>
    }
}

/// A single row in the requests table.
#[component]
fn RequestRow<FA, FD>(
    req: SectionRequest,
    on_approve: FA,
    on_deny: FD,
) -> impl IntoView
where
    FA: Fn() + 'static,
    FD: Fn() + 'static,
{
    let time_display = format_relative_time(req.created_at);
    let pk_short = use_display_name(&req.requester);

    view! {
        <div class="grid grid-cols-12 gap-2 px-4 py-3 border-b border-gray-700/50 hover:bg-gray-750 items-center text-sm">
            // User
            <div class="col-span-3 flex items-center gap-2 min-w-0">
                <div class="w-7 h-7 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0">
                    <svg class="w-3.5 h-3.5 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" stroke-linecap="round" stroke-linejoin="round"/>
                        <circle cx="12" cy="7" r="4" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <span class="text-gray-300 truncate font-mono text-xs" title=req.requester.clone()>
                    {pk_short}
                </span>
            </div>

            // Section
            <div class="col-span-3 text-gray-300 truncate">{req.section_name.clone()}</div>

            // Cohort
            <div class="col-span-2">
                <span class="text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded px-1.5 py-0.5">
                    {req.cohort.clone()}
                </span>
            </div>

            // Timestamp
            <div class="col-span-2 text-xs text-gray-500">{time_display}</div>

            // Actions
            <div class="col-span-2 flex items-center justify-end gap-2">
                <button
                    on:click=move |_| on_approve()
                    class="text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 hover:border-emerald-500/40 rounded px-2.5 py-1 transition-colors"
                    title="Approve request"
                >
                    "Approve"
                </button>
                <button
                    on:click=move |_| on_deny()
                    class="text-xs bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 hover:border-red-500/40 rounded px-2.5 py-1 transition-colors"
                    title="Deny request"
                >
                    "Deny"
                </button>
            </div>
        </div>
    }
}

/// Approve a request: add user to cohort via whitelist API, then remove from list.
///
/// All context (auth, admin, toasts, relay) must be captured at component level
/// and passed in — event handler closures lose the reactive owner in Leptos 0.7.
fn approve_request(
    req: SectionRequest,
    requests: RwSignal<Vec<SectionRequest>>,
    auth: crate::auth::AuthStore,
    admin: crate::admin::AdminStore,
    toasts: crate::components::toast::ToastStore,
    relay: RelayConnection,
) {
    let privkey = match auth.get_privkey_bytes() {
        Some(pk) => pk,
        None => {
            toasts.show("No private key available", ToastVariant::Error);
            return;
        }
    };

    let event_id = req.event_id.clone();
    let cohort = req.cohort.clone();
    let pk = req.requester.clone();
    let pk_display = crate::utils::shorten_pubkey(&pk);

    spawn_local(async move {
        // Add cohort to user's whitelist entry
        match admin.add_to_whitelist(&pk, &[cohort.clone()], &privkey).await {
            Ok(_) => {
                // Remove from pending list
                requests.update(|list| list.retain(|r| r.event_id != event_id));
                toasts.show(
                    format!("Approved: {} added to {}", pk_display, cohort),
                    ToastVariant::Success,
                );

                // Publish kind-9000 (add user to group) as confirmation
                if let Some(my_pk) = auth.pubkey().get_untracked() {
                    let now = (js_sys::Date::now() / 1000.0) as u64;
                    let unsigned = nostr_core::UnsignedEvent {
                        pubkey: my_pk,
                        created_at: now,
                        kind: 9000,
                        tags: vec![
                            vec!["p".to_string(), pk],
                            vec!["cohort".to_string(), cohort],
                        ],
                        content: "Approved section access request".to_string(),
                    };
                    let relay = relay.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Ok(signed) = auth.sign_event_async(unsigned).await {
                            relay.publish(&signed);
                        }
                    });
                }
            }
            Err(e) => {
                toasts.show(format!("Failed to approve: {}", e), ToastVariant::Error);
            }
        }
    });
}

/// Deny a request: publish kind-9005 (delete event) and remove from list.
///
/// All context must be captured at component level and passed in.
fn deny_request(
    req: SectionRequest,
    requests: RwSignal<Vec<SectionRequest>>,
    auth: crate::auth::AuthStore,
    toasts: crate::components::toast::ToastStore,
    relay: RelayConnection,
) {
    let pubkey = match auth.pubkey().get_untracked() {
        Some(pk) => pk,
        None => {
            toasts.show("Not authenticated", ToastVariant::Error);
            return;
        }
    };

    let now = (js_sys::Date::now() / 1000.0) as u64;

    // Kind 9005: Delete event in group (NIP-29)
    let unsigned = nostr_core::UnsignedEvent {
        pubkey,
        created_at: now,
        kind: 9005,
        tags: vec![vec!["e".to_string(), req.event_id.clone()]],
        content: "Denied section access request".to_string(),
    };

    let req_event_id = req.event_id.clone();
    wasm_bindgen_futures::spawn_local(async move {
        match auth.sign_event_async(unsigned).await {
            Ok(signed) => {
                relay.publish(&signed);
                requests.update(|list| list.retain(|r| r.event_id != req_event_id));
                toasts.show("Request denied", ToastVariant::Info);
            }
            Err(e) => {
                toasts.show(format!("Failed to deny: {}", e), ToastVariant::Error);
            }
        }
    });
}

fn request_icon() -> impl IntoView {
    view! {
        <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
            <circle cx="8.5" cy="7" r="4"/>
            <polyline points="17 11 19 13 23 9"/>
        </svg>
    }
}
