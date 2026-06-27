//! Agent Control Surface — governance dashboard.
//!
//! Renders agent-published panels (kind 31400-31405) as interactive control
//! surfaces. Each registered agent publishes PanelDefinition events that the
//! forum renders via meta-components: InboxTable, StatusBoard, DecisionCanvas,
//! ConfigForm.
//!
//! Panel data and action requests are sourced from the `PanelRegistry` reactive
//! store, which is fed by the relay governance subscription in `app.rs`.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::relay::RelayConnection;
use crate::stores::panel_registry::{use_panel_registry, ActionEntry, PanelEntry};
use wasm_bindgen_futures::spawn_local;

// ── Governance page component ────────────────────────────────────────────────

#[component]
pub fn GovernancePage() -> impl IntoView {
    let registry = use_panel_registry();
    let state = registry.state;

    let panels = Memo::new(move |_| {
        let s = state.read();
        let mut v: Vec<PanelEntry> = s.panels.values().cloned().collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.last_updated));
        v
    });

    let actions = Memo::new(move |_| {
        let s = state.read();
        let mut v = s.actions.clone();
        v.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        v
    });

    let panel_count = Memo::new(move |_| state.read().panels.len());
    let action_count = Memo::new(move |_| state.read().actions.len());

    view! {
        <div class="governance-page max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="governance-header mb-8">
                <h1 class="text-3xl font-bold text-white mb-2">"Agent Control Surface"</h1>
                <p class="text-gray-400">
                    "Interactive panels published by registered agents. Review decisions, monitor status, and respond to action requests."
                </p>
            </div>

            <div class="governance-stats grid grid-cols-3 gap-4 mb-8">
                <div class="bg-gray-800 rounded-lg p-4 text-center">
                    <span class="text-2xl font-bold text-amber-400 block">{move || panel_count.get()}</span>
                    <span class="text-gray-400 text-sm">"Active Panels"</span>
                </div>
                <div class="bg-gray-800 rounded-lg p-4 text-center">
                    <span class="text-2xl font-bold text-amber-400 block">{move || action_count.get()}</span>
                    <span class="text-gray-400 text-sm">"Pending Actions"</span>
                </div>
                <div class="bg-gray-800 rounded-lg p-4 text-center">
                    <span class="text-2xl font-bold text-amber-400 block">
                        {move || {
                            let s = state.read();
                            let agents: std::collections::HashSet<&str> =
                                s.panels.values().map(|p| p.agent_pubkey.as_str()).collect();
                            agents.len()
                        }}
                    </span>
                    <span class="text-gray-400 text-sm">"Registered Agents"</span>
                </div>
            </div>

            <Show
                when=move || action_count.get() != 0
                fallback=|| view! {
                    <div class="bg-gray-800/50 rounded-lg p-8 text-center mb-8">
                        <p class="text-gray-500">"No pending actions. Agents will publish action requests here when human review is needed."</p>
                    </div>
                }
            >
                <h2 class="text-xl font-semibold text-white mb-4">"Pending Actions"</h2>
                <div class="governance-inbox space-y-2 mb-8">
                    <For
                        each=move || actions.get()
                        key=|item| item.event_id.clone()
                        let:item
                    >
                        <ActionRow item=item />
                    </For>
                </div>
            </Show>

            <Show
                when=move || panel_count.get() != 0
                fallback=|| view! {
                    <div class="bg-gray-800/50 rounded-lg p-8 text-center">
                        <p class="text-gray-500">"No agent panels registered yet. Panels appear here when agents publish kind-31400 PanelDefinition events."</p>
                    </div>
                }
            >
                <h2 class="text-xl font-semibold text-white mb-4">"Agent Panels"</h2>
                <div class="governance-panels-grid grid grid-cols-1 md:grid-cols-2 gap-4">
                    <For
                        each=move || panels.get()
                        key=|panel| panel.d_tag.clone()
                        let:panel
                    >
                        <PanelCard panel=panel />
                    </For>
                </div>
            </Show>
        </div>
    }
}

// ── Panel card component ─────────────────────────────────────────────────────

#[component]
fn PanelCard(panel: PanelEntry) -> impl IntoView {
    let schema_str = format!("{:?}", panel.definition.schema);
    let schema_badge = match schema_str.as_str() {
        "ActionInbox" => "Inbox",
        "Dashboard" => "Dashboard",
        "ConfigForm" => "Config",
        "StatusBoard" => "Status",
        "ChatBridge" => "Chat",
        _ => "Panel",
    };
    let title = panel.definition.title.clone();
    let description = panel.definition.description.clone();
    // Resolve the publishing agent's name reactively through the shared profile
    // cache (display_name > name > NIP-05 > shortened pubkey). Fills in when the
    // agent's kind-0 metadata arrives instead of showing a raw hex pubkey.
    let agent_name =
        crate::components::user_display::use_display_name_memo(panel.agent_pubkey.clone());
    let field_count = panel.definition.fields.len();
    let action_count = panel.definition.actions.len();

    // Contexts resolved at construction (NOT inside the click handler — resolving
    // expect_context at event time risks "expected context" panics once the
    // reactive owner is gone). Panel action buttons publish a 31403 ActionResponse
    // keyed on the panel's own d-tag + definition event id, so a human can act
    // directly on a panel (the publishing agent subscribes to responses on its
    // panel d-tag), mirroring the ActionRow flow below.
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let relay = expect_context::<RelayConnection>();
    let panel_d_tag = panel.d_tag.clone();
    let panel_event_id = panel.event_id.clone();

    view! {
        <div class="panel-card bg-gray-800 rounded-lg p-5 border border-gray-700/50 hover:border-amber-400/30 transition-colors">
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-lg font-semibold text-white">{title}</h3>
                <span class="text-xs px-2 py-1 rounded-full bg-amber-400/10 text-amber-400 font-medium">{schema_badge}</span>
            </div>
            <p class="text-gray-400 text-sm mb-4">{description}</p>
            <div class="flex items-center gap-4 text-xs text-gray-500 mb-3">
                <span>{format!("{field_count} fields")}</span>
                <span>{format!("{action_count} actions")}</span>
                <span>{move || agent_name.get()}</span>
            </div>
            <div class="flex gap-2">
                {panel.definition.actions.iter().map(|action| {
                    let action_id = action.id.clone();
                    let label = action.label.clone();
                    let btn_class = match format!("{:?}", action.style).as_str() {
                        "Destructive" => "px-3 py-1.5 text-xs rounded bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-50",
                        "Primary" => "px-3 py-1.5 text-xs rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 transition-colors disabled:opacity-50",
                        _ => "px-3 py-1.5 text-xs rounded bg-gray-700 text-gray-300 border border-gray-600 hover:bg-gray-600 transition-colors disabled:opacity-50",
                    };
                    let loading = RwSignal::new(false);
                    let sent = RwSignal::new(false);
                    let on_click = {
                        let action_id = action_id.clone();
                        let d_tag = panel_d_tag.clone();
                        let event_id = panel_event_id.clone();
                        let relay = relay.clone();
                        move |_: web_sys::MouseEvent| {
                            if loading.get_untracked() || sent.get_untracked() {
                                return;
                            }
                            let pubkey = match auth.pubkey().get_untracked() {
                                Some(pk) => pk,
                                None => return,
                            };
                            loading.set(true);
                            let content = serde_json::json!({
                                "action": action_id,
                                "reasoning": format!("Human selected '{action_id}' on this panel via the governance UI"),
                            })
                            .to_string();
                            let now = (js_sys::Date::now() / 1000.0) as u64;
                            let unsigned = nostr_bbs_core::UnsignedEvent {
                                pubkey,
                                created_at: now,
                                kind: nostr_bbs_core::governance::KIND_ACTION_RESPONSE,
                                tags: vec![
                                    vec!["d".to_string(), d_tag.clone()],
                                    vec!["e".to_string(), event_id.clone()],
                                ],
                                content,
                            };
                            // Async sign so NIP-07 / extension users can respond.
                            let relay = relay.clone();
                            spawn_local(async move {
                                match auth.sign_event_async(unsigned).await {
                                    Ok(signed) => {
                                        relay.publish(&signed);
                                        sent.set(true);
                                        loading.set(false);
                                    }
                                    Err(e) => {
                                        web_sys::console::warn_1(
                                            &format!("[governance] panel action sign failed: {e}").into(),
                                        );
                                        loading.set(false);
                                    }
                                }
                            });
                        }
                    };
                    view! {
                        <button
                            class=btn_class
                            disabled=move || !is_authed.get() || loading.get() || sent.get()
                            on:click=on_click
                        >
                            {move || if sent.get() { "✓ Sent".to_string() }
                                else if loading.get() { "…".to_string() }
                                else { label.clone() }}
                        </button>
                    }
                }).collect_view()}
            </div>
        </div>
    }
}

// ── Action row component ─────────────────────────────────────────────────────

#[component]
fn ActionRow(item: ActionEntry) -> impl IntoView {
    let auth = use_auth();

    let priority_class = match item.priority.as_str() {
        "critical" => "bg-red-500/20 text-red-400 border-red-500/30",
        "high" => "bg-orange-500/20 text-orange-400 border-orange-500/30",
        "medium" => "bg-blue-500/20 text-blue-400 border-blue-500/30",
        "low" => "bg-gray-500/20 text-gray-400 border-gray-500/30",
        _ => "bg-gray-500/20 text-gray-400 border-gray-500/30",
    };

    let title_tag = nostr_bbs_core::governance::extract_tag(
        &item
            .d_tag
            .split('|')
            .map(|s| vec![s.to_string()])
            .collect::<Vec<_>>(),
        "title",
    )
    .map(|s| s.to_string())
    .unwrap_or_else(|| item.d_tag.clone());

    let reasoning = item.reasoning.clone().unwrap_or_default();
    let priority = item.priority.clone();
    let d_tag = item.d_tag.clone();
    let event_id = item.event_id.clone();
    // Resolve the requesting agent's name reactively (display_name > name >
    // NIP-05 > shortened pubkey). Re-renders when kind-0 metadata arrives.
    let agent_name =
        crate::components::user_display::use_display_name_memo(item.agent_pubkey.clone());

    let approve_loading = RwSignal::new(false);
    let reject_loading = RwSignal::new(false);
    let response_sent = RwSignal::new(false);

    let send_response = {
        let event_id = event_id.clone();
        let d_tag = d_tag.clone();
        move |action: &str, loading_sig: RwSignal<bool>| {
            let action = action.to_string();
            let event_id = event_id.clone();
            let d_tag = d_tag.clone();
            loading_sig.set(true);

            let auth = use_auth();
            let pubkey = match auth.pubkey().get_untracked() {
                Some(pk) => pk,
                None => {
                    loading_sig.set(false);
                    return;
                }
            };

            let content = serde_json::json!({
                "action": action,
                "reasoning": format!("Human {} via governance UI", action),
            })
            .to_string();

            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = nostr_bbs_core::UnsignedEvent {
                pubkey,
                created_at: now,
                kind: nostr_bbs_core::governance::KIND_ACTION_RESPONSE,
                tags: vec![
                    vec!["d".to_string(), d_tag],
                    vec!["e".to_string(), event_id],
                ],
                content,
            };

            // Async sign so NIP-07 / extension users can respond.
            let r = expect_context::<RelayConnection>();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        r.publish(&signed);
                        response_sent.set(true);
                        loading_sig.set(false);
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("[governance] Failed to sign action response: {e}").into(),
                        );
                        loading_sig.set(false);
                    }
                }
            });
        }
    };

    let on_approve = {
        let send = send_response.clone();
        move |_| send("approve", approve_loading)
    };
    let on_reject = {
        let send = send_response;
        move |_| send("reject", reject_loading)
    };

    let is_authed = auth.is_authenticated();

    view! {
        <div class="action-row bg-gray-800 rounded-lg p-4 border border-gray-700/50 flex items-center gap-4">
            <div class="flex-shrink-0">
                <span class={format!("inline-block px-2 py-1 text-xs font-medium rounded border {priority_class}")}>{priority}</span>
            </div>
            <div class="flex-1 min-w-0">
                <span class="text-white font-medium block truncate">{title_tag}</span>
                <span class="text-gray-500 text-xs block truncate">
                    {reasoning}" · "{move || agent_name.get()}
                </span>
            </div>
            <Show
                when=move || response_sent.get()
                fallback=move || view! {
                    <div class="flex gap-2 flex-shrink-0">
                        <button
                            class="px-3 py-1.5 text-xs rounded bg-green-500/10 text-green-400 border border-green-500/20 hover:bg-green-500/20 transition-colors disabled:opacity-50"
                            disabled=move || !is_authed.get() || approve_loading.get()
                            on:click=on_approve.clone()
                        >
                            {move || if approve_loading.get() { "..." } else { "Approve" }}
                        </button>
                        <button
                            class="px-3 py-1.5 text-xs rounded bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                            disabled=move || !is_authed.get() || reject_loading.get()
                            on:click=on_reject.clone()
                        >
                            {move || if reject_loading.get() { "..." } else { "Reject" }}
                        </button>
                    </div>
                }
            >
                <span class="text-green-400 text-xs font-medium">"Response sent"</span>
            </Show>
        </div>
    }
}
