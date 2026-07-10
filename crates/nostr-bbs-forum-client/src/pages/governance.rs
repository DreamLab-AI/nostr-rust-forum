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
use leptos_router::components::A;
use std::rc::Rc;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::agent_badge::AgentBadge;
use crate::relay::RelayConnection;
use crate::stores::panel_registry::{use_panel_registry, ActionEntry, DecisionView, PanelEntry};
use crate::stores::zone_access::use_zone_access;
use wasm_bindgen_futures::spawn_local;

// ── Governance page component ────────────────────────────────────────────────

/// The Agent Control Surface.
///
/// The surface is split by ROUTE, not by conditional render (ADR-106 Decision 2,
/// F1). `member_view = true` is mounted only at the auth-only `/governance`
/// member route (`MemberGatedGovernance`); it renders [`ReadOnlyPanelCard`] and
/// [`ReadOnlyActionRow`], neither of which compiles in a 31403 publish path — so
/// an ordinary member's client never mounts a response control. The admin write
/// surface (`member_view = false`, the default) lives at the distinct
/// `/governance/admin` route behind `AdminGatedGovernance`, where [`PanelCard`]
/// and [`ActionRow`] carry the Approve/Reject/action controls.
///
/// `member_view` also drives the F7 approval-fatigue filter: the member surface
/// suppresses `low` risk-tier action requests. Suppression is a **view filter** —
/// the events remain in the store, stay visible on the admin surface, and are
/// readable through the decisions read API (ADR-106 Decision 4).
#[component]
pub fn GovernancePage(#[prop(default = false)] member_view: bool) -> impl IntoView {
    let registry = use_panel_registry();
    let state = registry.state;

    // An admin who lands on the read-only member route gets a link across to the
    // write surface. Rendering a navigation link is not a write handler, so the
    // member component tree still mounts no publish path.
    let zone_access = use_zone_access();
    let is_admin = Memo::new(move |_| zone_access.is_admin.get());

    let panels = Memo::new(move |_| {
        let s = state.read();
        let mut v: Vec<PanelEntry> = s.panels.values().cloned().collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.last_updated));
        v
    });

    let actions = Memo::new(move |_| {
        let s = state.read();
        let mut v: Vec<ActionEntry> = s
            .actions
            .iter()
            .filter(|a| !member_view || a.is_member_visible())
            .cloned()
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        v
    });

    let panel_count = Memo::new(move |_| state.read().panels.len());
    // Count only the requests this surface renders, so the stat and the
    // empty-state gate agree with the F7 member suppression.
    let action_count = Memo::new(move |_| {
        state
            .read()
            .actions
            .iter()
            .filter(|a| !member_view || a.is_member_visible())
            .count()
    });

    view! {
        <div class="governance-page max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="governance-header mb-8">
                <h1 class="text-3xl font-bold text-white mb-2">"Agent Control Surface"</h1>
                {move || if member_view {
                    view! {
                        <p class="text-gray-400">
                            "Panels published by registered agents, with their outcomes. This is a read-only view — administrators respond to action requests."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <p class="text-gray-400">
                            "Interactive panels published by registered agents. Review decisions, monitor status, and respond to action requests."
                        </p>
                    }.into_any()
                }}
                // An admin viewing the read-only member route gets a link to the
                // distinct admin write surface (`/governance/admin`).
                {move || (member_view && is_admin.get()).then(|| view! {
                    <A
                        href=base_href("/governance/admin")
                        attr:class="inline-flex items-center gap-1.5 mt-3 text-sm px-3 py-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 transition-colors"
                    >
                        "Open admin controls →"
                    </A>
                })}
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
                        // Route-split (ADR-106 Decision 2): the member surface
                        // mounts a read-only row with no publish path; the admin
                        // surface mounts the writable ActionRow.
                        {if member_view {
                            view! { <ReadOnlyActionRow item=item /> }.into_any()
                        } else {
                            view! { <ActionRow item=item /> }.into_any()
                        }}
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
                        // Route-split (ADR-106 Decision 2): read-only card for the
                        // member surface, writable card for the admin surface.
                        {if member_view {
                            view! { <ReadOnlyPanelCard panel=panel /> }.into_any()
                        } else {
                            view! { <PanelCard panel=panel /> }.into_any()
                        }}
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
    // Disclosure badge (COM-13/F2): names the authorising principal when this
    // panel's publisher is an active registered agent.
    let agent_badge_pubkey = panel.agent_pubkey.clone();
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
    // F6: supersession history for this panel's case (DDD §7a.3).
    let history_d_tag = panel.d_tag.clone();

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
                <AgentBadge pubkey=agent_badge_pubkey compact=true />
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
                    // F4: relay-rejection state. The publish state advances to
                    // `sent` only on a relay OK; a rejection re-enables the
                    // control for a retry instead of reading as sent.
                    let rejected = RwSignal::new(false);
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
                            rejected.set(false);
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
                                        // F4: advance to Sent only on a relay OK;
                                        // a rejection (accepted = false) surfaces
                                        // as retryable, never as sent.
                                        let ack: crate::relay::PublishCallback =
                                            Rc::new(move |accepted: bool, message: String| {
                                                loading.set(false);
                                                if accepted {
                                                    sent.set(true);
                                                } else {
                                                    rejected.set(true);
                                                    web_sys::console::warn_1(
                                                        &format!("[governance] panel action rejected by relay: {message}").into(),
                                                    );
                                                }
                                            });
                                        if let Err(e) = relay.publish_with_ack(&signed, Some(ack)) {
                                            web_sys::console::warn_1(
                                                &format!("[governance] panel action publish failed: {e}").into(),
                                            );
                                            loading.set(false);
                                            rejected.set(true);
                                        }
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
                                else if rejected.get() { "⚠ Retry".to_string() }
                                else { label.clone() }}
                        </button>
                    }
                }).collect_view()}
            </div>
            <SupersessionHistory d_tag=history_d_tag />
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
    // F6: supersession history for this action's case (DDD §7a.3).
    let history_d_tag = item.d_tag.clone();
    let event_id = item.event_id.clone();
    // F5: the agent's stated confidence + risk tier, shown at decision time so a
    // human sees them before responding. Sourced from the 31402 ActionRequest.
    let confidence = item.confidence;
    let risk_tier = item.risk_tier.clone();
    // Resolve the requesting agent's name reactively (display_name > name >
    // NIP-05 > shortened pubkey). Re-renders when kind-0 metadata arrives.
    let agent_name =
        crate::components::user_display::use_display_name_memo(item.agent_pubkey.clone());
    // Disclosure badge (COM-13/F2): names the authorising principal when the
    // requesting agent is active in the registry.
    let agent_badge_pubkey = item.agent_pubkey.clone();

    let approve_loading = RwSignal::new(false);
    let reject_loading = RwSignal::new(false);
    let response_sent = RwSignal::new(false);
    // F4: relay-rejection state. `response_sent` advances only on a relay OK; a
    // rejection re-shows the controls (retryable) rather than reading as sent.
    let response_rejected = RwSignal::new(false);

    let send_response = {
        let event_id = event_id.clone();
        let d_tag = d_tag.clone();
        move |action: &str, loading_sig: RwSignal<bool>| {
            let action = action.to_string();
            let event_id = event_id.clone();
            let d_tag = d_tag.clone();
            loading_sig.set(true);
            response_rejected.set(false);

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
                        // F4: advance to "Response sent" only when the relay
                        // acknowledges with OK; a rejection surfaces as retryable.
                        let ack: crate::relay::PublishCallback = Rc::new(
                            move |accepted: bool, message: String| {
                                loading_sig.set(false);
                                if accepted {
                                    response_sent.set(true);
                                } else {
                                    response_rejected.set(true);
                                    web_sys::console::warn_1(
                                        &format!("[governance] action response rejected by relay: {message}").into(),
                                    );
                                }
                            },
                        );
                        if let Err(e) = r.publish_with_ack(&signed, Some(ack)) {
                            web_sys::console::warn_1(
                                &format!("[governance] Failed to publish action response: {e}")
                                    .into(),
                            );
                            loading_sig.set(false);
                            response_rejected.set(true);
                        }
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
                // F5: agent-declared risk tier + confidence, at decision time.
                {move || {
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(t) = risk_tier.clone() {
                        parts.push(format!("risk: {t}"));
                    }
                    if let Some(c) = confidence {
                        parts.push(format!("confidence: {:.0}%", (c * 100.0).clamp(0.0, 100.0)));
                    }
                    (!parts.is_empty()).then(|| view! {
                        <span class="text-amber-400/80 text-xs block truncate">{parts.join(" · ")}</span>
                    })
                }}
                <AgentBadge pubkey=agent_badge_pubkey compact=true />
                <SupersessionHistory d_tag=history_d_tag />
            </div>
            <Show
                when=move || response_sent.get()
                fallback=move || view! {
                    <div class="flex flex-col items-end gap-1 flex-shrink-0">
                        <div class="flex gap-2">
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
                        // F4: a relay-rejected response reads as rejected + retryable,
                        // never as sent.
                        <Show when=move || response_rejected.get() fallback=|| ()>
                            <span class="text-red-400 text-xs font-medium">"⚠ Rejected by relay — retry"</span>
                        </Show>
                    </div>
                }
            >
                <span class="text-green-400 text-xs font-medium">"Response sent"</span>
            </Show>
        </div>
    }
}

// ── Read-only member components (F1, ADR-106 Decision 2) ─────────────────────
//
// These are the ONLY panel/action components the member route (`member_view =
// true`) mounts. They render panels and their outcomes but compile in no relay
// handle, no signer, and no 31403 publish path — the split-by-route invariant
// (DDD Invariant 1: "the member read path publishes nothing"). A grep of this
// region for `publish`/`sign_event`/`RelayConnection` returns nothing; the write
// machinery lives only in [`PanelCard`] and [`ActionRow`] above, which the
// member route never instantiates.

/// Read-only panel card for the member surface. Mirrors [`PanelCard`]'s
/// presentation — title, schema, description, counts, agent name, disclosure
/// badge — but renders each declared action as a non-interactive label instead
/// of a publishing button. A member sees *what* an agent can be asked, never a
/// control that acts.
#[component]
fn ReadOnlyPanelCard(panel: PanelEntry) -> impl IntoView {
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
    let agent_name =
        crate::components::user_display::use_display_name_memo(panel.agent_pubkey.clone());
    let agent_badge_pubkey = panel.agent_pubkey.clone();
    let field_count = panel.definition.fields.len();
    let action_count = panel.definition.actions.len();
    // F6: supersession history for this panel's case (DDD §7a.3).
    let history_d_tag = panel.d_tag.clone();

    view! {
        <div class="panel-card bg-gray-800 rounded-lg p-5 border border-gray-700/50">
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-lg font-semibold text-white">{title}</h3>
                <span class="text-xs px-2 py-1 rounded-full bg-amber-400/10 text-amber-400 font-medium">{schema_badge}</span>
            </div>
            <p class="text-gray-400 text-sm mb-4">{description}</p>
            <div class="flex items-center gap-4 text-xs text-gray-500 mb-3">
                <span>{format!("{field_count} fields")}</span>
                <span>{format!("{action_count} actions")}</span>
                <span>{move || agent_name.get()}</span>
                <AgentBadge pubkey=agent_badge_pubkey compact=true />
            </div>
            <div class="flex flex-wrap gap-2">
                {panel.definition.actions.iter().map(|action| {
                    let label = action.label.clone();
                    view! {
                        <span class="px-3 py-1.5 text-xs rounded bg-gray-700/60 text-gray-400 border border-gray-600/60">
                            {label}
                        </span>
                    }
                }).collect_view()}
            </div>
            <SupersessionHistory d_tag=history_d_tag />
        </div>
    }
}

/// Read-only action row for the member surface. Mirrors [`ActionRow`]'s decision
/// context — priority, title, reasoning, agent, risk tier + confidence,
/// disclosure badge — but replaces the Approve/Reject controls with a static
/// "Awaiting administrator decision" status. No signer, no relay, no 31403.
#[component]
fn ReadOnlyActionRow(item: ActionEntry) -> impl IntoView {
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
    let confidence = item.confidence;
    let risk_tier = item.risk_tier.clone();
    let agent_name =
        crate::components::user_display::use_display_name_memo(item.agent_pubkey.clone());
    let agent_badge_pubkey = item.agent_pubkey.clone();
    // F6: supersession history for this action's case (DDD §7a.3).
    let history_d_tag = item.d_tag.clone();

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
                {move || {
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(t) = risk_tier.clone() {
                        parts.push(format!("risk: {t}"));
                    }
                    if let Some(c) = confidence {
                        parts.push(format!("confidence: {:.0}%", (c * 100.0).clamp(0.0, 100.0)));
                    }
                    (!parts.is_empty()).then(|| view! {
                        <span class="text-amber-400/80 text-xs block truncate">{parts.join(" · ")}</span>
                    })
                }}
                <AgentBadge pubkey=agent_badge_pubkey compact=true />
                <SupersessionHistory d_tag=history_d_tag />
            </div>
            <span class="flex-shrink-0 text-xs text-gray-500 border border-gray-600/60 rounded px-2.5 py-1">
                "Awaiting administrator decision"
            </span>
        </div>
    }
}

// ── Supersession history (F6, DDD §7a.3) ─────────────────────────────────────

/// Render the supersession history for a case `d`-tag. Mounted on both the member
/// (read-only) and admin panel/action surfaces (ADR-106 Decision 2): it is a pure
/// read of the [`PanelRegistry`] decision chain, mounting no publish path, so the
/// member route stays write-free.
///
/// Each observed decision (kind-31403) is listed oldest-first; a decision a later
/// authorised decision has superseded (§7a.1) is dimmed and struck through and
/// marked "Superseded", the current effective decision is marked "Current". A
/// case with a single, un-superseded decision still shows its outcome. A case
/// with no observed decisions renders nothing.
#[component]
fn SupersessionHistory(d_tag: String) -> impl IntoView {
    let registry = use_panel_registry();
    let chain = Memo::new(move |_| registry.decision_chain(&d_tag));

    view! {
        <Show when=move || !chain.get().is_empty() fallback=|| ()>
            <div class="supersession-history mt-3 pt-3 border-t border-gray-700/50">
                <span class="text-xs uppercase tracking-wide text-gray-500 block mb-1.5">
                    "Decision history"
                </span>
                <ol class="space-y-1">
                    <For
                        each=move || chain.get()
                        key=|v: &DecisionView| (v.entry.event_id.clone(), v.superseded, v.effective)
                        let:v
                    >
                        <DecisionChainRow view=v />
                    </For>
                </ol>
            </div>
        </Show>
    }
}

#[component]
fn DecisionChainRow(view: DecisionView) -> impl IntoView {
    let signer = view.entry.signer_pubkey.clone();
    let signer_short = if signer.len() > 12 {
        format!("{}…{}", &signer[..8], &signer[signer.len() - 4..])
    } else {
        signer
    };
    let outcome = view.entry.outcome.clone();
    let reason = view.entry.reason.clone();
    let superseded = view.superseded;
    let effective = view.effective;
    let is_supersede = view.entry.supersedes.is_some();

    let outcome_class = if superseded {
        "line-through text-gray-500"
    } else {
        "text-gray-200 font-medium"
    };

    view! {
        <li class="flex items-center gap-2 text-xs">
            {is_supersede.then(|| view! {
                <span class="text-amber-400/70" title="supersedes a prior decision">"↳"</span>
            })}
            <span class=outcome_class>{outcome}</span>
            <span class="text-gray-500 truncate">{signer_short}</span>
            {(!reason.is_empty()).then(|| view! {
                <span class="text-gray-600 truncate italic">{reason}</span>
            })}
            {superseded.then(|| view! {
                <span class="ml-auto flex-shrink-0 px-1.5 py-0.5 rounded bg-gray-700/60 text-gray-400 border border-gray-600/50">
                    "Superseded"
                </span>
            })}
            {effective.then(|| view! {
                <span class="ml-auto flex-shrink-0 px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">
                    "Current"
                </span>
            })}
        </li>
    }
}
