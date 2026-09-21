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
use crate::stores::case_projection::use_case_projection_store;
use crate::stores::panel_registry::{use_panel_registry, ActionEntry, DecisionView, PanelEntry};
use crate::stores::receipts::use_receipt_store;
use crate::stores::zone_access::use_zone_access;
use crate::utils::governance_view::{self, CardSection, CaseBoundary, MIN_RATIONALE_LEN};
use nostr_bbs_core::governance::broker::DecisionOutcome;
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
/// `member_view` also drives the F7 approval-fatigue filter, as ADR-2011
/// rewrote it: the member surface suppresses requests whose **effective** tier
/// is `low`, never the agent's own `risk_tier` (DDD §6 invariant 3), and never
/// suppresses a calibration sample (FR6.3) or work the operator declared
/// opaque, irreversible or critical. Suppression is a **view filter** — the
/// events remain in the store, stay visible on the admin surface, and are
/// readable through the decisions read API (ADR-106 Decision 4).
///
/// ## Amendment (FR6.2): the split is by *decidability*, not purely by route
///
/// ADR-106 Decision 2 split the surface so that an ordinary member's client
/// never mounts a 31403 publish path. FR6.2 introduces the `reviewer` role: an
/// admin publishes `Delegate { to }` on one case, and from then on that
/// delegatee — who is not an admin — must be able to decide **that case**. So
/// the member route now mounts [`ActionRow`] for exactly the cases
/// [`governance_view::is_decidable_by`] admits the viewer for, and
/// [`ReadOnlyActionRow`] for every other card. A member with no delegation
/// still mounts no publish path anywhere on the surface, which is the property
/// ADR-106 was protecting; what changed is that "who may decide" is now a
/// per-case question the delegation chain answers, rather than a property of
/// the URL. The relay enforces the same gate independently (scoped delegation
/// admission) — this is the view agreeing with it, not replacing it.
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

    // One pass over the store per render: resolve each request's panel, compute
    // its ADR-2011 boundary, and decide — from the delegation chain — whether
    // this viewer may act on it. Everything downstream (visibility, ordering,
    // which row component mounts) reads this and recomputes nothing.
    let auth = use_auth();
    let viewer_pubkey = auth.pubkey();

    // FR6.3: whether a case is a calibration sample is the RELAY's answer, not
    // ours. Selection is HMAC'd under a secret only it holds, precisely so the
    // requesting agent cannot grind its freely-chosen `d` tag out of being
    // sampled; a key shipped to the browser would be a published key. Read over
    // `GET /api/governance/cases`, which is member-readable (NIP-98, not admin)
    // — which it must be, since calibration samples exist to be shown to
    // members.
    let cases = use_case_projection_store();
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        if let Some(signer) = auth.get_signer() {
            cases.load(signer);
        }
    });

    let cards = Memo::new(move |_| {
        let admin = zone_access.is_admin.get();
        let case_state = cases.state.read();

        let viewer = viewer_pubkey.get();
        let s = state.read();
        let mut v: Vec<ActionCardData> = s
            .actions
            .iter()
            .map(|a| {
                let panel = crate::stores::panel_registry::resolve_panel_for(
                    &s.panels,
                    &a.tags,
                    &a.agent_pubkey,
                )
                .map(|p| p.context());
                let boundary = a.boundary(
                    panel.as_ref(),
                    crate::stores::case_projection::is_calibration_sample_in(&case_state, &a.d_tag),
                );
                // Scoped to the decisions bound to THIS request's event id: a
                // colliding `d` tag must not let another case's 31403 reveal
                // this one's probe or hand a stranger the controls.
                let steps = crate::stores::panel_registry::chain_steps(
                    &s.decisions
                        .get(&a.d_tag)
                        .map(|e| {
                            let bound: Vec<_> =
                                crate::stores::panel_registry::bind_to_request(e, &a.event_id)
                                    .into_iter()
                                    .cloned()
                                    .collect();
                            crate::stores::panel_registry::resolve_decision_chain(&bound)
                        })
                        .unwrap_or_default(),
                );
                let decidable = governance_view::is_decidable_by(&steps, viewer.as_deref(), admin);
                let decided = governance_view::chain_is_decided(&steps);
                ActionCardData {
                    item: a.clone(),
                    boundary,
                    decidable,
                    decided,
                }
            })
            // FR6.2: a case delegated to this viewer is shown to them even when
            // the member surface would otherwise suppress it — being handed a
            // case you cannot see is not delegation.
            .filter(|c| !member_view || c.boundary.is_member_visible() || c.decidable)
            .collect();
        // FR4.3 / EXP-AC-006: oldest first, so a stalled case rises rather than
        // sinking out of sight under fresher work.
        v.sort_by_key(|c| c.item.created_at);
        v
    });

    let panel_count = Memo::new(move |_| state.read().panels.len());
    // Count only the requests this surface renders, so the stat and the
    // empty-state gate agree with the member suppression.
    let action_count = Memo::new(move |_| cards.get().len());

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
                fallback=move || if member_view {
                    // Member surface: no decision to make, only to follow.
                    view! {
                        <div class="bg-gray-800/50 rounded-lg p-8 text-center mb-8">
                            <p class="text-gray-500">"No action requests are awaiting a decision. When an agent needs administrator review, the request appears here for you to follow — administrators respond on the community's behalf."</p>
                        </div>
                    }.into_any()
                } else {
                    // Admin surface: names the Approve/Reject controls that appear here.
                    view! {
                        <div class="bg-gray-800/50 rounded-lg p-8 text-center mb-8">
                            <p class="text-gray-500">"No action requests pending. When an agent asks for human review, its request appears here with Approve and Reject controls."</p>
                        </div>
                    }.into_any()
                }
            >
                <h2 class="text-xl font-semibold text-white mb-4">"Pending Actions"</h2>
                <p class="text-gray-500 text-sm mb-4">"Oldest first — a case that has been waiting is the one that needs you."</p>
                <div class="governance-inbox space-y-2 mb-8">
                    <For
                        each=move || cards.get()
                        key=|c| (c.item.event_id.clone(), c.decidable, c.decided)
                        let:c
                    >
                        // Decidability split (ADR-106 Decision 2 as amended by
                        // FR6.2): the writable row mounts only where this viewer
                        // may actually publish a 31403 — an admin, or the
                        // delegatee of this one case. Everyone else gets a row
                        // that compiles in no signer and no publish path.
                        {if c.decidable {
                            view! { <ActionRow card=c /> }.into_any()
                        } else {
                            view! { <ReadOnlyActionRow card=c /> }.into_any()
                        }}
                    </For>
                </div>
            </Show>

            <Show
                when=move || panel_count.get() != 0
                fallback=move || if member_view {
                    // Member surface: explain what governance is and that
                    // published policies/proposals will surface here to read.
                    view! {
                        <div class="bg-gray-800/50 rounded-lg p-8 text-center max-w-2xl mx-auto">
                            <h3 class="text-lg font-semibold text-white mb-2">"About governance"</h3>
                            <p class="text-gray-400 text-sm mb-3">
                                "Governance is where you can see how the forum's registered agents are configured and the decisions they take on the community's behalf. Published policies and proposals appear here for you to review."
                            </p>
                            <p class="text-gray-500 text-sm">
                                "Nothing has been published yet. This is a read-only view — administrators respond to any action requests."
                            </p>
                        </div>
                    }.into_any()
                } else {
                    // Admin surface: state it is the management surface, describe
                    // what admins can do, and offer a clear affordance for getting
                    // the first policy published.
                    view! {
                        <div class="bg-gray-800/50 rounded-lg p-8 text-center max-w-2xl mx-auto">
                            <h3 class="text-lg font-semibold text-white mb-2">"Governance management surface"</h3>
                            <p class="text-gray-400 text-sm mb-3">
                                "This is the admin control surface. From here you review agent decisions, monitor status, and respond to action requests as they arrive."
                            </p>
                            <p class="text-gray-500 text-sm mb-5">
                                "No policies have been published yet. Policies and panels are published by registered agents (kind-31400 PanelDefinition events) — register an agent to get the first one flowing."
                            </p>
                            <A
                                href=base_href("/admin")
                                attr:class="inline-flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold transition-colors"
                            >
                                "Register an agent →"
                            </A>
                        </div>
                    }.into_any()
                }
            >
                <h2 class="text-xl font-semibold text-white mb-4">"Agent Panels"</h2>
                <div class="governance-panels-grid grid grid-cols-1 md:grid-cols-2 gap-4">
                    <For
                        each=move || panels.get()
                        key=|panel| panel.address()
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

// ── Decision card (FR2, FR4.3, FR6.2/6.3/6.4) ───────────────────────────────

/// One pending request, with everything the surfaces derived about it resolved
/// once at the page level rather than per row.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionCardData {
    pub item: ActionEntry,
    /// The ADR-2011 boundary: effective tier, merged task properties,
    /// calibration flag, probe digest, ageing deadline.
    pub boundary: CaseBoundary,
    /// Whether THIS viewer may publish a 31403 on this case (admin, or the
    /// delegatee an admin named — DDD §6 invariant 6).
    pub decidable: bool,
    /// Whether an effective, non-delegation decision already exists.
    pub decided: bool,
}

/// Human-readable title for a request, from its `title` tag, else its `d`-tag.
fn card_title(item: &ActionEntry) -> String {
    nostr_bbs_core::governance::extract_tag(&item.tags, "title")
        .map(str::to_string)
        .unwrap_or_else(|| item.d_tag.clone())
}

fn tier_class(tier: &str) -> &'static str {
    match tier {
        "critical" => "bg-red-500/20 text-red-400 border-red-500/30",
        "high" => "bg-orange-500/20 text-orange-400 border-orange-500/30",
        "medium" => "bg-blue-500/20 text-blue-400 border-blue-500/30",
        _ => "bg-gray-500/20 text-gray-400 border-gray-500/30",
    }
}

/// Build every section of a decision card except the reviewer's controls.
///
/// Returned as `(section, view)` pairs so the caller can order them by
/// [`governance_view::card_sections`] — the ordering rule (FR2.1: the agent's
/// tier and confidence never render above Approve) lives in that tested pure
/// function, not in a `view!` macro nobody can assert against.
fn card_body_parts(card: &ActionCardData) -> Vec<(CardSection, AnyView)> {
    let item = &card.item;
    let b = &card.boundary;

    let title = card_title(item);
    let agent_name =
        crate::components::user_display::use_display_name_memo(item.agent_pubkey.clone());
    let agent_badge_pubkey = item.agent_pubkey.clone();

    // FR4.3: age from `created_at`, differenced client-side. `now` is read once
    // per render; the label itself is pure and tested.
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let age_label = governance_view::relative_age_label(item.created_at, now);
    let overdue = governance_view::is_overdue(item.created_at, now, b.max_pending_hours);
    let max_hours = b.max_pending_hours;

    // FR4.3: the relay's own `escalated-on-age` receipt, where this viewer can
    // read receipts. Authoritative; the clock reading above is advisory and is
    // labelled so.
    let escalated_d_tag = item.d_tag.clone();
    let receipts = use_receipt_store();
    let escalated = Memo::new(move |_| {
        receipts
            .case(&escalated_d_tag)
            .map(|c| c.escalated_on_age)
            .unwrap_or(false)
    });

    let calibration = b.calibration_sample;
    // DDD §6 invariant 7: this is the ONLY path by which a probe digest may
    // reach the DOM, and it yields `None` for every undecided case. The raw
    // 31402 still carries the tag — stripping it relay-side would invalidate
    // the signature this client verifies — so the blindness is ours to keep.
    let probe =
        governance_view::visible_probe(card.decided, b.probe_digest.as_deref()).map(str::to_string);

    let header = view! {
        <div class="flex flex-wrap items-center gap-2 mb-1">
            <span class=format!(
                "inline-block px-2 py-1 text-xs font-medium rounded border {}",
                tier_class(b.effective.as_str()),
            )>{b.effective.as_str()}</span>
            <span class="text-white font-medium">{title}</span>
            <span class="text-gray-500 text-xs">{move || agent_name.get()}</span>
            <AgentBadge pubkey=agent_badge_pubkey compact=true />
            <span
                class=move || if overdue || escalated.get() {
                    "text-xs px-2 py-0.5 rounded border bg-amber-500/10 text-amber-400 border-amber-500/30"
                } else {
                    "text-xs px-2 py-0.5 rounded border bg-gray-700/60 text-gray-400 border-gray-600/50"
                }
                title=format!("Pending deadline: {max_hours}h")
            >{age_label}</span>
            // The relay said so (a receipt), as against our own clock reading.
            {move || escalated.get().then(|| view! {
                <span
                    class="text-xs px-2 py-0.5 rounded border bg-amber-500/10 text-amber-400 border-amber-500/30"
                    title="The relay recorded an escalated-on-age receipt for this case"
                >"escalated on age"</span>
            })}
            {(overdue && !calibration).then(|| view! {
                <span
                    class="text-xs px-2 py-0.5 rounded border bg-amber-500/10 text-amber-400/80 border-amber-500/20"
                    title=format!("Past this panel's {max_hours}h pending deadline, by this browser's clock")
                >"overdue"</span>
            })}
            // FR6.3: a calibration sample is shown rather than suppressed, and
            // marked subtly — enough that the record is honest about why the
            // case is here, not so much that it reads as a different kind of
            // work. It is NOT a probe, and says nothing about the answer.
            {calibration.then(|| view! {
                <span
                    class="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded border border-gray-600/50 text-gray-500"
                    title="Shown as a routine calibration sample rather than suppressed by tier"
                >"calibration"</span>
            })}
            // Only ever reachable once a 31403 exists (invariant 7).
            {probe.map(|p| view! {
                <span
                    class="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded border border-purple-500/30 text-purple-400"
                    title=format!("Seeded probe {p}")
                >"probe"</span>
            })}
        </div>
    }
    .into_any();

    let mut parts: Vec<(CardSection, AnyView)> = vec![(CardSection::Header, header)];

    // The agent's own prose, verbatim. Absent where it wrote none.
    if let Some(reasoning) = item.reasoning.clone().filter(|r| !r.trim().is_empty()) {
        parts.push((
            CardSection::AgentReasoning,
            view! {
                <p class="text-gray-400 text-sm whitespace-pre-wrap mb-2">{reasoning}</p>
            }
            .into_any(),
        ));
    }

    // FR2.1: the proposed change itself, pretty-printed, in full, never
    // truncated. The container scrolls; the text does not shorten.
    if governance_view::has_proposal(&item.fields) {
        let pretty = governance_view::pretty_fields(&item.fields);
        parts.push((
            CardSection::Proposal,
            view! {
                <div class="mb-2">
                    <span class="text-xs uppercase tracking-wide text-gray-500 block mb-1">"Proposed change"</span>
                    <pre class="governance-proposal text-xs text-gray-200 bg-gray-900/70 border border-gray-700/60 rounded p-3 max-h-96 overflow-auto whitespace-pre-wrap break-words">{pretty}</pre>
                </div>
            }
            .into_any(),
        ));
    }

    // Re-checked here even though the store validated on ingest: this is the
    // DOM sink, and a sink that trusts its feed is one refactor from stored XSS.
    if let Some(url) = item
        .context_url
        .as_deref()
        .and_then(governance_view::safe_context_url)
    {
        let href = url.clone();
        parts.push((
            CardSection::ContextLink,
            view! {
                <a
                    href=href
                    target="_blank"
                    rel="noopener noreferrer"
                    class="inline-block text-xs text-amber-400 hover:text-amber-300 underline mb-2 break-all"
                >{url}</a>
            }
            .into_any(),
        ));
    }

    // FR2.1: the agent's framing, BELOW the controls. Declared tier and
    // effective tier are both shown — their divergence is exactly how a
    // habitually under-tiering agent becomes visible (ADR-2011).
    let declared = b.declared.map(|t| t.as_str().to_string());
    let effective = b.effective.as_str().to_string();
    let confidence = item.confidence;
    let props = b.props;
    parts.push((
        CardSection::AgentFraming,
        view! {
            <div class="mt-3 pt-3 border-t border-gray-700/50 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
                <span>"Agent declared: "{declared.unwrap_or_else(|| "—".into())}</span>
                {confidence.map(|c| view! {
                    <span>{format!("Agent confidence: {:.0}%", (c * 100.0).clamp(0.0, 100.0))}</span>
                })}
                <span class="text-amber-400/80">"Effective tier: "{effective}</span>
                {props.map(|p| view! {
                    <span title="Operator-declared task properties (ADR-2011)">
                        {format!(
                            "{} · {} · {}",
                            p.verifiability.as_str(),
                            p.reversibility.as_str(),
                            p.stakes.as_str(),
                        )}
                    </span>
                })}
            </div>
        }
        .into_any(),
    ));

    parts.push((
        CardSection::DecisionChain,
        view! {
            <SupersessionHistory
                d_tag=item.d_tag.clone()
                request_event_id=item.event_id.clone()
            />
        }
        .into_any(),
    ));

    parts
}

/// Assemble a card from its parts in the order
/// [`governance_view::card_sections`] dictates.
fn assemble_card(
    mut parts: Vec<(CardSection, AnyView)>,
    controls: AnyView,
    has_context_url: bool,
    has_agent_reasoning: bool,
) -> Vec<AnyView> {
    parts.push((CardSection::ReviewerControls, controls));
    governance_view::card_sections(has_context_url, has_agent_reasoning)
        .into_iter()
        .filter_map(|section| {
            parts
                .iter()
                .position(|(k, _)| *k == section)
                .map(|i| parts.remove(i).1)
        })
        .collect()
}

fn has_context_url(item: &ActionEntry) -> bool {
    item.context_url
        .as_deref()
        .and_then(governance_view::safe_context_url)
        .is_some()
}

fn has_agent_reasoning(item: &ActionEntry) -> bool {
    item.reasoning
        .as_deref()
        .is_some_and(|r| !r.trim().is_empty())
}

// ── Writable decision card ───────────────────────────────────────────────────

/// The decision card for a viewer who may actually decide this case: an admin,
/// or the delegatee an admin named on it (FR6.2).
///
/// It collects the human's rationale and publishes it **verbatim** as the
/// 31403's `reasoning` ([`governance_view::decision_content`]). There is no
/// template anywhere in this crate: where the reviewer typed nothing, the
/// published `reasoning` is the empty string, which is the honest record.
/// For an effective tier of `high` or `critical` every control stays disabled
/// until the rationale has at least [`MIN_RATIONALE_LEN`] non-whitespace
/// characters (FR2.2).
#[component]
fn ActionRow(card: ActionCardData) -> impl IntoView {
    let auth = use_auth();
    let zone_access = use_zone_access();
    let is_admin = Memo::new(move |_| zone_access.is_admin.get());

    let item = card.item.clone();
    let effective = card.boundary.effective;
    let d_tag = item.d_tag.clone();
    let event_id = item.event_id.clone();
    let ctx_url = has_context_url(&item);
    let agent_reasoning = has_agent_reasoning(&item);

    let rationale = RwSignal::new(String::new());
    let amend_open = RwSignal::new(false);
    let amend_diff = RwSignal::new(String::new());
    let delegate_open = RwSignal::new(false);
    let delegate_to = RwSignal::new(String::new());
    let pending: RwSignal<Option<String>> = RwSignal::new(None);
    let response_sent = RwSignal::new(false);
    // A relay rejection re-shows the controls (retryable) rather than reading
    // as sent (F4).
    let response_rejected = RwSignal::new(false);

    // Resolve the relay at component construction: calling expect_context()
    // inside a click handler panics once the reactive owner is gone, and the
    // panic kills the whole WASM runtime.
    let relay_stored = StoredValue::new_local(expect_context::<RelayConnection>());

    let publish = {
        let event_id = event_id.clone();
        let d_tag = d_tag.clone();
        move |outcome: DecisionOutcome| {
            let label = outcome.action_str().to_string();
            let event_id = event_id.clone();
            let d_tag = d_tag.clone();
            pending.set(Some(label));
            response_rejected.set(false);

            let Some(pubkey) = auth.pubkey().get_untracked() else {
                pending.set(None);
                return;
            };

            // FR2.2 / DDD §6 invariant 1: the reviewer's own bytes, untrimmed,
            // and nothing else.
            let content = governance_view::decision_content(&outcome, &rationale.get_untracked());

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

            let r = relay_stored.get_value();
            spawn_local(async move {
                match auth.sign_event_async(unsigned).await {
                    Ok(signed) => {
                        let ack: crate::relay::PublishCallback = Rc::new(
                            move |accepted: bool, message: String| {
                                pending.set(None);
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
                            pending.set(None);
                            response_rejected.set(true);
                        }
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("[governance] Failed to sign action response: {e}").into(),
                        );
                        pending.set(None);
                    }
                }
            });
        }
    };

    let is_authed = auth.is_authenticated();
    // FR2.2: the gate. One predicate, tested in `governance_view`, applied to
    // every control — approve, reject, amend and delegate alike, because a
    // delegation on a critical case is as consequential as a decision on it.
    let gate_ok =
        Memo::new(move |_| governance_view::rationale_satisfied(effective, &rationale.get()));
    let blocked = move || {
        !is_authed.get() || pending.get().is_some() || response_sent.get() || !gate_ok.get()
    };
    let required = governance_view::rationale_required(effective);

    // Park the publisher in a `StoredValue` so every handler captures a `Copy`
    // handle. A `Show` fallback and its children are `Fn`, so a handler that
    // captured the publisher by move would only be `FnOnce` and the whole
    // control block would fail to compile.
    let publish = StoredValue::new_local(Rc::new(publish) as Rc<dyn Fn(DecisionOutcome)>);

    let on_approve = move |_| (publish.get_value())(DecisionOutcome::Approve);
    let on_reject = move |_| (publish.get_value())(DecisionOutcome::Reject);
    let on_amend = move |_| {
        let diff = amend_diff.get_untracked();
        if diff.trim().is_empty() {
            return;
        }
        (publish.get_value())(DecisionOutcome::Amend { diff })
    };
    let on_delegate = move |_| {
        // A mistyped target would mint a delegation to a pubkey nobody holds
        // and park the case with no delegatee able to move it.
        let Some(to) = governance_view::normalise_delegate_pubkey(&delegate_to.get_untracked())
        else {
            return;
        };
        (publish.get_value())(DecisionOutcome::Delegate { delegate_to: to })
    };

    let btn = "px-3 py-1.5 text-xs rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed";

    let controls = view! {
        <div class="reviewer-controls mt-3">
            <Show
                when=move || response_sent.get()
                fallback=move || view! {
                    <div class="flex flex-col gap-2">
                        <label class="text-xs uppercase tracking-wide text-gray-500">
                            {if required {
                                format!("Your rationale (required, at least {MIN_RATIONALE_LEN} characters)")
                            } else {
                                "Your rationale (optional)".to_string()
                            }}
                        </label>
                        <textarea
                            class="w-full text-sm bg-gray-900/70 border border-gray-700/60 rounded p-2 text-gray-100 focus:outline-none focus:border-amber-500/60"
                            rows="3"
                            placeholder="Why you are deciding this, in your own words."
                            prop:value=move || rationale.get()
                            on:input=move |ev| rationale.set(event_target_value(&ev))
                        ></textarea>
                        {move || (required && !gate_ok.get()).then(|| {
                            let left = governance_view::rationale_remaining(effective, &rationale.get());
                            view! {
                                <span class="text-amber-400/80 text-xs">
                                    {format!(
                                        "This case is {} — {left} more character(s) of rationale before you can decide it.",
                                        effective.as_str(),
                                    )}
                                </span>
                            }
                        })}
                        <div class="flex flex-wrap gap-2">
                            <button
                                class=format!("{btn} bg-green-500/10 text-green-400 border-green-500/20 hover:bg-green-500/20")
                                disabled=blocked
                                on:click=on_approve
                            >
                                {move || if pending.get().as_deref() == Some("approve") { "…" } else { "Approve" }}
                            </button>
                            <button
                                class=format!("{btn} bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20")
                                disabled=blocked
                                on:click=on_reject
                            >
                                {move || if pending.get().as_deref() == Some("reject") { "…" } else { "Reject" }}
                            </button>
                            <button
                                class=format!("{btn} bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20")
                                disabled=blocked
                                on:click=move |_| amend_open.update(|o| *o = !*o)
                            >"Amend…"</button>
                            // FR6.2: delegation is an ADMIN act. A delegatee
                            // deciding their own case cannot re-delegate it.
                            {move || is_admin.get().then(|| view! {
                                <button
                                    class=format!("{btn} bg-purple-500/10 text-purple-400 border-purple-500/20 hover:bg-purple-500/20")
                                    disabled=blocked
                                    on:click=move |_| delegate_open.update(|o| *o = !*o)
                                >"Delegate to…"</button>
                            })}
                        </div>
                        <Show when=move || amend_open.get() fallback=|| ()>
                            <div class="flex flex-col gap-1">
                                <textarea
                                    class="w-full text-xs font-mono bg-gray-900/70 border border-gray-700/60 rounded p-2 text-gray-100"
                                    rows="4"
                                    placeholder="The amendment, as a diff or a replacement payload."
                                    prop:value=move || amend_diff.get()
                                    on:input=move |ev| amend_diff.set(event_target_value(&ev))
                                ></textarea>
                                <button
                                    class=format!("{btn} self-start bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20")
                                    disabled=move || blocked() || amend_diff.get().trim().is_empty()
                                    on:click=on_amend
                                >
                                    {move || if pending.get().as_deref() == Some("amend") { "…" } else { "Publish amendment" }}
                                </button>
                            </div>
                        </Show>
                        <Show when=move || delegate_open.get() && is_admin.get() fallback=|| ()>
                            <div class="flex flex-col gap-1">
                                <input
                                    class="w-full text-xs font-mono bg-gray-900/70 border border-gray-700/60 rounded p-2 text-gray-100"
                                    placeholder="Reviewer pubkey (64 hex characters)"
                                    prop:value=move || delegate_to.get()
                                    on:input=move |ev| delegate_to.set(event_target_value(&ev))
                                />
                                {move || {
                                    let raw = delegate_to.get();
                                    (!raw.trim().is_empty()
                                        && governance_view::normalise_delegate_pubkey(&raw).is_none())
                                    .then(|| view! {
                                        <span class="text-red-400 text-xs">"Not a 64-character hex pubkey."</span>
                                    })
                                }}
                                <button
                                    class=format!("{btn} self-start bg-purple-500/10 text-purple-400 border-purple-500/20 hover:bg-purple-500/20")
                                    disabled=move || blocked()
                                        || governance_view::normalise_delegate_pubkey(&delegate_to.get()).is_none()
                                    on:click=on_delegate
                                >
                                    {move || if pending.get().as_deref() == Some("delegate") { "…" } else { "Delegate this case" }}
                                </button>
                            </div>
                        </Show>
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
    .into_any();

    let sections = assemble_card(card_body_parts(&card), controls, ctx_url, agent_reasoning);

    view! {
        <div class="action-row bg-gray-800 rounded-lg p-4 border border-gray-700/50">
            {sections}
        </div>
    }
}

// ── Read-only member components (F1, ADR-106 Decision 2) ─────────────────────
//
// [`ReadOnlyPanelCard`] and [`ReadOnlyActionRow`] render panels, proposals and
// their outcomes but compile in no relay handle, no signer, and no 31403
// publish path. A grep of this region for `publish`/`sign_event`/
// `RelayConnection` returns nothing; the write machinery lives only in
// [`PanelCard`] and [`ActionRow`] above. Since FR6.2 the choice between the two
// rows is per-case decidability rather than the route alone — see
// [`GovernancePage`] — but the property ADR-106 protects is unchanged: a viewer
// who may not decide a case mounts nothing that could.

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

/// Read-only decision card. Renders exactly the same decision context as
/// [`ActionRow`] — including the proposed change in full, the context link and
/// the agent's framing below where the controls would be — and replaces the
/// controls with a status line. No signer, no relay, no 31403.
///
/// It is what a member sees on every case, and what a delegated reviewer sees
/// on every case except the one delegated to them.
#[component]
fn ReadOnlyActionRow(card: ActionCardData) -> impl IntoView {
    let ctx_url = has_context_url(&card.item);
    let agent_reasoning = has_agent_reasoning(&card.item);
    let decided = card.decided;

    let status = view! {
        <div class="reviewer-controls mt-3">
            <span class="inline-block text-xs text-gray-500 border border-gray-600/60 rounded px-2.5 py-1">
                {if decided { "Decided" } else { "Awaiting a decision" }}
            </span>
        </div>
    }
    .into_any();

    let sections = assemble_card(card_body_parts(&card), status, ctx_url, agent_reasoning);

    view! {
        <div class="action-row bg-gray-800 rounded-lg p-4 border border-gray-700/50">
            {sections}
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
fn SupersessionHistory(
    d_tag: String,
    /// The request EVENT id, on a decision card. When given, the chain is
    /// scoped to the decisions bound to that request, so a 31403 carrying a
    /// colliding `d` tag cannot land here. `None` on a PANEL card, which has
    /// no request to bind to.
    #[prop(optional)]
    request_event_id: Option<String>,
) -> impl IntoView {
    let registry = use_panel_registry();
    let receipts = use_receipt_store();
    let auth = use_auth();
    let chain_key = d_tag.clone();
    let bind_key = request_event_id.clone();
    let chain = Memo::new(move |_| match &bind_key {
        Some(req) => registry.case_chain(&chain_key, req),
        None => registry.decision_chain(&chain_key),
    });

    // FR4.1: pull the case's receipt trail so each decision can say how far it
    // actually got. The read is NIP-98 admin (the relay scopes cross-case
    // receipt reads to its administrative authority), so a member or a
    // delegated reviewer sees the chain without stages — which the store
    // records as "unavailable" and never as "not applied".
    #[cfg(target_arch = "wasm32")]
    {
        let load_key = d_tag.clone();
        Effect::new(move |_| {
            if chain.get().is_empty() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                return;
            };
            receipts.load_case(&load_key, signer);
        });
    }
    // The receipt read is a WASM-only path (it needs `window.fetch`); on the
    // host target these two are constructed for parity and not used.
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (&auth, &receipts);
    }

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
    // Character-safe: a hostile 31403 carries arbitrary strings, and a
    // byte-slice at a fixed offset panics on a multi-byte boundary — which in
    // WASM aborts the whole reactive render.
    let signer_short = governance_view::short_id(&view.entry.signer_pubkey);
    let outcome = view.entry.outcome.clone();
    let reason = view.entry.reason.clone();
    let superseded = view.superseded;
    let effective = view.effective;
    let is_supersede = view.entry.supersedes.is_some();
    // FR6.2: a delegation names its delegatee in the chain, and the admin who
    // made it stays attributable (DDD §6 invariant 6 — "the delegation itself
    // remains in the chain").
    let delegate_to = view
        .entry
        .delegate_to
        .as_deref()
        .map(governance_view::short_id);

    // FR4.1: how far this decision actually got.
    let receipts = use_receipt_store();
    let case_key = view.entry.d_tag.clone();
    let event_key = view.entry.event_id.clone();
    let receipt = Memo::new(move |_| {
        receipts
            .case(&case_key)
            .and_then(|c| c.by_decision.get(&event_key).cloned())
    });

    let outcome_class = if superseded {
        "line-through text-gray-500"
    } else {
        "text-gray-200 font-medium"
    };

    view! {
        <li class="flex flex-wrap items-center gap-2 text-xs">
            {is_supersede.then(|| view! {
                <span class="text-amber-400/70" title="supersedes a prior decision">"↳"</span>
            })}
            <span class=outcome_class>{outcome}</span>
            {delegate_to.map(|d| view! {
                <span class="text-purple-400/80" title="delegated to this reviewer">{format!("→ {d}")}</span>
            })}
            <span class="text-gray-500 truncate">{signer_short}</span>
            {(!reason.is_empty()).then(|| view! {
                <span class="text-gray-600 truncate italic">{reason}</span>
            })}
            // The receipt ladder: what the relay and the mutation owner each
            // certified. Absence of a receipt shows nothing at all — it is not
            // evidence that the act did not happen.
            {move || receipt.get().map(|r| {
                let label = r.stage.label();
                let class = r.stage.class();
                let detail = r
                    .acknowledgement
                    .clone()
                    .or_else(|| r.stage_error.clone())
                    .or_else(|| r.applied_by.clone().map(|by| format!("by {by}")))
                    .unwrap_or_else(|| label.clone());
                view! {
                    <span
                        class=format!("px-1.5 py-0.5 rounded border {class}")
                        title=detail
                    >{label}</span>
                }
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
