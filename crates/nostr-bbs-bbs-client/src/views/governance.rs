//! Full Agent Governance Control Plane (`31400–31405`).
//!
//! Powered by `PanelRegistry`, `CaseProjectionStore`, `ReceiptStore`, and
//! `utils::governance_view` from `nostr-bbs-client-core`:
//! - Pending Cases & Decided Archive tabs
//! - Relay-authoritative `effective_tier` + calibration sample flag (ADR-2011)
//! - High/Critical rationale enforcement (`MIN_RATIONALE_LEN`)
//! - Approve / Reject / Promote / Demote (ADR-2013) / Delegate / Amend / Supersede
//! - Durable execution receipt stage ladder (ADR-2010)
//! - Live panel definitions & state snapshots (`31400`, `31401`, `31404`)

use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::stores::case_projection::{
    effective_tier_in, is_calibration_sample_in, use_case_projection_store,
};
use nostr_bbs_client_core::stores::panel_registry::{
    chain_steps, resolve_panel_for, use_panel_registry,
};
use nostr_bbs_client_core::stores::receipts::use_receipt_store;
use nostr_bbs_client_core::stores::zone_access::use_zone_access;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::governance_view::{
    decision_content, decision_controls, is_decidable_by, normalise_delegate_pubkey, pretty_fields,
    rationale_remaining, rationale_required, rationale_satisfied, safe_context_url,
    DecisionControls,
};
use nostr_bbs_core::event::UnsignedEvent;
use nostr_bbs_core::governance::{
    broker::DecisionOutcome, canonical_json_string, RiskTier, KIND_ACTION_RESPONSE,
};

use crate::components::{AuthorChip, EmptyCard};

fn tier_badge_class(tier: RiskTier) -> &'static str {
    match tier {
        RiskTier::Low => "bbs-badge bbs-badge-ok",
        RiskTier::Medium => "bbs-badge bbs-badge-info",
        RiskTier::High => "bbs-badge bbs-badge-warn",
        RiskTier::Critical => "bbs-badge bbs-badge-danger",
    }
}

/// Governance Control Plane view (`#/agents`).
#[component]
pub fn AgentsView() -> impl IntoView {
    let registry = use_panel_registry();
    let projections = use_case_projection_store();
    let receipts = use_receipt_store();
    let zone_access = use_zone_access();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();

    let active_tab = RwSignal::new("pending"); // "pending" | "archive" | "panels"
    let show_low_tier = RwSignal::new(false);

    // Load relay-authoritative case projections once signed in.
    Effect::new(move |_| {
        if auth.is_authenticated().get() && projections.needs_load() {
            if let Some(signer) = auth.get_signer() {
                #[cfg(target_arch = "wasm32")]
                projections.load(signer);
                #[cfg(not(target_arch = "wasm32"))]
                let _ = signer;
            }
        }
    });

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"◈ Agents & Governance Control Plane"</h1>
                    <p class="tui-page-sub">
                        "Human-in-the-loop review over signed 31400–31405 panels, task-property risk tiers, and execution receipts."
                    </p>
                </div>
                <div class="tui-actions">
                    <label class="tui-row" style="font-size:0.82rem;cursor:pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || show_low_tier.get()
                            on:change=move |ev| show_low_tier.set(event_target_checked(&ev))
                        />
                        <span>"Show low-tier"</span>
                    </label>
                </div>
            </div>

            <div class="tui-tabs">
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || active_tab.get() == "pending"
                    on:click=move |_| active_tab.set("pending")
                >"Pending Cases"</button>
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || active_tab.get() == "archive"
                    on:click=move |_| active_tab.set("archive")
                >"Decided Archive"</button>
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || active_tab.get() == "panels"
                    on:click=move |_| active_tab.set("panels")
                >"Registered Panels"</button>
            </div>

            {move || {
                let st = registry.state.get();
                let proj = projections.state.get();
                let is_admin = zone_access.is_admin.get();
                let viewer_pk = auth.pubkey().get();
                let tab = active_tab.get();
                let low_ok = show_low_tier.get();

                if tab == "panels" {
                    if st.panels.is_empty() {
                        return view! {
                            <EmptyCard
                                title="No live panels registered"
                                body="Agent control panels (kind 31400) appear here automatically as registered agents publish their schemas to the relay."
                            />
                        }.into_any();
                    }
                    let mut panels: Vec<_> = st.panels.values().cloned().collect();
                    panels.sort_by(|a, b| a.definition.title.cmp(&b.definition.title));
                    return view! {
                        <div class="tui-stack">
                            {panels.into_iter().map(|entry| {
                                let addr = entry.address();
                                let snap = st.panel_states.get(&addr).cloned();
                                view! {
                                    <div class="tui-card tui-card-accent tui-stack">
                                        <div class="tui-row-between">
                                            <strong>{entry.definition.title.clone()}</strong>
                                            <AuthorChip pubkey=entry.agent_pubkey.clone() />
                                        </div>
                                        <p class="tui-muted">{entry.definition.description.clone()}</p>
                                        <div class="tui-row">
                                            <span class="bbs-badge">{format!("{:?}", entry.definition.schema)}</span>
                                            <span class="bbs-badge">{format!("d: {}", entry.d_tag)}</span>
                                            <span class="bbs-badge">{format!("↻ {}s", entry.definition.refresh_secs)}</span>
                                        </div>
                                        {snap.map(|val| view! {
                                            <pre class="bbs-md" style="margin:0;overflow-x:auto;font-size:0.8rem">
                                                {pretty_fields(&val)}
                                            </pre>
                                        })}
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    }.into_any();
                }

                // Pending or Archive cases
                let cases: Vec<_> = st
                    .actions
                    .iter()
                    .filter_map(|act| {
                        let panel = resolve_panel_for(&st.panels, &act.tags, &act.agent_pubkey);
                        let panel_ctx = panel.map(|p| p.context());
                        let calib = is_calibration_sample_in(&proj, &act.agent_pubkey, &act.d_tag);
                        let relay_tier = effective_tier_in(&proj, &act.agent_pubkey, &act.d_tag);
                        let boundary = act
                            .boundary(panel_ctx.as_ref(), calib)
                            .with_relay_tier(relay_tier);
                        let chain = registry.case_chain(&act.d_tag, &act.event_id);
                        let steps = chain_steps(&chain);
                        let decided = !steps.is_empty()
                            && nostr_bbs_client_core::utils::governance_view::chain_is_decided(&steps);

                        if tab == "pending" && decided {
                            return None;
                        }
                        if tab == "archive" && !decided {
                            return None;
                        }
                        if tab == "pending" && !low_ok && boundary.effective == RiskTier::Low && !calib {
                            return None;
                        }
                        let controls = decision_controls(
                            &act.tags,
                            &act.fields,
                            panel.map(|p| p.d_tag.as_str()),
                        );
                        let decidable = is_decidable_by(&steps, viewer_pk.as_deref(), is_admin);
                        Some((act.clone(), boundary, chain, controls, decidable))
                    })
                    .collect();

                if cases.is_empty() {
                    let msg = if tab == "pending" {
                        "No pending agent action requests match the current filter."
                    } else {
                        "No decided governance cases archived yet."
                    };
                    return view! { <EmptyCard title="All clear" body=msg /> }.into_any();
                }

                view! {
                    <div class="tui-stack">
                        {cases.into_iter().map(|(act, boundary, chain, controls, decidable)| {
                            let d_tag = act.d_tag.clone();
                            let ev_id = act.event_id.clone();
                            let agent_pk = act.agent_pubkey.clone();
                            let effective = boundary.effective;
                            let rationale = RwSignal::new(String::new());
                            let delegate_input = RwSignal::new(String::new());
                            let show_delegate = RwSignal::new(false);
                            let submitting = RwSignal::new(false);

                            // Load execution receipts for this case on demand
                            if receipts.needs_load(&d_tag) {
                                if let Some(signer) = auth.get_signer() {
                                    #[cfg(target_arch = "wasm32")]
                                    receipts.load_case(&d_tag, signer);
                                    #[cfg(not(target_arch = "wasm32"))]
                                    let _ = signer;
                                }
                            }
                            let case_receipts = receipts.case(&d_tag);

                            let submit_decision = {
                                let d_tag = d_tag.clone();
                                let ev_id = ev_id.clone();
                                let agent_pk = agent_pk.clone();
                                let relay = relay.clone();
                                move |outcome: DecisionOutcome| {
                                    let why = rationale.get_untracked();
                                    if !rationale_satisfied(effective, &why) {
                                        let rem = rationale_remaining(effective, &why);
                                        toasts.show(
                                            format!("High/Critical decisions require rationale ({rem} more chars)"),
                                            ToastVariant::Warning,
                                        );
                                        return;
                                    }
                                    let Some(signer) = auth.get_signer() else {
                                        toasts.show("Sign in first to sign a decision", ToastVariant::Warning);
                                        return;
                                    };
                                    let content = canonical_json_string(
                                        &serde_json::from_str::<serde_json::Value>(
                                            &decision_content(&outcome, &why),
                                        )
                                        .unwrap_or_else(|_| serde_json::json!({ "reasoning": why })),
                                    );
                                    let unsigned = UnsignedEvent {
                                        pubkey: signer.public_key().to_string(),
                                        created_at: (js_sys::Date::now() / 1000.0) as u64,
                                        kind: KIND_ACTION_RESPONSE,
                                        tags: vec![
                                            vec!["d".into(), d_tag.clone()],
                                            vec!["e".into(), ev_id.clone()],
                                            vec!["p".into(), agent_pk.clone()],
                                        ],
                                        content,
                                    };
                                    submitting.set(true);
                                    let relay = relay.clone();
                                    wasm_bindgen_futures::spawn_local(async move {
                                        match signer.sign_event(unsigned).await {
                                            Ok(signed) => {
                                                let cb = Rc::new(move |ok: bool, msg: String| {
                                                    if ok {
                                                        toasts.show("Signed 31403 decision accepted", ToastVariant::Success);
                                                    } else {
                                                        toasts.show(format!("Relay rejected decision: {msg}"), ToastVariant::Error);
                                                    }
                                                });
                                                let _ = relay.publish_with_ack(&signed, Some(cb));
                                            }
                                            Err(e) => toasts.show(format!("Sign error: {e}"), ToastVariant::Error),
                                        }
                                        submitting.set(false);
                                    });
                                }
                            };

                            let ctx_url = act.context_url.as_deref().and_then(safe_context_url);
                            let pretty = pretty_fields(&act.fields);
                            let title_str = act
                                .reasoning
                                .clone()
                                .filter(|s| !s.trim().is_empty())
                                .unwrap_or_else(|| act.d_tag.clone());

                            view! {
                                <div class="tui-card tui-card-accent tui-stack">
                                    <div class="tui-row-between">
                                        <div class="tui-row">
                                            <strong>{title_str}</strong>
                                            <span class=tier_badge_class(effective)>
                                                {format!("{effective:?}")}
                                            </span>
                                            {boundary.calibration_sample.then(|| view! {
                                                <span class="bbs-badge bbs-badge-info">"CALIBRATION"</span>
                                            })}
                                        </div>
                                        <AuthorChip pubkey=act.agent_pubkey.clone() />
                                    </div>

                                    {(!pretty.is_empty()).then(|| view! {
                                        <pre style="margin:0;padding:0.5rem;background:var(--bg-input);border:1px solid var(--border);overflow-x:auto;font-size:0.8rem">
                                            {pretty}
                                        </pre>
                                    })}

                                    {ctx_url.map(|u| view! {
                                        <a href=u target="_blank" rel="noopener" style="font-size:0.82rem">"Open context ↗"</a>
                                    })}

                                    // Decision chain history
                                    {(!chain.is_empty()).then(|| view! {
                                        <div class="tui-stack" style="font-size:0.82rem;border-top:1px dashed var(--border);padding-top:0.4rem">
                                            {chain.into_iter().map(|dv| view! {
                                                <div class="tui-row-between">
                                                    <div class="tui-row">
                                                        <span class=if dv.effective { "bbs-badge bbs-badge-ok" } else { "bbs-badge" }>
                                                            {dv.entry.action.clone()}
                                                        </span>
                                                        <AuthorChip pubkey=dv.entry.signer_pubkey.clone() />
                                                        {dv.superseded.then(|| view! { <span class="tui-muted">"(superseded)"</span> })}
                                                    </div>
                                                    <span class="tui-muted">{dv.entry.reason.clone()}</span>
                                                </div>
                                            }).collect_view()}
                                        </div>
                                    })}

                                    // Receipt ladder (ADR-2010)
                                    {case_receipts
                                        .and_then(|cr| cr.by_decision.values().next().map(|r| r.stage.label()))
                                        .map(|stage_lbl| view! {
                                            <div class="tui-row" style="font-size:0.78rem">
                                                <span class="tui-muted">"Receipt:"</span>
                                                <span class="bbs-badge bbs-badge-info">{stage_lbl}</span>
                                            </div>
                                        })}

                                    // Decision controls
                                    {(tab == "pending" && decidable).then(|| {
                                        let submit_approve = submit_decision.clone();
                                        let submit_reject = submit_decision.clone();
                                        let submit_promote = submit_decision.clone();
                                        let submit_demote = submit_decision.clone();
                                        let submit_delegate = Callback::new(submit_decision);
                                        let needs_why = rationale_required(effective);

                                        view! {
                                            <div class="tui-stack" style="border-top:1px solid var(--border);padding-top:0.55rem">
                                                <input
                                                    class="bbs-input"
                                                    type="text"
                                                    placeholder=if needs_why {
                                                        "Rationale required (min 20 chars for High/Critical)…"
                                                    } else {
                                                        "Optional decision rationale…"
                                                    }
                                                    prop:value=move || rationale.get()
                                                    on:input=move |ev| rationale.set(event_target_value(&ev))
                                                />
                                                <div class="tui-row">
                                                    {match controls {
                                                        DecisionControls::PromoteDemote { iri } => {
                                                            let iri_p = iri.clone();
                                                            let iri_d = iri;
                                                            view! {
                                                                <button
                                                                    type="button"
                                                                    class="bbs-btn bbs-btn-primary bbs-btn-sm"
                                                                    disabled=move || submitting.get()
                                                                    on:click=move |_| submit_promote(DecisionOutcome::Promote {
                                                                        iri: iri_p.clone(),
                                                                    })
                                                                >"▶ Promote"</button>
                                                                <button
                                                                    type="button"
                                                                    class="bbs-btn bbs-btn-danger bbs-btn-sm"
                                                                    disabled=move || submitting.get()
                                                                    on:click=move |_| submit_demote(DecisionOutcome::Demote {
                                                                        iri: iri_d.clone(),
                                                                    })
                                                                >"✗ Demote"</button>
                                                                <button
                                                                    type="button"
                                                                    class="bbs-btn bbs-btn-sm"
                                                                    disabled=move || submitting.get()
                                                                    on:click=move |_| submit_reject(DecisionOutcome::Reject)
                                                                >"✗ Reject"</button>
                                                            }.into_any()
                                                        }
                                                        DecisionControls::ApproveReject => view! {
                                                            <button
                                                                type="button"
                                                                class="bbs-btn bbs-btn-primary bbs-btn-sm"
                                                                disabled=move || submitting.get()
                                                                on:click=move |_| submit_approve(DecisionOutcome::Approve)
                                                            >"▶ Approve"</button>
                                                            <button
                                                                type="button"
                                                                class="bbs-btn bbs-btn-danger bbs-btn-sm"
                                                                disabled=move || submitting.get()
                                                                on:click=move |_| submit_reject(DecisionOutcome::Reject)
                                                            >"✗ Reject"</button>
                                                            <button
                                                                type="button"
                                                                class="bbs-btn bbs-btn-sm"
                                                                on:click=move |_| show_delegate.update(|v| *v = !*v)
                                                            >"↳ Delegate"</button>
                                                        }.into_any(),
                                                    }}
                                                </div>
                                                <Show when=move || show_delegate.get() fallback=|| ()>
                                                    <div class="tui-row">
                                                        <input
                                                            class="bbs-input"
                                                            type="text"
                                                            placeholder="Delegate pubkey (npub1… or 64-char hex)"
                                                            prop:value=move || delegate_input.get()
                                                            on:input=move |ev| delegate_input.set(event_target_value(&ev))
                                                        />
                                                        <button
                                                            type="button"
                                                            class="bbs-btn bbs-btn-sm"
                                                            on:click=move |_| {
                                                                let raw = delegate_input.get_untracked();
                                                                match normalise_delegate_pubkey(&raw) {
                                                                    Some(pk) => {
                                                                        submit_delegate.run(DecisionOutcome::Delegate {
                                                                            delegate_to: pk,
                                                                        });
                                                                        show_delegate.set(false);
                                                                    }
                                                                    None => toasts.show("Enter a valid npub or 64-char hex pubkey", ToastVariant::Error),
                                                                }
                                                            }
                                                        >"Send Delegation"</button>
                                                    </div>
                                                </Show>
                                            </div>
                                        }
                                    })}
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
