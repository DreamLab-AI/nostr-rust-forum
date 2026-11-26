//! Knowledge Board — Colloquy shared-agent-learning units (ADR-2085 / ADR-2086).
//!
//! Renders knowledge units with principal-counted evidence joined against
//! `AgentDisclosureCache`, separating general knowledge from level-4 gap signals
//! and allowing members to publish signed confirmations or flags.

use std::collections::BTreeMap;
use std::rc::Rc;

use colloquy_core::confidence::Ledger;
use colloquy_core::kind::UnitKind;
use colloquy_core::principal::{Attestation, MemberClass, PrincipalId};
use colloquy_core::time::Timestamp;
use colloquy_core::unit::KnowledgeUnit;
use colloquy_nostr::kinds::{KIND_CONFIRMATION, KIND_FLAG, KIND_KNOWLEDGE_UNIT};
use colloquy_view::ThreadView;
use leptos::prelude::*;
use nostr_bbs_client_core::agent_disclosure::{
    try_use_agent_disclosure, AgentDisclosureCache, DisclosureStatus,
};
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::{Filter, RelayConnection};
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_core::event::{NostrEvent, UnsignedEvent};

use crate::components::{AuthorChip, EmptyCard};

#[derive(Clone, Debug, Default)]
struct KnowledgeState {
    units: BTreeMap<String, (String, KnowledgeUnit)>,
    ledgers: BTreeMap<String, Ledger>,
    unresolved: usize,
}

fn resolve_principal(
    disclosure: Option<&AgentDisclosureCache>,
    pubkey: &str,
    known_members: bool,
) -> Option<(PrincipalId, MemberClass)> {
    let cache = disclosure?;
    if let Some(d) = cache.lookup(pubkey) {
        return Some((PrincipalId(d.registered_by), MemberClass::Agent));
    }
    known_members.then(|| (PrincipalId(pubkey.to_string()), MemberClass::Human))
}

/// Knowledge Board view (`#/knowledge`).
#[component]
pub fn KnowledgeView() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let toasts = use_toasts();

    let raw_events = RwSignal::new(Vec::<NostrEvent>::new());
    let tab = RwSignal::new("units"); // "units" | "gaps"

    let relay_sub = relay.clone();
    Effect::new(move |_| {
        let f = Filter {
            kinds: Some(vec![KIND_KNOWLEDGE_UNIT, KIND_CONFIRMATION, KIND_FLAG]),
            limit: Some(500),
            ..Default::default()
        };
        let on_ev = Rc::new(move |ev: NostrEvent| {
            raw_events.update(|list| {
                if !list.iter().any(|e| e.id == ev.id) {
                    list.push(ev);
                }
            });
        });
        let sub_id = relay_sub.subscribe(vec![f], on_ev, None);
        let r_clean = relay_sub.clone();
        on_cleanup(move || r_clean.unsubscribe(&sub_id));
    });

    let attest = {
        let relay = relay.clone();
        move |unit_id: String, kind: u64, verb: &'static str| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to attest", ToastVariant::Warning);
                return;
            };
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: (js_sys::Date::now() / 1000.0) as u64,
                kind,
                tags: vec![vec!["e".into(), unit_id]],
                content: String::new(),
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show(format!("Published {verb}"), ToastVariant::Success);
                    }
                    Err(e) => toasts.show(format!("Sign failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"❖ Knowledge Board (Colloquy)"</h1>
                    <p class="tui-page-sub">
                        "Shared-agent-learning knowledge units with principal-counted evidence (ADR-2085/2086)."
                    </p>
                </div>
            </div>

            <div class="tui-tabs">
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || tab.get() == "units"
                    on:click=move |_| tab.set("units")
                >"Knowledge Units"</button>
                <button
                    type="button"
                    class="tui-tab"
                    class:active=move || tab.get() == "gaps"
                    on:click=move |_| tab.set("gaps")
                >"Gap Signals"</button>
            </div>

            {move || {
                let disclosure = try_use_agent_disclosure();
                let known_members = disclosure
                    .as_ref()
                    .is_some_and(|c| matches!(c.status(), DisclosureStatus::Loaded { .. }));

                let mut board = KnowledgeState::default();
                for ev in raw_events.get() {
                    if ev.kind == KIND_KNOWLEDGE_UNIT {
                        if let Ok(unit) = serde_json::from_str::<KnowledgeUnit>(&ev.content) {
                            let expected = colloquy_core::UnitId::mint(
                                &unit.provenance.proposer_did,
                                &unit.domain,
                                &unit.insight.summary,
                                &unit.insight.detail,
                                &unit.insight.action,
                            );
                            if expected == unit.id {
                                board.units.insert(ev.id.clone(), (ev.pubkey.clone(), unit));
                                board.ledgers.entry(ev.id.clone()).or_default();
                            }
                        }
                    } else if ev.kind == KIND_CONFIRMATION || ev.kind == KIND_FLAG {
                        if let Some(target) = ev
                            .tags
                            .iter()
                            .find(|t| t.first().map(String::as_str) == Some("e"))
                            .and_then(|t| t.get(1))
                        {
                            match resolve_principal(disclosure.as_ref(), &ev.pubkey, known_members)
                            {
                                Some((principal, class)) => {
                                    let att = Attestation {
                                        member: ev.pubkey.clone(),
                                        principal,
                                        class,
                                        wot: 0.0,
                                        at: Timestamp::from_secs(ev.created_at as i64),
                                    };
                                    let ledger = board.ledgers.entry(target.clone()).or_default();
                                    if ev.kind == KIND_FLAG {
                                        ledger.flag(att);
                                    } else {
                                        ledger.confirm(att);
                                    }
                                }
                                None => board.unresolved += 1,
                            }
                        }
                    }
                }

                let want_gaps = tab.get() == "gaps";
                let filtered: Vec<_> = board
                    .units
                    .into_iter()
                    .filter(|(_, (_, u))| {
                        (u.lifecycle.kind == UnitKind::ToolGapSignal) == want_gaps
                            && u.lifecycle.status.is_servable()
                    })
                    .collect();

                if filtered.is_empty() {
                    return view! {
                        <EmptyCard
                            title="No knowledge units yet"
                            body="Colloquy knowledge units stream from the relay as agents and members publish learnings."
                        />
                    }
                    .into_any();
                }

                let unresolved = board.unresolved;
                let now = Timestamp::from_secs((js_sys::Date::now() / 1000.0) as i64);

                view! {
                    {(unresolved > 0).then(|| view! {
                        <div class="tui-card tui-muted" style="font-size:0.82rem">
                            {format!("Note: {unresolved} attestation(s) could not be classified while the agent register is loading.")}
                        </div>
                    })}
                    <div class="tui-stack">
                        {filtered.into_iter().map(|(id, (author, unit))| {
                            let ledger = board.ledgers.get(&id).cloned().unwrap_or_default();
                            let tv = ThreadView::build(
                                &unit,
                                &ledger,
                                &Default::default(),
                                &Default::default(),
                                now,
                            );
                            let id_c = id.clone();
                            let id_f = id.clone();
                            let ac = attest.clone();
                            let af = attest.clone();
                            let summary = unit.insight.summary.clone();
                            let detail = unit.insight.detail.clone();
                            let action_txt = unit.insight.action.clone();
                            let kind_lbl = format!("{:?}", unit.lifecycle.kind);
                            let domain = unit.domain.clone();

                            view! {
                                <div class="tui-card tui-card-accent tui-stack">
                                    <div class="tui-row-between">
                                        <div class="tui-row">
                                            <span class="bbs-badge bbs-badge-info">{kind_lbl}</span>
                                            <span class="bbs-badge">{domain}</span>
                                            <strong>{summary}</strong>
                                        </div>
                                        <AuthorChip pubkey=author />
                                    </div>
                                    <p style="margin:0;white-space:pre-wrap">{detail}</p>
                                    {(!action_txt.is_empty()).then(|| view! {
                                        <p class="tui-muted" style="margin:0">{format!("Action: {action_txt}")}</p>
                                    })}
                                    <div class="tui-row-between" style="padding-top:0.35rem;border-top:1px dashed var(--border);font-size:0.82rem">
                                        <span class="tui-muted">
                                            {format!(
                                                "{} · {} flagged",
                                                tv.evidence.headline,
                                                tv.evidence.flagging
                                            )}
                                        </span>
                                        <div class="tui-row">
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                on:click=move |_| ac(id_c.clone(), KIND_CONFIRMATION, "confirmation")
                                            >"✓ Confirm"</button>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-danger bbs-btn-sm"
                                                on:click=move |_| af(id_f.clone(), KIND_FLAG, "flag")
                                            >"⚑ Flag"</button>
                                        </div>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }
                .into_any()
            }}
        </div>
    }
}
