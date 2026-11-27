//! Per-zone Kanban Task Board (`#/z/<zone>/kanban`).
//!
//! Speaks Kanbanstr-compatible addressable kind-30301 (board) and kind-30302
//! (card) scoped by `["zone", id]` using `nostr_bbs_core::kanban`, with:
//! - Multi-author newest-wins card folding (`fold_cards`)
//! - Mobile-friendly column filter tabs + desktop horizontal column grid
//! - Create card, move card across columns (including approval-gated columns
//!   raising kind-31402 ActionRequest), and kind-38000 "Send to agent" dispatch!

use std::collections::HashMap;
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::{Filter, RelayConnection};
use nostr_bbs_client_core::stores::zones::{load_zones, resolve_zone_param};
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_core::event::{NostrEvent, UnsignedEvent};
use nostr_bbs_core::governance::KIND_ACTION_REQUEST;
use nostr_bbs_core::kanban::{
    fold_cards, KanbanBoard, KanbanCard, KIND_AGENT_INTENT, KIND_KANBAN_BOARD, KIND_KANBAN_CARD,
    PENDING_MOVE_TAG, RANK_TAG, STATUS_TAG,
};

use crate::components::{AuthorChip, EmptyCard, MarkdownBody};
use crate::router::{use_router, Route};

/// Per-zone Kanban board (`#/z/<zone>/kanban`).
#[component]
pub fn KanbanView(zone: String) -> impl IntoView {
    let router = use_router();
    let relay = expect_context::<RelayConnection>();
    let auth = use_auth();
    let toasts = use_toasts();

    let zones = load_zones();
    let resolved = resolve_zone_param(&zone, &zones).cloned();
    let zone_id = resolved
        .as_ref()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| zone.clone());
    let zone_title = resolved
        .as_ref()
        .map(|z| z.label())
        .unwrap_or_else(|| zone.clone());

    let boards = RwSignal::new(HashMap::<String, KanbanBoard>::new());
    let raw_cards = RwSignal::new(Vec::<KanbanCard>::new());
    let selected_board = RwSignal::new(Option::<String>::None);
    let col_filter = RwSignal::new(Option::<String>::None);
    let show_new_card = RwSignal::new(false);
    let new_title = RwSignal::new(String::new());
    let new_desc = RwSignal::new(String::new());
    let new_col = RwSignal::new(String::new());

    // Subscribe to zone-scoped 30301 boards and 30302 cards.
    let zid_sub = zone_id.clone();
    let relay_sub = relay.clone();
    Effect::new(move |_| {
        let f_boards = Filter {
            kinds: Some(vec![KIND_KANBAN_BOARD, KIND_KANBAN_CARD]),
            limit: Some(500),
            ..Default::default()
        };
        let z_match = zid_sub.clone();
        let on_ev = Rc::new(move |ev: NostrEvent| {
            if let Some(b) = KanbanBoard::from_event(&ev) {
                if b.zone.as_deref() == Some(z_match.as_str()) {
                    let coord = b.coord();
                    boards.update(|m| {
                        let replace = m
                            .get(&coord)
                            .map(|old| b.created_at >= old.created_at)
                            .unwrap_or(true);
                        if replace {
                            m.insert(coord.clone(), b);
                        }
                    });
                    if selected_board.get_untracked().is_none() {
                        selected_board.set(Some(coord));
                    }
                }
            } else if let Some(c) = KanbanCard::from_event(&ev) {
                if c.zone.as_deref() == Some(z_match.as_str()) {
                    raw_cards.update(|list| {
                        if !list.iter().any(|x| x.id == c.id) {
                            list.push(c);
                        }
                    });
                }
            }
        });
        let sub_id = relay_sub.subscribe(vec![f_boards], on_ev, None);
        let r_clean = relay_sub.clone();
        on_cleanup(move || r_clean.unsubscribe(&sub_id));
    });

    let zid_create = zone_id.clone();
    let relay_create = relay.clone();
    let create_card = move |_| {
        let title = new_title.get_untracked().trim().to_string();
        if title.is_empty() {
            return;
        }
        let Some(signer) = auth.get_signer() else {
            toasts.show("Sign in to create cards", ToastVariant::Warning);
            return;
        };
        let Some(b_coord) = selected_board.get_untracked() else {
            return;
        };
        let col = new_col.get_untracked();
        let col = if col.is_empty() {
            boards
                .get_untracked()
                .get(&b_coord)
                .and_then(|b| b.columns.first())
                .map(|c| c.id.clone())
                .unwrap_or_else(|| "todo".into())
        } else {
            col
        };
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let d_tag = format!("card-{now}-{}", js_sys::Math::random().to_bits() & 0xffff);
        let tags = vec![
            vec!["d".into(), d_tag],
            vec!["a".into(), b_coord],
            vec!["title".into(), title],
            vec![STATUS_TAG.into(), col],
            vec![RANK_TAG.into(), "100".into()],
            vec!["zone".into(), zid_create.clone()],
        ];
        let unsigned = UnsignedEvent {
            pubkey: signer.public_key().to_string(),
            created_at: now,
            kind: KIND_KANBAN_CARD,
            tags,
            content: new_desc.get_untracked().trim().to_string(),
        };
        let relay = relay_create.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match signer.sign_event(unsigned).await {
                Ok(signed) => {
                    relay.publish(&signed);
                    new_title.set(String::new());
                    new_desc.set(String::new());
                    show_new_card.set(false);
                    toasts.show("Card published", ToastVariant::Success);
                }
                Err(e) => toasts.show(format!("Sign failed: {e}"), ToastVariant::Error),
            }
        });
    };

    let move_card = {
        let relay = relay.clone();
        let zid = zone_id.clone();
        move |card: KanbanCard, target_col: String, needs_approval: bool| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in to move cards", ToastVariant::Warning);
                return;
            };
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let relay = relay.clone();
            let zid = zid.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let mut tags = vec![
                    vec!["d".into(), card.d_tag.clone()],
                    vec!["a".into(), card.board.clone()],
                    vec!["title".into(), card.title.clone()],
                    vec![RANK_TAG.into(), card.rank.to_string()],
                    vec!["zone".into(), zid.clone()],
                ];
                for a in &card.assignees {
                    tags.push(vec!["p".into(), a.clone()]);
                }
                if needs_approval {
                    // Publish kind-31402 approval request first
                    let req_d = format!("kanban-move-{}-{now}", card.d_tag);
                    let req_unsigned = UnsignedEvent {
                        pubkey: signer.public_key().to_string(),
                        created_at: now,
                        kind: KIND_ACTION_REQUEST,
                        tags: vec![
                            vec!["d".into(), req_d],
                            vec!["a".into(), card.board.clone()],
                            vec!["zone".into(), zid.clone()],
                            vec!["t".into(), "kanban-approval".into()],
                        ],
                        content: serde_json::json!({
                            "summary": format!("Approve moving '{}' → {}", card.title, target_col),
                            "fields": { "card": card.d_tag, "from": card.column, "to": target_col }
                        })
                        .to_string(),
                    };
                    if let Ok(req_signed) = signer.sign_event(req_unsigned).await {
                        let req_id = req_signed.id.clone();
                        relay.publish(&req_signed);
                        tags.push(vec![STATUS_TAG.into(), card.column.clone()]);
                        tags.push(vec![PENDING_MOVE_TAG.into(), target_col, req_id]);
                    } else {
                        return;
                    }
                } else {
                    tags.push(vec![STATUS_TAG.into(), target_col]);
                }

                let unsigned = UnsignedEvent {
                    pubkey: signer.public_key().to_string(),
                    created_at: now,
                    kind: KIND_KANBAN_CARD,
                    tags,
                    content: card.description,
                };
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show(
                            if needs_approval {
                                "Approval requested (kind-31402)"
                            } else {
                                "Card moved"
                            },
                            ToastVariant::Success,
                        );
                    }
                    Err(e) => toasts.show(format!("Move failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let dispatch_agent = {
        let relay = relay.clone();
        let zid = zone_id.clone();
        move |card: KanbanCard| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Sign in first", ToastVariant::Warning);
                return;
            };
            let now = (js_sys::Date::now() / 1000.0) as u64;
            let unsigned = UnsignedEvent {
                pubkey: signer.public_key().to_string(),
                created_at: now,
                kind: KIND_AGENT_INTENT,
                tags: vec![
                    vec!["a".into(), card.board.clone()],
                    vec!["zone".into(), zid.clone()],
                    vec!["t".into(), "kanban-dispatch".into()],
                ],
                content: serde_json::json!({
                    "card_id": card.d_tag,
                    "title": card.title,
                    "description": card.description,
                    "column": card.column,
                })
                .to_string(),
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match signer.sign_event(unsigned).await {
                    Ok(signed) => {
                        relay.publish(&signed);
                        toasts.show("Dispatched to agent (kind-38000)", ToastVariant::Info);
                    }
                    Err(e) => toasts.show(format!("Dispatch failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let zone_back = zone.clone();

    view! {
        <div class="tui-container wide">
            <div class="tui-crumb">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::Zone { slug: zone_back.clone() })
                >"← " {zone_title.clone()}</button>
                <span>"/"</span>
                <strong>"Kanban"</strong>
            </div>

            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"▤ " {zone_title} " — Kanban Board"</h1>
                    <p class="tui-page-sub">"Addressable kind-30301/30302 collaborative task board with approval gates & agent dispatch."</p>
                </div>
                <div class="tui-actions">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        on:click=move |_| show_new_card.update(|v| *v = !*v)
                    >{move || if show_new_card.get() { "× Close" } else { "+ New Card" }}</button>
                </div>
            </div>

            <Show when=move || show_new_card.get() fallback=|| ()>
                <div class="tui-card tui-stack">
                    <strong>"Create Card"</strong>
                    <input
                        class="bbs-input"
                        type="text"
                        placeholder="Card title…"
                        prop:value=move || new_title.get()
                        on:input=move |ev| new_title.set(event_target_value(&ev))
                    />
                    <textarea
                        class="bbs-textarea"
                        placeholder="Description (Markdown)…"
                        prop:value=move || new_desc.get()
                        on:input=move |ev| new_desc.set(event_target_value(&ev))
                    ></textarea>
                    <div class="tui-row">
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            on:click={
                                let cb = create_card.clone();
                                move |ev| cb(ev)
                            }
                        >
                            "Publish Card ▶"
                        </button>
                    </div>
                </div>
            </Show>

            {move || {
                let bmap = boards.get();
                let Some(coord) = selected_board.get().or_else(|| bmap.keys().next().cloned()) else {
                    return view! {
                        <EmptyCard
                            title="No Kanban board in this zone yet"
                            body="Boards (kind-30301) stream from the relay when configured for this zone."
                        />
                    }.into_any();
                };
                let Some(board) = bmap.get(&coord).cloned() else {
                    return view! { <EmptyCard title="Loading board…" body="Waiting for board definition." /> }.into_any();
                };

                let all_folded: Vec<KanbanCard> = fold_cards(
                    raw_cards
                        .get()
                        .into_iter()
                        .filter(|c| c.board == coord),
                )
                .into_iter()
                .filter(|c| !c.deleted)
                .collect();

                let filter_sel = col_filter.get();
                let cols_for_tabs = board.columns.clone();
                let cols_all = board.columns.clone();

                view! {
                    // Mobile-friendly column selector tabs
                    <div class="tui-tabs">
                        <button
                            type="button"
                            class="tui-tab"
                            class:active=move || col_filter.get().is_none()
                            on:click=move |_| col_filter.set(None)
                        >"All Columns"</button>
                        {cols_for_tabs.into_iter().map(|col| {
                            let cid = col.id.clone();
                            let cid_act = cid.clone();
                            let cnt = all_folded.iter().filter(|c| c.column == cid).count();
                            view! {
                                <button
                                    type="button"
                                    class="tui-tab"
                                    class:active=move || col_filter.get().as_deref() == Some(cid_act.as_str())
                                    on:click=move |_| col_filter.set(Some(cid.clone()))
                                >
                                    {col.name} " (" {cnt} ")"
                                </button>
                            }
                        }).collect_view()}
                    </div>

                    <div class="bbs-kanban-grid">
                        {board.columns.clone().into_iter().filter(|col| {
                            filter_sel.as_deref().is_none_or(|f| f == col.id)
                        }).map(|col| {
                            let col_id = col.id.clone();
                            let needs_gate = board.column_needs_approval(&col_id);
                            let mut col_cards: Vec<KanbanCard> = all_folded
                                .iter()
                                .filter(|c| c.column == col_id)
                                .cloned()
                                .collect();
                            col_cards.sort_by_key(|c| c.rank);
                            let other_cols = cols_all.clone();
                            let approval_cols = board.approval_columns.clone();

                            view! {
                                <section class="bbs-kanban-col">
                                    <div class="bbs-kanban-col-head">
                                        <span>{col.name}</span>
                                        <div class="tui-row">
                                            {needs_gate.then(|| view! { <span class="bbs-badge bbs-badge-warn">"GATE"</span> })}
                                            <span class="bbs-badge">{col_cards.len()}</span>
                                        </div>
                                    </div>

                                    {if col_cards.is_empty() {
                                        view! { <p class="tui-muted" style="font-size:0.8rem;padding:0.4rem">"(empty)"</p> }.into_any()
                                    } else {
                                        view! {
                                            {col_cards.into_iter().map(|card| {
                                                let other = other_cols.clone();
                                                let ap_cols = approval_cols.clone();
                                                let mv = move_card.clone();
                                                let disp = dispatch_agent.clone();
                                                let card_disp = card.clone();

                                                view! {
                                                    <div class="bbs-kanban-card">
                                                        <strong>{card.title.clone()}</strong>
                                                        {(!card.description.is_empty()).then(|| view! {
                                                            <div style="font-size:0.82rem">
                                                                <MarkdownBody content=card.description.clone() />
                                                            </div>
                                                        })}
                                                        {card.pending_move.as_ref().map(|(to, _)| view! {
                                                            <span class="bbs-badge bbs-badge-warn">
                                                                "⏳ Pending approval → " {to.clone()}
                                                            </span>
                                                        })}
                                                        {(!card.assignees.is_empty()).then(|| view! {
                                                            <div class="tui-row" style="font-size:0.78rem">
                                                                {card.assignees.iter().map(|pk| view! {
                                                                    <AuthorChip pubkey=pk.clone() />
                                                                }).collect_view()}
                                                            </div>
                                                        })}
                                                        <div class="tui-row" style="padding-top:0.25rem;border-top:1px dashed var(--border)">
                                                            {other.into_iter().filter(|c| c.id != card.column).map(|dst| {
                                                                let dst_id = dst.id.clone();
                                                                let gated = ap_cols.iter().any(|x| x == &dst_id);
                                                                let c_mv = card.clone();
                                                                let mv_fn = mv.clone();
                                                                view! {
                                                                    <button
                                                                        type="button"
                                                                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                                                        on:click=move |_| mv_fn(c_mv.clone(), dst_id.clone(), gated)
                                                                    >"→ " {dst.name}</button>
                                                                }
                                                            }).collect_view()}
                                                            <button
                                                                type="button"
                                                                class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                                                on:click=move |_| disp(card_disp.clone())
                                                            >"◈ Agent"</button>
                                                        </div>
                                                    </div>
                                                }
                                            }).collect_view()}
                                        }.into_any()
                                    }}
                                </section>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
