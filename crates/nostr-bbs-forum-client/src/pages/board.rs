//! Per-zone kanban task board.
//!
//! Route: `/forums/:category/board` (and the `/:category/board` slug alias).
//!
//! Board data rides Kanbanstr-compatible addressable events — kind 30301 board
//! definitions and kind 30302 cards — zone-bound with the calendar's
//! `["zone", <id>]` tag. The relay is the security boundary: zone write
//! cohorts govern who may publish boards/cards, the zone read gate governs who
//! receives them; this page only follows (ADR-022).
//!
//! Collaboration model: a card's identity is `(board coordinate, d tag)` and
//! the newest version across authors wins ([`nostr_bbs_core::fold_cards`]), so
//! any zone member can move any card — the intended semantic for a shared
//! zone board.
//!
//! Approval-gated columns (decision-broker bridge): a board may mark columns
//! as requiring a human decision (`approval_col` tags, e.g. "Done"). Moving a
//! card there republishes it with a `pending_move` tag and raises a
//! kanban-scoped kind-31402 ActionRequest; the relay admits these from
//! ordinary members (unlike agent 31402s). An admin resolves it with a
//! kind-31403 Approve/Reject — the same signed, immutable decision event the
//! judgment-broker projector records into D1 `broker_decisions`.
//!
//! Agent dispatch (VisionFlow bridge): "Send to agent" publishes a kind-38000
//! agent intent carrying the card as a JSON task envelope; the agentbox relay
//! consumer routes it to the agent's inbox.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use std::collections::HashMap;
use std::rc::Rc;

use nostr_bbs_core::{
    fold_cards, parse_approval_decision, BoardColumn, CardInput, KanbanBoard, KanbanCard,
    NostrEvent, KIND_KANBAN_BOARD, KIND_KANBAN_CARD,
};

use crate::auth::use_auth;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::toast::{use_toasts, ToastStore, ToastVariant};
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::zone_access::use_zone_access;
use crate::stores::zones::{load_zones, resolve_zone_param, ZoneVisibility};

const KIND_ACTION_REQUEST: u64 = 31402;
const KIND_ACTION_RESPONSE: u64 = 31403;

/// Resolved approval state of a pending move.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingState {
    Awaiting,
    Approved,
    Rejected,
}

/// Board-page shared state, provided as context to card/form children so
/// component props stay plain data (Leptos requires `Send + Sync` props; the
/// relay handle is `Rc`-based and is resolved from context instead).
#[derive(Clone, Copy)]
struct BoardCtx {
    /// Kanban 31402 requests by event id (admins respond to these).
    approval_requests: RwSignal<HashMap<String, NostrEvent>>,
    /// 31403 decisions: request event id -> approved.
    decisions: RwSignal<HashMap<String, bool>>,
    /// Card currently being dragged (HTML5 drag-and-drop). Set on `dragstart`
    /// by the card, consumed on `drop` by the target column.
    dragging: RwSignal<Option<KanbanCard>>,
}

/// Publish with an ack toast — the RSVP-buttons pattern.
fn publish_with_toast(
    relay: &RelayConnection,
    toasts: ToastStore,
    event: &NostrEvent,
    ok_msg: &'static str,
) {
    let ack = Rc::new(move |accepted: bool, message: String| {
        if accepted {
            toasts.show(ok_msg.to_string(), ToastVariant::Success);
        } else {
            let display = if message.trim().is_empty() {
                "Rejected by relay".to_string()
            } else {
                format!("Rejected: {message}")
            };
            toasts.show(display, ToastVariant::Error);
        }
    });
    if let Err(e) = relay.publish_with_ack(event, Some(ack)) {
        toasts.show(format!("Publish failed: {e}"), ToastVariant::Error);
    }
}

/// Current unix seconds (also used as an append-to-bottom rank).
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Move `card` into `target_col`, honouring the approval gate: a direct move
/// republishes the card; an approval-gated move raises the kanban 31402 first
/// and republishes the card with the `pending_move` tag. Shared by the card's
/// Move buttons and column drag-and-drop.
fn spawn_move(
    relay: RelayConnection,
    toasts: ToastStore,
    signer: Rc<dyn nostr_bbs_core::signer::Signer>,
    card: KanbanCard,
    target_col: String,
    needs_approval: bool,
) {
    let mut input = input_from(&card);
    input.pending_move = None;

    if !needs_approval {
        input.column = target_col;
        input.rank = now_secs() as i64;
        wasm_bindgen_futures::spawn_local(async move {
            match nostr_bbs_core::create_card_signer(signer.as_ref(), &input).await {
                Ok(event) => publish_with_toast(&relay, toasts, &event, "Card moved"),
                Err(e) => toasts.show(format!("Card failed: {e}"), ToastVariant::Error),
            }
        });
        return;
    }

    wasm_bindgen_futures::spawn_local(async move {
        match nostr_bbs_core::create_card_approval_request_signer(
            signer.as_ref(),
            &card,
            &target_col,
            "",
        )
        .await
        {
            Ok(request) => {
                let request_id = request.id.clone();
                publish_with_toast(&relay, toasts, &request, "Approval requested");
                input.pending_move = Some((target_col, request_id));
                match nostr_bbs_core::create_card_signer(signer.as_ref(), &input).await {
                    Ok(event) => {
                        publish_with_toast(&relay, toasts, &event, "Card marked pending")
                    }
                    Err(e) => toasts.show(format!("Card failed: {e}"), ToastVariant::Error),
                }
            }
            Err(e) => toasts.show(format!("Approval request failed: {e}"), ToastVariant::Error),
        }
    });
}

/// Render a card description with minimal bullet-list support: consecutive
/// lines starting with `- ` or `* ` become a `<ul>`, everything else renders
/// as paragraphs. Text-only (Leptos escapes by default) — no inline HTML.
fn render_description(text: &str) -> impl IntoView {
    enum Block {
        Para(String),
        List(Vec<String>),
    }
    let mut blocks: Vec<Block> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let bullet = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "));
        match bullet {
            Some(item) => match blocks.last_mut() {
                Some(Block::List(items)) => items.push(item.to_string()),
                _ => blocks.push(Block::List(vec![item.to_string()])),
            },
            None => {
                if !line.trim().is_empty() {
                    blocks.push(Block::Para(line.to_string()));
                }
            }
        }
    }
    blocks
        .into_iter()
        .map(|b| match b {
            Block::Para(t) => view! {
                <p class="text-xs text-gray-300 whitespace-pre-wrap">{t}</p>
            }
            .into_any(),
            Block::List(items) => view! {
                <ul class="text-xs text-gray-300 list-disc pl-4 space-y-0.5">
                    {items
                        .into_iter()
                        .map(|i| view! { <li>{i}</li> })
                        .collect_view()}
                </ul>
            }
            .into_any(),
        })
        .collect_view()
}

/// Unix seconds -> `datetime-local` input value (`YYYY-MM-DDTHH:MM`, local time).
fn due_to_input_value(ts: u64) -> String {
    let d = js_sys::Date::new_0();
    d.set_time((ts as f64) * 1000.0);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        d.get_full_year(),
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes()
    )
}

/// `datetime-local` input value -> unix seconds (None when empty/invalid).
fn input_value_to_due(raw: &str) -> Option<u64> {
    if raw.is_empty() {
        return None;
    }
    let ms = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(raw)).get_time();
    if ms.is_nan() {
        None
    } else {
        Some((ms / 1000.0) as u64)
    }
}

/// Rebuild a [`CardInput`] from an existing card version, preserving identity.
fn input_from(card: &KanbanCard) -> CardInput {
    CardInput {
        d_tag: Some(card.d_tag.clone()),
        board: card.board.clone(),
        title: card.title.clone(),
        description: card.description.clone(),
        column: card.column.clone(),
        rank: card.rank,
        assignees: card.assignees.clone(),
        due: card.due,
        zone: card.zone.clone(),
        pending_move: card.pending_move.clone(),
        deleted: card.deleted,
    }
}

#[component]
pub fn BoardPage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let zone_access = use_zone_access();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    let params = use_params_map();
    let category_slug = move || params.read().get("category").unwrap_or_default();

    // Canonical zone id for the URL param (slug or legacy id).
    let zone_id = Memo::new(move |_| {
        let slug = category_slug();
        let zs = load_zones();
        resolve_zone_param(&slug, &zs).map(|z| z.id.clone())
    });
    let zone_label = Memo::new(move |_| {
        let slug = category_slug();
        let zs = load_zones();
        resolve_zone_param(&slug, &zs)
            .map(|z| z.label())
            .unwrap_or_else(|| slug.clone())
    });
    let kanban_enabled = Memo::new(move |_| {
        let slug = category_slug();
        let zs = load_zones();
        resolve_zone_param(&slug, &zs)
            .map(|z| z.kanban)
            .unwrap_or(false)
    });

    // Access gate mirrors CategoryPage: relay is the real boundary (ADR-022).
    let has_zone_access = Memo::new(move |_| {
        let slug = category_slug();
        let zs = load_zones();
        match resolve_zone_param(&slug, &zs).cloned() {
            Some(zone) => {
                zone.visibility == ZoneVisibility::Public || zone_access.is_member_of(&zone)
            }
            None => false,
        }
    });
    let is_admin = zone_access.is_admin;

    // -- Relay-fed state ------------------------------------------------------

    let board_events: RwSignal<Vec<NostrEvent>> = RwSignal::new(Vec::new());
    let card_versions: RwSignal<Vec<KanbanCard>> = RwSignal::new(Vec::new());
    let ctx = BoardCtx {
        approval_requests: RwSignal::new(HashMap::new()),
        decisions: RwSignal::new(HashMap::new()),
        dragging: RwSignal::new(None),
    };
    provide_context(ctx);
    let toasts = use_toasts();
    let auth_for_drop = auth;

    let loading = RwSignal::new(true);
    let sub_ids: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    // Selected board d-tag (multi-board zones).
    let selected_board: RwSignal<Option<String>> = RwSignal::new(None);
    let show_create_board = RwSignal::new(false);
    let show_create_card = RwSignal::new(false);

    let relay_for_sub = relay.clone();
    // Copy-able handle over the Rc-based relay for the drag-and-drop handlers:
    // nested view closures capture the arena key instead of moving clones
    // through every closure boundary.
    let relay_for_dnd = StoredValue::new_local(relay.clone());
    let relay_for_cleanup = relay;
    Effect::new(move |_| {
        if conn_state.get() != ConnectionState::Connected {
            return;
        }
        if !sub_ids.get_untracked().is_empty() {
            return;
        }
        let Some(zid) = zone_id.get() else { return };

        loading.set(true);

        // Boards + cards. The relay's zone read gate already withholds other
        // zones' private boards; the zone filter here keeps THIS page scoped
        // when the viewer can read several zones.
        let zid_events = zid.clone();
        let on_kanban = Rc::new(move |event: NostrEvent| {
            let event_zone = nostr_bbs_core::read_zone_tag(&event).unwrap_or("");
            if event_zone != zid_events {
                return;
            }
            match event.kind {
                KIND_KANBAN_BOARD => {
                    board_events.update(|list| {
                        // Latest per (pubkey, d): replaceable semantics client-side.
                        let d = event
                            .tags
                            .iter()
                            .find(|t| t.len() >= 2 && t[0] == "d")
                            .map(|t| t[1].clone())
                            .unwrap_or_default();
                        if let Some(pos) = list.iter().position(|e| {
                            e.pubkey == event.pubkey
                                && e.tags
                                    .iter()
                                    .any(|t| t.len() >= 2 && t[0] == "d" && t[1] == d)
                        }) {
                            if list[pos].created_at <= event.created_at {
                                list[pos] = event;
                            }
                        } else {
                            list.push(event);
                        }
                    });
                }
                KIND_KANBAN_CARD => {
                    if let Some(card) = KanbanCard::from_event(&event) {
                        card_versions.update(|list| list.push(card));
                    }
                }
                _ => {}
            }
        });
        let on_eose = Rc::new(move || loading.set(false));
        let sid1 = relay_for_sub.subscribe(
            vec![Filter {
                kinds: Some(vec![KIND_KANBAN_BOARD, KIND_KANBAN_CARD]),
                ..Default::default()
            }],
            on_kanban,
            Some(on_eose),
        );

        // Approval traffic. Low volume; matched client-side by card reference.
        let on_governance = Rc::new(move |event: NostrEvent| match event.kind {
            KIND_ACTION_REQUEST => {
                if nostr_bbs_core::is_kanban_approval_request(&event) {
                    ctx.approval_requests.update(|map| {
                        map.insert(event.id.clone(), event);
                    });
                }
            }
            KIND_ACTION_RESPONSE => {
                if let Some(decision) = parse_approval_decision(&event) {
                    ctx.decisions.update(|map| {
                        map.insert(decision.request_id, decision.approved);
                    });
                }
            }
            _ => {}
        });
        let sid2 = relay_for_sub.subscribe(
            vec![Filter {
                kinds: Some(vec![KIND_ACTION_REQUEST, KIND_ACTION_RESPONSE]),
                ..Default::default()
            }],
            on_governance,
            None,
        );

        sub_ids.set(vec![sid1, sid2]);
    });

    on_cleanup(move || {
        for id in sub_ids.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    // -- Derived board/card state ----------------------------------------------

    let boards = Memo::new(move |_| {
        let mut list: Vec<KanbanBoard> = board_events
            .get()
            .iter()
            .filter_map(KanbanBoard::from_event)
            .collect();
        list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        list
    });

    let active_board = Memo::new(move |_| {
        let list = boards.get();
        match selected_board.get() {
            Some(d) => list.iter().find(|b| b.d_tag == d).cloned(),
            None => list.first().cloned(),
        }
    });

    let active_cards = Memo::new(move |_| {
        let Some(board) = active_board.get() else {
            return Vec::new();
        };
        let coord = board.coord();
        let mut cards = fold_cards(
            card_versions
                .get()
                .into_iter()
                .filter(|c| c.board == coord),
        );
        // Deletion tombstones win the fold (newest version), then hide here.
        cards.retain(|c| !c.deleted);
        cards
    });

    // -- View --------------------------------------------------------------------

    view! {
        <div class="mesh-bg min-h-[80vh] relative overflow-hidden">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
                {move || {
                    let label = zone_label.get();
                    let zone_href = format!("/forums/{}", category_slug());
                    view! {
                        <Breadcrumb items=vec![
                            BreadcrumbItem::link("Home", "/"),
                            BreadcrumbItem::link(label, zone_href),
                            BreadcrumbItem::current("Board"),
                        ] />
                    }
                }}

                <Show when=move || !kanban_enabled.get()>
                    <div class="glass-card p-8 text-center mt-6">
                        <h2 class="text-xl font-bold text-white mb-2">"No board here"</h2>
                        <p class="text-sm text-gray-400">
                            "This zone does not have a task board enabled. An operator can enable it with "
                            <code class="text-amber-400">"kanban = true"</code>
                            " on the zone."
                        </p>
                    </div>
                </Show>

                <Show when=move || kanban_enabled.get() && !has_zone_access.get()>
                    <div class="glass-card p-8 text-center mt-6">
                        <h2 class="text-xl font-bold text-white mb-2">"Access restricted"</h2>
                        <p class="text-sm text-gray-400">"You are not a member of this zone."</p>
                    </div>
                </Show>

                <Show when=move || kanban_enabled.get() && has_zone_access.get()>
                    // Header row: title + board picker + actions
                    <div class="flex items-center justify-between flex-wrap gap-3 mt-4 mb-6">
                        <h1 class="text-2xl sm:text-3xl font-bold candy-gradient">
                            {move || format!("{} — Task board", zone_label.get())}
                            // The active board's name — otherwise a single
                            // board's title is invisible (the picker only
                            // mounts with two or more boards), and a board
                            // created with a task-like name looks lost.
                            {move || {
                                active_board
                                    .get()
                                    .map(|b| {
                                        view! {
                                            <span class="block text-sm font-normal text-gray-400 mt-1">
                                                {b.title}
                                            </span>
                                        }
                                    })
                            }}
                        </h1>
                        <div class="flex items-center gap-2">
                            <Show when=move || { boards.get().len() > 1 }>
                                <select
                                    class="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm za-focus"
                                    on:change=move |ev| {
                                        selected_board.set(Some(event_target_value(&ev)))
                                    }
                                >
                                    {move || {
                                        boards
                                            .get()
                                            .into_iter()
                                            .map(|b| {
                                                view! {
                                                    <option value=b.d_tag.clone()>{b.title.clone()}</option>
                                                }
                                            })
                                            .collect_view()
                                    }}
                                </select>
                            </Show>
                            <Show when=move || is_authed.get() && active_board.get().is_some()>
                                <button
                                    class="inline-flex items-center gap-1.5 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
                                    on:click=move |_| show_create_card.set(true)
                                >
                                    "+ Card"
                                </button>
                            </Show>
                            <Show when=move || is_authed.get()>
                                <button
                                    class="inline-flex items-center gap-1.5 text-sm text-gray-300 hover:text-white border border-gray-600 hover:border-gray-400 px-3 py-2 rounded-lg transition-colors"
                                    on:click=move |_| show_create_board.set(true)
                                >
                                    "New board"
                                </button>
                            </Show>
                        </div>
                    </div>

                    <Show when=move || loading.get()>
                        <div class="glass-card p-6 animate-pulse">
                            <div class="h-4 bg-gray-700 rounded w-1/3 mb-3"></div>
                            <div class="h-3 bg-gray-700 rounded w-2/3"></div>
                        </div>
                    </Show>

                    <Show when=move || !loading.get() && active_board.get().is_none()>
                        <div class="glass-card p-8 text-center">
                            <h3 class="text-lg font-bold text-white mb-2">"No board yet"</h3>
                            <p class="text-sm text-gray-400 mb-4">
                                "Create the zone's first task board — anyone in the zone can add and move cards."
                            </p>
                        </div>
                    </Show>

                    // Columns
                    <Show when=move || active_board.get().is_some()>
                        <div class="flex gap-4 overflow-x-auto pb-4 items-start">
                            {move || {
                                let Some(board) = active_board.get() else {
                                    return ().into_any();
                                };
                                let cards = active_cards.get();
                                let decisions_map = ctx.decisions.get();
                                let admin = is_admin.get();
                                board
                                    .columns
                                    .iter()
                                    .map(|col| {
                                        let col_id = col.id.clone();
                                        let col_name = col.name.clone();
                                        let needs_approval = board.column_needs_approval(&col_id);
                                        // A card renders in its pending TARGET column
                                        // once approved; otherwise it stays put.
                                        let col_cards: Vec<KanbanCard> = cards
                                            .iter()
                                            .filter(|c| {
                                                let effective = match &c.pending_move {
                                                    Some((target, req)) => {
                                                        match decisions_map.get(req) {
                                                            Some(true) => target.clone(),
                                                            _ => c.column.clone(),
                                                        }
                                                    }
                                                    None => c.column.clone(),
                                                };
                                                effective == col_id
                                            })
                                            .cloned()
                                            .collect();
                                        let count = col_cards.len();
                                        // Column drop target: consume the dragged
                                        // card and run the same gated move the
                                        // card's Move buttons use.
                                        let drop_col = col_id.clone();
                                        let drop_approval = needs_approval;
                                        let on_drop = move |ev: leptos::ev::DragEvent| {
                                            ev.prevent_default();
                                            let Some(card) =
                                                ctx.dragging.try_update(|d| d.take()).flatten()
                                            else {
                                                return;
                                            };
                                            if card.column == drop_col {
                                                return;
                                            }
                                            let Some(signer) = auth_for_drop.get_signer() else {
                                                toasts.show(
                                                    "Not authenticated",
                                                    ToastVariant::Error,
                                                );
                                                return;
                                            };
                                            let relay = relay_for_dnd.get_value();
                                            spawn_move(
                                                relay,
                                                toasts,
                                                signer,
                                                card,
                                                drop_col.clone(),
                                                drop_approval && !admin,
                                            );
                                        };
                                        view! {
                                            <div
                                                class="flex-shrink-0 w-72 sm:w-80 bg-gray-900/60 border border-gray-700/60 rounded-xl p-3"
                                                on:dragover=move |ev: leptos::ev::DragEvent| {
                                                    ev.prevent_default()
                                                }
                                                on:drop=on_drop
                                            >
                                                <div class="flex items-center justify-between mb-3 px-1">
                                                    <h3 class="text-sm font-bold text-white uppercase tracking-wide">
                                                        {col_name}
                                                        {needs_approval
                                                            .then(|| {
                                                                view! {
                                                                    <span
                                                                        class="ml-1.5 text-amber-400"
                                                                        title="Entering this column requires an admin decision"
                                                                    >
                                                                        {"\u{1F512}"}
                                                                    </span>
                                                                }
                                                            })}
                                                    </h3>
                                                    <span class="text-xs text-gray-500">{count}</span>
                                                </div>
                                                <div class="space-y-2">
                                                    {col_cards
                                                        .into_iter()
                                                        .map(|card| {
                                                            let pending_state = card
                                                                .pending_move
                                                                .as_ref()
                                                                .map(|(_, req)| match decisions_map.get(req) {
                                                                    Some(true) => PendingState::Approved,
                                                                    Some(false) => PendingState::Rejected,
                                                                    None => PendingState::Awaiting,
                                                                });
                                                            view! {
                                                                <CardView
                                                                    card=card
                                                                    columns=board.columns.clone()
                                                                    approval_columns=board.approval_columns.clone()
                                                                    pending_state=pending_state
                                                                    is_admin=admin
                                                                />
                                                            }
                                                        })
                                                        .collect_view()}
                                                </div>
                                            </div>
                                        }
                                    })
                                    .collect_view()
                                    .into_any()
                            }}
                        </div>
                    </Show>

                    // Create board form
                    <Show when=move || show_create_board.get()>
                        {move || {
                            zone_id
                                .get()
                                .map(|zid| {
                                    view! {
                                        <CreateBoardForm
                                            zone_id=zid
                                            on_close=Callback::new(move |()| {
                                                show_create_board.set(false)
                                            })
                                            on_created=Callback::new(move |()| {
                                                // Guide straight into card
                                                // creation: the + Card form
                                                // mounts as soon as the new
                                                // board arrives from the relay.
                                                show_create_card.set(true)
                                            })
                                        />
                                    }
                                })
                        }}
                    </Show>

                    // Create card form
                    <Show when=move || show_create_card.get()>
                        {move || {
                            active_board
                                .get()
                                .map(|board| {
                                    view! {
                                        <CreateCardForm
                                            board=board
                                            on_close=Callback::new(move |()| {
                                                show_create_card.set(false)
                                            })
                                        />
                                    }
                                })
                        }}
                    </Show>
                </Show>
            </div>
        </div>
    }
}

// -- Card ------------------------------------------------------------------------

#[component]
fn CardView(
    card: KanbanCard,
    columns: Vec<BoardColumn>,
    approval_columns: Vec<String>,
    pending_state: Option<PendingState>,
    is_admin: bool,
) -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();
    let relay = expect_context::<RelayConnection>();
    let ctx = expect_context::<BoardCtx>();
    let my_pubkey = auth.pubkey();

    let expanded = RwSignal::new(false);
    let show_dispatch = RwSignal::new(false);
    let agent_input = RwSignal::new(String::new());
    // Inline edit form state, pre-filled from this card version.
    let editing = RwSignal::new(false);
    let edit_title = RwSignal::new(card.title.clone());
    let edit_desc = RwSignal::new(card.description.clone());
    let edit_due = RwSignal::new(card.due.map(due_to_input_value).unwrap_or_default());
    // Two-step delete confirmation.
    let del_confirm = RwSignal::new(false);
    let assignee_input = RwSignal::new(String::new());

    let title = card.title.clone();
    let description = card.description.clone();
    let due = card.due;
    let assignees = card.assignees.clone();
    let request_id = card.pending_move.as_ref().map(|(_, r)| r.clone());
    let pending_target = card.pending_move.as_ref().map(|(t, _)| t.clone());

    let due_label = due.map(|ts| {
        let d = js_sys::Date::new_0();
        d.set_time((ts as f64) * 1000.0);
        format!(
            "Due {:04}-{:02}-{:02}",
            d.get_full_year(),
            d.get_month() + 1,
            d.get_date()
        )
    });

    // Republish a card version. Shared by move/claim/finalise below.
    let publish_card = {
        let relay = relay.clone();
        move |input: CardInput, ok_msg: &'static str| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match nostr_bbs_core::create_card_signer(signer.as_ref(), &input).await {
                    Ok(event) => publish_with_toast(&relay, toasts, &event, ok_msg),
                    Err(e) => toasts.show(format!("Card failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    // Copy-able handle so nested Show children (edit form, delete confirm,
    // assignee rows) capture an arena key instead of moving the closure.
    let publish_card_sv = StoredValue::new_local(publish_card.clone());
    let card_sv = StoredValue::new_local(card.clone());

    // Move: approval-gated targets raise a 31402 and mark the card pending
    // (admins move directly). Shared logic with column drag-and-drop.
    let move_to = {
        let relay = relay.clone();
        let card = card.clone();
        let approval_columns = approval_columns.clone();
        move |target_col: String| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            };
            let needs_approval = approval_columns.iter().any(|c| *c == target_col) && !is_admin;
            spawn_move(
                relay.clone(),
                toasts,
                signer,
                card.clone(),
                target_col,
                needs_approval,
            );
        }
    };

    // Admin decision on the pending request.
    let decide = {
        let relay = relay.clone();
        move |request_id: String, approve: bool| {
            let Some(request) = ctx
                .approval_requests
                .get_untracked()
                .get(&request_id)
                .cloned()
            else {
                toasts.show("Request not found yet", ToastVariant::Error);
                return;
            };
            let Some(signer) = auth.get_signer() else {
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            };
            let relay = relay.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match nostr_bbs_core::create_card_approval_response_signer(
                    signer.as_ref(),
                    &request,
                    approve,
                )
                .await
                {
                    Ok(response) => publish_with_toast(
                        &relay,
                        toasts,
                        &response,
                        if approve { "Approved" } else { "Rejected" },
                    ),
                    Err(e) => toasts.show(format!("Decision failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    // Finalise a resolved pending move (anyone in the zone can tidy).
    let finalise = {
        let publish_card = publish_card.clone();
        let card = card.clone();
        move |state: PendingState| {
            let Some((target_col, _)) = card.pending_move.clone() else {
                return;
            };
            let mut input = input_from(&card);
            input.pending_move = None;
            if state == PendingState::Approved {
                input.column = target_col;
                input.rank = now_secs() as i64;
            }
            publish_card(input, "Card updated");
        }
    };

    // Claim: add my pubkey to assignees.
    let claim = {
        let publish_card = publish_card.clone();
        let card = card.clone();
        move |_| {
            let Some(me) = my_pubkey.get_untracked() else {
                return;
            };
            if card.assignees.contains(&me) {
                toasts.show("Already assigned", ToastVariant::Info);
                return;
            }
            let mut input = input_from(&card);
            input.assignees.push(me);
            publish_card(input, "Card claimed");
        }
    };

    // Dispatch to agent: kind-38000 agent intent.
    let dispatch = {
        let relay = relay.clone();
        let card = card.clone();
        move |agent_pubkey: String| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            };
            let relay = relay.clone();
            let card = card.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match nostr_bbs_core::create_agent_intent_signer(
                    signer.as_ref(),
                    &card,
                    &agent_pubkey,
                    "",
                )
                .await
                {
                    Ok(intent) => {
                        publish_with_toast(&relay, toasts, &intent, "Task dispatched to agent")
                    }
                    Err(e) => toasts.show(format!("Dispatch failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    // Due date → zone calendar (kind 31923 linked back to the card).
    let add_to_calendar = {
        let relay = relay.clone();
        let card = card.clone();
        move |_| {
            let Some(signer) = auth.get_signer() else {
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            };
            let relay = relay.clone();
            let card = card.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match nostr_bbs_core::create_card_due_event_signer(signer.as_ref(), &card).await {
                    Ok(event) => publish_with_toast(
                        &relay,
                        toasts,
                        &event,
                        "Due date added to zone calendar",
                    ),
                    Err(e) => toasts.show(format!("Calendar failed: {e}"), ToastVariant::Error),
                }
            });
        }
    };

    let card_column = card.column.clone();
    let card_for_drag = card.clone();

    view! {
        <div
            class="glass-card p-3 border border-gray-700/50 hover:border-gray-500/60 transition-colors cursor-grab active:cursor-grabbing"
            draggable="true"
            on:dragstart=move |ev: leptos::ev::DragEvent| {
                // Firefox requires dataTransfer payload to initiate a drag; the
                // real state rides the shared `dragging` signal.
                if let Some(dt) = ev.data_transfer() {
                    let _ = dt.set_data("text/plain", &card_for_drag.d_tag);
                }
                ctx.dragging.set(Some(card_for_drag.clone()));
            }
            on:dragend=move |_| ctx.dragging.set(None)
        >
            <button class="w-full text-left" on:click=move |_| expanded.update(|e| *e = !*e)>
                <div class="flex items-start justify-between gap-2">
                    <span class="font-medium text-white text-sm leading-snug">{title.clone()}</span>
                    {match pending_state {
                        Some(PendingState::Awaiting) => Some(
                            view! {
                                <span class="text-[10px] uppercase tracking-wide bg-amber-500/20 text-amber-400 rounded-full px-2 py-0.5 flex-shrink-0">
                                    "pending"
                                </span>
                            }
                                .into_any(),
                        ),
                        Some(PendingState::Approved) => Some(
                            view! {
                                <span class="text-[10px] uppercase tracking-wide bg-emerald-500/20 text-emerald-400 rounded-full px-2 py-0.5 flex-shrink-0">
                                    "approved"
                                </span>
                            }
                                .into_any(),
                        ),
                        Some(PendingState::Rejected) => Some(
                            view! {
                                <span class="text-[10px] uppercase tracking-wide bg-red-500/20 text-red-400 rounded-full px-2 py-0.5 flex-shrink-0">
                                    "rejected"
                                </span>
                            }
                                .into_any(),
                        ),
                        None => None,
                    }}
                </div>
                <div class="flex items-center gap-2 mt-1.5 flex-wrap">
                    {due_label
                        .map(|label| {
                            view! {
                                <span class="text-[11px] text-gray-400 bg-gray-800/80 rounded px-1.5 py-0.5">
                                    {label}
                                </span>
                            }
                        })}
                    {(!assignees.is_empty())
                        .then(|| {
                            view! {
                                <span class="text-[11px] text-gray-400">
                                    {format!(
                                        "{} assignee{}",
                                        assignees.len(),
                                        if assignees.len() == 1 { "" } else { "s" },
                                    )}
                                </span>
                            }
                        })}
                </div>
            </button>

            <Show when=move || expanded.get()>
                <div class="mt-2 pt-2 border-t border-gray-700/50 space-y-2">
                    {(!description.is_empty())
                        .then(|| render_description(&description))}

                    // Assignees: chips with remove, plus an add-by-pubkey row.
                    <div class="flex items-center gap-1.5 flex-wrap">
                        <span class="text-[11px] text-gray-500">"Assignees:"</span>
                        {card
                            .assignees
                            .iter()
                            .map(|pk| {
                                let pk_full = pk.clone();
                                let short = format!("{}…{}", &pk[..6], &pk[pk.len() - 4..]);
                                view! {
                                    <span class="inline-flex items-center gap-1 text-[11px] text-gray-300 bg-gray-800 rounded-full px-2 py-0.5">
                                        {short}
                                        <button
                                            class="text-gray-500 hover:text-red-400"
                                            title="Remove assignee"
                                            on:click=move |_| {
                                                let card = card_sv.get_value();
                                                let mut input = input_from(&card);
                                                input.assignees.retain(|a| *a != pk_full);
                                                publish_card_sv
                                                    .with_value(|p| p(input, "Assignee removed"));
                                            }
                                        >
                                            {"\u{00d7}"}
                                        </button>
                                    </span>
                                }
                            })
                            .collect_view()}
                        <input
                            type="text"
                            placeholder="Add pubkey (hex)"
                            prop:value=move || assignee_input.get()
                            on:input=move |ev| assignee_input.set(event_target_value(&ev))
                            class="w-36 bg-gray-900 border border-gray-600 rounded px-2 py-0.5 text-[11px] text-white placeholder-gray-500 za-focus"
                        />
                        <button
                            class="text-[11px] text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded px-2 py-0.5"
                            on:click=move |_| {
                                let pk = assignee_input.get_untracked().trim().to_string();
                                if pk.len() != 64 || hex::decode(&pk).is_err() {
                                    toasts.show(
                                        "Assignee must be a 64-hex pubkey",
                                        ToastVariant::Error,
                                    );
                                    return;
                                }
                                let card = card_sv.get_value();
                                if card.assignees.contains(&pk) {
                                    toasts.show("Already assigned", ToastVariant::Info);
                                    return;
                                }
                                let mut input = input_from(&card);
                                input.assignees.push(pk);
                                publish_card_sv.with_value(|p| p(input, "Assignee added"));
                                assignee_input.set(String::new());
                            }
                        >
                            "Add"
                        </button>
                    </div>

                    // Pending decision row
                    {match (pending_state, request_id.clone(), pending_target.clone()) {
                        (Some(PendingState::Awaiting), Some(req), Some(target)) => {
                            let decide_a = decide.clone();
                            let decide_r = decide.clone();
                            let req_r = req.clone();
                            Some(
                                view! {
                                    <div class="flex items-center gap-2 flex-wrap">
                                        <span class="text-[11px] text-amber-400">
                                            {format!("Awaiting approval \u{2192} {target}")}
                                        </span>
                                        <Show when=move || is_admin>
                                            <button
                                                class="text-[11px] bg-emerald-600 hover:bg-emerald-500 text-white rounded px-2 py-1"
                                                on:click={
                                                    let decide_a = decide_a.clone();
                                                    let req_a = req.clone();
                                                    move |_| decide_a(req_a.clone(), true)
                                                }
                                            >
                                                "Approve"
                                            </button>
                                            <button
                                                class="text-[11px] bg-red-600 hover:bg-red-500 text-white rounded px-2 py-1"
                                                on:click={
                                                    let decide_r = decide_r.clone();
                                                    let req_r = req_r.clone();
                                                    move |_| decide_r(req_r.clone(), false)
                                                }
                                            >
                                                "Reject"
                                            </button>
                                        </Show>
                                    </div>
                                }
                                    .into_any(),
                            )
                        }
                        (Some(state @ (PendingState::Approved | PendingState::Rejected)), _, _) => {
                            let finalise = finalise.clone();
                            Some(
                                view! {
                                    <button
                                        class="text-[11px] text-gray-300 hover:text-white border border-gray-600 rounded px-2 py-1"
                                        on:click=move |_| finalise(state)
                                    >
                                        {if state == PendingState::Approved {
                                            "Finalise move"
                                        } else {
                                            "Dismiss rejection"
                                        }}
                                    </button>
                                }
                                    .into_any(),
                            )
                        }
                        _ => None,
                    }}

                    // Move buttons
                    <div class="flex items-center gap-1.5 flex-wrap">
                        <span class="text-[11px] text-gray-500">"Move:"</span>
                        {columns
                            .iter()
                            .filter(|c| c.id != card_column)
                            .map(|c| {
                                let move_to = move_to.clone();
                                let target = c.id.clone();
                                view! {
                                    <button
                                        class="text-[11px] text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded px-2 py-1"
                                        on:click=move |_| move_to(target.clone())
                                    >
                                        {c.name.clone()}
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>

                    // Actions row
                    <div class="flex items-center gap-1.5 flex-wrap">
                        <button
                            class="text-[11px] text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded px-2 py-1"
                            on:click={
                                let claim = claim.clone();
                                move |ev| claim(ev)
                            }
                        >
                            "Claim"
                        </button>
                        {due.is_some()
                            .then(|| {
                                let add_to_calendar = add_to_calendar.clone();
                                view! {
                                    <button
                                        class="text-[11px] text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded px-2 py-1"
                                        on:click=move |ev| add_to_calendar(ev)
                                    >
                                        "Add to calendar"
                                    </button>
                                }
                            })}
                        <button
                            class="text-[11px] text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded px-2 py-1"
                            on:click=move |_| show_dispatch.update(|s| *s = !*s)
                        >
                            "Send to agent"
                        </button>
                        <button
                            class="text-[11px] text-gray-300 hover:text-white bg-gray-800 hover:bg-gray-700 rounded px-2 py-1"
                            on:click=move |_| editing.update(|e| *e = !*e)
                        >
                            "Edit"
                        </button>
                        {move || {
                            if del_confirm.get() {
                                view! {
                                    <button
                                        class="text-[11px] bg-red-600 hover:bg-red-500 text-white rounded px-2 py-1"
                                        on:click=move |_| {
                                            let card = card_sv.get_value();
                                            let mut input = input_from(&card);
                                            input.deleted = true;
                                            input.pending_move = None;
                                            publish_card_sv
                                                .with_value(|p| p(input, "Card deleted"));
                                        }
                                    >
                                        "Confirm delete"
                                    </button>
                                }
                                    .into_any()
                            } else {
                                view! {
                                    <button
                                        class="text-[11px] text-red-400 hover:text-red-300 bg-gray-800 hover:bg-gray-700 rounded px-2 py-1"
                                        on:click=move |_| del_confirm.set(true)
                                    >
                                        "Delete"
                                    </button>
                                }
                                    .into_any()
                            }
                        }}
                    </div>

                    // Inline edit form (title / description / due date).
                    <Show when=move || editing.get()>
                        <div class="space-y-1.5 bg-gray-900/60 border border-gray-700/60 rounded-lg p-2">
                            <input
                                type="text"
                                maxlength="120"
                                prop:value=move || edit_title.get()
                                on:input=move |ev| edit_title.set(event_target_value(&ev))
                                class="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-white za-focus"
                            />
                            <textarea
                                placeholder="Description — lines starting with \"- \" render as bullets"
                                prop:value=move || edit_desc.get()
                                on:input=move |ev| edit_desc.set(event_target_value(&ev))
                                class="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-white placeholder-gray-500 za-focus h-16"
                            ></textarea>
                            <input
                                type="datetime-local"
                                prop:value=move || edit_due.get()
                                on:input=move |ev| edit_due.set(event_target_value(&ev))
                                class="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-white za-focus"
                            />
                            <div class="flex gap-1.5">
                                <button
                                    class="text-[11px] bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold rounded px-2 py-1"
                                    on:click=move |_| {
                                        let t = edit_title.get_untracked().trim().to_string();
                                        if t.is_empty() {
                                            toasts.show(
                                                "Card needs a title",
                                                ToastVariant::Error,
                                            );
                                            return;
                                        }
                                        let card = card_sv.get_value();
                                        let mut input = input_from(&card);
                                        input.title = t;
                                        input.description = edit_desc.get_untracked();
                                        input.due =
                                            input_value_to_due(&edit_due.get_untracked());
                                        publish_card_sv.with_value(|p| p(input, "Card updated"));
                                        editing.set(false);
                                    }
                                >
                                    "Save"
                                </button>
                                <button
                                    class="text-[11px] text-gray-400 hover:text-white px-2 py-1"
                                    on:click=move |_| editing.set(false)
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </div>
                    </Show>

                    // Agent dispatch inline row. Wrapped in an interpolation
                    // block so the nested Show's children closure captures a
                    // per-run CLONE of `dispatch`, keeping the outer children
                    // closure `Fn` (not `FnOnce`).
                    {
                        let dispatch = dispatch.clone();
                        view! {
                            <Show when=move || show_dispatch.get()>
                                <div class="flex items-center gap-1.5">
                                    <input
                                        type="text"
                                        placeholder="Agent pubkey (hex)"
                                        prop:value=move || agent_input.get()
                                        on:input=move |ev| agent_input.set(event_target_value(&ev))
                                        class="flex-1 bg-gray-900 border border-gray-600 rounded px-2 py-1 text-[11px] text-white placeholder-gray-500 za-focus"
                                    />
                                    <button
                                        class="text-[11px] bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold rounded px-2 py-1"
                                        on:click={
                                            let dispatch = dispatch.clone();
                                            move |_| {
                                                let agent =
                                                    agent_input.get_untracked().trim().to_string();
                                                if agent.len() == 64 {
                                                    dispatch(agent);
                                                    show_dispatch.set(false);
                                                } else {
                                                    toasts.show(
                                                        "Agent pubkey must be 64 hex chars",
                                                        ToastVariant::Error,
                                                    );
                                                }
                                            }
                                        }
                                    >
                                        "Send"
                                    </button>
                                </div>
                            </Show>
                        }
                    }
                </div>
            </Show>
        </div>
    }
}

// -- Create board form ---------------------------------------------------------------

#[component]
fn CreateBoardForm(
    zone_id: String,
    on_close: Callback<()>,
    on_created: Callback<()>,
) -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();
    let relay = expect_context::<RelayConnection>();

    let title = RwSignal::new(String::new());
    let approval_done = RwSignal::new(true);
    let submitting = RwSignal::new(false);

    let submit = move |_| {
        let t = title.get_untracked().trim().to_string();
        if t.is_empty() {
            toasts.show("Board needs a title", ToastVariant::Error);
            return;
        }
        let Some(signer) = auth.get_signer() else {
            toasts.show("Not authenticated", ToastVariant::Error);
            return;
        };
        submitting.set(true);
        let zone = zone_id.clone();
        let approval: Vec<String> = if approval_done.get_untracked() {
            vec!["done".to_string()]
        } else {
            Vec::new()
        };
        let relay = relay.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let columns = vec![
                ("todo".to_string(), "To do".to_string()),
                ("doing".to_string(), "Doing".to_string()),
                ("done".to_string(), "Done".to_string()),
            ];
            match nostr_bbs_core::create_board_signer(
                signer.as_ref(),
                &t,
                "",
                &columns,
                &approval,
                &[],
                Some(&zone),
                None,
            )
            .await
            {
                Ok(event) => {
                    publish_with_toast(&relay, toasts, &event, "Board created");
                    on_created.run(());
                    // `on_close` unmounts this form and disposes its signals —
                    // do NOT touch `submitting` after this, even via try_set:
                    // the write re-notifies the disposed `disabled` effect and
                    // panics the WASM runtime.
                    on_close.run(());
                }
                Err(e) => {
                    toasts.show(format!("Board failed: {e}"), ToastVariant::Error);
                    // Error path: form is still mounted, re-enable the button.
                    let _ = submitting.try_set(false);
                }
            }
        });
    };

    view! {
        <div class="glass-card p-5 mt-4 space-y-3 max-w-md">
            <h3 class="text-lg font-semibold text-white">"New board"</h3>
            <input
                type="text"
                maxlength="80"
                placeholder="Board name (e.g. Sprint board) — you add task cards next"
                prop:value=move || title.get()
                on:input=move |ev| title.set(event_target_value(&ev))
                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 za-focus"
            />
            <label class="flex items-center gap-2 text-sm text-gray-300">
                <input
                    type="checkbox"
                    prop:checked=move || approval_done.get()
                    on:change=move |ev| approval_done.set(event_target_checked(&ev))
                />
                "\"Done\" requires admin approval (decision broker)"
            </label>
            <p class="text-xs text-gray-500">
                "This names the BOARD, not a task. It starts with To do / Doing / Done columns; the card form opens right after so you can add your first task."
            </p>
            <div class="flex gap-2">
                <button
                    class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg text-sm disabled:opacity-50"
                    disabled=move || submitting.try_get().unwrap_or(false)
                    on:click=submit
                >
                    "Create board"
                </button>
                <button
                    class="text-sm text-gray-400 hover:text-white px-3 py-2"
                    on:click=move |_| on_close.run(())
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// -- Create card form ----------------------------------------------------------------

#[component]
fn CreateCardForm(board: KanbanBoard, on_close: Callback<()>) -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();
    let relay = expect_context::<RelayConnection>();

    let title = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let due_input = RwSignal::new(String::new());

    let first_col = board
        .columns
        .first()
        .map(|c| c.id.clone())
        .unwrap_or_else(|| "todo".to_string());
    let board_coord = board.coord();
    let zone = board.zone.clone();

    let submit = move |_| {
        let t = title.get_untracked().trim().to_string();
        if t.is_empty() {
            toasts.show("Card needs a title", ToastVariant::Error);
            return;
        }
        let Some(signer) = auth.get_signer() else {
            toasts.show("Not authenticated", ToastVariant::Error);
            return;
        };
        // datetime-local -> unix seconds
        let due = {
            let raw = due_input.get_untracked();
            if raw.is_empty() {
                None
            } else {
                let ms = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(&raw)).get_time();
                if ms.is_nan() {
                    None
                } else {
                    Some((ms / 1000.0) as u64)
                }
            }
        };
        let input = CardInput {
            d_tag: None,
            board: board_coord.clone(),
            title: t,
            description: description.get_untracked(),
            column: first_col.clone(),
            rank: now_secs() as i64,
            assignees: Vec::new(),
            due,
            zone: zone.clone(),
            pending_move: None,
            deleted: false,
        };
        let relay = relay.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match nostr_bbs_core::create_card_signer(signer.as_ref(), &input).await {
                Ok(event) => {
                    publish_with_toast(&relay, toasts, &event, "Card created");
                    on_close.run(());
                }
                Err(e) => toasts.show(format!("Card failed: {e}"), ToastVariant::Error),
            }
        });
    };

    view! {
        <div class="glass-card p-5 mt-4 space-y-3 max-w-md">
            <h3 class="text-lg font-semibold text-white">"New card"</h3>
            <input
                type="text"
                maxlength="120"
                placeholder="Card title"
                prop:value=move || title.get()
                on:input=move |ev| title.set(event_target_value(&ev))
                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 za-focus"
            />
            <textarea
                placeholder="Description (optional)"
                prop:value=move || description.get()
                on:input=move |ev| description.set(event_target_value(&ev))
                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 za-focus h-20"
            ></textarea>
            <div>
                <label class="block text-sm text-gray-400 mb-1">"Due date (optional)"</label>
                <input
                    type="datetime-local"
                    prop:value=move || due_input.get()
                    on:input=move |ev| due_input.set(event_target_value(&ev))
                    class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white za-focus"
                />
            </div>
            <div class="flex gap-2">
                <button
                    class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg text-sm"
                    on:click=submit
                >
                    "Add card"
                </button>
                <button
                    class="text-sm text-gray-400 hover:text-white px-3 py-2"
                    on:click=move |_| on_close.run(())
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}
