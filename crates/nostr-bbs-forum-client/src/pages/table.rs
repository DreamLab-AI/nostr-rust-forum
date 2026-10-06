//! `/table`: the poker table — heads-up fixed-limit hold'em.
//!
//! Two tables share the page. The **practice table** runs entirely in the
//! browser for chips that are worth nothing: each hand both stacks reset to
//! the buy-in, the shuffle is committed before the deal (the page shows
//! SHA-256 of a fresh seed, deals from it, reveals it when the hand ends),
//! and the bot decides from its own seat's view with randomness derived from
//! the seed. The **asset tables** ([`crate::poker::live`]) — the DREAM table
//! on `sidestr:dreamlab`, the BLAKES7 table on `sidestr:dreamlab-txbt4` — are
//! played against that chain's house seat, or against another member the
//! house deals for, and settle each hand on their own chain from the
//! member's wallet on it; one is offered for each chain with an asset and a
//! house seat ([`poker::asset_tables`], ADR-2021). Each has its own tab and
//! its own `#<chain>` fragment (`#sidestr-dreamlab-txbt4`), which a
//! scheduled game links to; one table is open at a time, so one inbox and
//! one set of keyboard shortcuts are live.
//!
//! Either table can be shown in 3D ([`crate::components::table3d`]), a
//! member's choice kept in the preferences store. The scene renders the same
//! seat view and log the flat table does; the flat table stays in the page as
//! the accessible text layer (visually hidden while the scene draws) and as
//! the fallback wherever the scene cannot start. While the scene is still
//! showing what just happened, the action buttons wait for it.

use leptos::ev;
use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::copy_key::KeyName;
use crate::components::flat_peek::{provide_flat_peek, PeekSlot};
use crate::components::fx::use_render_tier;
use crate::components::poker_coach::PokerCoach;
use crate::components::poker_schedule::ScheduleGameModal;
use crate::components::table3d::{self, PeekGroup, Pick, PickTarget, Table3d, Table3dStatus};
use crate::poker::live::{LiveStore, Pay};
use crate::poker::{
    self, AssetTable, Choice, HandConfig, HandOutcome, HandState, HistoryRow, Legal, RosterEntry,
    SeatConfig, SeatView, Stake,
};
use crate::relay::{ConnectionState, RelayConnection};
use crate::stores::preferences::{save_preferences, use_preferences};
use crate::utils::set_timeout_once;
use crate::wallet::{chain, use_wallets};

/// The member's seat at the practice table.
const HERO: u32 = 0;
/// The house bot's seat at the practice table.
const BOT: u32 = 1;
/// How long the bot "thinks", so each turn can be read.
const BOT_DELAY_MS: i32 = 500;
/// Hands kept in the history card.
const HISTORY_LEN: usize = 20;

/// Which table is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Chips that are worth nothing, in the browser.
    Practice,
    /// A chain's asset, with that chain's house seat (the chain id).
    Chain(&'static str),
}

/// The fragment that names a table's section of the page.
fn fragment_of(m: Mode) -> String {
    match m {
        Mode::Practice => "practice".to_string(),
        Mode::Chain(id) => crate::wallet::profile::anchor_of(id),
    }
}

/// The table a page fragment names (`#sidestr-dreamlab-txbt4`), else the
/// first asset table, else the practice table.
fn opening_mode(tables: &[AssetTable], fragment: &str) -> Mode {
    let fragment = fragment.trim_start_matches('#');
    if fragment == "practice" {
        return Mode::Practice;
    }
    tables
        .iter()
        .find(|t| t.profile.anchor() == fragment)
        .or_else(|| tables.first())
        .map_or(Mode::Practice, |t| Mode::Chain(t.profile.id))
}

/// The `/table` route: the table where every gate holds, a notice otherwise.
#[component]
pub fn TablePage() -> impl IntoView {
    if !poker::site_enabled() {
        return view! {
            <div class="max-w-2xl mx-auto px-4 py-16 text-center text-gray-400">
                <p>"This forum has not switched on the poker table."</p>
            </div>
        }
        .into_any();
    }
    let enabled = poker::use_table_enabled();
    view! {
        <Show
            when=move || enabled.get()
            fallback=|| view! {
                <div class="max-w-2xl mx-auto px-4 py-16 text-center text-gray-400 space-y-3">
                    <p>"The poker table is switched off for your account."</p>
                    <p class="text-sm">
                        "Turn it on under "
                        <A href=base_href("/settings") attr:class="text-amber-400 hover:text-amber-300 underline">
                            "Settings → Games"
                        </A>
                        "."
                    </p>
                </div>
            }
        >
            <Tables />
        </Show>
    }
    .into_any()
}

/// The mode switch over the two tables.
#[component]
fn Tables() -> impl IntoView {
    // the schedule modal's invitations are DMs
    crate::dm::provide_dm_store();
    let config = poker::PokerConfig::load();
    let tables = poker::asset_tables();
    let fragment = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .unwrap_or_default();
    let mode = RwSignal::new(opening_mode(&tables, &fragment));
    // the fragment follows the open table, so the address can be shared
    Effect::new(move |_| {
        let frag = fragment_of(mode.get());
        if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
            let _ = h.replace_state_with_url(
                &wasm_bindgen::JsValue::NULL,
                "",
                Some(&format!("#{frag}")),
            );
        }
    });
    let show_schedule = RwSignal::new(false);
    let zone_access = crate::stores::zone_access::use_zone_access();
    let can_schedule = Memo::new(move |_| zone_access.is_admin.get());
    let stakes = config.stakes();
    let prefs = use_preferences();
    let tier = use_render_tier();
    let backend = Memo::new(move |_| table3d::available_backend(tier.get()));
    let three_d = Memo::new(move |_| prefs.with(|p| p.poker_table_3d) && backend.get().is_some());
    let tab = move |m: Mode, label: String| {
        let active = move || mode.get() == m;
        view! {
            <button
                class=move || if active() {
                    "px-3 py-1.5 rounded-lg text-sm font-semibold bg-amber-500 text-gray-900"
                } else {
                    "px-3 py-1.5 rounded-lg text-sm font-semibold bg-gray-800 text-gray-300 hover:bg-gray-700"
                }
                on:click=move |_| mode.set(m)
            >
                {label}
            </button>
        }
    };
    let tables_c = tables.clone();
    view! {
        <div class="max-w-5xl mx-auto px-4 pt-6 flex items-center justify-between gap-3 flex-wrap">
            <div class="flex gap-2 flex-wrap">
                {tables.iter().map(|t| tab(Mode::Chain(t.profile.id), t.title())).collect_view()}
                {tab(Mode::Practice, "Practice chips".to_string())}
            </div>
            <div class="flex items-center gap-4 flex-wrap">
                <label
                    class="text-sm text-gray-300 flex items-center gap-2 cursor-pointer"
                    title=move || if backend.get().is_none() {
                        "The 3D table needs WebGPU or WebGL 2, with reduced motion off; this browser shows the flat table."
                    } else {
                        "Show the table in 3D. The flat table stays available to screen readers."
                    }
                >
                    <input
                        type="checkbox"
                        class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500 disabled:opacity-40"
                        prop:checked=move || three_d.get()
                        prop:disabled=move || backend.get().is_none()
                        on:change=move |_| {
                            prefs.update(|p| p.poker_table_3d = !p.poker_table_3d);
                            save_preferences(&prefs.get_untracked());
                        }
                    />
                    "3D table"
                </label>
                <Show when=move || three_d.get()>
                    <label class="text-sm text-gray-300 flex items-center gap-2 cursor-pointer" title="Green clubs and blue diamonds, so every suit has its own colour">
                        <input
                            type="checkbox"
                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                            prop:checked=move || prefs.with(|p| p.poker_four_colour)
                            on:change=move |_| {
                                prefs.update(|p| p.poker_four_colour = !p.poker_four_colour);
                                save_preferences(&prefs.get_untracked());
                            }
                        />
                        "Four-colour deck"
                    </label>
                </Show>
            </div>
            <Show when=move || can_schedule.get()>
                <button
                    class="px-3 py-1.5 rounded-lg text-sm font-semibold bg-gray-800 text-amber-300 hover:bg-gray-700 border border-amber-500/40"
                    on:click=move |_| show_schedule.set(true)
                >
                    "Schedule a game"
                </button>
            </Show>
        </div>
        {move || match mode.get() {
            Mode::Practice => view! { <PracticeTable /> }.into_any(),
            Mode::Chain(id) => match tables_c.iter().find(|t| t.profile.id == id) {
                Some(t) => view! { <ChainTable table=t.clone() /> }.into_any(),
                None => view! { <PracticeTable /> }.into_any(),
            },
        }}
        <Show when=move || show_schedule.get()>
            <ScheduleGameModal
                stakes=stakes.clone()
                tables=tables.clone()
                chosen=match mode.get_untracked() { Mode::Chain(id) => Some(id), Mode::Practice => None }
                on_close=Callback::new(move |()| show_schedule.set(false))
            />
        </Show>
    }
}

/// Whether a key press is aimed at a text field, which the table's shortcuts
/// must leave alone.
fn typing_into_field(e: &web_sys::KeyboardEvent) -> bool {
    let Some(el) = e
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlElement>().ok())
    else {
        return false;
    };
    matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT") || el.is_content_editable()
}

/// Green for a gain, red for a loss, grey for level.
fn net_tone(n: i64) -> &'static str {
    match n.signum() {
        1 => "text-green-400",
        -1 => "text-red-400",
        _ => "text-gray-300",
    }
}

fn card_face(card: u8) -> AnyView {
    let name = poker::card_name(card);
    let (rank, suit, red) = poker::card_parts(&name);
    let colour = if red { "text-red-600" } else { "text-gray-900" };
    view! {
        <span
            class=format!("inline-flex flex-col items-center justify-center w-10 h-14 sm:w-12 sm:h-16 rounded-md border border-gray-300 bg-white shadow font-bold leading-none select-none {colour}")
            role="img"
            aria-label=name
        >
            <span class="text-base sm:text-lg">{rank}</span>
            <span class="text-base sm:text-lg">{suit}</span>
        </span>
    }
    .into_any()
}

fn card_back() -> AnyView {
    view! {
        <span
            class="inline-block w-10 h-14 sm:w-12 sm:h-16 rounded-md border-2 border-amber-500/60 bg-gradient-to-br from-amber-900/70 to-gray-900 shadow"
            role="img"
            aria-label="face-down card"
        ></span>
    }
    .into_any()
}

fn card_slot() -> AnyView {
    view! {
        <span class="inline-block w-10 h-14 sm:w-12 sm:h-16 rounded-md border border-dashed border-gray-700"></span>
    }
    .into_any()
}

/// One seat: name, stack, position, street bet, and cards. The hero's own
/// face-up cards (`inspectable`) can be inspected (`components::flat_peek`).
fn seat_panel(
    v: &SeatView,
    seat: u32,
    label: AnyView,
    blurb: Option<String>,
    unit: &str,
    inspectable: bool,
) -> AnyView {
    let Some(s) = v.seats.get(seat as usize).cloned() else {
        return ().into_any();
    };
    let position = if seat == v.button { "SB" } else { "BB" };
    let dealer = seat == v.button;
    let to_act = v.phase == "act" && v.to_act == seat as i32;
    let ring = if to_act {
        "ring-2 ring-amber-400"
    } else {
        "ring-1 ring-gray-700/50"
    };
    let cards = match s.hole.clone() {
        Some(hole) if inspectable => view! {
            <PeekSlot group=PeekGroup::Hole cards=hole.clone() class="flex gap-1.5">
                {hole.into_iter().map(card_face).collect_view()}
            </PeekSlot>
        }
        .into_any(),
        Some(hole) => hole.into_iter().map(card_face).collect_view().into_any(),
        None if s.folded => {
            view! { <span class="text-xs text-gray-500 italic">"folded"</span> }.into_any()
        }
        None => view! { {card_back()} {card_back()} }.into_any(),
    };
    let bb = v.bb;
    let unit = unit.to_string();
    view! {
        <div class=format!("rounded-xl bg-gray-900/60 p-3 sm:p-4 flex items-center justify-between gap-3 {ring}")>
            <div class="min-w-0 space-y-1">
                <div class="flex items-center gap-2 flex-wrap">
                    <span class="font-semibold text-white truncate">{label}</span>
                    <span class="text-[10px] font-bold px-1.5 py-0.5 rounded bg-gray-700 text-gray-200">{position}</span>
                    {dealer.then(|| view! {
                        <span class="text-[10px] font-bold w-5 h-5 inline-flex items-center justify-center rounded-full bg-white text-gray-900" title="Dealer button">"D"</span>
                    })}
                    {s.all_in.then(|| view! { <span class="text-[10px] font-bold text-amber-400">"ALL IN"</span> })}
                </div>
                {blurb.map(|b| view! { <p class="text-xs text-gray-500 italic">{b}</p> })}
                <p class="text-sm text-gray-300">
                    <span class="font-mono">{s.stack}</span>" "{unit}" "
                    <span class="text-gray-500">"· "{poker::bb_count(s.stack, bb)}</span>
                </p>
                {(s.street_commit > 0).then(|| view! {
                    <p class="text-xs text-amber-300">"bet "<span class="font-mono">{s.street_commit}</span></p>
                })}
            </div>
            <div class="flex gap-1.5 shrink-0">{cards}</div>
        </div>
    }
    .into_any()
}

/// The board: five places, dealt or empty; inspectable once one is dealt.
fn board_of(cards: &[u8]) -> AnyView {
    let places = (0..5)
        .map(|i| {
            cards
                .get(i)
                .copied()
                .map(card_face)
                .unwrap_or_else(card_slot)
        })
        .collect_view();
    view! {
        <PeekSlot group=PeekGroup::Board cards=cards.to_vec() class="flex gap-1.5 sm:gap-2">
            {places}
        </PeekSlot>
    }
    .into_any()
}

/// The three-button action bar for a legal envelope.
fn action_bar(
    l: Option<Legal>,
    waiting: bool,
    busy: bool,
    on_act: impl Fn(Choice) + Copy + 'static,
) -> AnyView {
    let Some(l) = l else {
        return view! {
            <p class="text-sm text-gray-500 text-center py-2">
                {if waiting { "Waiting for the other seat…" } else { "" }}
            </p>
        }
        .into_any();
    };
    // Each choice keeps its own column, so a button never moves under the
    // reader's thumb between streets: a wrapping row used to push "RAISE TO n"
    // onto a second, full-width line on a phone whenever its label outgrew
    // the first, and back again when it did not.
    let button = move |choice: Choice, key: &'static str, style: &'static str| {
        poker::choice_label(&l, choice).map(|label| {
            view! {
                <button
                    class=format!("min-h-[44px] px-2 sm:px-4 py-3 rounded-lg font-semibold text-sm leading-tight touch-manipulation transition-colors disabled:opacity-50 disabled:cursor-wait {style}")
                    prop:disabled=busy
                    on:click=move |_| on_act(choice)
                >
                    {label}
                    <span class="kbd-hint ml-2 text-[10px] opacity-60 font-mono">{key}</span>
                </button>
            }
        })
    };
    view! {
        <div class="grid grid-cols-3 gap-2">
            {button(Choice::Fold, "1", "col-start-1 bg-gray-700 hover:bg-gray-600 text-gray-100")}
            {button(Choice::Passive, "2", "col-start-2 bg-gray-600 hover:bg-gray-500 text-white")}
            {button(Choice::Aggressive, "3", "col-start-3 bg-amber-500 hover:bg-amber-400 text-gray-900")}
        </div>
    }
    .into_any()
}

fn narration(log: &[poker::LogEntry], names: &[String], hero: u32) -> AnyView {
    let lines: Vec<String> = log
        .iter()
        .filter_map(|e| poker::describe(e, names, hero))
        .collect();
    let skip = lines.len().saturating_sub(8);
    lines
        .into_iter()
        .skip(skip)
        .map(|l| view! { <li>{l}</li> })
        .collect_view()
        .into_any()
}

fn history_card(history: RwSignal<Vec<HistoryRow>>, unit: &'static str) -> AnyView {
    view! {
        <div class="glass-card p-4 space-y-2">
            <h2 class="text-sm font-semibold text-white">"Hand history"</h2>
            <Show
                when=move || history.with(|h| !h.is_empty())
                fallback=|| view! { <p class="text-xs text-gray-500">"No hands yet."</p> }
            >
                <ul class="space-y-2">
                    <For
                        each=move || history.get()
                        key=|row| row.number
                        let:row
                    >
                        <li class="text-xs flex gap-2">
                            <span class="font-mono text-gray-500 shrink-0">{format!("#{}", row.number)}</span>
                            <span class="text-gray-300 flex-1">{row.text.clone()}</span>
                            <span class=format!("font-mono shrink-0 {}", net_tone(row.net))>
                                {poker::signed(row.net)}" "{unit}
                            </span>
                        </li>
                    </For>
                </ul>
            </Show>
        </div>
    }
    .into_any()
}

fn session_card(hands: RwSignal<u32>, net: RwSignal<i64>, unit: &'static str) -> AnyView {
    view! {
        <div class="glass-card p-4 space-y-2">
            <h2 class="text-sm font-semibold text-white">"Session"</h2>
            <p class="text-sm text-gray-300">{move || format!("Hands played: {}", hands.get())}</p>
            <p class="text-sm text-gray-300">
                "Net: "
                <span class=move || format!("font-mono {}", net_tone(net.get()))>
                    {move || poker::signed(net.get())}
                </span>
                " "{unit}
            </p>
        </div>
    }
    .into_any()
}

// ── The table surface: 3D or flat ─────────────────────────────────────────────

/// Whether the device's main pointer is a finger, so the 3D table offers
/// "free look" (touch dragging the camera instead of scrolling the page).
fn coarse_pointer() -> bool {
    web_sys::window()
        .and_then(|w| w.match_media("(pointer: coarse)").ok().flatten())
        .is_some_and(|mq| mq.matches())
}

/// The newest thing that happened at the table, in words: the outcome once
/// the hand is over, else the latest log entry the narration tells.
fn latest_line(log: &[poker::LogEntry], names: &[String], hero: u32) -> String {
    log.iter()
        .rev()
        .find_map(|e| poker::describe(e, names, hero))
        .unwrap_or_default()
}

/// What a tap on the 3D table shows, read from the seat view.
fn pick_text(p: Pick, v: &SeatView, names: &[String], unit: &str) -> String {
    let hero = v.seat as usize;
    let other = if hero == 0 { 1 } else { 0 };
    match p.target {
        PickTarget::Pot => {
            if v.phase == "done" {
                return format!("This hand's pot was {} {unit}.", v.pot);
            }
            let bets: u64 = v.seats.iter().map(|s| s.street_commit).sum();
            format!(
                "Pot {} {unit}: {} in the middle, {bets} bet this street.",
                v.pot,
                v.pot.saturating_sub(bets)
            )
        }
        PickTarget::Stack => v
            .seats
            .get(hero)
            .map(|s| {
                format!(
                    "Your stack: {} {unit} ({}).",
                    s.stack,
                    poker::bb_count(s.stack, v.bb)
                )
            })
            .unwrap_or_default(),
        PickTarget::HeroCards => {
            let Some(hole) = v.hole.clone() else {
                return String::new();
            };
            let shown: Vec<String> = hole.iter().map(|&c| poker::card_name(c)).collect();
            let mut all = hole;
            all.extend_from_slice(&v.board);
            if v.board.len() >= 3 {
                format!(
                    "Your cards: {} — {}.",
                    shown.join(" "),
                    poker::hand_name(&all)
                )
            } else {
                format!("Your cards: {}.", shown.join(" "))
            }
        }
        PickTarget::Seat => {
            let seat = p.seat.map(|s| s as usize).unwrap_or(other);
            let Some(s) = v.seats.get(seat) else {
                return String::new();
            };
            let name = names.get(seat).cloned().unwrap_or_default();
            let state = if s.folded {
                " — folded"
            } else if s.all_in {
                " — all in"
            } else {
                ""
            };
            format!(
                "{name}: {} {unit} ({}){state}.",
                s.stack,
                poker::bb_count(s.stack, v.bb)
            )
        }
    }
}

/// The table itself. With the member's 3D toggle on and a GPU backend to
/// draw with, the scene shows over the flat table, which then stays in the
/// page only for screen readers; while the scene is loading, or if it fails,
/// the flat table shows as before. `children` is the flat table.
#[component]
fn TableSurface(
    /// The frame for the scene (`table3d::frame_json`).
    #[prop(into)]
    frame: Signal<Option<String>>,
    /// The hero's label.
    #[prop(into)]
    near_name: Signal<String>,
    /// The other seat's label.
    #[prop(into)]
    far_name: Signal<String>,
    /// The chip unit: `chips`, or the table's ticker (`DREAM`, `BLAKES7`).
    unit: &'static str,
    /// Set while the scene is still showing what happened.
    busy: RwSignal<bool>,
    /// The newest event in words, announced politely while the scene draws.
    #[prop(into)]
    narration: Signal<String>,
    /// What a tap on the scene shows.
    inspect: RwSignal<Option<String>>,
    /// Turns a tap into the `inspect` text.
    on_pick: Callback<Pick>,
    children: ChildrenFn,
) -> impl IntoView {
    let prefs = use_preferences();
    let tier = use_render_tier();
    let backend = Memo::new(move |_| table3d::available_backend(tier.get()));
    let status = RwSignal::new(Table3dStatus::Loading);
    let on = Memo::new(move |_| prefs.with(|p| p.poker_table_3d) && backend.get().is_some());
    let show = Memo::new(move |_| on.get() && !status.with(Table3dStatus::is_failed));
    let ready = Memo::new(move |_| on.get() && status.with(Table3dStatus::is_ready));
    let four_colour = Signal::derive(move || prefs.with(|p| p.poker_four_colour));
    let free_look = RwSignal::new(false);
    let touch = coarse_pointer();
    // the flat table's own card inspection, live only while it is the table
    // shown (the 3D table has its own); a new frame drops it
    let peek_live = provide_flat_peek(Signal::derive(move || !ready.get()), frame);

    // Switching the scene off releases the buttons and lets a later switch-on
    // try again after a failure.
    Effect::new(move |_| {
        if !on.get() {
            busy.set(false);
            status.set(Table3dStatus::Loading);
            inspect.set(None);
        }
    });
    // Whenever the scene is not shown (switched off, or failed), nothing is
    // animating, so the buttons are free. This lives here rather than in the
    // scene's cleanup: this effect goes with the page, so leaving the table
    // never writes into a page that is being taken down.
    Effect::new(move |_| {
        if !show.get() {
            busy.set(false);
        }
    });

    view! {
        <Show when=move || show.get()>
            {move || backend.get_untracked().map(|b| view! {
                <Table3d
                    frame=frame
                    backend=b
                    busy=busy
                    status=status
                    near_name=near_name
                    far_name=far_name
                    unit=unit
                    four_colour=four_colour
                    free_look=free_look
                    on_pick=on_pick
                />
            })}
            <div class="flex items-center justify-between gap-3 text-xs text-gray-500 min-h-[1.25rem]">
                <p class="text-gray-300" aria-live="polite">{move || inspect.get().unwrap_or_default()}</p>
                <div class="flex items-center gap-3 shrink-0">
                    {touch.then(|| view! {
                        <label class="flex items-center gap-1.5 cursor-pointer">
                            <input
                                type="checkbox"
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                prop:checked=move || free_look.get()
                                on:change=move |_| free_look.update(|v| *v = !*v)
                            />
                            "Free look"
                        </label>
                    })}
                    <span>{move || match status.get() {
                        Table3dStatus::Ready(b) => b.label().to_string(),
                        _ => String::new(),
                    }}</span>
                </div>
            </div>
            <p class="sr-only" aria-live="polite">{move || narration.get()}</p>
        </Show>
        {move || match status.get() {
            Table3dStatus::Failed(why) if on.get() => Some(view! {
                <p class="text-xs text-amber-300">
                    "The 3D table could not start (" {why} "), so the flat table is shown."
                </p>
            }),
            _ => None,
        }}
        <div class=move || if ready.get() { "sr-only" } else { "space-y-4" }>
            {children()}
            <p class="sr-only" aria-live="polite">{move || peek_live.get()}</p>
        </div>
    }
}

// ── The practice table ────────────────────────────────────────────────────────

/// The practice table, mounted only behind every gate.
#[component]
fn PracticeTable() -> impl IntoView {
    let config = poker::PokerConfig::load();
    let coach = config.coach();
    let prefs = use_preferences();
    let stakes = StoredValue::new(config.stakes());
    let bot: StoredValue<RosterEntry> =
        StoredValue::new(poker::pick_bot(&poker::roster(), &config.bot_profile));

    let stake_idx = RwSignal::new(0usize);
    let hand: RwSignal<Option<HandState>> = RwSignal::new(None);
    let next_seed: RwSignal<Option<String>> = RwSignal::new(poker::fresh_seed());
    let dealt_commit: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let outcome: RwSignal<Option<HandOutcome>> = RwSignal::new(None);
    let hands_played = RwSignal::new(0u32);
    let session_net = RwSignal::new(0i64);
    let history: RwSignal<Vec<HistoryRow>> = RwSignal::new(Vec::new());
    let next_button = StoredValue::new(HERO);
    // Bumped on every state change; a pending bot turn from an older state
    // sees the mismatch and stands down.
    let turn = StoredValue::new(0u64);

    let seat_view =
        Memo::new(move |_| hand.with(|h| h.as_ref().and_then(|h| poker::seat_view(h, HERO).ok())));
    let legal: Memo<Option<Legal>> =
        Memo::new(move |_| hand.with(|h| h.as_ref().and_then(|h| poker::legal(h).ok().flatten())));
    let in_play = Memo::new(move |_| hand.with(|h| h.as_ref().is_some_and(|h| h.hand.in_play())));
    let hero_turn = Memo::new(move |_| legal.get().is_some_and(|l| l.seat == HERO));
    // The 3D table is still showing what just happened: the buttons wait.
    let table_busy = RwSignal::new(false);
    let inspect: RwSignal<Option<String>> = RwSignal::new(None);
    let frame3d = Memo::new(move |_| {
        let v = seat_view.get()?;
        hand.with(|h| {
            h.as_ref()
                .map(|h| table3d::frame_json(&h.hand.seed_hex, &v, &h.hand.log))
        })
    });

    // Take a new engine state: count a finished hand, prepare the next commit.
    let settle = move |next: HandState| {
        turn.update_value(|t| *t += 1);
        if !next.hand.in_play() {
            if let Some(o) = poker::summarise(&next.hand, HERO as usize, poker::hand_name) {
                let n = hands_played.get_untracked() + 1;
                hands_played.set(n);
                session_net.update(|v| *v += o.hero_net);
                history.update(|rows| {
                    rows.insert(
                        0,
                        HistoryRow {
                            number: n,
                            text: o.text.clone(),
                            net: o.hero_net,
                        },
                    );
                    rows.truncate(HISTORY_LEN);
                });
                outcome.set(Some(o));
            }
            next_seed.set(poker::fresh_seed());
        }
        hand.set(Some(next));
    };

    let deal = move || {
        if in_play.get_untracked() || table_busy.get_untracked() {
            return;
        }
        let Some(seed) = next_seed.get_untracked() else {
            error.set(Some(
                "This browser offers no secure random source, so no shuffle can be committed."
                    .into(),
            ));
            return;
        };
        let stake: Stake = stakes.with_value(|s| s[stake_idx.get_untracked().min(s.len() - 1)]);
        let button = next_button.get_value();
        let cfg = HandConfig {
            seats: vec![
                SeatConfig {
                    name: "You".into(),
                    stack: stake.buyin,
                },
                SeatConfig {
                    name: bot.with_value(|b| b.name.clone()),
                    stack: stake.buyin,
                },
            ],
            button,
            sb: stake.sb,
            bb: stake.bb,
            ante: 0,
            seed_hex: seed.clone(),
            limit: true,
        };
        match poker::new_hand(&cfg) {
            Ok(h) => {
                next_button.set_value(if button == HERO { BOT } else { HERO });
                next_seed.set(None);
                dealt_commit.set(Some(poker::seed_commit(&seed)));
                outcome.set(None);
                error.set(None);
                settle(h);
            }
            Err(e) => error.set(Some(e)),
        }
    };

    let hero_act = move |choice: Choice| {
        if !hero_turn.get_untracked() || table_busy.get_untracked() {
            return;
        }
        let Some(l) = legal.get_untracked() else {
            return;
        };
        let Some(action) = poker::action_for(&l, choice) else {
            return;
        };
        let Some(h) = hand.get_untracked() else {
            return;
        };
        match poker::act(&h, &action) {
            Ok(next) => settle(next),
            Err(e) => error.set(Some(e)),
        }
    };

    // The bot's turn: keyed on the hand itself (not the legal envelope, which
    // can repeat across streets), played after a short pause.
    Effect::new(move |_| {
        let bot_to_act = hand.with(|h| {
            h.as_ref()
                .is_some_and(|h| h.hand.in_play() && h.hand.to_act == BOT as i32)
        });
        if !bot_to_act {
            return;
        }
        let token = turn.get_value();
        set_timeout_once(
            move || {
                // The page may have gone, or the state moved on, meanwhile.
                if turn.try_get_value() != Some(token) {
                    return;
                }
                let Some(Some(h)) = hand.try_get_untracked() else {
                    return;
                };
                let seed = poker::bot_seed(&h.hand.seed_hex, h.hand.log.len());
                let profile = bot.with_value(|b| b.profile.clone());
                let action = match poker::bot_decide(&h, BOT, &profile, &seed) {
                    Ok(a) => a,
                    Err(e) => {
                        error.set(Some(format!("The bot could not decide: {e}")));
                        let fallback = legal
                            .get_untracked()
                            .and_then(|l| poker::action_for(&l, Choice::Passive));
                        let Some(a) = fallback else {
                            return;
                        };
                        a
                    }
                };
                match poker::act(&h, &action) {
                    Ok(next) => settle(next),
                    Err(e) => error.set(Some(e)),
                }
            },
            BOT_DELAY_MS,
        );
    });

    // Keyboard: 1/f fold, 2/c check or call, 3/r bet or raise; Enter or 1
    // deals the next hand once this one is over.
    let keys = window_event_listener(ev::keydown, move |e: web_sys::KeyboardEvent| {
        if e.ctrl_key() || e.meta_key() || e.alt_key() || e.repeat() || typing_into_field(&e) {
            return;
        }
        let key = e.key();
        if !in_play.get_untracked() {
            if key == "Enter" || key == "1" {
                e.prevent_default();
                deal();
            }
            return;
        }
        let choice = match key.as_str() {
            "1" | "f" | "F" => Choice::Fold,
            "2" | "c" | "C" => Choice::Passive,
            "3" | "r" | "R" => Choice::Aggressive,
            _ => return,
        };
        e.prevent_default();
        hero_act(choice);
    });
    on_cleanup(move || keys.remove());

    // ── view pieces ──────────────────────────────────────────────────────
    let bot_label = bot.with_value(|b| format!("{} {}", b.emoji, b.name));
    let bot_blurb = bot.with_value(|b| format!("{} · plays {}", b.blurb, b.profile));

    let stake_select = move || {
        stakes.with_value(|list| {
            list.iter()
                .enumerate()
                .map(|(i, s)| {
                    let label = format!("{}/{} — buy-in {}", s.sb, s.bb, poker::chips(s.buyin));
                    view! { <option value=i.to_string() selected=move || stake_idx.get() == i>{label}</option> }
                })
                .collect_view()
        })
    };

    let board = move || {
        let cards = seat_view.with(|v| v.as_ref().map(|v| v.board.clone()).unwrap_or_default());
        board_of(&cards)
    };

    let bar = move || {
        let l = legal.get().filter(|l| l.seat == HERO);
        action_bar(l, in_play.get(), table_busy.get(), hero_act)
    };

    // the seats' display names, for the narration and the tap read-outs
    let names = move || -> Vec<String> {
        vec![
            "You".to_string(),
            bot.with_value(|b| format!("{} {}", b.emoji, b.name)),
        ]
    };
    let told = Signal::derive(move || {
        if let Some(o) = outcome.get() {
            return o.text;
        }
        hand.with(|h| {
            h.as_ref()
                .map(|h| latest_line(&h.hand.log, &names(), HERO))
                .unwrap_or_default()
        })
    });
    let on_pick = Callback::new(move |p: Pick| {
        inspect.set(
            seat_view
                .get_untracked()
                .map(|v| pick_text(p, &v, &names(), "chips")),
        );
    });

    let story = move || {
        let names = hand.with(|h| {
            h.as_ref()
                .map(|h| {
                    h.hand
                        .seats
                        .iter()
                        .map(|s| s.name.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        });
        hand.with(|h| {
            h.as_ref()
                .map(|h| narration(&h.hand.log, &names, HERO))
                .unwrap_or_else(|| ().into_any())
        })
    };

    let fairness = move || {
        let finished = hand.with(|h| {
            h.as_ref()
                .filter(|h| !h.hand.in_play())
                .map(|h| h.hand.seed_hex.clone())
        });
        let revealed = finished.map(|seed| {
            let check = poker::seed_commit(&seed);
            let matches = dealt_commit.get().as_deref() == Some(check.as_str());
            view! {
                <div class="space-y-1">
                    <p class="text-gray-400">"Seed revealed:"</p>
                    <p class="font-mono text-gray-300 break-all">{seed.clone()}</p>
                    <p class={if matches { "text-green-400" } else { "text-red-400" }}>
                        {if matches {
                            "verify: sha256(seed) matches the commit shown before the deal ✓"
                        } else {
                            "verify: sha256(seed) does NOT match the commit shown before the deal"
                        }}
                    </p>
                    <p class="font-mono text-gray-500 break-all">{format!("printf %s {seed} | sha256sum")}</p>
                </div>
            }
        });
        let commit = if in_play.get() {
            dealt_commit
                .get()
                .map(|c| ("Shuffle committed (sha256 of the seed):", c))
        } else {
            next_seed.get().map(|s| {
                (
                    "Next shuffle commit (sha256 of the seed):",
                    poker::seed_commit(&s),
                )
            })
        };
        view! {
            {revealed}
            {commit.map(|(label, c)| view! {
                <div class="space-y-1">
                    <p class="text-gray-400">{label}</p>
                    <p class="font-mono text-amber-300/90 break-all">{c}</p>
                </div>
            })}
        }
    };

    view! {
        <div class="max-w-5xl mx-auto px-4 py-6 space-y-4">
            <div class="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 class="text-2xl font-bold text-white">"Practice table"</h1>
                    <p class="text-sm text-gray-400">
                        "Heads-up limit hold'em against the house bot. Practice chips only — no funds move."
                    </p>
                </div>
                <label class="text-sm text-gray-300 flex items-center gap-2">
                    "Stakes"
                    <select
                        class="bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-1 focus:ring-amber-500 disabled:opacity-50"
                        prop:disabled=move || in_play.get()
                        on:change=move |ev| {
                            if let Ok(i) = event_target_value(&ev).parse::<usize>() {
                                stake_idx.set(i);
                            }
                        }
                        aria-label="Stakes"
                    >
                        {stake_select}
                    </select>
                </label>
            </div>

            <div class="grid gap-4 lg:grid-cols-3">
                <div class="lg:col-span-2 space-y-4">
                    <div class="glass-card p-4 sm:p-6 space-y-4">
                        <TableSurface
                            frame=frame3d
                            near_name=Signal::derive(|| "You".to_string())
                            far_name=Signal::derive(move || bot.with_value(|b| b.name.clone()))
                            unit="chips"
                            busy=table_busy
                            narration=told
                            inspect=inspect
                            on_pick=on_pick
                        >
                            {
                                let bot_label = bot_label.clone();
                                let bot_blurb = bot_blurb.clone();
                                move || match seat_view.get() {
                                    Some(v) => seat_panel(&v, BOT, bot_label.clone().into_any(), Some(bot_blurb.clone()), "chips", false),
                                    None => view! {
                                        <div class="rounded-xl bg-gray-900/60 p-4 ring-1 ring-gray-700/50">
                                            <p class="font-semibold text-white">{bot_label.clone()}</p>
                                            <p class="text-xs text-gray-500 italic">{bot_blurb.clone()}</p>
                                        </div>
                                    }.into_any(),
                                }
                            }

                            <div class="flex flex-col items-center gap-2 py-2">
                                <div class="flex gap-1.5 sm:gap-2">{board}</div>
                                <p class="text-sm text-gray-300">
                                    {move || seat_view.get().map(|v| view! {
                                        "Pot "<span class="font-mono text-amber-300">{v.pot}</span>
                                        <span class="text-gray-500">" · "{v.street.clone()}</span>
                                    })}
                                </p>
                            </div>

                            {move || seat_view.get().map(|v| seat_panel(&v, HERO, "You".into_any(), None, "chips", true))}
                        </TableSurface>

                        {move || outcome.get().map(|o| {
                            let tone = net_tone(o.hero_net);
                            view! {
                                <div class="rounded-lg bg-gray-800/70 p-3 text-sm">
                                    <p class="text-gray-100">{o.text.clone()}</p>
                                    <p class=format!("font-mono {tone}")>{poker::signed(o.hero_net)}" chips this hand"</p>
                                </div>
                            }
                        })}

                        {bar}

                        <Show when=move || !in_play.get()>
                            <button
                                class="w-full min-h-[44px] px-4 py-3 rounded-lg font-semibold text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 touch-manipulation transition-colors disabled:opacity-50 disabled:cursor-wait"
                                prop:disabled=move || table_busy.get()
                                on:click=move |_| deal()
                            >
                                {move || if hand.with(Option::is_some) { "Next hand" } else { "Deal" }}
                                <span class="kbd-hint ml-2 text-[10px] opacity-60 font-mono">"Enter"</span>
                            </button>
                        </Show>

                        {move || error.get().map(|e| view! {
                            <p class="text-sm text-red-400" role="alert">{e}</p>
                        })}

                        <p class="kbd-hint text-xs text-gray-500">
                            "Keys: 1 / F fold · 2 / C check or call · 3 / R bet or raise · Enter next hand"
                        </p>
                    </div>

                    {coach.map(|coach| view! {
                        <Show when=move || prefs.with(|p| p.poker_coach)>
                            <PokerCoach
                                coach=coach.clone()
                                hand=hand
                                seat_view=seat_view
                                legal=legal
                            />
                        </Show>
                    })}

                    <div class="glass-card p-4 text-xs space-y-3">
                        <h2 class="text-sm font-semibold text-white">"Fair shuffle"</h2>
                        {fairness}
                    </div>
                </div>

                <div class="space-y-4">
                    {session_card(hands_played, session_net, "chips")}
                    <div class="glass-card p-4 space-y-2">
                        <h2 class="text-sm font-semibold text-white">"This hand"</h2>
                        <ul class="text-xs text-gray-400 space-y-0.5">{story}</ul>
                    </div>
                    {history_card(history, "chips")}
                </div>
            </div>
        </div>
    }
}

// ── The asset tables ──────────────────────────────────────────────────────────

/// A member's name, reactively — or, while they have none, their abridged
/// key as a click-to-copy button.
#[component]
fn Name(#[prop(into)] pubkey: String) -> impl IntoView {
    view! { <span><KeyName pubkey=pubkey key_class="font-mono" /></span> }
}

/// An asset table: hands against one chain's house seat or another member,
/// settled on that chain from the member's wallet on it.
#[component]
fn ChainTable(table: AssetTable) -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let relay_authed = relay.authenticated();
    let profile = table.profile;
    let unit: &'static str = &profile.ticker;
    let citizen = table.citizen.clone();
    // this chain's wallet, whichever chain the wallet page is showing
    let wallet = use_wallets().and_then(|w| w.get(profile.id));
    let me = auth.pubkey().get_untracked().unwrap_or_default();
    let Some(signer) = auth.get_signer() else {
        return view! {
            <div class="max-w-2xl mx-auto px-4 py-16 text-center text-gray-400">
                <p>{format!("Sign in with a key that can sign to play for {unit}.")}</p>
            </div>
        }
        .into_any();
    };
    let live = LiveStore::new(relay.clone(), signer, auth, wallet, &me, &citizen);
    let citizen_pk = StoredValue::new(citizen.clone());

    // Join once the relay session is NIP-42 authenticated: the inbox REQ is
    // gated on it.
    let started = RwSignal::new(false);
    Effect::new(move |_| {
        if conn_state.get() != ConnectionState::Connected || !relay_authed.get() {
            return;
        }
        if started.get_untracked() {
            return;
        }
        started.set(true);
        live.start();
    });
    on_cleanup(move || live.stop());
    if let Some(w) = wallet {
        w.ensure_loaded();
    }

    // Our balance of the asset, and the chain's word on the last hand's
    // payment to us.
    let my_script = chain::script_of(&me);
    let my_script_hex = my_script
        .as_ref()
        .map(|s| s.to_hex_string())
        .unwrap_or_default();
    let balance = Memo::new(move |_| {
        let (Some(w), Some(script)) = (wallet, my_script.as_ref()) else {
            return None;
        };
        // read the snapshot for its tracking; the counts read it untracked
        w.snapshot()?;
        w.asset_now_and_incoming(script)
    });
    Effect::new(move |_| {
        let Some(w) = wallet else { return };
        let Some(snap) = w.snapshot() else { return };
        let Some(f) = live.finished.get() else { return };
        if !matches!(f.pay, Pay::Awaiting { .. }) {
            return;
        }
        let paid = snap.txs.iter().rev().find(|t| {
            t.hand_root.as_deref() == Some(f.root.as_str())
                && t.outs
                    .iter()
                    .any(|o| o.script == my_script_hex && o.asset > 0)
        });
        if let Some(t) = paid {
            live.received(&f.root, &t.txid);
        }
    });

    let in_play = Memo::new(move |_| live.hand.get().is_some_and(|h| h.view.phase == "act"));
    let my_turn = Memo::new(move |_| {
        live.hand
            .get()
            .is_some_and(|h| h.view.phase == "act" && h.view.to_act == h.seat as i32)
    });
    // The 3D table is still showing what just happened: the buttons wait.
    let table_busy = RwSignal::new(false);
    let inspect: RwSignal<Option<String>> = RwSignal::new(None);
    let hero_act = move |choice: Choice| {
        if my_turn.get_untracked() && !live.busy.get_untracked() && !table_busy.get_untracked() {
            live.act(choice);
        }
    };
    let keys = window_event_listener(ev::keydown, move |e: web_sys::KeyboardEvent| {
        if e.ctrl_key() || e.meta_key() || e.alt_key() || e.repeat() || typing_into_field(&e) {
            return;
        }
        let key = e.key();
        if !in_play.get_untracked() {
            if (key == "Enter" || key == "1")
                && live.offer.get_untracked().is_some()
                && !live.busy.get_untracked()
                && !table_busy.get_untracked()
                && live.waiting.get_untracked().is_none()
            {
                e.prevent_default();
                live.sit();
            }
            return;
        }
        let choice = match key.as_str() {
            "1" | "f" | "F" => Choice::Fold,
            "2" | "c" | "C" => Choice::Passive,
            "3" | "r" | "R" => Choice::Aggressive,
            _ => return,
        };
        e.prevent_default();
        hero_act(choice);
    });
    on_cleanup(move || keys.remove());

    let stake_select = move || {
        let tables = live.offer.get().map(|o| o.tables).unwrap_or_default();
        let chosen = live.stake_bb.get();
        tables
            .into_iter()
            .map(|t| {
                let label = format!("{} — buy-in {} {unit}", t.label, t.buyin);
                view! { <option value=t.bb.to_string() selected=move || chosen == t.bb>{label}</option> }
            })
            .collect_view()
    };
    let chosen_buyin = Memo::new(move |_| {
        let bb = live.stake_bb.get();
        live.offer
            .get()
            .and_then(|o| o.tables.into_iter().find(|t| t.bb == bb).map(|t| t.buyin))
            .unwrap_or(0)
    });
    let can_sit = Memo::new(move |_| {
        !in_play.get()
            && !live.busy.get()
            && !table_busy.get()
            && live.offer.get().is_some()
            && live.waiting.get().is_none()
            && balance.get().is_some_and(|(d, _)| d >= chosen_buyin.get())
    });

    let opponent_label = move |h: &crate::poker::live::LiveHand| -> (String, Option<String>) {
        if h.house {
            let o = live.offer.get_untracked();
            (
                o.as_ref()
                    .map(|o| o.name.clone())
                    .unwrap_or_else(|| "House".into()),
                o.map(|o| format!("the house · plays {}", o.profile)),
            )
        } else {
            (
                h.opponent.clone(),
                Some("a member · the house deals".into()),
            )
        }
    };

    let board = move || {
        let cards = live
            .hand
            .get()
            .map(|h| h.view.board.clone())
            .or_else(|| live.finished.get().map(|f| f.view.board.clone()))
            .unwrap_or_default();
        board_of(&cards)
    };

    let bar = move || {
        let l = live.hand.get().and_then(|h| legal_of_view_live(&h));
        action_bar(
            l,
            in_play.get() && !my_turn.get(),
            table_busy.get(),
            hero_act,
        )
    };

    // The 3D table's frame: the hand in play, else the one just finished,
    // keyed by its commitment so each hand starts from a fresh deal.
    let frame3d = Memo::new(move |_| match (live.hand.get(), live.finished.get()) {
        (Some(h), _) => Some(table3d::frame_json(&h.commit, &h.view, &h.log)),
        (None, Some(f)) => Some(table3d::frame_json(&f.commit, &f.view, &f.log)),
        _ => None,
    });
    // a pubkey shown as the member's display name; a house name as it is
    let display = |label: String| {
        if label.len() == 64 {
            crate::components::user_display::use_display_name(&label)
        } else {
            label
        }
    };
    let house_name = move || {
        live.offer
            .get()
            .map(|o| o.name)
            .unwrap_or_else(|| "House".into())
    };
    let far_name = Signal::derive(move || match (live.hand.get(), live.finished.get()) {
        (Some(h), _) => display(opponent_label(&h).0),
        (None, Some(f)) if f.house => house_name(),
        (None, Some(f)) => display(f.opponent),
        _ => house_name(),
    });
    let told = Signal::derive(move || match (live.hand.get(), live.finished.get()) {
        (Some(h), _) => latest_line(
            &h.log,
            &seat_names(h.seat, &h.opponent, h.house, live),
            h.seat,
        ),
        (None, Some(f)) => f.text,
        _ => String::new(),
    });
    let on_pick = Callback::new(move |p: Pick| {
        let text = match (live.hand.get_untracked(), live.finished.get_untracked()) {
            (Some(h), _) => {
                let names = seat_names(h.seat, &h.opponent, h.house, live);
                Some(pick_text(p, &h.view, &names, unit))
            }
            (None, Some(f)) => {
                let names = seat_names(f.seat, &f.opponent, f.house, live);
                Some(pick_text(p, &f.view, &names, unit))
            }
            _ => None,
        };
        inspect.set(text);
    });

    let story = move || {
        let (log, seat, names) = match (live.hand.get(), live.finished.get()) {
            (Some(h), _) => {
                let names = seat_names(h.seat, &h.opponent, h.house, live);
                (h.log, h.seat, names)
            }
            (None, Some(f)) => {
                let names = seat_names(f.seat, &f.opponent, f.house, live);
                (f.log, f.seat, names)
            }
            _ => return ().into_any(),
        };
        narration(&log, &names, seat)
    };

    let settlement = move || {
        let Some(f) = live.finished.get() else {
            return ().into_any();
        };
        let tone = net_tone(f.net);
        let verified = match &f.verified {
            Ok(()) => view! { <p class="text-xs text-green-400">"Replay verified: committed shuffle, your nonce, the record, and the house's play ✓"</p> }.into_any(),
            Err(e) => view! { <p class="text-xs text-red-400">"Replay did not verify: "{e.clone()}</p> }.into_any(),
        };
        let pay = match &f.pay {
            Pay::Split => view! { <p class="text-xs text-gray-400">"Split pot: nothing moves."</p> }.into_any(),
            Pay::Sent(txid) => view! { <p class="text-xs text-gray-300">"You paid "<span class="font-mono">{f.net.unsigned_abs()}</span>" "{unit}" — transfer "<span class="font-mono break-all">{txid.clone()}</span></p> }.into_any(),
            Pay::Received(txid) => view! { <p class="text-xs text-green-300">"Paid to you — transfer "<span class="font-mono break-all">{txid.clone()}</span></p> }.into_any(),
            Pay::Awaiting { amount } => view! { <p class="text-xs text-amber-300">"You are owed "{*amount}" "{unit}"; waiting for the chain to show it."</p> }.into_any(),
            Pay::Queued { amount, .. } => view! { <p class="text-xs text-amber-300">"You owe "{*amount}" "{unit}". Your last payment is still confirming; this one goes out by itself when it lands (about a minute)."</p> }.into_any(),
            Pay::Owed { amount, error, .. } => {
                let amount = *amount;
                view! {
                    <div class="flex items-center gap-3 flex-wrap">
                        <p class="text-xs text-amber-300">"You owe "{amount}" "{unit}" for this hand."</p>
                        <button
                            class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-gray-900"
                            on:click=move |_| live.pay_now()
                        >
                            "Pay now"
                        </button>
                        {error.clone().map(|e| view! { <p class="text-xs text-red-400">{e}</p> })}
                    </div>
                }.into_any()
            }
        };
        view! {
            <div class="rounded-lg bg-gray-800/70 p-3 text-sm space-y-1">
                <p class="text-gray-100">{f.text.clone()}</p>
                <p class=format!("font-mono {tone}")>{poker::signed(f.net)}" "{unit}" this hand"</p>
                {verified}
                {pay}
                <p class="font-mono text-[10px] text-gray-500 break-all">"hand:"{f.root.clone()}</p>
            </div>
        }
        .into_any()
    };

    let present_list = move || {
        let Some(o) = live.offer.get() else {
            return ().into_any();
        };
        if o.present.is_empty() {
            return view! { <p class="text-xs text-gray-500">"No other members at the table right now. Invite someone: schedule a game, or send them the link."</p> }.into_any();
        }
        o.present
            .into_iter()
            .map(|pk| {
                let pk2 = pk.clone();
                view! {
                    <li class="flex items-center justify-between gap-2 text-sm">
                        <span class="text-gray-200 truncate"><Name pubkey=pk.clone() /></span>
                        <button
                            class="px-2 py-1 rounded text-xs font-semibold bg-gray-700 hover:bg-gray-600 text-amber-300 disabled:opacity-50"
                            prop:disabled=move || !can_sit.get()
                            on:click=move |_| live.challenge(&pk2)
                        >
                            "Challenge"
                        </button>
                    </li>
                }
            })
            .collect_view()
            .into_any()
    };

    let challenges = move || {
        live.challenges
            .get()
            .into_iter()
            .map(|c| {
                let accept = c.commit.clone();
                let decline = c.commit.clone();
                view! {
                    <div class="rounded-lg bg-amber-900/30 border border-amber-500/40 p-3 text-sm space-y-2">
                        <p class="text-gray-100"><Name pubkey=c.from.clone() />" challenges you: "{c.bb / 2}"/"{c.bb}", buy-in "{c.buyin}" "{unit}"."</p>
                        <div class="flex gap-2">
                            <button
                                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-gray-900 disabled:opacity-50"
                                prop:disabled=move || balance.get().is_none_or(|(d, _)| d < c.buyin)
                                on:click=move |_| live.accept(&accept)
                            >
                                "Accept"
                            </button>
                            <button
                                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-700 hover:bg-gray-600 text-gray-100"
                                on:click=move |_| live.decline(&decline)
                            >
                                "Decline"
                            </button>
                        </div>
                    </div>
                }
            })
            .collect_view()
    };

    view! {
        <div class="max-w-5xl mx-auto px-4 py-6 space-y-4">
            <div class="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 class="text-2xl font-bold text-white">{table.title()}</h1>
                    <p class="text-sm text-gray-400">
                        {format!("Heads-up limit hold'em for {unit} on {} (testnet, no value). The house deals every hand; the loser pays the winner one transfer.", profile.id)}
                    </p>
                </div>
                <div class="text-right text-sm text-gray-300">
                    <p>{format!("Your {unit}: ")}<span class="font-mono text-amber-300">{move || balance.get().map(|(free, _)| free.to_string()).unwrap_or_else(|| "…".into())}</span>
                        {move || balance.get().filter(|(_, incoming)| *incoming > 0).map(|(_, incoming)| view! {
                            <span class="block text-xs text-gray-400">{format!("+{incoming} confirming")}</span>
                        })}</p>
                    <A href=base_href("/wallet") attr:class="text-xs text-amber-400 hover:text-amber-300 underline">"Wallet"</A>
                </div>
            </div>

            {move || live.error.get().map(|e| view! {
                <p class="text-sm text-red-400" role="alert">{e}</p>
            })}
            {move || live.notice.get().map(|n| view! {
                <p class="text-sm text-gray-300">{n}</p>
            })}
            {challenges}

            <div class="grid gap-4 lg:grid-cols-3">
                <div class="lg:col-span-2 space-y-4">
                    <div class="glass-card p-4 sm:p-6 space-y-4">
                        <TableSurface
                            frame=frame3d
                            near_name=Signal::derive(|| "You".to_string())
                            far_name=far_name
                            unit=unit
                            busy=table_busy
                            narration=told
                            inspect=inspect
                            on_pick=on_pick
                        >
                        {move || {
                            let (view_now, seat, label, blurb) = match (live.hand.get(), live.finished.get()) {
                                (Some(h), _) => {
                                    let (label, blurb) = opponent_label(&h);
                                    (Some(h.view), h.seat, label, blurb)
                                }
                                (None, Some(f)) => {
                                    let label = if f.house {
                                        live.offer.get_untracked().map(|o| o.name).unwrap_or_else(|| "House".into())
                                    } else {
                                        f.opponent.clone()
                                    };
                                    (Some(f.view), f.seat, label, None)
                                }
                                _ => (None, 0, String::new(), None),
                            };
                            match view_now {
                                Some(v) => {
                                    let other = 1 - seat;
                                    // a member's pubkey: their name, or the copyable key
                                    let label_view = if label.len() == 64 {
                                        view! { <KeyName pubkey=label.clone() key_class="font-mono" /> }.into_any()
                                    } else {
                                        label.clone().into_any()
                                    };
                                    view! {
                                        {seat_panel(&v, other, label_view, blurb, unit, false)}
                                        <div class="flex flex-col items-center gap-2 py-2">
                                            <div class="flex gap-1.5 sm:gap-2">{board()}</div>
                                            <p class="text-sm text-gray-300">
                                                "Pot "<span class="font-mono text-amber-300">{v.pot}</span>
                                                <span class="text-gray-500">" · "{v.street.clone()}</span>
                                            </p>
                                        </div>
                                        {seat_panel(&v, seat, "You".into_any(), None, unit, true)}
                                    }.into_any()
                                }
                                None => view! {
                                    <div class="rounded-xl bg-gray-900/60 p-4 ring-1 ring-gray-700/50 text-sm text-gray-400">
                                        {move || match live.offer.get() {
                                            Some(o) => format!("{} deals. Tables: {}.", o.name, o.tables.iter().map(|t| t.label.clone()).collect::<Vec<_>>().join(", ")),
                                            None if live.house_quiet.get() => {
                                                "The house is not answering yet. Still asking…".to_string()
                                            }
                                            None => "Reaching the house…".to_string(),
                                        }}
                                    </div>
                                }.into_any(),
                            }
                        }}
                        </TableSurface>

                        {settlement}
                        {bar}

                        <Show when=move || !in_play.get()>
                            <div class="flex items-center gap-3 flex-wrap">
                                <label class="text-sm text-gray-300 flex items-center gap-2">
                                    "Stakes"
                                    <select
                                        class="bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-1 focus:ring-amber-500"
                                        on:change=move |ev| {
                                            if let Ok(bb) = event_target_value(&ev).parse::<u64>() {
                                                live.stake_bb.set(bb);
                                            }
                                        }
                                        aria-label="Stakes"
                                    >
                                        {stake_select}
                                    </select>
                                </label>
                                <button
                                    class="flex-1 min-w-[10rem] min-h-[44px] px-4 py-3 rounded-lg font-semibold text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 touch-manipulation transition-colors disabled:opacity-50"
                                    prop:disabled=move || !can_sit.get()
                                    on:click=move |_| live.sit()
                                >
                                    {move || if live.busy.get() { "Dealing…" } else if live.finished.get().is_some() { "Next hand against the house" } else { "Sit against the house" }}
                                    <span class="kbd-hint ml-2 text-[10px] opacity-60 font-mono">"Enter"</span>
                                </button>
                            </div>
                            {move || live.waiting.get().map(|w| view! {
                                <p class="text-sm text-amber-300">"Waiting for "<Name pubkey=w.opponent.clone() />" to accept your challenge…"</p>
                            })}
                            {move || (balance.get().is_some_and(|(d, _)| d < chosen_buyin.get())).then(|| view! {
                                <p class="text-xs text-amber-300">"This table's buy-in is "{chosen_buyin.get()}" "{unit}"; ask the faucet from your wallet."</p>
                            })}
                        </Show>
                        <Show when=move || in_play.get()>
                            <button
                                class="min-h-[44px] px-1 py-3 text-xs text-gray-500 hover:text-red-300 underline touch-manipulation"
                                on:click=move |_| live.leave_hand()
                            >
                                "Fold and leave the hand"
                            </button>
                        </Show>

                        <p class="kbd-hint text-xs text-gray-500">
                            "Keys: 1 / F fold · 2 / C check or call · 3 / R bet or raise · Enter sit"
                        </p>
                    </div>

                    <div class="glass-card p-4 text-xs space-y-2">
                        <h2 class="text-sm font-semibold text-white">"Fair deal"</h2>
                        <p class="text-gray-400">"The house commits to a secret before you sit; your browser adds a nonce; the deck is sha256(secret ‖ nonces). When the hand ends the secret is revealed and this page replays the whole hand with its own engine, checks every house action against the bot's book, and only then settles."</p>
                        {move || live.finished.get().map(|f| view! {
                            <p class="font-mono text-gray-500 break-all">"seed "{f.seed.clone()}</p>
                        })}
                    </div>
                </div>

                <div class="space-y-4">
                    {session_card(live.hands_played, live.session_net, unit)}
                    <div class="glass-card p-4 space-y-2">
                        <h2 class="text-sm font-semibold text-white">"At the table"</h2>
                        <ul class="space-y-1">{present_list}</ul>
                        <p class="text-[10px] text-gray-500">"House: "<span class="font-mono break-all">{citizen_pk.get_value()}</span></p>
                    </div>
                    <div class="glass-card p-4 space-y-2">
                        <h2 class="text-sm font-semibold text-white">"This hand"</h2>
                        <ul class="text-xs text-gray-400 space-y-0.5">{story}</ul>
                    </div>
                    {history_card(live.history, unit)}
                    {move || live.offer.get().filter(|o| !o.owed.is_empty() || !o.owing.is_empty()).map(|o| view! {
                        <div class="glass-card p-4 space-y-1 text-xs">
                            <h2 class="text-sm font-semibold text-white">"Open settlements"</h2>
                            {o.owed.iter().map(|d| view! { <p class="text-amber-300">"You owe "{d.amount}" "{unit}" for hand "{d.root[..12].to_string()}"…"</p> }).collect_view()}
                            {o.owing.iter().map(|d| view! { <p class="text-gray-300">"The house owes you "{d.amount}" "{unit}" for hand "{d.root[..12].to_string()}"…"</p> }).collect_view()}
                        </div>
                    })}
                </div>
            </div>
        </div>
    }
    .into_any()
}

/// The display names for a live hand's two seats: "You" and the opponent
/// (the house character's name for the house).
fn seat_names(seat: u32, opponent: &str, house: bool, live: LiveStore) -> Vec<String> {
    let other = if house {
        live.offer
            .get_untracked()
            .map(|o| o.name)
            .unwrap_or_else(|| "House".into())
    } else {
        opponent.to_string()
    };
    (0..2)
        .map(|i| {
            if i == seat {
                "You".to_string()
            } else {
                other.clone()
            }
        })
        .collect()
}

fn legal_of_view_live(h: &crate::poker::live::LiveHand) -> Option<Legal> {
    poker::legal_of_view(&h.view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::profile;

    fn tables() -> Vec<AssetTable> {
        let json = format!(
            r#"[{{"id":"sidestr:dreamlab"}},{{"id":"sidestr:dreamlab-txbt4","asset_id":"{}"}}]"#,
            "07".repeat(32)
        );
        let (list, _) = profile::resolve(Some(&json), profile::Legacy::default());
        let list: &'static [profile::ChainProfile] = Box::leak(list.into_boxed_slice());
        list.iter()
            .map(|p| AssetTable {
                profile: p,
                citizen: "aa".repeat(32),
            })
            .collect()
    }

    /// A scheduled game's link opens its chain's table; anything else opens
    /// the first asset table, and with none the practice table.
    #[test]
    fn the_fragment_opens_its_chains_table() {
        let t = tables();
        assert_eq!(
            opening_mode(&t, "#sidestr-dreamlab-txbt4"),
            Mode::Chain(chain::TXBT4_CHAIN_ID)
        );
        assert_eq!(
            opening_mode(&t, "sidestr-dreamlab"),
            Mode::Chain(chain::CHAIN_ID)
        );
        assert_eq!(opening_mode(&t, ""), Mode::Chain(chain::CHAIN_ID));
        assert_eq!(opening_mode(&t, "#nonsense"), Mode::Chain(chain::CHAIN_ID));
        assert_eq!(opening_mode(&t, "#practice"), Mode::Practice);
        assert_eq!(opening_mode(&[], "#sidestr-dreamlab"), Mode::Practice);
        for m in [
            Mode::Practice,
            Mode::Chain(chain::CHAIN_ID),
            Mode::Chain(chain::TXBT4_CHAIN_ID),
        ] {
            assert_eq!(opening_mode(&t, &fragment_of(m)), m, "round trip");
        }
    }
}
