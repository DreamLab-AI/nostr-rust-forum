//! `/table`: a practice table — heads-up fixed-limit hold'em against a house
//! bot, for chips that are worth nothing.
//!
//! Each hand both stacks reset to the buy-in, the button alternates, and the
//! shuffle is committed before the deal: the page shows SHA-256 of a fresh
//! 32-byte seed, deals from that seed, and reveals it when the hand ends so
//! anyone can check the deck was fixed in advance. The bot decides from its
//! own seat's view only, with randomness derived from the same seed, so a
//! revealed seed replays the whole hand. Nothing here touches the wallet or
//! sends anything; the engine runs locally (see [`crate::poker`]).

use leptos::ev;
use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::poker::{
    self, Choice, HandConfig, HandOutcome, HandState, HistoryRow, Legal, Phase, RosterEntry,
    SeatConfig, SeatView, Stake,
};
use crate::utils::set_timeout_once;

/// The member's seat.
const HERO: u32 = 0;
/// The house bot's seat.
const BOT: u32 = 1;
/// How long the bot "thinks", so each turn can be read.
const BOT_DELAY_MS: i32 = 500;
/// Hands kept in the history card.
const HISTORY_LEN: usize = 20;

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
            <Table />
        </Show>
    }
    .into_any()
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

/// One seat: name, stack, position, street bet, and cards.
fn seat_panel(v: &SeatView, seat: u32, label: String, blurb: Option<String>) -> AnyView {
    let Some(s) = v.seats.get(seat as usize).cloned() else {
        return ().into_any();
    };
    let position = if seat == v.button { "SB" } else { "BB" };
    let dealer = seat == v.button;
    let to_act = v.phase == Phase::Act && v.to_act == seat as i32;
    let ring = if to_act {
        "ring-2 ring-amber-400"
    } else {
        "ring-1 ring-gray-700/50"
    };
    let cards = match s.hole.clone() {
        Some(hole) => hole.into_iter().map(card_face).collect_view().into_any(),
        None if s.folded => {
            view! { <span class="text-xs text-gray-500 italic">"folded"</span> }.into_any()
        }
        None => view! { {card_back()} {card_back()} }.into_any(),
    };
    let bb = v.bb;
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
                    <span class="font-mono">{s.stack}</span>" chips "
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

/// The table itself, mounted only behind every gate.
#[component]
fn Table() -> impl IntoView {
    let config = poker::PokerConfig::load();
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
    let in_play =
        Memo::new(move |_| hand.with(|h| h.as_ref().is_some_and(|h| h.hand.phase == Phase::Act)));
    let hero_turn = Memo::new(move |_| legal.get().is_some_and(|l| l.seat == HERO));

    // Take a new engine state: count a finished hand, prepare the next commit.
    let settle = move |next: HandState| {
        turn.update_value(|t| *t += 1);
        if next.hand.phase == Phase::Done {
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
        if in_play.get_untracked() {
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
        if !hero_turn.get_untracked() {
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
                .is_some_and(|h| h.hand.phase == Phase::Act && h.hand.to_act == BOT as i32)
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
        (0..5)
            .map(|i| {
                cards
                    .get(i)
                    .copied()
                    .map(card_face)
                    .unwrap_or_else(card_slot)
            })
            .collect_view()
    };

    let action_bar = move || {
        let Some(l) = legal.get().filter(|l| l.seat == HERO) else {
            let waiting = in_play.get();
            return view! {
                <p class="text-sm text-gray-500 text-center py-2">
                    {if waiting { "The bot is thinking…" } else { "" }}
                </p>
            }
            .into_any();
        };
        let button = move |choice: Choice, key: &'static str, style: &'static str| {
            poker::choice_label(&l, choice).map(|label| {
                view! {
                    <button
                        class=format!("flex-1 min-w-[6rem] px-4 py-3 rounded-lg font-semibold text-sm transition-colors {style}")
                        on:click=move |_| hero_act(choice)
                    >
                        {label}
                        <span class="ml-2 text-[10px] opacity-60 font-mono">{key}</span>
                    </button>
                }
            })
        };
        view! {
            <div class="flex flex-wrap gap-2">
                {button(Choice::Fold, "1", "bg-gray-700 hover:bg-gray-600 text-gray-100")}
                {button(Choice::Passive, "2", "bg-gray-600 hover:bg-gray-500 text-white")}
                {button(Choice::Aggressive, "3", "bg-amber-500 hover:bg-amber-400 text-gray-900")}
            </div>
        }
        .into_any()
    };

    let narration = move || {
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
        let lines: Vec<String> = hand.with(|h| {
            h.as_ref()
                .map(|h| {
                    h.hand
                        .log
                        .iter()
                        .filter_map(|e| poker::describe(e, &names, HERO))
                        .collect()
                })
                .unwrap_or_default()
        });
        let skip = lines.len().saturating_sub(8);
        lines
            .into_iter()
            .skip(skip)
            .map(|l| view! { <li>{l}</li> })
            .collect_view()
    };

    let fairness = move || {
        let finished = hand.with(|h| {
            h.as_ref()
                .filter(|h| h.hand.phase == Phase::Done)
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
                        {move || match seat_view.get() {
                            Some(v) => seat_panel(&v, BOT, bot_label.clone(), Some(bot_blurb.clone())),
                            None => view! {
                                <div class="rounded-xl bg-gray-900/60 p-4 ring-1 ring-gray-700/50">
                                    <p class="font-semibold text-white">{bot_label.clone()}</p>
                                    <p class="text-xs text-gray-500 italic">{bot_blurb.clone()}</p>
                                </div>
                            }.into_any(),
                        }}

                        <div class="flex flex-col items-center gap-2 py-2">
                            <div class="flex gap-1.5 sm:gap-2">{board}</div>
                            <p class="text-sm text-gray-300">
                                {move || seat_view.get().map(|v| view! {
                                    "Pot "<span class="font-mono text-amber-300">{v.pot}</span>
                                    <span class="text-gray-500">" · "{v.street.clone()}</span>
                                })}
                            </p>
                        </div>

                        {move || seat_view.get().map(|v| seat_panel(&v, HERO, "You".to_string(), None))}

                        {move || outcome.get().map(|o| {
                            let tone = net_tone(o.hero_net);
                            view! {
                                <div class="rounded-lg bg-gray-800/70 p-3 text-sm">
                                    <p class="text-gray-100">{o.text.clone()}</p>
                                    <p class=format!("font-mono {tone}")>{poker::signed(o.hero_net)}" chips this hand"</p>
                                </div>
                            }
                        })}

                        {action_bar}

                        <Show when=move || !in_play.get()>
                            <button
                                class="w-full px-4 py-3 rounded-lg font-semibold text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 transition-colors"
                                on:click=move |_| deal()
                            >
                                {move || if hand.with(Option::is_some) { "Next hand" } else { "Deal" }}
                                <span class="ml-2 text-[10px] opacity-60 font-mono">"Enter"</span>
                            </button>
                        </Show>

                        {move || error.get().map(|e| view! {
                            <p class="text-sm text-red-400" role="alert">{e}</p>
                        })}

                        <p class="text-xs text-gray-500">
                            "Keys: 1 / F fold · 2 / C check or call · 3 / R bet or raise · Enter next hand"
                        </p>
                    </div>

                    <div class="glass-card p-4 text-xs space-y-3">
                        <h2 class="text-sm font-semibold text-white">"Fair shuffle"</h2>
                        {fairness}
                    </div>
                </div>

                <div class="space-y-4">
                    <div class="glass-card p-4 space-y-2">
                        <h2 class="text-sm font-semibold text-white">"Session"</h2>
                        <p class="text-sm text-gray-300">
                            {move || format!("Hands played: {}", hands_played.get())}
                        </p>
                        <p class="text-sm text-gray-300">
                            "Net: "
                            <span class=move || format!("font-mono {}", net_tone(session_net.get()))>
                                {move || poker::signed(session_net.get())}
                            </span>
                            " chips"
                        </p>
                    </div>

                    <div class="glass-card p-4 space-y-2">
                        <h2 class="text-sm font-semibold text-white">"This hand"</h2>
                        <ul class="text-xs text-gray-400 space-y-0.5">{narration}</ul>
                    </div>

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
                                            {poker::signed(row.net)}
                                        </span>
                                    </li>
                                </For>
                            </ul>
                        </Show>
                    </div>
                </div>
            </div>
        </div>
    }
}
