//! Door Games Hub (`#/games`) and Terminal Heads-Up Limit Hold'em Poker
//! (`#/games/poker` & `#/games/poker/<chain>`).
//!
//! Combines the classic UA 571-C Sentry Gun door game (with Opus audio) with a
//! responsive terminal poker table powered by [`nostr_bbs_client_core::poker`]:
//! - **Practice Table**: local Libre Poker engine, deterministic verifiable
//!   shuffle commitment, bot character picker, keyboard (`F`/`C`/`R`) and
//!   thumb-friendly mobile action controls, plus optional AI Poker Coach via DM.
//! - **Live Asset Tables**: real-time NIP-59 gift-wrapped sessions against the
//!   forum's house seat (`LiveStore`) with client-side replay verification and
//!   automatic Sidestr wallet settlement.

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::dm::use_dm_store;
use nostr_bbs_client_core::poker::{
    self, action_for, asset_tables, bb_count, bot_decide, card_name, card_parts, choice_label,
    coach, fresh_seed, hand_name, legal, legal_of_view,
    live::{LiveStore, Pay},
    new_hand, pick_bot, roster, seat_view, seed_commit, signed, summarise, Choice, HandConfig,
    HandState, HistoryRow, PokerConfig, SeatConfig, SeatView, Stake,
};
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::wallet::{chain, use_wallets};

use crate::components::{launch_sentry, AuthorChip, EmptyCard};
use crate::router::{use_router, Route};

/// Door Games Hub (`#/games`).
#[component]
pub fn GamesView() -> impl IntoView {
    let router = use_router();
    let cfg = PokerConfig::load();
    let live_tables = asset_tables();
    let poker_on = poker::site_enabled();
    let has_coach = cfg.coach().is_some();

    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div>
                    <h1 class="bbs-view-title">"DOOR GAMES"</h1>
                    <p class="bbs-view-sub">"Terminal doors, heads-up poker, and retro arcade subsystems."</p>
                </div>
            </div>

            <div class="bbs-grid">
                // Door 1: UA 571-C Automated Sentry Gun
                <article class="bbs-card">
                    <div class="bbs-card-head">
                        <span class="bbs-badge bbs-badge-accent">"DOOR #01"</span>
                        <span class="bbs-muted">"AUDIO · ARCADE"</span>
                    </div>
                    <h2 class="bbs-card-title">"UA 571-C SENTRY GUN"</h2>
                    <p class="bbs-card-desc">
                        "Automated perimeter defence console. Motion-tracker sweep, 500-round ammunition counter, and Opus sound effects."
                    </p>
                    <div class="bbs-card-actions">
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            on:click=move |_| launch_sentry()
                        >
                            "▶ DEPLOY SENTRY"
                        </button>
                    </div>
                </article>

                // Door 2: Practice Hold'em Poker
                <article class="bbs-card">
                    <div class="bbs-card-head">
                        <span class="bbs-badge bbs-badge-accent">"DOOR #02"</span>
                        <span class="bbs-muted">
                            {if has_coach { "PRACTICE · AI COACH" } else { "PRACTICE · FREE CHIPS" }}
                        </span>
                    </div>
                    <h2 class="bbs-card-title">"HEADS-UP LIMIT HOLD'EM"</h2>
                    <p class="bbs-card-desc">
                        "Play fixed-limit Texas Hold'em against local bot archetypes (TAG, LAG, Rock, Station, Maniac) with provably-fair shuffle seeds."
                    </p>
                    <div class="bbs-card-actions">
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            on:click=move |_| router.go(Route::Poker { chain: None })
                        >
                            "♠ PLAY PRACTICE TABLE"
                        </button>
                    </div>
                </article>

                // Live Asset Tables (DREAM, BLAKES7, etc.)
                {live_tables
                    .into_iter()
                    .enumerate()
                    .map(|(idx, tbl)| {
                        let chain_id = tbl.profile.id.to_string();
                        let label = tbl.profile.label.to_string();
                        let title = tbl.title().to_uppercase();
                        let parent = tbl.profile.parent_name.to_string();
                        let door_num = format!("DOOR #{:02}", idx + 3);
                        let nav_id = chain_id.clone();
                        view! {
                            <article class="bbs-card">
                                <div class="bbs-card-head">
                                    <span class="bbs-badge bbs-badge-warn">{door_num}</span>
                                    <span class="bbs-muted">{format!("{label} · {parent}")}</span>
                                </div>
                                <h2 class="bbs-card-title">{title}</h2>
                                <p class="bbs-card-desc">
                                    {format!(
                                        "Live heads-up poker against the forum house seat or other members. Settled on {} with client-side replay verification.",
                                        tbl.profile.id
                                    )}
                                </p>
                                <div class="bbs-card-actions">
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-primary"
                                        disabled=move || !poker_on
                                        on:click=move |_| router.go(Route::Poker { chain: Some(nav_id.clone()) })
                                    >
                                        {if poker_on {
                                            format!("♦ ENTER {label} TABLE")
                                        } else {
                                            "TABLE DISABLED ON NODE".to_string()
                                        }}
                                    </button>
                                </div>
                            </article>
                        }
                    })
                    .collect_view()}
            </div>
        </div>
    }
}

/// Poker table route wrapper: dispatches to Practice or Live chain table.
#[component]
pub fn PokerView(chain: Option<String>) -> impl IntoView {
    let router = use_router();
    let live_tables = asset_tables();

    match chain {
        None => view! { <PracticePokerTable/> }.into_any(),
        Some(target) => {
            let found = live_tables.into_iter().find(|t| {
                t.profile.id.eq_ignore_ascii_case(&target)
                    || t.profile.label.eq_ignore_ascii_case(&target)
            });
            match found {
                Some(tbl) => view! { <LivePokerTable table=tbl/> }.into_any(),
                None => view! {
                    <div class="bbs-view">
                        <div class="bbs-view-head">
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-ghost"
                                on:click=move |_| router.go(Route::Games)
                            >
                                "← GAMES"
                            </button>
                        </div>
                        <EmptyCard
                            title="TABLE NOT FOUND"
                            body=format!("No live poker table matches '{target}' on this deployment.")
                        />
                    </div>
                }
                .into_any(),
            }
        }
    }
}

/// Render a single playing card tile (or face-down card back).
#[component]
fn CardTile(#[prop(optional)] card: Option<u8>) -> impl IntoView {
    match card {
        Some(c) => {
            let name = card_name(c);
            let (rank, suit, red) = card_parts(&name);
            let cls = if red {
                "bbs-playing-card bbs-card-red"
            } else {
                "bbs-playing-card"
            };
            view! {
                <span class=cls aria-label=name>
                    <span class="bbs-card-rank">{rank}</span>
                    <span class="bbs-card-suit">{suit}</span>
                </span>
            }
            .into_any()
        }
        None => view! {
            <span class="bbs-playing-card bbs-card-back" aria-label="face-down card">
                "▒"
            </span>
        }
        .into_any(),
    }
}

/// Shared terminal felt layout used by both Practice and Live tables.
#[component]
fn FeltDisplay(
    view_state: SeatView,
    opp_name: String,
    hero_name: String,
    unit_label: String,
) -> impl IntoView {
    let hero_idx = view_state.seat as usize;
    let opp_idx = if hero_idx == 0 { 1 } else { 0 };
    let hero_seat = view_state.seats.get(hero_idx).cloned();
    let opp_seat = view_state.seats.get(opp_idx).cloned();
    let hero_cards = view_state.hole.clone().unwrap_or_default();
    let opp_cards = opp_seat
        .as_ref()
        .and_then(|s| s.hole.clone())
        .unwrap_or_default();
    let board = view_state.board.clone();
    let pot = view_state.pot;
    let street = view_state.street.to_uppercase();
    let bb = view_state.bb;
    let hero_btn = view_state.button == view_state.seat;

    view! {
        <div class="bbs-poker-felt">
            // Opponent row
            <div class="bbs-poker-seat bbs-poker-opp">
                <div class="bbs-poker-seat-meta">
                    <span class="bbs-poker-seat-name">
                        {opp_name}
                        {(!hero_btn).then(|| view! { <span class="bbs-badge bbs-badge-accent">"BTN"</span> })}
                    </span>
                    {opp_seat.as_ref().map(|s| view! {
                        <span class="bbs-muted">
                            {format!("{} {} ({})", s.stack, unit_label, bb_count(s.stack, bb))}
                            {(s.street_commit > 0).then(|| format!(" · in: {}", s.street_commit))}
                        </span>
                    })}
                </div>
                <div class="bbs-poker-cards">
                    {if opp_cards.is_empty() {
                        view! { <CardTile/><CardTile/> }.into_any()
                    } else {
                        opp_cards.into_iter().map(|c| view! { <CardTile card=c/> }).collect_view().into_any()
                    }}
                </div>
            </div>

            // Community board + pot
            <div class="bbs-poker-center">
                <div class="bbs-poker-pot-row">
                    <span class="bbs-badge">{street}</span>
                    <span class="bbs-poker-pot">{format!("POT: {} {}", pot, unit_label)}</span>
                </div>
                <div class="bbs-poker-board">
                    {if board.is_empty() {
                        view! { <span class="bbs-muted">"[ PREFLOP — NO BOARD CARDS ]"</span> }.into_any()
                    } else {
                        board.into_iter().map(|c| view! { <CardTile card=c/> }).collect_view().into_any()
                    }}
                </div>
            </div>

            // Hero row
            <div class="bbs-poker-seat bbs-poker-hero">
                <div class="bbs-poker-cards">
                    {if hero_cards.is_empty() {
                        view! { <CardTile/><CardTile/> }.into_any()
                    } else {
                        hero_cards.into_iter().map(|c| view! { <CardTile card=c/> }).collect_view().into_any()
                    }}
                </div>
                <div class="bbs-poker-seat-meta">
                    <span class="bbs-poker-seat-name">
                        {hero_name}
                        {hero_btn.then(|| view! { <span class="bbs-badge bbs-badge-accent">"BTN"</span> })}
                    </span>
                    {hero_seat.as_ref().map(|s| view! {
                        <span class="bbs-muted">
                            {format!("{} {} ({})", s.stack, unit_label, bb_count(s.stack, bb))}
                            {(s.street_commit > 0).then(|| format!(" · in: {}", s.street_commit))}
                        </span>
                    })}
                </div>
            </div>
        </div>
    }
}

/// Practice Heads-Up Limit Hold'em table against the local Libre Poker engine.
#[component]
fn PracticePokerTable() -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    let cfg = PokerConfig::load();
    let stakes = cfg.stakes();
    let bot_list = roster();
    let default_bot = pick_bot(&bot_list, &cfg.bot_profile);

    let selected_stake = RwSignal::new(stakes.first().copied().unwrap_or(Stake {
        bb: 2,
        sb: 1,
        buyin: 200,
    }));
    let selected_bot = RwSignal::new(default_bot.profile.clone());
    let hand_state: RwSignal<Option<HandState>> = RwSignal::new(None);
    let current_seed: RwSignal<String> = RwSignal::new(String::new());
    let current_commit: RwSignal<String> = RwSignal::new(String::new());
    let button_seat: RwSignal<u32> = RwSignal::new(0);
    let session_net: RwSignal<i64> = RwSignal::new(0);
    let hands_played: RwSignal<u32> = RwSignal::new(0);
    let history: RwSignal<Vec<HistoryRow>> = RwSignal::new(Vec::new());
    let last_outcome: RwSignal<Option<String>> = RwSignal::new(None);
    let err_msg: RwSignal<Option<String>> = RwSignal::new(None);

    // Optional AI Coach state
    let coach_pk = cfg.coach();
    let coach_status: RwSignal<Option<String>> = RwSignal::new(None);
    let coach_reply: RwSignal<Option<String>> = RwSignal::new(None);
    let dm = use_dm_store();

    // Watch incoming DM replies from the coach
    if let Some(cpk) = coach_pk.clone() {
        let cpk_watch = cpk.clone();
        Effect::new(move |_| {
            let msgs = dm.messages().get();
            if let Some(latest) = msgs.iter().rev().find(|m| {
                !m.is_sent
                    && m.sender_pubkey.eq_ignore_ascii_case(&cpk_watch)
                    && coach::is_coach_content(&m.content)
            }) {
                let text = coach::reply_text(&latest.content);
                if !text.is_empty() {
                    coach_reply.set(Some(text));
                    coach_status.set(None);
                }
            }
        });
    }

    let bot_name_for = move |prof: &str| -> String {
        let list = roster();
        let entry = pick_bot(&list, prof);
        format!("{} {}", entry.emoji, entry.name)
    };

    // Advance bot turns automatically until it's hero's turn (seat 0) or hand ends.
    let advance_bot =
        move |mut st: HandState, seed: &str, profile: &str| -> Result<HandState, String> {
            let mut step = 0u32;
            while st.hand.phase == "act" && st.hand.to_act == 1 && step < 40 {
                let bseed = poker::bot_seed(seed, step as usize);
                let act = bot_decide(&st, 1, profile, &bseed)?;
                st = poker::act(&st, &act)?;
                step += 1;
            }
            Ok(st)
        };

    let finish_if_over = move |st: &HandState| {
        if st.hand.phase != "act" {
            if let Some(outcome) = summarise(&st.hand, 0, hand_name) {
                let n = hands_played.get_untracked() + 1;
                hands_played.set(n);
                session_net.update(|net| *net += outcome.hero_net);
                last_outcome.set(Some(outcome.text.clone()));
                history.update(|h| {
                    h.insert(
                        0,
                        HistoryRow {
                            number: n,
                            text: outcome.text,
                            net: outcome.hero_net,
                        },
                    );
                    h.truncate(20);
                });
            }
        }
    };

    let deal_new = move || {
        err_msg.set(None);
        last_outcome.set(None);
        coach_reply.set(None);
        let Some(seed) = fresh_seed() else {
            err_msg.set(Some("Browser crypto unavailable for shuffle seed.".into()));
            return;
        };
        let commit = seed_commit(&seed);
        let stake = selected_stake.get_untracked();
        let prof = selected_bot.get_untracked();
        let opp_label = bot_name_for(&prof);
        let btn = button_seat.get_untracked();
        button_seat.set(1 - btn);

        let hcfg = HandConfig {
            seats: vec![
                SeatConfig {
                    name: "You".into(),
                    stack: stake.buyin,
                },
                SeatConfig {
                    name: opp_label,
                    stack: stake.buyin,
                },
            ],
            sb: stake.sb,
            bb: stake.bb,
            ante: 0,
            button: btn,
            seed_hex: seed.clone(),
            limit: true,
        };

        match new_hand(&hcfg).and_then(|st| advance_bot(st, &seed, &prof)) {
            Ok(st) => {
                current_seed.set(seed);
                current_commit.set(commit);
                finish_if_over(&st);
                hand_state.set(Some(st));
            }
            Err(e) => err_msg.set(Some(e)),
        }
    };

    let do_choice = move |choice: Choice| {
        let Some(st) = hand_state.get_untracked() else {
            return;
        };
        let Ok(Some(leg)) = legal(&st) else {
            return;
        };
        let Some(action) = action_for(&leg, choice) else {
            return;
        };
        let seed = current_seed.get_untracked();
        let prof = selected_bot.get_untracked();
        coach_reply.set(None);
        match poker::act(&st, &action).and_then(|next| advance_bot(next, &seed, &prof)) {
            Ok(next) => {
                finish_if_over(&next);
                hand_state.set(Some(next));
            }
            Err(e) => err_msg.set(Some(e)),
        }
    };

    let ask_coach = {
        let coach_pk = coach_pk.clone();
        move |_| {
            let Some(cpk) = coach_pk.clone() else {
                return;
            };
            let Some(st) = hand_state.get_untracked() else {
                return;
            };
            let Ok(view_st) = seat_view(&st, 0) else {
                return;
            };
            let Ok(Some(leg)) = legal(&st) else {
                return;
            };
            let Some(prompt) = coach::build_prompt(&view_st, &leg, &st.hand.log, 4) else {
                return;
            };
            let (Some(me), Some(signer)) = (auth.pubkey().get_untracked(), auth.get_signer())
            else {
                coach_status.set(Some("Sign in to ask the poker coach.".into()));
                return;
            };
            let relay = expect_context::<RelayConnection>();
            coach_status.set(Some("Consulting poker coach...".into()));
            coach_reply.set(None);
            match dm.send_message(&relay, &cpk, &prompt, signer, &me) {
                Ok(()) => coach_status.set(Some("Waiting for coach reply...".into())),
                Err(e) => coach_status.set(Some(format!("Coach error: {e}"))),
            }
        }
    };

    let stakes_for_select = stakes.clone();
    let bots_for_select = if bot_list.is_empty() {
        vec![default_bot]
    } else {
        bot_list
    };

    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div class="bbs-row-gap">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost"
                        on:click=move |_| router.go(Route::Games)
                    >
                        "← GAMES"
                    </button>
                    <div>
                        <h1 class="bbs-view-title">"PRACTICE HOLD'EM"</h1>
                        <p class="bbs-view-sub">
                            {move || format!(
                                "Hands: {} · Session: {} chips",
                                hands_played.get(),
                                signed(session_net.get())
                            )}
                        </p>
                    </div>
                </div>
            </div>

            // Stakes + Bot controls
            <div class="bbs-card bbs-poker-controls">
                <div class="bbs-row-wrap">
                    <label class="bbs-field-inline">
                        <span class="bbs-label">"STAKES"</span>
                        <select
                            class="bbs-input"
                            on:change=move |ev| {
                                if let Ok(bb) = event_target_value(&ev).parse::<u64>() {
                                    if let Some(s) = stakes_for_select.iter().find(|s| s.bb == bb) {
                                        selected_stake.set(*s);
                                    }
                                }
                            }
                        >
                            {stakes
                                .iter()
                                .map(|s| {
                                    let val = s.bb.to_string();
                                    let txt = format!("{}/{} (buy-in {})", s.sb, s.bb, s.buyin);
                                    view! { <option value=val>{txt}</option> }
                                })
                                .collect_view()}
                        </select>
                    </label>

                    <label class="bbs-field-inline">
                        <span class="bbs-label">"BOT"</span>
                        <select
                            class="bbs-input"
                            on:change=move |ev| selected_bot.set(event_target_value(&ev))
                        >
                            {bots_for_select
                                .into_iter()
                                .map(|b| {
                                    let selected = b.profile == selected_bot.get_untracked();
                                    let label = format!("{} {} ({})", b.emoji, b.name, b.profile);
                                    view! {
                                        <option value=b.profile selected=selected>{label}</option>
                                    }
                                })
                                .collect_view()}
                        </select>
                    </label>

                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        on:click=move |_| deal_new()
                    >
                        {move || if hand_state.get().is_some() { "DEAL NEXT HAND" } else { "DEAL HAND" }}
                    </button>
                </div>
            </div>

            {move || err_msg.get().map(|e| view! { <div class="bbs-alert bbs-alert-err">{e}</div> })}

            {move || match hand_state.get() {
                None => view! {
                    <EmptyCard
                        title="READY TO DEAL"
                        body="Choose stakes and a bot opponent above, then hit DEAL HAND. Practice chips carry no real value."
                    />
                }.into_any(),
                Some(st) => {
                    let view_res = seat_view(&st, 0);
                    let legal_res = legal(&st).ok().flatten();
                    let opp_n = st.hand.seats.get(1).map(|s| s.name.clone()).unwrap_or_else(|| "House".into());
                    let is_over = st.hand.phase != "act";
                    let commit_short = current_commit.get();
                    let seed_reveal = if is_over { Some(current_seed.get()) } else { None };
                    let show_coach = coach_pk.is_some() && !is_over && legal_res.is_some();

                    view! {
                        <div class="bbs-stack">
                            {view_res.ok().map(|vs| view! {
                                <FeltDisplay
                                    view_state=vs
                                    opp_name=opp_n.clone()
                                    hero_name="YOU".to_string()
                                    unit_label="chips".to_string()
                                />
                            })}

                            {last_outcome.get().map(|txt| view! {
                                <div class="bbs-alert bbs-alert-ok">{txt}</div>
                            })}

                            <div class="bbs-poker-actions">
                                {if is_over {
                                    view! {
                                        <button
                                            type="button"
                                            class="bbs-btn bbs-btn-primary bbs-btn-lg"
                                            on:click=move |_| deal_new()
                                        >
                                            "▶ DEAL NEXT HAND"
                                        </button>
                                    }.into_any()
                                } else if let Some(leg) = legal_res {
                                    let f_lbl = choice_label(&leg, Choice::Fold);
                                    let p_lbl = choice_label(&leg, Choice::Passive);
                                    let a_lbl = choice_label(&leg, Choice::Aggressive);
                                    view! {
                                        <>
                                            {f_lbl.map(|l| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-danger bbs-btn-lg"
                                                    on:click=move |_| do_choice(Choice::Fold)
                                                >
                                                    {l}
                                                </button>
                                            })}
                                            {p_lbl.map(|l| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-lg"
                                                    on:click=move |_| do_choice(Choice::Passive)
                                                >
                                                    {l}
                                                </button>
                                            })}
                                            {a_lbl.map(|l| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-primary bbs-btn-lg"
                                                    on:click=move |_| do_choice(Choice::Aggressive)
                                                >
                                                    {l}
                                                </button>
                                            })}
                                        </>
                                    }.into_any()
                                } else {
                                    view! { <span class="bbs-muted">"Bot thinking..."</span> }.into_any()
                                }}
                            </div>

                            {show_coach.then(|| {
                                let ask = ask_coach.clone();
                                view! {
                                    <div class="bbs-card">
                                        <div class="bbs-card-head">
                                            <strong>"AI POKER COACH"</strong>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                on:click=ask
                                            >
                                                "ASK COACH"
                                            </button>
                                        </div>
                                        {move || coach_status.get().map(|s| view! { <p class="bbs-muted">{s}</p> })}
                                        {move || coach_reply.get().map(|r| view! { <pre class="bbs-pre">{r}</pre> })}
                                    </div>
                                }
                            })}

                            <div class="bbs-card bbs-meta-box">
                                <div class="bbs-muted bbs-mono-xs">
                                    {format!("COMMIT: {}", &commit_short[..commit_short.len().min(24)])}
                                    {seed_reveal.map(|s| format!(" · SEED: {}", &s[..s.len().min(24)]))}
                                </div>
                            </div>
                        </div>
                    }.into_any()
                }
            }}

            {move || {
                let rows = history.get();
                (!rows.is_empty()).then(|| view! {
                    <div class="bbs-card">
                        <h3 class="bbs-section-title">"SESSION LOG"</h3>
                        <ul class="bbs-list">
                            {rows.into_iter().map(|r| {
                                let net_cls = if r.net >= 0 { "bbs-pos" } else { "bbs-neg" };
                                view! {
                                    <li class="bbs-list-row">
                                        <span class="bbs-muted">{format!("#{}", r.number)}</span>
                                        <span class="bbs-flex-1">{r.text}</span>
                                        <span class=net_cls>
                                            {signed(r.net)}
                                        </span>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    </div>
                })
            }}
        </div>
    }
}

/// Live asset-settled poker table backed by [`LiveStore`].
#[component]
fn LivePokerTable(table: poker::AssetTable) -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let wallets = use_wallets();
    let ticker = table.profile.ticker.to_string();
    let title = table.title().to_uppercase();
    let chain_id = table.profile.id;
    let citizen = table.citizen.clone();

    let wallet_store = wallets.and_then(|w| w.get(chain_id));
    if let Some(ws) = wallet_store {
        ws.ensure_loaded();
    }

    let me = auth.pubkey().get_untracked();
    let signer = auth.get_signer();

    let Some((me_pk, signer_rc)) = me.zip(signer) else {
        return view! {
            <div class="bbs-view">
                <div class="bbs-view-head">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost"
                        on:click=move |_| router.go(Route::Games)
                    >
                        "← GAMES"
                    </button>
                </div>
                <EmptyCard
                    title="SIGN IN REQUIRED"
                    body="Sign in with a local key, passkey, or NIP-07 extension to play live asset poker tables."
                />
            </div>
        }
        .into_any();
    };

    let live = LiveStore::new(relay, signer_rc, auth, wallet_store, &me_pk, &citizen);
    live.start();
    on_cleanup(move || live.stop());

    let my_script = chain::script_of(&me_pk);
    let ticker_bal = ticker.clone();
    let ticker_felt = ticker.clone();
    let ticker_fin = ticker.clone();

    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div class="bbs-row-gap">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost"
                        on:click=move |_| router.go(Route::Games)
                    >
                        "← GAMES"
                    </button>
                    <div>
                        <h1 class="bbs-view-title">{title}</h1>
                        <p class="bbs-view-sub">
                            {move || {
                                let bal = wallet_store
                                    .and_then(|w| my_script.as_ref().and_then(|sc| w.asset_now_and_incoming(sc)))
                                    .map(|(free, inc)| {
                                        if inc > 0 {
                                            format!("{free} {ticker_bal} (+{inc} incoming)")
                                        } else {
                                            format!("{free} {ticker_bal}")
                                        }
                                    })
                                    .unwrap_or_else(|| format!("Loading {ticker_bal} wallet..."));
                                format!(
                                    "{bal} · Hands: {} · Net: {}",
                                    live.hands_played.get(),
                                    signed(live.session_net.get())
                                )
                            }}
                        </p>
                    </div>
                </div>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-sm"
                    on:click=move |_| live.hello()
                >
                    "↻ PING HOUSE"
                </button>
            </div>

            {move || live.error.get().map(|e| view! { <div class="bbs-alert bbs-alert-err">{e}</div> })}
            {move || live.notice.get().map(|n| view! { <div class="bbs-alert">{n}</div> })}

            // Incoming member challenges
            {move || {
                let list = live.challenges.get();
                (!list.is_empty()).then(|| view! {
                    <div class="bbs-card">
                        <h3 class="bbs-section-title">"INCOMING CHALLENGES"</h3>
                        <div class="bbs-stack">
                            {list.into_iter().map(|ch| {
                                let c_acc = ch.commit.clone();
                                let c_dec = ch.commit.clone();
                                view! {
                                    <div class="bbs-list-row">
                                        <AuthorChip pubkey=ch.from.clone()/>
                                        <span class="bbs-muted">{format!("BB {} · Buy-in {}", ch.bb, ch.buyin)}</span>
                                        <div class="bbs-row-gap">
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-primary bbs-btn-sm"
                                                on:click=move |_| live.accept(&c_acc)
                                            >
                                                "ACCEPT"
                                            </button>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                                on:click=move |_| live.decline(&c_dec)
                                            >
                                                "DECLINE"
                                            </button>
                                        </div>
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    </div>
                })
            }}

            // Active live hand OR Lobby
            {move || {
                let ticker_f = ticker_felt.clone();
                if let Some(h) = live.hand.get() {
                    let leg = legal_of_view(&h.view);
                    let opp_n = if h.house {
                        live.offer
                            .get()
                            .map(|o| format!("House ({})", o.name))
                            .unwrap_or_else(|| "House".into())
                    } else {
                        format!("{}…", &h.opponent[..h.opponent.len().min(8)])
                    };
                    let busy = live.busy.get();
                    view! {
                        <div class="bbs-stack">
                            <FeltDisplay
                                view_state=h.view.clone()
                                opp_name=opp_n
                                hero_name="YOU".to_string()
                                unit_label=ticker_f
                            />
                            <div class="bbs-poker-actions">
                                {if let Some(l) = leg {
                                    let f_lbl = choice_label(&l, Choice::Fold);
                                    let p_lbl = choice_label(&l, Choice::Passive);
                                    let a_lbl = choice_label(&l, Choice::Aggressive);
                                    view! {
                                        <>
                                            {f_lbl.map(|lbl| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-danger bbs-btn-lg"
                                                    disabled=busy
                                                    on:click=move |_| live.act(Choice::Fold)
                                                >{lbl}</button>
                                            })}
                                            {p_lbl.map(|lbl| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-lg"
                                                    disabled=busy
                                                    on:click=move |_| live.act(Choice::Passive)
                                                >{lbl}</button>
                                            })}
                                            {a_lbl.map(|lbl| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-primary bbs-btn-lg"
                                                    disabled=busy
                                                    on:click=move |_| live.act(Choice::Aggressive)
                                                >{lbl}</button>
                                            })}
                                        </>
                                    }.into_any()
                                } else {
                                    view! {
                                        <span class="bbs-muted">"Waiting for opponent / house..."</span>
                                    }.into_any()
                                }}
                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                    on:click=move |_| live.leave_hand()
                                >
                                    "LEAVE HAND"
                                </button>
                            </div>
                        </div>
                    }.into_any()
                } else if let Some(offer) = live.offer.get() {
                    let chosen_bb = live.stake_bb.get();
                    let tables_offer = offer.tables.clone();
                    let present = offer.present.clone();
                    view! {
                        <div class="bbs-card bbs-stack">
                            <div class="bbs-card-head">
                                <strong>{format!("HOUSE: {} ({})", offer.name, offer.profile)}</strong>
                                <span class="bbs-muted">{format!("Daily cap left: {}", offer.daily_cap_left)}</span>
                            </div>

                            <div class="bbs-row-wrap">
                                {tables_offer.into_iter().map(|t| {
                                    let bb = t.bb;
                                    let active = chosen_bb == bb;
                                    view! {
                                        <button
                                            type="button"
                                            class=if active { "bbs-pill bbs-pill-active" } else { "bbs-pill" }
                                            on:click=move |_| live.stake_bb.set(bb)
                                        >
                                            {format!("{}/{} (buy-in {})", t.sb, t.bb, t.buyin)}
                                        </button>
                                    }
                                }).collect_view()}
                            </div>

                            <div class="bbs-row-wrap">
                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-primary"
                                    disabled=move || live.busy.get()
                                    on:click=move |_| live.sit()
                                >
                                    "♠ DEAL HAND VS HOUSE"
                                </button>
                            </div>

                            {(!present.is_empty()).then(|| view! {
                                <div class="bbs-stack">
                                    <h4 class="bbs-section-title">"PLAYERS AT TABLE"</h4>
                                    {present.into_iter().map(|pk| {
                                        let target = pk.clone();
                                        view! {
                                            <div class="bbs-list-row">
                                                <AuthorChip pubkey=pk/>
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-sm"
                                                    on:click=move |_| live.challenge(&target)
                                                >
                                                    "CHALLENGE"
                                                </button>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            })}
                        </div>
                    }.into_any()
                } else {
                    let quiet = live.house_quiet.get();
                    view! {
                        <EmptyCard
                            title=if quiet { "HOUSE SEAT QUIET" } else { "CONNECTING TO HOUSE SEAT..." }
                            body=if quiet {
                                "The house seat has not answered yet. Keep this open or tap PING HOUSE."
                            } else {
                                "Sending NIP-59 hello to the forum poker citizen over the relay..."
                            }
                        />
                    }.into_any()
                }
            }}

            // Last finished hand verification & settlement status
            {move || {
                let tf = ticker_fin.clone();
                live.finished.get().map(|f| {
                    let verified_badge = match &f.verified {
                        Ok(()) => view! { <span class="bbs-badge bbs-badge-accent">"✓ REPLAY VERIFIED"</span> }.into_any(),
                        Err(why) => view! { <span class="bbs-badge bbs-badge-danger">{format!("✗ {why}")}</span> }.into_any(),
                    };
                    let pay_view = match f.pay.clone() {
                        Pay::Owed { amount, error, .. } => view! {
                            <div class="bbs-row-wrap">
                                <span class="bbs-neg">{format!("Owed: {amount} {tf}")}</span>
                                {error.map(|e| view! { <span class="bbs-muted">{e}</span> })}
                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-primary bbs-btn-sm"
                                    on:click=move |_| live.pay_now()
                                >
                                    "PAY NOW"
                                </button>
                            </div>
                        }.into_any(),
                        Pay::Queued { amount, .. } => view! {
                            <span class="bbs-muted">{format!("Queued {amount} {tf} (waiting for change to confirm)...")}</span>
                        }.into_any(),
                        Pay::Sent(txid) => view! {
                            <span class="bbs-pos">{format!("Paid (tx {}…)", &txid[..txid.len().min(12)])}</span>
                        }.into_any(),
                        Pay::Awaiting { amount } => view! {
                            <span class="bbs-muted">{format!("Awaiting opponent payment of {amount} {tf}...")}</span>
                        }.into_any(),
                        Pay::Received(txid) => view! {
                            <span class="bbs-pos">{format!("Received (tx {}…)", &txid[..txid.len().min(12)])}</span>
                        }.into_any(),
                        Pay::Split => view! { <span class="bbs-muted">"Split pot — no transfer needed."</span> }.into_any(),
                        Pay::Refused(why) => view! { <span class="bbs-neg">{format!("Settlement refused: {why}")}</span> }.into_any(),
                    };
                    view! {
                        <div class="bbs-card bbs-stack">
                            <div class="bbs-card-head">
                                <strong>"LAST HAND"</strong>
                                {verified_badge}
                            </div>
                            <p>{f.text}</p>
                            {pay_view}
                        </div>
                    }
                })
            }}
        </div>
    }
    .into_any()
}
