//! `/wallet`: a member's DREAM wallet on the DreamLab test chain (ADR-2015).
//!
//! One page, top to bottom in the order a member needs it: what I have,
//! (unlock, if my key lives in an extension), give (DREAM, sats, or a starter
//! pack that provisions a member or an agent in one transaction), receive,
//! my agents, what happened, and what this is. Every figure comes from the
//! chain the browser has just validated; nothing is taken from a server.

use bitcoin::OutPoint;
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use wasm_bindgen_futures::spawn_local;

use crate::admin::agents_roster::{load_roster, AgentRosterEntry};
use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::mention_autocomplete::{search_profiles, MentionCandidate};
use crate::components::tip_button::{dream_icon, grouped};
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::utils::format_relative_time;
use crate::wallet::chain::{self, Balances, Snapshot};
use crate::wallet::{use_wallet, LoadStatus, Pending, PendingKind, WalletStore};

/// What the give form sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Dream,
    Sats,
    Pack,
}

/// The starter pack: enough DREAM to tip with, enough sats for its fees.
const PACK_DREAM: u64 = 100;
const PACK_SATS: u64 = 2_000;
/// What a transfer typically costs: shown before review, not charged by it.
const FEE_HINT: u64 = 250;

fn short(s: &str) -> String {
    if s.len() <= 20 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..12], &s[s.len() - 6..])
    }
}

fn held(wallet: &WalletStore) -> Vec<OutPoint> {
    wallet
        .pending
        .get()
        .iter()
        .flat_map(|p| p.spent.iter().filter_map(|s| s.parse().ok()))
        .collect()
}

fn copy(text: String) {
    if let Some(w) = web_sys::window() {
        let _ = w.navigator().clipboard().write_text(&text);
    }
}

/// A script's owner shown by name when it is a member's key.
#[component]
fn Party(#[prop(into)] script: String) -> impl IntoView {
    match chain::script_of_hex(&script).and_then(|s| chain::pubkey_of_script(&s)) {
        Some(pk) => {
            let name = use_display_name_memo(pk.clone());
            view! { <span class="text-gray-200">{move || name.get()}</span> }.into_any()
        }
        None => view! { <span class="text-gray-400 font-mono text-xs">{short(&script)}</span> }
            .into_any(),
    }
}

#[component]
pub fn WalletPage() -> impl IntoView {
    let Some(wallet) = use_wallet() else {
        return view! {
            <div class="max-w-2xl mx-auto px-4 py-16 text-center text-gray-400">
                <p>"This forum has not switched on member wallets."</p>
            </div>
        }
        .into_any();
    };
    wallet.ensure_loaded();
    let auth = use_auth();
    let toasts = use_toasts();

    let me = auth.pubkey();
    let my_script = Memo::new(move |_| me.get().and_then(|pk| chain::script_of(&pk)));
    let balances = Memo::new(move |_| -> Option<Balances> {
        let snap = wallet.snapshot()?;
        Some(snap.balances(&my_script.get()?, &held(&wallet)))
    });
    let pending_out = Memo::new(move |_| {
        wallet
            .pending
            .get()
            .iter()
            .fold((0u64, 0u64), |(d, s), p| (d + p.dream, s + p.sats + p.fee))
    });

    // ── give form ────────────────────────────────────────────────────────
    let query = use_query_map();
    let mode = RwSignal::new(match query.get_untracked().get("mode").as_deref() {
        Some("pack") => Mode::Pack,
        Some("sats") => Mode::Sats,
        _ => Mode::Dream,
    });
    let to_text = RwSignal::new(query.get_untracked().get("to").unwrap_or_default());
    let picked: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let suggestions: RwSignal<Vec<MentionCandidate>> = RwSignal::new(Vec::new());
    let amount = RwSignal::new(String::new());
    let pack_dream = RwSignal::new(PACK_DREAM.to_string());
    let pack_sats = RwSignal::new(PACK_SATS.to_string());
    let review = RwSignal::new(false);
    let sending = RwSignal::new(false);
    let search_seq = StoredValue::new(0u32);

    let recipient = Memo::new(
        move |_| -> Result<(bitcoin::ScriptBuf, Option<String>), String> {
            if let Some((pk, _)) = picked.get() {
                return chain::script_of(&pk)
                    .map(|s| (s, Some(pk)))
                    .ok_or_else(|| "That member's key is not valid.".to_string());
            }
            let t = to_text.get();
            if t.trim().is_empty() {
                return Err("Choose who to send to.".into());
            }
            let s = chain::destination_script(&t)?;
            let pk = chain::pubkey_of_script(&s);
            Ok((s, pk))
        },
    );
    let parse = |s: &str| s.trim().replace(',', "").parse::<u64>().unwrap_or(0);

    let on_search = move |text: String| {
        to_text.set(text.clone());
        picked.set(None);
        review.set(false);
        let q = text.trim().to_string();
        if q.len() < 2 || q.starts_with("npub1") || q.starts_with("drm1") || q.starts_with("did:") {
            suggestions.set(Vec::new());
            return;
        }
        let seq = search_seq.get_value() + 1;
        search_seq.set_value(seq);
        spawn_local(async move {
            let found = search_profiles(&q, 6).await;
            if search_seq.get_value() == seq {
                suggestions.set(found);
            }
        });
    };

    let submit = move |_| {
        let Ok((to, _)) = recipient.get_untracked() else {
            return;
        };
        let m = mode.get_untracked();
        let (d, s) = match m {
            Mode::Dream => (parse(&amount.get_untracked()), 0),
            Mode::Sats => (0, parse(&amount.get_untracked())),
            Mode::Pack => (
                parse(&pack_dream.get_untracked()),
                parse(&pack_sats.get_untracked()),
            ),
        };
        sending.set(true);
        spawn_local(async move {
            let r = match m {
                Mode::Dream => wallet.send_dream(&auth, to, d, None).await,
                Mode::Sats => wallet.send_sats(&auth, to, s).await,
                Mode::Pack => wallet.provision(&auth, to, d, s).await,
            };
            match r {
                Ok(_) => {
                    toasts.show(
                        "Sent. It confirms in a minute or two.",
                        ToastVariant::Success,
                    );
                    review.set(false);
                    amount.set(String::new());
                    to_text.set(String::new());
                    picked.set(None);
                }
                Err(e) => toasts.show(e, ToastVariant::Error),
            }
            sending.set(false);
        });
    };

    // ── agents ───────────────────────────────────────────────────────────
    let agents: RwSignal<Vec<AgentRosterEntry>> = RwSignal::new(Vec::new());
    Effect::new(move |_| {
        if me.get().is_some() {
            spawn_local(async move {
                if let Ok(list) = load_roster(auth).await {
                    agents.set(list.into_iter().filter(|a| a.is_active()).collect());
                }
            });
        }
    });

    // ── unlock ───────────────────────────────────────────────────────────
    let unlock_text = RwSignal::new(String::new());
    let unlock_error: RwSignal<Option<String>> = RwSignal::new(None);

    let faucet_busy = RwSignal::new(false);
    let ask_faucet = move |_| {
        let Some(pk) = me.get_untracked() else { return };
        faucet_busy.set(true);
        spawn_local(async move {
            match wallet.request_faucet(&pk).await {
                Ok(n) => toasts.show(
                    format!("Asked the DreamLab faucet on {n} relays. A starter pack arrives within a few minutes when it is running; once a day per member."),
                    ToastVariant::Info,
                ),
                Err(e) => toasts.show(e, ToastVariant::Error),
            }
            faucet_busy.set(false);
        });
    };

    let card = "glass-card rounded-2xl p-5";
    let label = "text-xs uppercase tracking-wide text-gray-500";
    let input = "w-full bg-gray-800/80 border border-gray-600/60 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-amber-500/60";
    let chip = "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors";

    view! {
        <div class="max-w-3xl mx-auto px-4 py-6 space-y-5">
            <header class="flex items-start justify-between gap-4">
                <div>
                    <h1 class="text-2xl font-bold text-gray-100 flex items-center gap-2">
                        {dream_icon("w-6 h-6 text-amber-400")}
                        "Wallet"
                    </h1>
                    <p class="text-sm text-gray-400 mt-1">"DREAM, the community's tipping token, on the DreamLab test chain."</p>
                </div>
            </header>

            <div class="rounded-xl border border-sky-500/30 bg-sky-500/10 px-4 py-3 text-sm text-sky-200">
                "Test tokens on a sidechain of Bitcoin's testnet4. They have no cash value and can't be bought or sold. Use them to thank people, and to give new members and agents what they need to get started."
            </div>

            // ── balance ──────────────────────────────────────────────────
            <section class=card aria-labelledby="bal-h">
                <h2 id="bal-h" class=label>"Your balance"</h2>
                {move || match (balances.get(), wallet.status.get()) {
                    (Some(b), _) => view! {
                        <div class="mt-2 flex items-baseline gap-2">
                            <span class="text-4xl font-bold text-amber-300 tabular-nums">{grouped(b.dream)}</span>
                            <span class="text-lg text-amber-200/80">"DREAM"</span>
                        </div>
                        <p class="mt-1 text-sm text-gray-400">
                            <span class="tabular-nums text-gray-300">{grouped(b.plain)}</span>
                            " sats for fees"
                            {(b.carrier_sats > 0).then(|| view! {
                                <span class="text-gray-500">" · " {grouped(b.carrier_sats)} " sats travel with your DREAM"</span>
                            })}
                        </p>
                        {move || {
                            let (d, s) = pending_out.get();
                            (d > 0 || s > 0).then(|| view! {
                                <p class="mt-2 text-xs text-amber-200/80">
                                    "On its way: " {grouped(d)} " DREAM and " {grouped(s)} " sats, confirming in a minute or two."
                                </p>
                            })
                        }}
                    }.into_any(),
                    (None, LoadStatus::Failed(e)) => view! {
                        <p class="mt-2 text-sm text-red-300">"The DreamLab chain could not be read: " {e}</p>
                    }.into_any(),
                    (None, _) => view! {
                        <p class="mt-2 text-sm text-gray-400">"Downloading and checking the chain…"</p>
                    }.into_any(),
                }}
                <div class="mt-3 flex items-center gap-2 text-xs text-gray-500">
                    {move || wallet.snapshot().map(|s| view! {
                        <span>
                            "Checked in your browser to block " {s.height()} " · last block "
                            {format_relative_time(u64::from(s.tip_time()))}
                        </span>
                    })}
                    <button
                        class="ml-auto text-amber-400 hover:text-amber-300 disabled:opacity-40"
                        disabled=move || wallet.status.get() == LoadStatus::Loading
                        on:click=move |_| wallet.reload()
                    >
                        {move || if wallet.status.get() == LoadStatus::Loading { "Checking…" } else { "Refresh" }}
                    </button>
                </div>
            </section>

            // ── unlock (extension sign-in only) ──────────────────────────
            <Show when=move || me.get().is_some() && !wallet.can_spend(&auth)>
                <section class=card aria-labelledby="unlock-h">
                    <h2 id="unlock-h" class="text-sm font-semibold text-gray-100">"Unlock to send"</h2>
                    <p class="mt-1 text-sm text-gray-400">
                        "You signed in with a browser extension, which can receive DREAM but can't sign DreamLab transfers yet. Paste your nsec to send from this tab. It stays in this tab's memory and is forgotten when you close it or sign out; it is never sent anywhere."
                    </p>
                    <form class="mt-3 flex gap-2" on:submit=move |ev| {
                        ev.prevent_default();
                        let pk = me.get_untracked().unwrap_or_default();
                        match wallet.unlock(&unlock_text.get_untracked(), &pk) {
                            Ok(()) => { unlock_error.set(None); unlock_text.set(String::new()); }
                            Err(e) => unlock_error.set(Some(e)),
                        }
                    }>
                        <input
                            type="password"
                            autocomplete="off"
                            spellcheck="false"
                            class=input
                            placeholder="nsec1…"
                            aria-label="Your nsec"
                            prop:value=move || unlock_text.get()
                            on:input=move |ev| unlock_text.set(event_target_value(&ev))
                        />
                        <button type="submit" class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold">"Unlock"</button>
                    </form>
                    {move || unlock_error.get().map(|e| view! { <p class="mt-2 text-xs text-red-300">{e}</p> })}
                </section>
            </Show>
            <Show when=move || wallet.unlocked.get()>
                <p class="text-xs text-gray-500 -mt-2">
                    "Unlocked for this tab. "
                    <button class="text-amber-400 hover:text-amber-300" on:click=move |_| wallet.lock()>"Lock now"</button>
                </p>
            </Show>

            // ── give ─────────────────────────────────────────────────────
            <section class=card aria-labelledby="give-h">
                <h2 id="give-h" class="text-sm font-semibold text-gray-100">"Give"</h2>
                <div class="mt-3 flex gap-1.5" role="tablist" aria-label="What to give">
                    {[(Mode::Dream, "DREAM"), (Mode::Pack, "Starter pack"), (Mode::Sats, "Sats")].into_iter().map(|(m, text)| view! {
                        <button
                            role="tab"
                            aria-selected=move || if mode.get() == m { "true" } else { "false" }
                            class=move || if mode.get() == m {
                                format!("{chip} bg-amber-500/20 text-amber-200 border border-amber-500/40")
                            } else {
                                format!("{chip} bg-gray-700/40 text-gray-300 border border-transparent hover:bg-gray-700/70")
                            }
                            on:click=move |_| { mode.set(m); review.set(false); }
                        >
                            {text}
                        </button>
                    }).collect_view()}
                </div>
                <p class="mt-2 text-xs text-gray-500">
                    {move || match mode.get() {
                        Mode::Dream => "Send DREAM to a member or an agent.",
                        Mode::Pack => "Provision a new member or an agent: DREAM to tip with and sats for their fees, in one transfer.",
                        Mode::Sats => "Send sats for fees. Sats never come out of your DREAM.",
                    }}
                </p>

                // recipient
                <div class="mt-4 relative">
                    <label class="block text-xs text-gray-400 mb-1" for="give-to">"To"</label>
                    {move || match picked.get() {
                        Some((pk, name)) => view! {
                            <div class="flex items-center justify-between gap-2 bg-gray-800/80 border border-amber-500/40 rounded-lg px-3 py-2">
                                <span class="text-sm text-gray-100 truncate">{name} <span class="text-gray-500 font-mono text-xs">" " {short(&pk)}</span></span>
                                <button class="text-xs text-gray-400 hover:text-gray-200" on:click=move |_| { picked.set(None); review.set(false); }>"Change"</button>
                            </div>
                        }.into_any(),
                        None => view! {
                            <input
                                id="give-to"
                                class=input
                                placeholder="A member's name, an npub, or a drm1… address"
                                autocomplete="off"
                                spellcheck="false"
                                prop:value=move || to_text.get()
                                on:input=move |ev| on_search(event_target_value(&ev))
                            />
                        }.into_any(),
                    }}
                    <Show when=move || picked.get().is_none() && !suggestions.get().is_empty()>
                        <ul class="absolute z-40 mt-1 w-full glass-card rounded-lg py-1 max-h-60 overflow-y-auto" role="listbox">
                            <For each=move || suggestions.get() key=|c| c.pubkey.clone() let:c>
                                {
                                    let name = c.display_name.clone().or(c.name.clone()).unwrap_or_else(|| short(&c.pubkey));
                                    let pk = c.pubkey.clone();
                                    let name_c = name.clone();
                                    view! {
                                        <li>
                                            <button
                                                class="w-full text-left px-3 py-2 text-sm text-gray-200 hover:bg-gray-700/60"
                                                on:click=move |_| {
                                                    picked.set(Some((pk.clone(), name_c.clone())));
                                                    suggestions.set(Vec::new());
                                                }
                                            >
                                                {name}
                                            </button>
                                        </li>
                                    }
                                }
                            </For>
                        </ul>
                    </Show>
                    {move || {
                        let t = to_text.get();
                        (picked.get().is_none() && !t.trim().is_empty() && suggestions.get().is_empty())
                            .then(|| recipient.get().err())
                            .flatten()
                            .filter(|_| t.starts_with("npub1") || t.starts_with("drm1") || t.starts_with("did:") || t.len() == 64)
                            .map(|e| view! { <p class="mt-1 text-xs text-red-300">{e}</p> })
                    }}
                </div>

                // amounts
                {move || match mode.get() {
                    Mode::Pack => view! {
                        <div class="mt-4 grid grid-cols-2 gap-3">
                            <div>
                                <label class="block text-xs text-gray-400 mb-1">"DREAM"</label>
                                <input class=input inputmode="numeric" prop:value=move || pack_dream.get()
                                    on:input=move |ev| { pack_dream.set(event_target_value(&ev)); review.set(false); } />
                            </div>
                            <div>
                                <label class="block text-xs text-gray-400 mb-1">"Sats for fees"</label>
                                <input class=input inputmode="numeric" prop:value=move || pack_sats.get()
                                    on:input=move |ev| { pack_sats.set(event_target_value(&ev)); review.set(false); } />
                            </div>
                        </div>
                    }.into_any(),
                    m => {
                        let presets: &'static [u64] = if m == Mode::Dream { &[10, 50, 100, 500] } else { &[1_000, 2_000, 5_000] };
                        view! {
                            <div class="mt-4">
                                <label class="block text-xs text-gray-400 mb-1">{if m == Mode::Dream { "Amount of DREAM" } else { "Amount of sats" }}</label>
                                <div class="flex gap-2 flex-wrap">
                                    <input class=format!("{input} max-w-[10rem]") inputmode="numeric" placeholder="0"
                                        prop:value=move || amount.get()
                                        on:input=move |ev| { amount.set(event_target_value(&ev)); review.set(false); } />
                                    {presets.iter().map(|&n| view! {
                                        <button class=format!("{chip} bg-gray-700/40 text-gray-300 hover:bg-gray-700/70")
                                            on:click=move |_| { amount.set(n.to_string()); review.set(false); }>
                                            {grouped(n)}
                                        </button>
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_any()
                    }
                }}

                // review → confirm
                {move || {
                    let can = wallet.can_spend(&auth);
                    let rec = recipient.get();
                    let m = mode.get();
                    let (d, s) = match m {
                        Mode::Dream => (parse(&amount.get()), 0),
                        Mode::Sats => (0, parse(&amount.get())),
                        Mode::Pack => (parse(&pack_dream.get()), parse(&pack_sats.get())),
                    };
                    let bal = balances.get().unwrap_or_default();
                    let ready = rec.is_ok() && (d > 0 || s > 0) && can && wallet.snapshot().is_some();
                    let short_dream = d > bal.dream;
                    let short_sats = s + FEE_HINT > bal.plain;
                    if !review.get() {
                        return view! {
                            <div class="mt-5 flex items-center gap-3">
                                <button
                                    class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
                                    disabled=!ready
                                    on:click=move |_| review.set(true)
                                >
                                    "Review"
                                </button>
                                {(!can && me.get().is_some()).then(|| view! { <span class="text-xs text-gray-500">"Unlock above to send."</span> })}
                                {(ready && short_dream).then(|| view! { <span class="text-xs text-red-300">"More DREAM than you hold."</span> })}
                                {(ready && !short_dream && short_sats).then(|| view! { <span class="text-xs text-amber-200/80">"You may not have enough sats for the fee."</span> })}
                            </div>
                        }.into_any();
                    }
                    let (to_script, to_pk) = match rec { Ok(r) => r, Err(_) => return ().into_any() };
                    let what = match m {
                        Mode::Dream => format!("{} DREAM", grouped(d)),
                        Mode::Sats => format!("{} sats", grouped(s)),
                        Mode::Pack => format!("{} DREAM and {} sats", grouped(d), grouped(s)),
                    };
                    let after = match m {
                        Mode::Sats => format!("{} sats left for fees, about", grouped(bal.plain.saturating_sub(s + FEE_HINT))),
                        _ => format!("{} DREAM left", grouped(bal.dream.saturating_sub(d))),
                    };
                    view! {
                        <div class="mt-5 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
                            <dl class="grid grid-cols-[6rem_1fr] gap-y-1.5 text-sm">
                                <dt class="text-gray-500">"To"</dt>
                                <dd class="text-gray-100 min-w-0 truncate">
                                    {match to_pk.clone() {
                                        Some(pk) => view! { <Party script=to_script.to_hex_string() /> <span class="text-gray-500 font-mono text-xs">" " {short(&chain::address_of(&pk).unwrap_or_default())}</span> }.into_any(),
                                        None => view! { <span class="font-mono text-xs">{short(&to_script.to_hex_string())}</span> }.into_any(),
                                    }}
                                </dd>
                                <dt class="text-gray-500">"Sending"</dt>
                                <dd class="text-gray-100 font-medium">{what}</dd>
                                <dt class="text-gray-500">"Fee"</dt>
                                <dd class="text-gray-300">"about " {FEE_HINT} " sats"</dd>
                                <dt class="text-gray-500">"After"</dt>
                                <dd class="text-gray-300">{after}</dd>
                            </dl>
                            <p class="mt-3 text-xs text-gray-500">"Transfers can't be undone. They confirm in a minute or two."</p>
                            <div class="mt-3 flex gap-2">
                                <button
                                    class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-semibold disabled:opacity-40"
                                    disabled=move || sending.get()
                                    on:click=submit
                                >
                                    {move || if sending.get() { "Sending…" } else { "Confirm and send" }}
                                </button>
                                <button class="px-4 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-700/50" on:click=move |_| review.set(false)>"Back"</button>
                            </div>
                        </div>
                    }.into_any()
                }}
            </section>

            // ── receive ──────────────────────────────────────────────────
            {move || me.get().and_then(|pk| {
                let addr = chain::address_of(&pk)?;
                let npub = sidestr_agent::parse_pubkey(&pk).ok().map(|k| sidestr_agent::npub(&k))?;
                let qr = crate::utils::devices::qr_svg(&addr);
                let addr_c = addr.clone();
                let npub_c = npub.clone();
                let empty = balances.get().is_some_and(|b| b.dream == 0 && b.plain == 0);
                Some(view! {
                    <section class=card aria-labelledby="recv-h">
                        <h2 id="recv-h" class="text-sm font-semibold text-gray-100">"Receive"</h2>
                        <p class="mt-1 text-sm text-gray-400">"Anyone here can pay you by name. Your npub is your wallet: there's nothing to set up."</p>
                        <div class="mt-4 flex flex-col sm:flex-row gap-5 items-start">
                            <div class="bg-white rounded-xl p-2 w-40 h-40 shrink-0 [&>svg]:w-full [&>svg]:h-full" inner_html=qr aria-label="QR code of your wallet address"></div>
                            <div class="min-w-0 space-y-3 flex-1">
                                <div>
                                    <div class=label>"Address"</div>
                                    <div class="flex items-center gap-2 mt-1">
                                        <code class="text-xs text-gray-200 break-all">{addr.clone()}</code>
                                        <button class="text-xs text-amber-400 hover:text-amber-300 shrink-0" on:click=move |_| { copy(addr_c.clone()); toasts.show("Address copied", ToastVariant::Success); }>"Copy"</button>
                                    </div>
                                </div>
                                <div>
                                    <div class=label>"Or your npub"</div>
                                    <div class="flex items-center gap-2 mt-1">
                                        <code class="text-xs text-gray-400 break-all">{npub.clone()}</code>
                                        <button class="text-xs text-amber-400 hover:text-amber-300 shrink-0" on:click=move |_| { copy(npub_c.clone()); toasts.show("npub copied", ToastVariant::Success); }>"Copy"</button>
                                    </div>
                                </div>
                                {empty.then(|| view! {
                                    <div class="rounded-lg border border-gray-600/50 p-3">
                                        <p class="text-sm text-gray-300">"New here? Ask the DreamLab faucet for a starter pack: " {PACK_DREAM} " DREAM and " {grouped(PACK_SATS)} " sats."</p>
                                        <button
                                            class="mt-2 px-3 py-1.5 rounded-lg bg-gray-700/70 hover:bg-gray-700 text-sm text-gray-100 disabled:opacity-40"
                                            disabled=move || faucet_busy.get()
                                            on:click=ask_faucet
                                        >
                                            {move || if faucet_busy.get() { "Asking…" } else { "Ask the faucet" }}
                                        </button>
                                    </div>
                                })}
                            </div>
                        </div>
                    </section>
                })
            })}

            // ── agents ───────────────────────────────────────────────────
            {move || {
                let list = agents.get();
                if list.is_empty() { return None; }
                let mine_pk = me.get().unwrap_or_default();
                let mut rows = list;
                rows.sort_by_key(|a| (!a.registered_by.eq_ignore_ascii_case(&mine_pk), a.name.to_lowercase()));
                let snap = wallet.snapshot();
                Some(view! {
                    <section class=card aria-labelledby="agents-h">
                        <h2 id="agents-h" class="text-sm font-semibold text-gray-100">"Agents"</h2>
                        <p class="mt-1 text-sm text-gray-400">"Agents have wallets too. Top one up with a starter pack so it can tip and pay its own fees."</p>
                        <ul class="mt-3 divide-y divide-gray-700/50">
                            {rows.into_iter().map(|a| {
                                let bal = snap.as_ref().zip(chain::script_of(&a.pubkey)).map(|(s, sc)| s.balances(&sc, &[])).unwrap_or_default();
                                let yours = a.registered_by.eq_ignore_ascii_case(&mine_pk);
                                let pk = a.pubkey.clone();
                                let name = if a.name.is_empty() { short(&a.pubkey) } else { a.name.clone() };
                                let name_c = name.clone();
                                view! {
                                    <li class="py-2.5 flex items-center gap-3">
                                        <div class="min-w-0 flex-1">
                                            <div class="text-sm text-gray-100 truncate">
                                                {name}
                                                {yours.then(|| view! { <span class="ml-2 text-[10px] uppercase tracking-wide text-amber-300/80">"yours"</span> })}
                                            </div>
                                            <div class="text-xs text-gray-500 tabular-nums">{grouped(bal.dream)} " DREAM · " {grouped(bal.plain)} " sats"</div>
                                        </div>
                                        <button
                                            class=format!("{chip} bg-gray-700/50 text-gray-200 hover:bg-amber-500/20 hover:text-amber-200")
                                            on:click=move |_| {
                                                mode.set(Mode::Pack);
                                                picked.set(Some((pk.clone(), name_c.clone())));
                                                review.set(false);
                                                if let Some(el) = web_sys::window().and_then(|w| w.document()).and_then(|d| d.get_element_by_id("give-h")) {
                                                    el.scroll_into_view();
                                                }
                                            }
                                        >
                                            "Top up"
                                        </button>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    </section>
                })
            }}

            // ── activity ─────────────────────────────────────────────────
            <section class=card aria-labelledby="act-h">
                <h2 id="act-h" class="text-sm font-semibold text-gray-100">"Activity"</h2>
                {move || {
                    let pend = wallet.pending.get();
                    let Some(script) = my_script.get() else { return view! { <p class="mt-2 text-sm text-gray-500">"Sign in to see your activity."</p> }.into_any() };
                    let snap: Option<std::rc::Rc<Snapshot>> = wallet.snapshot();
                    let me_hex = script.to_hex_string();
                    let hist: Vec<chain::TxSummary> = snap.as_ref().map(|s| s.history(&me_hex).into_iter().take(50).cloned().collect()).unwrap_or_default();
                    if pend.is_empty() && hist.is_empty() {
                        return view! { <p class="mt-2 text-sm text-gray-500">"Nothing yet. Tips you send and receive will show here."</p> }.into_any();
                    }
                    view! {
                        <ul class="mt-3 divide-y divide-gray-700/50">
                            {pend.into_iter().map(|p: Pending| {
                                let what = match p.kind {
                                    PendingKind::Tip => "Tip",
                                    PendingKind::Dream => "Sent",
                                    PendingKind::Sats => "Sent",
                                    PendingKind::Provision => "Starter pack",
                                };
                                view! {
                                    <li class="py-2.5 flex items-center gap-3 text-sm">
                                        <span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse shrink-0" aria-hidden="true"></span>
                                        <div class="min-w-0 flex-1">
                                            <div class="text-gray-200">{what} " to " <Party script=p.to.clone() /></div>
                                            <div class="text-xs text-gray-500">"Confirming…"</div>
                                        </div>
                                        <div class="text-right tabular-nums text-gray-300">
                                            {(p.dream > 0).then(|| view! { <div>"−" {grouped(p.dream)} " DREAM"</div> })}
                                            {(p.sats > 0).then(|| view! { <div class="text-xs text-gray-500">"−" {grouped(p.sats)} " sats"</div> })}
                                        </div>
                                    </li>
                                }
                            }).collect_view()}
                            {hist.into_iter().map(|t| {
                                let mv = t.movement(&me_hex);
                                let incoming = mv.dream > 0 || (mv.dream == 0 && mv.sats > 0);
                                let what = if t.txid == chain::DREAM_ASSET_ID {
                                    "Issued DREAM"
                                } else if t.tip_event.is_some() {
                                    if incoming { "Tip received" } else { "Tip" }
                                } else if t.coinbase {
                                    "Pegged in"
                                } else if incoming {
                                    "Received"
                                } else {
                                    "Sent"
                                };
                                let from_to = if incoming { " from " } else { " to " };
                                view! {
                                    <li class="py-2.5 flex items-center gap-3 text-sm">
                                        <span class={if incoming { "w-2 h-2 rounded-full bg-emerald-400 shrink-0" } else { "w-2 h-2 rounded-full bg-gray-500 shrink-0" }} aria-hidden="true"></span>
                                        <div class="min-w-0 flex-1">
                                            <div class="text-gray-200 truncate">
                                                {what}
                                                {mv.counterparty.clone().map(|c| view! { {from_to} <Party script=c /> })}
                                            </div>
                                            <div class="text-xs text-gray-500">
                                                "Block " {t.height} " · " {format_relative_time(u64::from(t.time))}
                                                {t.broken.clone().map(|_| view! { <span class="text-red-300">" · DREAM rule broken"</span> })}
                                            </div>
                                        </div>
                                        <div class="text-right tabular-nums">
                                            {(mv.dream != 0).then(|| view! {
                                                <div class={if mv.dream > 0 { "text-emerald-300" } else { "text-gray-300" }}>
                                                    {if mv.dream > 0 { "+" } else { "−" }} {grouped(mv.dream.unsigned_abs())} " DREAM"
                                                </div>
                                            })}
                                            {(mv.sats != 0).then(|| view! {
                                                <div class="text-xs text-gray-500">
                                                    {if mv.sats > 0 { "+" } else { "−" }} {grouped(mv.sats.unsigned_abs())} " sats"
                                                </div>
                                            })}
                                        </div>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </section>

            // ── about ────────────────────────────────────────────────────
            <details class=format!("{card} text-sm text-gray-400")>
                <summary class="cursor-pointer text-gray-200 font-medium">"How this works"</summary>
                <div class="mt-3 space-y-2 leading-relaxed">
                    <p>"Your forum key is also your wallet on " <code class="text-gray-300">{chain::CHAIN_ID}</code> ", a sidestr sidechain beside Bitcoin's testnet4. DREAM is a token issued on that chain (" {grouped(1_000_000)} " in all)."</p>
                    <p>"This page downloads the chain from a public mirror and checks every block in your browser against the chain's sealed document, so a balance here is never a number a server told you. Transfers are signed in your browser with your key, which never leaves it, and go to the chain through public relays."</p>
                    <p>"Every transfer pays a small fee in sats. DREAM rides on small coins of 330 sats, so tips and starter packs carry some sats to the recipient too."</p>
                    <p class="text-amber-200/80">"Only move DREAM from this wallet. Other sidestr wallets don't know about DREAM yet and could destroy it if you spend the same key's coins there."</p>
                    <p>
                        "Chain explorer: "
                        <a class="text-amber-400 hover:text-amber-300" href="https://sidestr.com/explorer/?chain=sidestr:dreamlab" target="_blank" rel="noopener noreferrer">"sidestr.com/explorer"</a>
                        " · DREAM asset id " <code class="text-xs break-all">{chain::DREAM_ASSET_ID}</code>
                    </p>
                </div>
            </details>

            <p class="text-center text-xs text-gray-600"><a href=base_href("/forums") class="hover:text-gray-400">"Back to the forums"</a></p>
        </div>
    }
    .into_any()
}
