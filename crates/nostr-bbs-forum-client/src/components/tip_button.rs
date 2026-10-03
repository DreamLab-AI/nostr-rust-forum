//! Tips on a post (ADR-2015, ADR-2021): what a post has been tipped, per
//! asset, and, on other members' posts, a tip button.
//!
//! A tip may be paid in the asset of any chain the deployment offers that has
//! one (DREAM on `sidestr:dreamlab`, BLAKES7 on `sidestr:dreamlab-txbt4`):
//! opening the control shows a token picker first — one row per chain, its
//! mark, its ticker and the member's balance there — with the wallet's active
//! chain highlighted, then the amounts for the chosen token. With one such
//! chain the picker is skipped. Everything a row shows comes from that
//! chain's [`ChainProfile`] and wallet store, so a further pinned chain needs
//! no change here.
//!
//! A tip is an ordinary transfer of the chosen asset to the author's npub,
//! on that asset's chain, carrying a `tip:nostr:<event id>` record beside the
//! tally; the tally names the asset, so the chain says what was tipped, and
//! each chain's replay counts its own asset only. The post's total is shown
//! per asset ("12 DREAM · 500 BLAKES7"), never summed across chains.
//!
//! The control sits at the far right of a post's reply row, away from the
//! emoji reactions ([`crate::components::reaction_bar`]); the caller places it.
//! It renders nothing when the wallet is off or no chain has an asset. Each
//! chain loads lazily on first render and is shared across every post, so a
//! page of fifty posts downloads and validates each chain once.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::wallet::chain::{self, Mark, TipTotal};
use crate::wallet::{use_wallets, ChainProfile, LoadStatus, SpendPath, WalletStore};

const PRESETS: [u64; 4] = [10, 25, 50, 100];

/// Group digits in threes: `12,500`.
pub(crate) fn grouped(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The four-point spark: DREAM's mark, and the wallet's.
pub(crate) fn dream_icon(class: &'static str) -> impl IntoView {
    view! {
        <svg class=class viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" focusable="false">
            <path d="M10 1.5c.4 3.9 1.9 6.9 5.2 7.9.7.2.7 1.2 0 1.4-3.3 1-4.8 4-5.2 7.9-.4-3.9-1.9-6.9-5.2-7.9-.7-.2-.7-1.2 0-1.4C8.1 8.4 9.6 5.4 10 1.5z"/>
        </svg>
    }
}

/// The faceted hexagon: BLAKES7's mark.
fn facet_icon(class: &'static str) -> impl IntoView {
    view! {
        <svg class=class viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" focusable="false">
            <path d="M10 1.5l7.4 4.25v8.5L10 18.5l-7.4-4.25v-8.5L10 1.5zm0 2.3L4.6 6.9v6.2L10 16.2l5.4-3.1V6.9L10 3.8z"/>
            <path d="M10 6.2l3.3 1.9v3.8L10 13.8l-3.3-1.9V8.1L10 6.2z"/>
        </svg>
    }
}

/// A chain asset's mark: the deployment's icon image when the profile names
/// one, else the pin's built-in mark.
pub(crate) fn asset_icon(profile: &ChainProfile, class: &'static str) -> AnyView {
    match &profile.icon_url {
        Some(url) => {
            view! { <img src=url.clone() alt="" class=class aria-hidden="true" /> }.into_any()
        }
        None => match profile.pin().mark {
            Mark::Spark => dream_icon(class).into_any(),
            Mark::Facet => facet_icon(class).into_any(),
        },
    }
}

/// The picker row highlighted when it opens: the wallet's active chain when
/// it is one of `rows`, else the first.
pub(crate) fn default_row(rows: &[&str], active: &str) -> usize {
    rows.iter().position(|id| *id == active).unwrap_or(0)
}

/// A post's tips, one entry per asset that has any, in the order given (the
/// key is whatever names the asset: a ticker, a row).
pub(crate) fn totals_by_asset<K: Copy>(totals: &[(K, TipTotal)]) -> Vec<(K, TipTotal)> {
    totals
        .iter()
        .filter(|(_, t)| t.asset > 0)
        .copied()
        .collect()
}

/// A post's tips in words, per asset: `12 DREAM · 500 BLAKES7`; `None` when
/// nothing was tipped.
pub(crate) fn totals_line(totals: &[(&str, TipTotal)]) -> Option<String> {
    let parts: Vec<String> = totals_by_asset(totals)
        .into_iter()
        .map(|(ticker, t)| format!("{} {ticker}", grouped(t.asset)))
        .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// The member's balance of a store's asset, less coins held by pending
/// transfers; `None` until the chain has loaded or when signed out.
fn balance_of(w: WalletStore, me: Option<String>) -> Option<u64> {
    let snap = w.snapshot()?;
    let script = chain::script_of(&me?)?;
    let held: Vec<bitcoin::OutPoint> = w
        .pending
        .get()
        .iter()
        .flat_map(|p| p.spent.iter().filter_map(|s| s.parse().ok()))
        .collect();
    Some(snap.balances(&script, &held).asset)
}

/// The tip totals and the tip button for one post.
#[component]
pub(crate) fn TipControl(
    /// The post's event id.
    #[prop(into)]
    event_id: String,
    /// The post's author (who the tip pays).
    #[prop(into)]
    author_pubkey: String,
    /// Open the popover below the button (for a control near the top of a
    /// card) rather than above it.
    #[prop(optional)]
    open_down: bool,
) -> impl IntoView {
    let Some(wallets) = use_wallets() else {
        return ().into_any();
    };
    if chain::script_of(&author_pubkey).is_none() {
        return ().into_any();
    }
    let tippable: Vec<WalletStore> = wallets
        .all()
        .into_iter()
        .filter(|w| w.has_asset())
        .collect();
    if tippable.is_empty() {
        return ().into_any();
    }
    for w in &tippable {
        w.ensure_loaded();
    }
    let several = tippable.len() > 1;
    let stores = StoredValue::new(tippable);
    let auth = use_auth();
    let toasts = use_toasts();
    let eid = StoredValue::new(event_id.to_ascii_lowercase());
    let author = StoredValue::new(author_pubkey.to_ascii_lowercase());
    let author_name = use_display_name_memo(author_pubkey.clone());
    let open = RwSignal::new(false);
    // the chosen token's row; `None` while the picker shows
    let chosen: RwSignal<Option<usize>> = RwSignal::new(None);
    let highlighted = RwSignal::new(0usize);
    let custom = RwSignal::new(String::new());
    let sending = RwSignal::new(false);
    let signer_name = StoredValue::new(crate::wallet::extension::name());
    let store_at = move |i: usize| stores.with_value(|l| l.get(i).copied());

    let is_own = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .is_some_and(|me| me.eq_ignore_ascii_case(&author.get_value()))
    });
    // every tippable chain's total for this post, by row
    let totals = Memo::new(move |_| {
        stores.with_value(|l| {
            l.iter()
                .enumerate()
                .map(|(i, w)| (i, w.tip_total(&eid.get_value())))
                .collect::<Vec<_>>()
        })
    });
    let totals_text = move || {
        let named: Vec<(&'static str, TipTotal)> = totals
            .get()
            .into_iter()
            .filter_map(|(i, t)| store_at(i).map(|w| (w.ticker(), t)))
            .collect();
        totals_line(&named)
    };

    let toggle = move |_| {
        if open.get_untracked() {
            open.set(false);
            return;
        }
        let rows: Vec<&str> = stores.with_value(|l| l.iter().map(|w| w.profile.id).collect());
        let row = default_row(&rows, wallets.selected.get_untracked());
        highlighted.set(row);
        chosen.set((!several).then_some(0));
        custom.set(String::new());
        open.set(true);
    };

    let send = move |amount: u64| {
        if amount == 0 || sending.get_untracked() {
            return;
        }
        let (Some(i), Some(to)) = (
            chosen.get_untracked(),
            chain::script_of(&author.get_value()),
        ) else {
            return;
        };
        let Some(wallet) = store_at(i) else { return };
        sending.set(true);
        let event = eid.get_value();
        spawn_local(async move {
            match wallet.send_asset(&auth, to, amount, Some(event)).await {
                Ok(_) => {
                    open.set(false);
                    custom.set(String::new());
                    toasts.show(
                        format!(
                            "Tipped {} {} to {}. It confirms in a minute or two.",
                            grouped(amount),
                            wallet.ticker(),
                            author_name.get_untracked()
                        ),
                        ToastVariant::Success,
                    );
                }
                Err(e) => toasts.show(e, ToastVariant::Error),
            }
            sending.set(false);
        });
    };

    // the token picker: one row per chain with an asset
    let picker = move || {
        let me = auth.pubkey().get();
        let rows = stores.get_value();
        let n = rows.len();
        view! {
            <p class="text-xs text-gray-400 mb-1.5">"Tip in"</p>
            <ul
                class="space-y-1"
                role="listbox"
                aria-label="Token to tip in"
                tabindex="0"
                aria-activedescendant=move || format!("tip-{}-{}", eid.get_value(), highlighted.get())
                on:keydown=move |ev| match ev.key().as_str() {
                    "ArrowDown" => { ev.prevent_default(); highlighted.update(|h| *h = (*h + 1) % n); }
                    "ArrowUp" => { ev.prevent_default(); highlighted.update(|h| *h = (*h + n - 1) % n); }
                    "Enter" | " " => { ev.prevent_default(); chosen.set(Some(highlighted.get_untracked())); }
                    _ => {}
                }
            >
                {rows.into_iter().enumerate().map(|(i, w)| {
                    let me = me.clone();
                    let bal = move || match (balance_of(w, me.clone()), w.status.get()) {
                        (Some(b), _) => grouped(b),
                        (None, LoadStatus::Failed(_)) => "unavailable".to_string(),
                        (None, _) => "…".to_string(),
                    };
                    view! {
                        <li
                            id=format!("tip-{}-{i}", eid.get_value())
                            role="option"
                            aria-selected=move || if highlighted.get() == i { "true" } else { "false" }
                            class=move || if highlighted.get() == i {
                                "flex items-center gap-2 px-2 py-1.5 rounded-lg cursor-pointer bg-amber-500/20 ring-1 ring-amber-500/40 text-amber-100"
                            } else {
                                "flex items-center gap-2 px-2 py-1.5 rounded-lg cursor-pointer text-gray-200 hover:bg-gray-700/60"
                            }
                            on:mouseenter=move |_| highlighted.set(i)
                            on:click=move |_| chosen.set(Some(i))
                        >
                            {asset_icon(w.profile, "w-4 h-4 text-amber-400 shrink-0")}
                            <span class="font-medium">{w.ticker()}</span>
                            <span class="ml-auto text-xs tabular-nums text-gray-400">{bal}</span>
                        </li>
                    }
                }).collect_view()}
            </ul>
        }
    };

    // the amounts for the chosen token
    let amounts = move |wallet: WalletStore| {
        let ticker = wallet.ticker();
        let status = wallet.status.get();
        let back = several.then(|| view! {
            <button class="mb-2 text-[11px] text-gray-400 hover:text-amber-300" on:click=move |_| chosen.set(None)>
                "← Another token"
            </button>
        });
        if wallet.snapshot().is_none() {
            return view! {
                {back}
                {match status {
                    LoadStatus::Failed(e) => view! {
                        <p class="text-xs text-red-300">{format!("The {} chain could not be read: ", wallet.profile.id)} {e}</p>
                        <button class="mt-2 text-xs text-amber-400 hover:text-amber-300" on:click=move |_| wallet.reload()>"Try again"</button>
                    }.into_any(),
                    _ => view! { <p class="text-xs text-gray-400">"Checking your wallet…"</p> }.into_any(),
                }}
            }.into_any();
        }
        if !wallet.can_spend(&auth) {
            return view! {
                {back}
                <p class="text-xs text-gray-400">
                    "Your key lives in your browser extension, which can't sign DreamLab transfers. Podkey can, and asks you to confirm each one; or unlock your wallet for this tab to tip."
                </p>
                <a href=base_href("/wallet") class="mt-2 inline-block text-xs text-amber-400 hover:text-amber-300">"Open wallet →"</a>
            }.into_any();
        }
        let via_extension = wallet.spend_path(&auth) == SpendPath::Extension;
        let bal = balance_of(wallet, auth.pubkey().get()).unwrap_or(0);
        if bal == 0 {
            return view! {
                {back}
                <p class="text-xs text-gray-400">{format!("You have no {ticker} yet. Members can send you some, or ask the faucet from your wallet.")}</p>
                <a href=base_href("/wallet") class="mt-2 inline-block text-xs text-amber-400 hover:text-amber-300">"Open wallet →"</a>
            }.into_any();
        }
        view! {
            {back}
            <div class="grid grid-cols-4 gap-1.5">
                {PRESETS.iter().map(|&n| view! {
                    <button
                        class="px-2 py-1.5 rounded-lg bg-gray-700/60 hover:bg-amber-500/20 hover:text-amber-200 text-gray-200 text-xs font-medium transition-colors disabled:opacity-40"
                        disabled=move || sending.get() || bal < n
                        on:click=move |_| send(n)
                    >
                        {n}
                    </button>
                }).collect_view()}
            </div>
            <form
                class="flex gap-1.5 mt-2"
                on:submit=move |ev| {
                    ev.prevent_default();
                    if let Ok(n) = custom.get_untracked().trim().parse::<u64>() {
                        send(n);
                    }
                }
            >
                <input
                    type="number"
                    min="1"
                    inputmode="numeric"
                    placeholder="Other"
                    class="flex-1 min-w-0 bg-gray-800/80 border border-gray-600/60 rounded-lg px-2 py-1 text-xs text-gray-100 focus:outline-none focus:border-amber-500/60"
                    prop:value=move || custom.get()
                    on:input=move |ev| custom.set(event_target_value(&ev))
                    aria-label=format!("Other amount of {ticker}")
                />
                <button
                    type="submit"
                    class="px-3 py-1 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-xs font-semibold disabled:opacity-40"
                    disabled=move || sending.get()
                >
                    {move || match (sending.get(), via_extension) {
                        (true, true) => "Confirm…",
                        (true, false) => "Sending…",
                        _ => "Tip",
                    }}
                </button>
            </form>
            {via_extension.then(|| view! {
                <p class="mt-2 text-[11px] leading-snug text-amber-200/80" role="status">
                    {move || if sending.get() {
                        format!("{} is showing you this tip. Confirm it there.", signer_name.get_value())
                    } else {
                        crate::wallet::extension::review_hint(&signer_name.get_value(), "each tip")
                    }}
                </p>
            })}
            <p class="mt-2 text-[11px] leading-snug text-gray-500">
                {format!("You have {} {ticker} · each tip uses about 200 sats in fees. {ticker} is a test token with no cash value.", grouped(bal))}
            </p>
        }.into_any()
    };

    let popover_class = if open_down {
        "absolute top-full right-0 mt-1 glass-card p-3 rounded-xl shadow-lg z-50 w-64 text-sm"
    } else {
        "absolute bottom-full right-0 mb-1 glass-card p-3 rounded-xl shadow-lg z-50 w-64 text-sm"
    };

    view! {
        <div class="relative inline-flex items-center gap-1">
            // What the post has been tipped, per asset: shown to everyone,
            // own posts included.
            <span class="inline-flex items-center gap-1" title=totals_text aria-label=totals_text>
            {move || {
                totals_by_asset(&totals.get()).into_iter().map(|(i, t)| {
                    let Some(w) = store_at(i) else {
                        return ().into_any();
                    };
                    let ticker = w.ticker();
                    view! {
                        <span
                            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-amber-500/10 border border-amber-500/30 text-amber-300"
                            title=format!("{} {ticker} tipped in {} tip{}", grouped(t.asset), t.count, if t.count == 1 { "" } else { "s" })
                            aria-hidden="true"
                        >
                            {asset_icon(w.profile, "w-3 h-3")}
                            <span class="font-medium">{grouped(t.asset)}</span>
                        </span>
                    }.into_any()
                }).collect_view()
            }}
            </span>

            // The tip button: other members' posts only.
            <Show when=move || !is_own.get()>
                <button
                    class="inline-flex items-center justify-center w-6 h-6 rounded-full text-gray-500 opacity-70 hover:opacity-100 hover:text-amber-400 hover:bg-gray-700/50 focus-visible:opacity-100 focus-visible:text-amber-400 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-400/60 transition-all"
                    on:click=toggle
                    aria-label=move || format!("Tip {}", author_name.get())
                    aria-haspopup="dialog"
                    aria-expanded=move || if open.get() { "true" } else { "false" }
                    title="Tip"
                >
                    {dream_icon("w-3.5 h-3.5")}
                </button>
            </Show>

            <Show when=move || open.get()>
                <div
                    class=popover_class
                    role="dialog"
                    aria-label=move || match chosen.get().and_then(store_at) {
                        Some(w) => format!("Tip in {}", w.ticker()),
                        None => "Tip".to_string(),
                    }
                    on:keydown=move |ev| if ev.key() == "Escape" { open.set(false) }
                >
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-gray-200 font-medium truncate">
                            "Tip " {move || author_name.get()}
                            {move || chosen.get().and_then(store_at).map(|w| format!(" in {}", w.ticker()))}
                        </span>
                        <button class="text-gray-500 hover:text-gray-300 text-xs" on:click=move |_| open.set(false) aria-label="Close">"✕"</button>
                    </div>
                    {move || match chosen.get().and_then(store_at) {
                        None => picker().into_any(),
                        Some(w) => amounts(w),
                    }}
                </div>
            </Show>
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_group_in_threes() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(1_000_000), "1,000,000");
        assert_eq!(grouped(12_500), "12,500");
    }

    /// The picker opens on the wallet's active chain, and on the first row
    /// when the active chain has no asset to tip in.
    #[test]
    fn the_picker_highlights_the_wallets_active_chain() {
        let rows = [chain::CHAIN_ID, chain::TXBT4_CHAIN_ID];
        assert_eq!(default_row(&rows, chain::TXBT4_CHAIN_ID), 1);
        assert_eq!(default_row(&rows, chain::CHAIN_ID), 0);
        // BLAKES7 not yet named: only dreamlab is a row, whatever is active
        assert_eq!(default_row(&rows[..1], chain::TXBT4_CHAIN_ID), 0);
        assert_eq!(default_row(&rows, "sidestr:other"), 0);
    }

    /// Totals are per asset, in the wallet's order, never summed, and an
    /// asset nobody tipped in is left out.
    #[test]
    fn totals_are_shown_per_asset() {
        let t = |asset, count| TipTotal { asset, count };
        let both = [("DREAM", t(12, 2)), ("BLAKES7", t(500, 1))];
        assert_eq!(
            totals_line(&both).as_deref(),
            Some("12 DREAM · 500 BLAKES7")
        );
        assert_eq!(totals_by_asset(&both).len(), 2);
        let one = [("DREAM", t(0, 0)), ("BLAKES7", t(1_500, 3))];
        assert_eq!(totals_line(&one).as_deref(), Some("1,500 BLAKES7"));
        assert_eq!(totals_by_asset(&one), vec![("BLAKES7", t(1_500, 3))]);
        assert_eq!(totals_line(&[("DREAM", t(0, 0))]), None);
        assert_eq!(totals_line(&[]), None);
    }
}
