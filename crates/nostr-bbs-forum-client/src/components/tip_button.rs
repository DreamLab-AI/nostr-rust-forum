//! DREAM tips on a post (ADR-2015): a chip showing what a post has been
//! tipped, and, on other members' posts, a tip button with a small popover.
//!
//! Rendered inside the reaction row, so every surface that shows reactions
//! (channel messages, forum threads, replies) offers tips too. It renders
//! nothing when the deployment has not switched the wallet on. The chain
//! loads lazily on first render and is shared across every post, so a page
//! of fifty posts downloads and validates it once.
//!
//! A tip is an ordinary DREAM transfer to the author's npub carrying a
//! `tip:nostr:<event id>` record: the chain, not the forum, is where tips
//! live, so a total is the same for everyone who replays it.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_memo;
use crate::wallet::{chain, use_wallet, LoadStatus, SpendPath};

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

/// The DREAM mark: a four-point spark.
pub(crate) fn dream_icon(class: &'static str) -> impl IntoView {
    view! {
        <svg class=class viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" focusable="false">
            <path d="M10 1.5c.4 3.9 1.9 6.9 5.2 7.9.7.2.7 1.2 0 1.4-3.3 1-4.8 4-5.2 7.9-.4-3.9-1.9-6.9-5.2-7.9-.7-.2-.7-1.2 0-1.4C8.1 8.4 9.6 5.4 10 1.5z"/>
        </svg>
    }
}

/// The tip chip and button for one post.
#[component]
pub(crate) fn TipControl(
    /// The post's event id.
    #[prop(into)]
    event_id: String,
    /// The post's author (who the tip pays).
    #[prop(into)]
    author_pubkey: String,
) -> impl IntoView {
    let Some(wallet) = use_wallet() else {
        return ().into_any();
    };
    let author_ok = chain::script_of(&author_pubkey).is_some();
    if !author_ok {
        return ().into_any();
    }
    wallet.ensure_loaded();
    let auth = use_auth();
    let toasts = use_toasts();
    let eid = StoredValue::new(event_id.to_ascii_lowercase());
    let author = StoredValue::new(author_pubkey.to_ascii_lowercase());
    let author_name = use_display_name_memo(author_pubkey.clone());
    let open = RwSignal::new(false);
    let custom = RwSignal::new(String::new());
    let sending = RwSignal::new(false);
    let signer_name = StoredValue::new(crate::wallet::extension::name());

    let is_own = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .is_some_and(|me| me.eq_ignore_ascii_case(&author.get_value()))
    });
    let total = Memo::new(move |_| wallet.tip_total(&eid.get_value()));
    let my_dream = Memo::new(move |_| {
        let me = auth.pubkey().get()?;
        let snap = wallet.snapshot()?;
        let script = chain::script_of(&me)?;
        let held: Vec<bitcoin::OutPoint> = wallet
            .pending
            .get()
            .iter()
            .flat_map(|p| p.spent.iter().filter_map(|s| s.parse().ok()))
            .collect();
        Some(snap.balances(&script, &held))
    });

    let send = move |amount: u64| {
        if amount == 0 || sending.get_untracked() {
            return;
        }
        let Some(to) = chain::script_of(&author.get_value()) else {
            return;
        };
        sending.set(true);
        let event = eid.get_value();
        spawn_local(async move {
            match wallet.send_dream(&auth, to, amount, Some(event)).await {
                Ok(_) => {
                    open.set(false);
                    custom.set(String::new());
                    toasts.show(
                        format!(
                            "Tipped {} {} to {}. It confirms in a minute or two.",
                            grouped(amount),
                            chain::DREAM,
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

    view! {
        <div class="relative inline-flex items-center gap-1">
            // What the post has been tipped: shown to everyone, own posts included.
            <Show when=move || { total.get().dream > 0 }>
                <span
                    class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-amber-500/10 border border-amber-500/30 text-amber-300"
                    title=move || {
                        let t = total.get();
                        format!(
                            "{} {} tipped in {} tip{}",
                            grouped(t.dream),
                            chain::DREAM,
                            t.count,
                            if t.count == 1 { "" } else { "s" }
                        )
                    }
                >
                    {dream_icon("w-3 h-3")}
                    <span class="font-medium">{move || grouped(total.get().dream)}</span>
                </span>
            </Show>

            // The tip button: other members' posts only.
            <Show when=move || !is_own.get()>
                <button
                    class="inline-flex items-center justify-center w-6 h-6 rounded-full text-gray-500 opacity-70 hover:opacity-100 hover:text-amber-400 hover:bg-gray-700/50 focus-visible:opacity-100 focus-visible:text-amber-400 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-400/60 transition-all"
                    on:click=move |_| open.update(|v| *v = !*v)
                    aria-label=move || format!("Tip {} in DREAM", author_name.get())
                    aria-haspopup="dialog"
                    aria-expanded=move || if open.get() { "true" } else { "false" }
                    title="Tip in DREAM"
                >
                    {dream_icon("w-3.5 h-3.5")}
                </button>
            </Show>

            <Show when=move || open.get()>
                <div
                    class="absolute bottom-full left-0 mb-1 glass-card p-3 rounded-xl shadow-lg z-50 w-64 text-sm"
                    role="dialog"
                    aria-label="Tip in DREAM"
                    on:keydown=move |ev| if ev.key() == "Escape" { open.set(false) }
                >
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-gray-200 font-medium truncate">
                            "Tip " {move || author_name.get()}
                        </span>
                        <button class="text-gray-500 hover:text-gray-300 text-xs" on:click=move |_| open.set(false) aria-label="Close">"✕"</button>
                    </div>
                    {move || {
                        let status = wallet.status.get();
                        let loaded = wallet.snapshot().is_some();
                        if !loaded {
                            return match status {
                                LoadStatus::Failed(e) => view! {
                                    <p class="text-xs text-red-300">"The DreamLab chain could not be read: " {e}</p>
                                    <button class="mt-2 text-xs text-amber-400 hover:text-amber-300" on:click=move |_| wallet.reload()>"Try again"</button>
                                }.into_any(),
                                _ => view! { <p class="text-xs text-gray-400">"Checking your wallet…"</p> }.into_any(),
                            };
                        }
                        if !wallet.can_spend(&auth) {
                            return view! {
                                <p class="text-xs text-gray-400">
                                    "Your key lives in your browser extension, which can't sign DreamLab transfers. Podkey can, and asks you to confirm each one; or unlock your wallet for this tab to tip."
                                </p>
                                <a href=base_href("/wallet") class="mt-2 inline-block text-xs text-amber-400 hover:text-amber-300">"Open wallet →"</a>
                            }.into_any();
                        }
                        let via_extension = wallet.spend_path(&auth) == SpendPath::Extension;
                        let bal = my_dream.get().unwrap_or_default();
                        if bal.dream == 0 {
                            return view! {
                                <p class="text-xs text-gray-400">"You have no DREAM yet. Members can send you some, or ask the faucet from your wallet."</p>
                                <a href=base_href("/wallet") class="mt-2 inline-block text-xs text-amber-400 hover:text-amber-300">"Open wallet →"</a>
                            }.into_any();
                        }
                        view! {
                            <div class="grid grid-cols-4 gap-1.5">
                                {PRESETS.iter().map(|&n| view! {
                                    <button
                                        class="px-2 py-1.5 rounded-lg bg-gray-700/60 hover:bg-amber-500/20 hover:text-amber-200 text-gray-200 text-xs font-medium transition-colors disabled:opacity-40"
                                        disabled=move || sending.get() || bal.dream < n
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
                                    aria-label="Other amount of DREAM"
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
                                "You have " {grouped(bal.dream)} " DREAM · each tip uses about 200 sats in fees. DREAM is a test token with no cash value."
                            </p>
                        }.into_any()
                    }}
                </div>
            </Show>
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::grouped;

    #[test]
    fn digits_group_in_threes() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(1_000_000), "1,000,000");
        assert_eq!(grouped(12_500), "12,500");
    }
}
