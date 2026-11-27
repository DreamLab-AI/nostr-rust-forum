//! Multi-Chain Sidestr Wallet (`#/wallet`).
//!
//! Powered by [`nostr_bbs_client_core::wallet`] (`DREAM` on `sidestr:dreamlab`,
//! `BLAKES7` on `sidestr:dreamlab-txbt4`, etc.). Validates every block against
//! compiled-in chain pins, displays balances & incoming change, generates
//! in-WASM receive QR codes, requests starter packs from the chain faucet, and
//! signs/publishes `kind:23500` transfers.

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::wallet::{chain, use_wallets, LoadStatus, PendingKind, SpendPath};

use crate::components::{qr_svg, CopyKeyBtn, EmptyCard};

/// Wallet view (`#/wallet`).
#[component]
pub fn WalletView() -> impl IntoView {
    let auth = use_auth();
    let toast = use_toasts();
    let Some(wallets) = use_wallets() else {
        return view! {
            <div class="bbs-view">
                <div class="bbs-view-head">
                    <h1 class="bbs-view-title">"SIDESTR WALLET"</h1>
                </div>
                <EmptyCard
                    title="WALLET DISABLED"
                    body="This deployment has not enabled Sidestr member wallets (SIDESTR_WALLET)."
                />
            </div>
        }
        .into_any();
    };

    // Ensure the currently selected chain begins loading
    Effect::new(move |_| {
        let store = wallets.current();
        store.ensure_loaded();
    });

    // Send form state
    let send_mode: RwSignal<String> = RwSignal::new("asset".into());
    let send_to: RwSignal<String> = RwSignal::new(String::new());
    let send_amount: RwSignal<String> = RwSignal::new(String::new());
    let sending: RwSignal<bool> = RwSignal::new(false);
    let send_err: RwSignal<Option<String>> = RwSignal::new(None);
    let faucet_busy: RwSignal<bool> = RwSignal::new(false);
    let unlock_input: RwSignal<String> = RwSignal::new(String::new());
    let unlock_err: RwSignal<Option<String>> = RwSignal::new(None);
    let show_qr: RwSignal<bool> = RwSignal::new(false);

    let all_stores = wallets.all();

    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div>
                    <h1 class="bbs-view-title">"SIDESTR WALLET"</h1>
                    <p class="bbs-view-sub">"Self-custodied Nostr key balances validated against pinned chain documents."</p>
                </div>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-sm"
                    on:click=move |_| wallets.current().reload()
                >
                    "↻ SYNC CHAIN"
                </button>
            </div>

            // Chain switcher
            {wallets.several().then(|| view! {
                <div class="bbs-tabs">
                    {all_stores.iter().copied().map(|st| {
                        let cid = st.profile.id;
                        let lbl = st.profile.label.clone();
                        let parent = st.profile.parent_name;
                        view! {
                            <button
                                type="button"
                                class=move || if wallets.selected.get() == cid { "bbs-tab bbs-tab-active" } else { "bbs-tab" }
                                on:click=move |_| wallets.select(cid)
                            >
                                {format!("{lbl} ({parent})")}
                            </button>
                        }
                    }).collect_view()}
                </div>
            })}

            {move || {
                let Some(pk) = auth.pubkey().get() else {
                    return view! {
                        <EmptyCard
                            title="SIGN IN TO OPEN WALLET"
                            body="Your Nostr pubkey is your wallet address on every Sidestr chain. Sign in via Settings to view balances and send transfers."
                        />
                    }.into_any();
                };

                let store = wallets.current();
                let status = store.status.get();
                let snap = store.snapshot();
                let my_script = chain::script_of(&pk);
                let my_addr = chain::address_of(store.pin(), &pk).unwrap_or_default();
                let npub = nostr_bbs_core::encode_npub(&pk).unwrap_or_else(|_| pk.clone());
                let ticker = store.ticker();
                let has_asset = store.has_asset();
                let spend_path = store.spend_path(&auth);
                let held = store.held();
                let balances = snap
                    .as_ref()
                    .zip(my_script.as_ref())
                    .map(|(s, sc)| s.balances(sc, &held))
                    .unwrap_or_default();
                let incoming_asset = my_script
                    .as_ref()
                    .and_then(|sc| store.asset_now_and_incoming(sc))
                    .map(|(_, inc)| inc)
                    .unwrap_or(0);
                let pending_list = store.pending.get();

                let status_badge = match status {
                    LoadStatus::Idle => view! { <span class="bbs-badge">"IDLE"</span> }.into_any(),
                    LoadStatus::Loading => view! { <span class="bbs-badge bbs-badge-warn">"SYNCING..."</span> }.into_any(),
                    LoadStatus::Ready => {
                        let h = snap.as_ref().map(|s| s.height()).unwrap_or(0);
                        view! { <span class="bbs-badge bbs-badge-accent">{format!("HEIGHT #{h}")}</span> }.into_any()
                    }
                    LoadStatus::Failed(e) => view! { <span class="bbs-badge bbs-badge-danger">{format!("SYNC ERR: {e}")}</span> }.into_any(),
                };

                let pk_faucet = pk.clone();
                let pk_unlock = pk.clone();
                let my_script_hex = my_script.as_ref().map(|s| s.to_hex_string()).unwrap_or_default();

                view! {
                    <div class="bbs-stack">
                        // Balance Summary Card
                        <section class="bbs-card bbs-stack">
                            <div class="bbs-card-head">
                                <strong>{format!("{} · {}", store.profile.label, store.profile.id)}</strong>
                                {status_badge}
                            </div>
                            <div class="bbs-stat-grid">
                                {has_asset.then(|| view! {
                                    <div class="bbs-stat-box">
                                        <span class="bbs-label">{ticker}</span>
                                        <span class="bbs-stat-val">{balances.asset.to_string()}</span>
                                        {(incoming_asset > 0).then(|| view! {
                                            <span class="bbs-muted">{format!("+{incoming_asset} change pending")}</span>
                                        })}
                                    </div>
                                })}
                                <div class="bbs-stat-box">
                                    <span class="bbs-label">"FEE SATS"</span>
                                    <span class="bbs-stat-val">{balances.plain.to_string()}</span>
                                    {(balances.carrier_sats > 0).then(|| view! {
                                        <span class="bbs-muted">{format!("+{} on asset carriers", balances.carrier_sats)}</span>
                                    })}
                                </div>
                            </div>
                        </section>

                        // Receive & Faucet Card
                        <section class="bbs-card bbs-stack">
                            <div class="bbs-card-head">
                                <strong>"RECEIVE"</strong>
                                <div class="bbs-row-gap">
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-sm"
                                        on:click=move |_| show_qr.update(|v| *v = !*v)
                                    >
                                        {move || if show_qr.get() { "HIDE QR" } else { "SHOW QR" }}
                                    </button>
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-sm"
                                        disabled=move || faucet_busy.get()
                                        on:click=move |_| {
                                            let pk_f = pk_faucet.clone();
                                            faucet_busy.set(true);
                                            wasm_bindgen_futures::spawn_local(async move {
                                                match store.request_faucet(&pk_f).await {
                                                    Ok(n) => toast.show(format!("Faucet request sent to {n} relay(s). Check back in ~30s."), ToastVariant::Success),
                                                    Err(e) => toast.show(e, ToastVariant::Error),
                                                }
                                                faucet_busy.set(false);
                                            });
                                        }
                                    >
                                        {move || if faucet_busy.get() { "REQUESTING..." } else { "FAUCET" }}
                                    </button>
                                </div>
                            </div>

                            <div class="bbs-kv-list">
                                <div class="bbs-kv-row">
                                    <span class="bbs-label">"NPUB"</span>
                                    <code class="bbs-mono-xs bbs-truncate">{npub.clone()}</code>
                                    <CopyKeyBtn full=npub.clone() label="COPY"/>
                                </div>
                                {(!my_addr.is_empty()).then(|| view! {
                                    <div class="bbs-kv-row">
                                        <span class="bbs-label">"ADDR"</span>
                                        <code class="bbs-mono-xs bbs-truncate">{my_addr.clone()}</code>
                                        <CopyKeyBtn full=my_addr.clone() label="COPY"/>
                                    </div>
                                })}
                            </div>

                            {move || show_qr.get().then(|| {
                                let target = if my_addr.is_empty() { npub.clone() } else { my_addr.clone() };
                                qr_svg(&target).map(|svg| view! {
                                    <div class="bbs-qr-wrap" inner_html=svg></div>
                                })
                            })}
                        </section>

                        // Spend unlock (when signed in with NIP-07 without sidestr extension)
                        {(spend_path == SpendPath::None).then(|| view! {
                            <section class="bbs-card bbs-stack">
                                <strong>"UNLOCK SPENDING (TAB-ONLY)"</strong>
                                <p class="bbs-muted">
                                    "Your browser extension cannot sign Sidestr spends directly. Paste your matching nsec or 64-hex key to hold in memory for this tab only."
                                </p>
                                <div class="bbs-row-wrap">
                                    <input
                                        type="password"
                                        class="bbs-input bbs-flex-1"
                                        placeholder="nsec1... or 64-hex secret"
                                        prop:value=move || unlock_input.get()
                                        on:input=move |ev| unlock_input.set(event_target_value(&ev))
                                    />
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-primary"
                                        on:click=move |_| {
                                            unlock_err.set(None);
                                            let key = unlock_input.get_untracked();
                                            match store.unlock(&key, &pk_unlock) {
                                                Ok(()) => {
                                                    unlock_input.set(String::new());
                                                    toast.show("Wallet unlocked for this tab.", ToastVariant::Success);
                                                }
                                                Err(e) => unlock_err.set(Some(e)),
                                            }
                                        }
                                    >
                                        "UNLOCK"
                                    </button>
                                </div>
                                {move || unlock_err.get().map(|e| view! { <div class="bbs-alert bbs-alert-err">{e}</div> })}
                            </section>
                        })}

                        // Send Form
                        {(spend_path != SpendPath::None).then(|| view! {
                            <section class="bbs-card bbs-stack">
                                <div class="bbs-card-head">
                                    <strong>"SEND TRANSFER"</strong>
                                    {store.unlocked.get().then(|| view! {
                                        <button
                                            type="button"
                                            class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                            on:click=move |_| store.lock()
                                        >
                                            "LOCK TAB KEY"
                                        </button>
                                    })}
                                </div>

                                <div class="bbs-row-wrap">
                                    {has_asset.then(|| view! {
                                        <button
                                            type="button"
                                            class=move || if send_mode.get() == "asset" { "bbs-pill bbs-pill-active" } else { "bbs-pill" }
                                            on:click=move |_| send_mode.set("asset".into())
                                        >
                                            {ticker}
                                        </button>
                                    })}
                                    <button
                                        type="button"
                                        class=move || if send_mode.get() == "sats" || !has_asset { "bbs-pill bbs-pill-active" } else { "bbs-pill" }
                                        on:click=move |_| send_mode.set("sats".into())
                                    >
                                        "SATS"
                                    </button>
                                </div>

                                <label class="bbs-field">
                                    <span class="bbs-label">"RECIPIENT (NPUB, DID:NOSTR, HEX, OR ADDRESS)"</span>
                                    <input
                                        type="text"
                                        class="bbs-input"
                                        placeholder="npub1..."
                                        prop:value=move || send_to.get()
                                        on:input=move |ev| send_to.set(event_target_value(&ev))
                                    />
                                </label>

                                <label class="bbs-field">
                                    <span class="bbs-label">
                                        {move || if has_asset && send_mode.get() == "asset" {
                                            format!("AMOUNT ({ticker})")
                                        } else {
                                            "AMOUNT (SATS)".to_string()
                                        }}
                                    </span>
                                    <input
                                        type="number"
                                        min="1"
                                        class="bbs-input"
                                        placeholder="10"
                                        prop:value=move || send_amount.get()
                                        on:input=move |ev| send_amount.set(event_target_value(&ev))
                                    />
                                </label>

                                {move || send_err.get().map(|e| view! { <div class="bbs-alert bbs-alert-err">{e}</div> })}

                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-primary"
                                    disabled=move || sending.get()
                                    on:click=move |_| {
                                        send_err.set(None);
                                        let dest_text = send_to.get_untracked();
                                        let dest = match chain::destination_script(store.pin(), &dest_text) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                send_err.set(Some(e));
                                                return;
                                            }
                                        };
                                        let amt = match send_amount.get_untracked().trim().parse::<u64>() {
                                            Ok(n) if n > 0 => n,
                                            _ => {
                                                send_err.set(Some("Enter a whole number greater than zero.".into()));
                                                return;
                                            }
                                        };
                                        let is_asset = has_asset && send_mode.get_untracked() == "asset";
                                        sending.set(true);
                                        wasm_bindgen_futures::spawn_local(async move {
                                            let res = if is_asset {
                                                store.send_asset(&auth, dest, amt, None).await
                                            } else {
                                                store.send_sats(&auth, dest, amt).await
                                            };
                                            match res {
                                                Ok(txid) => {
                                                    send_to.set(String::new());
                                                    send_amount.set(String::new());
                                                    toast.show(format!("Sent! txid {}…", &txid[..txid.len().min(12)]), ToastVariant::Success);
                                                }
                                                Err(e) => send_err.set(Some(e)),
                                            }
                                            sending.set(false);
                                        });
                                    }
                                >
                                    {move || if sending.get() { "BROADCASTING..." } else { "SEND TRANSFER" }}
                                </button>
                            </section>
                        })}

                        // Pending transactions
                        {(!pending_list.is_empty()).then(|| view! {
                            <section class="bbs-card bbs-stack">
                                <h3 class="bbs-section-title">"PENDING (UNMINED)"</h3>
                                <ul class="bbs-list">
                                    {pending_list.into_iter().map(|p| {
                                        let kind_lbl = match p.kind {
                                            PendingKind::Asset => ticker,
                                            PendingKind::Tip => "TIP",
                                            PendingKind::Sats => "SATS",
                                            PendingKind::Provision => "PROVISION",
                                            PendingKind::Hand => "POKER",
                                        };
                                        let amt_txt = if p.asset > 0 {
                                            format!("-{} {ticker}", p.asset)
                                        } else {
                                            format!("-{} sats", p.sats)
                                        };
                                        view! {
                                            <li class="bbs-list-row">
                                                <span class="bbs-badge bbs-badge-warn">{kind_lbl}</span>
                                                <code class="bbs-mono-xs bbs-flex-1">{format!("tx {}…", &p.txid[..p.txid.len().min(14)])}</code>
                                                <span class="bbs-neg">{amt_txt}</span>
                                            </li>
                                        }
                                    }).collect_view()}
                                </ul>
                            </section>
                        })}

                        // Confirmed history
                        {snap.map(|s| {
                            let hist: Vec<_> = s.history(&my_script_hex).into_iter().take(25).cloned().collect();
                            view! {
                                <section class="bbs-card bbs-stack">
                                    <h3 class="bbs-section-title">"CONFIRMED ACTIVITY"</h3>
                                    {if hist.is_empty() {
                                        view! { <p class="bbs-muted">"No confirmed transactions on this chain yet."</p> }.into_any()
                                    } else {
                                        view! {
                                            <ul class="bbs-list">
                                                {hist.into_iter().map(|tx| {
                                                    let mv = tx.movement(&my_script_hex);
                                                    let tag = if tx.hand_root.is_some() {
                                                        "POKER"
                                                    } else if tx.tip_event.is_some() {
                                                        "TIP"
                                                    } else if tx.coinbase {
                                                        "MINT"
                                                    } else if mv.asset != 0 {
                                                        ticker
                                                    } else {
                                                        "SATS"
                                                    };
                                                    let delta = if mv.asset != 0 {
                                                        format!("{:+} {ticker}", mv.asset)
                                                    } else {
                                                        format!("{:+} sats", mv.sats)
                                                    };
                                                    let cls = if mv.asset > 0 || (mv.asset == 0 && mv.sats > 0) {
                                                        "bbs-pos"
                                                    } else {
                                                        "bbs-neg"
                                                    };
                                                    view! {
                                                        <li class="bbs-list-row">
                                                            <span class="bbs-badge">{tag}</span>
                                                            <span class="bbs-muted">{format!("#{}", tx.height)}</span>
                                                            <code class="bbs-mono-xs bbs-flex-1">{format!("{}…", &tx.txid[..tx.txid.len().min(12)])}</code>
                                                            <span class=cls>{delta}</span>
                                                        </li>
                                                    }
                                                }).collect_view()}
                                            </ul>
                                        }.into_any()
                                    }}
                                </section>
                            }
                        })}
                    </div>
                }.into_any()
            }}
        </div>
    }
    .into_any()
}
