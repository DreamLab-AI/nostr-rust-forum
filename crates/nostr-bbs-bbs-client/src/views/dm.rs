//! Encrypted Direct Messages (NIP-59 Gift Wrap / NIP-17 / NIP-04 read).
//!
//! Backed directly by `nostr_bbs_client_core::dm::DMStore` — full parity with
//! `forum-client` including delivery reports, reactions, sender deletions,
//! foreign-relay consent prompts, and per-account read marks.

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::dm::{use_dm_store, Delivery};
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::{format_relative_time, is_hex_pubkey};
use nostr_bbs_core::decode_npub;

use crate::components::{AuthorChip, EmptyCard, MarkdownBody};
use crate::router::{use_router, Route};

fn parse_peer_input(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if is_hex_pubkey(trimmed) {
        Some(trimmed.to_ascii_lowercase())
    } else if trimmed.starts_with("npub1") {
        decode_npub(trimmed).ok()
    } else {
        None
    }
}

/// DM inbox view (`#/dm`).
#[component]
pub fn DmListView() -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    let dm = use_dm_store();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();

    let new_peer = RwSignal::new(String::new());

    // Ensure DM subscriptions are active once signed in.
    Effect::new(move |_| {
        if let (Some(pk), Some(signer)) = (auth.pubkey().get(), auth.get_signer()) {
            dm.fetch_conversations(&relay, signer.clone(), &pk);
            dm.subscribe_incoming(&relay, signer, &pk);
        }
    });

    let open_new = move || {
        let raw = new_peer.get_untracked();
        match parse_peer_input(&raw) {
            Some(pk) => {
                new_peer.set(String::new());
                router.go(Route::DmChat { pubkey: pk });
            }
            None => toasts.show(
                "Enter a valid npub1… or 64-char hex pubkey",
                ToastVariant::Error,
            ),
        }
    };

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"✉ Direct Messages"</h1>
                    <p class="tui-page-sub">
                        "NIP-44 encrypted, NIP-59 gift-wrapped private conversations."
                    </p>
                </div>
            </div>

            {move || if !auth.is_authenticated().get() {
                view! {
                    <div class="tui-card tui-stack">
                        <p class="tui-muted">"Sign in to read and send encrypted direct messages."</p>
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            on:click=move |_| router.go(Route::Settings)
                        >"Sign in"</button>
                    </div>
                }.into_any()
            } else {
                view! {
                    <div class="tui-card tui-row">
                        <input
                            class="bbs-input"
                            style="flex:1 1 220px"
                            type="text"
                            placeholder="Start DM with npub1… or 64-char hex pubkey"
                            prop:value=move || new_peer.get()
                            on:input=move |ev| new_peer.set(event_target_value(&ev))
                            on:keydown=move |ev| {
                                if ev.key() == "Enter" {
                                    ev.prevent_default();
                                    open_new();
                                }
                            }
                        />
                        <button type="button" class="bbs-btn bbs-btn-primary" on:click=move |_| open_new()>
                            "Open Chat ▶"
                        </button>
                    </div>

                    {move || {
                        let convos = dm.conversations().get();
                        if convos.is_empty() {
                            return view! {
                                <EmptyCard
                                    title="No conversations yet"
                                    body="Paste a member's npub above or tap 'Message' on any member profile."
                                />
                            }.into_any();
                        }
                        view! {
                            <div class="tui-stack">
                                {convos.into_iter().map(|c| {
                                    let pk = c.pubkey.clone();
                                    let pk_go = pk.clone();
                                    view! {
                                        <div
                                            class="tui-card tui-card-interactive tui-stack"
                                            role="button"
                                            tabindex="0"
                                            on:click=move |_| router.go(Route::DmChat { pubkey: pk_go.clone() })
                                        >
                                            <div class="tui-row-between">
                                                <AuthorChip pubkey=pk />
                                                <div class="tui-row">
                                                    {(c.unread_count > 0).then(|| view! {
                                                        <span class="bbs-badge bbs-badge-accent">{c.unread_count}</span>
                                                    })}
                                                    <span class="tui-muted" style="font-size:0.78rem">
                                                        {format_relative_time(c.last_timestamp)}
                                                    </span>
                                                </div>
                                            </div>
                                            <div class="tui-muted" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                                                {c.last_message}
                                            </div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }}
                }.into_any()
            }}
        </div>
    }
}

/// 1:1 Encrypted DM conversation view (`#/dm/<pubkey>`).
#[component]
pub fn DmChatView(pubkey: String) -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    let dm = use_dm_store();
    let relay = expect_context::<RelayConnection>();
    let toasts = use_toasts();

    let draft = RwSignal::new(String::new());
    let sending = RwSignal::new(false);

    let pk_load = pubkey.clone();
    let relay_load = relay.clone();
    Effect::new(move |_| {
        dm.select_conversation(&pk_load);
        if let (Some(me), Some(signer)) = (auth.pubkey().get(), auth.get_signer()) {
            dm.load_conversation_messages(&relay_load, signer, &me, &pk_load);
        }
    });

    let pk_send = pubkey.clone();
    let relay_send = relay.clone();
    let send = move || {
        let body = draft.get_untracked().trim().to_string();
        if body.is_empty() || sending.get_untracked() {
            return;
        }
        let (Some(me), Some(signer)) = (auth.pubkey().get_untracked(), auth.get_signer()) else {
            toasts.show("Sign in first", ToastVariant::Warning);
            return;
        };
        draft.set(String::new());
        sending.set(true);
        if let Err(e) = dm.send_message(&relay_send, &pk_send, &body, signer, &me) {
            toasts.show(e, ToastVariant::Error);
        }
        sending.set(false);
    };

    let pk_head = pubkey.clone();
    let pk_msgs = pubkey.clone();
    let send_click = send.clone();
    let send_key = send;

    view! {
        <div class="tui-container">
            <div class="tui-crumb">
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                    on:click=move |_| router.go(Route::DmList)
                >"← Inbox"</button>
                <span>"/"</span>
                <AuthorChip pubkey=pk_head />
                <span class="bbs-badge bbs-badge-ok">"🔒 NIP-59"</span>
            </div>

            // Foreign-relay consent prompt (ADR-2027)
            {move || dm.pending_consent().get().map(|req| view! {
                <div class="tui-card tui-card-accent tui-stack">
                    <strong>"Connect to recipient's external relays?"</strong>
                    <p class="tui-muted">
                        {format!("This member advertises {} external DM relay(s).", req.hosts.len())}
                    </p>
                    <div class="tui-row">
                        <button type="button" class="bbs-btn bbs-btn-primary bbs-btn-sm" on:click=move |_| dm.answer_consent(true)>
                            "Allow"
                        </button>
                        <button type="button" class="bbs-btn bbs-btn-sm" on:click=move |_| dm.answer_consent(false)>
                            "Decline"
                        </button>
                    </div>
                </div>
            })}

            {move || dm.error().get().map(|err| view! {
                <div class="tui-card tui-row-between">
                    <span style="color:var(--danger)">{err}</span>
                    <button type="button" class="bbs-btn bbs-btn-ghost bbs-btn-sm" on:click=move |_| dm.clear_error()>"×"</button>
                </div>
            })}

            {move || {
                let all = dm.messages().get();
                let extras = dm.extras().get();
                let list: Vec<_> = all
                    .into_iter()
                    .filter(|m| m.sender_pubkey == pk_msgs || m.recipient_pubkey == pk_msgs)
                    .collect();

                if list.is_empty() {
                    return view! {
                        <EmptyCard
                            title="Encrypted channel ready"
                            body="Messages are NIP-44 sealed and NIP-59 gift-wrapped before leaving your browser."
                        />
                    }.into_any();
                }

                view! {
                    <div class="bbs-dm-bubbles">
                        {list.into_iter().map(|m| {
                            let id = m.id.clone();
                            let deliv = extras.deliveries.get(&id).map(|d| d.outcome);
                            let reacts = extras.reactions.get(&id).cloned().unwrap_or_default();
                            let is_sent = m.is_sent;
                            let id_react = id.clone();
                            let id_del = id.clone();
                            let peer_act = pk_msgs.clone();
                            let peer_del = pk_msgs.clone();
                            let relay_r = relay.clone();
                            let relay_d = relay.clone();

                            view! {
                                <div class="bbs-dm-bubble" class:mine=is_sent>
                                    <MarkdownBody content=m.content />
                                    <div class="tui-row-between" style="margin-top:0.3rem;font-size:0.74rem">
                                        <span class="tui-muted">
                                            {format_relative_time(m.timestamp)}
                                            {deliv.map(|o| match o {
                                                Delivery::Sent => " · ✓",
                                                Delivery::Partial => " · ◐ partial",
                                                Delivery::Failed => " · ✗ failed",
                                            }).unwrap_or("")}
                                        </span>
                                        <div class="tui-row">
                                            {reacts.into_iter().map(|r| view! {
                                                <span class="bbs-react-pill">{r.emoji}</span>
                                            }).collect_view()}
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                                title="Thumbs up"
                                                on:click=move |_| {
                                                    if let Some(signer) = auth.get_signer() {
                                                        let _ = dm.send_reaction(&relay_r, &peer_act, &id_react, "👍", signer);
                                                    }
                                                }
                                            >"👍"</button>
                                            {is_sent.then(|| view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                                                    title="Delete for both"
                                                    on:click=move |_| {
                                                        if let Some(signer) = auth.get_signer() {
                                                            let _ = dm.send_deletion(&relay_d, &peer_del, std::slice::from_ref(&id_del), signer);
                                                        }
                                                    }
                                                >"×"</button>
                                            })}
                                        </div>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}

            <div class="bbs-composer">
                <div class="tui-row">
                    <input
                        class="bbs-input"
                        style="flex:1 1 200px"
                        type="text"
                        placeholder="Write an encrypted message…"
                        prop:value=move || draft.get()
                        on:input=move |ev| draft.set(event_target_value(&ev))
                        on:keydown=move |ev| {
                            if ev.key() == "Enter" && !ev.shift_key() {
                                ev.prevent_default();
                                send_key();
                            }
                        }
                    />
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        disabled=move || draft.get().trim().is_empty()
                        on:click=move |_| send_click()
                    >"Send 🔒"</button>
                </div>
            </div>
        </div>
    }
}
