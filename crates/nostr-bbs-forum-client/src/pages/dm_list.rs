//! DM conversation list page.
//!
//! Route: `/dm`
//! Auth-gated. On mount, fetches conversations from the relay, displays them
//! sorted by most recent, and provides a "New Message" input for starting
//! conversations.
//!
//! Starting a DM no longer requires pasting a raw 64-char hex key (issue #25).
//! The "New Message" box is a name search: it reuses the same mention engine as
//! the post composer (`components::mention_autocomplete`) to turn a typed
//! display name / `@handle` into the recipient's key. Pasting a raw hex key (or
//! an `npub`) still works as a power-user fallback.

use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::info_term::InfoTerm;
use crate::components::mention_autocomplete::{
    local_candidates, merge_candidates, search_profiles, MentionAutocomplete, MentionCandidate,
    NETWORK_SEARCH_MIN_LEN,
};
use crate::dm::{provide_dm_store, use_dm_store, DMConversation};
use crate::relay::{ConnectionState, RelayConnection};
use crate::utils::{format_relative_time, pubkey_color};

/// Max candidates surfaced in the new-DM name search dropdown.
const DM_SEARCH_LIMIT: usize = 8;

/// Resolve a raw typed key to a canonical 64-char lowercase hex pubkey, or
/// `None` if it is not a recognisable key. Accepts bare hex and bech32 `npub`.
fn resolve_raw_key(input: &str) -> Option<String> {
    let s = input.trim();
    // bech32 npub -> hex
    if s.starts_with("npub1") {
        return nostr_bbs_core::decode_npub(s).ok();
    }
    let lower = s.to_lowercase();
    if lower.len() == 64 && hex::decode(&lower).is_ok() {
        return Some(lower);
    }
    None
}

/// DM conversation list page component.
#[component]
pub fn DmListPage() -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let relay_authed = relay.authenticated();

    // Provide DM store for this subtree
    provide_dm_store();
    let dm_store = use_dm_store();

    // New conversation input. The field is a name search (issue #25): you type
    // a display name / @handle and pick a person; a pasted raw hex key or npub
    // still resolves directly as a power-user fallback.
    let new_pubkey_input = RwSignal::new(String::new());
    let show_new_dm = RwSignal::new(false);
    let new_dm_error: RwSignal<Option<String>> = RwSignal::new(None);

    // Name-search dropdown state, driven by the shared mention engine.
    let search_open = RwSignal::new(false);
    let search_query = RwSignal::new(String::new());
    let search_candidates: RwSignal<Vec<MentionCandidate>> = RwSignal::new(Vec::new());
    let search_active_idx = RwSignal::new(0usize);
    // Monotonic sequence to discard stale async search responses.
    let search_seq = RwSignal::new(0u64);

    // Track whether we've already started fetching
    let fetch_started = RwSignal::new(false);

    // Fetch conversations only once the relay session is NIP-42 AUTHenticated.
    //
    // kind-1059 gift-wrap REQs are AUTH-gated server-side. Firing them on bare
    // `Connected` raced the AUTH handshake — fine for fast local-key signing,
    // but a NIP-07 extension signs the AUTH challenge through `window.nostr`
    // (often with a user prompt), so the REQ landed pre-AUTH, was answered with
    // `auth-required: must authenticate to receive kind-1059 DMs`, and dropped
    // without an EOSE. The recipient then saw no DMs. Gating on `authenticated`
    // (flipped true after the AUTH response is sent + subscriptions replayed)
    // makes delivery deterministic for both signer backends; the time-based
    // re-subscribe in the DM store remains as a belt-and-braces self-heal.
    let relay_for_fetch = relay.clone();
    Effect::new(move |_| {
        let connected = conn_state.get() == ConnectionState::Connected;
        let authed = relay_authed.get();
        if !connected || !authed {
            return;
        }
        if fetch_started.get_untracked() {
            return;
        }

        let signer = auth.get_signer();
        let pubkey = auth.pubkey().get_untracked();

        if let (Some(s), Some(pk)) = (signer, pubkey) {
            fetch_started.set(true);
            dm_store.fetch_conversations(&relay_for_fetch, s.clone(), &pk);
            dm_store.subscribe_incoming(&relay_for_fetch, s, &pk);
        }
    });

    // Cleanup on unmount
    let relay_for_cleanup = relay;
    on_cleanup(move || {
        dm_store.cleanup(&relay_for_cleanup);
    });

    // Open the chat with a resolved hex pubkey, after the self-DM guard.
    let open_chat_with = move |pk: String| -> bool {
        let pk = pk.trim().to_lowercase();
        if pk.len() != 64 || hex::decode(&pk).is_err() {
            new_dm_error.set(Some("Couldn't resolve that to a person.".to_string()));
            return false;
        }
        let my_pk = auth.pubkey().get_untracked().unwrap_or_default();
        if pk == my_pk {
            new_dm_error.set(Some("You cannot send a message to yourself.".to_string()));
            return false;
        }
        new_dm_error.set(None);
        new_pubkey_input.set(String::new());
        search_open.set(false);
        search_candidates.set(Vec::new());
        show_new_dm.set(false);
        if let Some(window) = web_sys::window() {
            let _ = window
                .location()
                .set_href(&base_href(&format!("/dm/{}", pk)));
        }
        true
    };

    // Picking a person from the dropdown opens the chat with their key.
    let select_candidate = Callback::new(move |c: MentionCandidate| {
        open_chat_with(c.pubkey);
    });

    // "Start" / Enter: resolve whatever is typed. Priority:
    //   1. the highlighted dropdown candidate (a name was searched);
    //   2. a raw hex key or `npub` pasted as a fallback;
    //   3. otherwise prompt the user to pick a name.
    let on_start_conversation = move |_| {
        let raw = new_pubkey_input.get_untracked();
        let raw = raw.trim().to_string();
        if raw.is_empty() {
            new_dm_error.set(Some("Type a name to find someone to message.".to_string()));
            return;
        }
        // 1. highlighted candidate, if the dropdown has matches.
        let cands = search_candidates.get_untracked();
        if !cands.is_empty() {
            let idx = search_active_idx.get_untracked().min(cands.len() - 1);
            open_chat_with(cands[idx].pubkey.clone());
            return;
        }
        // 2. raw hex / npub fallback.
        if let Some(hex_pk) = resolve_raw_key(&raw) {
            open_chat_with(hex_pk);
            return;
        }
        new_dm_error.set(Some(
            "No match. Pick a name from the list, or paste their key.".to_string(),
        ));
    };

    // Recompute the dropdown as the user types. Mirrors the composer: show
    // local (ProfileCache + seed) candidates instantly, then merge in a
    // debounced relay search for queries above the network threshold.
    let run_search = move |query: String| {
        search_query.set(query.clone());
        search_active_idx.set(0);

        // A raw key/npub paste isn't a name search — hide the dropdown so the
        // fallback path takes over on Start/Enter.
        if resolve_raw_key(&query).is_some() {
            search_open.set(false);
            search_candidates.set(Vec::new());
            return;
        }

        if query.is_empty() {
            search_open.set(false);
            search_candidates.set(Vec::new());
            return;
        }

        search_open.set(true);
        let local = local_candidates(&query, DM_SEARCH_LIMIT);
        search_candidates.set(local.clone());

        if query.len() < NETWORK_SEARCH_MIN_LEN {
            return;
        }
        let seq_now = search_seq.get_untracked().wrapping_add(1);
        search_seq.set(seq_now);
        wasm_bindgen_futures::spawn_local(async move {
            let network = search_profiles(&query, DM_SEARCH_LIMIT).await;
            if search_seq.get_untracked() == seq_now {
                let merged = merge_candidates(network, local, DM_SEARCH_LIMIT);
                search_candidates.set(merged);
                search_active_idx.set(0);
            }
        });
    };

    let on_new_pubkey_input = move |ev: leptos::ev::Event| {
        let target = ev.target().unwrap();
        let input: web_sys::HtmlInputElement = target.unchecked_into();
        let val = input.value();
        new_pubkey_input.set(val.clone());
        new_dm_error.set(None);
        run_search(val.trim().to_string());
    };

    let on_new_pubkey_keydown = {
        let on_start = on_start_conversation;
        move |ev: leptos::ev::KeyboardEvent| {
            let cand_len = search_candidates.get_untracked().len();
            match ev.key().as_str() {
                "ArrowDown" if cand_len > 0 => {
                    ev.prevent_default();
                    search_active_idx.update(|i| *i = (*i + 1).min(cand_len - 1));
                }
                "ArrowUp" if cand_len > 0 => {
                    ev.prevent_default();
                    search_active_idx.update(|i| *i = i.saturating_sub(1));
                }
                "Escape" => {
                    search_open.set(false);
                }
                "Enter" => {
                    ev.prevent_default();
                    on_start(());
                }
                _ => {}
            }
        }
    };

    let conversations = dm_store.conversations();
    let is_loading = dm_store.is_loading();
    let error = dm_store.error();

    view! {
        <div class="max-w-2xl mx-auto p-4 sm:p-6">
            // Header
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h1 class="text-3xl font-bold text-white mb-1 flex items-center gap-2">
                        {shield_icon()}
                        "Direct Messages"
                    </h1>
                    <p class="text-gray-400 text-sm">"Private, encrypted conversations"</p>
                    <div class="text-xs text-green-400/60 flex items-center gap-1 mt-1">
                        {lock_icon_small()}
                        "Encrypted ("
                        <InfoTerm
                            term="NIP-44"
                            explainer="The encryption standard that scrambles your messages so only you and the recipient can read them — not even the server."
                            slug="nip44"
                        />
                        ")"
                    </div>
                </div>
                <button
                    class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm flex items-center gap-1.5"
                    on:click=move |_| {
                        show_new_dm.update(|v| *v = !*v);
                        new_dm_error.set(None);
                    }
                >
                    {move || if show_new_dm.get() {
                        view! { <>{x_icon_small()}" Cancel"</> }.into_any()
                    } else {
                        view! { <>{plus_icon()}" New Message"</> }.into_any()
                    }}
                </button>
            </div>

            // New DM input — search by name, with raw-key paste as a fallback.
            <Show when=move || show_new_dm.get()>
                <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 mb-4">
                    <label class="block text-sm text-gray-300 mb-1">"Message someone"</label>
                    <p class="text-xs text-gray-500 mb-2">
                        "Start typing a name to find them."
                    </p>
                    <div class="flex gap-2">
                        // Wrapper is the positioning context for the dropdown
                        // (MentionAutocomplete renders an absolute panel).
                        <div class="relative flex-1">
                            <input
                                type="text"
                                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-amber-500 transition-colors text-sm"
                                placeholder="Search by name, or paste a key…"
                                autocomplete="off"
                                aria-label="Find someone to message by name"
                                prop:value=move || new_pubkey_input.get()
                                on:input=on_new_pubkey_input
                                on:keydown=on_new_pubkey_keydown
                                on:focus=move |_| {
                                    if !search_candidates.get_untracked().is_empty() {
                                        search_open.set(true);
                                    }
                                }
                            />
                            // MentionAutocomplete anchors its panel with
                            // `bottom-full` (opens upward) — correct in the
                            // composer at the foot of the screen, wrong here at
                            // the top of the page. Flip it to open downward with
                            // a scoped override of the child panel, without
                            // modifying the shared component.
                            <style>
                                ".dm-search-anchor > div { top: 100%; bottom: auto; margin-top: 0.25rem; margin-bottom: 0; }"
                            </style>
                            <div class="dm-search-anchor">
                                <MentionAutocomplete
                                    open=search_open
                                    query=search_query
                                    candidates=search_candidates
                                    active_idx=search_active_idx
                                    on_select=select_candidate
                                />
                            </div>
                        </div>
                        <button
                            class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:text-gray-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm"
                            on:click=move |_| on_start_conversation(())
                            disabled=move || new_pubkey_input.get().trim().is_empty()
                        >
                            "Start"
                        </button>
                    </div>
                    {move || {
                        new_dm_error.get().map(|msg| view! {
                            <p class="text-red-400 text-sm mt-2">{msg}</p>
                        })
                    }}
                    <p class="text-[11px] text-gray-500 mt-2 leading-snug">
                        "Know their key already? Paste their "
                        <InfoTerm
                            term="npub"
                            explainer="A person's public username code (starts with \"npub\"). Safe to share — it's how others find you."
                            slug="npub"
                            below=true
                        />
                        " or 64-character key instead."
                    </p>
                </div>
            </Show>

            // Connection banner
            {move || {
                let state = conn_state.get();
                match state {
                    ConnectionState::Reconnecting => Some(view! {
                        <div class="bg-yellow-900/50 border border-yellow-700 rounded-lg px-4 py-3 mb-4 flex items-center gap-2">
                            <span class="animate-pulse w-2 h-2 rounded-full bg-yellow-400"></span>
                            <span class="text-yellow-200 text-sm">"Reconnecting to relay..."</span>
                        </div>
                    }.into_any()),
                    ConnectionState::Error => Some(view! {
                        <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 mb-4">
                            <span class="text-red-200 text-sm">"Connection error. Retrying..."</span>
                        </div>
                    }.into_any()),
                    ConnectionState::Disconnected => Some(view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 mb-4">
                            <span class="text-gray-300 text-sm">"Disconnected from relay."</span>
                        </div>
                    }.into_any()),
                    _ => None,
                }
            }}

            // Error from DM store
            {move || {
                error.get().map(|msg| view! {
                    <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 mb-4 flex items-center justify-between">
                        <span class="text-red-200 text-sm">{msg}</span>
                        <button
                            class="text-red-400 hover:text-red-200 text-xs ml-4"
                            on:click=move |_| dm_store.clear_error()
                        >
                            "dismiss"
                        </button>
                    </div>
                })
            }}

            // Conversation list
            {move || {
                if is_loading.get() {
                    view! {
                        <div class="space-y-3">
                            <ConversationSkeleton/>
                            <ConversationSkeleton/>
                            <ConversationSkeleton/>
                        </div>
                    }.into_any()
                } else {
                    let convos = conversations.get();
                    if convos.is_empty() {
                        let empty_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                            <svg class="w-7 h-7 text-amber-400/60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" stroke-linecap="round" stroke-linejoin="round"/>
                                <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        }.into_any());
                        view! {
                            <crate::components::empty_state::EmptyState
                                icon=empty_icon
                                title="No conversations yet".to_string()
                                description="Start a new encrypted conversation by clicking \"New Message\" above.".to_string()
                            />
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-2">
                                {convos.into_iter().map(|convo| {
                                    view! { <ConversationRow convo=convo/> }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }
            }}
        </div>
    }
}

/// A single conversation row in the DM list.
#[component]
fn ConversationRow(convo: DMConversation) -> impl IntoView {
    let href = base_href(&format!("/dm/{}", convo.pubkey));
    let has_unread = convo.unread_count > 0;
    let unread_count = convo.unread_count;
    let time_display = format_relative_time(convo.last_timestamp);
    // Avatar glyph: first two hex chars, uppercased. This is a deterministic
    // identicon initial, not a displayed identity label.
    let avatar_text = if convo.pubkey.len() >= 2 {
        convo.pubkey[..2].to_uppercase()
    } else {
        "??".to_string()
    };
    let avatar_bg = pubkey_color(&convo.pubkey);
    // Keep the raw shortened npub as the secondary identity fingerprint
    // beneath the resolved nickname — intentional technical context.
    let short_pk = crate::utils::shorten_pubkey(&convo.pubkey);
    // Resolve the display name reactively through the shared profile cache
    // (display_name > name > NIP-05 > shortened pubkey). Falls back to any
    // pre-populated `convo.name`, then the shortened pubkey, while kind-0
    // metadata is still in flight. Re-renders when the cache fills.
    let resolved_name =
        crate::components::user_display::use_display_name_memo(convo.pubkey.clone());
    let convo_name = convo.name.clone();
    let short_pk_for_name = short_pk.clone();
    let name = move || {
        let r = resolved_name.get();
        // If resolution only yielded the shortened pubkey, prefer any explicit
        // nickname carried on the conversation; otherwise show the resolved label.
        if r == short_pk_for_name && !convo_name.is_empty() {
            convo_name.clone()
        } else {
            r
        }
    };
    let last_message = convo.last_message.clone();
    let has_message = !last_message.is_empty();

    view! {
        <A href=href attr:class="block bg-gray-800 hover:bg-gray-750 border border-gray-700 hover:border-amber-500/30 rounded-lg hover:-translate-y-px hover:shadow-md transition-all duration-200 no-underline text-inherit">
            <div class="p-4">
                <div class="flex gap-3 items-center">
                    // Avatar
                    <div
                        class="w-10 h-10 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0"
                        style=format!("background-color: {}", avatar_bg)
                    >
                        {avatar_text}
                    </div>

                    // Content
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center justify-between gap-2">
                            <div class="min-w-0">
                                <span class=move || {
                                    if has_unread {
                                        "font-bold text-sm text-white truncate block"
                                    } else {
                                        "font-semibold text-sm text-gray-200 truncate block"
                                    }
                                }>
                                    {name}
                                </span>
                                <span class="text-[10px] font-mono text-gray-500 truncate block">
                                    {short_pk}
                                </span>
                            </div>
                            <span class="text-xs text-gray-500 flex-shrink-0">
                                {time_display}
                            </span>
                        </div>
                        <div class="flex items-center justify-between gap-2 mt-0.5">
                            <p class=move || {
                                if has_unread {
                                    "text-sm text-gray-200 truncate"
                                } else {
                                    "text-sm text-gray-400 truncate"
                                }
                            }>
                                {if has_message {
                                    last_message
                                } else {
                                    "No messages yet".to_string()
                                }}
                            </p>
                            {has_unread.then(|| view! {
                                <span class="bg-amber-500 text-gray-900 text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center flex-shrink-0">
                                    {unread_count.to_string()}
                                </span>
                            })}
                        </div>
                    </div>
                </div>
            </div>
        </A>
    }
}

/// Loading skeleton for a conversation row.
#[component]
fn ConversationSkeleton() -> impl IntoView {
    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 animate-pulse">
            <div class="flex gap-3 items-center">
                <div class="w-10 h-10 rounded-full bg-gray-700"></div>
                <div class="flex-1 space-y-2">
                    <div class="h-4 bg-gray-700 rounded w-1/3"></div>
                    <div class="h-3 bg-gray-700 rounded w-2/3"></div>
                </div>
            </div>
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn shield_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-7 h-7 text-amber-400/80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
    }
}

fn lock_icon_small() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
    }
}

fn plus_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
    }
}

fn x_icon_small() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
    }
}

#[allow(dead_code)]
fn mail_icon_large() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-16 h-16 text-amber-400/20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
            <polyline points="22,6 12,13 2,6"/>
        </svg>
    }
}
