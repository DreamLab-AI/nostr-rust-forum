//! Single note deep-link view page.
//!
//! Route: `/view/:note_id`
//! Fetches a single Nostr event by ID from the relay and displays it in a
//! centered glass card with author, content, timestamp, and actions.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use nostr_core::NostrEvent;
use std::rc::Rc;

use crate::app::base_href;
use crate::components::mention_text::MentionText;
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::components::user_display::use_display_name;
use crate::utils::{format_relative_time, pubkey_color, set_timeout_once};

/// Internal representation of the fetched event for display.
#[derive(Clone, Debug)]
struct NoteData {
    id: String,
    pubkey: String,
    content: String,
    kind: u64,
    created_at: u64,
    /// Channel root event ID, if this is a kind 42 channel message.
    channel_id: Option<String>,
}

impl NoteData {
    fn from_event(event: &NostrEvent) -> Self {
        let channel_id = if event.kind == 42 {
            event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "e")
                .map(|t| t[1].clone())
        } else {
            None
        };

        Self {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            content: event.content.clone(),
            kind: event.kind,
            created_at: event.created_at,
            channel_id,
        }
    }
}

/// Kind label for display.
fn kind_label(kind: u64) -> &'static str {
    match kind {
        0 => "Profile Metadata",
        1 => "Note",
        4 => "Encrypted DM (NIP-04)",
        7 => "Reaction",
        40 => "Channel Creation",
        42 => "Channel Message",
        1059 => "Gift-Wrapped DM",
        _ => "Event",
    }
}

fn is_private_kind(kind: u64) -> bool {
    matches!(kind, 4 | 1059)
}

#[component]
pub fn NoteViewPage() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let params = use_params_map();

    let note_id = move || params.read().get("note_id").unwrap_or_default();

    let note: RwSignal<Option<NoteData>> = RwSignal::new(None);
    let loading = RwSignal::new(true);
    let not_found = RwSignal::new(false);
    let copied = RwSignal::new(false);
    let sub_id: RwSignal<Option<String>> = RwSignal::new(None);

    let relay_for_sub = relay.clone();
    let relay_for_cleanup = relay;

    // Subscribe to fetch the single event
    Effect::new(move |_| {
        let state = conn_state.get();
        let nid = note_id();
        if state != ConnectionState::Connected || nid.is_empty() {
            return;
        }
        if sub_id.get_untracked().is_some() {
            return;
        }

        loading.set(true);
        not_found.set(false);

        let filter = Filter {
            ids: Some(vec![nid]),
            ..Default::default()
        };

        let note_sig = note;
        let loading_sig = loading;
        let on_event = Rc::new(move |event: NostrEvent| {
            note_sig.set(Some(NoteData::from_event(&event)));
            loading_sig.set(false);
        });

        let on_eose = Rc::new({
            let loading_sig = loading;
            let note_sig = note;
            let not_found_sig = not_found;
            move || {
                loading_sig.set(false);
                if note_sig.get_untracked().is_none() {
                    not_found_sig.set(true);
                }
            }
        });

        let id = relay_for_sub.subscribe(vec![filter], on_event, Some(on_eose));
        sub_id.set(Some(id));

        // Timeout fallback — re-bind signals for this closure's capture
        let loading_timeout = loading;
        let note_timeout = note;
        let not_found_timeout = not_found;
        set_timeout_once(
            move || {
                if loading_timeout.get_untracked() {
                    loading_timeout.set(false);
                    if note_timeout.get_untracked().is_none() {
                        not_found_timeout.set(true);
                    }
                }
            },
            10_000,
        );
    });

    // Cleanup on unmount
    on_cleanup(move || {
        if let Some(id) = sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    // Copy link handler
    let on_copy_link = move |_| {
        if let Some(window) = web_sys::window() {
            let origin = window.location().origin().unwrap_or_default();
            let full_url = format!("{}{}", origin, base_href(&format!("/view/{}", note_id())));
            let nav = window.navigator().clipboard();
            let _ = nav.write_text(&full_url);
            copied.set(true);
            set_timeout_once(move || copied.set(false), 2000);
        }
    };

    view! {
        <div class="max-w-[640px] mx-auto p-4 sm:p-6">
            // Breadcrumb
            <div class="flex items-center gap-2 text-sm text-gray-500 mb-6">
                <A href=base_href("/") attr:class="hover:text-amber-400 transition-colors">"Home"</A>
                <span>"/"</span>
                <span class="text-gray-300">"Note"</span>
            </div>

            {move || {
                if loading.get() {
                    view! {
                        <div class="glass-card p-6 space-y-4 animate-pulse">
                            <div class="flex items-center gap-3">
                                <div class="w-10 h-10 rounded-full bg-gray-700"></div>
                                <div class="space-y-2 flex-1">
                                    <div class="h-4 bg-gray-700 rounded w-1/3"></div>
                                    <div class="h-3 bg-gray-700 rounded w-1/4"></div>
                                </div>
                            </div>
                            <div class="space-y-2">
                                <div class="h-4 bg-gray-700 rounded w-full"></div>
                                <div class="h-4 bg-gray-700 rounded w-2/3"></div>
                            </div>
                        </div>
                    }.into_any()
                } else if not_found.get() {
                    view! {
                        <div class="glass-card p-8 text-center">
                            <div class="w-14 h-14 rounded-full bg-gray-800 flex items-center justify-center mx-auto mb-4">
                                {not_found_icon()}
                            </div>
                            <h2 class="text-xl font-bold text-white mb-2">"Note Not Found"</h2>
                            <p class="text-gray-400 text-sm mb-4">
                                "The event could not be found on the relay. It may have been deleted or the ID is invalid."
                            </p>
                            <A href=base_href("/") attr:class="text-amber-400 hover:text-amber-300 text-sm underline">
                                "Go home"
                            </A>
                        </div>
                    }.into_any()
                } else if let Some(n) = note.get() {
                    let avatar_text = n.pubkey[..2].to_uppercase();
                    let avatar_bg = pubkey_color(&n.pubkey);
                    let pk_short = use_display_name(&n.pubkey);
                    let time_str = format_relative_time(n.created_at);
                    let label = kind_label(n.kind);
                    let is_private = is_private_kind(n.kind);
                    let is_channel_msg = n.kind == 42;
                    let channel_id = n.channel_id.clone();

                    view! {
                        <div class="glass-card p-6 space-y-4">
                            // Author header
                            <div class="flex items-center gap-3">
                                <div
                                    class="w-10 h-10 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0"
                                    style=format!("background-color: {}", avatar_bg)
                                >
                                    {avatar_text}
                                </div>
                                <div>
                                    <div class="font-semibold text-white text-sm">{pk_short}</div>
                                    <div class="text-xs text-gray-500">{time_str}</div>
                                </div>
                                <span class="ml-auto text-xs text-gray-500 border border-gray-700 rounded px-2 py-0.5">
                                    {label}
                                </span>
                            </div>

                            <div class="border-t border-gray-700/50"></div>

                            // Content
                            {if is_private {
                                view! {
                                    <div class="bg-gray-800/50 rounded-lg p-4 flex items-center gap-3">
                                        {lock_icon()}
                                        <div>
                                            <p class="text-gray-300 text-sm font-medium">"Private Message"</p>
                                            <p class="text-gray-500 text-xs">"This content is encrypted and cannot be displayed here."</p>
                                        </div>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="text-sm text-gray-200 leading-relaxed">
                                        <MentionText content=n.content.clone() />
                                    </div>
                                }.into_any()
                            }}

                            <div class="border-t border-gray-700/50"></div>

                            // Actions
                            <div class="flex items-center gap-3">
                                <button
                                    on:click=on_copy_link
                                    class="text-xs text-gray-400 hover:text-amber-400 border border-gray-700 hover:border-amber-500/30 rounded-lg px-3 py-1.5 transition-colors flex items-center gap-1.5"
                                >
                                    {share_icon()}
                                    {move || if copied.get() { "Copied!" } else { "Share" }}
                                </button>
                                {is_channel_msg.then(|| {
                                    let cid = channel_id.clone().unwrap_or_default();
                                    view! {
                                        <A
                                            href=base_href(&format!("/chat/{}", cid))
                                            attr:class="text-xs text-gray-400 hover:text-amber-400 border border-gray-700 hover:border-amber-500/30 rounded-lg px-3 py-1.5 transition-colors flex items-center gap-1.5"
                                        >
                                            {channel_icon()}
                                            "View in Channel"
                                        </A>
                                    }
                                })}
                            </div>

                            // Event ID footer
                            <div class="text-xs text-gray-600 font-mono break-all">
                                "ID: " {n.id.clone()}
                            </div>
                        </div>
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn not_found_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            <line x1="8" y1="11" x2="14" y2="11"/>
        </svg>
    }
}

fn lock_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400/60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
    }
}

fn share_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="18" cy="5" r="3"/>
            <circle cx="6" cy="12" r="3"/>
            <circle cx="18" cy="19" r="3"/>
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
        </svg>
    }
}

fn channel_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="4" y1="9" x2="20" y2="9"/>
            <line x1="4" y1="15" x2="20" y2="15"/>
            <line x1="10" y1="3" x2="8" y2="21"/>
            <line x1="16" y1="3" x2="14" y2="21"/>
        </svg>
    }
}
