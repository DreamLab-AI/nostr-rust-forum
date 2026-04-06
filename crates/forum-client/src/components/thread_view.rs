//! Threaded reply view for NIP-22 kind-1111 comment events.
//!
//! Displays replies indented under a parent message with a connecting line.
//! Includes a collapsible toggle and an inline reply composer. Reply events
//! are kind-1111 with `E` (root) and `e` (parent) tags per NIP-22.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::mention_text::MentionText;
use crate::components::reaction_bar::{Reaction, ReactionBar};
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::NameCache;
use crate::relay::RelayConnection;
use crate::utils::{format_relative_time, shorten_pubkey};

/// Data for a single thread reply.
#[derive(Clone, Debug)]
pub struct ThreadReply {
    pub id: String,
    pub pubkey: String,
    pub content: String,
    pub created_at: u64,
    pub reactions: RwSignal<Vec<Reaction>>,
}

/// Collapsible threaded reply view for a parent message.
///
/// Shows a count of replies with expand/collapse. When expanded, renders
/// each reply indented with a vertical connecting line. Includes an inline
/// reply composer at the bottom.
#[component]
pub fn ThreadView(
    /// The root channel event ID (for the `E` tag on kind-1111).
    #[prop(into)]
    root_event_id: String,
    /// The parent message event ID (for the `e` tag on kind-1111).
    #[prop(into)]
    parent_event_id: String,
    /// The parent message author pubkey (for the `p` tag).
    #[prop(into)]
    parent_pubkey: String,
    /// Reactive list of replies to this message.
    replies: RwSignal<Vec<ThreadReply>>,
) -> impl IntoView {
    let expanded = RwSignal::new(false);
    let show_composer = RwSignal::new(false);
    let reply_text = RwSignal::new(String::new());
    let sending = RwSignal::new(false);

    let reply_count = move || replies.get().len();
    let has_replies = move || reply_count() > 0;

    let root_eid = StoredValue::new(root_event_id);
    let parent_eid = StoredValue::new(parent_event_id);
    let parent_pk = StoredValue::new(parent_pubkey);

    let auth = use_auth();
    let is_authed = auth.is_authenticated();

    // Submit a kind-1111 reply
    let on_send_reply = move |_: leptos::ev::MouseEvent| {
        let content = reply_text.get_untracked();
        if content.trim().is_empty() {
            return;
        }

        let relay = expect_context::<RelayConnection>();
        let auth = use_auth();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }

        sending.set(true);

        let root = root_eid.get_value();
        let parent = parent_eid.get_value();
        let ppk = parent_pk.get_value();
        let now = (js_sys::Date::now() / 1000.0) as u64;

        // NIP-22 kind 1111 comment event
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 1111,
            tags: vec![
                // Root reference (uppercase E per NIP-22)
                vec!["E".to_string(), root, String::new(), "root".to_string()],
                // Parent reference (lowercase e per NIP-22)
                vec!["e".to_string(), parent, String::new(), "reply".to_string()],
                // Root kind
                vec!["K".to_string(), "42".to_string()],
                // Parent kind
                vec!["k".to_string(), "42".to_string()],
                // Notify parent author
                vec!["p".to_string(), ppk],
            ],
            content,
        };

        let reply_text_sig = reply_text;
        let show_composer_sig = show_composer;
        let sending_sig = sending;
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    let _ = relay.publish(&signed);
                    reply_text_sig.set(String::new());
                    show_composer_sig.set(false);
                    let toasts = use_toasts();
                    toasts.show("Reply sent", ToastVariant::Success);
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("[ThreadView] Sign failed: {}", e).into(),
                    );
                    let toasts = use_toasts();
                    toasts.show("Failed to send reply", ToastVariant::Error);
                }
            }
            sending_sig.set(false);
        });
    };

    view! {
        <div class="mt-1">
            // Thread toggle / reply button row
            <div class="flex items-center gap-2">
                // Show/hide replies toggle
                <Show when=has_replies>
                    <button
                        class="flex items-center gap-1 text-xs text-gray-500 hover:text-amber-400 transition-colors"
                        on:click=move |_| expanded.update(|v| *v = !*v)
                    >
                        <svg
                            class=move || if expanded.get() {
                                "w-3 h-3 transition-transform"
                            } else {
                                "w-3 h-3 transition-transform -rotate-90"
                            }
                            viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                        >
                            <polyline points="6 9 12 15 18 9" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        <span>
                            {move || {
                                let n = reply_count();
                                format!("{} repl{}", n, if n == 1 { "y" } else { "ies" })
                            }}
                        </span>
                    </button>
                </Show>

                // Reply button
                <Show when=move || is_authed.get()>
                    <button
                        class="opacity-0 group-hover:opacity-100 flex items-center gap-1 text-xs text-gray-500 hover:text-amber-400 transition-all"
                        on:click=move |_| {
                            show_composer.set(true);
                            expanded.set(true);
                        }
                    >
                        <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        "Reply"
                    </button>
                </Show>
            </div>

            // Expanded thread replies
            <Show when=move || expanded.get() && has_replies()>
                <div class="ml-4 mt-1 border-l-2 border-gray-700/50 pl-3 space-y-1">
                    {move || {
                        replies.get().into_iter().map(|reply| {
                            let pk = reply.pubkey.clone();
                            let pk_for_name = pk.clone();
                            let time = format_relative_time(reply.created_at);
                            let content = reply.content.clone();
                            let eid = reply.id.clone();
                            let reactions = reply.reactions;

                            let display_name = Memo::new(move |_| {
                                if let Some(cache) = use_context::<NameCache>() {
                                    if let Some(name) = cache.0.get().get(&pk_for_name).cloned() {
                                        return name;
                                    }
                                }
                                shorten_pubkey(&pk_for_name)
                            });

                            view! {
                                <div class="flex gap-2 py-1.5 hover:bg-gray-800/20 rounded-lg px-1 transition-colors group">
                                    <div class="flex-shrink-0 mt-0.5">
                                        <Avatar pubkey=pk size=AvatarSize::Sm />
                                    </div>
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-baseline gap-2">
                                            <span class="font-semibold text-xs text-amber-400">
                                                {move || display_name.get()}
                                            </span>
                                            <span class="text-xs text-gray-600">{time.clone()}</span>
                                        </div>
                                        <div class="text-xs text-gray-300 leading-relaxed">
                                            <MentionText content=content />
                                        </div>
                                        <ReactionBar event_id=eid reactions=reactions />
                                    </div>
                                </div>
                            }
                        }).collect_view()
                    }}
                </div>
            </Show>

            // Inline reply composer
            <Show when=move || show_composer.get()>
                <div class="ml-4 mt-2 border-l-2 border-amber-500/30 pl-3">
                    <div class="flex gap-2">
                        <textarea
                            class="flex-1 bg-gray-800/50 border border-gray-700 rounded-lg p-2 text-sm text-gray-200 placeholder-gray-500 focus:border-amber-500/50 focus:outline-none resize-none"
                            rows="2"
                            placeholder="Write a reply..."
                            prop:value=move || reply_text.get()
                            on:input=move |ev| {
                                let val = event_target_value(&ev);
                                reply_text.set(val);
                            }
                            on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                                if ev.key() == "Escape" {
                                    show_composer.set(false);
                                }
                            }
                        />
                    </div>
                    <div class="flex justify-end gap-2 mt-1.5">
                        <button
                            class="px-3 py-1 text-xs text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-800"
                            on:click=move |_| show_composer.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            class=move || {
                                let has_text = !reply_text.get().trim().is_empty();
                                if has_text && !sending.get() {
                                    "px-3 py-1 text-xs font-medium bg-amber-600 hover:bg-amber-500 text-white rounded transition-colors"
                                } else {
                                    "px-3 py-1 text-xs font-medium bg-gray-700 text-gray-500 rounded cursor-not-allowed"
                                }
                            }
                            disabled=move || reply_text.get().trim().is_empty() || sending.get()
                            on:click=on_send_reply
                        >
                            {move || if sending.get() { "Sending..." } else { "Reply" }}
                        </button>
                    </div>
                </div>
            </Show>
        </div>
    }
}
