//! Collapsible banner showing pinned messages at the top of a channel.
//!
//! Displays up to 5 pinned messages with author, timestamp, and a click
//! handler that scrolls to the original message in the list. Admins see
//! an unpin button on each pinned message.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::NameCache;
use crate::relay::RelayConnection;
use crate::stores::zone_access::ZoneAccess;
use crate::utils::{format_relative_time, shorten_pubkey};

/// A single pinned message's data.
#[derive(Clone, Debug)]
pub struct PinnedMessage {
    pub event_id: String,
    pub pubkey: String,
    pub content: String,
    pub created_at: u64,
}

/// Maximum number of pinned messages to display.
const MAX_PINNED: usize = 5;

/// Admin-only pin button for individual messages.
///
/// Publishes a kind-41 channel metadata update event with a `pin` tag
/// referencing the target event ID. Only shown for admin users.
#[component]
pub fn PinButton(
    /// The channel ID for the kind-41 metadata event.
    #[prop(into)]
    channel_id: String,
    /// The event ID to pin.
    #[prop(into)]
    event_id: String,
) -> impl IntoView {
    let is_admin = Memo::new(move |_| {
        use_context::<ZoneAccess>()
            .map(|za| za.is_admin.get())
            .unwrap_or(false)
    });

    let cid = StoredValue::new(channel_id);
    let eid = StoredValue::new(event_id);

    let on_pin = move |_: leptos::ev::MouseEvent| {
        let relay = expect_context::<RelayConnection>();
        let auth = use_auth();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }

        let now = (js_sys::Date::now() / 1000.0) as u64;
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 41,
            tags: vec![
                vec!["e".to_string(), cid.get_value(), String::new(), "root".to_string()],
                vec!["pin".to_string(), eid.get_value()],
            ],
            content: String::new(),
        };

        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    let _ = relay.publish(&signed);
                    let toasts = use_toasts();
                    toasts.show("Message pinned", ToastVariant::Success);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("[PinButton] Sign failed: {}", e).into());
                }
            }
        });
    };

    view! {
        <Show when=move || is_admin.get()>
            <button
                class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-gray-700/50 text-gray-600 hover:text-amber-400"
                title="Pin message"
                on:click=on_pin
            >
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6h1.6v-6H18v-2l-2-2z"/>
                </svg>
            </button>
        </Show>
    }
}

/// Collapsible pinned-messages banner for a channel.
///
/// Renders a glass-card with an amber left border. Clicking a pinned message
/// scrolls to its position in the message list via `data-event-id`. Admin
/// users see an unpin button on each pinned message.
#[component]
pub fn PinnedMessages(
    /// The channel ID (used for unpin actions).
    #[prop(into)]
    channel_id: String,
    /// Reactive list of pinned messages for this channel.
    pinned: RwSignal<Vec<PinnedMessage>>,
) -> impl IntoView {
    let collapsed = RwSignal::new(false);
    let cid_stored = StoredValue::new(channel_id);

    let is_admin = Memo::new(move |_| {
        use_context::<ZoneAccess>()
            .map(|za| za.is_admin.get())
            .unwrap_or(false)
    });

    let pinned_count = move || pinned.get().len();
    let has_pinned = move || pinned_count() > 0;

    let toggle = move |_| collapsed.update(|v| *v = !*v);

    view! {
        <Show when=has_pinned>
            <div class="glass-card border-l-2 border-amber-400 rounded-lg mb-3 overflow-hidden">
                // Header bar (always visible)
                <button
                    class="w-full flex items-center justify-between px-4 py-2.5 text-left hover:bg-gray-800/30 transition-colors"
                    on:click=toggle
                >
                    <div class="flex items-center gap-2 text-amber-400">
                        // Pin icon
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M16 12V4h1V2H7v2h1v8l-2 2v2h5.2v6h1.6v-6H18v-2l-2-2z"/>
                        </svg>
                        <span class="text-sm font-medium">
                            {move || format!("{} pinned message{}", pinned_count(), if pinned_count() == 1 { "" } else { "s" })}
                        </span>
                    </div>
                    // Chevron
                    <svg
                        class=move || if collapsed.get() {
                            "w-4 h-4 text-gray-500 transition-transform -rotate-90"
                        } else {
                            "w-4 h-4 text-gray-500 transition-transform"
                        }
                        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                    >
                        <polyline points="6 9 12 15 18 9" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>

                // Pinned messages list
                <Show when=move || !collapsed.get()>
                    <div class="border-t border-gray-700/50 divide-y divide-gray-700/30">
                        {move || {
                            let msgs = pinned.get();
                            msgs.into_iter().take(MAX_PINNED).map(|msg| {
                                let eid = msg.event_id.clone();
                                let eid_unpin = eid.clone();
                                let pk = msg.pubkey.clone();
                                let pk_for_name = pk.clone();
                                let content_preview = truncate_content(&msg.content, 120);
                                let time = format_relative_time(msg.created_at);

                                let display_name = Memo::new(move |_| {
                                    if let Some(cache) = use_context::<NameCache>() {
                                        if let Some(name) = cache.0.get().get(&pk_for_name).cloned() {
                                            return name;
                                        }
                                    }
                                    shorten_pubkey(&pk_for_name)
                                });

                                let on_click = move |_| {
                                    scroll_to_event(&eid);
                                };

                                // Unpin handler for admins
                                let eid_for_unpin = StoredValue::new(eid_unpin);
                                let cid_for_unpin = cid_stored;
                                let pinned_sig = pinned;
                                let on_unpin = move |ev: leptos::ev::MouseEvent| {
                                    ev.stop_propagation();
                                    let relay = expect_context::<RelayConnection>();
                                    let auth = use_auth();
                                    let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
                                    if pubkey.is_empty() {
                                        return;
                                    }

                                    let now = (js_sys::Date::now() / 1000.0) as u64;
                                    // Kind 41 without pin tag = unpin
                                    let unsigned = nostr_core::UnsignedEvent {
                                        pubkey: pubkey.clone(),
                                        created_at: now,
                                        kind: 41,
                                        tags: vec![
                                            vec!["e".to_string(), cid_for_unpin.get_value(), String::new(), "root".to_string()],
                                            vec!["unpin".to_string(), eid_for_unpin.get_value()],
                                        ],
                                        content: String::new(),
                                    };

                                    let unpin_eid = eid_for_unpin.get_value();
                                    wasm_bindgen_futures::spawn_local(async move {
                                        match auth.sign_event_async(unsigned).await {
                                            Ok(signed) => {
                                                let _ = relay.publish(&signed);
                                                // Optimistically remove from local state
                                                pinned_sig.update(|list| {
                                                    list.retain(|p| p.event_id != unpin_eid);
                                                });
                                                let toasts = use_toasts();
                                                toasts.show("Message unpinned", ToastVariant::Success);
                                            }
                                            Err(e) => {
                                                web_sys::console::error_1(&format!("[PinnedMessages] Unpin sign failed: {}", e).into());
                                            }
                                        }
                                    });
                                };

                                view! {
                                    <div
                                        class="w-full text-left px-4 py-2 hover:bg-gray-800/30 transition-colors flex items-start gap-2.5 cursor-pointer group/pin"
                                        on:click=on_click
                                    >
                                        <Avatar pubkey=pk size=AvatarSize::Sm />
                                        <div class="flex-1 min-w-0">
                                            <div class="flex items-baseline gap-2">
                                                <span class="text-xs font-medium text-amber-400">{move || display_name.get()}</span>
                                                <span class="text-xs text-gray-600">{time.clone()}</span>
                                            </div>
                                            <p class="text-xs text-gray-400 truncate mt-0.5">{content_preview}</p>
                                        </div>
                                        // Unpin button (admin only)
                                        <Show when=move || is_admin.get()>
                                            <button
                                                class="opacity-0 group-hover/pin:opacity-100 transition-opacity p-1 rounded hover:bg-gray-700/50 text-gray-500 hover:text-red-400 flex-shrink-0"
                                                title="Unpin message"
                                                on:click=on_unpin
                                            >
                                                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                    <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                                                    <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                                                </svg>
                                            </button>
                                        </Show>
                                    </div>
                                }
                            }).collect_view()
                        }}
                    </div>
                </Show>
            </div>
        </Show>
    }
}

/// Scroll to a message element with the given `data-event-id` attribute.
fn scroll_to_event(event_id: &str) {
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        let selector = format!("[data-event-id=\"{}\"]", event_id);
        if let Ok(Some(el)) = doc.query_selector(&selector) {
            let opts = web_sys::ScrollIntoViewOptions::new();
            opts.set_behavior(web_sys::ScrollBehavior::Smooth);
            el.scroll_into_view_with_scroll_into_view_options(&opts);
        }
    }
}

/// Truncate content to at most `max` characters, appending "..." if truncated.
fn truncate_content(content: &str, max: usize) -> String {
    if content.len() <= max {
        content.to_string()
    } else {
        let end = content
            .char_indices()
            .nth(max)
            .map(|(i, _)| i)
            .unwrap_or(content.len());
        format!("{}...", &content[..end])
    }
}
