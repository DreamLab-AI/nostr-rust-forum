//! "Request Access" button for gated channels the user hasn't joined.
//!
//! Publishes a kind-9021 join-request event to the relay on click.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::relay::RelayConnection;

/// Button states for the join-request flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestState {
    Idle,
    Pending,
    Sent,
}

/// "Request Access" button for gated channels.
///
/// - Shows "Request Access" in idle state with an amber gradient.
/// - Transitions to "Pending..." after the event is published.
/// - Disabled while pending or sent.
#[allow(dead_code)]
#[component]
pub fn JoinRequestButton(
    /// The channel ID to request access to.
    #[prop(into)]
    channel_id: String,
    /// Whether this channel is gated (requires explicit access).
    #[prop(default = true)]
    is_gated: bool,
) -> impl IntoView {
    let state = RwSignal::new(RequestState::Idle);
    let auth = use_auth();
    let cid = channel_id.clone();

    let cid_stored = StoredValue::new(cid);
    let on_request = move |_: leptos::ev::MouseEvent| {
        if state.get_untracked() != RequestState::Idle {
            return;
        }

        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            return;
        }

        state.set(RequestState::Pending);

        let now = (js_sys::Date::now() / 1000.0) as u64;
        let cid_val = cid_stored.get_value();
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 9021,
            tags: vec![vec!["e".to_string(), cid_val]],
            content: String::new(),
        };

        let relay = expect_context::<RelayConnection>();
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    relay.publish(&signed);
                    state.set(RequestState::Sent);
                }
                Err(_) => {
                    state.set(RequestState::Idle);
                }
            }
        });
    };

    let button_class = move || match state.get() {
        RequestState::Idle => {
            "inline-flex items-center gap-2 bg-gradient-to-r from-amber-500 to-amber-400 \
             hover:from-amber-400 hover:to-amber-300 text-gray-900 font-semibold px-5 py-2.5 \
             rounded-lg transition-all shadow-md shadow-amber-500/20"
        }
        RequestState::Pending => {
            "inline-flex items-center gap-2 bg-gray-700 text-gray-400 font-semibold px-5 py-2.5 \
             rounded-lg cursor-not-allowed"
        }
        RequestState::Sent => {
            "inline-flex items-center gap-2 bg-gray-700 text-amber-400/60 font-semibold px-5 \
             py-2.5 rounded-lg cursor-not-allowed border border-amber-500/20"
        }
    };

    let button_text = move || match state.get() {
        RequestState::Idle => "Request Access",
        RequestState::Pending => "Sending...",
        RequestState::Sent => "Request Sent",
    };

    let is_disabled = move || state.get() != RequestState::Idle;

    view! {
        <Show when=move || is_gated>
            <button
                class=button_class
                on:click=on_request
                disabled=is_disabled
            >
                {move || match state.get() {
                    RequestState::Idle => view! {
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4" stroke-linecap="round" stroke-linejoin="round"/>
                            <polyline points="10 17 15 12 10 7" stroke-linecap="round" stroke-linejoin="round"/>
                            <line x1="15" y1="12" x2="3" y2="12" stroke-linecap="round"/>
                        </svg>
                    }.into_any(),
                    RequestState::Pending => view! {
                        <div class="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin"></div>
                    }.into_any(),
                    RequestState::Sent => view! {
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    }.into_any(),
                }}
                <span>{button_text}</span>
            </button>
        </Show>
    }
}
