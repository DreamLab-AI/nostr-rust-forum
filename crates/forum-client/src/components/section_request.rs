//! Section access request button component.
//!
//! Publishes a kind-9021 NIP-29 join request event with section info in tags.
//! Shows pending state after submission with toast notification on success.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::{ConnectionState, RelayConnection};

/// Request access button for gated forum sections.
///
/// Publishes a kind-9021 join request targeting the given section/cohort.
#[allow(dead_code)]
#[component]
pub fn SectionRequestButton(
    /// The section's channel event ID.
    section_id: String,
    /// The cohort name required for access.
    required_cohort: String,
    /// Display name of the section (for the button label).
    #[prop(default = "this section".to_string())]
    section_name: String,
) -> impl IntoView {
    let auth = use_auth();
    let is_pending = RwSignal::new(false);
    let is_sent = RwSignal::new(false);

    let section_id_clone = section_id.clone();
    let cohort_clone = required_cohort.clone();
    let section_name_clone = section_name.clone();

    let on_request = move |_| {
        if is_pending.get_untracked() || is_sent.get_untracked() {
            return;
        }

        let relay = expect_context::<RelayConnection>();
        let conn = relay.connection_state();
        if conn.get_untracked() != ConnectionState::Connected {
            let toasts = use_toasts();
            toasts.show("Relay not connected. Please try again.", ToastVariant::Error);
            return;
        }

        let pubkey = match auth.pubkey().get_untracked() {
            Some(pk) => pk,
            None => {
                let toasts = use_toasts();
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            }
        };

        is_pending.set(true);

        let now = (js_sys::Date::now() / 1000.0) as u64;

        // Kind 9021: NIP-29 Join Request
        let unsigned = nostr_core::UnsignedEvent {
            pubkey,
            created_at: now,
            kind: 9021,
            tags: vec![
                vec!["e".to_string(), section_id_clone.clone(), String::new(), "root".to_string()],
                vec!["cohort".to_string(), cohort_clone.clone()],
                vec!["section".to_string(), section_name_clone.clone()],
            ],
            content: format!("Requesting access to {}", section_name_clone),
        };

        let section_name_for_toast = section_name_clone.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    relay.publish(&signed);
                    is_pending.set(false);
                    is_sent.set(true);
                    let toasts = use_toasts();
                    toasts.show(
                        format!("Access request sent for \"{}\"", section_name_for_toast),
                        ToastVariant::Success,
                    );
                }
                Err(e) => {
                    is_pending.set(false);
                    let toasts = use_toasts();
                    toasts.show(format!("Failed to send request: {}", e), ToastVariant::Error);
                }
            }
        });
    };

    let button_text = move || {
        if is_sent.get() {
            "Request Sent".to_string()
        } else if is_pending.get() {
            "Sending...".to_string()
        } else {
            format!("Request Access to {}", section_name)
        }
    };

    let button_class = move || {
        if is_sent.get() {
            "flex items-center gap-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-4 py-2 rounded-lg text-sm cursor-default"
        } else if is_pending.get() {
            "flex items-center gap-2 bg-gray-700 text-gray-400 px-4 py-2 rounded-lg text-sm cursor-wait"
        } else {
            "flex items-center gap-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20 hover:border-amber-500/40 px-4 py-2 rounded-lg text-sm transition-colors cursor-pointer"
        }
    };

    view! {
        <button
            on:click=on_request
            disabled=move || is_pending.get() || is_sent.get()
            class=button_class
        >
            {move || {
                if is_sent.get() {
                    view! {
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    }.into_any()
                } else {
                    view! {
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    }.into_any()
                }
            }}
            <span>{button_text}</span>
        </button>
    }
}
