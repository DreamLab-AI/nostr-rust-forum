//! NIP-56 report button component for message moderation.
//!
//! Shows on hover for TL1+ users. Opens a modal with reason picker (spam,
//! inappropriate, off-topic, other with free-text). On submit, creates and
//! publishes a kind-1984 event per NIP-56.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::modal::Modal;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::RelayConnection;
use crate::stores::zone_access::ZoneAccess;

/// Predefined report reasons per NIP-56.
const REPORT_REASONS: &[(&str, &str)] = &[
    ("spam", "Spam"),
    ("inappropriate", "Inappropriate content"),
    ("off-topic", "Off-topic"),
    ("other", "Other"),
];

/// Report button shown on hover for authenticated TL1+ users.
///
/// Clicking opens a modal with reason selection and optional free-text
/// detail. Submit publishes a NIP-56 kind-1984 report event via the relay.
#[component]
pub fn ReportButton(
    /// The event ID of the message to report.
    #[prop(into)]
    event_id: String,
    /// The pubkey of the message author being reported.
    #[prop(into)]
    reported_pubkey: String,
) -> impl IntoView {
    let show_modal = RwSignal::new(false);
    let selected_reason = RwSignal::new(String::new());
    let other_text = RwSignal::new(String::new());
    let submitting = RwSignal::new(false);

    let auth = use_auth();
    let is_authed = auth.is_authenticated();

    // Only show for authenticated users (TL1+ check via zone access)
    let can_report = Memo::new(move |_| {
        if !is_authed.get() {
            return false;
        }
        // If ZoneAccess context exists, user must be whitelisted (TL1+)
        if let Some(zone) = use_context::<ZoneAccess>() {
            return zone.loaded.get() && zone.home.get();
        }
        // Fallback: any authenticated user can report
        true
    });

    let eid_stored = StoredValue::new(event_id);
    let rpk_stored = StoredValue::new(reported_pubkey);

    let on_submit = move |_: leptos::ev::MouseEvent| {
        let reason = selected_reason.get_untracked();
        if reason.is_empty() {
            return;
        }

        let detail = if reason == "other" {
            let txt = other_text.get_untracked();
            if txt.trim().is_empty() {
                return;
            }
            txt
        } else {
            reason.clone()
        };

        submitting.set(true);

        let relay = expect_context::<RelayConnection>();
        let auth = use_auth();
        let pubkey = auth.pubkey().get_untracked().unwrap_or_default();
        if pubkey.is_empty() {
            submitting.set(false);
            return;
        }

        let eid = eid_stored.get_value();
        let rpk = rpk_stored.get_value();
        let now = (js_sys::Date::now() / 1000.0) as u64;

        // NIP-56 kind 1984 report event
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey.clone(),
            created_at: now,
            kind: 1984,
            tags: vec![
                vec!["e".to_string(), eid],
                vec!["p".to_string(), rpk],
                vec!["report".to_string(), detail],
            ],
            content: String::new(),
        };

        let show = show_modal;
        let sub = submitting;
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    let _ = relay.publish(&signed);
                    let toasts = use_toasts();
                    toasts.show("Report submitted", ToastVariant::Success);
                    show.set(false);
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("[ReportButton] Sign failed: {}", e).into(),
                    );
                    let toasts = use_toasts();
                    toasts.show("Failed to submit report", ToastVariant::Error);
                }
            }
            sub.set(false);
        });
    };

    view! {
        <Show when=move || can_report.get()>
            // Flag icon button (appears on hover via parent group class)
            <button
                class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-gray-700/50 text-gray-600 hover:text-red-400"
                title="Report message"
                on:click=move |_| {
                    selected_reason.set(String::new());
                    other_text.set(String::new());
                    show_modal.set(true);
                }
            >
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z" stroke-linecap="round" stroke-linejoin="round"/>
                    <line x1="4" y1="22" x2="4" y2="15" stroke-linecap="round"/>
                </svg>
            </button>

            // Report modal
            <Modal is_open=show_modal title="Report Message".to_string() max_width="420px".to_string()>
                <div class="space-y-4">
                    <p class="text-sm text-gray-400">
                        "Select a reason for reporting this message. Reports are reviewed by moderators."
                    </p>

                    // Reason radio buttons
                    <div class="space-y-2">
                        {REPORT_REASONS.iter().map(|&(value, label)| {
                            let val = value.to_string();
                            let val_click = val.clone();
                            let val_check = val.clone();
                            view! {
                                <label
                                    class="flex items-center gap-3 p-2.5 rounded-lg cursor-pointer hover:bg-gray-800/50 transition-colors"
                                    on:click=move |_| selected_reason.set(val_click.clone())
                                >
                                    <div class=move || {
                                        if selected_reason.get() == val_check {
                                            "w-4 h-4 rounded-full border-2 border-amber-400 bg-amber-400 flex items-center justify-center"
                                        } else {
                                            "w-4 h-4 rounded-full border-2 border-gray-600"
                                        }
                                    }>
                                        <Show when={
                                            let vc = val.clone();
                                            move || selected_reason.get() == vc
                                        }>
                                            <div class="w-1.5 h-1.5 rounded-full bg-gray-900"></div>
                                        </Show>
                                    </div>
                                    <span class="text-sm text-gray-200">{label}</span>
                                </label>
                            }
                        }).collect_view()}
                    </div>

                    // Free-text for "other" reason
                    <Show when=move || selected_reason.get() == "other">
                        <textarea
                            class="w-full bg-gray-800/50 border border-gray-700 rounded-lg p-3 text-sm text-gray-200 placeholder-gray-500 focus:border-amber-500/50 focus:outline-none resize-none"
                            rows="3"
                            placeholder="Describe the issue..."
                            prop:value=move || other_text.get()
                            on:input=move |ev| {
                                let val = event_target_value(&ev);
                                other_text.set(val);
                            }
                        />
                    </Show>

                    // Submit / cancel buttons
                    <div class="flex justify-end gap-3 pt-2">
                        <button
                            class="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-gray-800"
                            on:click=move |_| show_modal.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            class=move || {
                                let reason = selected_reason.get();
                                let valid = if reason == "other" {
                                    !other_text.get().trim().is_empty()
                                } else {
                                    !reason.is_empty()
                                };
                                if valid && !submitting.get() {
                                    "px-4 py-2 text-sm font-medium bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors"
                                } else {
                                    "px-4 py-2 text-sm font-medium bg-gray-700 text-gray-500 rounded-lg cursor-not-allowed"
                                }
                            }
                            disabled=move || {
                                let reason = selected_reason.get();
                                let valid = if reason == "other" {
                                    !other_text.get().trim().is_empty()
                                } else {
                                    !reason.is_empty()
                                };
                                !valid || submitting.get()
                            }
                            on:click=on_submit
                        >
                            {move || if submitting.get() { "Submitting..." } else { "Submit Report" }}
                        </button>
                    </div>
                </div>
            </Modal>
        </Show>
    }
}
