//! RSVP button group for calendar events.
//!
//! Shows Accept / Tentative / Decline buttons with the user's current status
//! highlighted, attendee count, and max-capacity enforcement.

use std::rc::Rc;

use leptos::prelude::*;
use nostr_core::RsvpStatus;

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::RelayConnection;

/// RSVP action buttons for a single calendar event.
#[component]
pub fn RsvpButtons(
    /// The Nostr event ID of the calendar event.
    event_id: String,
    /// Current user's RSVP status (if any).
    current_status: Signal<Option<RsvpStatus>>,
    /// Number of accepted attendees.
    attendee_count: Signal<u32>,
    /// Maximum attendees (None = unlimited).
    #[prop(into)]
    max_attendees: Option<u32>,
) -> impl IntoView {
    let event_id_accept = event_id.clone();
    let event_id_tentative = event_id.clone();
    let event_id_decline = event_id.clone();

    let max = max_attendees;

    let is_full = move || {
        max.map(|m| attendee_count.get() >= m).unwrap_or(false)
    };

    let rsvp_action = move |eid: String, status: RsvpStatus| {
        let auth = use_auth();
        let toasts = use_toasts();
        let privkey = match auth.get_privkey_bytes() {
            Some(pk) => pk,
            None => {
                toasts.show("Not authenticated", ToastVariant::Error);
                return;
            }
        };

        match nostr_core::create_rsvp(&privkey, &eid, status) {
            Ok(event) => {
                let relay = expect_context::<RelayConnection>();
                let label = match status {
                    RsvpStatus::Accept => "Accepted",
                    RsvpStatus::Decline => "Declined",
                    RsvpStatus::Tentative => "Tentative",
                };
                let toasts_ok = toasts.clone();
                let label_owned = label.to_string();
                let ack = Rc::new(move |accepted: bool, message: String| {
                    if accepted {
                        toasts_ok.show(format!("RSVP: {}", label_owned), ToastVariant::Success);
                    } else {
                        toasts_ok.show(
                            format!("RSVP rejected: {}", message),
                            ToastVariant::Error,
                        );
                    }
                });
                if let Err(e) = relay.publish_with_ack(&event, Some(ack)) {
                    toasts.show(format!("RSVP failed: {}", e), ToastVariant::Error);
                }
            }
            Err(e) => {
                toasts.show(format!("RSVP failed: {}", e), ToastVariant::Error);
            }
        }
    };

    let btn_class = move |status: RsvpStatus, base_bg: &str, base_text: &str, base_border: &str| {
        let cur = current_status.get();
        if cur == Some(status) {
            format!(
                "text-xs font-semibold px-2.5 py-1 rounded-lg transition-colors ring-2 ring-offset-1 ring-offset-gray-900 {} {} {}",
                base_bg.replace("/15", "/30"),
                base_text,
                base_border,
            )
        } else {
            format!(
                "text-xs font-semibold px-2.5 py-1 rounded-lg transition-colors {} {} {}",
                base_bg, base_text, base_border,
            )
        }
    };

    view! {
        <div class="flex items-center gap-2 flex-wrap">
            // Accept button
            <button
                class=move || btn_class(
                    RsvpStatus::Accept,
                    "bg-emerald-500/15 hover:bg-emerald-500/25",
                    "text-emerald-400",
                    "border border-emerald-500/30",
                )
                disabled=move || {
                    let full = is_full();
                    let already = current_status.get() == Some(RsvpStatus::Accept);
                    full && !already
                }
                on:click={
                    let eid = event_id_accept.clone();
                    move |_| rsvp_action(eid.clone(), RsvpStatus::Accept)
                }
            >
                "Accept"
            </button>

            // Tentative button
            <button
                class=move || btn_class(
                    RsvpStatus::Tentative,
                    "bg-amber-500/15 hover:bg-amber-500/25",
                    "text-amber-400",
                    "border border-amber-500/30",
                )
                on:click={
                    let eid = event_id_tentative.clone();
                    move |_| rsvp_action(eid.clone(), RsvpStatus::Tentative)
                }
            >
                "Tentative"
            </button>

            // Decline button
            <button
                class=move || btn_class(
                    RsvpStatus::Decline,
                    "bg-red-500/15 hover:bg-red-500/25",
                    "text-red-400",
                    "border border-red-500/30",
                )
                on:click={
                    let eid = event_id_decline.clone();
                    move |_| rsvp_action(eid.clone(), RsvpStatus::Decline)
                }
            >
                "Decline"
            </button>

            // Attendee count
            <span class="text-xs text-gray-500 ml-1">
                {move || {
                    let count = attendee_count.get();
                    match max {
                        Some(m) => format!("{}/{} attending", count, m),
                        None => format!("{} attending", count),
                    }
                }}
            </span>
        </div>
    }
}
