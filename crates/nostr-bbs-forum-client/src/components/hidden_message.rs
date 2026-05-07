//! Hidden message placeholder for reported/moderated content.
//!
//! Replaces the content of messages that have been hidden pending review.
//! Shows a grey placeholder with lock icon. Admin users see a "Review" link
//! to the admin reports tab.

use leptos::prelude::*;

use crate::app::base_href;
use crate::stores::zone_access::ZoneAccess;

/// Placeholder component for hidden/reported messages.
///
/// Renders a subdued card with a lock icon and explanatory text. Admin
/// users additionally see a link to the moderation review queue.
#[component]
pub fn HiddenMessage(
    /// The event ID of the hidden message (used for admin deep-link).
    #[prop(into)]
    event_id: String,
) -> impl IntoView {
    let is_admin = Memo::new(move |_| {
        use_context::<ZoneAccess>()
            .map(|za| za.is_admin.get())
            .unwrap_or(false)
    });

    let eid = StoredValue::new(event_id);

    view! {
        <div
            class="flex items-center gap-3 py-2 px-3 rounded-lg bg-gray-800/40 border border-gray-700/50"
            data-event-id=move || eid.get_value()
        >
            // Lock icon
            <div class="flex-shrink-0 text-gray-600">
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>

            <div class="flex-1 min-w-0">
                <span class="text-sm text-gray-500 italic">
                    "This message has been hidden pending review"
                </span>
            </div>

            // Admin review link
            <Show when=move || is_admin.get()>
                <a
                    href=move || format!("{}/admin?tab=reports&event={}", base_href(""), eid.get_value())
                    class="text-xs text-amber-500 hover:text-amber-400 transition-colors font-medium whitespace-nowrap"
                >
                    "Review"
                </a>
            </Show>
        </div>
    }
}
