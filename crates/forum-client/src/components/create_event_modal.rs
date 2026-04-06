//! Modal dialog for creating a new NIP-52 calendar event (kind 31923).
//!
//! Collects title, description, dates, location, and max attendees, then signs
//! and publishes via the relay connection.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::RelayConnection;

/// Modal for creating a calendar event.
#[component]
pub fn CreateEventModal(
    /// Called when the modal should close.
    on_close: Callback<()>,
    /// Called with the new event ID on successful creation.
    on_created: Callback<String>,
) -> impl IntoView {
    let title = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let start_date = RwSignal::new(String::new());
    let start_time = RwSignal::new(String::new());
    let end_date = RwSignal::new(String::new());
    let end_time = RwSignal::new(String::new());
    let location = RwSignal::new(String::new());
    let max_attendees = RwSignal::new(String::new());
    let error_msg: RwSignal<Option<String>> = RwSignal::new(None);
    let submitting = RwSignal::new(false);

    let toasts = use_toasts();

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        error_msg.set(None);

        let t = title.get_untracked();
        let sd = start_date.get_untracked();
        let st = start_time.get_untracked();

        // Validation
        if t.trim().is_empty() {
            error_msg.set(Some("Title is required".into()));
            return;
        }
        if sd.is_empty() || st.is_empty() {
            error_msg.set(Some("Start date and time are required".into()));
            return;
        }

        let start_ts = match parse_datetime(&sd, &st) {
            Some(ts) => ts,
            None => {
                error_msg.set(Some("Invalid start date/time".into()));
                return;
            }
        };

        let ed = end_date.get_untracked();
        let et = end_time.get_untracked();
        let end_ts = if !ed.is_empty() && !et.is_empty() {
            match parse_datetime(&ed, &et) {
                Some(ts) => {
                    if ts < start_ts {
                        error_msg.set(Some("End must be after start".into()));
                        return;
                    }
                    Some(ts)
                }
                None => {
                    error_msg.set(Some("Invalid end date/time".into()));
                    return;
                }
            }
        } else {
            None
        };

        let loc = location.get_untracked();
        let loc_opt = if loc.trim().is_empty() {
            None
        } else {
            Some(loc)
        };

        let max_str = max_attendees.get_untracked();
        let max_opt: Option<u32> = if max_str.trim().is_empty() {
            None
        } else {
            match max_str.trim().parse::<u32>() {
                Ok(n) if n > 0 => Some(n),
                _ => {
                    error_msg.set(Some("Max attendees must be a positive number".into()));
                    return;
                }
            }
        };

        let desc = description.get_untracked();
        let desc_opt = if desc.trim().is_empty() {
            None
        } else {
            Some(desc)
        };

        // Sign and publish
        let auth = use_auth();
        let privkey = match auth.get_privkey_bytes() {
            Some(pk) => pk,
            None => {
                error_msg.set(Some("Not authenticated".into()));
                return;
            }
        };

        submitting.set(true);

        match nostr_core::create_calendar_event(
            &privkey,
            t.trim(),
            start_ts,
            end_ts,
            loc_opt.as_deref(),
            desc_opt.as_deref(),
            max_opt,
        ) {
            Ok(event) => {
                let relay = expect_context::<RelayConnection>();
                relay.publish(&event);
                let event_id = event.id.clone();
                toasts.show("Event created", ToastVariant::Success);
                on_created.run(event_id);
                on_close.run(());
            }
            Err(e) => {
                error_msg.set(Some(format!("Failed to create event: {}", e)));
            }
        }

        submitting.set(false);
    };

    let on_backdrop = move |_| {
        on_close.run(());
    };

    let stop_propagation = move |ev: web_sys::MouseEvent| {
        ev.stop_propagation();
    };

    view! {
        <div
            class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
            on:click=on_backdrop
        >
            <div
                class="glass-card w-full max-w-lg mx-4 p-6 rounded-2xl border border-gray-700/50 shadow-2xl animate-slide-in-down max-h-[90vh] overflow-y-auto"
                on:click=stop_propagation
            >
                // Header
                <div class="flex items-center justify-between mb-5">
                    <h2 class="text-xl font-bold text-white">"Create Event"</h2>
                    <button
                        class="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
                        on:click=move |_| on_close.run(())
                    >
                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                    </button>
                </div>

                // Error
                {move || error_msg.get().map(|msg| view! {
                    <div class="mb-4 bg-red-900/40 border border-red-700/50 rounded-lg px-3 py-2 text-sm text-red-300">
                        {msg}
                    </div>
                })}

                <form on:submit=on_submit class="space-y-4">
                    // Title
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-1">"Title *"</label>
                        <input
                            type="text"
                            prop:value=move || title.get()
                            on:input=move |ev| title.set(event_target_value(&ev))
                            class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            placeholder="Event title"
                        />
                    </div>

                    // Description
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-1">"Description"</label>
                        <textarea
                            prop:value=move || description.get()
                            on:input=move |ev| description.set(event_target_value(&ev))
                            rows=3
                            class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors resize-none"
                            placeholder="Describe the event (markdown supported)"
                        ></textarea>
                    </div>

                    // Start date/time
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-1">"Start Date *"</label>
                            <input
                                type="date"
                                prop:value=move || start_date.get()
                                on:input=move |ev| start_date.set(event_target_value(&ev))
                                class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-1">"Start Time *"</label>
                            <input
                                type="time"
                                prop:value=move || start_time.get()
                                on:input=move |ev| start_time.set(event_target_value(&ev))
                                class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                    </div>

                    // End date/time
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-1">"End Date"</label>
                            <input
                                type="date"
                                prop:value=move || end_date.get()
                                on:input=move |ev| end_date.set(event_target_value(&ev))
                                class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-1">"End Time"</label>
                            <input
                                type="time"
                                prop:value=move || end_time.get()
                                on:input=move |ev| end_time.set(event_target_value(&ev))
                                class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                    </div>

                    // Location
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-1">"Location"</label>
                        <input
                            type="text"
                            prop:value=move || location.get()
                            on:input=move |ev| location.set(event_target_value(&ev))
                            class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            placeholder="Virtual - Discord, London, etc."
                        />
                    </div>

                    // Max attendees
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-1">"Max Attendees"</label>
                        <input
                            type="number"
                            min="1"
                            prop:value=move || max_attendees.get()
                            on:input=move |ev| max_attendees.set(event_target_value(&ev))
                            class="w-full bg-gray-900/70 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            placeholder="Leave empty for unlimited"
                        />
                    </div>

                    // Submit
                    <button
                        type="submit"
                        disabled=move || submitting.get()
                        class="w-full py-2.5 rounded-lg font-semibold text-sm transition-all bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-gray-900 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {move || if submitting.get() { "Creating..." } else { "Create Event" }}
                    </button>
                </form>
            </div>
        </div>
    }
}

/// Parse "YYYY-MM-DD" + "HH:MM" into a UNIX timestamp.
fn parse_datetime(date: &str, time: &str) -> Option<u64> {
    let datetime_str = format!("{}T{}:00", date, time);
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(&datetime_str));
    let ts = d.get_time();
    if ts.is_nan() {
        None
    } else {
        Some((ts / 1000.0) as u64)
    }
}
