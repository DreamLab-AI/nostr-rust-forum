//! Compact channel statistics bar.
//!
//! Shows message count, member count, and optional creation date in a
//! glass pill style. Intended for the channel header area.

use leptos::prelude::*;

/// Format a UNIX timestamp as "Mon DD" (e.g. "Mar 1").
fn format_date_short(ts: u64) -> String {
    if ts == 0 {
        return String::new();
    }
    let date = js_sys::Date::new_0();
    date.set_time((ts as f64) * 1000.0);
    let month = date.get_month();
    let day = date.get_date();
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_name = months.get(month as usize).unwrap_or(&"???");
    format!("{} {}", month_name, day)
}

/// Compact stats bar for a channel header.
///
/// Displays message count, member count, and creation date as a glass pill.
#[component]
pub fn ChannelStats(
    message_count: Signal<u32>,
    member_count: Signal<u32>,
    #[prop(optional)] created_at: Option<u64>,
) -> impl IntoView {
    view! {
        <div class="inline-flex items-center gap-2 text-xs text-gray-400 bg-gray-800/60 border border-gray-700/50 rounded-full px-3 py-1 backdrop-blur-sm">
            // Message count
            <span class="flex items-center gap-1">
                <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"
                        stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                {move || format!("{} messages", message_count.get())}
            </span>

            <span class="text-gray-600">"·"</span>

            // Member count
            <span class="flex items-center gap-1">
                <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"
                        stroke-linecap="round" stroke-linejoin="round"/>
                    <circle cx="9" cy="7" r="4" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                {move || format!("{} members", member_count.get())}
            </span>

            // Creation date (if provided)
            {created_at.map(|ts| {
                let date_str = format_date_short(ts);
                if date_str.is_empty() {
                    None
                } else {
                    Some(view! {
                        <span class="text-gray-600">"·"</span>
                        <span>{"Created "}{date_str}</span>
                    })
                }
            }).flatten()}
        </div>
    }
}
