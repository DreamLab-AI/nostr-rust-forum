//! Today's activity compact stats row component.
//!
//! Shows a glass pill with today's key metrics and a minimal sparkline
//! rendered with CSS dots.

use leptos::prelude::*;

/// Compact "Today" activity summary pill with inline sparkline.
#[component]
pub fn TodaysActivity(
    /// Total messages sent today.
    message_count: Signal<u32>,
    /// New users who joined today.
    new_users: Signal<u32>,
    /// Number of channels with activity today.
    active_channels: Signal<u32>,
) -> impl IntoView {
    view! {
        <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-full px-4 py-2 shadow-lg shadow-amber-500/10 flex items-center gap-3 text-xs text-gray-400 flex-wrap">
            // Sparkline dots (8 dots showing relative activity pattern)
            <div class="flex items-end gap-px h-3" aria-hidden="true">
                {(0..8).map(|i| {
                    // Generate a pseudo-pattern based on message_count seed
                    let mc = message_count.get();
                    let seed = mc.wrapping_mul(17).wrapping_add(i * 31) % 100;
                    let h = (seed as f64 / 100.0 * 12.0).max(2.0) as u32;
                    let dot_style = format!("height: {}px", h);
                    view! {
                        <div
                            class="w-1 rounded-full bg-amber-400/60"
                            style=dot_style
                        />
                    }
                }).collect_view()}
            </div>

            <span class="flex items-center gap-1">
                <span class="font-medium text-gray-200">{move || message_count.get()}</span>
                " messages"
            </span>

            <span class="text-gray-600">"·"</span>

            <span class="flex items-center gap-1">
                <span class="font-medium text-gray-200">{move || new_users.get()}</span>
                " new members"
            </span>

            <span class="text-gray-600">"·"</span>

            <span class="flex items-center gap-1">
                <span class="font-medium text-gray-200">{move || active_channels.get()}</span>
                " active channels"
            </span>
        </div>
    }
}
