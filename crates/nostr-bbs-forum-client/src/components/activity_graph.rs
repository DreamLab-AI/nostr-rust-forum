//! 24-hour activity bar chart component.
//!
//! Renders a bar chart of message activity over the last 24 hours using
//! Tailwind-styled HTML divs. Includes hover tooltips and responsive layout.

use leptos::prelude::*;

/// A single data point representing activity in one hour.
#[derive(Clone, Debug)]
pub struct ActivityPoint {
    /// Hour of day (0-23).
    pub hour: u32,
    /// Number of messages in that hour.
    pub count: u32,
}

/// Bar chart showing hourly message activity over the last 24 hours.
///
/// Bars are rendered as divs with computed heights, amber gradient fills,
/// and hover tooltips showing exact counts.
#[component]
pub fn ActivityGraph(
    /// Activity data points, one per hour.
    data: Signal<Vec<ActivityPoint>>,
) -> impl IntoView {
    view! {
        <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-4 shadow-lg shadow-amber-500/10">
            <div class="flex items-center gap-2 mb-4">
                <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z"
                        stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <h3 class="text-sm font-semibold text-white">"Activity"</h3>
                <span class="text-[10px] text-gray-500 ml-auto">"24h"</span>
            </div>

            {move || {
                let points = data.get();
                if points.is_empty() {
                    return view! {
                        <p class="text-sm text-gray-500 text-center py-6">"No activity data"</p>
                    }.into_any();
                }

                let max_count = points.iter().map(|p| p.count).max().unwrap_or(1).max(1);

                view! {
                    <div class="flex items-end gap-px h-24">
                        {points.into_iter().map(|point| {
                            let height_pct = if max_count > 0 {
                                (point.count as f64 / max_count as f64 * 100.0) as u32
                            } else {
                                0
                            };
                            // Minimum visible height of 2% for non-zero counts
                            let bar_height = if point.count > 0 { height_pct.max(4) } else { 0 };
                            let bar_style = format!("height: {}%", bar_height);
                            let tooltip = format!("{:02}:00 - {} messages", point.hour, point.count);
                            let hour_label = format!("{}", point.hour);
                            let show_label = point.hour % 3 == 0;

                            view! {
                                <div class="flex-1 flex flex-col items-center gap-1 group" title=tooltip>
                                    <div class="w-full relative flex items-end" style="height: 72px">
                                        <div
                                            class="w-full rounded-t bg-gradient-to-t from-amber-500/60 to-amber-400/80 group-hover:from-amber-400 group-hover:to-orange-400 transition-colors duration-200"
                                            style=bar_style
                                        />
                                        // Tooltip on hover
                                        <div class="absolute -top-7 left-1/2 -translate-x-1/2 hidden group-hover:block bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-[10px] text-gray-200 whitespace-nowrap z-10">
                                            {point.count}
                                        </div>
                                    </div>
                                    {show_label.then(|| view! {
                                        <span class="text-[9px] text-gray-600">{hour_label}</span>
                                    })}
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
