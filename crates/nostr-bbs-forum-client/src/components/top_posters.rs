//! Top posters leaderboard component.
//!
//! Shows the 10 most active users in the last 7 days with rank medals,
//! avatars, names, message counts, and proportional bar indicators.

use leptos::prelude::*;

use crate::components::avatar::{Avatar, AvatarSize};

/// Data for a single poster entry.
#[derive(Clone, Debug)]
pub struct PosterData {
    pub pubkey: String,
    pub name: String,
    pub message_count: u32,
    #[allow(dead_code)]
    pub avatar_url: Option<String>,
}

/// Leaderboard card showing top 10 most active posters.
#[component]
pub fn TopPosters(
    /// List of poster data sorted by message_count descending.
    posters: Signal<Vec<PosterData>>,
) -> impl IntoView {
    view! {
        <div class="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-4 shadow-lg shadow-amber-500/10">
            <div class="flex items-center gap-2 mb-4">
                <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M16.5 18.75h-9m9 0a3 3 0 013 3h-15a3 3 0 013-3m9 0v-3.375c0-.621-.503-1.125-1.125-1.125h-.871M7.5 18.75v-3.375c0-.621.504-1.125 1.125-1.125h.872m5.007 0H9.497m5.007 0a7.454 7.454 0 01-.982-3.172M9.497 14.25a7.454 7.454 0 00.981-3.172M5.25 4.236c-.982.143-1.954.317-2.916.52A6.003 6.003 0 007.73 9.728M5.25 4.236V4.5c0 2.108.966 3.99 2.48 5.228M5.25 4.236V2.721C7.456 2.41 9.71 2.25 12 2.25c2.291 0 4.545.16 6.75.47v1.516M18.75 4.236c.982.143 1.954.317 2.916.52A6.003 6.003 0 0016.27 9.728M18.75 4.236V4.5c0 2.108-.966 3.99-2.48 5.228m0 0a6.842 6.842 0 01-2.27.988 6.842 6.842 0 01-2.27-.988"
                        stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <h3 class="text-sm font-semibold text-white">"Top Posters"</h3>
                <span class="text-[10px] text-gray-500 ml-auto">"7-day"</span>
            </div>

            {move || {
                let list = posters.get();
                if list.is_empty() {
                    return view! {
                        <p class="text-sm text-gray-500 text-center py-4">"No activity yet"</p>
                    }.into_any();
                }

                let max_count = list.iter().map(|p| p.message_count).max().unwrap_or(1).max(1);

                view! {
                    <div class="space-y-1">
                        {list.into_iter().enumerate().take(10).map(|(i, poster)| {
                            let rank = i + 1;
                            let bar_pct = (poster.message_count as f64 / max_count as f64 * 100.0) as u32;
                            let bar_width = format!("width: {}%", bar_pct.max(4));
                            let pk = poster.pubkey.clone();

                            view! {
                                <div class="group flex items-center gap-2 p-2 rounded-lg hover:bg-white/5 transition-colors cursor-default">
                                    // Rank indicator
                                    <div class="w-6 text-center shrink-0">
                                        {match rank {
                                            1 => view! { <span class="text-sm" title="1st">"🥇"</span> }.into_any(),
                                            2 => view! { <span class="text-sm" title="2nd">"🥈"</span> }.into_any(),
                                            3 => view! { <span class="text-sm" title="3rd">"🥉"</span> }.into_any(),
                                            n => view! { <span class="text-xs text-gray-500">{n}</span> }.into_any(),
                                        }}
                                    </div>

                                    // Avatar
                                    <Avatar pubkey=pk size=AvatarSize::Sm />

                                    // Name + bar
                                    <div class="flex-1 min-w-0">
                                        <div class="text-sm text-gray-200 truncate">{poster.name.clone()}</div>
                                        <div class="h-1 mt-1 rounded-full bg-gray-800 overflow-hidden">
                                            <div
                                                class="h-full rounded-full bg-gradient-to-r from-amber-500 to-orange-500 transition-all duration-500"
                                                style=bar_width
                                            />
                                        </div>
                                    </div>

                                    // Count
                                    <span class="text-xs text-gray-400 tabular-nums shrink-0">
                                        {poster.message_count}
                                    </span>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
