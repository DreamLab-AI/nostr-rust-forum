//! Badge display components for profile pages and message author cards.
//!
//! - `BadgeIcon`: Single badge with icon, name, and tooltip.
//! - `BadgeBar`: Horizontal row of badge icons for message author cards.
//! - `BadgeGrid`: Grid layout for profile page badge section.

use leptos::prelude::*;

use crate::stores::badges::{badge_def, BadgeIcon as BadgeIconType, EarnedBadge};

// -- BadgeIconView: Single badge with tooltip ---------------------------------

/// Renders a single badge as an icon with tooltip on hover.
#[component]
pub fn BadgeIconView(
    /// Badge definition ID (e.g., "pioneer", "first-post").
    badge_id: String,
) -> impl IntoView {
    let def = badge_def(&badge_id);

    match def {
        Some(def) => {
            let icon_svg = badge_svg(def.icon);
            let cls = format!(
                "inline-flex items-center justify-center w-5 h-5 rounded-full {} cursor-default",
                def.color_class
            );
            let tooltip = format!("{}: {}", def.name, def.description);

            view! {
                <span class=cls title=tooltip>
                    {icon_svg}
                </span>
            }
            .into_any()
        }
        None => view! { <span></span> }.into_any(),
    }
}

// -- BadgeBar: Horizontal row for message author cards ------------------------

/// Horizontal row of badge icons shown next to author name in messages.
/// Displays up to `max` badges (default 3).
#[component]
pub fn BadgeBar(
    /// List of earned badge IDs to display.
    badge_ids: Signal<Vec<String>>,
    /// Maximum number of badges to show (default 3).
    #[prop(optional, default = 3)]
    max: usize,
) -> impl IntoView {
    view! {
        <span class="inline-flex items-center gap-0.5 ml-1">
            {move || {
                let ids = badge_ids.get();
                let visible: Vec<_> = ids.into_iter().take(max).collect();
                visible
                    .into_iter()
                    .map(|id| view! { <BadgeIconView badge_id=id /> })
                    .collect::<Vec<_>>()
            }}
        </span>
    }
}

// -- BadgeGrid: Grid layout for profile page ----------------------------------

/// Grid layout displaying all earned badges with names and descriptions.
/// Used on the profile page.
#[component]
pub fn BadgeGrid(
    /// Earned badges to display.
    badges: Signal<Vec<EarnedBadge>>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <h2 class="text-xs text-gray-500 font-medium">"Badges"</h2>
            <Show
                when=move || !badges.get().is_empty()
                fallback=|| view! {
                    <p class="text-sm text-gray-600">"No badges earned yet"</p>
                }
            >
                <div class="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {move || {
                        badges.get().into_iter().map(|earned| {
                            let bid = earned.badge_id.clone();
                            view! { <BadgeCard badge_id=bid awarded_at=earned.awarded_at /> }
                        }).collect::<Vec<_>>()
                    }}
                </div>
            </Show>
        </div>
    }
}

// -- BadgeCard: Individual badge in the grid ----------------------------------

/// Single badge card for the grid layout.
#[component]
fn BadgeCard(
    badge_id: String,
    awarded_at: u64,
) -> impl IntoView {
    let def = badge_def(&badge_id);

    match def {
        Some(def) => {
            let icon_svg = badge_svg(def.icon);
            let border_cls = match def.icon {
                BadgeIconType::Pioneer => "border-amber-500/20",
                BadgeIconType::FirstPost => "border-green-500/20",
                BadgeIconType::Conversationalist => "border-blue-500/20",
                BadgeIconType::Contributor => "border-purple-500/20",
                BadgeIconType::Helpful => "border-pink-500/20",
                BadgeIconType::Explorer => "border-cyan-500/20",
                BadgeIconType::Trusted => "border-emerald-500/20",
                BadgeIconType::FoundingMember => "border-orange-500/20",
                BadgeIconType::Moderator => "border-red-500/20",
                BadgeIconType::OG => "border-yellow-500/20",
            };
            let cls = format!(
                "bg-gray-800/50 border {} rounded-xl p-3 flex flex-col items-center gap-1.5 text-center hover:bg-gray-800/80 transition-colors",
                border_cls
            );
            let icon_cls = format!("w-6 h-6 {}", def.color_class);
            let date = format_date(awarded_at);

            view! {
                <div class=cls>
                    <div class=icon_cls>{icon_svg}</div>
                    <div class="text-xs font-medium text-white">{def.name}</div>
                    <div class="text-[10px] text-gray-500 leading-tight">{def.description}</div>
                    <div class="text-[10px] text-gray-600">{date}</div>
                </div>
            }
            .into_any()
        }
        None => view! { <div></div> }.into_any(),
    }
}

// -- Badge SVG icons ----------------------------------------------------------

/// Render the SVG icon for a badge type.
fn badge_svg(icon: BadgeIconType) -> impl IntoView {
    match icon {
        BadgeIconType::Pioneer => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M3 3v1.5M3 21v-6m0 0l2.77-.693a9 9 0 016.208.682l.108.054a9 9 0 006.086.71l3.114-.732a48.524 48.524 0 01-.005-10.499l-3.11.732a9 9 0 01-6.085-.711l-.108-.054a9 9 0 00-6.208-.682L3 4.5M3 15V4.5"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::FirstPost => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::Conversationalist => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 01-.825-.242m9.345-8.334a2.126 2.126 0 00-.476-.095 48.64 48.64 0 00-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0011.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::Contributor => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::Helpful => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M21 8.25c0-2.485-2.099-4.5-4.688-4.5-1.935 0-3.597 1.126-4.312 2.733-.715-1.607-2.377-2.733-4.313-2.733C5.1 3.75 3 5.765 3 8.25c0 7.22 9 12 9 12s9-4.78 9-12z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::Explorer => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::Trusted => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::FoundingMember => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z"
                    stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M12 18a3.75 3.75 0 00.495-7.467 5.99 5.99 0 00-1.925 3.546 5.974 5.974 0 01-2.133-1A3.75 3.75 0 0012 18z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::Moderator => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        BadgeIconType::OG => view! {
            <svg class="w-full h-full" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M16.5 18.75h-9m9 0a3 3 0 013 3h-15a3 3 0 013-3m9 0v-3.375c0-.621-.503-1.125-1.125-1.125h-.871M7.5 18.75v-3.375c0-.621.504-1.125 1.125-1.125h.872m5.007 0H9.497m5.007 0a7.454 7.454 0 01-.982-3.172M9.497 14.25a7.454 7.454 0 00.981-3.172M5.25 4.236c-.982.143-1.954.317-2.916.52A6.003 6.003 0 007.73 9.728M5.25 4.236V4.5c0 2.108.966 3.99 2.48 5.228M5.25 4.236V2.721C7.456 2.41 9.71 2.25 12 2.25c2.291 0 4.545.16 6.75.47v1.516M18.75 4.236c.982.143 1.954.317 2.916.52A6.003 6.003 0 0016.27 9.728M18.75 4.236V4.5c0 2.108-.966 3.99-2.48 5.228m0 0a6.023 6.023 0 01-2.77.677h-.5a6.023 6.023 0 01-2.77-.677"
                    stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
    }
}

// -- Helpers ------------------------------------------------------------------

/// Format a UNIX timestamp as a short date string.
fn format_date(ts: u64) -> String {
    let date = js_sys::Date::new_0();
    date.set_time((ts as f64) * 1000.0);
    let month = date.get_month() + 1;
    let day = date.get_date();
    let year = date.get_full_year();
    format!("{:02}/{:02}/{}", month, day, year)
}
