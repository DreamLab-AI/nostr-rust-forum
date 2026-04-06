//! Zone hero header component.
//!
//! Full-width glass banner with zone-specific gradient, title, and description.
//! Used at the top of category and section pages to visually identify the zone.

use leptos::prelude::*;

/// Visual hero header for different forum zones.
///
/// Renders a gradient glass banner with the zone's accent colour,
/// an optional lock icon for restricted zones, and the title/description.
#[component]
pub fn ZoneHero(
    title: String,
    description: String,
    /// Zone identifier: "home", "members", or "private".
    zone_id: String,
    /// SVG path data for the zone icon.
    icon: &'static str,
) -> impl IntoView {
    let gradient = match zone_id.as_str() {
        "home" => "from-amber-500/20 via-orange-500/10 to-yellow-500/10",
        "members" => "from-pink-500/20 via-rose-500/10 to-fuchsia-500/10",
        "private" => "from-purple-500/20 via-indigo-500/10 to-violet-500/10",
        _ => "from-gray-500/20 via-gray-500/10 to-gray-500/5",
    };

    let zone_label = match zone_id.as_str() {
        "home" => "Home",
        "members" => "Nostr BBS",
        "private" => "Private",
        _ => "Forum",
    };

    let border_color = match zone_id.as_str() {
        "home" => "border-amber-500/20",
        "members" => "border-pink-500/20",
        "private" => "border-purple-500/20",
        _ => "border-gray-500/20",
    };

    view! {
        <div class=format!(
            "relative mb-6 py-10 px-6 rounded-2xl overflow-hidden bg-gradient-to-br {} border {} backdrop-blur-sm",
            gradient, border_color
        )>
            // Ambient decorative orbs
            <div class="absolute -top-10 -right-10 w-40 h-40 rounded-full bg-white/5 blur-3xl" aria-hidden="true"></div>
            <div class="absolute -bottom-8 -left-8 w-32 h-32 rounded-full bg-white/3 blur-2xl" aria-hidden="true"></div>

            <div class="relative z-10 flex items-start gap-4">
                // Zone icon
                <div class="flex-shrink-0 w-12 h-12 rounded-xl bg-white/10 flex items-center justify-center">
                    <svg class="w-6 h-6 text-white/80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d=icon/>
                    </svg>
                </div>

                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 mb-1">
                        <h1 class="text-2xl sm:text-3xl font-bold text-white truncate">
                            {title}
                        </h1>
                        // Lock icon for non-home zones
                        {(zone_id.as_str() != "home").then(|| view! {
                            <svg class="w-4 h-4 text-white/50 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        })}
                    </div>
                    <p class="text-gray-300 text-sm sm:text-base line-clamp-2">
                        {description}
                    </p>
                    <span class="inline-block mt-2 text-xs font-medium text-white/50 bg-white/10 rounded-full px-2.5 py-0.5">
                        {zone_label}
                    </span>
                </div>
            </div>
        </div>
    }
}
