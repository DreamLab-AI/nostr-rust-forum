//! Zone hero header component.
//!
//! Full-width glass banner with zone-specific gradient, title, and description.
//! Used at the top of category and section pages to visually identify the zone.

use leptos::prelude::*;

use crate::utils::zone_theme::{zone_accent_style, zone_theme};

/// Visual hero header for different forum zones.
///
/// Renders a gradient glass banner with the zone's accent colour (centralised in
/// [`crate::utils::zone_theme`]), an optional lock icon for restricted zones, and
/// the title/description. The container also exposes the zone accent as a
/// `--zone-accent` CSS custom property so descendant / sibling pages (chat,
/// thread) can pick up the zone identity without this component reaching into
/// them.
#[component]
pub fn ZoneHero(
    title: String,
    description: String,
    /// Zone identifier from the operator config: `"public"`, `"friends"`,
    /// `"family"`, `"business"` (legacy `home`/`members`/`private` aliases
    /// still themed). Drives the palette via `zone_theme`.
    zone_id: String,
    /// SVG path data for the zone icon.
    icon: &'static str,
    /// Optional zone banner image URL (each zone's configured `banner_image_url`,
    /// e.g. the public hero). Rendered behind the hero content with a dark
    /// overlay for legibility; falls back to the gradient when absent.
    #[prop(optional)]
    banner_url: Option<String>,
    /// Optional explicit zone display label (the operator `display_name`, e.g.
    /// "Business" for the business zone). Falls back to a humanised id when
    /// absent so the chip never shows a raw slug.
    #[prop(optional)]
    zone_label: Option<String>,
) -> impl IntoView {
    let theme = zone_theme(&zone_id);
    let gradient = theme.gradient;
    let border_color = theme.border;
    let accent_style = zone_accent_style(&zone_id);

    // The pill label: explicit operator display name, else humanise the id.
    let zone_label = zone_label
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| crate::utils::capitalize(&zone_id));

    // `public` (Landing) is the only open zone; everything else shows the lock.
    let is_open_zone = matches!(zone_id.as_str(), "public" | "home" | "landing");

    view! {
        <div
            class=format!(
                "relative mb-6 py-10 px-6 rounded-2xl overflow-hidden bg-gradient-to-br {} border {} backdrop-blur-sm",
                gradient, border_color
            )
            style=accent_style
        >
            // Zone banner image (behind content). A dark gradient overlay keeps
            // the title/description legible over the artwork.
            {banner_url.filter(|u| !u.is_empty()).map(|url| view! {
                <img
                    src=url alt="" loading="lazy" decoding="async" aria-hidden="true"
                    class="absolute inset-0 w-full h-full object-cover opacity-40"
                />
                <div
                    class="absolute inset-0 bg-gradient-to-t from-gray-900/85 via-gray-900/45 to-gray-900/20"
                    aria-hidden="true"
                ></div>
            })}
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
                        // Lock icon for restricted (non-public) zones.
                        {(!is_open_zone).then(|| view! {
                            <svg class="w-4 h-4 text-white/50 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        })}
                    </div>
                    <p class="text-gray-300 text-sm sm:text-base line-clamp-2">
                        {description}
                    </p>
                    // Zone label chip tinted with the zone accent (via the
                    // `--zone-accent` custom property set on the root container).
                    <span
                        class="inline-block mt-2 text-xs font-medium text-white/70 bg-white/10 rounded-full px-2.5 py-0.5"
                        style="border:1px solid color-mix(in srgb, var(--zone-accent) 50%, transparent)"
                    >
                        {zone_label}
                    </span>
                </div>
            </div>
        </div>
    }
}
