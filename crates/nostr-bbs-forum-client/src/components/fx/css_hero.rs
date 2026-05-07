//! CSS-only fallback hero background for reduced-motion or no-canvas environments.
//!
//! Uses mesh gradients and ambient orbs with CSS animations only.

use leptos::prelude::*;

/// Pure CSS hero background with animated ambient orbs.
///
/// No canvas, no JS animation loop. Safe for `prefers-reduced-motion`.
/// The pulse animations are CSS-native and respect the OS setting.
#[component]
pub fn CSSFallbackHero() -> impl IntoView {
    view! {
        <div class="absolute inset-0 overflow-hidden" aria-hidden="true">
            // Deep navy mesh gradient
            <div class="absolute inset-0 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900" />

            // Amber ambient orb (top-left quadrant)
            <div
                class="absolute top-1/4 left-1/4 w-96 h-96 bg-amber-500/10 rounded-full blur-3xl animate-pulse"
            />

            // Orange ambient orb (bottom-right, offset phase)
            <div
                class="absolute bottom-1/3 right-1/3 w-64 h-64 bg-orange-500/10 rounded-full blur-3xl animate-pulse"
                style="animation-delay: 1s;"
            />

            // Subtle amber center orb (slowest phase)
            <div
                class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-48 h-48 bg-amber-400/5 rounded-full blur-2xl animate-pulse"
                style="animation-delay: 2s;"
            />

            // Faint edge gradient for depth
            <div class="absolute inset-0 bg-gradient-to-t from-gray-900/80 via-transparent to-gray-900/40" />
        </div>
    }
}
