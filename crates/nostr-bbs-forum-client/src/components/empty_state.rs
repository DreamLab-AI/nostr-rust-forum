//! Animated empty-state placeholder for lists with no content.
//!
//! Renders a glass card with a floating icon, title, description, and an
//! optional call-to-action button. Uses `animate-gentle-float` and ambient
//! orb classes from `style.css`.

use leptos::prelude::*;

/// Empty-state display for empty lists or sections.
///
/// The `icon` slot is wrapped in `animate-gentle-float` for a subtle bob.
/// An optional CTA button links to `action_href`.
#[component]
pub(crate) fn EmptyState(
    /// SVG or other icon content.
    icon: Children,
    /// Heading text.
    title: String,
    /// Explanatory paragraph.
    description: String,
    /// CTA button label.
    #[prop(optional)]
    action_label: Option<String>,
    /// CTA button destination.
    #[prop(optional)]
    action_href: Option<String>,
) -> impl IntoView {
    let has_action = action_label.is_some() && action_href.is_some();
    let label = action_label.unwrap_or_default();
    let href = action_href.unwrap_or_default();

    view! {
        <div class="flex items-center justify-center py-16 px-4">
            <div class="glass-card relative overflow-hidden text-center max-w-md w-full p-8">
                // Ambient orbs (subtle background glow)
                <div class="ambient-orb ambient-orb-1" aria-hidden="true"/>
                <div class="ambient-orb ambient-orb-3" aria-hidden="true"/>

                // Floating icon
                <div class="animate-gentle-float inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gray-800/60 border border-gray-700/50 text-gray-400 mb-5">
                    {icon()}
                </div>

                <h3 class="text-lg font-bold text-white mb-2">{title}</h3>
                <p class="text-sm text-gray-400 leading-relaxed mb-6">{description}</p>

                {has_action.then(|| view! {
                    <a
                        href=href.clone()
                        class="inline-flex items-center gap-2 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-5 py-2.5 rounded-lg transition-colors text-sm"
                    >
                        {label.clone()}
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M5 12h14M12 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </a>
                })}
            </div>
        </div>
    }
}
