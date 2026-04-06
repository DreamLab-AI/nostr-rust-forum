//! Access denied component for zone-gated content.
//!
//! Displays a glassmorphism card with a lock icon, explains the required access
//! level, and offers a link back to forums.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;

/// Access denied page shown when a user lacks the required zone permissions.
#[component]
pub fn AccessDenied(
    /// The zone that was denied (e.g. "home", "members", "private").
    #[prop(default = "".to_string())]
    zone_id: String,
) -> impl IntoView {
    let (title, description) = match zone_id.as_str() {
        "home" => (
            "Members Only",
            "You need to be a registered member to access this area. Please log in or sign up.",
        ),
        "members" => (
            "Nostr BBS Access Required",
            "This section is restricted to Nostr BBS members. Contact an admin for access.",
        ),
        "private" => (
            "Private Access Required",
            "This section is restricted to Private guests. Contact an admin for access.",
        ),
        _ => ("Access Denied", "This content is not available."),
    };

    let show_login = zone_id.as_str() == "home" || zone_id.is_empty();

    let badge_class = match zone_id.as_str() {
        "home" => "text-amber-400 bg-amber-500/10 border-amber-500/20",
        "members" => "text-pink-400 bg-pink-500/10 border-pink-500/20",
        "private" => "text-purple-400 bg-purple-500/10 border-purple-500/20",
        _ => "text-gray-400 bg-gray-500/10 border-gray-500/20",
    };

    let zone_label = match zone_id.as_str() {
        "home" => "Home",
        "members" => "Nostr BBS",
        "private" => "Private",
        _ => "Restricted",
    };

    view! {
        <div class="flex items-center justify-center min-h-[60vh] p-4">
            <div class="relative max-w-md w-full">
                // Glass card
                <div class="glass-card p-8 text-center relative overflow-hidden">
                    // Ambient glow
                    <div class="absolute inset-0 bg-gradient-to-br from-red-500/5 via-transparent to-amber-500/5 pointer-events-none"></div>

                    <div class="relative z-10">
                        // Lock icon
                        <div class="w-16 h-16 mx-auto mb-6 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center">
                            <svg class="w-8 h-8 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <rect x="3" y="11" width="18" height="11" rx="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>

                        // Zone badge
                        <span class=format!(
                            "inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider border rounded-full px-2.5 py-0.5 mb-4 {}",
                            badge_class
                        )>
                            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            {zone_label}
                        </span>

                        <h2 class="text-2xl font-bold text-white mb-2">{title}</h2>
                        <p class="text-gray-400 text-sm leading-relaxed mb-6">{description}</p>

                        <div class="flex flex-col gap-3">
                            // Login button for home/unknown zones
                            {show_login.then(|| view! {
                                <A
                                    href=base_href("/login")
                                    attr:class="bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-6 py-2.5 rounded-lg transition-colors inline-block"
                                >
                                    "Log In"
                                </A>
                                <A
                                    href=base_href("/signup")
                                    attr:class="border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-6 py-2.5 rounded-lg transition-colors inline-block"
                                >
                                    "Sign Up"
                                </A>
                            })}

                            // Back to forums
                            <A
                                href=base_href("/forums")
                                attr:class="text-sm text-gray-400 hover:text-amber-400 transition-colors mt-2 inline-block"
                            >
                                "Back to Forums"
                            </A>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}
