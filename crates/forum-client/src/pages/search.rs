//! Search page -- global forum search entry point.
//!
//! Route: /search

use leptos::prelude::*;

/// Search page with global search prompt.
#[component]
pub fn SearchPage() -> impl IntoView {
    view! {
        <div class="max-w-5xl mx-auto p-4 sm:p-6">
            <h1 class="text-3xl font-bold text-white mb-4">"Search"</h1>
            <p class="text-gray-400">"Use Cmd/Ctrl+K for global search, or browse channels and forums."</p>
        </div>
    }
}
