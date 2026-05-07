//! "Mark all read" button component.
//!
//! Displays a compact button that, when clicked, fires the provided callback
//! so the parent can mark all channels as read via the read_position store.

use leptos::prelude::*;

#[component]
pub fn MarkAllRead(on_click: Callback<()>) -> impl IntoView {
    view! {
        <button
            class="text-xs text-amber-400/70 hover:text-amber-400 transition-colors flex items-center gap-1"
            on:click=move |_| on_click.run(())
            title="Mark all channels as read"
        >
            <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            "Mark all read"
        </button>
    }
}
