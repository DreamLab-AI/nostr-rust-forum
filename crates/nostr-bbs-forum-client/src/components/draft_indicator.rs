//! Small "Draft saved" pill that appears when a draft exists for a channel.

use gloo::storage::Storage as _;
use leptos::prelude::*;

/// Tiny amber pill indicating a draft is saved in localStorage.
#[component]
pub fn DraftIndicator(
    /// The channel ID to check for a stored draft.
    #[prop(into)]
    channel_id: String,
    /// Reactive flag — `true` when a non-empty draft exists.
    has_draft: Memo<bool>,
) -> impl IntoView {
    let _ = channel_id; // reserved for future multi-draft UI

    view! {
        <Show when=move || has_draft.get()>
            <span class="inline-flex items-center gap-1 text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-full px-2 py-0.5">
                <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"
                        stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"
                        stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                "Draft saved"
            </span>
        </Show>
    }
}

/// Get the localStorage key for a channel draft.
pub fn draft_key(channel_id: &str) -> String {
    format!("draft:{}", channel_id)
}

/// Load a stored draft from localStorage. Returns `None` if absent or empty.
pub fn load_draft(channel_id: &str) -> Option<String> {
    let key = draft_key(channel_id);
    let val: String = gloo::storage::LocalStorage::get(&key).ok()?;
    if val.trim().is_empty() {
        None
    } else {
        Some(val)
    }
}

/// Save a draft to localStorage. Removes the key if content is empty.
pub fn save_draft(channel_id: &str, content: &str) {
    let key = draft_key(channel_id);
    if content.trim().is_empty() {
        let _ = gloo::storage::LocalStorage::delete(&key);
    } else {
        let _ = gloo::storage::LocalStorage::set(&key, content.to_string());
    }
}

/// Clear the stored draft for a channel.
pub fn clear_draft(channel_id: &str) {
    let key = draft_key(channel_id);
    gloo::storage::LocalStorage::delete(&key);
}
