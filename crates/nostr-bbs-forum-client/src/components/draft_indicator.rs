//! Small "Draft saved" pill that appears when a draft exists for a channel.

use gloo::storage::Storage as _;
use leptos::prelude::*;

use crate::zone_crypto::key_owner::Owner;

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

// -- Draft storage -------------------------------------------------------------
//
// Drafts are kept per signed-in identity: unsent text, including text typed
// into an encrypted zone, must never be offered to the next account that opens
// the channel on this browser. Drafts written before this (`draft:<channel>`)
// cannot be attributed to an account and are dropped once, at start-up
// ([`drop_legacy_drafts`]); keeping them would hand one account's unsent text
// to whoever opened the channel next, which is worse than losing a draft.

/// Prefix of every draft key, old and new.
const DRAFT_PREFIX: &str = "draft:";
/// Prefix of an owner-scoped draft key.
const DRAFT_PREFIX_V2: &str = "draft:v2:";

/// The localStorage key of `owner`'s draft for a channel.
pub fn draft_key(owner: &Owner, channel_id: &str) -> String {
    format!("{DRAFT_PREFIX_V2}{owner}:{channel_id}")
}

/// Whether `key` is a draft written before drafts had owners.
pub fn is_legacy_draft_key(key: &str) -> bool {
    key.starts_with(DRAFT_PREFIX) && !key.starts_with(DRAFT_PREFIX_V2)
}

/// Load `owner`'s stored draft for a channel. `None` if absent or empty.
pub fn load_draft(owner: &Owner, channel_id: &str) -> Option<String> {
    let val: String = gloo::storage::LocalStorage::get(draft_key(owner, channel_id)).ok()?;
    if val.trim().is_empty() {
        None
    } else {
        Some(val)
    }
}

/// Save `owner`'s draft for a channel. Removes the key if content is empty.
pub fn save_draft(owner: &Owner, channel_id: &str, content: &str) {
    let key = draft_key(owner, channel_id);
    if content.trim().is_empty() {
        gloo::storage::LocalStorage::delete(&key);
    } else {
        let _ = gloo::storage::LocalStorage::set(&key, content.to_string());
    }
}

/// Clear `owner`'s stored draft for a channel.
pub fn clear_draft(owner: &Owner, channel_id: &str) {
    gloo::storage::LocalStorage::delete(draft_key(owner, channel_id));
}

/// Delete every draft written before drafts had owners. Call once at start-up.
pub fn drop_legacy_drafts() {
    let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) else {
        return;
    };
    let len = storage.length().unwrap_or(0);
    let legacy: Vec<String> = (0..len)
        .filter_map(|i| storage.key(i).ok().flatten())
        .filter(|k| is_legacy_draft_key(k))
        .collect();
    for k in legacy {
        let _ = storage.remove_item(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_keys_are_per_owner_and_legacy_ones_are_recognised() {
        let a = Owner::parse(&"a".repeat(64)).expect("hex");
        let b = Owner::parse(&"b".repeat(64)).expect("hex");
        let chan = "c".repeat(64);
        assert_ne!(draft_key(&a, &chan), draft_key(&b, &chan));
        assert!(!is_legacy_draft_key(&draft_key(&a, &chan)));
        assert!(is_legacy_draft_key(&format!("draft:{chan}")));
        assert!(!is_legacy_draft_key("nostrbbs_bookmarks"));
        assert!(!is_legacy_draft_key("drafts-other"));
    }
}
