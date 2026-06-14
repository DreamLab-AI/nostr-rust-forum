//! Compact inline user display component.
//!
//! Shows a small identicon avatar and display name (or shortened pubkey) in a
//! single-line layout. Used in message headers, user lists, and other compact
//! contexts. Resolves display names from a layered cache:
//!
//!   1. `ProfileCache` (kind-0 metadata, batch-fetched from relay-worker).
//!   2. Legacy `NameCache` string overrides (still populated by some flows).
//!   3. Shortened hex pubkey fallback (`shorten_pubkey`).
//!
//! Display name precedence (per Sprint v10 plan):
//!   `display_name` > `name` > NIP-05 handle > shortened pubkey.

use std::collections::HashMap;

use leptos::prelude::*;

use crate::stores::profile_cache::{try_use_profile_cache, ProfileCache};
use crate::utils::shorten_pubkey;

// -- Name cache context -------------------------------------------------------

/// Shared name cache: maps hex pubkey -> display name.
/// Provided at the app level; components can read from and write to it.
///
/// This legacy override layer remains in place so callers that already wrote
/// nicknames (e.g. via NIP-05 lookups) continue to work. The richer
/// `ProfileCache` is consulted first.
#[derive(Clone, Copy)]
pub struct NameCache(pub RwSignal<HashMap<String, String>>);

/// Provide the name cache context. Call once at the app root.
pub fn provide_name_cache() {
    provide_context(NameCache(RwSignal::new(HashMap::new())));
}

/// Get the name cache from context. Returns None if not provided.
fn try_use_name_cache() -> Option<NameCache> {
    use_context::<NameCache>()
}

/// Resolve a pubkey to a display name through the layered caches.
///
/// Returns the best label available now. If the pubkey is not yet cached,
/// schedules a debounced batch fetch via `ProfileCache` and returns the
/// shortened hex pubkey for display until the cache fills.
pub fn use_display_name(pubkey: &str) -> String {
    if pubkey.is_empty() {
        return String::new();
    }
    // Profile cache is the canonical source — display_name > name > NIP-05.
    if let Some(cache) = try_use_profile_cache() {
        if let Some(entry) = cache.lookup(pubkey) {
            if let Some(label) = entry.best_label() {
                return label;
            }
        }
    }
    // Legacy NameCache overrides (e.g. from prior NIP-05 lookups).
    if let Some(cache) = try_use_name_cache() {
        if let Some(name) = cache.0.get_untracked().get(pubkey).cloned() {
            return name;
        }
    }
    shorten_pubkey(pubkey)
}

/// Tracked (subscribing) layered lookup that returns `Some(label)` only when
/// a cache layer resolves a human label, and `None` while resolution is still
/// pending. Schedules the debounced batch fetch on a miss.
///
/// Call this INSIDE a reactive scope (a `Memo`, `Signal::derive`, or a
/// `move ||` view closure): it subscribes to the `ProfileCache` entries
/// signal and the legacy `NameCache`, so the enclosing closure re-runs when
/// the kind-0 metadata arrives. Use it when the caller wants to supply its
/// own fallback (e.g. the logged-in user's claimed nickname).
pub fn try_display_name_tracked(pubkey: &str) -> Option<String> {
    if pubkey.is_empty() {
        return None;
    }
    if let Some(cache) = try_use_profile_cache() {
        // Reactive read — subscribes to entries signal.
        if let Some(entry) = cache.lookup_reactive(pubkey) {
            if let Some(label) = entry.best_label() {
                return Some(label);
            }
        }
    }
    if let Some(cache) = try_use_name_cache() {
        if let Some(name) = cache.0.get().get(pubkey).cloned() {
            return Some(name);
        }
    }
    None
}

/// Tracked variant of `use_display_name` for call sites that already sit
/// inside a reactive closure (a `Memo`, `Signal::derive`, or a `move ||`
/// view closure). Subscribes to the caches, so the enclosing closure
/// re-runs and the name fills in when the batch fetcher completes.
/// Falls back to the shortened hex pubkey while resolution is pending.
pub fn use_display_name_tracked(pubkey: &str) -> String {
    try_display_name_tracked(pubkey).unwrap_or_else(|| shorten_pubkey(pubkey))
}

/// Reactive version of `use_display_name` for use inside `view!` macros.
///
/// Returns a `Memo<String>` that re-evaluates whenever the underlying
/// caches change. Use this whenever the value is rendered inside a closure
/// so the UI updates automatically when the batch fetcher completes.
pub fn use_display_name_memo(pubkey: String) -> Memo<String> {
    Memo::new(move |_| {
        if pubkey.is_empty() {
            return String::new();
        }
        use_display_name_tracked(&pubkey)
    })
}

/// Direct access to the underlying `ProfileCache`, for components that need
/// avatar URLs or NIP-05 verification badges in addition to the name.
#[allow(dead_code)]
pub fn use_profile_cache() -> Option<ProfileCache> {
    try_use_profile_cache()
}
