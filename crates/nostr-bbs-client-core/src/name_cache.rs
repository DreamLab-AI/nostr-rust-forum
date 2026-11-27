//! Layered display-name cache shared across browser clients.
//!
//! Resolves display names in precedence order:
//! `ProfileCache` (`display_name` > `name` > NIP-05) > legacy `NameCache`
//! overrides > shortened canonical pubkey.

use std::collections::HashMap;

use leptos::prelude::*;

use crate::stores::profile_cache::{try_use_profile_cache, ProfileCache};
use crate::utils::shorten_pubkey;

/// Shared legacy name cache: maps hex pubkey -> display name.
#[derive(Clone, Copy)]
pub struct NameCache(pub RwSignal<HashMap<String, String>>);

/// Provide the name cache context. Call once at the app root.
pub fn provide_name_cache() {
    provide_context(NameCache(RwSignal::new(HashMap::new())));
}

/// Get the name cache from context. Returns `None` if not provided.
pub fn try_use_name_cache() -> Option<NameCache> {
    use_context::<NameCache>()
}

/// The identity `pubkey` is displayed as: its successor (one hop) when the
/// key was replaced, else itself. Tracked; no network.
pub fn canonical_pubkey(pubkey: &str) -> String {
    match try_use_profile_cache() {
        Some(cache) if !pubkey.is_empty() => cache.canonical_tracked(pubkey),
        _ => pubkey.to_string(),
    }
}

/// [`canonical_pubkey`] without subscribing (for one-off strings).
fn canonical_untracked(pubkey: &str) -> String {
    match try_use_profile_cache() {
        Some(cache) => cache
            .successor_of(pubkey)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| pubkey.to_string()),
        None => pubkey.to_string(),
    }
}

/// Untracked layered lookup returning the best label or shortened pubkey.
pub fn use_display_name(pubkey: &str) -> String {
    if pubkey.is_empty() {
        return String::new();
    }
    try_display_name(pubkey).unwrap_or_else(|| shorten_pubkey(&canonical_untracked(pubkey)))
}

/// Untracked layered lookup: `Some(label)` when resolved, `None` otherwise.
pub fn try_display_name(pubkey: &str) -> Option<String> {
    if pubkey.is_empty() {
        return None;
    }
    if let Some(cache) = try_use_profile_cache() {
        if let Some(entry) = cache.lookup(pubkey) {
            if let Some(label) = entry.best_label() {
                return Some(label);
            }
        }
    }
    if let Some(cache) = try_use_name_cache() {
        let canonical = canonical_untracked(pubkey);
        let names = cache.0.get_untracked();
        if let Some(name) = names.get(&canonical).or_else(|| names.get(pubkey)).cloned() {
            return Some(name);
        }
    }
    None
}

/// Tracked (subscribing) layered lookup returning `Some(label)` when resolved.
pub fn try_display_name_tracked(pubkey: &str) -> Option<String> {
    if pubkey.is_empty() {
        return None;
    }
    if let Some(cache) = try_use_profile_cache() {
        if let Some(entry) = cache.lookup_reactive(pubkey) {
            if let Some(label) = entry.best_label() {
                return Some(label);
            }
        }
    }
    if let Some(cache) = try_use_name_cache() {
        let canonical = canonical_pubkey(pubkey);
        let names = cache.0.get();
        if let Some(name) = names.get(&canonical).or_else(|| names.get(pubkey)).cloned() {
            return Some(name);
        }
    }
    None
}

/// Tracked display name falling back to shortened canonical pubkey.
pub fn use_display_name_tracked(pubkey: &str) -> String {
    try_display_name_tracked(pubkey).unwrap_or_else(|| shorten_pubkey(&canonical_pubkey(pubkey)))
}

/// Reactive `Memo<String>` resolving a pubkey's display name.
pub fn use_display_name_memo(pubkey: String) -> Memo<String> {
    Memo::new(move |_| {
        if pubkey.is_empty() {
            return String::new();
        }
        use_display_name_tracked(&pubkey)
    })
}

/// Direct access to the underlying `ProfileCache`.
pub fn use_profile_cache() -> Option<ProfileCache> {
    try_use_profile_cache()
}
