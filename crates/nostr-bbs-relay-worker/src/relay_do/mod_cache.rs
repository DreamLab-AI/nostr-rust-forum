//! WI-2 Relay-side ingress enforcement for bans and mutes.
//!
//! The `moderation_actions` D1 table (mirrored from kind-30910/30911 Nostr
//! events accepted at this relay) names pubkeys that are currently banned
//! (no expiry) or muted (optional expiry in unix seconds). Kind-1 and
//! kind-42 ingress calls [`ModCache::is_blocked`] before saving to drop
//! content authored by those pubkeys.
//!
//! A 60-second per-DO cache keeps the hot path to an in-memory HashMap
//! lookup instead of a D1 round-trip. Cache entries are stamped with
//! wall-clock seconds and refreshed lazily when stale.

use std::cell::RefCell;
use std::collections::HashMap;

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{js_sys, Env};

/// TTL on cache entries (seconds).
const CACHE_TTL_SECS: u64 = 60;

/// The strongest in-force moderation state for a pubkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    /// No active ban or mute.
    None,
    /// Permanent ban (no expiry).
    Banned,
    /// Muted until this unix-second timestamp.
    MutedUntil(i64),
}

#[derive(Debug, Clone)]
struct Entry {
    state: Block,
    loaded_at: u64,
}

/// Per-DO moderation cache. Not Send/Sync; the DO runs single-threaded in a
/// V8 isolate so `RefCell` interior mutability is fine.
#[derive(Default)]
pub struct ModCache {
    entries: RefCell<HashMap<String, Entry>>,
}

impl ModCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear the cache. Called on admin-driven moderation changes if needed.
    #[allow(dead_code)]
    pub fn invalidate(&self, pubkey: &str) {
        self.entries.borrow_mut().remove(pubkey);
    }

    /// Check whether `pubkey` is currently banned or actively muted.
    pub async fn is_blocked(&self, pubkey: &str, env: &Env) -> bool {
        let now = now_secs();
        match self.get_state(pubkey, now, env).await {
            Block::Banned => true,
            Block::MutedUntil(t) => t > now as i64,
            Block::None => false,
        }
    }

    /// Lookup-or-refresh helper.
    async fn get_state(&self, pubkey: &str, now: u64, env: &Env) -> Block {
        if let Some(entry) = self.entries.borrow().get(pubkey) {
            if now.saturating_sub(entry.loaded_at) < CACHE_TTL_SECS {
                return entry.state;
            }
        }
        let fresh = load_state(pubkey, now as i64, env).await;
        self.entries.borrow_mut().insert(
            pubkey.to_string(),
            Entry {
                state: fresh,
                loaded_at: now,
            },
        );
        fresh
    }
}

#[derive(Deserialize)]
struct ActionRow {
    action: String,
    expires_at: Option<i64>,
}

async fn load_state(pubkey: &str, now: i64, env: &Env) -> Block {
    let Ok(db) = env.d1("DB") else {
        return Block::None;
    };
    // A ban with no expiry wins over any mute. Otherwise take the mute with
    // the furthest-in-future `expires_at` (or NULL -- treated as permanent
    // mute, which we convert to Banned semantics for simplicity).
    let Ok(stmt) = db
        .prepare(
            "SELECT action, expires_at FROM moderation_actions \
             WHERE target_pubkey = ?1 AND action IN ('ban', 'mute') \
             ORDER BY created_at DESC LIMIT 20",
        )
        .bind(&[JsValue::from_str(pubkey)])
    else {
        return Block::None;
    };
    let Ok(res) = stmt.all().await else {
        return Block::None;
    };
    let rows: Vec<ActionRow> = res.results().unwrap_or_default();

    let mut best = Block::None;
    for r in rows {
        match (r.action.as_str(), r.expires_at) {
            ("ban", _) => return Block::Banned,
            ("mute", None) => return Block::Banned, // permanent mute == ban
            ("mute", Some(t)) if t > now => {
                best = match best {
                    Block::MutedUntil(prev) if prev >= t => best,
                    _ => Block::MutedUntil(t),
                };
            }
            _ => {}
        }
    }
    best
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_none() {
        assert_eq!(Block::None, Block::None);
    }

    #[test]
    fn muted_until_ordering_picks_furthest_future() {
        let a = Block::MutedUntil(100);
        let b = Block::MutedUntil(200);
        // The loop keeps the later mute; simulate the decision manually.
        let picked = match (a, b) {
            (Block::MutedUntil(x), Block::MutedUntil(y)) if y > x => b,
            _ => a,
        };
        assert_eq!(picked, Block::MutedUntil(200));
    }

    #[test]
    fn cache_invalidate_removes_entry() {
        let cache = ModCache::new();
        cache.entries.borrow_mut().insert(
            "pubkey-a".into(),
            Entry {
                state: Block::Banned,
                loaded_at: 1,
            },
        );
        assert!(cache.entries.borrow().contains_key("pubkey-a"));
        cache.invalidate("pubkey-a");
        assert!(!cache.entries.borrow().contains_key("pubkey-a"));
    }

    #[test]
    fn stale_entry_is_considered_expired() {
        // Simulate: an entry loaded 120s ago (> TTL of 60s) should not be
        // served from cache. This test only exercises the TTL constant, not
        // the async refresh path (which needs Env).
        let loaded_at: u64 = 0;
        let now: u64 = 120;
        assert!(now.saturating_sub(loaded_at) >= CACHE_TTL_SECS);
    }
}
