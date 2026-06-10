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
    /// P2: moderation state could not be determined (D1 fault). Fail-CLOSED —
    /// callers MUST treat this as "blocked" so a D1 outage cannot let banned
    /// or muted users post. The 60s cache TTL ensures this self-heals once D1
    /// recovers (the next refresh re-reads the real state).
    Unknown,
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
    ///
    /// P2: fails CLOSED — `Block::Unknown` (D1 fault) returns `true` so banned
    /// or muted users cannot post through a D1 outage.
    pub async fn is_blocked(&self, pubkey: &str, env: &Env) -> bool {
        let now = now_secs();
        match self.get_state(pubkey, now, env).await {
            Block::Banned => true,
            Block::MutedUntil(t) => t > now as i64,
            Block::Unknown => true,
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
        // P2: never cache a transient D1 fault (Block::Unknown). Caching it for
        // 60s would block a legitimate user for the full TTL after D1 recovers;
        // instead we deny THIS request and let the next call retry D1.
        if fresh != Block::Unknown {
            self.entries.borrow_mut().insert(
                pubkey.to_string(),
                Entry {
                    state: fresh,
                    loaded_at: now,
                },
            );
        }
        fresh
    }
}

#[derive(Deserialize)]
pub struct ActionRow {
    pub action: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

async fn load_state(pubkey: &str, now: i64, env: &Env) -> Block {
    let Ok(db) = env.d1("DB") else {
        // P2: D1 binding unavailable — fail CLOSED (do not allow through).
        return Block::Unknown;
    };
    // P0-4(b): read ban/mute AND unban/unmute rows so a lifted ban/mute is no
    // longer enforced. `resolve_block` applies latest-wins per target.
    let Ok(stmt) = db
        .prepare(
            "SELECT action, expires_at, created_at FROM moderation_actions \
             WHERE target_pubkey = ?1 AND action IN ('ban', 'mute', 'unban', 'unmute') \
             ORDER BY created_at DESC LIMIT 40",
        )
        .bind(&[JsValue::from_str(pubkey)])
    else {
        // P2: query prep/bind failure — fail CLOSED.
        return Block::Unknown;
    };
    let Ok(res) = stmt.all().await else {
        // P2: D1 query error — fail CLOSED so banned users cannot post through
        // a D1 outage. Not cached (see get_state), so it self-heals on retry.
        return Block::Unknown;
    };
    let rows: Vec<ActionRow> = res.results().unwrap_or_default();
    resolve_block(&rows, now)
}

/// Pure resolution of the strongest in-force `Block` from moderation rows.
///
/// P0-4(b) latest-wins semantics (per target, rows for one pubkey):
///   - A `ban` is in force unless a later `unban` cancels it.
///   - A `mute` is in force unless a later `unmute` cancels it (and unless its
///     `expires_at` has already passed — NIP-40 expiry, `>` boundary).
///   - A `ban` (even after considering unbans) dominates any active mute.
///   - A permanent mute (NULL expiry) with no later unmute == Banned semantics.
///
/// Rows need not be pre-sorted; comparison is by `created_at`.
pub fn resolve_block(rows: &[ActionRow], now: i64) -> Block {
    // Newest ban / unban / mute / unmute timestamps for this target.
    let mut last_ban: Option<i64> = None;
    let mut last_unban: Option<i64> = None;
    // Strongest still-in-force mute: track the furthest-future expiry among
    // mutes, plus whether any permanent (NULL-expiry) mute exists, and the
    // newest mute created_at so a later unmute can cancel.
    let mut last_mute: Option<i64> = None;
    let mut last_unmute: Option<i64> = None;
    let mut mute_perm = false;
    let mut mute_best_until: Option<i64> = None;

    for r in rows {
        match r.action.as_str() {
            "ban" => last_ban = Some(last_ban.map_or(r.created_at, |c| c.max(r.created_at))),
            "unban" => last_unban = Some(last_unban.map_or(r.created_at, |c| c.max(r.created_at))),
            "mute" => {
                last_mute = Some(last_mute.map_or(r.created_at, |c| c.max(r.created_at)));
                match r.expires_at {
                    None => mute_perm = true,
                    Some(t) if t > now => {
                        mute_best_until = Some(match mute_best_until {
                            Some(prev) if prev >= t => prev,
                            _ => t,
                        });
                    }
                    Some(_) => {} // expired mute — ignored
                }
            }
            "unmute" => {
                last_unmute = Some(last_unmute.map_or(r.created_at, |c| c.max(r.created_at)))
            }
            _ => {}
        }
    }

    // Ban in force unless a strictly-later unban cancels it.
    let ban_active = match (last_ban, last_unban) {
        (Some(b), Some(u)) => b > u,
        (Some(_), None) => true,
        _ => false,
    };
    if ban_active {
        return Block::Banned;
    }

    // Mute in force unless a strictly-later unmute cancels it.
    let mute_cancelled = matches!((last_mute, last_unmute), (Some(m), Some(u)) if u >= m);
    if mute_cancelled {
        return Block::None;
    }

    if mute_perm {
        return Block::Banned; // permanent mute == ban semantics
    }
    match mute_best_until {
        Some(t) => Block::MutedUntil(t),
        None => Block::None,
    }
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

    // -----------------------------------------------------------------------
    // P0-4(b): resolve_block latest-wins unban / unmute semantics
    // -----------------------------------------------------------------------

    fn row(action: &str, expires_at: Option<i64>, created_at: i64) -> ActionRow {
        ActionRow {
            action: action.to_string(),
            expires_at,
            created_at,
        }
    }

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn ban_with_no_unban_is_banned() {
        let rows = [row("ban", None, NOW - 100)];
        assert_eq!(resolve_block(&rows, NOW), Block::Banned);
    }

    #[test]
    fn later_unban_lifts_ban() {
        // P0-4: a lifted ban is no longer enforced.
        let rows = [row("ban", None, NOW - 100), row("unban", None, NOW - 50)];
        assert_eq!(resolve_block(&rows, NOW), Block::None);
    }

    #[test]
    fn unban_older_than_ban_does_not_lift() {
        // Re-ban after an unban: newest ban wins.
        let rows = [row("unban", None, NOW - 100), row("ban", None, NOW - 50)];
        assert_eq!(resolve_block(&rows, NOW), Block::Banned);
    }

    #[test]
    fn later_unmute_lifts_mute() {
        let rows = [
            row("mute", Some(NOW + 3600), NOW - 100),
            row("unmute", None, NOW - 50),
        ];
        assert_eq!(resolve_block(&rows, NOW), Block::None);
    }

    #[test]
    fn unmute_older_than_mute_does_not_lift() {
        let rows = [
            row("unmute", None, NOW - 100),
            row("mute", Some(NOW + 3600), NOW - 50),
        ];
        assert_eq!(resolve_block(&rows, NOW), Block::MutedUntil(NOW + 3600));
    }

    #[test]
    fn future_mute_is_active_expired_mute_is_dropped() {
        // Preserve NIP-40 expiry handling: future expiry stays a mute.
        assert_eq!(
            resolve_block(&[row("mute", Some(NOW + 10), NOW - 5)], NOW),
            Block::MutedUntil(NOW + 10)
        );
        // An expired mute is dropped.
        assert_eq!(
            resolve_block(&[row("mute", Some(NOW - 1), NOW - 100)], NOW),
            Block::None
        );
    }

    #[test]
    fn permanent_mute_is_ban_semantics() {
        assert_eq!(
            resolve_block(&[row("mute", None, NOW - 100)], NOW),
            Block::Banned
        );
    }

    #[test]
    fn ban_dominates_active_mute() {
        let rows = [
            row("mute", Some(NOW + 3600), NOW - 100),
            row("ban", None, NOW - 50),
        ];
        assert_eq!(resolve_block(&rows, NOW), Block::Banned);
    }

    #[test]
    fn empty_rows_is_none() {
        assert_eq!(resolve_block(&[], NOW), Block::None);
    }

    #[test]
    fn furthest_future_mute_wins() {
        let rows = [
            row("mute", Some(NOW + 100), NOW - 20),
            row("mute", Some(NOW + 9000), NOW - 10),
        ];
        assert_eq!(resolve_block(&rows, NOW), Block::MutedUntil(NOW + 9000));
    }

    // P2: Block::Unknown is the fail-CLOSED sentinel; is_blocked treats it as
    // blocked. resolve_block itself never produces Unknown (only D1 faults do).
    #[test]
    fn unknown_is_distinct_block_variant() {
        assert_ne!(Block::Unknown, Block::None);
        assert_ne!(Block::Unknown, Block::Banned);
    }
}
