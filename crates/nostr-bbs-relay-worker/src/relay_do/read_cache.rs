//! Per-Durable-Object read caches and the activity throttle (ADR-2018).
//!
//! # Why this module exists
//!
//! Before it, the cost of serving one `REQ` scaled with the number of events
//! delivered, not with the number of requests: `authorize_event` ran two D1
//! queries for every kind-40/42 event it let through (`channel_zones` for the
//! channel, then the viewer's whitelist row again for zone access), and
//! `resolve_viewer_context` re-read the viewer's device-owner and cohort rows on
//! every frame. A forum tab opening a 50-message channel cost ~110 D1 queries;
//! a client re-sending a subscription every 15 seconds cost seven queries and
//! three writes a time. On a production instance that alone consumed ~70% of
//! D1's free-tier daily row-read budget before a single human read anything,
//! and one busy evening exhausted it — the relay then served nothing to anyone
//! until midnight UTC.
//!
//! # What it does
//!
//! - [`TtlCache`]: a small per-DO memo with a fixed time-to-live, used for the
//!   three lookups that are stable over seconds but were being re-read per
//!   frame or per event: channel → zone, pubkey → (cohorts, is_admin), and
//!   device key → owner. The 60-second TTL matches the existing moderation
//!   cache: a cohort revocation or zone re-binding is honoured within a minute,
//!   which is the same self-heal window the mod cache already accepts. Negative
//!   channel-zone results are **not** cached: a channel that is not yet bound to
//!   a zone must not be remembered as unscoped for a minute after it is bound.
//! - [`ActivityLedger`]: coalesces the per-frame trust writes. Delivered read
//!   counts accumulate in memory and are flushed together with the
//!   `last_active_at` stamp and promotion check at most once per pubkey per
//!   [`ACTIVITY_FLUSH_SECS`], or sooner once [`PENDING_READS_FLUSH_AT`] reads
//!   are pending. The stamps are activity *signals* for the six-month
//!   inactivity sweep and TL0→TL1 promotion, so a five-minute delay is
//!   invisible; a DO eviction can drop at most one window of pending reads.
//!
//! Everything here is pure over an explicit `now` so it is unit-tested
//! natively, without the Workers runtime.

use std::cell::RefCell;
use std::collections::HashMap;

/// Time-to-live for the lookup caches (seconds).
pub(crate) const LOOKUP_TTL_SECS: u64 = 60;

/// Minimum interval between trust-ledger flushes for one pubkey (seconds).
pub(crate) const ACTIVITY_FLUSH_SECS: u64 = 300;

/// Pending delivered-read count that forces an early flush.
pub(crate) const PENDING_READS_FLUSH_AT: i32 = 50;

struct Entry<V> {
    value: V,
    fetched_at: u64,
}

/// A string-keyed memo whose entries expire `ttl_secs` after they were stored.
pub(crate) struct TtlCache<V: Clone> {
    entries: RefCell<HashMap<String, Entry<V>>>,
    ttl_secs: u64,
}

impl<V: Clone> TtlCache<V> {
    pub(crate) fn new(ttl_secs: u64) -> Self {
        Self {
            entries: RefCell::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// The cached value for `key` if it was stored less than the TTL ago.
    pub(crate) fn get(&self, key: &str, now: u64) -> Option<V> {
        let entries = self.entries.borrow();
        let entry = entries.get(key)?;
        if now.saturating_sub(entry.fetched_at) < self.ttl_secs {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    pub(crate) fn insert(&self, key: &str, value: V, now: u64) {
        self.entries.borrow_mut().insert(
            key.to_string(),
            Entry {
                value,
                fetched_at: now,
            },
        );
    }

    /// Forget `key` so the next lookup goes back to D1.
    #[allow(dead_code)]
    pub(crate) fn invalidate(&self, key: &str) {
        self.entries.borrow_mut().remove(key);
    }
}

/// Coalesces per-frame trust-ledger writes into one flush per pubkey per window.
pub(crate) struct ActivityLedger {
    last_flush: RefCell<HashMap<String, u64>>,
    pending_reads: RefCell<HashMap<String, i32>>,
}

/// What the caller must write to D1 after recording activity.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Flush {
    /// Delivered reads accumulated since the last flush (may be 0 on a
    /// write-only flush).
    pub reads: i32,
}

impl ActivityLedger {
    pub(crate) fn new() -> Self {
        Self {
            last_flush: RefCell::new(HashMap::new()),
            pending_reads: RefCell::new(HashMap::new()),
        }
    }

    /// Record `delivered` reads for `pubkey`. Returns `Some` when a flush is
    /// due — the first activity in a window, a window that has elapsed, or a
    /// pending count at or past [`PENDING_READS_FLUSH_AT`].
    pub(crate) fn record_read(&self, pubkey: &str, delivered: i32, now: u64) -> Option<Flush> {
        if delivered > 0 {
            *self
                .pending_reads
                .borrow_mut()
                .entry(pubkey.to_string())
                .or_insert(0) += delivered;
        }
        let pending = self
            .pending_reads
            .borrow()
            .get(pubkey)
            .copied()
            .unwrap_or(0);
        if self.window_elapsed(pubkey, now) || pending >= PENDING_READS_FLUSH_AT {
            Some(self.take(pubkey, now))
        } else {
            None
        }
    }

    /// Record a write (an accepted EVENT) for `pubkey`. Returns `Some` when the
    /// `last_active_at` stamp and promotion check are due.
    pub(crate) fn record_write(&self, pubkey: &str, now: u64) -> Option<Flush> {
        if self.window_elapsed(pubkey, now) {
            Some(self.take(pubkey, now))
        } else {
            None
        }
    }

    fn window_elapsed(&self, pubkey: &str, now: u64) -> bool {
        match self.last_flush.borrow().get(pubkey) {
            Some(last) => now.saturating_sub(*last) >= ACTIVITY_FLUSH_SECS,
            None => true,
        }
    }

    fn take(&self, pubkey: &str, now: u64) -> Flush {
        self.last_flush.borrow_mut().insert(pubkey.to_string(), now);
        let reads = self.pending_reads.borrow_mut().remove(pubkey).unwrap_or(0);
        Flush { reads }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_cache_serves_fresh_entries_and_expires_stale_ones() {
        let c: TtlCache<String> = TtlCache::new(60);
        assert_eq!(c.get("k", 1_000), None);
        c.insert("k", "v".into(), 1_000);
        assert_eq!(c.get("k", 1_059).as_deref(), Some("v"));
        assert_eq!(c.get("k", 1_060), None, "expires exactly at the TTL");
        c.insert("k", "v2".into(), 1_060);
        assert_eq!(c.get("k", 1_100).as_deref(), Some("v2"));
        c.invalidate("k");
        assert_eq!(c.get("k", 1_100), None);
    }

    #[test]
    fn ttl_cache_tolerates_clock_going_backwards() {
        let c: TtlCache<u8> = TtlCache::new(60);
        c.insert("k", 7, 5_000);
        assert_eq!(c.get("k", 4_000), Some(7));
    }

    #[test]
    fn first_read_in_a_window_flushes_immediately() {
        let l = ActivityLedger::new();
        assert_eq!(l.record_read("a", 3, 100), Some(Flush { reads: 3 }));
    }

    #[test]
    fn reads_inside_the_window_accumulate_and_flush_when_it_elapses() {
        let l = ActivityLedger::new();
        assert!(l.record_read("a", 1, 100).is_some());
        assert_eq!(l.record_read("a", 5, 101), None);
        assert_eq!(l.record_read("a", 6, 200), None);
        assert_eq!(
            l.record_read("a", 2, 100 + ACTIVITY_FLUSH_SECS),
            Some(Flush { reads: 13 })
        );
        assert_eq!(l.record_read("a", 1, 100 + ACTIVITY_FLUSH_SECS + 1), None);
    }

    #[test]
    fn a_large_pending_count_forces_an_early_flush() {
        let l = ActivityLedger::new();
        assert!(l.record_read("a", 1, 100).is_some());
        assert_eq!(l.record_read("a", PENDING_READS_FLUSH_AT - 1, 101), None);
        assert_eq!(
            l.record_read("a", 1, 102),
            Some(Flush {
                reads: PENDING_READS_FLUSH_AT
            })
        );
        assert_eq!(
            l.record_read("a", 1, 103),
            None,
            "window restarted at the early flush"
        );
    }

    #[test]
    fn writes_share_the_window_with_reads_and_carry_pending_reads() {
        let l = ActivityLedger::new();
        assert_eq!(l.record_write("a", 100), Some(Flush { reads: 0 }));
        assert_eq!(l.record_read("a", 4, 150), None);
        assert_eq!(l.record_write("a", 200), None);
        assert_eq!(
            l.record_write("a", 100 + ACTIVITY_FLUSH_SECS),
            Some(Flush { reads: 4 })
        );
    }

    #[test]
    fn pubkeys_are_throttled_independently() {
        let l = ActivityLedger::new();
        assert!(l.record_read("a", 1, 100).is_some());
        assert!(l.record_read("b", 1, 100).is_some());
        assert_eq!(l.record_read("a", 1, 101), None);
        assert_eq!(l.record_read("b", 1, 101), None);
    }

    #[test]
    fn a_zero_delivery_read_never_adds_pending_but_still_respects_the_window() {
        let l = ActivityLedger::new();
        assert_eq!(l.record_read("a", 0, 100), Some(Flush { reads: 0 }));
        assert_eq!(l.record_read("a", 0, 101), None);
    }
}
