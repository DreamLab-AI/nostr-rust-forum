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

use nostr_bbs_core::event::NostrEvent;
use std::cell::RefCell;
use std::collections::HashMap;

/// Time-to-live for the lookup caches (seconds).
pub(crate) const LOOKUP_TTL_SECS: u64 = 60;

/// TTL of negative memo entries ("no zone row", "target not stored"): short,
/// so a new binding or a late-arriving target takes effect within seconds.
pub(crate) const NEGATIVE_LOOKUP_TTL_SECS: u64 = 5;

/// Minimum interval between trust-ledger flushes for one pubkey (seconds).
pub(crate) const ACTIVITY_FLUSH_SECS: u64 = 300;

/// Pending delivered-read count that forces an early flush.
pub(crate) const PENDING_READS_FLUSH_AT: i32 = 50;

/// How long a channel/topic message-count snapshot is reused. A hit adds the
/// messages created after the snapshot with a cheap time-range query, so new
/// posts are counted. Not exact: a post stored after the snapshot with a
/// `created_at` at or before `as_of` (more than
/// [`COUNT_SNAPSHOT_MARGIN_SECS`] back-dated), and deletions, show only once
/// the snapshot expires.
pub(crate) const COUNT_CACHE_TTL_SECS: u64 = 300;

/// A snapshot covers messages up to this long before it was taken, so posts
/// arriving with a slightly old `created_at` (clock skew, slow sends) still
/// fall in the always-fresh delta.
pub(crate) const COUNT_SNAPSHOT_MARGIN_SECS: u64 = 120;

/// Most snapshots kept before the cache is emptied. Keys are 64-hex event
/// ids ([`count_key`]); each entry holds at most a few `(channel, n)` pairs
/// and [`snapshot_exceptions`]-bounded exception rows.
pub(crate) const COUNT_CACHE_MAX: usize = 1024;

/// Most exception rows a snapshot keeps, and their total size; past either,
/// the snapshot keeps none and they are read fresh each time.
const SNAPSHOT_EXCEPTIONS_MAX: usize = 16;
const SNAPSHOT_EXCEPTIONS_MAX_BYTES: usize = 32 * 1024;

/// A message count (see `filter::build_channel_count`), valid for every
/// message created at or before `as_of`: grouped counts, and the raw
/// exception rows (NIP-40 expiry is applied when served) when small enough.
#[derive(Debug, Clone)]
pub(crate) struct CountSnapshot {
    pub(crate) as_of: u64,
    pub(crate) groups: Vec<(String, u64)>,
    pub(crate) exceptions: Option<Vec<NostrEvent>>,
}

/// The exception rows a snapshot may keep: all of them when few and small,
/// else none (read fresh on each hit instead).
pub(crate) fn snapshot_exceptions(rows: &[NostrEvent]) -> Option<Vec<NostrEvent>> {
    let bytes: usize = rows
        .iter()
        .map(|e| e.content.len() + e.tags.iter().flatten().map(String::len).sum::<usize>())
        .sum();
    (rows.len() <= SNAPSHOT_EXCEPTIONS_MAX && bytes <= SNAPSHOT_EXCEPTIONS_MAX_BYTES)
        .then(|| rows.to_vec())
}

/// Whether a full count to `horizon` should become the snapshot: only one
/// reaching the present (minus the margin). A request with an old `until`
/// is answered but never replaces a newer snapshot with an older one.
pub(crate) fn should_store(horizon: u64, now: u64) -> bool {
    horizon == now.saturating_sub(COUNT_SNAPSHOT_MARGIN_SECS)
}

/// How to answer a grouped count for a request ending at `until` (`None`:
/// no upper bound), given the snapshot held for its `(value, since)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CountPlan {
    /// Add the messages created after the snapshot (`from` onward, up to the
    /// request's `until`) to it.
    Delta { from: u64 },
    /// Count up to `horizon` from scratch and keep that as the snapshot, then
    /// add anything after `horizon` the request still covers.
    Full { horizon: u64 },
}

/// The plan for a count ending at `until`, at time `now`. A snapshot serves
/// any request whose range reaches at least to its `as_of`; an older `until`
/// is counted from scratch, exactly.
pub(crate) fn plan_count(snap: Option<&CountSnapshot>, until: Option<u64>, now: u64) -> CountPlan {
    let reach = until.unwrap_or(u64::MAX);
    match snap {
        Some(s) if s.as_of <= reach => CountPlan::Delta {
            from: s.as_of.saturating_add(1),
        },
        _ => CountPlan::Full {
            horizon: reach.min(now.saturating_sub(COUNT_SNAPSHOT_MARGIN_SECS)),
        },
    }
}

/// Sum two grouped counts channel by channel, in first-seen order.
pub(crate) fn merge_groups(a: &[(String, u64)], b: &[(String, u64)]) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = a.to_vec();
    for (ch, n) in b {
        match out.iter_mut().find(|(c, _)| c == ch) {
            Some((_, m)) => *m += n,
            None => out.push((ch.clone(), *n)),
        }
    }
    out
}

/// The snapshot key of a count of `value` from `since`, or `None` when
/// `value` is not a lowercase 64-hex event id. Only real ids are cached: the
/// key's size is fixed, and it cannot contain the `|` separator.
pub(crate) fn count_key(value: &str, since: Option<u64>) -> Option<String> {
    let hex = value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    hex.then(|| match since {
        Some(s) => format!("{value}|{s}"),
        None => value.to_string(),
    })
}

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

    /// Number of entries held, expired ones included.
    pub(crate) fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Forget everything.
    pub(crate) fn clear(&self) {
        self.entries.borrow_mut().clear();
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

    fn snap(as_of: u64) -> CountSnapshot {
        CountSnapshot {
            as_of,
            groups: vec![("ch".into(), 200_000)],
            exceptions: None,
        }
    }

    #[test]
    fn a_count_snapshot_serves_any_request_reaching_its_horizon() {
        // The client asks "up to now": served from the snapshot plus newer.
        assert_eq!(
            plan_count(Some(&snap(1_000)), Some(1_030), 1_030),
            CountPlan::Delta { from: 1_001 }
        );
        assert_eq!(
            plan_count(Some(&snap(1_000)), None, 1_030),
            CountPlan::Delta { from: 1_001 }
        );
        // Exactly at the horizon: nothing newer to add, still a hit.
        assert_eq!(
            plan_count(Some(&snap(1_000)), Some(1_000), 1_030),
            CountPlan::Delta { from: 1_001 }
        );
        // An older `until` is counted from scratch (the snapshot would overcount).
        assert_eq!(
            plan_count(Some(&snap(1_000)), Some(900), 1_030),
            CountPlan::Full { horizon: 900 }
        );
        // No snapshot: count to the margin before now, never past it.
        let h = 1_030 - COUNT_SNAPSHOT_MARGIN_SECS;
        assert_eq!(
            plan_count(None, None, 1_030),
            CountPlan::Full { horizon: h }
        );
        assert_eq!(
            plan_count(None, Some(5_000), 1_030),
            CountPlan::Full { horizon: h }
        );
        assert_eq!(
            plan_count(None, Some(700), 1_030),
            CountPlan::Full { horizon: 700 }
        );
        // Only a count reaching the present becomes the snapshot.
        assert!(should_store(h, 1_030));
        assert!(!should_store(700, 1_030));
        assert!(!should_store(1, 1_030));
    }

    fn ev(content_len: usize) -> NostrEvent {
        NostrEvent {
            id: "i".into(),
            pubkey: "p".into(),
            created_at: 1,
            kind: 42,
            tags: vec![vec!["expiration".into(), "9".into()]],
            content: "x".repeat(content_len),
            sig: "s".into(),
        }
    }

    #[test]
    fn snapshots_keep_only_few_small_exception_rows() {
        assert_eq!(snapshot_exceptions(&[]).map(|v| v.len()), Some(0));
        assert_eq!(
            snapshot_exceptions(&[ev(10), ev(10)]).map(|v| v.len()),
            Some(2)
        );
        assert!(snapshot_exceptions(&vec![ev(1); 17]).is_none());
        assert!(snapshot_exceptions(&[ev(40_000)]).is_none());
    }

    #[test]
    fn grouped_counts_merge_per_channel() {
        let a = vec![("x".to_string(), 10), ("y".to_string(), 1)];
        let b = vec![("y".to_string(), 2), ("z".to_string(), 3)];
        assert_eq!(
            merge_groups(&a, &b),
            vec![
                ("x".to_string(), 10),
                ("y".to_string(), 3),
                ("z".to_string(), 3)
            ]
        );
        assert_eq!(merge_groups(&a, &[]), a);
        assert_eq!(merge_groups(&[], &b), b);
    }

    #[test]
    fn count_keys_are_only_for_hex_ids_and_never_collide() {
        let id = "a".repeat(64);
        assert_eq!(count_key(&id, None), Some(id.clone()));
        assert_eq!(count_key(&id, Some(5)), Some(format!("{id}|5")));
        assert_ne!(count_key(&id, Some(5)), count_key(&id, Some(6)));
        // Anything else takes the uncached path: no oversized or colliding keys.
        assert_eq!(count_key(&format!("{}|5", "a".repeat(62)), None), None);
        assert_eq!(count_key(&"A".repeat(64), None), None);
        assert_eq!(count_key(&"a".repeat(65), None), None);
        assert_eq!(count_key(&"a".repeat(100_000), None), None);
        assert_eq!(count_key("", None), None);
    }

    #[test]
    fn ttl_cache_len_and_clear() {
        let c: TtlCache<u8> = TtlCache::new(60);
        c.insert("a", 1, 0);
        c.insert("b", 2, 0);
        assert_eq!(c.len(), 2);
        c.clear();
        assert_eq!(c.len(), 0);
        assert_eq!(c.get("a", 0), None);
    }

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
