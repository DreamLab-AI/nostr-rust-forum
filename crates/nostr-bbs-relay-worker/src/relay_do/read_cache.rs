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

/// How long a snapshot stays in the per-isolate memory cache before it is
/// re-read from DO storage. The durable copy ([`persist_snapshot`]) is the
/// source of truth: the DO hibernates when idle and loses memory, which is
/// why an in-memory snapshot alone left every cold page load paying for a
/// full count (2026-11-26).
pub(crate) const COUNT_CACHE_TTL_SECS: u64 = 300;

/// A snapshot covers messages up to this long before it was taken, so posts
/// arriving with a slightly old `created_at` (clock skew, slow sends) still
/// fall in the always-fresh delta.
pub(crate) const COUNT_SNAPSHOT_MARGIN_SECS: u64 = 120;

/// Once a snapshot is this old it is rolled forward (the messages since are
/// folded in with a small range count) so deltas stay small.
pub(crate) const COUNT_ROLL_SECS: u64 = 600;

/// A request ending before the snapshot is answered by subtracting the
/// messages between its `until` and the snapshot, when that gap is at most
/// this long; a longer gap is counted afresh in windows, not stored.
pub(crate) const COUNT_SUBTRACT_MAX_GAP_SECS: u64 = 86_400;

/// Smallest snapshot (total messages) kept in DO storage. Smaller counts are
/// cheap to redo, and a random id (no messages) must never occupy storage.
pub(crate) const COUNT_PERSIST_MIN: u64 = 200;

/// Rows per window of a full count, and the pause between windows: each
/// window is a short statement, and the pause lets other members' queries
/// run, so D1 is never held for seconds by one count.
pub(crate) const COUNT_WINDOW_ROWS: u32 = 10_000;
pub(crate) const COUNT_WINDOW_PAUSE_MS: u64 = 150;

/// How long a request waits for a full count of the same key already running
/// in this isolate before giving up with a retryable error.
pub(crate) const COUNT_INFLIGHT_WAIT_MS: u64 = 30_000;

/// Most snapshots kept in memory before the memory cache is emptied.
pub(crate) const COUNT_CACHE_MAX: usize = 1024;

/// Most exception rows a snapshot keeps, and their total size; past either,
/// the snapshot keeps none and they are read fresh each time.
const SNAPSHOT_EXCEPTIONS_MAX: usize = 64;
const SNAPSHOT_EXCEPTIONS_MAX_BYTES: usize = 64 * 1024;

/// A message count (see `filter::build_channel_count`), valid for every
/// message created at or before `as_of`: grouped counts, and the raw
/// exception rows (NIP-40 expiry is applied when served) when small enough.
///
/// Drift: a deletion, or a post stored after `as_of` with a `created_at` at
/// or before it (more than the margin back-dated), is not reflected. Counts
/// are display-only; the drift is accepted and documented rather than paid
/// for with periodic full recounts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct CountSnapshot {
    pub(crate) as_of: u64,
    pub(crate) groups: Vec<(String, u64)>,
    pub(crate) exceptions: Option<Vec<NostrEvent>>,
}

impl CountSnapshot {
    /// Total messages counted.
    pub(crate) fn total(&self) -> u64 {
        self.groups.iter().map(|(_, n)| n).sum()
    }
}

/// The exception rows a snapshot may keep: all of them when few and small,
/// else `None`, which makes the snapshot unusable (the caller takes the
/// row-capped generic path) rather than re-reading every row on each hit.
pub(crate) fn snapshot_exceptions(rows: &[NostrEvent]) -> Option<Vec<NostrEvent>> {
    let bytes: usize = rows
        .iter()
        .map(|e| e.content.len() + e.tags.iter().flatten().map(String::len).sum::<usize>())
        .sum();
    (rows.len() <= SNAPSHOT_EXCEPTIONS_MAX && bytes <= SNAPSHOT_EXCEPTIONS_MAX_BYTES)
        .then(|| rows.to_vec())
}

/// Whether a snapshot is worth keeping in DO storage.
pub(crate) fn persist_snapshot(snap: &CountSnapshot) -> bool {
    snap.total() >= COUNT_PERSIST_MIN
}

/// The horizon a snapshot taken at `now` covers.
pub(crate) fn snapshot_horizon(now: u64) -> u64 {
    now.saturating_sub(COUNT_SNAPSHOT_MARGIN_SECS)
}

/// Whether `snap` should be rolled forward to [`snapshot_horizon`] first.
pub(crate) fn should_roll(snap: &CountSnapshot, now: u64) -> bool {
    snapshot_horizon(now).saturating_sub(snap.as_of) >= COUNT_ROLL_SECS
}

/// How to answer a count ending at `until` (`None`: no upper bound) from a
/// snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CountPlan {
    /// The snapshot plus the messages created from `from` up to `until`.
    Delta { from: u64 },
    /// The snapshot minus the messages created in `lo..=hi` (the request
    /// ends before the snapshot; the gap is small).
    Subtract { lo: u64, hi: u64 },
    /// Count the request's range afresh, in windows, without storing it (the
    /// request ends long before the snapshot).
    Fresh,
}

/// The plan for a count ending at `until` against `snap`.
pub(crate) fn plan_count(snap: &CountSnapshot, until: Option<u64>) -> CountPlan {
    let reach = until.unwrap_or(u64::MAX);
    if reach >= snap.as_of {
        CountPlan::Delta {
            from: snap.as_of.saturating_add(1),
        }
    } else if snap.as_of - reach <= COUNT_SUBTRACT_MAX_GAP_SECS {
        CountPlan::Subtract {
            lo: reach.saturating_add(1),
            hi: snap.as_of,
        }
    } else {
        CountPlan::Fresh
    }
}

/// `a` minus `b`, channel by channel, never below zero.
pub(crate) fn subtract_groups(a: &[(String, u64)], b: &[(String, u64)]) -> Vec<(String, u64)> {
    a.iter()
        .map(|(ch, n)| {
            let minus = b.iter().find(|(c, _)| c == ch).map_or(0, |(_, m)| *m);
            (ch.clone(), n.saturating_sub(minus))
        })
        .collect()
}

/// The bounds of the next full-count window: from `lo` up to `edge` (the
/// `created_at` [`COUNT_WINDOW_ROWS`] rows on, `None` when fewer remain) or
/// `hi`, and where the window after it starts (`None`: this is the last).
/// Every message is in exactly one window, ties at an edge included.
pub(crate) fn next_window(lo: u64, edge: Option<u64>, hi: u64) -> (u64, u64, Option<u64>) {
    match edge {
        Some(e) if e < hi => (lo, e, Some(e + 1)),
        _ => (lo, hi, None),
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

/// The snapshot key of a count of `value` with no `since`, or `None` when
/// the count is not served from a snapshot: `value` not a lowercase 64-hex
/// event id, or a `since` given. The forum never sends `since`; keying on it
/// let one client mint unlimited snapshots of one big channel (review
/// finding), so such counts take the row-capped generic path.
pub(crate) fn count_key(value: &str, since: Option<u64>) -> Option<String> {
    let hex = value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    (hex && since.is_none()).then(|| value.to_string())
}

/// Largest timestamp the count path accepts: beyond 2^53 the f64 and i64
/// binds lose meaning (a `since` near 2^64 wrapped to -1 and disabled the
/// windows). A larger `until` is clamped to it.
pub(crate) const COUNT_MAX_TS: u64 = 1 << 53;

/// DO storage key of a persisted snapshot. Versioned, so a change to the
/// count logic can abandon old snapshots by bumping it.
pub(crate) fn snapshot_storage_key(key: &str) -> String {
    format!("count_snap:v1:{key}")
}

/// Most full (windowed) counts running at once in this isolate, across keys.
pub(crate) const COUNT_FULL_MAX_CONCURRENT: u32 = 2;

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
    fn requests_reaching_the_snapshot_add_newer_messages() {
        assert_eq!(
            plan_count(&snap(1_000), Some(1_030)),
            CountPlan::Delta { from: 1_001 }
        );
        assert_eq!(
            plan_count(&snap(1_000), None),
            CountPlan::Delta { from: 1_001 }
        );
        assert_eq!(
            plan_count(&snap(1_000), Some(1_000)),
            CountPlan::Delta { from: 1_001 }
        );
    }

    #[test]
    fn an_older_until_subtracts_a_small_gap_or_counts_afresh() {
        // An open tab resends its original `until` after the snapshot rolled.
        assert_eq!(
            plan_count(&snap(10_000), Some(9_400)),
            CountPlan::Subtract {
                lo: 9_401,
                hi: 10_000
            }
        );
        let far = 10_000 + COUNT_SUBTRACT_MAX_GAP_SECS + 1;
        assert_eq!(plan_count(&snap(far), Some(9_999)), CountPlan::Fresh);
    }

    #[test]
    fn snapshots_roll_forward_and_only_big_ones_persist() {
        let now = 100_000;
        let h = snapshot_horizon(now);
        assert_eq!(h, now - COUNT_SNAPSHOT_MARGIN_SECS);
        assert!(!should_roll(&snap(h - COUNT_ROLL_SECS + 1), now));
        assert!(should_roll(&snap(h - COUNT_ROLL_SECS), now));
        assert!(persist_snapshot(&snap(1)));
        let small = CountSnapshot {
            as_of: 1,
            groups: vec![("ch".into(), COUNT_PERSIST_MIN - 1)],
            exceptions: None,
        };
        assert!(!persist_snapshot(&small));
        // A random id: nothing counted, nothing stored.
        let empty = CountSnapshot {
            as_of: 1,
            groups: vec![],
            exceptions: None,
        };
        assert!(!persist_snapshot(&empty));
    }

    #[test]
    fn subtracting_groups_never_goes_negative() {
        let a = vec![("x".to_string(), 10), ("y".to_string(), 1)];
        let b = vec![
            ("x".to_string(), 3),
            ("y".to_string(), 5),
            ("z".to_string(), 9),
        ];
        assert_eq!(
            subtract_groups(&a, &b),
            vec![("x".to_string(), 7), ("y".to_string(), 0)]
        );
    }

    #[test]
    fn windows_cover_the_range_once_ties_included() {
        assert_eq!(next_window(0, Some(50), 100), (0, 50, Some(51)));
        assert_eq!(next_window(51, None, 100), (51, 100, None));
        // An edge at or past the end closes the range.
        assert_eq!(next_window(51, Some(100), 100), (51, 100, None));
        assert_eq!(next_window(51, Some(130), 100), (51, 100, None));
        // Many rows sharing one timestamp: the window still advances.
        assert_eq!(next_window(70, Some(70), 100), (70, 70, Some(71)));
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
        assert!(snapshot_exceptions(&vec![ev(1); 65]).is_none());
        assert!(snapshot_exceptions(&[ev(70_000)]).is_none());
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
        // A `since` is never snapshotted (one key per channel only).
        assert_eq!(count_key(&id, Some(5)), None);
        assert_eq!(snapshot_storage_key(&id), format!("count_snap:v1:{id}"));
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
