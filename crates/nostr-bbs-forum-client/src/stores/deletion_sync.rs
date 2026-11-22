//! Incremental kind-5 (NIP-09) deletion sync: a per-device `since` marker and
//! a bounded set of persisted tombstones.
//!
//! Without a marker every session asked the relay for the newest
//! [`RELAY_FILTER_LIMIT`] deletions, most of which the device had already
//! applied. A device that has completed a deletion sync now asks only for
//! deletions newer than its marker. The relay keeps NIP-09 tombstones (it
//! hard-deletes every target it honours and refuses to store a deleted event
//! again), so a target whose kind-5 is older than the marker is not served
//! back to the device.
//!
//! # Why the marker is safe
//!
//! The marker is `min(newest kind-5 created_at delivered, local now)` minus
//! [`DELETION_SINCE_MARGIN_SECS`] (14 days, twice the relay's 7-day
//! [`RELAY_MAX_TIMESTAMP_DRIFT_SECS`]). The relay accepts an event only when
//! `|created_at - relay_now| <= 7 days`, and kind 5 has no exemption. So:
//!
//! - the newest kind-5 delivered is at most `relay_now + 7d`, which puts the
//!   marker at most `relay_now - 7d` whatever the author's or the device's
//!   clock says;
//! - every kind-5 the relay accepts after that sync has
//!   `created_at >= relay_now - 7d`, and the relay's `since` is inclusive;
//!
//! so every kind-5 is delivered to the device by at least one completed sync.
//! The local-now clamp is defence in depth for a device whose clock is right,
//! and a stored marker later than local now is discarded as corrupt.
//!
//! # Why tombstones are persisted
//!
//! Hard deletion does not cover a sealed original (ADR-2017): the relay
//! deletes rows by the deleted id, but the zone-encrypted envelope carrying
//! that original has its own id and an admin author, so it survives and the
//! client restores the original from it. Only a client tombstone hides that
//! post. Once its kind-5 falls below the marker it is no longer re-fetched, so
//! the tombstone has to outlive the session. The marker and the tombstones
//! that justify it are written together, in one record, only when a sync has
//! completed.
//!
//! The decision logic lives in pure functions; [`load`] and [`save`] are the
//! only code that touches `localStorage`.

use gloo::storage::{LocalStorage, Storage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::stores::channels::RELAY_FILTER_LIMIT;

/// The relay's `created_at` drift allowance in either direction
/// (`MAX_TIMESTAMP_DRIFT` in the relay worker's `relay_do/nip_handlers.rs`).
pub const RELAY_MAX_TIMESTAMP_DRIFT_SECS: u64 = 7 * 24 * 60 * 60;

/// Subtracted from the newest kind-5 delivered to form the marker.
///
/// One drift allowance absorbs an author clock up to 7 days fast (the newest
/// kind-5 may be dated that far ahead of the relay); the second covers every
/// deletion the relay may still accept after the sync, which can be dated up
/// to 7 days in the past (late publication, a slow author clock). See the
/// module documentation for the bound this gives.
pub const DELETION_SINCE_MARGIN_SECS: u64 = 2 * RELAY_MAX_TIMESTAMP_DRIFT_SECS;

/// Most tombstones persisted for the channel store.
///
/// Before the marker a device hid a sealed original only while its kind-5
/// was among the newest [`RELAY_FILTER_LIMIT`] deletions. Keeping twice that
/// many targets, newest first, matches or beats that even when a kind-5 names
/// two targets, at roughly 150 KB of `localStorage` when full.
pub const MAX_PERSISTED_TOMBSTONES: usize = 2 * RELAY_FILTER_LIMIT as usize;

/// Which subscription a marker belongs to.
///
/// The channel and reaction subscriptions each carry their own kind-5 filter
/// and reach EOSE independently; a marker may only advance on the EOSE of the
/// subscription that will use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionScope {
    /// The channel-list subscription in [`crate::stores::channels`].
    Channels,
    /// The reaction subscription in [`crate::stores::reactions`].
    Reactions,
}

impl DeletionScope {
    /// The `localStorage` key holding this scope's [`DeletionSyncState`].
    pub fn storage_key(self) -> &'static str {
        match self {
            Self::Channels => "nostrbbs_deletion_sync_channels",
            Self::Reactions => "nostrbbs_deletion_sync_reactions",
        }
    }
}

/// What one scope persists between sessions.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeletionSyncState {
    /// `since` for the kind-5 filter, or `None` to take the newest
    /// [`RELAY_FILTER_LIMIT`] deletions.
    #[serde(default)]
    pub since: Option<u64>,
    /// Deleted event id (lowercase hex) to the `created_at` of the kind-5 that
    /// deleted it, bounded by local now. The timestamp only orders eviction.
    #[serde(default)]
    pub tombstones: HashMap<String, u64>,
}

/// Whether `id` is a lowercase 64-character hex event id.
fn is_event_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse a stored [`DeletionSyncState`], discarding anything untrustworthy.
///
/// Unreadable JSON yields the default state (no marker, no tombstones), which
/// is the full sync a new device does. A marker of zero or later than `now`
/// is dropped: zero is meaningless and a future marker would skip deletions.
/// Tombstones that are not event ids are dropped and the rest are capped at
/// [`MAX_PERSISTED_TOMBSTONES`].
pub fn parse_state(raw: Option<&str>, now: u64) -> DeletionSyncState {
    let mut state: DeletionSyncState = raw
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    state.since = state.since.filter(|&s| s > 0 && s <= now);
    state.tombstones.retain(|id, _| is_event_id(id));
    cap_tombstones(&mut state.tombstones, MAX_PERSISTED_TOMBSTONES);
    state
}

/// The marker to store after a completed sync.
///
/// `newest_seen` is the newest kind-5 `created_at` the subscription delivered
/// this session. With none delivered the previous marker stands: there is
/// nothing relay-derived to advance from, and the device clock alone is not
/// trusted. The candidate is `min(newest_seen, now) - margin`; the marker
/// never moves backwards, because every candidate is individually safe.
pub fn next_marker(previous: Option<u64>, newest_seen: Option<u64>, now: u64) -> Option<u64> {
    let candidate = newest_seen
        .map(|newest| newest.min(now).saturating_sub(DELETION_SINCE_MARGIN_SECS))
        .filter(|&c| c > 0);
    match (previous, candidate) {
        (Some(p), Some(c)) => Some(p.max(c)),
        (p, c) => p.or(c),
    }
}

/// Record the targets of one kind-5 in the persisted tombstone map.
///
/// Ids that are not event ids are skipped (the relay tombstones only those,
/// so the rest cannot be restored by an envelope either). `created_at` is
/// bounded by `now` so a kind-5 dated in the future cannot pin itself at the
/// head of the eviction order.
pub fn record_tombstones(
    tombstones: &mut HashMap<String, u64>,
    targets: &[String],
    created_at: u64,
    now: u64,
) {
    let ts = created_at.min(now);
    for id in targets.iter().filter(|id| is_event_id(id)) {
        let entry = tombstones.entry(id.clone()).or_insert(ts);
        *entry = (*entry).max(ts);
    }
}

/// Keep the `cap` tombstones whose deletions are newest.
///
/// Ties break on the id so the result does not depend on hash order.
pub fn cap_tombstones(tombstones: &mut HashMap<String, u64>, cap: usize) {
    if tombstones.len() <= cap {
        return;
    }
    let mut entries: Vec<(String, u64)> = tombstones.drain().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries.truncate(cap);
    tombstones.extend(entries);
}

/// Session-long progress of one scope's deletion sync.
///
/// `newest_seen` is cumulative across the session rather than per REQ: the
/// relay connection deduplicates deliveries per subscription, so the replay
/// sent after NIP-42 AUTH (or a reconnect) does not re-deliver what the first
/// REQ already did, and a per-REQ reset would leave its EOSE with nothing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeletionProgress {
    /// The state loaded at session start, then as last saved.
    pub state: DeletionSyncState,
    /// Newest kind-5 `created_at` delivered this session.
    pub newest_seen: Option<u64>,
}

impl DeletionProgress {
    /// Start from the persisted state.
    pub fn new(state: DeletionSyncState) -> Self {
        Self {
            state,
            newest_seen: None,
        }
    }

    /// Note a delivered kind-5. `persist_targets` is true for the channel
    /// scope, whose tombstones must outlive the session (see the module docs).
    pub fn observe(
        &mut self,
        created_at: u64,
        targets: &[String],
        persist_targets: bool,
        now: u64,
    ) {
        self.newest_seen = Some(self.newest_seen.map_or(created_at, |n| n.max(created_at)));
        if persist_targets {
            record_tombstones(&mut self.state.tombstones, targets, created_at, now);
        }
    }

    /// The subscription reached EOSE: advance the marker, cap the tombstones,
    /// and return the state to persist.
    pub fn complete(&mut self, now: u64) -> &DeletionSyncState {
        self.state.since = next_marker(self.state.since, self.newest_seen, now);
        cap_tombstones(&mut self.state.tombstones, MAX_PERSISTED_TOMBSTONES);
        &self.state
    }
}

// -- localStorage wrapper ------------------------------------------------------

/// Current Unix time in seconds, from the browser clock.
pub fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Read a scope's persisted state; a missing or unreadable record is the
/// default (full sync).
pub fn load(scope: DeletionScope) -> DeletionSyncState {
    let raw: Option<String> = LocalStorage::get(scope.storage_key()).ok();
    parse_state(raw.as_deref(), now_secs())
}

/// Persist a scope's state. A write failure (quota, private mode) only costs
/// the next session a full sync, so it is ignored.
pub fn save(scope: DeletionScope, state: &DeletionSyncState) {
    if let Ok(json) = serde_json::to_string(state) {
        let _ = LocalStorage::set(scope.storage_key(), json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn id(n: u64) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn margin_is_two_relay_drift_allowances() {
        assert_eq!(RELAY_MAX_TIMESTAMP_DRIFT_SECS, 7 * DAY);
        assert_eq!(DELETION_SINCE_MARGIN_SECS, 14 * DAY);
    }

    #[test]
    fn missing_or_corrupt_state_is_a_full_sync() {
        assert_eq!(parse_state(None, NOW), DeletionSyncState::default());
        assert_eq!(
            parse_state(Some("not json"), NOW),
            DeletionSyncState::default()
        );
        assert_eq!(
            parse_state(Some("[1,2]"), NOW),
            DeletionSyncState::default()
        );
        assert_eq!(
            parse_state(Some(r#"{"since":"x"}"#), NOW),
            DeletionSyncState::default()
        );
    }

    #[test]
    fn a_stored_marker_round_trips() {
        let state = DeletionSyncState {
            since: Some(NOW - 20 * DAY),
            tombstones: HashMap::from([(id(1), NOW - DAY)]),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(parse_state(Some(&json), NOW), state);
    }

    #[test]
    fn a_future_or_zero_marker_is_discarded() {
        let future = format!(r#"{{"since":{}}}"#, NOW + 1);
        assert_eq!(parse_state(Some(&future), NOW).since, None);
        assert_eq!(parse_state(Some(r#"{"since":0}"#), NOW).since, None);
        let at_now = format!(r#"{{"since":{NOW}}}"#);
        assert_eq!(parse_state(Some(&at_now), NOW).since, Some(NOW));
    }

    #[test]
    fn stored_tombstones_must_be_event_ids() {
        let raw = format!(
            r#"{{"tombstones":{{"{}":1,"{}":2,"short":3,"{}":4}}}}"#,
            id(7),
            // Letters in it, so uppercasing actually changes it.
            id(0xabcd).to_uppercase(),
            "g".repeat(64)
        );
        let state = parse_state(Some(&raw), NOW);
        assert_eq!(state.tombstones, HashMap::from([(id(7), 1)]));
    }

    #[test]
    fn stored_tombstones_are_capped_on_load() {
        let tombstones: HashMap<String, u64> = (0..MAX_PERSISTED_TOMBSTONES as u64 + 5)
            .map(|n| (id(n), n))
            .collect();
        let json = serde_json::to_string(&DeletionSyncState {
            since: None,
            tombstones,
        })
        .unwrap();
        let state = parse_state(Some(&json), NOW);
        assert_eq!(state.tombstones.len(), MAX_PERSISTED_TOMBSTONES);
        assert!(!state.tombstones.contains_key(&id(0)), "oldest evicted");
    }

    #[test]
    fn no_marker_and_nothing_delivered_stays_a_full_sync() {
        assert_eq!(next_marker(None, None, NOW), None);
    }

    #[test]
    fn the_marker_is_the_newest_deletion_less_the_margin() {
        let newest = NOW - 3 * DAY;
        assert_eq!(
            next_marker(None, Some(newest), NOW),
            Some(newest - DELETION_SINCE_MARGIN_SECS)
        );
    }

    #[test]
    fn a_future_dated_deletion_is_bounded_by_local_now() {
        // An author clock 7 days fast: the marker comes from local now.
        let newest = NOW + RELAY_MAX_TIMESTAMP_DRIFT_SECS;
        assert_eq!(
            next_marker(None, Some(newest), NOW),
            Some(NOW - DELETION_SINCE_MARGIN_SECS)
        );
    }

    #[test]
    fn a_fast_device_clock_cannot_push_the_marker_past_relay_now() {
        // Device clock a year fast, newest deletion dated the full 7 days
        // ahead of the relay: the marker still lands 7 days before relay now.
        let relay_now = NOW;
        let device_now = relay_now + 365 * DAY;
        let newest = relay_now + RELAY_MAX_TIMESTAMP_DRIFT_SECS;
        // That is exactly the oldest `created_at` the relay can still accept,
        // and `since` is inclusive, so nothing accepted later is skipped.
        assert_eq!(
            next_marker(None, Some(newest), device_now),
            Some(relay_now - RELAY_MAX_TIMESTAMP_DRIFT_SECS)
        );
    }

    #[test]
    fn nothing_delivered_keeps_the_previous_marker() {
        assert_eq!(
            next_marker(Some(NOW - 30 * DAY), None, NOW),
            Some(NOW - 30 * DAY)
        );
    }

    #[test]
    fn the_marker_never_moves_backwards() {
        // An older delivery (candidate 34 days back) keeps the stored marker.
        let previous = NOW - 20 * DAY;
        assert_eq!(
            next_marker(Some(previous), Some(NOW - 20 * DAY), NOW),
            Some(previous)
        );
        // A newer one (candidate 14 days back) advances it.
        assert_eq!(
            next_marker(Some(previous), Some(NOW), NOW),
            Some(NOW - DELETION_SINCE_MARGIN_SECS)
        );
    }

    #[test]
    fn a_deletion_older_than_the_margin_sets_no_zero_marker() {
        assert_eq!(next_marker(None, Some(DAY), NOW), None);
    }

    #[test]
    fn tombstones_keep_the_newest_deletion_and_skip_non_ids() {
        let mut t = HashMap::new();
        record_tombstones(&mut t, &[id(1), "nope".into()], NOW - 5, NOW);
        record_tombstones(&mut t, &[id(1)], NOW - 9, NOW);
        assert_eq!(t, HashMap::from([(id(1), NOW - 5)]));
        record_tombstones(&mut t, &[id(2)], NOW + 99 * DAY, NOW);
        assert_eq!(t[&id(2)], NOW, "future kind-5 bounded by now");
    }

    #[test]
    fn capping_keeps_the_newest_deterministically() {
        let mut t: HashMap<String, u64> =
            HashMap::from([(id(1), 10), (id(2), 30), (id(3), 20), (id(4), 30)]);
        cap_tombstones(&mut t, 2);
        assert_eq!(t, HashMap::from([(id(2), 30), (id(4), 30)]));
        cap_tombstones(&mut t, 1);
        assert_eq!(t, HashMap::from([(id(2), 30)]));
    }

    #[test]
    fn progress_spans_replays_and_advances_only_on_completion() {
        let mut p = DeletionProgress::new(DeletionSyncState::default());
        p.observe(NOW - 2 * DAY, &[id(1)], true, NOW);
        // Before EOSE nothing has advanced.
        assert_eq!(p.state.since, None);
        let saved = p.complete(NOW).clone();
        assert_eq!(
            saved.since,
            Some(NOW - 2 * DAY - DELETION_SINCE_MARGIN_SECS)
        );
        assert!(saved.tombstones.contains_key(&id(1)));
        // The post-AUTH replay re-delivers nothing (per-sub dedup): its EOSE
        // must keep the marker, not lose it.
        assert_eq!(p.complete(NOW).since, saved.since);
    }

    #[test]
    fn reaction_progress_persists_no_tombstones() {
        let mut p = DeletionProgress::new(DeletionSyncState::default());
        p.observe(NOW - DAY, &[id(1)], false, NOW);
        let saved = p.complete(NOW);
        assert!(saved.tombstones.is_empty());
        assert_eq!(saved.since, Some(NOW - DAY - DELETION_SINCE_MARGIN_SECS));
    }

    #[test]
    fn scopes_use_distinct_keys() {
        assert_ne!(
            DeletionScope::Channels.storage_key(),
            DeletionScope::Reactions.storage_key()
        );
    }
}
