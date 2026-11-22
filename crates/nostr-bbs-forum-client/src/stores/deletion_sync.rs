//! Incremental kind-5 (NIP-09) deletion sync: a per-device `since` marker and
//! persisted `(id, deleter)` tombstones.
//!
//! Without a marker every session asked the relay for the newest
//! [`RELAY_FILTER_LIMIT`] deletions, most of which the device had already
//! applied. A device that has completed a deletion sync now asks only for
//! deletions at or after its marker. The relay keeps NIP-09 tombstones (it
//! hard-deletes every target it honours and refuses to store a deleted event
//! again), so a target whose kind-5 is older than the marker is not served
//! back to the device.
//!
//! # What is guaranteed
//!
//! The marker advances only at the EOSE of the subscription that uses it,
//! and only when one of these holds:
//!
//! - **Marked sync, not truncated.** The kind-5 filter carried `since = M`
//!   and fewer than [`RELAY_FILTER_LIMIT`] kind-5s were delivered before the
//!   first EOSE. The relay then returned every stored kind-5 with
//!   `created_at >= M`.
//! - **Unmarked first sync.** No `since`, so the device received the newest
//!   [`RELAY_FILTER_LIMIT`] deletions only, exactly what every session got
//!   before markers existed. Older deletions are not recovered.
//!
//! A marked sync that delivered [`RELAY_FILTER_LIMIT`] or more kind-5s may
//! have been cut short by the relay's row cap, so it keeps the old marker.
//! That session received the same newest rows an unmarked sync would. If the
//! window keeps holding more than the limit, the device stays on that marker:
//! coverage matches the old behaviour and recovers nothing older. Counting is
//! conservative (live kind-5s before EOSE count too), so an overcount only
//! costs a re-fetch.
//!
//! A sync cut off before EOSE writes nothing. A failed `localStorage` write
//! (quota, private mode) leaves the previous record in place, older marker
//! included, so the next session re-fetches from there: slower, never wrong.
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
//! so a kind-5 accepted after a marker-advancing sync is at or above that
//! marker and is fetched by the next one. The local-now clamp is defence in
//! depth for a device whose clock is right, and a stored marker later than
//! local now is discarded as corrupt.
//!
//! # Why tombstones are persisted, and how they are bounded
//!
//! Hard deletion does not cover a sealed original (ADR-2017): the relay
//! deletes rows by the deleted id, but the zone-encrypted envelope carrying
//! that original has its own id and an admin author, so it survives and the
//! client restores the original from it. Only a client tombstone hides that
//! post, so it has to outlive the session once its kind-5 is below the marker.
//!
//! Tombstones are persisted as `deleter -> {id -> deleted_at}` and capped
//! **per deleter** at [`MAX_PERSISTED_PER_DELETER`], with no eviction across
//! deleters: however many kind-5s one author publishes, or however many
//! targets one kind-5 names, only that author's own entries are displaced.
//! Storage is bounded by the number of deleters, which are whitelisted
//! (admin-approved) members. Whether an entry hides anything is decided by
//! [`crate::stores::tombstones`], against its deleter.
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

/// Most tombstones persisted for any one deleter, newest deletion first.
///
/// The entries that matter after the marker passes them are deletions of
/// sealed originals by their own author (an admin's are also made real on
/// the relay, which deletes the envelope). 256 of one author's own most
/// recent deletions is about 18 KB per deleter when full.
pub const MAX_PERSISTED_PER_DELETER: usize = 256;

/// Persisted tombstones: deleter pubkey -> deleted id -> kind-5 `created_at`
/// (bounded by local now; it only orders eviction within that deleter).
pub type PersistedTombstones = HashMap<String, HashMap<String, u64>>;

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
    ///
    /// Versioned: an unreleased draft of this record stored tombstones
    /// without their deleter, which must never be read as authoritative.
    pub fn storage_key(self) -> &'static str {
        match self {
            Self::Channels => "nostrbbs_deletion_sync_v2_channels",
            Self::Reactions => "nostrbbs_deletion_sync_v2_reactions",
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
    /// Tombstones with their deleters; empty for the reaction scope.
    #[serde(default)]
    pub tombstones: PersistedTombstones,
}

/// Whether `s` is lowercase 64-character hex (an event id or a pubkey).
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse a stored [`DeletionSyncState`], discarding anything untrustworthy.
///
/// Unreadable JSON yields the default state (no marker, no tombstones), which
/// is the full sync a new device does. A marker of zero or later than `now`
/// is dropped: zero is meaningless and a future marker would skip deletions.
/// Entries whose deleter or id is not lowercase hex are dropped, and each
/// deleter is capped at [`MAX_PERSISTED_PER_DELETER`].
pub fn parse_state(raw: Option<&str>, now: u64) -> DeletionSyncState {
    let mut state: DeletionSyncState = raw
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    state.since = state.since.filter(|&s| s > 0 && s <= now);
    state.tombstones.retain(|deleter, ids| {
        ids.retain(|id, _| is_hex64(id));
        is_hex64(deleter) && !ids.is_empty()
    });
    cap_tombstones(&mut state.tombstones, MAX_PERSISTED_PER_DELETER);
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

/// Whether a sync's first EOSE may have been cut short by the relay's row
/// cap: only a marked filter counts, since an unmarked one is by design the
/// newest [`RELAY_FILTER_LIMIT`] (see the module docs).
pub fn is_truncated(since: Option<u64>, delivered_before_first_eose: usize) -> bool {
    since.is_some() && delivered_before_first_eose >= RELAY_FILTER_LIMIT as usize
}

/// Record the targets of one kind-5 from `deleter`.
///
/// A deleter or id that is not lowercase hex is skipped (the relay only
/// tombstones well-formed ids, and only hex pubkeys sign). `created_at` is
/// bounded by `now` so a kind-5 dated in the future cannot pin itself at the
/// head of its deleter's eviction order. Only `deleter`'s own map is touched.
pub fn record_tombstones(
    tombstones: &mut PersistedTombstones,
    deleter: &str,
    targets: &[String],
    created_at: u64,
    now: u64,
) {
    if !is_hex64(deleter) {
        return;
    }
    let ts = created_at.min(now);
    let mut valid = targets.iter().filter(|id| is_hex64(id)).peekable();
    if valid.peek().is_none() {
        return;
    }
    let own = tombstones.entry(deleter.to_string()).or_default();
    for id in valid {
        let entry = own.entry(id.clone()).or_insert(ts);
        *entry = (*entry).max(ts);
    }
}

/// Keep each deleter's `cap` newest entries. Never removes one deleter's
/// entries on account of another's. Ties break on the id so the result does
/// not depend on hash order.
pub fn cap_tombstones(tombstones: &mut PersistedTombstones, cap: usize) {
    for ids in tombstones.values_mut() {
        if ids.len() <= cap {
            continue;
        }
        let mut entries: Vec<(String, u64)> = ids.drain().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.truncate(cap);
        ids.extend(entries);
    }
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
    /// Kind-5s delivered before the first EOSE.
    delivered_before_eose: usize,
    /// Set at the first EOSE: whether this session's sync may be truncated.
    truncated: Option<bool>,
}

impl DeletionProgress {
    /// Start from the persisted state.
    pub fn new(state: DeletionSyncState) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }

    /// Note a delivered kind-5 from `deleter`. `persist_targets` is true for
    /// the channel scope, whose tombstones must outlive the session.
    pub fn observe(
        &mut self,
        created_at: u64,
        deleter: &str,
        targets: &[String],
        persist_targets: bool,
        now: u64,
    ) {
        self.newest_seen = Some(self.newest_seen.map_or(created_at, |n| n.max(created_at)));
        if self.truncated.is_none() {
            self.delivered_before_eose += 1;
        }
        if persist_targets {
            record_tombstones(
                &mut self.state.tombstones,
                deleter,
                targets,
                created_at,
                now,
            );
        }
    }

    /// The subscription reached EOSE: advance the marker unless this
    /// session's sync may be truncated, cap the tombstones, and return the
    /// state to persist. Truncation is decided once, at the first EOSE.
    pub fn complete(&mut self, now: u64) -> &DeletionSyncState {
        let since = self.state.since;
        let delivered = self.delivered_before_eose;
        let truncated = *self
            .truncated
            .get_or_insert_with(|| is_truncated(since, delivered));
        if !truncated {
            self.state.since = next_marker(self.state.since, self.newest_seen, now);
        }
        cap_tombstones(&mut self.state.tombstones, MAX_PERSISTED_PER_DELETER);
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

/// Persist a scope's state. A failed write leaves the previous record (and
/// its older marker) in place, which only costs a re-fetch, so it is ignored.
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
    const LIMIT: usize = RELAY_FILTER_LIMIT as usize;

    fn id(n: u64) -> String {
        format!("{n:064x}")
    }

    fn pk(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn total(t: &PersistedTombstones) -> usize {
        t.values().map(HashMap::len).sum()
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
        // The deleter-less draft shape is unreadable, not misread.
        let draft = format!(r#"{{"since":5,"tombstones":{{"{}":1}}}}"#, id(1));
        assert_eq!(parse_state(Some(&draft), NOW), DeletionSyncState::default());
    }

    #[test]
    fn a_stored_record_round_trips() {
        let state = DeletionSyncState {
            since: Some(NOW - 20 * DAY),
            tombstones: HashMap::from([(pk('a'), HashMap::from([(id(1), NOW - DAY)]))]),
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
    fn stored_entries_need_hex_deleters_and_ids() {
        let raw = format!(
            r#"{{"tombstones":{{"{a}":{{"{ok}":1,"{upper}":2,"short":3}},"{bad}":{{"{ok}":4}},"{b}":{{"short":5}}}}}}"#,
            a = pk('a'),
            b = pk('b'),
            bad = "g".repeat(64),
            ok = id(7),
            // Letters in it, so uppercasing actually changes it.
            upper = id(0xabcd).to_uppercase(),
        );
        let state = parse_state(Some(&raw), NOW);
        assert_eq!(
            state.tombstones,
            HashMap::from([(pk('a'), HashMap::from([(id(7), 1)]))])
        );
    }

    #[test]
    fn each_deleter_is_capped_on_load() {
        let many: HashMap<String, u64> = (0..MAX_PERSISTED_PER_DELETER as u64 + 5)
            .map(|n| (id(n), n))
            .collect();
        let json = serde_json::to_string(&DeletionSyncState {
            since: None,
            tombstones: HashMap::from([(pk('a'), many)]),
        })
        .unwrap();
        let state = parse_state(Some(&json), NOW);
        assert_eq!(state.tombstones[&pk('a')].len(), MAX_PERSISTED_PER_DELETER);
        assert!(
            !state.tombstones[&pk('a')].contains_key(&id(0)),
            "oldest evicted"
        );
    }

    // --- eviction attack (one author must never displace another) ---

    #[test]
    fn one_deleter_flooding_cannot_evict_anothers_entries() {
        let mut t = PersistedTombstones::new();
        record_tombstones(&mut t, &pk('b'), &[id(1), id(2)], NOW - 30 * DAY, NOW);
        // Deleter A: cap + 500 junk targets, newer than B's, some in a single
        // kind-5 (the relay allows up to 2,000 `e` tags) and some spread out.
        let junk: Vec<String> = (1000..1000 + MAX_PERSISTED_PER_DELETER as u64 + 500)
            .map(id)
            .collect();
        record_tombstones(&mut t, &pk('a'), &junk[..300], NOW, NOW);
        for (i, j) in junk[300..].iter().enumerate() {
            record_tombstones(
                &mut t,
                &pk('a'),
                std::slice::from_ref(j),
                NOW - i as u64,
                NOW,
            );
        }
        cap_tombstones(&mut t, MAX_PERSISTED_PER_DELETER);
        assert_eq!(
            t[&pk('b')],
            HashMap::from([(id(1), NOW - 30 * DAY), (id(2), NOW - 30 * DAY)])
        );
        assert_eq!(t[&pk('a')].len(), MAX_PERSISTED_PER_DELETER);
    }

    #[test]
    fn a_new_deleter_never_removes_existing_deleters() {
        let mut t = PersistedTombstones::new();
        record_tombstones(&mut t, &pk('a'), &[id(1)], NOW - 9 * DAY, NOW);
        record_tombstones(&mut t, &pk('b'), &[id(2)], NOW - 8 * DAY, NOW);
        // C's kind-5 is future-dated (allowed up to 7 days ahead): no effect
        // on A or B, whatever its timestamp.
        record_tombstones(&mut t, &pk('c'), &[id(3)], NOW + 7 * DAY, NOW);
        cap_tombstones(&mut t, MAX_PERSISTED_PER_DELETER);
        assert_eq!(t.len(), 3);
        assert!(t[&pk('a')].contains_key(&id(1)));
        assert!(t[&pk('b')].contains_key(&id(2)));
        assert_eq!(t[&pk('c')][&id(3)], NOW, "future kind-5 bounded by now");
    }

    #[test]
    fn recording_keeps_the_newest_and_skips_malformed_input() {
        let mut t = PersistedTombstones::new();
        record_tombstones(&mut t, &pk('a'), &[id(1), "nope".into()], NOW - 5, NOW);
        record_tombstones(&mut t, &pk('a'), &[id(1)], NOW - 9, NOW);
        assert_eq!(t[&pk('a')], HashMap::from([(id(1), NOW - 5)]));
        record_tombstones(&mut t, "not-a-pubkey", &[id(2)], NOW, NOW);
        record_tombstones(&mut t, &pk('b'), &["nope".into()], NOW, NOW);
        assert_eq!(t.len(), 1, "no entry for a bad deleter or no valid id");
        assert_eq!(total(&t), 1);
    }

    #[test]
    fn capping_keeps_the_newest_deterministically() {
        let mut t = HashMap::from([(
            pk('a'),
            HashMap::from([(id(1), 10), (id(2), 30), (id(3), 20), (id(4), 30)]),
        )]);
        cap_tombstones(&mut t, 2);
        assert_eq!(t[&pk('a')], HashMap::from([(id(2), 30), (id(4), 30)]));
        cap_tombstones(&mut t, 1);
        assert_eq!(t[&pk('a')], HashMap::from([(id(2), 30)]));
    }

    // --- marker ---

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

    // --- truncation ---

    #[test]
    fn only_a_marked_sync_at_the_limit_is_truncated() {
        assert!(!is_truncated(None, LIMIT));
        assert!(!is_truncated(Some(1), LIMIT - 1));
        assert!(is_truncated(Some(1), LIMIT));
        assert!(is_truncated(Some(1), LIMIT + 7));
    }

    fn progress_with(since: Option<u64>, delivered: usize) -> DeletionProgress {
        let mut p = DeletionProgress::new(DeletionSyncState {
            since,
            tombstones: HashMap::new(),
        });
        for i in 0..delivered {
            p.observe(NOW - DAY + i as u64, &pk('a'), &[id(i as u64)], true, NOW);
        }
        p
    }

    #[test]
    fn a_truncated_marked_sync_keeps_the_marker_but_saves_tombstones() {
        let old = NOW - 40 * DAY;
        let mut p = progress_with(Some(old), LIMIT);
        let saved = p.complete(NOW).clone();
        assert_eq!(saved.since, Some(old));
        assert_eq!(total(&saved.tombstones), MAX_PERSISTED_PER_DELETER);
        // Decided once: a later EOSE (AUTH replay) does not advance it either.
        assert_eq!(p.complete(NOW).since, Some(old));
    }

    #[test]
    fn a_marked_sync_below_the_limit_advances() {
        let mut p = progress_with(Some(NOW - 40 * DAY), LIMIT - 1);
        assert!(p.complete(NOW).since.unwrap() > NOW - 40 * DAY);
    }

    #[test]
    fn an_unmarked_first_sync_at_the_limit_still_sets_a_marker() {
        let mut p = progress_with(None, LIMIT);
        assert!(p.complete(NOW).since.is_some());
    }

    #[test]
    fn live_deletions_after_the_first_eose_do_not_count_towards_truncation() {
        let mut p = progress_with(Some(NOW - 40 * DAY), 3);
        p.complete(NOW);
        for i in 0..LIMIT {
            p.observe(NOW, &pk('a'), &[id(9000 + i as u64)], true, NOW);
        }
        // A replayed EOSE after that live burst still advances.
        assert_eq!(
            p.complete(NOW).since,
            Some(NOW - DELETION_SINCE_MARGIN_SECS)
        );
    }

    // --- progress ---

    #[test]
    fn progress_spans_replays_and_advances_only_on_completion() {
        let mut p = DeletionProgress::new(DeletionSyncState::default());
        p.observe(NOW - 2 * DAY, &pk('a'), &[id(1)], true, NOW);
        // Before EOSE nothing has advanced.
        assert_eq!(p.state.since, None);
        let saved = p.complete(NOW).clone();
        assert_eq!(
            saved.since,
            Some(NOW - 2 * DAY - DELETION_SINCE_MARGIN_SECS)
        );
        assert!(saved.tombstones[&pk('a')].contains_key(&id(1)));
        // The post-AUTH replay re-delivers nothing (per-sub dedup): its EOSE
        // must keep the marker, not lose it.
        assert_eq!(p.complete(NOW).since, saved.since);
    }

    #[test]
    fn reaction_progress_persists_no_tombstones() {
        let mut p = DeletionProgress::new(DeletionSyncState::default());
        p.observe(NOW - DAY, &pk('a'), &[id(1)], false, NOW);
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
