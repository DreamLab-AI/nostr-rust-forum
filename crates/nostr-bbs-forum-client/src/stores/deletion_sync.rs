//! Incremental kind-5 (NIP-09) deletion sync: a per-device `since` marker,
//! paging when the relay's row cap is hit, and the few tombstones a device
//! must keep across sessions.
//!
//! Without a marker every session asked the relay for the newest
//! [`RELAY_FILTER_LIMIT`] deletions, most of which the device had already
//! applied. A device that has completed a deletion sync now asks only for
//! deletions at or after its marker. The relay keeps NIP-09 tombstones (it
//! hard-deletes every ordinary target it honours and refuses to store a
//! deleted event again), so a target whose kind-5 is older than the marker is
//! not served back to the device.
//!
//! # What is guaranteed
//!
//! The marker advances only once a sync has **settled**, and only when one of
//! these holds:
//!
//! - **Marked sync, complete.** The kind-5 filter carried `since = M` and the
//!   relay returned every stored kind-5 with `created_at >= M`: either fewer
//!   than [`RELAY_FILTER_LIMIT`] came back before the first EOSE, or the
//!   device paged downwards (`until` = the oldest `created_at` delivered,
//!   inclusive) until a page delivered nothing older than its `until`, within
//!   [`MAX_PAGES`] pages (see [`next_page`] for why pages end on progress,
//!   not on a short count).
//! - **Unmarked first sync.** No `since`, so the device received the newest
//!   [`RELAY_FILTER_LIMIT`] deletions only, exactly what every session got
//!   before markers existed. Older deletions are not recovered, and there is
//!   no paging: a first sync never walks the whole deletion history.
//!
//! When paging gives up, the old marker stays and the next session tries
//! again. It gives up when it reaches [`MAX_PAGES`], when a full page makes
//! no progress (more than a page of kind-5s share one `created_at`), or when
//! a page comes back empty (a failed query).
//!
//! One residue is accepted. The first step does count: a backfill that
//! delivered fewer than [`RELAY_FILTER_LIMIT`] is taken as complete. If the
//! relay's SQL page was full but it dropped rows after the `LIMIT` (expired
//! NIP-40 kind-5s), deletions just above `since` could be skipped. That
//! needs a page's worth of kind-5s carrying expiry tags.
//! A sync cut off before it settles writes nothing. A failed `localStorage`
//! write (quota, private mode) leaves the previous record, older marker
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
//! marker and is fetched by the next one.
//!
//! # Which tombstones are persisted
//!
//! The relay hard-deletes ordinary posts and refuses their re-publication, so
//! across sessions a device only needs the tombstones that hide a **restored
//! sealed original** (ADR-2017): its envelope survives under its own id and
//! the client restores the original from it. Of those, only tombstones from
//! an honoured deleter count (the inner author, or an admin the relay vouches
//! for; see [`crate::stores::tombstones`]). Two persisted sets:
//!
//! - **`sealed`**: resolved tombstones: the target was seen restored and the
//!   deleter honoured. At most [`SEALED_PER_DELETER`] per deleter.
//! - **`held`**: every other kind-5 target, until it resolves. A kind-5
//!   usually lands before its target is known to be a sealed original (the
//!   target may only arrive in a later session, once a zone key does, or on
//!   scrolling), and the admin answer may come later still. Holding it is
//!   what keeps it from being lost when the marker passes its kind-5 before
//!   it resolves. A held entry is promoted to `sealed` once honoured, and
//!   dropped once refused (the target is restored and the deleter is neither
//!   its author nor, by the relay's definite answer, an admin). At most
//!   [`HELD_PER_DELETER`] per deleter, newest first.
//!
//! The alternative, not advancing the marker past an unresolved tombstone,
//! would pin it for good: most targets are ordinary posts the relay has
//! already hard-deleted, so they never arrive and never resolve.
//!
//! Each set also has a global cap ([`SEALED_TOTAL`], [`HELD_TOTAL`]) enforced
//! by a fair share: when over, every deleter is trimmed to a common level,
//! oldest first. Deleters below that level lose nothing, so one account's
//! flood displaces only its own entries until it is down to the same share as
//! everyone else. Ordinary deletions never enter `sealed`, so they cannot
//! evict a sealed-original deletion. Worst case is
//! `(SEALED_TOTAL + HELD_TOTAL)` entries, about 150 KB.
//!
//! The decision logic lives in pure functions; [`load`], [`save`] and
//! [`drive`] are the only code that touches `localStorage` or the relay.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use nostr_bbs_core::NostrEvent;
use serde::{Deserialize, Serialize};

use crate::relay::RelayConnection;
use crate::stores::channels::{deletion_page_filter, RELAY_FILTER_LIMIT};

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

/// Most extra pages fetched after a marked sync hits the row cap, so 20,000
/// more deletions in all. Beyond that the old marker stays.
pub const MAX_PAGES: u32 = 20;

/// Most resolved sealed-original tombstones kept per deleter.
pub const SEALED_PER_DELETER: usize = 256;
/// Most resolved sealed-original tombstones kept in all (fair share).
pub const SEALED_TOTAL: usize = 1024;
/// Most unresolved (held) tombstones kept per deleter, newest first.
pub const HELD_PER_DELETER: usize = 64;
/// Most unresolved (held) tombstones kept in all (fair share).
pub const HELD_TOTAL: usize = 1024;

/// Deleter pubkey -> deleted id -> kind-5 `created_at` (bounded by local now;
/// it only orders eviction within that deleter).
pub type DeleterMap = HashMap<String, HashMap<String, u64>>;

/// Which subscription a marker belongs to.
///
/// The channel and reaction subscriptions each carry their own kind-5 filter
/// and settle independently; a marker may only advance on the subscription
/// that will use it.
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
    /// Versioned: unreleased drafts of this record kept tombstones with other
    /// meanings, which must never be read as these.
    pub fn storage_key(self) -> &'static str {
        match self {
            Self::Channels => "nostrbbs_deletion_sync_v3_channels",
            Self::Reactions => "nostrbbs_deletion_sync_v3_reactions",
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
    /// Resolved: honoured deletions of restored sealed originals.
    #[serde(default)]
    pub sealed: DeleterMap,
    /// Unresolved kind-5 targets, until they are promoted or dropped.
    #[serde(default)]
    pub held: DeleterMap,
}

/// Whether `s` is lowercase 64-character hex (an event id or a pubkey).
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Drop malformed deleters and ids, and empty deleters.
fn sanitise(map: &mut DeleterMap) {
    map.retain(|deleter, ids| {
        ids.retain(|id, _| is_hex64(id));
        is_hex64(deleter) && !ids.is_empty()
    });
}

/// Keep `ids`'s `cap` newest entries; ties break on the id so the result does
/// not depend on hash order.
pub fn trim_deleter(ids: &mut HashMap<String, u64>, cap: usize) {
    if ids.len() <= cap {
        return;
    }
    let mut entries: Vec<(String, u64)> = ids.drain().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries.truncate(cap);
    ids.extend(entries);
}

/// Cap `map` at `total` entries by a fair share: find the highest level `L`
/// such that `sum(min(len, L)) <= total` and trim every deleter above `L` to
/// its `L` newest. A deleter at or below `L` loses nothing, so a flood only
/// ever cuts the flooder (and anyone else above the common share).
pub fn fair_trim(map: &mut DeleterMap, total: usize) {
    let sum: usize = map.values().map(HashMap::len).sum();
    if sum <= total {
        return;
    }
    let fits = |level: usize| map.values().map(|ids| ids.len().min(level)).sum::<usize>() <= total;
    let (mut lo, mut hi) = (0usize, map.values().map(HashMap::len).max().unwrap_or(0));
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    for ids in map.values_mut() {
        trim_deleter(ids, lo);
    }
    map.retain(|_, ids| !ids.is_empty());
}

/// Apply every cap to a state: per deleter, then the fair global share.
pub fn enforce_caps(state: &mut DeletionSyncState) {
    for ids in state.sealed.values_mut() {
        trim_deleter(ids, SEALED_PER_DELETER);
    }
    for ids in state.held.values_mut() {
        trim_deleter(ids, HELD_PER_DELETER);
    }
    fair_trim(&mut state.sealed, SEALED_TOTAL);
    fair_trim(&mut state.held, HELD_TOTAL);
}

/// Parse a stored [`DeletionSyncState`], discarding anything untrustworthy.
///
/// Unreadable JSON yields the default state (no marker, no tombstones), which
/// is the full sync a new device does. A marker of zero or later than `now`
/// is dropped: zero is meaningless and a future marker would skip deletions.
/// Entries whose deleter or id is not lowercase hex are dropped, and every
/// cap is applied.
pub fn parse_state(raw: Option<&str>, now: u64) -> DeletionSyncState {
    let mut state: DeletionSyncState = raw
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    state.since = state.since.filter(|&s| s > 0 && s <= now);
    sanitise(&mut state.sealed);
    sanitise(&mut state.held);
    enforce_caps(&mut state);
    state
}

/// The marker to store after a settled sync.
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

/// Hold the targets of one kind-5 from `deleter` until they resolve.
///
/// A deleter or id that is not lowercase hex is skipped (the relay only
/// tombstones well-formed ids, and only hex pubkeys sign); so is an id this
/// deleter already has resolved. `created_at` is bounded by `now` so a kind-5
/// dated in the future cannot pin itself at the head of its deleter's order.
/// Only `deleter`'s own entries are touched.
pub fn record_held(
    state: &mut DeletionSyncState,
    deleter: &str,
    targets: &[String],
    created_at: u64,
    now: u64,
) {
    if !is_hex64(deleter) {
        return;
    }
    let ts = created_at.min(now);
    let resolved = state.sealed.get(deleter);
    let fresh: Vec<&String> = targets
        .iter()
        .filter(|id| is_hex64(id) && !resolved.is_some_and(|r| r.contains_key(*id)))
        .collect();
    if fresh.is_empty() {
        return;
    }
    let own = state.held.entry(deleter.to_string()).or_default();
    for id in fresh {
        let entry = own.entry(id.clone()).or_insert(ts);
        *entry = (*entry).max(ts);
    }
    trim_deleter(own, HELD_PER_DELETER);
}

/// How a held tombstone on a restored sealed original resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The deleter is the author, or the relay vouches it is an admin.
    Honoured,
    /// The relay has definitely said the (non-author) deleter is no admin.
    Refused,
    /// No answer from the relay yet.
    Pending,
}

/// Resolve `deleter`'s tombstone on a sealed original by `author`, given the
/// relay's answer on whether `deleter` is an admin (`None`: not yet asked or
/// not yet answered).
pub fn resolution(author: &str, deleter: &str, admin: Option<bool>) -> Resolution {
    if deleter.eq_ignore_ascii_case(author) {
        return Resolution::Honoured;
    }
    match admin {
        Some(true) => Resolution::Honoured,
        Some(false) => Resolution::Refused,
        None => Resolution::Pending,
    }
}

/// `id` has been seen as a restored sealed original by `author`: promote each
/// honoured held tombstone on it to `sealed`, drop each refused one, keep the
/// pending. Returns whether anything changed.
pub fn resolve_sealed(
    state: &mut DeletionSyncState,
    id: &str,
    author: &str,
    admin: impl Fn(&str) -> Option<bool>,
) -> bool {
    let id = id.to_lowercase();
    let mut changed = false;
    let deleters: Vec<String> = state
        .held
        .iter()
        .filter(|(_, ids)| ids.contains_key(&id))
        .map(|(d, _)| d.clone())
        .collect();
    for deleter in deleters {
        let outcome = resolution(author, &deleter, admin(&deleter));
        if outcome == Resolution::Pending {
            continue;
        }
        let Some(ids) = state.held.get_mut(&deleter) else {
            continue;
        };
        let Some(ts) = ids.remove(&id) else {
            continue;
        };
        if ids.is_empty() {
            state.held.remove(&deleter);
        }
        if outcome == Resolution::Honoured {
            let own = state.sealed.entry(deleter).or_default();
            own.insert(id.clone(), ts);
            trim_deleter(own, SEALED_PER_DELETER);
        }
        changed = true;
    }
    changed
}

// -- paging -------------------------------------------------------------------

/// Where a delivered kind-5 came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The store's long-lived subscription (backfill, then live).
    Main,
    /// The numbered page subscription.
    Page(u32),
}

/// What to do after a backfill or a page reaches EOSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageStep {
    /// Every kind-5 at or after the marker has been delivered.
    Done,
    /// Fetch the next page down, `until` inclusive.
    Next {
        /// `until` for the next page.
        until: u64,
    },
    /// Too many pages, or a page made no progress: keep the old marker.
    GiveUp,
}

/// After the first EOSE: page only when a marked filter hit the row cap.
pub fn first_step(since: Option<u64>, rows: usize, oldest: Option<u64>) -> PageStep {
    match (since, oldest) {
        (Some(_), Some(o)) if rows >= RELAY_FILTER_LIMIT as usize => PageStep::Next { until: o },
        _ => PageStep::Done,
    }
}

/// After page `pages_done` (fetched with `until`, inclusive) reaches EOSE.
///
/// Termination is by progress, not by counting: the relay drops rows after
/// its SQL `LIMIT` (NIP-40-expired events) and answers a failed query with an
/// empty result and an EOSE, so a short page does not prove the relay had no
/// more. `rows` counts every row delivered for the page, and `oldest` is the
/// oldest `created_at` among them.
///
/// - No rows at all: the inclusive `until` boundary row should have come
///   back, so the query failed or the row vanished. Give up.
/// - No row older than `until`: nothing below the boundary is left, so the
///   sync is complete. If such a page is full, though, more than a page
///   shares the boundary timestamp and stepping past it would skip unseen
///   rows. Give up.
/// - Otherwise page on from the new oldest, up to [`MAX_PAGES`].
pub fn next_page(rows: usize, oldest: Option<u64>, until: u64, pages_done: u32) -> PageStep {
    let Some(oldest) = oldest.filter(|_| rows > 0) else {
        return PageStep::GiveUp;
    };
    if oldest >= until {
        return if rows >= RELAY_FILTER_LIMIT as usize {
            PageStep::GiveUp
        } else {
            PageStep::Done
        };
    }
    if pages_done >= MAX_PAGES {
        return PageStep::GiveUp;
    }
    PageStep::Next { until: oldest }
}

/// What the caller must do after an EOSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EoseAction {
    /// Nothing (a replayed or stale EOSE while paging).
    Ignore,
    /// Persist the state.
    Save,
    /// Subscribe to page `page` with `until`.
    Fetch {
        /// `until` for the page, inclusive.
        until: u64,
        /// Page number, starting at 1.
        page: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Backfill {
        rows: usize,
        oldest: Option<u64>,
    },
    Paging {
        page: u32,
        until: u64,
        rows: usize,
        oldest: Option<u64>,
    },
    Settled,
}

impl Default for Phase {
    fn default() -> Self {
        Self::Backfill {
            rows: 0,
            oldest: None,
        }
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
    phase: Phase,
}

impl DeletionProgress {
    /// Start from the persisted state.
    pub fn new(state: DeletionSyncState) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }

    /// Note a delivered kind-5 from `deleter`. `hold_targets` is true for the
    /// channel scope, whose sealed-original tombstones must outlive the
    /// session.
    pub fn observe(
        &mut self,
        created_at: u64,
        deleter: &str,
        targets: &[String],
        hold_targets: bool,
        now: u64,
        source: Source,
    ) {
        self.newest_seen = Some(self.newest_seen.map_or(created_at, |n| n.max(created_at)));
        match (&mut self.phase, source) {
            (Phase::Backfill { rows, oldest }, Source::Main) => {
                *rows += 1;
                *oldest = Some(oldest.map_or(created_at, |o| o.min(created_at)));
            }
            (
                Phase::Paging {
                    page, rows, oldest, ..
                },
                Source::Page(p),
            ) if *page == p => {
                *rows += 1;
                *oldest = Some(oldest.map_or(created_at, |o| o.min(created_at)));
            }
            _ => {}
        }
        if hold_targets {
            record_held(&mut self.state, deleter, targets, created_at, now);
        }
    }

    fn settle(&mut self, advance: bool, now: u64) -> EoseAction {
        // A marked backfill with no kind-5 at all leaves the marker as it is
        // (`next_marker` needs a delivery); that also covers a failed query.
        if advance {
            self.state.since = next_marker(self.state.since, self.newest_seen, now);
        }
        enforce_caps(&mut self.state);
        self.phase = Phase::Settled;
        EoseAction::Save
    }

    fn step(&mut self, step: PageStep, next_page_no: u32, now: u64) -> EoseAction {
        match step {
            PageStep::Done => self.settle(true, now),
            PageStep::GiveUp => self.settle(false, now),
            PageStep::Next { until } => {
                self.phase = Phase::Paging {
                    page: next_page_no,
                    until,
                    rows: 0,
                    oldest: None,
                };
                EoseAction::Fetch {
                    until,
                    page: next_page_no,
                }
            }
        }
    }

    /// The store's subscription reached EOSE.
    pub fn on_main_eose(&mut self, now: u64) -> EoseAction {
        match self.phase {
            Phase::Backfill { rows, oldest } => {
                let step = first_step(self.state.since, rows, oldest);
                self.step(step, 1, now)
            }
            // The page chain settles the sync; a replayed EOSE changes nothing.
            Phase::Paging { .. } => EoseAction::Ignore,
            // Settled once: a replayed EOSE (AUTH, reconnect) saves the
            // tombstones but never recomputes the marker from deliveries
            // that were not part of the settled sync.
            Phase::Settled => {
                enforce_caps(&mut self.state);
                EoseAction::Save
            }
        }
    }

    /// Page `page` reached EOSE.
    pub fn on_page_eose(&mut self, page: u32, now: u64) -> EoseAction {
        match self.phase {
            Phase::Paging {
                page: current,
                until,
                rows,
                oldest,
            } if current == page => {
                let step = next_page(rows, oldest, until, page);
                self.step(step, page + 1, now)
            }
            _ => EoseAction::Ignore,
        }
    }
}

// -- localStorage and relay ----------------------------------------------------

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

/// Apply the caps and persist.
pub fn persist(scope: DeletionScope, progress: StoredValue<DeletionProgress>) {
    progress.update_value(|p| {
        enforce_caps(&mut p.state);
        save(scope, &p.state);
    });
}

/// The store's handler for one kind-5, told where it came from.
pub type Kind5Handler = Rc<dyn Fn(NostrEvent, Source)>;

/// Carry out an [`EoseAction`]: save, or open the next page subscription.
///
/// A page goes through the same `on_kind5` handler as the main subscription
/// (re-deliveries at the inclusive `until` boundary are idempotent there),
/// and is unsubscribed at its first EOSE.
pub fn drive(
    relay: &RelayConnection,
    scope: DeletionScope,
    progress: StoredValue<DeletionProgress>,
    on_kind5: Kind5Handler,
    action: EoseAction,
) {
    match action {
        EoseAction::Ignore => {}
        EoseAction::Save => persist(scope, progress),
        EoseAction::Fetch { until, page } => {
            let since = progress.with_value(|p| p.state.since);
            let sub_id: Rc<RefCell<Option<String>>> = Rc::default();
            let handler = on_kind5.clone();
            let on_event = Rc::new(move |ev: NostrEvent| {
                if ev.kind == 5 {
                    handler(ev, Source::Page(page));
                }
            });
            let relay_for_eose = relay.clone();
            let sub_for_eose = sub_id.clone();
            let on_eose = Rc::new(move || {
                // First EOSE only: a replay after a reconnect finds no id.
                let Some(id) = sub_for_eose.borrow_mut().take() else {
                    return;
                };
                relay_for_eose.unsubscribe(&id);
                let now = now_secs();
                let next = progress
                    .try_update_value(|p| p.on_page_eose(page, now))
                    .unwrap_or(EoseAction::Ignore);
                drive(&relay_for_eose, scope, progress, on_kind5.clone(), next);
            });
            let id = relay.subscribe(
                vec![deletion_page_filter(since, until)],
                on_event,
                Some(on_eose),
            );
            *sub_id.borrow_mut() = Some(id);
        }
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

    fn total(t: &DeleterMap) -> usize {
        t.values().map(HashMap::len).sum()
    }

    fn unknown(_: &str) -> Option<bool> {
        None
    }

    #[test]
    fn margin_is_two_relay_drift_allowances() {
        assert_eq!(RELAY_MAX_TIMESTAMP_DRIFT_SECS, 7 * DAY);
        assert_eq!(DELETION_SINCE_MARGIN_SECS, 14 * DAY);
    }

    // --- parsing ---

    #[test]
    fn missing_or_corrupt_state_is_a_full_sync() {
        for raw in [
            None,
            Some("not json"),
            Some("[1,2]"),
            Some(r#"{"since":"x"}"#),
        ] {
            assert_eq!(parse_state(raw, NOW), DeletionSyncState::default());
        }
    }

    #[test]
    fn a_stored_record_round_trips() {
        let state = DeletionSyncState {
            since: Some(NOW - 20 * DAY),
            sealed: HashMap::from([(pk('a'), HashMap::from([(id(1), NOW - DAY)]))]),
            held: HashMap::from([(pk('b'), HashMap::from([(id(2), NOW - DAY)]))]),
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
            r#"{{"held":{{"{a}":{{"{ok}":1,"{upper}":2,"short":3}},"{bad}":{{"{ok}":4}},"{b}":{{"short":5}}}}}}"#,
            a = pk('a'),
            b = pk('b'),
            bad = "g".repeat(64),
            ok = id(7),
            // Letters in it, so uppercasing actually changes it.
            upper = id(0xabcd).to_uppercase(),
        );
        let state = parse_state(Some(&raw), NOW);
        assert_eq!(
            state.held,
            HashMap::from([(pk('a'), HashMap::from([(id(7), 1)]))])
        );
    }

    #[test]
    fn caps_are_applied_on_load() {
        let many: HashMap<String, u64> = (0..HELD_PER_DELETER as u64 + 5)
            .map(|n| (id(n), n))
            .collect();
        let json = serde_json::to_string(&DeletionSyncState {
            since: None,
            sealed: HashMap::new(),
            held: HashMap::from([(pk('a'), many)]),
        })
        .unwrap();
        let state = parse_state(Some(&json), NOW);
        assert_eq!(state.held[&pk('a')].len(), HELD_PER_DELETER);
        assert!(!state.held[&pk('a')].contains_key(&id(0)), "oldest evicted");
    }

    // --- held tombstones ---

    #[test]
    fn holding_is_per_deleter_newest_first_and_skips_malformed_input() {
        let mut s = DeletionSyncState::default();
        record_held(&mut s, &pk('a'), &[id(1), "nope".into()], NOW - 5, NOW);
        record_held(&mut s, &pk('a'), &[id(1)], NOW - 9, NOW);
        assert_eq!(s.held[&pk('a')], HashMap::from([(id(1), NOW - 5)]));
        record_held(&mut s, "not-a-pubkey", &[id(2)], NOW, NOW);
        record_held(&mut s, &pk('b'), &["nope".into()], NOW, NOW);
        record_held(&mut s, &pk('c'), &[id(3)], NOW + 7 * DAY, NOW);
        assert_eq!(
            s.held[&pk('c')][&id(3)],
            NOW,
            "future kind-5 bounded by now"
        );
        assert_eq!(s.held.len(), 2);
    }

    #[test]
    fn one_kind5_with_many_targets_only_cuts_its_own_deleter() {
        let mut s = DeletionSyncState::default();
        record_held(&mut s, &pk('b'), &[id(1)], NOW - 30 * DAY, NOW);
        let junk: Vec<String> = (1000..3000).map(id).collect();
        record_held(&mut s, &pk('a'), &junk, NOW, NOW);
        enforce_caps(&mut s);
        assert_eq!(s.held[&pk('a')].len(), HELD_PER_DELETER);
        assert_eq!(s.held[&pk('b')], HashMap::from([(id(1), NOW - 30 * DAY)]));
    }

    #[test]
    fn an_already_resolved_target_is_not_held_again() {
        let mut s = DeletionSyncState::default();
        s.sealed.insert(pk('a'), HashMap::from([(id(1), 5)]));
        record_held(&mut s, &pk('a'), &[id(1)], NOW, NOW);
        assert!(s.held.is_empty());
    }

    // --- resolution (the ordering problem) ---

    #[test]
    fn resolution_rules() {
        let a = pk('a');
        assert_eq!(resolution(&a, &a, None), Resolution::Honoured);
        assert_eq!(
            resolution(&a, &a.to_uppercase(), Some(false)),
            Resolution::Honoured
        );
        assert_eq!(resolution(&a, &pk('m'), Some(true)), Resolution::Honoured);
        assert_eq!(resolution(&a, &pk('m'), Some(false)), Resolution::Refused);
        assert_eq!(resolution(&a, &pk('m'), None), Resolution::Pending);
    }

    #[test]
    fn a_held_author_tombstone_is_promoted_when_its_target_proves_sealed() {
        // Session 1: the kind-5 lands, the target is unknown; the marker may
        // then pass the kind-5. The held entry survives the reload.
        let mut s = DeletionSyncState::default();
        record_held(&mut s, &pk('a'), &[id(1)], NOW - 20 * DAY, NOW);
        let reloaded = parse_state(Some(&serde_json::to_string(&s).unwrap()), NOW);
        // Session 2: the target arrives as a restored sealed original by A.
        let mut s = reloaded;
        assert!(resolve_sealed(&mut s, &id(1), &pk('a'), unknown));
        assert!(s.held.is_empty());
        assert_eq!(s.sealed[&pk('a')], HashMap::from([(id(1), NOW - 20 * DAY)]));
        // Resolving again changes nothing.
        assert!(!resolve_sealed(&mut s, &id(1), &pk('a'), unknown));
    }

    #[test]
    fn a_held_admin_tombstone_waits_for_the_answer_then_resolves() {
        let mut s = DeletionSyncState::default();
        record_held(&mut s, &pk('d'), &[id(1)], NOW, NOW);
        assert!(
            !resolve_sealed(&mut s, &id(1), &pk('a'), unknown),
            "pending stays held"
        );
        assert!(s.held[&pk('d')].contains_key(&id(1)));
        assert!(resolve_sealed(&mut s, &id(1), &pk('a'), |d| Some(
            d == pk('d')
        )));
        assert!(s.sealed[&pk('d')].contains_key(&id(1)));
    }

    #[test]
    fn a_members_held_tombstone_on_anothers_sealed_original_is_dropped() {
        let mut s = DeletionSyncState::default();
        record_held(&mut s, &pk('e'), &[id(1)], NOW, NOW);
        assert!(resolve_sealed(&mut s, &id(1), &pk('a'), |_| Some(false)));
        assert!(s.held.is_empty());
        assert!(s.sealed.is_empty());
    }

    #[test]
    fn ordinary_deletions_cannot_evict_a_resolved_sealed_deletion() {
        // Finding 3: an author's sealed-original deletion, then many ordinary
        // deletions by the same author.
        let mut s = DeletionSyncState::default();
        record_held(&mut s, &pk('a'), &[id(1)], NOW - 30 * DAY, NOW);
        resolve_sealed(&mut s, &id(1), &pk('a'), unknown);
        let later: Vec<String> = (100..100 + 5 * HELD_PER_DELETER as u64).map(id).collect();
        for (i, t) in later.iter().enumerate() {
            record_held(
                &mut s,
                &pk('a'),
                std::slice::from_ref(t),
                NOW - i as u64,
                NOW,
            );
        }
        enforce_caps(&mut s);
        assert!(s.sealed[&pk('a')].contains_key(&id(1)));
    }

    // --- caps ---

    #[test]
    fn fair_trim_cuts_only_those_above_the_common_share() {
        let mut m: DeleterMap = HashMap::new();
        m.insert(pk('a'), (0..900).map(|n| (id(n), n)).collect());
        m.insert(pk('b'), (1000..1010).map(|n| (id(n), n)).collect());
        m.insert(pk('c'), (2000..2200).map(|n| (id(n), n)).collect());
        fair_trim(&mut m, 500);
        assert!(total(&m) <= 500);
        assert_eq!(m[&pk('b')].len(), 10, "small deleter untouched");
        assert_eq!(m[&pk('c')].len(), 200, "below the common level, untouched");
        assert_eq!(
            m[&pk('a')].len(),
            290,
            "only the flooder is cut, to the level"
        );
        assert!(m[&pk('a')].contains_key(&id(899)), "newest kept");
        assert!(!m[&pk('a')].contains_key(&id(0)));
    }

    #[test]
    fn fair_trim_is_a_no_op_under_the_cap() {
        let mut m: DeleterMap = HashMap::from([(pk('a'), HashMap::from([(id(1), 1)]))]);
        let before = m.clone();
        fair_trim(&mut m, 1);
        assert_eq!(m, before);
    }

    #[test]
    fn global_caps_bound_storage_against_many_deleters() {
        let mut s = DeletionSyncState::default();
        for d in 0..100u64 {
            let deleter = format!("{d:064x}");
            let targets: Vec<String> = (0..HELD_PER_DELETER as u64)
                .map(|n| id(d * 1000 + n))
                .collect();
            record_held(&mut s, &deleter, &targets, NOW, NOW);
            s.sealed
                .insert(deleter, targets.iter().map(|t| (t.clone(), NOW)).collect());
        }
        enforce_caps(&mut s);
        assert!(total(&s.held) <= HELD_TOTAL);
        assert!(total(&s.sealed) <= SEALED_TOTAL);
        assert_eq!(s.held.len(), 100, "every deleter keeps a share");
    }

    // --- marker ---

    #[test]
    fn marker_arithmetic() {
        assert_eq!(next_marker(None, None, NOW), None);
        let newest = NOW - 3 * DAY;
        assert_eq!(
            next_marker(None, Some(newest), NOW),
            Some(newest - DELETION_SINCE_MARGIN_SECS)
        );
        assert_eq!(
            next_marker(Some(NOW - 30 * DAY), None, NOW),
            Some(NOW - 30 * DAY)
        );
        assert_eq!(next_marker(None, Some(DAY), NOW), None, "no zero marker");
    }

    #[test]
    fn a_future_dated_deletion_is_bounded_by_local_now() {
        let newest = NOW + RELAY_MAX_TIMESTAMP_DRIFT_SECS;
        assert_eq!(
            next_marker(None, Some(newest), NOW),
            Some(NOW - DELETION_SINCE_MARGIN_SECS)
        );
    }

    #[test]
    fn a_fast_device_clock_cannot_push_the_marker_past_relay_now() {
        // Device clock a year fast, newest deletion dated the full 7 days
        // ahead of the relay: the marker lands exactly on the oldest
        // `created_at` the relay can still accept, and `since` is inclusive.
        let relay_now = NOW;
        let newest = relay_now + RELAY_MAX_TIMESTAMP_DRIFT_SECS;
        assert_eq!(
            next_marker(None, Some(newest), relay_now + 365 * DAY),
            Some(relay_now - RELAY_MAX_TIMESTAMP_DRIFT_SECS)
        );
    }

    #[test]
    fn the_marker_never_moves_backwards() {
        let previous = NOW - 20 * DAY;
        assert_eq!(
            next_marker(Some(previous), Some(NOW - 20 * DAY), NOW),
            Some(previous)
        );
        assert_eq!(
            next_marker(Some(previous), Some(NOW), NOW),
            Some(NOW - DELETION_SINCE_MARGIN_SECS)
        );
    }

    // --- paging decisions ---

    #[test]
    fn first_step_pages_only_a_marked_full_backfill() {
        assert_eq!(first_step(None, LIMIT, Some(5)), PageStep::Done);
        assert_eq!(first_step(Some(1), LIMIT - 1, Some(5)), PageStep::Done);
        assert_eq!(
            first_step(Some(1), LIMIT, Some(5)),
            PageStep::Next { until: 5 }
        );
    }

    #[test]
    fn next_page_rules() {
        assert_eq!(next_page(3, Some(9), 9, 1), PageStep::Done, "boundary only");
        assert_eq!(next_page(LIMIT, Some(7), 9, 1), PageStep::Next { until: 7 });
        // A short page with older rows is not proof of the end (post-LIMIT
        // drops), so page on.
        assert_eq!(next_page(10, Some(7), 9, 1), PageStep::Next { until: 7 });
        assert_eq!(
            next_page(LIMIT, Some(9), 9, 1),
            PageStep::GiveUp,
            "no progress"
        );
        assert_eq!(
            next_page(LIMIT, Some(7), 9, MAX_PAGES),
            PageStep::GiveUp,
            "bound"
        );
        assert_eq!(
            next_page(0, None, 9, 1),
            PageStep::GiveUp,
            "empty: failed query"
        );
        assert_eq!(next_page(0, Some(7), 9, 1), PageStep::GiveUp);
    }

    fn marked(since: u64) -> DeletionProgress {
        DeletionProgress::new(DeletionSyncState {
            since: Some(since),
            ..DeletionSyncState::default()
        })
    }

    fn deliver(p: &mut DeletionProgress, n: usize, oldest: u64, source: Source) {
        for i in 0..n {
            p.observe(oldest + i as u64, &pk('a'), &[], true, NOW, source);
        }
    }

    #[test]
    fn a_full_marked_backfill_pages_down_and_settles_on_a_short_page() {
        let old = NOW - 40 * DAY;
        let mut p = marked(old);
        deliver(&mut p, LIMIT, NOW - 2 * DAY, Source::Main);
        assert_eq!(
            p.on_main_eose(NOW),
            EoseAction::Fetch {
                until: NOW - 2 * DAY,
                page: 1
            }
        );
        assert_eq!(p.state.since, Some(old), "nothing advanced while paging");
        // A replayed main EOSE during paging changes nothing.
        assert_eq!(p.on_main_eose(NOW), EoseAction::Ignore);
        // Page 1: full, older (boundary rows re-delivered count as rows).
        deliver(&mut p, LIMIT, NOW - 5 * DAY, Source::Page(1));
        assert_eq!(
            p.on_page_eose(1, NOW),
            EoseAction::Fetch {
                until: NOW - 5 * DAY,
                page: 2
            }
        );
        // A stale EOSE for page 1 is ignored.
        assert_eq!(p.on_page_eose(1, NOW), EoseAction::Ignore);
        // Page 2: short but with older rows, so one more page.
        deliver(&mut p, 10, NOW - 9 * DAY, Source::Page(2));
        assert_eq!(
            p.on_page_eose(2, NOW),
            EoseAction::Fetch {
                until: NOW - 9 * DAY,
                page: 3
            }
        );
        // Page 3: only the boundary row comes back, so complete.
        p.observe(NOW - 9 * DAY, &pk('a'), &[], true, NOW, Source::Page(3));
        assert_eq!(p.on_page_eose(3, NOW), EoseAction::Save);
        let newest = NOW - 2 * DAY + LIMIT as u64 - 1;
        assert_eq!(p.state.since, Some(newest - DELETION_SINCE_MARGIN_SECS));
    }

    #[test]
    fn a_page_with_no_progress_gives_up_and_keeps_the_marker() {
        let old = NOW - 40 * DAY;
        let mut p = marked(old);
        for _ in 0..LIMIT {
            p.observe(NOW - DAY, &pk('a'), &[], true, NOW, Source::Main);
        }
        assert_eq!(
            p.on_main_eose(NOW),
            EoseAction::Fetch {
                until: NOW - DAY,
                page: 1
            }
        );
        for _ in 0..LIMIT {
            p.observe(NOW - DAY, &pk('a'), &[], true, NOW, Source::Page(1));
        }
        assert_eq!(p.on_page_eose(1, NOW), EoseAction::Save);
        assert_eq!(p.state.since, Some(old));
        // Settled without advancing: later EOSEs never advance it this session.
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        assert_eq!(p.state.since, Some(old));
    }

    #[test]
    fn the_page_bound_gives_up_and_keeps_the_marker() {
        let old = NOW - 40 * DAY;
        let mut p = marked(old);
        let mut oldest = NOW;
        deliver(&mut p, LIMIT, oldest - LIMIT as u64, Source::Main);
        let mut action = p.on_main_eose(NOW);
        let mut pages = 0;
        while let EoseAction::Fetch { page, .. } = action {
            pages = page;
            oldest -= 2 * LIMIT as u64;
            deliver(&mut p, LIMIT, oldest, Source::Page(page));
            action = p.on_page_eose(page, NOW);
        }
        assert_eq!(pages, MAX_PAGES);
        assert_eq!(action, EoseAction::Save);
        assert_eq!(p.state.since, Some(old));
    }

    #[test]
    fn live_and_other_page_deliveries_do_not_count_towards_a_page() {
        let mut p = marked(NOW - 40 * DAY);
        deliver(&mut p, LIMIT, NOW - DAY, Source::Main);
        p.on_main_eose(NOW);
        // Live deliveries on the main subscription, and a stale page.
        deliver(&mut p, LIMIT, NOW, Source::Main);
        deliver(&mut p, LIMIT, NOW - 3 * DAY, Source::Page(7));
        // Page 1 (until = NOW - DAY) brings back only boundary rows.
        for _ in 0..3 {
            p.observe(NOW - DAY, &pk('a'), &[], true, NOW, Source::Page(1));
        }
        assert_eq!(p.on_page_eose(1, NOW), EoseAction::Save);
    }

    #[test]
    fn an_empty_page_gives_up_and_keeps_the_marker() {
        let old = NOW - 40 * DAY;
        let mut p = marked(old);
        deliver(&mut p, LIMIT, NOW - DAY, Source::Main);
        assert!(matches!(p.on_main_eose(NOW), EoseAction::Fetch { .. }));
        assert_eq!(p.on_page_eose(1, NOW), EoseAction::Save);
        assert_eq!(p.state.since, Some(old));
    }

    #[test]
    fn a_marked_backfill_with_nothing_delivered_keeps_the_marker() {
        let old = NOW - 40 * DAY;
        let mut p = marked(old);
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        assert_eq!(p.state.since, Some(old));
        // Live deliveries and a replayed EOSE do not move a settled marker.
        p.observe(NOW, &pk('a'), &[], true, NOW, Source::Main);
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        assert_eq!(p.state.since, Some(old));
    }

    #[test]
    fn an_unmarked_full_first_sync_settles_without_paging() {
        let mut p = DeletionProgress::new(DeletionSyncState::default());
        deliver(&mut p, LIMIT, NOW - DAY, Source::Main);
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        assert!(p.state.since.is_some());
    }

    #[test]
    fn a_short_marked_backfill_settles_and_replays_keep_the_marker() {
        let mut p = marked(NOW - 40 * DAY);
        deliver(&mut p, 3, NOW - 2 * DAY, Source::Main);
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        let first = p.state.since;
        assert!(first > Some(NOW - 40 * DAY));
        // The post-AUTH replay re-delivers nothing (per-sub dedup).
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        assert_eq!(p.state.since, first);
    }

    #[test]
    fn reaction_progress_holds_no_tombstones() {
        let mut p = DeletionProgress::new(DeletionSyncState::default());
        p.observe(NOW - DAY, &pk('a'), &[id(1)], false, NOW, Source::Main);
        assert_eq!(p.on_main_eose(NOW), EoseAction::Save);
        assert!(p.state.held.is_empty() && p.state.sealed.is_empty());
        assert_eq!(p.state.since, Some(NOW - DAY - DELETION_SINCE_MARGIN_SECS));
    }

    #[test]
    fn scopes_use_distinct_keys() {
        assert_ne!(
            DeletionScope::Channels.storage_key(),
            DeletionScope::Reactions.storage_key()
        );
    }
}
