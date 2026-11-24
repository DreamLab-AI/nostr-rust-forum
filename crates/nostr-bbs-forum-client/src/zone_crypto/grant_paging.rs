//! Paging the grant sync's gift-wrap backlog past the relay's row cap.
//!
//! Every kind-1059 addressed to a member (DMs, self-copies, tickets and
//! zone-key grants alike) comes through the grant subscriptions. The relay
//! answers a filter with at most `limit` rows, newest first, so one REQ on a
//! cold device with more wraps than that never receives the oldest ones, and
//! zone-key grants are typically the oldest. The backlog would still settle,
//! and a topic needing a missed key would read as a definitive "not found".
//!
//! So each grant scope (the identity key, and the inbox key when used) pages:
//! the long-lived subscription asks for [`RELAY_FILTER_LIMIT`] rows; then a
//! page subscription asks again with an inclusive `until` at the oldest
//! `created_at` seen, and so on, one page subscription at a time per scope
//! (each closed at its EOSE, so the relay's subscription cap is never
//! approached). [`ScopePager`] holds that state for one scope; the store only
//! opens and closes the subscriptions it asks for. One rule decides every
//! page, the first included: the deletion sync's
//! ([`deletion_sync::next_page_within`]), since it is the same relay, the
//! same `ORDER BY created_at DESC LIMIT`, and the same failure modes. In
//! particular a short page does not prove the end (the relay drops
//! NIP-40-expired rows after its SQL `LIMIT`), so any page with rows older
//! than its `until` is followed by one more. A page's rows are counted once
//! per wrap id, so a page re-delivered after a reconnect is not mistaken for
//! a fuller one.
//!
//! An empty later page should not happen: the inclusive boundary wrap comes
//! back unless it was deleted meanwhile (the old-grant sweep, another
//! device) or the query failed (the relay currently answers a storage error
//! with an empty result and an EOSE). The same inclusive `until` is asked
//! again first, which rides out one failed query without skipping the
//! unseen wraps that share the boundary timestamp. Empty twice, the page is
//! asked once more past the boundary (`until - 1`); a walk that takes that
//! step may have skipped wraps at the boundary, so however it ends it is
//! *unverified*: the backlog may settle, but no backfill marker is written,
//! so the next session walks the scope again.
//!
//! The walk is bounded at page 0 plus [`GRANT_MAX_PAGES`] pages. Reaching the
//! bound gives up: the backlog never settles this session, so a page waiting
//! on a key reports the keys-timed-out copy, never "not found", and no marker
//! is written.
//!
//! A wrap's `created_at` is not when it arrived: NIP-59 randomises it up to
//! two days into the past, and the relay accepts any event dated up to
//! seven days either side of its clock. That is fine for paging (`until` steps through the wraps' own timestamps, which
//! is what the relay orders by), but "oldest seen" is the wrap's timestamp,
//! never the rumour's.
//!
//! A warm device must not re-page its whole history every session. A scope
//! that completes a verified backfill records WHEN (`completed_at`, persisted
//! per identity, scope and addressed key), and only once every wrap of that
//! sign-in has been processed with no failure worth retrying (see
//! `GrantBacklog::take_due_markers`). A later session may stop at a full page
//! whose wraps were all already processed, but only once that page lies
//! entirely below `completed_at - WARM_STOP_MARGIN_SECS` (the relay's
//! accepted past drift, seven days, plus a day for skew between this
//! device's clock, which wrote `completed_at`, and the relay's): a wrap that
//! reached the relay after the last backfill carries a `created_at` at most
//! seven days before it landed, whoever sent it and however (a mesh peer
//! included), so it always sorts above such a page, and was delivered (and
//! processed) on an earlier page of this session. NIP-59's own two-day
//! backdating is not the bound: a sender may date a wrap anywhere the relay
//! accepts. The page must also lie below the marker's *floor*, the oldest
//! wrap the last session left unread after a refusable signer failed on it
//! twice (see `GrantBacklog::take_due_markers`), so that wrap is reached
//! and tried again. Stopping on processed wraps alone
//! would be unsafe: an account that received more than a page of wraps
//! while offline could have a fresh grant backdated below a fully processed
//! page. Without a marker (a first backfill, or one that was interrupted)
//! paging continues to the end, so an interrupted backfill resumes from the
//! top next session, skipping the unwrap of every wrap it already processed.
//!
//! The inbox scope's marker names the inbox key as well as the identity: a
//! different inbox key restored later (from its backup event) has its own
//! history, which the old key's marker says nothing about.
//!
//! With `GRANT_SWEEP_ENABLED` on there is no warm stop at all
//! ([`warm_marker`]): the sweep deliberately revisits processed wraps to
//! delete old grants, and its "cleanup finished" verdict is sent when a
//! scope completes, so stopping early would let that verdict claim wraps
//! that were never examined.
//!
//! Pure, so it unit-tests natively.

use std::collections::HashSet;

use crate::stores::channels::RELAY_FILTER_LIMIT;
use crate::stores::deletion_sync::{self as deletion_sync, PageStep};

/// How far before it lands the relay accepts a wrap's `created_at`: the
/// relay's own ingress bound, shared through core so the two cannot drift.
pub const RELAY_PAST_DRIFT_SECS: u64 = nostr_bbs_core::event::MAX_CREATED_AT_DRIFT_SECS;

/// Allowance for skew between this device's clock (which wrote the marker)
/// and the relay's clock: one day.
pub const CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;

/// How far below the marker time a page must lie to be a warm stop: eight
/// days.
pub const WARM_STOP_MARGIN_SECS: u64 = RELAY_PAST_DRIFT_SECS + CLOCK_SKEW_SECS;

/// Pages a grant scope may fetch after page 0 in one session: 51,000 wraps
/// in all. Separate from the deletion sync's bound
/// ([`deletion_sync::MAX_PAGES`], 20) because a missed grant costs the
/// member a zone, not a stale tombstone, and because grant pages are cheap
/// on the client once their wraps are processed (they are skipped, not
/// unwrapped). It still bounds the relay's work for one cold session at
/// 51 row-capped queries per scope; a warm session stops far earlier.
pub const GRANT_MAX_PAGES: u32 = 50;

/// The marker the warm stop may use: none while the grant sweep is on (see
/// the module notes), else the persisted completion time.
pub fn warm_marker(marker: Option<Marker>, sweep_on: bool) -> Option<Marker> {
    if sweep_on {
        None
    } else {
        marker
    }
}

/// A scope's persisted "backfill complete" marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Marker {
    /// When the backfill completed (seconds, this device's clock).
    pub done_at: u64,
    /// The oldest `created_at` among wraps that session left unread after a
    /// refusable signer failed on them twice (`WrapOutcome::UnreadableBySigner`):
    /// a warm stop must lie below it, so the next session reaches them again.
    pub floor: Option<u64>,
}

impl Marker {
    /// The stored form: `"<done_at>"`, or `"<done_at>:<floor>"`.
    pub fn encode(&self) -> String {
        match self.floor {
            Some(f) => format!("{}:{f}", self.done_at),
            None => self.done_at.to_string(),
        }
    }

    /// Whether a page whose newest wrap is `newest` lies below every wrap
    /// that may have reached the relay since the backfill, and below the
    /// floor.
    fn covers(&self, newest: u64) -> bool {
        newest < self.done_at.saturating_sub(WARM_STOP_MARGIN_SECS)
            && self.floor.is_none_or(|f| newest < f)
    }
}

/// What a page that came back empty is followed by (see the module notes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EmptyRetry {
    /// An ordinary page.
    #[default]
    No,
    /// The same inclusive `until` asked again after an empty answer.
    SameUntil,
    /// `until - 1`, after the same `until` came back empty twice. Wraps at
    /// `until` may have been skipped, so the walk ends unverified.
    PastBoundary,
}

/// What to do after a scope's page reaches EOSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStep {
    /// Every stored wrap of the scope has been delivered.
    Done {
        /// The end was seen, not inferred from two empty answers in a row
        /// (see the module notes). Only a verified end may write a marker.
        verified: bool,
    },
    /// Fetch the next page, wraps with `created_at <= until`.
    Next {
        /// `until` for the next page (inclusive).
        until: u64,
        /// Whether this page re-asks after an empty one.
        retry: EmptyRetry,
    },
    /// Too many pages, or a full page of one timestamp: the scope cannot be
    /// completed this session.
    GiveUp,
}

/// Parse a stored marker ([`Marker::encode`]), or `None` for a missing,
/// corrupt or zero value (treated as "no completed backfill").
pub fn parse_marker(raw: Option<&str>) -> Option<Marker> {
    let raw = raw?.trim();
    let (done, floor) = match raw.split_once(':') {
        Some((d, f)) => (d, Some(f.parse::<u64>().ok()?)),
        None => (raw, None),
    };
    let done_at = done.parse::<u64>().ok().filter(|&t| t > 0)?;
    Some(Marker { done_at, floor })
}

/// One grant subscription scope, for the persisted backfill marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrantScope {
    /// Wraps addressed to the member's identity key.
    Identity,
    /// Wraps addressed to the member's inbox key (`RECIPIENT_KEYS_ENABLED`).
    Inbox,
}

impl GrantScope {
    /// The `zone_kv` id of this scope's "backfill complete" marker for
    /// `owner` (the signed-in pubkey), whose wraps are addressed to `target`
    /// (the owner itself for [`GrantScope::Identity`], the inbox key for
    /// [`GrantScope::Inbox`]).
    pub fn marker_id(self, owner: &str, target: &str) -> String {
        let scope = match self {
            GrantScope::Identity => "identity",
            GrantScope::Inbox => "inbox",
        };
        format!("grant_backfill_complete:v1:{owner}:{scope}:{target}")
    }
}

/// What one page (or the long-lived subscription's stored events) delivered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageTally {
    /// Distinct wraps delivered, including the re-delivered `until`
    /// boundary rows from the page before.
    pub rows: usize,
    /// Oldest wrap `created_at` among them.
    pub oldest: Option<u64>,
    /// Newest wrap `created_at` among them.
    pub newest: Option<u64>,
    /// Rows whose wrap was not yet in the processed set.
    pub unprocessed: usize,
}

impl PageTally {
    /// Count one delivered wrap.
    pub fn observe(&mut self, created_at: u64, already_processed: bool) {
        self.rows += 1;
        self.oldest = Some(self.oldest.map_or(created_at, |o| o.min(created_at)));
        self.newest = Some(self.newest.map_or(created_at, |n| n.max(created_at)));
        if !already_processed {
            self.unprocessed += 1;
        }
    }

    fn full(&self) -> bool {
        self.rows >= RELAY_FILTER_LIMIT as usize
    }
}

/// Decide after a scope's page reaches EOSE.
///
/// `page` is 0 for the long-lived subscription's stored events (fetched with
/// no `until`) and `n` for the `n`-th page subscription, fetched with `until`
/// inclusive; `retry` says whether it re-asks after an empty page. `warm` is [`warm_marker`]'s answer.
///
/// - **Warm stop:** with a marker, a full page with nothing unprocessed whose
///   newest wrap is older than `warm - WARM_STOP_MARGIN_SECS`: done.
/// - **Empty page:** page 0 → done, unverified (no wraps, or a failed
///   query); a later page → the same `until` again, then once past the
///   boundary; empty again → done, unverified.
/// - **Otherwise** the deletion sync's rule, page 0 included (with `until`
///   taken as one past its newest row, so any rows at all lead to one more
///   page): nothing older than `until` → done, unless that page is full of
///   one timestamp → give up; otherwise page on from the oldest row, up to
///   [`GRANT_MAX_PAGES`], then give up.
///
/// [`GrantStep::GiveUp`] leaves the backlog unsettled, so a page waiting on a
/// key reports the keys-timed-out copy, never "not found".
pub fn grant_page_step(
    page: u32,
    until: Option<u64>,
    tally: PageTally,
    warm: Option<Marker>,
    retry: EmptyRetry,
) -> GrantStep {
    let below_new_wraps = match (warm, tally.newest) {
        (Some(marker), Some(newest)) => marker.covers(newest),
        _ => false,
    };
    if below_new_wraps && tally.full() && tally.unprocessed == 0 {
        return GrantStep::Done { verified: true };
    }
    if tally.rows == 0 {
        return match (until, retry) {
            // Page 0 empty: the member has no wraps, or the query failed (the
            // relay answers a storage error as empty, KF-31). Done either
            // way, but unverified: a fresh marker over a failed page 0 could
            // put a wrap that landed since below the next warm stop. A
            // member with no wraps loses nothing by having no marker.
            (None, _) => GrantStep::Done { verified: false },
            // Ask the same inclusive `until` again: one failed query must
            // not skip the unseen wraps sharing the boundary timestamp.
            (Some(u), EmptyRetry::No) => GrantStep::Next {
                until: u,
                retry: EmptyRetry::SameUntil,
            },
            (Some(u), EmptyRetry::SameUntil) if u > 0 => GrantStep::Next {
                until: u - 1,
                retry: EmptyRetry::PastBoundary,
            },
            (Some(_), _) => GrantStep::Done { verified: false },
        };
    }
    // Page 0 has no `until`: one past its newest row stands in, so every
    // delivered row is "older than until" and one more page follows.
    let effective_until = until.unwrap_or_else(|| tally.newest.unwrap_or(0).saturating_add(1));
    match deletion_sync::next_page_within(
        tally.rows,
        tally.oldest,
        effective_until,
        page,
        GRANT_MAX_PAGES,
    ) {
        PageStep::Done => GrantStep::Done { verified: true },
        PageStep::GiveUp => GrantStep::GiveUp,
        PageStep::Next { until } => GrantStep::Next {
            until,
            retry: EmptyRetry::No,
        },
    }
}

/// What a scope does after one of its pages ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagerAction {
    /// Open page subscription `page`: wraps with `created_at <= until`.
    Fetch {
        /// The page number, from 1.
        page: u32,
        /// Inclusive upper bound on `created_at`.
        until: u64,
    },
    /// Every stored wrap of the scope has been delivered.
    Done {
        /// See [`GrantStep::Done`].
        verified: bool,
    },
    /// The scope cannot be completed this session (see [`GrantStep::GiveUp`]).
    GiveUp,
}

/// The end of one page, as [`ScopePager::eose`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageEnd {
    /// The page that ended was a page subscription, not the long-lived
    /// page 0: close it now.
    pub close: bool,
    /// What follows.
    pub then: PagerAction,
}

/// The paging state of one grant scope across its page subscriptions.
///
/// Events and EOSEs are reported with the page number of the subscription
/// that delivered them; anything from another page (page 0's live wraps
/// after its EOSE, a stale EOSE after a reconnect) does not touch the
/// current page.
#[derive(Clone, Debug, Default)]
pub struct ScopePager {
    page: u32,
    until: Option<u64>,
    retry: EmptyRetry,
    /// The walk stepped past a boundary timestamp after two empty answers:
    /// its end cannot be verified.
    skipped: bool,
    tally: PageTally,
    page_ids: HashSet<String>,
    finished: bool,
}

impl ScopePager {
    /// A scope about to subscribe page 0 (no `until`).
    pub fn new() -> Self {
        Self::default()
    }

    /// The page being fetched, or `None` once the scope is done or gave up.
    #[cfg(test)]
    pub fn current_page(&self) -> Option<u32> {
        (!self.finished).then_some(self.page)
    }

    /// Count wrap `id` (with `created_at`, already `processed` or not)
    /// delivered by page `page`'s subscription. Returns whether it counted:
    /// not for another page, nor a second delivery of the same wrap.
    pub fn observe(&mut self, page: u32, id: &str, created_at: u64, processed: bool) -> bool {
        if self.finished || page != self.page || !self.page_ids.insert(id.to_string()) {
            return false;
        }
        self.tally.observe(created_at, processed);
        true
    }

    /// Page `page`'s subscription reached EOSE; `warm` is [`warm_marker`]'s
    /// answer. `None` when it is not the current page's first EOSE.
    pub fn eose(&mut self, page: u32, warm: Option<Marker>) -> Option<PageEnd> {
        if self.finished || page != self.page {
            return None;
        }
        let close = page > 0;
        let then = match grant_page_step(self.page, self.until, self.tally, warm, self.retry) {
            GrantStep::Next { until, retry } => {
                self.page += 1;
                self.until = Some(until);
                self.retry = retry;
                self.skipped |= retry == EmptyRetry::PastBoundary;
                self.tally = PageTally::default();
                self.page_ids.clear();
                PagerAction::Fetch {
                    page: self.page,
                    until,
                }
            }
            GrantStep::Done { verified } => {
                self.finished = true;
                PagerAction::Done {
                    verified: verified && !self.skipped,
                }
            }
            GrantStep::GiveUp => {
                self.finished = true;
                PagerAction::GiveUp
            }
        };
        Some(PageEnd { close, then })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const LIMIT: usize = RELAY_FILTER_LIMIT as usize;

    /// `rows` wraps, `processed` of them already handled, timestamps
    /// counting down from `newest`.
    fn page(rows: usize, processed: usize, newest: u64) -> PageTally {
        let mut t = PageTally::default();
        for i in 0..rows {
            t.observe(newest - i as u64, i < processed);
        }
        t
    }

    fn next(until: u64) -> GrantStep {
        GrantStep::Next {
            until,
            retry: EmptyRetry::No,
        }
    }

    fn warm(done_at: u64) -> Option<Marker> {
        Some(Marker {
            done_at,
            floor: None,
        })
    }

    const DONE: GrantStep = GrantStep::Done { verified: true };

    #[test]
    fn full_first_page_pages_on_from_its_oldest_row() {
        let t = page(LIMIT, 0, 1_000_000);
        assert_eq!(
            grant_page_step(0, None, t, None, EmptyRetry::No),
            next(1_000_000 - (LIMIT as u64 - 1))
        );
    }

    /// One rule for every page: a short page 0 with rows still takes one
    /// more page, since the relay may have dropped expired rows after its
    /// `LIMIT`.
    #[test]
    fn short_first_page_with_rows_takes_one_more_page() {
        assert_eq!(
            grant_page_step(0, None, page(37, 0, 500), None, EmptyRetry::No),
            next(464)
        );
    }

    /// Security re-review finding A: an empty page 0 is also what a failed
    /// D1 query looks like (KF-31), so it ends the walk unverified and
    /// writes no marker. A member with no wraps loses nothing by that.
    #[test]
    fn empty_first_page_is_done_but_unverified() {
        assert_eq!(
            grant_page_step(0, None, PageTally::default(), None, EmptyRetry::No),
            GrantStep::Done { verified: false }
        );
    }

    #[test]
    fn full_later_page_pages_on() {
        let t = page(LIMIT, 0, 900_000);
        assert_eq!(
            grant_page_step(1, Some(900_000), t, None, EmptyRetry::No),
            next(900_000 - (LIMIT as u64 - 1))
        );
    }

    #[test]
    fn short_later_page_with_older_rows_takes_one_more_page() {
        assert_eq!(
            grant_page_step(1, Some(900_000), page(12, 1, 900_000), None, EmptyRetry::No),
            next(899_989)
        );
    }

    #[test]
    fn page_with_nothing_older_than_until_is_done() {
        // Only the inclusive boundary row came back.
        assert_eq!(
            grant_page_step(2, Some(800), page(1, 1, 800), None, EmptyRetry::No),
            DONE
        );
    }

    /// An empty later page (a failed query, or the boundary wrap deleted at
    /// the true end): ask the same inclusive `until` again first, then once
    /// past the boundary, then give up as done but unverified (it may
    /// equally be three failed queries).
    #[test]
    fn empty_later_page_re_asks_the_same_until_then_past_the_boundary() {
        let empty = PageTally::default();
        assert_eq!(
            grant_page_step(2, Some(800), empty, None, EmptyRetry::No),
            GrantStep::Next {
                until: 800,
                retry: EmptyRetry::SameUntil
            }
        );
        assert_eq!(
            grant_page_step(3, Some(800), empty, None, EmptyRetry::SameUntil),
            GrantStep::Next {
                until: 799,
                retry: EmptyRetry::PastBoundary
            }
        );
        assert_eq!(
            grant_page_step(4, Some(799), empty, None, EmptyRetry::PastBoundary),
            GrantStep::Done { verified: false },
            "empty again: nothing older, or the relay failed three times"
        );
        // A re-ask found wraps: page on as usual.
        assert_eq!(
            grant_page_step(3, Some(800), page(5, 0, 800), None, EmptyRetry::SameUntil),
            next(796)
        );
    }

    #[test]
    fn full_page_of_one_timestamp_gives_up() {
        let mut t = PageTally::default();
        for _ in 0..LIMIT {
            t.observe(800, false);
        }
        assert_eq!(
            grant_page_step(2, Some(800), t, None, EmptyRetry::No),
            GrantStep::GiveUp
        );
    }

    #[test]
    fn page_bound_gives_up() {
        let t = page(LIMIT, 0, 500_000);
        assert_eq!(
            grant_page_step(GRANT_MAX_PAGES, Some(500_000), t, None, EmptyRetry::No),
            GrantStep::GiveUp
        );
        assert!(matches!(
            grant_page_step(GRANT_MAX_PAGES - 1, Some(500_000), t, None, EmptyRetry::No),
            GrantStep::Next { .. }
        ));
    }

    /// Marker written well after this page's wraps.
    const DONE_AT: u64 = 1_000_000 + 3 * WARM_STOP_MARGIN_SECS;

    #[test]
    fn warm_device_stops_at_a_fully_processed_old_full_page() {
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert_eq!(
            grant_page_step(0, None, t, warm(DONE_AT), EmptyRetry::No),
            DONE
        );
    }

    /// The relay's past drift plus clock skew: a grant received while
    /// offline can be dated up to seven days below a page of processed
    /// wraps, and the device's clock may be a day out. A page that recent
    /// must not stop.
    #[test]
    fn warm_device_pages_on_within_the_relay_drift_and_skew_margin() {
        assert_eq!(
            WARM_STOP_MARGIN_SECS,
            nostr_bbs_core::event::MAX_CREATED_AT_DRIFT_SECS + 24 * 60 * 60
        );
        assert_eq!(WARM_STOP_MARGIN_SECS, 8 * 24 * 60 * 60);
        let recent = DONE_AT - WARM_STOP_MARGIN_SECS + 10;
        let t = page(LIMIT, LIMIT, recent);
        assert!(matches!(
            grant_page_step(0, None, t, warm(DONE_AT), EmptyRetry::No),
            GrantStep::Next { .. }
        ));
    }

    #[test]
    fn without_the_marker_a_processed_page_still_pages_on() {
        // An interrupted or failed backfill wrote no marker: processed wraps
        // are skipped (not unwrapped) but paging continues to the end.
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, None, EmptyRetry::No),
            GrantStep::Next { .. }
        ));
    }

    #[test]
    fn warm_device_pages_on_while_a_page_has_new_wraps() {
        let t = page(LIMIT, LIMIT - 1, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, warm(DONE_AT), EmptyRetry::No),
            GrantStep::Next { .. }
        ));
    }

    /// With the grant sweep on there is no warm stop: the sweep revisits
    /// processed wraps and its verdict must not cover unexamined ones.
    #[test]
    fn grant_sweep_disables_the_warm_stop() {
        assert_eq!(warm_marker(warm(DONE_AT), true), None);
        assert_eq!(warm_marker(warm(DONE_AT), false), warm(DONE_AT));
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, warm_marker(warm(DONE_AT), true), EmptyRetry::No),
            GrantStep::Next { .. }
        ));
    }

    #[test]
    fn markers_parse_as_completion_times_with_an_optional_floor() {
        let plain = Marker {
            done_at: 1_800_000_000,
            floor: None,
        };
        let floored = Marker {
            done_at: 1_800_000_000,
            floor: Some(1_700_000_000),
        };
        assert_eq!(parse_marker(Some("1800000000")), Some(plain));
        assert_eq!(parse_marker(Some(&plain.encode())), Some(plain));
        assert_eq!(parse_marker(Some(&floored.encode())), Some(floored));
        assert_eq!(parse_marker(Some("0")), None);
        assert_eq!(parse_marker(Some("yes")), None);
        assert_eq!(parse_marker(Some("1800000000:x")), None);
        assert_eq!(parse_marker(None), None);
    }

    /// Security review finding 2: a page that would be a warm stop by the
    /// marker's time is not one while it lies at or above the floor (a wrap
    /// the last session left unread after a refusable signer failed twice).
    #[test]
    fn the_warm_stop_lies_below_the_floor() {
        let floor = 900_000;
        let marker = Some(Marker {
            done_at: DONE_AT,
            floor: Some(floor),
        });
        let above = page(LIMIT, LIMIT, floor + 5_000);
        assert!(matches!(
            grant_page_step(0, None, above, marker, EmptyRetry::No),
            GrantStep::Next { .. }
        ));
        let at = page(LIMIT, LIMIT, floor);
        assert!(matches!(
            grant_page_step(0, None, at, marker, EmptyRetry::No),
            GrantStep::Next { .. }
        ));
        let below = page(LIMIT, LIMIT, floor - 1);
        assert_eq!(
            grant_page_step(0, None, below, marker, EmptyRetry::No),
            DONE
        );
    }

    #[test]
    fn markers_are_per_identity_scope_and_addressed_key() {
        let a = GrantScope::Identity.marker_id("aa", "aa");
        assert_ne!(a, GrantScope::Inbox.marker_id("aa", "aa"));
        assert_ne!(a, GrantScope::Identity.marker_id("bb", "bb"));
        // A different inbox key has its own history.
        assert_ne!(
            GrantScope::Inbox.marker_id("aa", "k1"),
            GrantScope::Inbox.marker_id("aa", "k2")
        );
    }

    #[test]
    fn tally_tracks_the_wrap_timestamp_range() {
        let mut t = PageTally::default();
        t.observe(50, true);
        t.observe(10, false);
        t.observe(30, false);
        assert_eq!(t.oldest, Some(10));
        assert_eq!(t.newest, Some(50));
        assert_eq!(t.rows, 3);
        assert_eq!(t.unprocessed, 2);
    }

    // -- A fake relay with the D1 query's semantics -------------------------

    /// Stored wraps answered like the relay's
    /// `ORDER BY created_at DESC LIMIT ?` with an inclusive `until`. Ties are
    /// returned in id order, which SQLite does not promise; any fixed order
    /// exercises the same boundary rule.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct FakeRelay {
        /// `(id, created_at)`.
        pub rows: Vec<(String, u64)>,
        /// Query numbers (from 0) answered with an empty result, as the relay
        /// answers a failed D1 query today.
        pub fail_queries: HashSet<usize>,
        /// Before answering query `n`, delete these ids (the sweep, another
        /// device).
        pub delete_before: Vec<(usize, Vec<String>)>,
        pub queries: usize,
    }

    impl FakeRelay {
        /// `n` wraps with ids `w{i}` at `created_at = top - i / per_ts`
        /// (`per_ts` wraps share each timestamp).
        pub fn counting_down(n: usize, top: u64, per_ts: usize) -> Self {
            Self {
                rows: (0..n)
                    .map(|i| (format!("w{i:06}"), top - (i / per_ts) as u64))
                    .collect(),
                ..Self::default()
            }
        }

        pub fn query(&mut self, until: Option<u64>) -> Vec<(String, u64)> {
            let n = self.queries;
            self.queries += 1;
            for (at, ids) in &self.delete_before {
                if *at == n {
                    self.rows.retain(|(id, _)| !ids.contains(id));
                }
            }
            if self.fail_queries.contains(&n) {
                return Vec::new();
            }
            let mut hits: Vec<(String, u64)> = self
                .rows
                .iter()
                .filter(|(_, ts)| until.is_none_or(|u| *ts <= u))
                .cloned()
                .collect();
            hits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            hits.truncate(LIMIT);
            hits
        }
    }

    /// The result of walking one scope.
    #[derive(Debug)]
    pub(crate) struct Walk {
        /// Every wrap id delivered, in delivery order (duplicates included).
        pub delivered: Vec<String>,
        /// Subscriptions opened (page 0 included).
        pub subscriptions: u32,
        /// Page subscriptions closed by the pager.
        pub closed: u32,
        pub end: PagerAction,
    }

    /// Drive a [`ScopePager`] against `relay`, exactly as the store does: one
    /// page at a time, each page subscription closed at its EOSE.
    pub(crate) fn walk(
        relay: &mut FakeRelay,
        warm: Option<Marker>,
        processed: &HashSet<String>,
    ) -> Walk {
        let mut pager = ScopePager::new();
        let mut delivered = Vec::new();
        let (mut subscriptions, mut closed) = (1, 0);
        let mut until = None;
        loop {
            let page = pager.current_page().expect("walk ended without an action");
            for (id, ts) in relay.query(until) {
                pager.observe(page, &id, ts, processed.contains(&id));
                delivered.push(id);
            }
            let end = pager.eose(page, warm).expect("current page EOSE");
            closed += u32::from(end.close);
            match end.then {
                PagerAction::Fetch { page: p, until: u } => {
                    assert_eq!(p, page + 1, "pages advance one at a time");
                    until = Some(u);
                    subscriptions += 1;
                }
                other => {
                    return Walk {
                        delivered,
                        subscriptions,
                        closed,
                        end: other,
                    }
                }
            }
        }
    }

    fn distinct(ids: &[String]) -> HashSet<String> {
        ids.iter().cloned().collect()
    }

    fn all_ids(relay: &FakeRelay) -> HashSet<String> {
        relay.rows.iter().map(|(id, _)| id.clone()).collect()
    }

    #[test]
    fn a_backlog_just_over_one_page_is_delivered_in_full() {
        let mut relay = FakeRelay::counting_down(LIMIT + 1, 2_000_000, 1);
        let want = all_ids(&relay);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: true });
        assert_eq!(distinct(&w.delivered), want);
        // Every page subscription the pager opened, it closed.
        assert_eq!(w.closed, w.subscriptions - 1);
    }

    #[test]
    fn a_multi_page_backlog_is_delivered_in_full() {
        let mut relay = FakeRelay::counting_down(5_500, 2_000_000, 1);
        let want = all_ids(&relay);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: true });
        assert_eq!(distinct(&w.delivered), want);
        assert!(w.subscriptions >= 6, "{}", w.subscriptions);
        assert_eq!(w.closed, w.subscriptions - 1);
    }

    /// Wraps sharing a `created_at` straddle every page boundary; the
    /// inclusive `until` re-delivers them and nothing is skipped.
    #[test]
    fn shared_timestamps_at_page_boundaries_skip_nothing() {
        for per_ts in [2, 7, 333, 999] {
            let mut relay = FakeRelay::counting_down(4_321, 2_000_000, per_ts);
            let want = all_ids(&relay);
            let w = walk(&mut relay, None, &HashSet::new());
            assert_eq!(w.end, PagerAction::Done { verified: true }, "{per_ts}");
            assert_eq!(distinct(&w.delivered), want, "{per_ts} per timestamp");
        }
    }

    /// More than a page sharing one timestamp cannot be stepped past without
    /// skipping rows: give up rather than settle.
    #[test]
    fn more_than_a_page_on_one_timestamp_gives_up() {
        let mut relay = FakeRelay::counting_down(3 * LIMIT, 2_000_000, LIMIT + 1);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::GiveUp);
    }

    /// A backlog that ends exactly within the bound completes...
    #[test]
    fn a_backlog_inside_the_bound_completes() {
        // Each later page re-delivers one boundary row, so page 0 plus
        // GRANT_MAX_PAGES pages cover this many distinct wraps with one
        // final short page left to prove the end.
        let n = LIMIT + (GRANT_MAX_PAGES as usize - 1) * (LIMIT - 1);
        let mut relay = FakeRelay::counting_down(n, 9_000_000, 1);
        let want = all_ids(&relay);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: true });
        assert_eq!(distinct(&w.delivered), want);
        assert!(w.subscriptions <= GRANT_MAX_PAGES + 1);
    }

    /// ...and one beyond it gives up at page 0 + GRANT_MAX_PAGES, having
    /// delivered the newest wraps but not the oldest.
    #[test]
    fn a_backlog_beyond_the_bound_gives_up_at_the_bound() {
        let n = (GRANT_MAX_PAGES as usize + 1) * LIMIT + 500;
        let mut relay = FakeRelay::counting_down(n, 9_000_000, 1);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::GiveUp);
        assert_eq!(w.subscriptions, GRANT_MAX_PAGES + 1);
        assert_eq!(w.closed, GRANT_MAX_PAGES);
        let got = distinct(&w.delivered);
        assert!(got.contains("w000000"), "newest delivered");
        assert!(
            !got.contains(&format!("w{:06}", n - 1)),
            "oldest never seen"
        );
    }

    /// The deletion sync's bound (20) is not the grant bound: 21 pages of
    /// wraps, beyond the old bound, now complete.
    #[test]
    fn twenty_one_pages_of_wraps_complete_under_the_grant_bound() {
        let n = 21 * LIMIT + 1;
        let mut relay = FakeRelay::counting_down(n, 9_000_000, 1);
        let want = all_ids(&relay);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: true });
        assert_eq!(distinct(&w.delivered), want);
    }

    /// The boundary wrap is deleted between pages (the sweep, another
    /// device): the older wraps still arrive.
    #[test]
    fn a_deleted_boundary_wrap_does_not_stop_the_walk() {
        let mut relay = FakeRelay::counting_down(1_500, 2_000_000, 1);
        // Page 0 returns w000000..w000999; its oldest (w000999) is page 1's
        // inclusive boundary. Delete it before page 1 is asked.
        relay.delete_before.push((1, vec!["w000999".to_string()]));
        let older: HashSet<String> = (LIMIT..1_500).map(|i| format!("w{i:06}")).collect();
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: true });
        assert!(older.is_subset(&distinct(&w.delivered)));
    }

    /// The boundary wrap is deleted and it was the oldest: page 1 is empty,
    /// the re-ask is empty, and the walk ends unverified (no marker), which
    /// costs the next session a walk and nothing else.
    #[test]
    fn a_deleted_boundary_at_the_true_end_ends_unverified() {
        let mut relay = FakeRelay::counting_down(LIMIT, 2_000_000, 1);
        relay.delete_before.push((1, vec!["w000999".to_string()]));
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: false });
    }

    /// Two failed queries in a row read as the end, but unverified: the
    /// store may settle on it but must not write the marker.
    #[test]
    fn two_failed_queries_in_a_row_end_unverified() {
        let mut relay = FakeRelay::counting_down(2_500, 2_000_000, 1);
        relay.fail_queries = [1, 2].into_iter().collect();
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: false });
    }

    /// One failed query is ridden out by asking the same `until` again.
    #[test]
    fn one_failed_query_is_ridden_out() {
        let mut relay = FakeRelay::counting_down(2_500, 2_000_000, 1);
        relay.fail_queries = [1].into_iter().collect();
        let want = all_ids(&relay);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: true });
        // Only the boundary row of page 0 is not re-delivered; it was
        // delivered on page 0.
        assert_eq!(distinct(&w.delivered), want);
    }

    /// Warm session: new wraps on top, a long processed history below. It
    /// stops at the first full processed page past the margin, having
    /// delivered every new wrap, without walking the whole history.
    #[test]
    fn warm_session_stops_early_but_delivers_every_new_wrap() {
        let done_at = 50_000_000;
        let below = done_at - WARM_STOP_MARGIN_SECS - 10;
        // 1,200 new wraps from just below the marker upwards (inside the
        // margin), then 8,000 processed wraps well below it.
        let mut rows: Vec<(String, u64)> = (0..1_200)
            .map(|i| (format!("n{i:05}"), done_at + 500 - i as u64))
            .collect();
        rows.extend((0..8_000).map(|i| (format!("o{i:05}"), below - i as u64)));
        let processed: HashSet<String> = rows
            .iter()
            .filter(|(id, _)| id.starts_with('o'))
            .map(|(id, _)| id.clone())
            .collect();
        let mut relay = FakeRelay {
            rows,
            ..FakeRelay::default()
        };
        let w = walk(&mut relay, warm(done_at), &processed);
        assert_eq!(w.end, PagerAction::Done { verified: true });
        let got = distinct(&w.delivered);
        assert!((0..1_200).all(|i| got.contains(&format!("n{i:05}"))));
        assert!(w.subscriptions <= 4, "walked {} pages", w.subscriptions);
        // Cold (no marker), the same relay is walked to the end.
        relay.queries = 0;
        let cold = walk(&mut relay, None, &processed);
        assert!(cold.subscriptions >= 10);
    }

    /// Security review finding 1: the relay accepts a kind-1059 dated up to
    /// seven days before it lands, so a grant can arrive after the marker
    /// yet sort five days below it. A page that recent must not stop.
    #[test]
    fn a_page_inside_the_relay_drift_window_is_not_a_warm_stop() {
        let done_at = 50_000_000;
        let five_days = 5 * 24 * 60 * 60;
        let t = page(LIMIT, LIMIT, done_at - five_days);
        assert!(matches!(
            grant_page_step(0, None, t, warm(done_at), EmptyRetry::No),
            GrantStep::Next { .. }
        ));
    }

    /// Security review finding 3: a full page ends on timestamp T with more
    /// wraps at T unseen, and the next inclusive query fails (the relay
    /// answers a storage error as empty). Stepping straight to `until - 1`
    /// would skip the rest of T and still end verified.
    #[test]
    fn a_failed_query_inside_a_shared_timestamp_skips_nothing() {
        // 3,000 wraps sharing each timestamp in runs of 700: page 0 ends
        // inside a run, so page 1's inclusive `until` has unseen rows at it.
        let mut relay = FakeRelay::counting_down(3_000, 2_000_000, 700);
        relay.fail_queries = [1].into_iter().collect();
        let want = all_ids(&relay);
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(distinct(&w.delivered), want, "nothing at T skipped");
        assert_eq!(w.end, PagerAction::Done { verified: true });
    }

    /// Two failed inclusive queries in a row: only then the walk steps past
    /// T, and it ends unverified, since rows at T may have been skipped.
    #[test]
    fn stepping_past_a_shared_timestamp_ends_unverified() {
        let mut relay = FakeRelay::counting_down(3_000, 2_000_000, 700);
        relay.fail_queries = [1, 2].into_iter().collect();
        let w = walk(&mut relay, None, &HashSet::new());
        assert_eq!(w.end, PagerAction::Done { verified: false });
    }

    /// A page re-delivered after a reconnect (its REQ replayed before its
    /// EOSE) is counted once. Counting rows twice would make 600 boundary
    /// rows look like a full page of one timestamp and give up.
    #[test]
    fn a_replayed_page_is_counted_once() {
        let mut pager = ScopePager::new();
        for i in 0..LIMIT {
            assert!(pager.observe(0, &format!("a{i}"), 5_000 - i as u64, false));
        }
        let Some(PageEnd {
            then: PagerAction::Fetch { page: 1, until },
            ..
        }) = pager.eose(0, None)
        else {
            panic!("page 0 pages on");
        };
        // Page 1: 600 wraps at the boundary timestamp, delivered twice.
        for _ in 0..2 {
            for i in 0..600 {
                pager.observe(1, &format!("b{i}"), until, false);
            }
        }
        assert_eq!(
            pager.eose(1, None),
            Some(PageEnd {
                close: true,
                then: PagerAction::Done { verified: true }
            })
        );
    }

    /// Page 0 keeps delivering live wraps after its EOSE; they belong to no
    /// page and must not inflate page 1's tally. A stale or repeated EOSE is
    /// ignored.
    #[test]
    fn live_wraps_and_stale_eoses_do_not_touch_the_current_page() {
        let mut pager = ScopePager::new();
        pager.observe(0, "x", 100, false);
        assert!(matches!(
            pager.eose(0, None),
            Some(PageEnd {
                close: false,
                then: PagerAction::Fetch { page: 1, .. }
            })
        ));
        assert!(!pager.observe(0, "live", 200, false), "page 0 is over");
        assert_eq!(pager.eose(0, None), None, "a replayed page-0 EOSE");
        assert_eq!(pager.current_page(), Some(1));
        // Page 1 is empty → the same `until` again, then past it, then
        // done (unverified).
        assert_eq!(
            pager.eose(1, None).map(|e| e.then),
            Some(PagerAction::Fetch {
                page: 2,
                until: 100
            })
        );
        assert_eq!(
            pager.eose(2, None).map(|e| e.then),
            Some(PagerAction::Fetch { page: 3, until: 99 })
        );
        assert_eq!(
            pager.eose(3, None).map(|e| e.then),
            Some(PagerAction::Done { verified: false })
        );
        assert_eq!(pager.current_page(), None);
        assert_eq!(pager.eose(3, None), None);
        assert!(!pager.observe(3, "late", 1, false));
    }
}
