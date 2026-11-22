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
//! approached). One rule decides every page, the first included: the
//! deletion sync's ([`deletion_sync::next_page`]), since it is the same
//! relay, the same `ORDER BY created_at DESC LIMIT`, and the same failure
//! modes. In particular a short page does not prove the end (the relay drops
//! NIP-40-expired rows after its SQL `LIMIT`), so any page with rows older
//! than its `until` is followed by one more.
//!
//! An empty later page is not taken as a failed query outright: the inclusive
//! boundary wrap can have been deleted meanwhile (the old-grant sweep,
//! another device). The page is asked again once with an exclusive
//! boundary (`until - 1`); if that is empty too, there is nothing older.
//!
//! NIP-59 randomises a wrap's `created_at` up to two days into the past. That
//! is fine for paging (`until` steps through the wraps' own timestamps, which
//! is what the relay orders by), but "oldest seen" is the wrap's timestamp,
//! never the rumour's.
//!
//! A warm device must not re-page its whole history every session. A scope
//! that completes a backfill records WHEN (`completed_at`, persisted per
//! identity and scope), and only once every wrap of that sign-in has been
//! processed with no failure worth retrying (see
//! `GrantBacklog::marker_writable`). A later session may stop at a full page
//! whose wraps were all already processed, but only once that page lies
//! entirely below `completed_at - WARM_STOP_MARGIN_SECS` (NIP-59's two-day
//! backdating plus a day for skew between this device's clock, which wrote
//! `completed_at`, and the senders' clocks): a wrap published after the last
//! backfill carries a `created_at` at most two days before its publication,
//! so it always sorts above such a page, and was delivered (and processed)
//! on an earlier page of this session. Stopping on processed wraps alone
//! would be unsafe: an account that received more than a page of wraps
//! while offline could have a fresh grant backdated below a fully processed
//! page. Without a marker (a first backfill, or one that was interrupted)
//! paging continues to the end, so an interrupted backfill resumes from the
//! top next session, skipping the unwrap of every wrap it already processed.
//!
//! With `GRANT_SWEEP_ENABLED` on there is no warm stop at all
//! ([`warm_marker`]): the sweep deliberately revisits processed wraps to
//! delete old grants, and its "cleanup finished" verdict is sent when a
//! scope completes, so stopping early would let that verdict claim wraps
//! that were never examined.
//!
//! Pure, so it unit-tests natively.

use crate::stores::channels::RELAY_FILTER_LIMIT;
use crate::stores::deletion_sync::{self as deletion_sync, PageStep};

/// How far into the past NIP-59 lets a gift wrap's `created_at` be
/// randomised: two days.
pub const NIP59_BACKDATE_SECS: u64 = 2 * 24 * 60 * 60;

/// Allowance for skew between this device's clock (which wrote the marker)
/// and the clocks of the wraps' senders: one day.
pub const CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;

/// How far below the marker time a page must lie to be a warm stop.
pub const WARM_STOP_MARGIN_SECS: u64 = NIP59_BACKDATE_SECS + CLOCK_SKEW_SECS;

/// The marker the warm stop may use: none while the grant sweep is on (see
/// the module notes), else the persisted completion time.
pub fn warm_marker(completed_at: Option<u64>, sweep_on: bool) -> Option<u64> {
    if sweep_on {
        None
    } else {
        completed_at
    }
}

/// What to do after a scope's page reaches EOSE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStep {
    /// Every stored wrap of the scope has been delivered.
    Done,
    /// Fetch the next page, wraps with `created_at <= until`.
    Next {
        /// `until` for the next page (inclusive).
        until: u64,
        /// This next page is the exclusive re-ask after an empty page (see
        /// the module notes); if it is empty too, the scope is done.
        boundary_retry: bool,
    },
    /// Too many pages, or a full page of one timestamp: the scope cannot be
    /// completed this session.
    GiveUp,
}

/// Parse a stored marker: the completion time in seconds, or `None` for a
/// missing, corrupt or zero value (treated as "no completed backfill").
pub fn parse_marker(raw: Option<&str>) -> Option<u64> {
    raw?.trim().parse::<u64>().ok().filter(|&t| t > 0)
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
    /// `owner` (a pubkey).
    pub fn marker_id(self, owner: &str) -> String {
        let scope = match self {
            GrantScope::Identity => "identity",
            GrantScope::Inbox => "inbox",
        };
        format!("grant_backfill_complete:v1:{owner}:{scope}")
    }
}

/// What one page (or the long-lived subscription's stored events) delivered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageTally {
    /// Every row delivered, including re-deliveries at the `until` boundary.
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
/// inclusive; `boundary_retry` marks the exclusive re-ask after an empty
/// page. `warm` is [`warm_marker`]'s answer.
///
/// - **Warm stop:** with a marker, a full page with nothing unprocessed whose
///   newest wrap is older than `warm - WARM_STOP_MARGIN_SECS`:
///   [`GrantStep::Done`].
/// - **Empty page:** page 0 → done (there are no wraps); a later page → ask
///   once more with an exclusive boundary; empty again → done.
/// - **Otherwise** the deletion sync's rule, page 0 included (with `until`
///   taken as "now", so any rows at all lead to one more page): nothing
///   older than `until` → done, unless that page is full of one timestamp →
///   give up; otherwise page on from the oldest row, up to
///   [`deletion_sync::MAX_PAGES`], then give up.
///
/// [`GrantStep::GiveUp`] leaves the backlog unsettled, so a page waiting on a
/// key reports the keys-timed-out copy, never "not found".
pub fn grant_page_step(
    page: u32,
    until: Option<u64>,
    tally: PageTally,
    warm: Option<u64>,
    boundary_retry: bool,
) -> GrantStep {
    let below_new_wraps = match (warm, tally.newest) {
        (Some(done), Some(newest)) => newest < done.saturating_sub(WARM_STOP_MARGIN_SECS),
        _ => false,
    };
    if below_new_wraps && tally.full() && tally.unprocessed == 0 {
        return GrantStep::Done;
    }
    if tally.rows == 0 {
        return match until {
            Some(u) if !boundary_retry && u > 0 => GrantStep::Next {
                until: u - 1,
                boundary_retry: true,
            },
            _ => GrantStep::Done,
        };
    }
    // Page 0 has no `until`: one past its newest row stands in, so every
    // delivered row is "older than until" and one more page follows.
    let effective_until = until.unwrap_or_else(|| tally.newest.unwrap_or(0).saturating_add(1));
    match deletion_sync::next_page(tally.rows, tally.oldest, effective_until, page) {
        PageStep::Done => GrantStep::Done,
        PageStep::GiveUp => GrantStep::GiveUp,
        PageStep::Next { until } => GrantStep::Next {
            until,
            boundary_retry: false,
        },
    }
}

#[cfg(test)]
mod tests {
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
            boundary_retry: false,
        }
    }

    #[test]
    fn full_first_page_pages_on_from_its_oldest_row() {
        let t = page(LIMIT, 0, 1_000_000);
        assert_eq!(
            grant_page_step(0, None, t, None, false),
            next(1_000_000 - (LIMIT as u64 - 1))
        );
    }

    /// One rule for every page: a short page 0 with rows still takes one
    /// more page, since the relay may have dropped expired rows after its
    /// `LIMIT`.
    #[test]
    fn short_first_page_with_rows_takes_one_more_page() {
        assert_eq!(
            grant_page_step(0, None, page(37, 0, 500), None, false),
            next(464)
        );
    }

    #[test]
    fn empty_first_page_is_done() {
        assert_eq!(
            grant_page_step(0, None, PageTally::default(), None, false),
            GrantStep::Done
        );
    }

    #[test]
    fn full_later_page_pages_on() {
        let t = page(LIMIT, 0, 900_000);
        assert_eq!(
            grant_page_step(1, Some(900_000), t, None, false),
            next(900_000 - (LIMIT as u64 - 1))
        );
    }

    #[test]
    fn short_later_page_with_older_rows_takes_one_more_page() {
        assert_eq!(
            grant_page_step(1, Some(900_000), page(12, 1, 900_000), None, false),
            next(899_989)
        );
    }

    #[test]
    fn page_with_nothing_older_than_until_is_done() {
        // Only the inclusive boundary row came back.
        assert_eq!(
            grant_page_step(2, Some(800), page(1, 1, 800), None, false),
            GrantStep::Done
        );
    }

    /// The boundary wrap was deleted meanwhile (the sweep, another device):
    /// ask once more without it rather than give up for good.
    #[test]
    fn empty_later_page_re_asks_past_the_boundary_once() {
        assert_eq!(
            grant_page_step(2, Some(800), PageTally::default(), None, false),
            GrantStep::Next {
                until: 799,
                boundary_retry: true
            }
        );
        assert_eq!(
            grant_page_step(3, Some(799), PageTally::default(), None, true),
            GrantStep::Done,
            "empty again: nothing older"
        );
        // The re-ask found older wraps: page on as usual.
        assert_eq!(
            grant_page_step(3, Some(799), page(5, 0, 790), None, true),
            next(786)
        );
    }

    #[test]
    fn full_page_of_one_timestamp_gives_up() {
        let mut t = PageTally::default();
        for _ in 0..LIMIT {
            t.observe(800, false);
        }
        assert_eq!(
            grant_page_step(2, Some(800), t, None, false),
            GrantStep::GiveUp
        );
    }

    #[test]
    fn page_bound_gives_up() {
        let t = page(LIMIT, 0, 500_000);
        assert_eq!(
            grant_page_step(deletion_sync::MAX_PAGES, Some(500_000), t, None, false),
            GrantStep::GiveUp
        );
    }

    /// Marker written well after this page's wraps.
    const DONE_AT: u64 = 1_000_000 + 3 * WARM_STOP_MARGIN_SECS;

    #[test]
    fn warm_device_stops_at_a_fully_processed_old_full_page() {
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert_eq!(
            grant_page_step(0, None, t, Some(DONE_AT), false),
            GrantStep::Done
        );
    }

    /// The NIP-59 hole plus clock skew: a grant received while offline can
    /// be backdated up to two days below a page of processed wraps, and the
    /// device's clock may be a day out. A page that recent must not stop.
    #[test]
    fn warm_device_pages_on_within_the_backdating_and_skew_margin() {
        assert_eq!(WARM_STOP_MARGIN_SECS, 3 * 24 * 60 * 60);
        let recent = DONE_AT - WARM_STOP_MARGIN_SECS + 10;
        let t = page(LIMIT, LIMIT, recent);
        assert!(matches!(
            grant_page_step(0, None, t, Some(DONE_AT), false),
            GrantStep::Next { .. }
        ));
    }

    #[test]
    fn without_the_marker_a_processed_page_still_pages_on() {
        // An interrupted or failed backfill wrote no marker: processed wraps
        // are skipped (not unwrapped) but paging continues to the end.
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, None, false),
            GrantStep::Next { .. }
        ));
    }

    #[test]
    fn warm_device_pages_on_while_a_page_has_new_wraps() {
        let t = page(LIMIT, LIMIT - 1, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, Some(DONE_AT), false),
            GrantStep::Next { .. }
        ));
    }

    /// With the grant sweep on there is no warm stop: the sweep revisits
    /// processed wraps and its verdict must not cover unexamined ones.
    #[test]
    fn grant_sweep_disables_the_warm_stop() {
        assert_eq!(warm_marker(Some(DONE_AT), true), None);
        assert_eq!(warm_marker(Some(DONE_AT), false), Some(DONE_AT));
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, warm_marker(Some(DONE_AT), true), false),
            GrantStep::Next { .. }
        ));
    }

    #[test]
    fn markers_parse_as_completion_times() {
        assert_eq!(parse_marker(Some("1800000000")), Some(1_800_000_000));
        assert_eq!(parse_marker(Some("0")), None);
        assert_eq!(parse_marker(Some("yes")), None);
        assert_eq!(parse_marker(None), None);
    }

    #[test]
    fn markers_are_per_identity_and_scope() {
        let a = GrantScope::Identity.marker_id("aa");
        assert_ne!(a, GrantScope::Inbox.marker_id("aa"));
        assert_ne!(a, GrantScope::Identity.marker_id("bb"));
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
}
