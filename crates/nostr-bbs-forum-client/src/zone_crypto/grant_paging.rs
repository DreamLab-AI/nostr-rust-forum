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
//! the long-lived subscription asks for [`RELAY_FILTER_LIMIT`] rows; if that
//! page came back full, a page subscription asks again with an inclusive
//! `until` at the oldest `created_at` seen, and so on, one page subscription
//! at a time per scope (each closed at its EOSE, so the relay's subscription
//! cap is never approached). The stepping rule after the first page is the
//! deletion sync's ([`deletion_sync::next_page`]): it is the same relay, the
//! same `ORDER BY created_at DESC LIMIT`, and the same failure modes.
//!
//! NIP-59 randomises a wrap's `created_at` up to two days into the past. That
//! is fine for paging (`until` steps through the wraps' own timestamps, which
//! is what the relay orders by), but "oldest seen" is the wrap's timestamp,
//! never the rumour's.
//!
//! A warm device must not re-page its whole history every session. Once a
//! scope has completed a backfill on this device (persisted per identity and
//! scope), a full page whose wraps were all already processed proves the
//! sync has reached history it has handled before: wraps arrive newest
//! first, so everything below that page was seen by the completed backfill.
//! Paging stops there. Without the marker (a first backfill, or one that was
//! interrupted) paging continues to the end, so an interrupted backfill
//! resumes from the top next session, skipping the unwrap of every wrap it
//! already processed.
//!
//! Pure, so it unit-tests natively.

use crate::stores::channels::RELAY_FILTER_LIMIT;
use crate::stores::deletion_sync::{self as deletion_sync, PageStep};

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
    /// Rows whose wrap was not yet in the processed set.
    pub unprocessed: usize,
}

impl PageTally {
    /// Count one delivered wrap.
    pub fn observe(&mut self, created_at: u64, already_processed: bool) {
        self.rows += 1;
        self.oldest = Some(self.oldest.map_or(created_at, |o| o.min(created_at)));
        if !already_processed {
            self.unprocessed += 1;
        }
    }

    fn full(&self) -> bool {
        self.rows >= RELAY_FILTER_LIMIT as usize
    }
}

/// What to do after a scope's page reaches EOSE.
///
/// `page` is 0 for the long-lived subscription's stored events (fetched with
/// no `until`) and `n` for the `n`-th page subscription, fetched with `until`
/// inclusive. `backfill_done_before` is the persisted marker for this
/// identity and scope.
///
/// - **Warm stop:** with the marker, a full page with nothing unprocessed is
///   history a completed backfill already handled: [`PageStep::Done`].
/// - **First page:** full → page on from its oldest row; short → done.
/// - **Later pages:** the deletion sync's rule ([`deletion_sync::next_page`]):
///   no rows → give up (the boundary row should have come back); nothing
///   older than `until` → done, unless that page is full of one timestamp →
///   give up; otherwise page on, up to [`deletion_sync::MAX_PAGES`], then
///   give up.
///
/// [`PageStep::GiveUp`] leaves the backlog unsettled, so a page waiting on a
/// key reports the keys-timed-out copy, never "not found".
pub fn grant_page_step(
    page: u32,
    until: Option<u64>,
    tally: PageTally,
    backfill_done_before: bool,
) -> PageStep {
    if backfill_done_before && tally.full() && tally.unprocessed == 0 {
        return PageStep::Done;
    }
    match until {
        None => match tally.oldest {
            Some(oldest) if tally.full() => PageStep::Next { until: oldest },
            _ => PageStep::Done,
        },
        Some(until) => deletion_sync::next_page(tally.rows, tally.oldest, until, page),
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

    #[test]
    fn full_first_page_pages_on_from_its_oldest_row() {
        let t = page(LIMIT, 0, 1_000_000);
        assert_eq!(
            grant_page_step(0, None, t, false),
            PageStep::Next {
                until: 1_000_000 - (LIMIT as u64 - 1)
            }
        );
    }

    #[test]
    fn short_first_page_is_done() {
        assert_eq!(
            grant_page_step(0, None, page(37, 0, 500), false),
            PageStep::Done
        );
        assert_eq!(
            grant_page_step(0, None, page(0, 0, 500), false),
            PageStep::Done
        );
    }

    #[test]
    fn full_later_page_pages_on() {
        let t = page(LIMIT, 0, 900_000);
        assert_eq!(
            grant_page_step(1, Some(900_000), t, false),
            PageStep::Next {
                until: 900_000 - (LIMIT as u64 - 1)
            }
        );
    }

    /// The deletion sync's rule, reused: the relay drops NIP-40-expired rows
    /// after its SQL `LIMIT`, so a short page with rows older than `until`
    /// does not prove the end. One more page settles it.
    #[test]
    fn short_later_page_with_older_rows_takes_one_more_page() {
        assert_eq!(
            grant_page_step(1, Some(900_000), page(12, 1, 900_000), false),
            PageStep::Next { until: 899_989 }
        );
    }

    #[test]
    fn page_with_nothing_older_than_until_is_done() {
        // Only the inclusive boundary row came back.
        assert_eq!(
            grant_page_step(2, Some(800), page(1, 1, 800), false),
            PageStep::Done
        );
    }

    #[test]
    fn page_that_made_no_progress_gives_up() {
        // Not even the boundary row: the query failed or the row vanished.
        assert_eq!(
            grant_page_step(2, Some(800), PageTally::default(), false),
            PageStep::GiveUp
        );
        // A full page all at the boundary timestamp: stepping past it would
        // skip rows that share it.
        let mut t = PageTally::default();
        for _ in 0..LIMIT {
            t.observe(800, false);
        }
        assert_eq!(grant_page_step(2, Some(800), t, false), PageStep::GiveUp);
    }

    #[test]
    fn page_bound_gives_up() {
        let t = page(LIMIT, 0, 500_000);
        assert_eq!(
            grant_page_step(deletion_sync::MAX_PAGES, Some(500_000), t, false),
            PageStep::GiveUp
        );
    }

    #[test]
    fn warm_device_stops_at_a_fully_processed_full_page() {
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert_eq!(grant_page_step(0, None, t, true), PageStep::Done);
    }

    #[test]
    fn without_the_marker_a_processed_page_still_pages_on() {
        // An interrupted first backfill resumes: processed wraps are skipped
        // (not unwrapped) but paging continues to the end.
        let t = page(LIMIT, LIMIT, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, false),
            PageStep::Next { .. }
        ));
    }

    #[test]
    fn warm_device_pages_on_while_a_page_has_new_wraps() {
        let t = page(LIMIT, LIMIT - 1, 1_000_000);
        assert!(matches!(
            grant_page_step(0, None, t, true),
            PageStep::Next { .. }
        ));
    }

    #[test]
    fn markers_are_per_identity_and_scope() {
        let a = GrantScope::Identity.marker_id("aa");
        assert_ne!(a, GrantScope::Inbox.marker_id("aa"));
        assert_ne!(a, GrantScope::Identity.marker_id("bb"));
    }

    #[test]
    fn tally_tracks_the_oldest_wrap_timestamp() {
        let mut t = PageTally::default();
        t.observe(50, true);
        t.observe(10, false);
        t.observe(30, false);
        assert_eq!(t.oldest, Some(10));
        assert_eq!(t.rows, 3);
        assert_eq!(t.unprocessed, 2);
    }
}
