//! When has the signed-in identity's zone-key grant backlog been worked
//! through?
//!
//! On a cold device the member's zone keys are not in IndexedDB; they arrive
//! as gift-wrapped grants through the grant sync, and each wrap is opened and
//! checked asynchronously. Until that backlog is through, an encrypted zone's
//! posts that need a key (a sealed original under its envelope id, a `zk`
//! post under a placeholder) are still waiting to be decrypted, so a page
//! must not yet conclude that a topic is absent.
//!
//! The backlog is through when every grant subscription has delivered all
//! its stored events (its last page reached EOSE, see
//! [`super::grant_paging`]), every wrap received so far has finished
//! processing, and none is waiting for a retry ([`WrapOutcome::Retry`] or
//! [`WrapOutcome::Refused`]): a wrap that could not be read for a reason
//! that may pass (an unanswered admin check, a refused NIP-07 prompt) may be
//! the very grant a page is waiting for, so the page must not conclude
//! "not found" over it. Once through, it stays through for the sign-in (it is
//! latched): a live DM or a reconnect retry arriving later is processed as
//! usual, and a key it carries still re-decrypts the screen, but it does not
//! reopen the verdict. That mirrors the old-grant sweep's own verdict
//! (`public_inbox::SweepTracker`), but also covers the inbox-key
//! subscription, which grants may arrive on with `RECIPIENT_KEYS_ENABLED`.
//!
//! While it is not through, [`GrantBacklog::phase`] tells a backlog that is
//! still moving (keep waiting, and say the keys are on their way) from one
//! that has stopped (give up and say so), by when it last advanced.
//!
//! Pure, so it unit-tests natively.

/// How long the backlog may go without advancing (a wrap processed, a
/// subscription reaching EOSE) before it counts as stalled. One wrap's
/// longest step is the sealer's admin check, a network fetch that is cached
/// per sealer after the first, followed by an IndexedDB write; NIP-44
/// unwrapping with a local key takes milliseconds. Twenty seconds is twice
/// the relay AUTH answer bound (`relay::receipt::AUTH_ANSWER_TIMEOUT_MS`)
/// and long enough for one slow admin check, while a backlog that is
/// genuinely stuck (a NIP-07 prompt nobody answers, a fetch that hangs) is
/// reported well before the overall cap.
pub const KEYS_STALL_MS: f64 = 20_000.0;

/// The most a page waits for a moving backlog, from when the grant sync
/// started or, if later, from when the last grant scope finished paging (a
/// paged backlog of thousands of wraps legitimately takes longer than one
/// page of them). The live cold load on an admin account took 28.6 s to the first
/// usable key and 75.9 s to the last; two minutes covers that whole backlog
/// with about 1.5x headroom, and bounds the wait for a backlog that keeps
/// trickling (many DMs, each one a wrap) without ever finishing.
pub const KEYS_CAP_MS: f64 = 120_000.0;

/// Where an unsettled backlog stands at a given moment.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyPhase {
    /// Through: every key this member will get has arrived.
    Settled,
    /// Still advancing. `until` (epoch ms) is when it next needs looking at:
    /// the end of the stall window or the cap, whichever comes first.
    Progressing {
        /// When to re-evaluate.
        until: f64,
    },
    /// Not through, and it has stopped advancing or hit the cap.
    Stalled,
}

use std::collections::HashSet;

use super::grant_paging::GrantScope;
use super::UnwrapError;

/// How processing one wrap ended, as far as retrying it matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapOutcome {
    /// Final: marked processed (a key stored, a refusal, not a grant).
    Settled,
    /// Cannot be read by this member (not addressed to a key held here, or
    /// the signer cannot decrypt it). Left unmarked so a later session with
    /// a capable signer may try, but it is not a failure worth holding the
    /// backfill marker for: it would hold it forever.
    Unreadable,
    /// A transient failure (the sealer's admin check unanswered, the key not
    /// persisted, ticket bindings not loaded, processing timed out). Left
    /// unmarked to be retried; the backlog does not settle and the backfill
    /// is not recorded complete over it.
    Retry,
    /// A signer that can refuse (NIP-07) failed to decrypt before it had
    /// decrypted any other wrap since this one was queued: a denied prompt
    /// or a locked extension looks the same as a wrap it cannot read. Held
    /// like [`WrapOutcome::Retry`], and queued again once the signer has
    /// decrypted another wrap (see `WrapQueue::park`). Failing again then,
    /// it is [`WrapOutcome::UnreadableBySigner`].
    Refused,
    /// The refusable signer failed on it again after it had decrypted
    /// another wrap. Settles like [`WrapOutcome::Unreadable`] (a junk wrap
    /// must not hold every session open), but the failure may still have
    /// been a lock or a refusal, so the wrap's `created_at` becomes the
    /// marker's floor: the next session's warm stop must lie below it, and
    /// that session tries the wrap again.
    UnreadableBySigner,
}

impl WrapOutcome {
    /// The wrap may succeed later this session or the next: it holds the
    /// backlog open and withholds the backfill marker.
    pub fn retryable(self) -> bool {
        matches!(self, WrapOutcome::Retry | WrapOutcome::Refused)
    }
}

/// Whether the grant sync's signer can refuse a decrypt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerKind {
    /// A key held in the page (or the local inbox key): a decrypt failure
    /// means the wrap was not encrypted to it.
    Local,
    /// A NIP-07 extension: a decrypt can fail because a prompt was denied,
    /// the extension is locked, or it errored.
    CanRefuse,
}

/// Which attempt at a wrap this was, for [`unwrap_failure_outcome`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// Queued from a subscription.
    First,
    /// Queued again because the signer decrypted another wrap after this
    /// one was refused.
    AfterSignerSuccess,
}

/// Classify a wrap that could not be opened.
///
/// An invalid wrap is final for anyone. A signer-level decrypt failure is
/// final with a local key (the wrap was not encrypted to it). With a signer
/// that can refuse it is [`WrapOutcome::Refused`] on the first attempt: the
/// NIP-07 error type does not tell a denied prompt or a locked extension
/// from a wrap the key cannot read, and classing a refusal as unreadable
/// would let the backlog settle (and a later warm stop skip) over a grant
/// that was merely refused. Once the same signer has decrypted another wrap
/// and this one still fails, it no longer holds this session open (a single
/// junk wrap addressed to a NIP-07 user would otherwise hold every session's
/// backlog open for good), but it is [`WrapOutcome::UnreadableBySigner`],
/// not unreadable: it lowers the marker's floor, so it is not skipped later.
pub fn unwrap_failure_outcome(
    error: &UnwrapError,
    signer: SignerKind,
    attempt: Attempt,
) -> WrapOutcome {
    match (error, signer, attempt) {
        (UnwrapError::Signer(_), SignerKind::CanRefuse, Attempt::First) => WrapOutcome::Refused,
        (UnwrapError::Signer(_), SignerKind::CanRefuse, Attempt::AfterSignerSuccess) => {
            WrapOutcome::UnreadableBySigner
        }
        _ => WrapOutcome::Unreadable,
    }
}

/// The inbox-key grant subscription's part in the backlog.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InboxSub {
    /// Recipient keys are off: there is no inbox subscription to wait for.
    #[default]
    NotUsed,
    /// The inbox key is still being created, restored or confirmed.
    Pending,
    /// Subscribed; `eose` once its stored events are through.
    Open {
        /// The subscription reached EOSE.
        eose: bool,
    },
    /// The inbox key could not be set up; grants can only come on the
    /// identity subscription, so there is nothing more to wait for here.
    Failed,
}

/// Progress of one sign-in's grant backlog.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GrantBacklog {
    identity_eose: bool,
    inbox: InboxSub,
    in_flight: usize,
    /// When the grant sync started (epoch ms).
    started_at: f64,
    /// When the backlog last advanced (epoch ms).
    last_progress_at: f64,
    /// When a grant scope last finished paging (epoch ms); the cap runs
    /// from here when it is later than `started_at`.
    delivered_at: f64,
    /// A scope's paging hit its bound or made no progress: some stored
    /// wraps were never delivered, so the backlog can never honestly settle.
    gave_up: bool,
    /// Reached settled once this sign-in; stays settled.
    latched: bool,
    /// Wraps whose latest attempt this sign-in was retryable
    /// ([`WrapOutcome::retryable`]). A later attempt that settles removes it.
    retrying: HashSet<String>,
    /// Scopes that finished a verified walk and await their backfill marker.
    markers_due: HashSet<GrantScope>,
    /// The oldest `created_at` of a wrap that ended
    /// [`WrapOutcome::UnreadableBySigner`] this sign-in.
    floor: Option<u64>,
}

impl GrantBacklog {
    /// A fresh backlog started at `now` (epoch ms); `inbox_used` is whether
    /// an inbox-key subscription will be opened (recipient keys on).
    pub fn new(inbox_used: bool, now: f64) -> Self {
        Self {
            identity_eose: false,
            inbox: if inbox_used {
                InboxSub::Pending
            } else {
                InboxSub::NotUsed
            },
            in_flight: 0,
            started_at: now,
            last_progress_at: now,
            delivered_at: now,
            gave_up: false,
            latched: false,
            retrying: HashSet::new(),
            markers_due: HashSet::new(),
            floor: None,
        }
    }

    /// A wrap began processing. Not progress by itself: a wrap that starts
    /// and never finishes must not keep the page waiting.
    pub fn wrap_started(&mut self) {
        self.in_flight += 1;
    }

    /// Wrap `id` (dated `created_at`) finished processing at `now`, with
    /// `outcome` (a grant's key is stored before this).
    pub fn wrap_done(&mut self, now: f64, id: &str, created_at: u64, outcome: WrapOutcome) {
        self.in_flight = self.in_flight.saturating_sub(1);
        if outcome.retryable() {
            self.retrying.insert(id.to_string());
        } else {
            self.retrying.remove(id);
        }
        if outcome == WrapOutcome::UnreadableBySigner {
            self.floor = Some(self.floor.map_or(created_at, |f| f.min(created_at)));
        }
        self.advance(now);
    }

    /// The floor to store with this sign-in's markers (see
    /// [`WrapOutcome::UnreadableBySigner`]).
    pub fn marker_floor(&self) -> Option<u64> {
        self.floor
    }

    /// Wraps whose latest attempt was retryable.
    #[cfg(test)]
    pub fn retrying(&self) -> usize {
        self.retrying.len()
    }

    /// Whether a scope that has paged to the end may record its backfill as
    /// complete now: every wrap delivered this sign-in (queued ones
    /// included) has finished, and none is waiting for a retry. Recording it
    /// earlier would let the next session's warm stop skip the very wraps
    /// still processing or waiting for a retry, typically the oldest, where
    /// grants live. An unreadable wrap does not hold it.
    pub fn marker_writable(&self) -> bool {
        self.in_flight == 0 && self.retrying.is_empty()
    }

    /// `scope`'s last page reached EOSE at `now`: every stored wrap addressed
    /// to it has been delivered. `verified` is whether the end was seen
    /// rather than inferred (see `grant_paging::GrantStep::Done`); only a
    /// verified end makes the scope's marker due.
    pub fn scope_delivered(&mut self, scope: GrantScope, verified: bool, now: f64) {
        match scope {
            GrantScope::Identity => self.identity_eose = true,
            GrantScope::Inbox => self.inbox = InboxSub::Open { eose: true },
        }
        if verified {
            self.markers_due.insert(scope);
        }
        self.delivered_at = self.delivered_at.max(now);
        self.advance(now);
    }

    /// The scopes whose backfill marker may be written now, removed from the
    /// due set; empty until [`GrantBacklog::marker_writable`].
    pub fn take_due_markers(&mut self) -> Vec<GrantScope> {
        if !self.marker_writable() {
            return Vec::new();
        }
        let mut due: Vec<GrantScope> = self.markers_due.drain().collect();
        due.sort_by_key(|s| matches!(s, GrantScope::Inbox));
        due
    }

    /// The inbox-key subscription was opened at `now`.
    pub fn inbox_opened(&mut self, now: f64) {
        self.inbox = InboxSub::Open { eose: false };
        self.advance(now);
    }

    /// The inbox key could not be set up (at `now`).
    pub fn inbox_failed(&mut self, now: f64) {
        self.inbox = InboxSub::Failed;
        self.advance(now);
    }

    /// A scope's paging gave up (bound hit, or a page made no progress) at
    /// `now`. The backlog then reads as stalled: a page waiting on a key
    /// shows the keys-timed-out copy, never "not found".
    pub fn paging_gave_up(&mut self, now: f64) {
        self.gave_up = true;
        self.advance(now);
    }

    fn advance(&mut self, now: f64) {
        self.last_progress_at = self.last_progress_at.max(now);
        if self.through() {
            self.latched = true;
        }
    }

    fn through(&self) -> bool {
        let inbox_done = matches!(
            self.inbox,
            InboxSub::NotUsed | InboxSub::Failed | InboxSub::Open { eose: true }
        );
        !self.gave_up
            && self.identity_eose
            && inbox_done
            && self.in_flight == 0
            && self.retrying.is_empty()
    }

    /// Where the backlog stands at `now`: settled, still advancing (within
    /// [`KEYS_STALL_MS`] of its last step and [`KEYS_CAP_MS`] of its start),
    /// or stalled.
    pub fn phase(&self, now: f64) -> KeyPhase {
        if self.settled() {
            return KeyPhase::Settled;
        }
        if self.gave_up {
            return KeyPhase::Stalled;
        }
        let stall_at = self.last_progress_at + KEYS_STALL_MS;
        let cap_at = self.started_at.max(self.delivered_at) + KEYS_CAP_MS;
        let until = stall_at.min(cap_at);
        if now < until {
            KeyPhase::Progressing { until }
        } else {
            KeyPhase::Stalled
        }
    }

    /// Whether the backlog is through: every subscription's stored events
    /// have arrived and nothing is still being opened. Live grants arriving
    /// later still decrypt what is on screen; they do not reopen this.
    pub fn settled(&self) -> bool {
        self.latched || self.through()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_received_yet_is_not_settled() {
        assert!(!GrantBacklog::new(false, 0.0).settled());
    }

    #[test]
    fn eose_with_no_wraps_settles_a_keyless_member() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.scope_delivered(GrantScope::Identity, true, 1.0);
        assert!(b.settled(), "a member with no grants must not wait forever");
    }

    #[test]
    fn wraps_still_opening_hold_it_open() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_started();
        b.scope_delivered(GrantScope::Identity, true, 1.0);
        assert!(!b.settled());
        b.wrap_done(1.0, "w", 1, WrapOutcome::Settled);
        assert!(!b.settled());
        b.wrap_done(1.0, "w", 1, WrapOutcome::Settled);
        assert!(b.settled());
    }

    #[test]
    fn inbox_subscription_is_waited_for_when_used() {
        let mut b = GrantBacklog::new(true, 0.0);
        b.scope_delivered(GrantScope::Identity, true, 1.0);
        assert!(!b.settled(), "inbox key still being set up");
        b.inbox_opened(1.0);
        assert!(!b.settled(), "inbox stored events not through");
        b.scope_delivered(GrantScope::Inbox, true, 1.0);
        assert!(b.settled());
    }

    #[test]
    fn failed_inbox_setup_does_not_hold_it_open() {
        let mut b = GrantBacklog::new(true, 0.0);
        b.scope_delivered(GrantScope::Identity, true, 1.0);
        b.inbox_failed(1.0);
        assert!(b.settled());
    }

    #[test]
    fn spurious_done_does_not_underflow() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_done(1.0, "w", 1, WrapOutcome::Settled);
        b.scope_delivered(GrantScope::Identity, true, 1.0);
        assert!(b.settled());
    }

    #[test]
    fn a_moving_backlog_is_progressing_until_the_stall_window() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        assert_eq!(
            b.phase(1_000.0),
            KeyPhase::Progressing {
                until: KEYS_STALL_MS
            }
        );
        // A wrap finishes at 15 s: the window restarts from there.
        b.wrap_started();
        b.wrap_done(15_000.0, "w", 1, WrapOutcome::Settled);
        assert_eq!(
            b.phase(30_000.0),
            KeyPhase::Progressing {
                until: 15_000.0 + KEYS_STALL_MS
            }
        );
    }

    #[test]
    fn no_progress_for_the_stall_window_is_stalled() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        assert_eq!(b.phase(KEYS_STALL_MS), KeyPhase::Stalled);
    }

    #[test]
    fn a_wrap_that_starts_but_never_finishes_is_not_progress() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.scope_delivered(GrantScope::Identity, true, 1_000.0);
        assert_eq!(b.phase(1_000.0 + KEYS_STALL_MS), KeyPhase::Stalled);
    }

    #[test]
    fn a_backlog_that_keeps_trickling_hits_the_cap() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        let mut t = 0.0;
        while t < KEYS_CAP_MS {
            t += 5_000.0;
            b.wrap_started();
            b.wrap_done(t, "w", 1, WrapOutcome::Settled);
        }
        assert_eq!(b.phase(KEYS_CAP_MS), KeyPhase::Stalled);
        assert!(matches!(
            b.phase(KEYS_CAP_MS - 1.0),
            KeyPhase::Progressing { until } if until <= KEYS_CAP_MS
        ));
    }

    /// The live cold run: first usable key at 28.6 s, last at 75.9 s, with
    /// wraps (grants and DMs) finishing throughout. It must read as
    /// progressing the whole way, never stalled.
    #[test]
    fn the_observed_cold_admin_backlog_never_reads_as_stalled() {
        let mut b = GrantBacklog::new(false, 0.0);
        // The relay delivers the stored wraps before EOSE; each is opened
        // asynchronously, so most are still in flight when EOSE lands.
        let wraps = 25;
        for _ in 0..wraps {
            b.wrap_started();
        }
        b.scope_delivered(GrantScope::Identity, true, 2_000.0);
        let mut t = 2_000.0;
        for i in 0..wraps {
            // One every ~3 s, the last at 75.9 s.
            t = 2_000.0 + f64::from(i + 1) * (73_900.0 / f64::from(wraps));
            assert!(matches!(b.phase(t), KeyPhase::Progressing { .. }), "{t}");
            b.wrap_done(t, "w", 1, WrapOutcome::Settled);
        }
        assert!((t - 75_900.0).abs() < 1e-6);
        assert_eq!(b.phase(t), KeyPhase::Settled);
    }

    #[test]
    fn settled_wins_over_the_clock() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.scope_delivered(GrantScope::Identity, true, 1.0);
        assert_eq!(b.phase(10.0 * KEYS_CAP_MS), KeyPhase::Settled);
    }

    /// A live DM wrap (or a reconnect retry) after the backlog settled must
    /// not flip a settled page to the keys-timeout copy.
    #[test]
    fn settled_is_latched_against_later_wraps() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.scope_delivered(GrantScope::Identity, true, 1_000.0);
        assert!(b.settled());
        b.wrap_started();
        assert!(b.settled(), "a live wrap does not reopen it");
        assert_eq!(b.phase(10.0 * KEYS_CAP_MS), KeyPhase::Settled);
        b.wrap_done(2_000.0, "w", 1, WrapOutcome::Settled);
        assert!(b.settled());
    }

    #[test]
    fn paging_that_gave_up_never_settles() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.paging_gave_up(1_000.0);
        assert!(!b.settled());
        assert_eq!(b.phase(1_001.0), KeyPhase::Stalled);
        // Even if the other conditions are later met.
        b.scope_delivered(GrantScope::Identity, true, 2_000.0);
        assert!(!b.settled());
        assert_eq!(b.phase(2_001.0), KeyPhase::Stalled);
    }

    #[test]
    fn marker_waits_for_every_wrap_to_finish() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_started();
        b.scope_delivered(GrantScope::Identity, true, 1_000.0);
        assert!(
            !b.marker_writable(),
            "the last page's wraps are still opening"
        );
        b.wrap_done(2_000.0, "w", 1, WrapOutcome::Settled);
        assert!(!b.marker_writable());
        b.wrap_done(3_000.0, "w", 1, WrapOutcome::Settled);
        assert!(b.marker_writable());
    }

    /// A transient failure (admin check unanswered, key not persisted) leaves
    /// no marker, so the next session pages fully and retries the wrap.
    #[test]
    fn a_transient_failure_withholds_the_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_done(1_000.0, "w", 1, WrapOutcome::Retry);
        b.scope_delivered(GrantScope::Identity, true, 2_000.0);
        assert!(!b.marker_writable());
        assert!(b.take_due_markers().is_empty());
    }

    /// The finding PR A's fix depends on: a wrap that may be the grant a
    /// page waits for, left to retry, must not let the page conclude
    /// "not found". The backlog stays open and stalls into the
    /// keys-timed-out copy instead.
    #[test]
    fn a_retryable_wrap_holds_the_backlog_open() {
        for outcome in [WrapOutcome::Retry, WrapOutcome::Refused] {
            let mut b = GrantBacklog::new(false, 0.0);
            b.wrap_started();
            b.scope_delivered(GrantScope::Identity, true, 1_000.0);
            b.wrap_done(2_000.0, "g", 1, outcome);
            assert!(!b.settled(), "{outcome:?}");
            assert_eq!(b.phase(2_000.0 + KEYS_STALL_MS), KeyPhase::Stalled);
        }
    }

    /// A refused wrap queued again and settled clears its hold (finding 3:
    /// the old `retry_failed` flag never cleared).
    #[test]
    fn a_retry_that_later_settles_releases_the_backlog_and_the_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_started();
        b.scope_delivered(GrantScope::Identity, true, 1_000.0);
        b.wrap_done(1_500.0, "g", 1, WrapOutcome::Refused);
        b.wrap_done(1_600.0, "dm", 1, WrapOutcome::Settled);
        assert_eq!(b.retrying(), 1);
        assert!(!b.settled() && !b.marker_writable());
        // Queued again after the signer decrypted "dm", and it opens.
        b.wrap_started();
        b.wrap_done(2_000.0, "g", 1, WrapOutcome::Settled);
        assert!(b.settled());
        assert_eq!(b.take_due_markers(), vec![GrantScope::Identity]);
        assert!(b.take_due_markers().is_empty(), "taken once");
    }

    #[test]
    fn an_unreadable_wrap_does_not_withhold_the_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_done(1_000.0, "w", 1, WrapOutcome::Unreadable);
        b.scope_delivered(GrantScope::Identity, true, 2_000.0);
        assert!(b.marker_writable());
        assert!(b.settled());
    }

    /// A walk that ended on two empty answers settles but writes no marker.
    #[test]
    fn an_unverified_end_settles_without_a_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.scope_delivered(GrantScope::Identity, false, 1_000.0);
        assert!(b.settled());
        assert!(b.take_due_markers().is_empty());
    }

    #[test]
    fn markers_come_due_per_scope() {
        let mut b = GrantBacklog::new(true, 0.0);
        b.inbox_opened(10.0);
        b.wrap_started();
        b.scope_delivered(GrantScope::Identity, true, 1_000.0);
        assert!(b.take_due_markers().is_empty(), "a wrap is still opening");
        b.wrap_done(1_100.0, "w", 1, WrapOutcome::Settled);
        assert_eq!(b.take_due_markers(), vec![GrantScope::Identity]);
        b.scope_delivered(GrantScope::Inbox, true, 1_200.0);
        assert_eq!(b.take_due_markers(), vec![GrantScope::Inbox]);
    }

    /// Finding 2: a paged backlog that finishes delivering late and keeps
    /// advancing is not cut off at two minutes from the start.
    #[test]
    fn the_cap_runs_from_the_last_delivered_scope() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.scope_delivered(GrantScope::Identity, true, 100_000.0);
        let mut t = 100_000.0;
        while t < 200_000.0 {
            t += 10_000.0;
            b.wrap_started();
            b.wrap_done(t, "w", 1, WrapOutcome::Settled);
            assert!(matches!(b.phase(t), KeyPhase::Progressing { .. }), "{t}");
        }
        assert_eq!(b.phase(100_000.0 + KEYS_CAP_MS), KeyPhase::Stalled);
    }

    #[test]
    fn invalid_wraps_are_unreadable_for_any_signer() {
        let bad = UnwrapError::Invalid("seal JSON malformed".into());
        for signer in [SignerKind::Local, SignerKind::CanRefuse] {
            for attempt in [Attempt::First, Attempt::AfterSignerSuccess] {
                assert_eq!(
                    unwrap_failure_outcome(&bad, signer, attempt),
                    WrapOutcome::Unreadable
                );
            }
        }
    }

    #[test]
    fn a_local_key_decrypt_failure_is_unreadable() {
        let e = UnwrapError::Signer("gift wrap layer does not decrypt".into());
        assert_eq!(
            unwrap_failure_outcome(&e, SignerKind::Local, Attempt::First),
            WrapOutcome::Unreadable
        );
    }

    /// A refused or failed NIP-07 decrypt (indistinguishable by error type)
    /// is held and retried after the signer works; failing again then, it
    /// is unreadable (finding 1: a junk wrap must not hold every session).
    #[test]
    fn a_nip07_decrypt_failure_is_refused_then_unreadable() {
        let e = UnwrapError::Signer("gift wrap layer does not decrypt".into());
        assert_eq!(
            unwrap_failure_outcome(&e, SignerKind::CanRefuse, Attempt::First),
            WrapOutcome::Refused
        );
        assert_eq!(
            unwrap_failure_outcome(&e, SignerKind::CanRefuse, Attempt::AfterSignerSuccess),
            WrapOutcome::UnreadableBySigner
        );
    }

    /// Security review finding 2: a wrap the refusable signer failed on
    /// twice settles the backlog (a junk wrap must not hold it) but lowers
    /// the marker's floor to its timestamp, so the next session reaches it.
    #[test]
    fn a_twice_refused_wrap_settles_but_floors_the_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        for _ in 0..3 {
            b.wrap_started();
        }
        b.scope_delivered(GrantScope::Identity, true, 10.0);
        b.wrap_done(20.0, "a", 5_000, WrapOutcome::UnreadableBySigner);
        b.wrap_done(30.0, "b", 4_000, WrapOutcome::UnreadableBySigner);
        b.wrap_done(40.0, "c", 1_000, WrapOutcome::Unreadable);
        assert!(b.settled());
        assert_eq!(b.take_due_markers(), vec![GrantScope::Identity]);
        assert_eq!(b.marker_floor(), Some(4_000), "the oldest, not junk");
    }
}
