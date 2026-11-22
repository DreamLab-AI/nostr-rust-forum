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
//! [`super::grant_paging`]) and every wrap received so far has finished
//! processing. Once through, it stays through for the sign-in (it is
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
/// started. The live cold load on an admin account took 28.6 s to the first
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
    /// persisted, ticket bindings not loaded). Left unmarked to be retried,
    /// and the backfill must not be recorded complete over it.
    Retry,
}

/// Classify a wrap that could not be opened. An invalid wrap is final for
/// anyone. A signer-level decrypt failure is final with a local key (the
/// wrap was not encrypted to it), but with a signer that can refuse (a
/// NIP-07 extension: a denied prompt, a locked or erroring extension) it is
/// worth a retry, and must hold the backfill marker: classing it as
/// unreadable would let the next session's warm stop skip an old grant
/// whose decrypt was merely refused. The NIP-07 error type does not tell a
/// refusal from a genuine decrypt failure, so it errs towards retrying.
pub fn unwrap_failure_outcome(signer_failed: bool, signer_can_refuse: bool) -> WrapOutcome {
    if signer_failed && signer_can_refuse {
        WrapOutcome::Retry
    } else {
        WrapOutcome::Unreadable
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
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GrantBacklog {
    identity_eose: bool,
    inbox: InboxSub,
    in_flight: usize,
    /// When the grant sync started (epoch ms).
    started_at: f64,
    /// When the backlog last advanced (epoch ms).
    last_progress_at: f64,
    /// A scope's paging hit its bound or made no progress: some stored
    /// wraps were never delivered, so the backlog can never honestly settle.
    gave_up: bool,
    /// Reached settled once this sign-in; stays settled.
    latched: bool,
    /// A wrap this sign-in ended in [`WrapOutcome::Retry`].
    retry_failed: bool,
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
            gave_up: false,
            latched: false,
            retry_failed: false,
        }
    }

    /// A wrap began processing. Not progress by itself: a wrap that starts
    /// and never finishes must not keep the page waiting.
    pub fn wrap_started(&mut self) {
        self.in_flight += 1;
    }

    /// A wrap finished processing at `now`, with `outcome` (a grant's key is
    /// stored before this).
    pub fn wrap_done(&mut self, now: f64, outcome: WrapOutcome) {
        self.in_flight = self.in_flight.saturating_sub(1);
        if outcome == WrapOutcome::Retry {
            self.retry_failed = true;
        }
        self.advance(now);
    }

    /// Whether a scope that has paged to the end may record its backfill as
    /// complete now: every wrap delivered this sign-in (queued ones
    /// included) has finished, and none ended in a failure worth retrying.
    /// Recording it earlier would let the next session's warm stop skip the
    /// very wraps still processing or waiting for a retry, typically the
    /// oldest, where grants live. An unreadable wrap does not hold it.
    pub fn marker_writable(&self) -> bool {
        self.in_flight == 0 && !self.retry_failed
    }

    /// The identity scope's last page reached EOSE at `now`: every stored
    /// wrap addressed to the identity has been delivered.
    pub fn identity_eose(&mut self, now: f64) {
        self.identity_eose = true;
        self.advance(now);
    }

    /// The inbox-key subscription was opened at `now`.
    pub fn inbox_opened(&mut self, now: f64) {
        self.inbox = InboxSub::Open { eose: false };
        self.advance(now);
    }

    /// The inbox scope's last page reached EOSE at `now`.
    pub fn inbox_eose(&mut self, now: f64) {
        self.inbox = InboxSub::Open { eose: true };
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
        !self.gave_up && self.identity_eose && inbox_done && self.in_flight == 0
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
        let cap_at = self.started_at + KEYS_CAP_MS;
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
        b.identity_eose(1.0);
        assert!(b.settled(), "a member with no grants must not wait forever");
    }

    #[test]
    fn wraps_still_opening_hold_it_open() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_started();
        b.identity_eose(1.0);
        assert!(!b.settled());
        b.wrap_done(1.0, WrapOutcome::Settled);
        assert!(!b.settled());
        b.wrap_done(1.0, WrapOutcome::Settled);
        assert!(b.settled());
    }

    #[test]
    fn inbox_subscription_is_waited_for_when_used() {
        let mut b = GrantBacklog::new(true, 0.0);
        b.identity_eose(1.0);
        assert!(!b.settled(), "inbox key still being set up");
        b.inbox_opened(1.0);
        assert!(!b.settled(), "inbox stored events not through");
        b.inbox_eose(1.0);
        assert!(b.settled());
    }

    #[test]
    fn failed_inbox_setup_does_not_hold_it_open() {
        let mut b = GrantBacklog::new(true, 0.0);
        b.identity_eose(1.0);
        b.inbox_failed(1.0);
        assert!(b.settled());
    }

    #[test]
    fn spurious_done_does_not_underflow() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_done(1.0, WrapOutcome::Settled);
        b.identity_eose(1.0);
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
        b.wrap_done(15_000.0, WrapOutcome::Settled);
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
        b.identity_eose(1_000.0);
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
            b.wrap_done(t, WrapOutcome::Settled);
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
        b.identity_eose(2_000.0);
        let mut t = 2_000.0;
        for i in 0..wraps {
            // One every ~3 s, the last at 75.9 s.
            t = 2_000.0 + f64::from(i + 1) * (73_900.0 / f64::from(wraps));
            assert!(matches!(b.phase(t), KeyPhase::Progressing { .. }), "{t}");
            b.wrap_done(t, WrapOutcome::Settled);
        }
        assert!((t - 75_900.0).abs() < 1e-6);
        assert_eq!(b.phase(t), KeyPhase::Settled);
    }

    #[test]
    fn settled_wins_over_the_clock() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.identity_eose(1.0);
        assert_eq!(b.phase(10.0 * KEYS_CAP_MS), KeyPhase::Settled);
    }

    /// A live DM wrap (or a reconnect retry) after the backlog settled must
    /// not flip a settled page to the keys-timeout copy.
    #[test]
    fn settled_is_latched_against_later_wraps() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.identity_eose(1_000.0);
        assert!(b.settled());
        b.wrap_started();
        assert!(b.settled(), "a live wrap does not reopen it");
        assert_eq!(b.phase(10.0 * KEYS_CAP_MS), KeyPhase::Settled);
        b.wrap_done(2_000.0, WrapOutcome::Settled);
        assert!(b.settled());
    }

    #[test]
    fn paging_that_gave_up_never_settles() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.paging_gave_up(1_000.0);
        assert!(!b.settled());
        assert_eq!(b.phase(1_001.0), KeyPhase::Stalled);
        // Even if the other conditions are later met.
        b.identity_eose(2_000.0);
        assert!(!b.settled());
        assert_eq!(b.phase(2_001.0), KeyPhase::Stalled);
    }

    #[test]
    fn marker_waits_for_every_wrap_to_finish() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_started();
        b.identity_eose(1_000.0);
        assert!(
            !b.marker_writable(),
            "the last page's wraps are still opening"
        );
        b.wrap_done(2_000.0, WrapOutcome::Settled);
        assert!(!b.marker_writable());
        b.wrap_done(3_000.0, WrapOutcome::Settled);
        assert!(b.marker_writable());
    }

    /// A transient failure (admin check unanswered, key not persisted) leaves
    /// no marker, so the next session pages fully and retries the wrap.
    #[test]
    fn a_transient_failure_withholds_the_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_done(1_000.0, WrapOutcome::Retry);
        b.identity_eose(2_000.0);
        assert!(!b.marker_writable());
    }

    #[test]
    fn an_unreadable_wrap_does_not_withhold_the_marker() {
        let mut b = GrantBacklog::new(false, 0.0);
        b.wrap_started();
        b.wrap_done(1_000.0, WrapOutcome::Unreadable);
        b.identity_eose(2_000.0);
        assert!(b.marker_writable());
    }

    #[test]
    fn invalid_wraps_are_unreadable_for_any_signer() {
        assert_eq!(
            unwrap_failure_outcome(false, false),
            WrapOutcome::Unreadable
        );
        assert_eq!(unwrap_failure_outcome(false, true), WrapOutcome::Unreadable);
    }

    #[test]
    fn a_local_key_decrypt_failure_is_unreadable() {
        assert_eq!(unwrap_failure_outcome(true, false), WrapOutcome::Unreadable);
    }

    /// A refused or failed NIP-07 decrypt (indistinguishable by error type)
    /// is retried and holds the marker, so an old grant is not skipped.
    #[test]
    fn a_nip07_decrypt_failure_is_retried() {
        assert_eq!(unwrap_failure_outcome(true, true), WrapOutcome::Retry);
    }
}
