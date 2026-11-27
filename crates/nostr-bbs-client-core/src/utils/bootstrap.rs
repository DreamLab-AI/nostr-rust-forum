//! Deep-link self-bootstrap state (ADR-092).
//!
//! A page reachable by URL must boot its own data. Proving that it *did* is a
//! separate problem from starting it, and the two must not be conflated: the
//! previous implementation declared success by letting an eight-second timer
//! clear the spinner. A timer is not a receipt. It reports "loaded" for a
//! channel that does not exist, for a relay that never connected, and for a
//! subscription that was silently dropped — and it reports it in exactly the
//! same way as a genuine, fully-loaded empty channel.
//!
//! This module separates the two:
//!
//! - **Success is an observed condition.** Either the target events resolved
//!   into the store, or the channel's metadata resolved *and* its kind-42
//!   subscription reached EOSE (the relay's own "that is all the history I
//!   have" receipt). Either is proof; a clock is not.
//! - **The bounded deadline is a failure path.** When it fires with no receipt,
//!   the page reports a distinct, named failure — with a retry — rather than
//!   pretending to have succeeded.
//!
//! A receipt that arrives late still wins: [`derive_phase`] checks the observed
//! conditions before the deadline, so a slow relay that answers at nine seconds
//! transitions to [`BootstrapPhase::Ready`], not to a stuck error.
//!
//! Pure and `web_sys`-free, so it unit-tests natively.

/// Everything the page has actually observed about its own bootstrap.
///
/// Every field is a fact the page has witnessed, never a timer's opinion —
/// except `deadline_passed`, which is explicitly the failure clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootstrapSignals {
    /// The relay socket is open.
    pub connected: bool,
    /// The channel's metadata resolved — either from its kind-40 event or from
    /// the shared channel store.
    pub channel_resolved: bool,
    /// The kind-40 lookup AND the store's channel list both completed, and
    /// neither produced this channel. The channel does not exist on this relay.
    pub channel_absent: bool,
    /// A kind-42 subscription for this channel reported EOSE — the relay has
    /// delivered all the history it holds.
    pub replay_complete: bool,
    /// At least one message for this channel is in the store. The target
    /// resolved, which is a receipt in its own right.
    pub messages_present: bool,
    /// The bounded failure deadline elapsed.
    pub deadline_passed: bool,
}

/// Why a bootstrap failed. Distinct variants so the page can say something
/// true, and so a retry can be offered where a retry might help.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapFailure {
    /// The relay socket never opened.
    Disconnected,
    /// The relay answered and does not have this channel.
    ChannelNotFound,
    /// Connected, but the channel's metadata never arrived before the deadline.
    ChannelUnresolved,
    /// Metadata arrived; the message replay never reported EOSE.
    ReplayTimedOut,
}

/// Where a deep-link bootstrap has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapPhase {
    /// Waiting for the relay socket.
    Connecting,
    /// Connected; waiting for the channel's metadata.
    ResolvingChannel,
    /// Channel known; waiting for its message history.
    LoadingMessages,
    /// A real receipt arrived. The view is authoritative — including when it
    /// is authoritatively empty.
    Ready,
    /// No receipt within the bounded deadline, or a definitive negative answer.
    Failed(BootstrapFailure),
}

impl BootstrapPhase {
    /// Whether the view may be trusted as complete.
    pub fn is_ready(&self) -> bool {
        matches!(self, BootstrapPhase::Ready)
    }

    /// Whether bootstrap gave up. The view must say so rather than render an
    /// empty state that reads as "there is nothing here".
    pub fn is_failed(&self) -> bool {
        matches!(self, BootstrapPhase::Failed(_))
    }

    /// Whether a spinner is still the honest thing to show.
    pub fn is_pending(&self) -> bool {
        !self.is_ready() && !self.is_failed()
    }

    /// Whether offering a retry makes sense. A channel the relay definitively
    /// does not have will not appear by asking again.
    pub fn is_retryable(&self) -> bool {
        !matches!(
            self,
            BootstrapPhase::Failed(BootstrapFailure::ChannelNotFound)
        )
    }

    /// Short status line for the user. UK English, no jargon, and never
    /// "loaded" for something that was not.
    pub fn message(&self) -> &'static str {
        match self {
            BootstrapPhase::Connecting => "Connecting to the relay\u{2026}",
            BootstrapPhase::ResolvingChannel => "Finding this channel\u{2026}",
            BootstrapPhase::LoadingMessages => "Loading messages\u{2026}",
            BootstrapPhase::Ready => "Up to date",
            BootstrapPhase::Failed(BootstrapFailure::Disconnected) => {
                "Could not reach the relay, so this channel could not be loaded."
            }
            BootstrapPhase::Failed(BootstrapFailure::ChannelNotFound) => {
                "This channel is not on the relay. It may have been removed, or the link may be wrong."
            }
            BootstrapPhase::Failed(BootstrapFailure::ChannelUnresolved) => {
                "This channel's details did not arrive in time, so its messages could not be loaded."
            }
            BootstrapPhase::Failed(BootstrapFailure::ReplayTimedOut) => {
                "The relay did not finish sending this channel's messages, so the list below may be incomplete."
            }
        }
    }
}

/// Derive the bootstrap phase from what the page has observed.
///
/// Order matters, and it is deliberate:
///
/// 1. **Receipts first.** An observed success beats the clock, so a late but
///    genuine answer still resolves to [`BootstrapPhase::Ready`] instead of
///    being frozen into a failure by a deadline that has already gone by.
/// 2. **A definitive negative next.** "The relay does not have this channel" is
///    an answer, not a timeout, and does not need the deadline to be reported.
/// 3. **Then the deadline**, attributing the failure to the furthest stage the
///    bootstrap actually reached.
/// 4. **Otherwise the pending stage**, which is what the spinner names.
pub fn derive_phase(s: BootstrapSignals) -> BootstrapPhase {
    // 1. Receipts. Either the target events resolved, or the channel resolved
    //    and the relay signed off its history with an EOSE.
    if s.messages_present || (s.channel_resolved && s.replay_complete) {
        return BootstrapPhase::Ready;
    }

    // 2. A definitive negative answer.
    if s.channel_absent {
        return BootstrapPhase::Failed(BootstrapFailure::ChannelNotFound);
    }

    // 3. The bounded failure deadline.
    if s.deadline_passed {
        return BootstrapPhase::Failed(if !s.connected {
            BootstrapFailure::Disconnected
        } else if !s.channel_resolved {
            BootstrapFailure::ChannelUnresolved
        } else {
            BootstrapFailure::ReplayTimedOut
        });
    }

    // 4. Still working.
    if !s.connected {
        BootstrapPhase::Connecting
    } else if !s.channel_resolved {
        BootstrapPhase::ResolvingChannel
    } else {
        BootstrapPhase::LoadingMessages
    }
}

#[cfg(test)]
mod tests {
    use super::BootstrapFailure::*;
    use super::BootstrapPhase::*;
    use super::*;

    fn connected() -> BootstrapSignals {
        BootstrapSignals {
            connected: true,
            ..Default::default()
        }
    }

    // -- Pending stages -------------------------------------------------------

    #[test]
    fn nothing_observed_yet_is_connecting() {
        assert_eq!(derive_phase(BootstrapSignals::default()), Connecting);
    }

    #[test]
    fn connected_without_metadata_is_resolving() {
        assert_eq!(derive_phase(connected()), ResolvingChannel);
    }

    #[test]
    fn metadata_without_history_is_loading_messages() {
        let s = BootstrapSignals {
            channel_resolved: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), LoadingMessages);
        assert!(derive_phase(s).is_pending());
    }

    // -- Real receipts --------------------------------------------------------

    #[test]
    fn eose_on_a_resolved_channel_is_a_receipt() {
        let s = BootstrapSignals {
            channel_resolved: true,
            replay_complete: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Ready);
    }

    #[test]
    fn an_empty_channel_that_reached_eose_is_ready_not_failed() {
        // The ADR-092 distinction: an authoritatively EMPTY channel is Ready,
        // and says "no messages yet". A bootstrap that never finished is
        // Failed, and says so. The old timer collapsed both into "loaded".
        let s = BootstrapSignals {
            channel_resolved: true,
            replay_complete: true,
            messages_present: false,
            ..connected()
        };
        assert_eq!(derive_phase(s), Ready);
    }

    #[test]
    fn resolved_target_events_are_a_receipt_on_their_own() {
        // Messages rendered before any EOSE — the target resolved, which is
        // all "the deep link worked" means.
        let s = BootstrapSignals {
            messages_present: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Ready);
    }

    #[test]
    fn a_late_receipt_beats_an_elapsed_deadline() {
        let s = BootstrapSignals {
            channel_resolved: true,
            replay_complete: true,
            deadline_passed: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Ready, "the clock overrode a real receipt");
    }

    #[test]
    fn late_messages_beat_an_elapsed_deadline() {
        let s = BootstrapSignals {
            messages_present: true,
            deadline_passed: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Ready);
    }

    // -- Failures -------------------------------------------------------------

    #[test]
    fn the_deadline_alone_never_reports_success() {
        // This is the defect being closed: eight seconds elapsing used to mean
        // "loaded". It now means "failed", attributed to where it stalled.
        let s = BootstrapSignals {
            deadline_passed: true,
            ..Default::default()
        };
        let phase = derive_phase(s);
        assert!(phase.is_failed());
        assert!(!phase.is_ready());
        assert_eq!(phase, Failed(Disconnected));
    }

    #[test]
    fn deadline_while_connected_without_metadata_is_channel_unresolved() {
        let s = BootstrapSignals {
            deadline_passed: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Failed(ChannelUnresolved));
    }

    #[test]
    fn deadline_after_metadata_is_a_replay_timeout() {
        let s = BootstrapSignals {
            channel_resolved: true,
            deadline_passed: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Failed(ReplayTimedOut));
    }

    #[test]
    fn a_missing_channel_fails_immediately_without_waiting_for_the_deadline() {
        let s = BootstrapSignals {
            channel_absent: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Failed(ChannelNotFound));
        assert!(!derive_phase(s).is_retryable());
    }

    #[test]
    fn a_channel_that_later_resolves_overrides_an_earlier_absent_reading() {
        let s = BootstrapSignals {
            channel_resolved: true,
            replay_complete: true,
            channel_absent: true,
            ..connected()
        };
        assert_eq!(derive_phase(s), Ready);
    }

    #[test]
    fn timeouts_are_retryable_but_a_missing_channel_is_not() {
        assert!(Failed(Disconnected).is_retryable());
        assert!(Failed(ChannelUnresolved).is_retryable());
        assert!(Failed(ReplayTimedOut).is_retryable());
        assert!(!Failed(ChannelNotFound).is_retryable());
    }

    // -- Presentation ---------------------------------------------------------

    #[test]
    fn every_failure_states_the_failure_rather_than_claiming_success() {
        for failure in [
            Disconnected,
            ChannelNotFound,
            ChannelUnresolved,
            ReplayTimedOut,
        ] {
            let msg = Failed(failure).message();
            assert!(!msg.is_empty());
            let lower = msg.to_lowercase();
            assert!(
                !lower.contains("loaded successfully") && !lower.contains("up to date"),
                "failure message reads as success: {msg}"
            );
        }
    }

    #[test]
    fn phase_predicates_are_mutually_exclusive() {
        for phase in [
            Connecting,
            ResolvingChannel,
            LoadingMessages,
            Ready,
            Failed(Disconnected),
            Failed(ChannelNotFound),
        ] {
            let flags = [phase.is_ready(), phase.is_failed(), phase.is_pending()];
            assert_eq!(
                flags.iter().filter(|f| **f).count(),
                1,
                "{phase:?} is in more than one state"
            );
        }
    }
}
