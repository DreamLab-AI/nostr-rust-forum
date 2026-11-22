//! Which EOSE answers count as an *authenticated* "that is everything".
//!
//! A NIP-42 relay evaluates each REQ against the session's authentication at
//! the moment it starts processing that REQ. A REQ sent before the relay
//! accepted our AUTH gets the anonymous view, which for a members-only zone
//! omits the very events a page is waiting for. The client replays every
//! subscription once AUTH is accepted, under the same subscription id, so a
//! subscription can have an anonymous and an authenticated REQ in flight at
//! once — and the relay does not promise to answer them in order (its REQ
//! handler awaits a D1 query, so a later REQ can finish first).
//!
//! [`ReqLedger`] therefore never guesses which REQ an EOSE belongs to. It
//! reports an answer as authenticated only when every REQ sent for the
//! subscription has been answered and the most recent one went out after the
//! relay accepted AUTH. Whatever the arrival order, at that point the
//! authenticated answer's events have all been delivered.
//!
//! The relay can also drop a REQ with nothing but a NOTICE (its per-IP rate
//! limit, its subscription cap), which names no subscription, so that REQ is
//! never answered. [`ReqLedger::on_watch`] is the per-REQ timeout that keeps
//! such a drop from pinning the ledger: re-send a bounded number of times,
//! then stop waiting.
//!
//! The same module bounds the NIP-42 handshake itself ([`auth_stalled`]):
//! writes are held until AUTH is accepted, so an AUTH that is never signed or
//! never answered must not hold them forever.
//!
//! Pure, so it unit-tests natively.

/// How many times a rate-limited AUTH is re-sent before giving up.
pub const AUTH_RETRY_LIMIT: u32 = 3;

/// How long a REQ may go unanswered (no EOSE, no CLOSED) before it is taken
/// to have been dropped. The relay answers from one D1 query capped at 1000
/// rows, normally well under two seconds; eight leaves room for a cold DO and
/// a slow query, and still lets a re-sent REQ's answer land before a page's
/// 15 s lookup deadline. The relay's per-IP rate limit is a one-second
/// window, so a REQ it dropped for rate will pass when re-sent.
pub const REQ_ANSWER_TIMEOUT_MS: i32 = 8_000;

/// How many times a REQ that went unanswered is re-sent. A REQ refused by
/// the subscription cap keeps being refused while the cap is full, so this
/// is small; after it the ledger stops waiting rather than stick.
pub const REQ_RESEND_LIMIT: u32 = 2;

/// How long a NIP-42 challenge may wait for a signature before held writes
/// are released. Long, because a NIP-07 extension may be showing the user a
/// prompt; a denial or a signer error is handled at once, not by this.
pub const AUTH_SIGN_TIMEOUT_MS: i32 = 60_000;

/// How long a sent AUTH may wait for the relay's `OK` before held writes are
/// released. The relay answers after one signature check and one storage
/// write; ten seconds is generous for that and spans its rate-limit retry
/// backoff (each re-send restarts this clock). A lost `OK` must not leave a
/// post waiting with no error.
pub const AUTH_ANSWER_TIMEOUT_MS: i32 = 10_000;

/// Per-subscription count of REQs awaiting an answer (EOSE or CLOSED).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReqLedger {
    outstanding: u32,
    last_req_authed: bool,
    /// Sequence number of the latest REQ sent, so a timeout armed for an
    /// older REQ can tell it has been superseded.
    seq: u64,
    /// Re-sends since the last answer.
    resends: u32,
}

/// What a REQ's answer timeout should do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    /// Answered, or superseded by a newer REQ with its own timeout.
    Settled,
    /// Taken as dropped: send the REQ again (and count it).
    Resend,
    /// Dropped too often: stop waiting so the ledger cannot stick. No
    /// receipt follows; the page's own deadline reports it.
    GiveUp,
}

impl ReqLedger {
    /// A REQ frame for this subscription went out; `authed` is whether the
    /// relay had accepted our AUTH on this socket when it did.
    /// Returns the REQ's sequence number, for its answer timeout.
    pub fn sent(&mut self, authed: bool) -> u64 {
        self.outstanding = self.outstanding.saturating_add(1);
        self.last_req_authed = authed;
        self.seq += 1;
        self.seq
    }

    /// The relay answered one REQ (EOSE or CLOSED). Returns whether the
    /// subscription is now fully answered on an authenticated REQ.
    pub fn answered(&mut self) -> bool {
        self.outstanding = self.outstanding.saturating_sub(1);
        self.resends = 0;
        self.outstanding == 0 && self.last_req_authed
    }

    /// Re-sends since the last answer (scales the next timeout).
    pub fn resends(&self) -> u32 {
        self.resends
    }

    /// The answer timeout armed for REQ `seq` fired.
    ///
    /// Taking a REQ as dropped forgets every outstanding count, because a
    /// dropped REQ will never answer. The cost is that a REQ which was only
    /// slow — slower than [`REQ_ANSWER_TIMEOUT_MS`] — answers later and is
    /// subtracted from the re-sent one; that requires a pathological relay
    /// query and is the price of never sticking.
    pub fn on_watch(&mut self, seq: u64) -> Watch {
        if seq != self.seq || self.outstanding == 0 {
            return Watch::Settled;
        }
        self.outstanding = 0;
        if self.resends < REQ_RESEND_LIMIT {
            self.resends += 1;
            Watch::Resend
        } else {
            Watch::GiveUp
        }
    }

    /// A new socket: answers to REQs sent on the old one will never arrive.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Delay before the answer timeout for a REQ fires: backs off with each
/// re-send so a briefly saturated relay is not hammered.
pub fn req_watch_delay(resends: u32) -> i32 {
    // Clamp before the cast: `u32` beyond `i32::MAX` would wrap negative.
    let factor = i32::try_from(resends.saturating_add(1)).unwrap_or(i32::MAX);
    REQ_ANSWER_TIMEOUT_MS.saturating_mul(factor)
}

/// Whether the NIP-42 handshake has stalled: a challenge (received at
/// `challenge_at`; the connect time until one arrives) still unsigned after [`AUTH_SIGN_TIMEOUT_MS`], or an AUTH
/// sent at `sent_at` still unanswered after [`AUTH_ANSWER_TIMEOUT_MS`].
/// Times are epoch milliseconds. A stalled handshake is treated like a
/// refused one, so held writes reach the relay and its refusal reaches the
/// user.
pub fn auth_stalled(challenge_at: f64, sent_at: Option<f64>, now: f64) -> bool {
    match sent_at {
        None => now - challenge_at >= f64::from(AUTH_SIGN_TIMEOUT_MS),
        Some(sent) => now - sent >= f64::from(AUTH_ANSWER_TIMEOUT_MS),
    }
}

/// What to do with the relay's `OK` for our kind-22242 AUTH event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthReply {
    /// The session is authenticated: replay subscriptions, flush writes.
    Accepted,
    /// Refused by the relay's rate limiter; re-send the same AUTH frame.
    Retry,
    /// Refused outright (bad challenge, skew, signature); stay anonymous.
    Rejected,
}

/// Classify the relay's `OK` for our AUTH. `attempts` is how many times the
/// frame has already been sent. The relay prefixes a rate-limit refusal with
/// `rate-limited:` (NIP-01 machine-readable prefix) precisely so the client
/// knows to retry rather than sit unauthenticated.
pub fn classify_auth_ok(accepted: bool, message: &str, attempts: u32) -> AuthReply {
    if accepted {
        AuthReply::Accepted
    } else if message.starts_with("rate-limited:") && attempts < AUTH_RETRY_LIMIT {
        AuthReply::Retry
    } else {
        AuthReply::Rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_authed_req_answered_is_authed() {
        let mut l = ReqLedger::default();
        l.sent(true);
        assert!(l.answered());
    }

    #[test]
    fn single_anonymous_req_answered_is_not_authed() {
        let mut l = ReqLedger::default();
        l.sent(false);
        assert!(!l.answered());
    }

    /// The reviewed race: the anonymous REQ sent at socket open is answered
    /// after AUTH was accepted and the replay went out. Its EOSE must not
    /// count; only the last outstanding answer may.
    #[test]
    fn anonymous_answer_after_acceptance_does_not_count() {
        let mut l = ReqLedger::default();
        l.sent(false); // REQ at on_open, before AUTH
        l.sent(true); // replay after OK true
        assert!(!l.answered(), "first answer may be the anonymous one");
        assert!(l.answered(), "both answered, last REQ authed");
    }

    #[test]
    fn out_of_order_answers_still_settle_only_when_all_are_in() {
        // Whichever REQ's EOSE lands first, the verdict waits for the other.
        let mut l = ReqLedger::default();
        l.sent(false);
        l.sent(true);
        assert!(!l.answered());
        assert!(l.answered());
    }

    #[test]
    fn req_sent_during_handshake_then_replayed_settles_after_both() {
        let mut l = ReqLedger::default();
        l.sent(false); // subscribe() while AUTH is pending
        l.sent(false); // another anonymous resend
        l.sent(true); // replay on acceptance
        assert!(!l.answered());
        assert!(!l.answered());
        assert!(l.answered());
    }

    #[test]
    fn reset_forgets_answers_owed_by_an_old_socket() {
        let mut l = ReqLedger::default();
        l.sent(true);
        l.sent(true);
        l.reset();
        l.sent(false);
        assert!(!l.answered());
    }

    #[test]
    fn spurious_answer_does_not_underflow() {
        let mut l = ReqLedger::default();
        assert!(!l.answered());
        l.sent(true);
        assert!(l.answered());
    }

    #[test]
    fn watch_for_an_answered_req_is_settled() {
        let mut l = ReqLedger::default();
        let seq = l.sent(true);
        l.answered();
        assert_eq!(l.on_watch(seq), Watch::Settled);
    }

    #[test]
    fn watch_for_a_superseded_req_is_settled() {
        let mut l = ReqLedger::default();
        let old = l.sent(false);
        l.sent(true);
        assert_eq!(
            l.on_watch(old),
            Watch::Settled,
            "the newer REQ has its own watch"
        );
    }

    /// A REQ dropped with only a NOTICE: re-sent, and its answer settles the
    /// ledger instead of it sticking above zero.
    #[test]
    fn dropped_req_is_resent_and_then_settles() {
        let mut l = ReqLedger::default();
        let seq = l.sent(true);
        assert_eq!(l.on_watch(seq), Watch::Resend);
        let seq = l.sent(true);
        assert!(l.answered(), "the re-sent REQ's EOSE settles it");
        assert_eq!(l.on_watch(seq), Watch::Settled);
    }

    #[test]
    fn repeatedly_dropped_req_gives_up_without_sticking() {
        let mut l = ReqLedger::default();
        let mut seq = l.sent(true);
        for _ in 0..REQ_RESEND_LIMIT {
            assert_eq!(l.on_watch(seq), Watch::Resend);
            seq = l.sent(true);
        }
        assert_eq!(l.on_watch(seq), Watch::GiveUp);
        // Not stuck: the next (e.g. post-reconnect) REQ settles on its answer.
        l.sent(true);
        assert!(l.answered());
    }

    #[test]
    fn an_answer_restores_the_resend_budget() {
        let mut l = ReqLedger::default();
        let seq = l.sent(true);
        assert_eq!(l.on_watch(seq), Watch::Resend);
        l.sent(true);
        l.answered();
        assert_eq!(l.resends(), 0);
    }

    #[test]
    fn watch_delay_backs_off() {
        assert_eq!(req_watch_delay(0), REQ_ANSWER_TIMEOUT_MS);
        assert_eq!(req_watch_delay(1), 2 * REQ_ANSWER_TIMEOUT_MS);
        assert!(
            req_watch_delay(u32::MAX) > 0,
            "no overflow to a negative delay"
        );
    }

    #[test]
    fn auth_stalls_when_unsigned_too_long() {
        let t = 1_000_000.0;
        assert!(!auth_stalled(t, None, t + 59_999.0));
        assert!(auth_stalled(t, None, t + 60_000.0));
    }

    #[test]
    fn auth_stalls_when_unanswered_too_long() {
        let t = 1_000_000.0;
        let sent = t + 30_000.0;
        assert!(!auth_stalled(t, Some(sent), sent + 9_999.0));
        assert!(auth_stalled(t, Some(sent), sent + 10_000.0));
    }

    #[test]
    fn a_resent_auth_restarts_the_answer_clock() {
        let t = 1_000_000.0;
        // A timer armed for the first send fires after a retry went out.
        let resent = t + 9_000.0;
        assert!(!auth_stalled(t, Some(resent), t + 10_000.0));
    }

    #[test]
    fn auth_ok_classification() {
        assert_eq!(classify_auth_ok(true, "", 1), AuthReply::Accepted);
        assert_eq!(
            classify_auth_ok(false, "rate-limited: slow down", 1),
            AuthReply::Retry
        );
        assert_eq!(
            classify_auth_ok(false, "rate-limited: slow down", AUTH_RETRY_LIMIT),
            AuthReply::Rejected
        );
        assert_eq!(
            classify_auth_ok(false, "auth-required: bad challenge", 1),
            AuthReply::Rejected
        );
    }
}
