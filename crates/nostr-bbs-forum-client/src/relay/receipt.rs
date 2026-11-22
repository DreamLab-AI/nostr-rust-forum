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
//! Pure, so it unit-tests natively.

/// How many times a rate-limited AUTH is re-sent before giving up.
pub const AUTH_RETRY_LIMIT: u32 = 3;

/// Per-subscription count of REQs awaiting an answer (EOSE or CLOSED).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReqLedger {
    outstanding: u32,
    last_req_authed: bool,
}

impl ReqLedger {
    /// A REQ frame for this subscription went out; `authed` is whether the
    /// relay had accepted our AUTH on this socket when it did.
    pub fn sent(&mut self, authed: bool) {
        self.outstanding = self.outstanding.saturating_add(1);
        self.last_req_authed = authed;
    }

    /// The relay answered one REQ (EOSE or CLOSED). Returns whether the
    /// subscription is now fully answered on an authenticated REQ.
    pub fn answered(&mut self) -> bool {
        self.outstanding = self.outstanding.saturating_sub(1);
        self.outstanding == 0 && self.last_req_authed
    }

    /// A new socket: answers to REQs sent on the old one will never arrive.
    pub fn reset(&mut self) {
        *self = Self::default();
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
