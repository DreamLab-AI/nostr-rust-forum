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
//! A re-send goes out under a FRESH wire subscription id ([`wire_id`]), and
//! the old one is closed. That is what makes the ledger exact: under one
//! shared id an EOSE cannot say which REQ it answers, so a dropped REQ and a
//! merely slow one are indistinguishable. With a retired id, a late answer to
//! the abandoned REQ arrives under that id, [`route`] reports it as
//! [`Route::Retired`], and it never reaches the ledger.
//!
//! **Invariant: an answer is never credited to a REQ sent after it.** Within
//! one wire id, the ledger only settles when every REQ sent under it is
//! answered; across ids, answers under a retired id are discarded.
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

    /// The relay answered one REQ (EOSE or CLOSED) under the CURRENT wire
    /// id. Returns whether the subscription is now fully answered on an
    /// authenticated REQ. An answer with nothing outstanding (e.g. a late one
    /// after [`Watch::GiveUp`]) is never credited: it changes nothing and
    /// returns `false`.
    pub fn answered(&mut self) -> bool {
        if self.outstanding == 0 {
            return false;
        }
        self.outstanding -= 1;
        self.resends = 0;
        self.outstanding == 0 && self.last_req_authed
    }

    /// Whether the timeout armed for REQ `seq` still has something to judge:
    /// it is the latest REQ and its answer is outstanding. Read-only, so a
    /// timeout can re-check later without spending a re-send.
    pub fn is_waiting_on(&self, seq: u64) -> bool {
        seq == self.seq && self.outstanding > 0
    }

    /// Re-sends since the last answer (scales the next timeout).
    pub fn resends(&self) -> u32 {
        self.resends
    }

    /// The answer timeout armed for REQ `seq` fired.
    ///
    /// Taking the REQs as dropped zeroes the outstanding count. That is exact,
    /// not a guess, because the caller retires their wire id: on
    /// [`Watch::Resend`] it closes the old id and re-sends under a fresh one,
    /// and on [`Watch::GiveUp`] any late answer is uncreditable (see
    /// [`answered`](Self::answered)), so a slow answer to an abandoned REQ can
    /// never be counted against a newer one.
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

/// Separator between a logical subscription id and its re-send generation
/// in a wire id. Logical ids are `sub_N` and never contain it.
const WIRE_SEP: char = '~';

/// The wire subscription id for re-send generation `generation` of logical
/// subscription `sub_id`. Generation 0 is the logical id itself, so the
/// common path (never re-sent) is unchanged on the wire. Stays well inside
/// NIP-01's 64-character limit.
pub fn wire_id(sub_id: &str, generation: u32) -> String {
    if generation == 0 {
        sub_id.to_string()
    } else {
        format!("{sub_id}{WIRE_SEP}{generation}")
    }
}

/// The logical subscription id a wire id belongs to.
pub fn logical_id(wire: &str) -> &str {
    wire.split(WIRE_SEP).next().unwrap_or(wire)
}

/// How a frame's subscription id relates to a subscription.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// The subscription's current wire id: credit answers, deliver events.
    Current,
    /// An id the subscription has since re-sent under a new one: answers
    /// belong to an abandoned REQ and are discarded.
    Retired,
}

/// Classify `wire` against the subscription's `current` wire id. Callers
/// look the subscription up by [`logical_id`] first; an unknown logical id
/// has no route at all.
pub fn route(wire: &str, current: &str) -> Route {
    if wire == current {
        Route::Current
    } else {
        Route::Retired
    }
}

/// The NIP-42 state a held-writes release is judged on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HandshakeView {
    /// The check was armed for the socket that is current now.
    pub same_socket: bool,
    /// That socket is OPEN. Released writes go to the send queue, and a
    /// closed socket's queue is flushed on reconnect BEFORE that socket's
    /// AUTH, where the relay refuses them — so a dead socket must keep them
    /// held for the next AUTH instead.
    pub socket_open: bool,
    /// A one-shot foreign connection, which never holds writes.
    pub immediate_writes: bool,
    pub accepted: bool,
    pub refused: bool,
    /// When the challenge arrived (or the socket opened), epoch ms.
    pub challenge_at: Option<f64>,
    /// When the pending AUTH (or its latest re-send) went out, epoch ms.
    pub sent_at: Option<f64>,
}

/// Whether held writes should be released now because the handshake stalled
/// on a live socket. See [`auth_stalled`] for the clocks.
pub fn release_held_writes(v: HandshakeView, now: f64) -> bool {
    let unresolved =
        v.same_socket && v.socket_open && !v.immediate_writes && !v.accepted && !v.refused;
    match (unresolved, v.challenge_at) {
        (true, Some(challenge_at)) => auth_stalled(challenge_at, v.sent_at, now),
        _ => false,
    }
}

/// The error a post shows when the relay refused it. A bare
/// `auth-required: …` reads as a relay fault; when it follows a sign-in that
/// did not complete on this socket (`auth_note` is why), say that instead.
/// Every other message is passed through unchanged.
pub fn explain_write_refusal(message: &str, auth_note: Option<&str>) -> String {
    match auth_note {
        Some(note) if message.starts_with("auth-required:") => format!(
            "Relay sign-in did not complete ({note}), so the relay refused this. Reload the page and try again."
        ),
        _ => message.to_string(),
    }
}

/// How soon a REQ's timeout looks again while the REQ is still in the
/// client's paced send queue (not yet on the wire).
pub const QUEUED_RECHECK_MS: i32 = 1_000;

/// What a REQ's answer timeout should do once it fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchDue {
    /// The REQ has been on the wire for the whole timeout: judge it.
    Due,
    /// Look again in this many milliseconds.
    RecheckIn(i32),
}

/// Whether a REQ's answer timeout is due. The clock runs from when the frame
/// actually left the paced send queue (`sent_at`, epoch ms; `None` while it
/// is still queued), not from when it was queued: at boot the queue holds
/// every subscription plus the post-AUTH replay, paced at a few frames a
/// second, so timing from the queue took REQs the relay had not even
/// received yet as dropped, and each re-send lengthened the queue further.
pub fn watch_due(sent_at: Option<f64>, now: f64, timeout_ms: i32) -> WatchDue {
    let Some(sent) = sent_at else {
        return WatchDue::RecheckIn(QUEUED_RECHECK_MS);
    };
    let elapsed = now - sent;
    let timeout = f64::from(timeout_ms);
    if elapsed >= timeout {
        WatchDue::Due
    } else {
        // At least 1 ms, so a rounding remainder cannot spin.
        WatchDue::RecheckIn(((timeout - elapsed).ceil() as i32).max(1))
    }
}

/// The wire subscription id of a `["REQ", id, …]` frame, if it is one.
pub fn req_wire_id(frame: &str) -> Option<&str> {
    let rest = frame.strip_prefix("[\"REQ\",\"")?;
    rest.split('"').next()
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

    // -- Re-send under a fresh wire id ---------------------------------------

    /// One logical subscription's ledger plus its current wire id, driven the
    /// way relay.rs drives them, so the routing and the counting are tested
    /// together.
    struct Sim {
        ledger: ReqLedger,
        generation: u32,
        current: String,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                ledger: ReqLedger::default(),
                generation: 0,
                current: wire_id("sub_1", 0),
            }
        }
        /// Send a REQ under the current id; returns (wire id, seq).
        fn send(&mut self, authed: bool) -> (String, u64) {
            (self.current.clone(), self.ledger.sent(authed))
        }
        /// The answer timeout for `seq` fired; on Resend, retire the id.
        fn watch(&mut self, seq: u64) -> Watch {
            let w = self.ledger.on_watch(seq);
            if w == Watch::Resend {
                self.generation += 1;
                self.current = wire_id("sub_1", self.generation);
            }
            w
        }
        /// An EOSE arrived under `wire`; returns the receipt verdict, or
        /// `None` when it was not credited (retired id).
        fn eose(&mut self, wire: &str) -> Option<bool> {
            assert_eq!(logical_id(wire), "sub_1");
            match route(wire, &self.current) {
                Route::Current => Some(self.ledger.answered()),
                Route::Retired => None,
            }
        }
    }

    #[test]
    fn wire_ids_round_trip_to_the_logical_id() {
        assert_eq!(wire_id("sub_7", 0), "sub_7");
        assert_eq!(wire_id("sub_7", 2), "sub_7~2");
        assert_eq!(logical_id("sub_7~2"), "sub_7");
        assert_eq!(logical_id("sub_7"), "sub_7");
        assert_eq!(logical_id("count_3"), "count_3");
        assert!(wire_id("sub_18446744073709551615", u32::MAX).len() <= 64);
    }

    #[test]
    fn routing_distinguishes_current_from_retired() {
        assert_eq!(route("sub_1~1", "sub_1~1"), Route::Current);
        assert_eq!(route("sub_1", "sub_1~1"), Route::Retired);
    }

    /// The reviewed sequence: anonymous #1 times out, anonymous #2 is
    /// re-sent, AUTH is accepted and #3 replays authenticated; then #1's and
    /// #2's anonymous EOSEs arrive. Neither may settle the ledger while #3 is
    /// in flight.
    #[test]
    fn late_anonymous_answers_never_settle_ahead_of_the_authed_replay() {
        let mut s = Sim::new();
        let (w1, seq1) = s.send(false);
        assert_eq!(s.watch(seq1), Watch::Resend);
        let (w2, _) = s.send(false);
        let (w3, _) = s.send(true);
        assert_ne!(w1, w2, "the re-send uses a fresh wire id");
        assert_eq!(w2, w3, "the replay reuses the current id");
        assert_eq!(s.eose(&w1), None, "#1's late answer is not credited");
        assert_eq!(s.eose(&w2), Some(false), "#2 answered, #3 still in flight");
        assert_eq!(s.eose(&w3), Some(true), "#3 settles it, authenticated");
    }

    /// The dropped case: #1 never answers; the re-sent #2 settles alone.
    #[test]
    fn dropped_req_settles_on_the_resent_answer() {
        let mut s = Sim::new();
        let (_, seq1) = s.send(true);
        assert_eq!(s.watch(seq1), Watch::Resend);
        let (w2, _) = s.send(true);
        assert_eq!(s.eose(&w2), Some(true));
    }

    #[test]
    fn late_answer_after_give_up_is_not_credited() {
        let mut l = ReqLedger::default();
        let mut seq = l.sent(true);
        for _ in 0..REQ_RESEND_LIMIT {
            assert_eq!(l.on_watch(seq), Watch::Resend);
            seq = l.sent(true);
        }
        assert_eq!(l.on_watch(seq), Watch::GiveUp);
        assert!(!l.answered(), "nothing outstanding: no credit");
    }

    // -- Timeout runs from the send, not the queue ---------------------------

    #[test]
    fn queued_req_is_rechecked_not_judged() {
        assert_eq!(
            watch_due(None, 1e6, REQ_ANSWER_TIMEOUT_MS),
            WatchDue::RecheckIn(QUEUED_RECHECK_MS)
        );
    }

    /// The boot case: queued at t=0, sent at t=5 s after the paced backlog.
    /// At t=8 s it has been on the wire 3 s, so it is not yet dropped.
    #[test]
    fn timeout_counts_from_the_send() {
        let sent = 5_000.0;
        assert_eq!(
            watch_due(Some(sent), 8_000.0, REQ_ANSWER_TIMEOUT_MS),
            WatchDue::RecheckIn(5_000)
        );
        assert_eq!(
            watch_due(Some(sent), 13_000.0, REQ_ANSWER_TIMEOUT_MS),
            WatchDue::Due
        );
    }

    #[test]
    fn recheck_never_spins_on_a_rounding_remainder() {
        assert_eq!(
            watch_due(Some(0.0), 7_999.999_9, REQ_ANSWER_TIMEOUT_MS),
            WatchDue::RecheckIn(1)
        );
    }

    #[test]
    fn waiting_on_is_read_only_and_tracks_the_latest_req() {
        let mut l = ReqLedger::default();
        let old = l.sent(false);
        let new = l.sent(true);
        assert!(!l.is_waiting_on(old));
        assert!(l.is_waiting_on(new));
        assert!(l.is_waiting_on(new), "asking twice spends nothing");
        l.answered();
        l.answered();
        assert!(!l.is_waiting_on(new));
    }

    #[test]
    fn req_frames_yield_their_wire_id() {
        assert_eq!(
            req_wire_id(r#"["REQ","sub_3~1",{"kinds":[42]}]"#),
            Some("sub_3~1")
        );
        assert_eq!(req_wire_id(r#"["CLOSE","sub_3"]"#), None);
        assert_eq!(req_wire_id(r#"["EVENT",{}]"#), None);
    }

    // -- Held writes ---------------------------------------------------------

    fn stalled_view() -> HandshakeView {
        HandshakeView {
            same_socket: true,
            socket_open: true,
            immediate_writes: false,
            accepted: false,
            refused: false,
            challenge_at: Some(0.0),
            sent_at: Some(1_000.0),
        }
    }

    #[test]
    fn stalled_handshake_on_a_live_socket_releases() {
        assert!(release_held_writes(stalled_view(), 20_000.0));
    }

    /// The reviewed case: the socket dropped mid-handshake and the reconnect
    /// backoff outlasted the clock. Held writes must stay held for the next
    /// socket's AUTH rather than be flushed before it and refused.
    #[test]
    fn dead_socket_never_releases() {
        let v = HandshakeView {
            socket_open: false,
            ..stalled_view()
        };
        assert!(!release_held_writes(v, 20_000.0));
    }

    #[test]
    fn old_socket_generation_never_releases() {
        let v = HandshakeView {
            same_socket: false,
            ..stalled_view()
        };
        assert!(!release_held_writes(v, 20_000.0));
    }

    #[test]
    fn resolved_or_foreign_handshakes_never_release() {
        for v in [
            HandshakeView {
                accepted: true,
                ..stalled_view()
            },
            HandshakeView {
                refused: true,
                ..stalled_view()
            },
            HandshakeView {
                immediate_writes: true,
                ..stalled_view()
            },
            HandshakeView {
                challenge_at: None,
                ..stalled_view()
            },
        ] {
            assert!(!release_held_writes(v, 20_000.0), "{v:?}");
        }
    }

    #[test]
    fn not_yet_stalled_does_not_release() {
        assert!(!release_held_writes(stalled_view(), 5_000.0));
    }

    #[test]
    fn auth_refusal_after_failed_sign_in_is_explained() {
        let m = explain_write_refusal("auth-required: sign in first", Some("signing was denied"));
        assert!(m.starts_with("Relay sign-in did not complete (signing was denied)"));
    }

    #[test]
    fn other_refusals_pass_through() {
        assert_eq!(
            explain_write_refusal("blocked: spam", Some("stalled")),
            "blocked: spam"
        );
        assert_eq!(
            explain_write_refusal("auth-required: sign in first", None),
            "auth-required: sign in first"
        );
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
