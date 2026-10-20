//! Outgoing-frame queue and delivery tracking for the DM socket.
//!
//! Pure state, no I/O, so it is unit-tested on native. The wasm socket in
//! `dm.rs` owns one [`Outbox`] and feeds it three things: frames to publish
//! ([`Outbox::submit`], which queues while the socket is not OPEN), the
//! relay's `OK` replies ([`Outbox::on_ok`]) and ack timeouts
//! ([`Outbox::on_timeout`]). A message with several wraps (self-copy plus
//! recipient copy) is [`Delivery::Sent`] only when every wrap is acknowledged.

use std::collections::{HashMap, HashSet, VecDeque};

/// Delivery state of a sent message, shown next to its bubble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Published (or queued) but not yet acknowledged by the relay.
    Sending,
    /// Every wrap was acknowledged with `OK true`.
    Sent,
    /// The relay refused a wrap (`OK false`) or no acknowledgement arrived in time.
    Failed,
}

/// First reconnect delay.
pub const BASE_RECONNECT_MS: u32 = 1_000;
/// Reconnect delay ceiling (same policy as the forum client's relay).
pub const MAX_RECONNECT_MS: u32 = 30_000;

/// Delay before reconnect attempt number `attempts` (0-based): `1 s` doubling
/// to a `30 s` cap, reduced by up to 25 % by `jitter` (0.0..=1.0) so a relay
/// restart does not see every client return in the same instant.
pub fn reconnect_delay_ms(attempts: u32, jitter: f64) -> u32 {
    let base = BASE_RECONNECT_MS
        .saturating_mul(2u32.saturating_pow(attempts))
        .min(MAX_RECONNECT_MS);
    let j = jitter.clamp(0.0, 1.0);
    (f64::from(base) * (1.0 - 0.25 * j)) as u32
}

/// Reconnect bookkeeping for the DM socket.
#[derive(Default)]
pub struct Reconnect {
    attempts: u32,
    active: bool,
}

impl Reconnect {
    /// The socket closed or errored: unauthenticate `outbox` (the new socket
    /// must AUTH again), enter the reconnecting state and return the delay
    /// before the next attempt.
    pub fn on_close(&mut self, outbox: &mut Outbox, jitter: f64) -> u32 {
        outbox.set_authed(false);
        let delay = reconnect_delay_ms(self.attempts, jitter);
        self.attempts = self.attempts.saturating_add(1);
        self.active = true;
        delay
    }

    /// The socket (re)opened: leave the reconnecting state and reset the backoff.
    pub fn on_open(&mut self) {
        self.attempts = 0;
        self.active = false;
    }

    /// Whether a reconnect is in progress (drives the "reconnecting" indicator).
    pub fn is_reconnecting(&self) -> bool {
        self.active
    }
}

struct Queued {
    event_id: String,
    frame: String,
}

struct Tracker {
    remaining: HashSet<String>,
    events: Vec<String>,
}

/// Queue of frames awaiting an OPEN socket, plus per-message ack tracking.
#[derive(Default)]
pub struct Outbox {
    queue: VecDeque<Queued>,
    /// message id -> outstanding wraps.
    trackers: HashMap<String, Tracker>,
    /// event id -> message id.
    by_event: HashMap<String, String>,
    /// Whether the NIP-42 AUTH handshake has completed on the current socket.
    authed: bool,
    /// Frames of in-flight events, kept so an `auth-required` refusal can retry.
    frames: HashMap<String, String>,
    /// Events already re-queued once after `auth-required`.
    retried: HashSet<String>,
    /// Messages shown `Failed` by an ack timeout whose events stay resolvable,
    /// so a late `OK true` can still settle them as `Sent`.
    timed_out: HashSet<String>,
    /// event id -> token of its live ack timer (older timers are stale).
    timers: HashMap<String, u64>,
    next_token: u64,
}

impl Outbox {
    /// Mark the NIP-42 handshake complete (or lost, on a new socket).
    pub fn set_authed(&mut self, authed: bool) {
        self.authed = authed;
    }

    /// Whether writes may currently be sent.
    pub fn is_authed(&self) -> bool {
        self.authed
    }

    /// Take the queued frames if the socket is `open` and authenticated, else
    /// nothing. Call when the socket opens, when AUTH succeeds, and after an
    /// `auth-required` re-queue.
    pub fn flush(&mut self, open: bool) -> Vec<String> {
        if open && self.authed {
            self.drain()
        } else {
            Vec::new()
        }
    }

    /// Offer a frame for `event_id`. Returns it for immediate sending when the
    /// socket is `open` and authenticated; otherwise queues it (returning
    /// `None`) until [`Self::flush`]. The relay refuses unauthenticated writes
    /// with `auth-required`, so sending earlier would only fail the message.
    pub fn submit(&mut self, event_id: &str, frame: String, open: bool) -> Option<String> {
        self.frames.insert(event_id.to_string(), frame.clone());
        if open && self.authed {
            Some(frame)
        } else {
            self.queue.push_back(Queued {
                event_id: event_id.to_string(),
                frame,
            });
            None
        }
    }

    /// Number of frames waiting for the socket to open.
    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    /// Take every queued frame, oldest first (call when the socket opens).
    pub fn drain(&mut self) -> Vec<String> {
        self.queue.drain(..).map(|q| q.frame).collect()
    }

    /// Like [`Self::flush`] but also returns each frame's event id, so the
    /// caller can arm the ack timer for frames at the moment they really leave.
    pub fn flush_with_ids(&mut self, open: bool) -> Vec<(String, String)> {
        if open && self.authed {
            self.queue
                .drain(..)
                .map(|q| (q.event_id, q.frame))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Start an ack timer for `event_id` (call when its frame is actually sent).
    /// Returns the token to hand back to [`Self::on_timer`]; arming again
    /// (a retry) supersedes the earlier timer.
    pub fn arm_timer(&mut self, event_id: &str) -> u64 {
        self.next_token += 1;
        self.timers.insert(event_id.to_string(), self.next_token);
        self.next_token
    }

    /// An ack timer fired. Ignored unless `token` is the live timer for the
    /// event (a queued-but-never-sent frame has none), then behaves as
    /// [`Self::on_timeout`].
    pub fn on_timer(&mut self, event_id: &str, token: u64) -> Option<(String, Delivery)> {
        if self.timers.get(event_id) != Some(&token) {
            return None;
        }
        self.timers.remove(event_id);
        self.on_timeout(event_id)
    }

    /// Start tracking `msg_id`, which is delivered once all `event_ids` are acked.
    pub fn track(&mut self, msg_id: &str, event_ids: &[String]) {
        for e in event_ids {
            self.by_event.insert(e.clone(), msg_id.to_string());
        }
        self.trackers.insert(
            msg_id.to_string(),
            Tracker {
                remaining: event_ids.iter().cloned().collect(),
                events: event_ids.to_vec(),
            },
        );
    }

    /// Record the relay's `OK` for `event_id` (with its `reason` text). Returns
    /// the message id and its final state only on the transition to `Sent` or
    /// `Failed`. An `auth-required` refusal re-queues the frame once instead of
    /// failing; a repeat fails.
    pub fn on_ok(
        &mut self,
        event_id: &str,
        accepted: bool,
        reason: &str,
    ) -> Option<(String, Delivery)> {
        let msg_id = self.by_event.get(event_id)?.clone();
        self.timers.remove(event_id);
        if self.timed_out.contains(&msg_id) {
            // Late answer for a message already shown Failed.
            if !accepted {
                self.timed_out.remove(&msg_id);
                self.finish(&msg_id);
                return None;
            }
            let done = {
                let t = self.trackers.get_mut(&msg_id)?;
                t.remaining.remove(event_id);
                t.remaining.is_empty()
            };
            return if done {
                self.timed_out.remove(&msg_id);
                self.finish(&msg_id);
                Some((msg_id, Delivery::Sent))
            } else {
                None
            };
        }
        if !accepted {
            if reason.starts_with("auth-required") && self.retried.insert(event_id.to_string()) {
                if let Some(frame) = self.frames.get(event_id).cloned() {
                    self.queue.push_back(Queued {
                        event_id: event_id.to_string(),
                        frame,
                    });
                    return None;
                }
            }
            return self.fail(&msg_id);
        }
        let done = {
            let t = self.trackers.get_mut(&msg_id)?;
            t.remaining.remove(event_id);
            t.remaining.is_empty()
        };
        if done {
            self.finish(&msg_id);
            Some((msg_id, Delivery::Sent))
        } else {
            None
        }
    }

    /// The ack timer for `event_id` fired. Fails the message if that wrap is
    /// still unacknowledged; a no-op if it was already settled.
    pub fn on_timeout(&mut self, event_id: &str) -> Option<(String, Delivery)> {
        let msg_id = self.by_event.get(event_id)?.clone();
        let pending = !self.timed_out.contains(&msg_id)
            && self
                .trackers
                .get(&msg_id)
                .is_some_and(|t| t.remaining.contains(event_id));
        if !pending {
            return None;
        }
        // Failed, but keep the tracker: the frame was sent, so the relay may
        // still answer, and a late `OK true` must settle it as Sent.
        let events = self.trackers.get(&msg_id)?.events.clone();
        self.queue.retain(|q| !events.contains(&q.event_id));
        self.timed_out.insert(msg_id.clone());
        Some((msg_id, Delivery::Failed))
    }

    fn fail(&mut self, msg_id: &str) -> Option<(String, Delivery)> {
        let t = self.finish(msg_id)?;
        // A failed message must not be published later by a reconnect flush.
        self.queue.retain(|q| !t.events.contains(&q.event_id));
        Some((msg_id.to_string(), Delivery::Failed))
    }

    fn finish(&mut self, msg_id: &str) -> Option<Tracker> {
        let t = self.trackers.remove(msg_id)?;
        for e in &t.events {
            self.by_event.remove(e);
            self.frames.remove(e);
            self.retried.remove(e);
            self.timers.remove(e);
        }
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn open_socket_sends_immediately_connecting_socket_queues() {
        let mut o = Outbox::default();
        o.set_authed(true);
        assert_eq!(o.submit("e1", s("F1"), true), Some(s("F1")));
        assert_eq!(o.submit("e2", s("F2"), false), None);
        assert_eq!(o.submit("e3", s("F3"), false), None);
        assert_eq!(o.queued_len(), 2);
    }

    #[test]
    fn queued_frames_flush_in_order_on_open() {
        let mut o = Outbox::default();
        o.submit("e2", s("F2"), false);
        o.submit("e3", s("F3"), false);
        assert_eq!(o.drain(), vec![s("F2"), s("F3")]);
        assert!(o.drain().is_empty());
    }

    #[test]
    fn message_is_sent_only_when_every_copy_is_acked() {
        let mut o = Outbox::default();
        o.track("m1", &[s("self"), s("rcpt")]);
        assert_eq!(o.on_ok("self", true, ""), None);
        assert_eq!(o.on_ok("rcpt", true, ""), Some((s("m1"), Delivery::Sent)));
    }

    #[test]
    fn ok_false_marks_failed_and_later_acks_are_ignored() {
        let mut o = Outbox::default();
        o.track("m1", &[s("self"), s("rcpt")]);
        assert_eq!(
            o.on_ok("self", false, ""),
            Some((s("m1"), Delivery::Failed))
        );
        assert_eq!(o.on_ok("rcpt", true, ""), None);
        assert_eq!(o.on_timeout("rcpt"), None);
    }

    #[test]
    fn timeout_marks_failed_and_purges_queued_frames() {
        let mut o = Outbox::default();
        o.track("m1", &[s("self"), s("rcpt")]);
        o.submit("self", s("FS"), false);
        o.submit("rcpt", s("FR"), false);
        o.submit("other", s("FO"), false);
        assert_eq!(o.on_timeout("self"), Some((s("m1"), Delivery::Failed)));
        // A failed message must not be resurrected by a later reconnect.
        assert_eq!(o.drain(), vec![s("FO")]);
    }

    #[test]
    fn timeout_after_ack_is_a_noop() {
        let mut o = Outbox::default();
        o.track("m1", &[s("self"), s("rcpt")]);
        o.on_ok("self", true, "");
        o.on_ok("rcpt", true, "");
        assert_eq!(o.on_timeout("self"), None);
    }

    #[test]
    fn open_but_unauthed_stays_queued_until_authed() {
        let mut o = Outbox::default();
        assert_eq!(o.submit("e1", s("F1"), true), None);
        assert!(o.flush(true).is_empty(), "no flush before AUTH completes");
        o.set_authed(true);
        assert!(o.flush(false).is_empty(), "no flush on a closed socket");
        assert_eq!(o.flush(true), vec![s("F1")]);
    }

    #[test]
    fn auth_required_requeues_once_then_fails() {
        let mut o = Outbox::default();
        o.track("m1", &[s("e1")]);
        o.set_authed(true);
        assert_eq!(o.submit("e1", s("F1"), true), Some(s("F1")));
        // The relay disagrees about being authed: refuse, re-queue once.
        o.set_authed(false);
        assert_eq!(o.on_ok("e1", false, "auth-required: sign in"), None);
        assert_eq!(o.queued_len(), 1);
        assert!(o.flush(true).is_empty());
        o.set_authed(true);
        assert_eq!(o.flush(true), vec![s("F1")]);
        assert_eq!(
            o.on_ok("e1", false, "auth-required: sign in"),
            Some((s("m1"), Delivery::Failed))
        );
        assert_eq!(o.queued_len(), 0);
    }

    #[test]
    fn other_refusals_fail_immediately() {
        let mut o = Outbox::default();
        o.track("m1", &[s("e1")]);
        o.submit("e1", s("F1"), false);
        assert_eq!(
            o.on_ok("e1", false, "blocked: nope"),
            Some((s("m1"), Delivery::Failed))
        );
    }

    #[test]
    fn close_unauthenticates_and_enters_reconnecting() {
        let mut o = Outbox::default();
        let mut r = Reconnect::default();
        o.set_authed(true);
        r.on_close(&mut o, 0.0);
        assert!(!o.is_authed());
        assert!(r.is_reconnecting());
        // A send while down is held, not sent into the dead socket.
        assert_eq!(o.submit("e1", s("F1"), false), None);
    }

    #[test]
    fn backoff_doubles_to_the_cap_with_bounded_jitter() {
        let seq: Vec<u32> = (0..8).map(|a| reconnect_delay_ms(a, 0.0)).collect();
        assert_eq!(
            seq,
            vec![1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]
        );
        assert_eq!(reconnect_delay_ms(2, 1.0), 3_000);
        assert_eq!(reconnect_delay_ms(40, 0.5), 26_250);
        assert!(reconnect_delay_ms(0, 7.0) >= 750, "jitter is clamped");
        let mut o = Outbox::default();
        let mut r = Reconnect::default();
        assert_eq!(r.on_close(&mut o, 0.0), 1_000);
        assert_eq!(r.on_close(&mut o, 0.0), 2_000);
    }

    #[test]
    fn reopen_resets_backoff_and_flushes_only_after_auth() {
        let mut o = Outbox::default();
        let mut r = Reconnect::default();
        r.on_close(&mut o, 0.0);
        r.on_close(&mut o, 0.0);
        o.submit("e1", s("F1"), false);
        r.on_open();
        assert!(!r.is_reconnecting());
        assert!(o.flush(true).is_empty(), "open but not yet re-authed");
        o.set_authed(true);
        assert_eq!(o.flush(true), vec![s("F1")]);
        assert_eq!(r.on_close(&mut o, 0.0), 1_000, "backoff restarted");
    }

    #[test]
    fn queued_frame_is_not_failed_by_an_ack_timer_it_never_had() {
        let mut o = Outbox::default();
        o.track("m1", &[s("e1")]);
        // Socket down (e.g. 30 s backoff): queued, so no timer is armed.
        assert_eq!(o.submit("e1", s("F1"), false), None);
        assert_eq!(o.on_timer("e1", 1), None);
        assert_eq!(o.queued_len(), 1, "frame survives for the reopen flush");
        o.set_authed(true);
        let sent = o.flush_with_ids(true);
        assert_eq!(sent, vec![(s("e1"), s("F1"))]);
        // The timer starts only now that the frame has left.
        let tok = o.arm_timer("e1");
        assert_eq!(o.on_timer("e1", tok), Some((s("m1"), Delivery::Failed)));
    }

    #[test]
    fn late_ok_after_timeout_settles_as_sent() {
        let mut o = Outbox::default();
        o.track("m1", &[s("self"), s("rcpt")]);
        let ts = o.arm_timer("self");
        let tr = o.arm_timer("rcpt");
        assert_eq!(o.on_timer("self", ts), Some((s("m1"), Delivery::Failed)));
        assert_eq!(o.on_timer("rcpt", tr), None, "already failed once");
        assert_eq!(o.on_ok("self", true, ""), None);
        assert_eq!(o.on_ok("rcpt", true, ""), Some((s("m1"), Delivery::Sent)));
        assert_eq!(o.on_ok("rcpt", true, ""), None, "settled once, no repeat");
    }

    #[test]
    fn late_refusal_keeps_failed_and_stale_timers_are_ignored() {
        let mut o = Outbox::default();
        o.track("m1", &[s("e1")]);
        let old = o.arm_timer("e1");
        let new = o.arm_timer("e1");
        assert_eq!(o.on_timer("e1", old), None, "superseded timer");
        assert_eq!(o.on_timer("e1", new), Some((s("m1"), Delivery::Failed)));
        assert_eq!(o.on_ok("e1", false, "blocked: x"), None);
    }

    #[test]
    fn rekey_follows_the_message() {
        let mut o = Outbox::default();
        o.track("m1", &[s("e")]);
        assert_eq!(o.on_ok("e", true, ""), Some((s("m1"), Delivery::Sent)));
    }
}
