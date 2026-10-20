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
        let pending = self
            .trackers
            .get(&msg_id)
            .is_some_and(|t| t.remaining.contains(event_id));
        if pending {
            self.fail(&msg_id)
        } else {
            None
        }
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
    fn rekey_follows_the_message() {
        let mut o = Outbox::default();
        o.track("m1", &[s("e")]);
        assert_eq!(o.on_ok("e", true, ""), Some((s("m1"), Delivery::Sent)));
    }
}
