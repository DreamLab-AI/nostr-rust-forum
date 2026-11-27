//! Where a freshly opened topic lands: at the newest post (or a deep-linked
//! one), held there while late batches of history, keys and media arrive,
//! until the reader takes over or a ceiling passes.
//!
//! Pure state; each client supplies the scrolling (the forum scrolls the
//! window, the BBS its content pane).

/// Hard ceiling on the landing phase, counted from the first pin, however
/// slowly history, keys or media arrive. Until then every growth (a reply
/// rendered, the layout resized) re-pins at once, whether or not a load is in
/// flight: on a cold load of a long encrypted topic the rest of the posts can
/// render many seconds after the first, with the relay's receipts long in
/// and zone keys still opening posts, so no quiet spell is evidence that the
/// topic has finished growing.
pub const LANDING_MAX_MS: f64 = 30_000.0;

/// Input this soon after landing starts is momentum carried over from the
/// previous page, not the reader taking control.
pub const LANDING_INPUT_GRACE_MS: f64 = 400.0;

/// Progress of the "open at the bottom" landing for one mount of the page.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Landing {
    /// When the first pin was scheduled (`0.0` = not started).
    pub started_at: f64,
    /// The ceiling passed or the reader took over: growth no longer pins.
    pub done: bool,
    /// The reader scrolled, tapped or typed: nothing moves them again.
    pub touched: bool,
    /// The ceiling passed while the topic's history was still loading: one
    /// final pin is owed when it settles, unless the reader touches the page.
    pub final_pin_owed: bool,
    /// Post to pin, and whether it is a `?focus=` deep link.
    pub target: Option<(String, bool)>,
    /// The focus outline has been flashed once.
    pub flashed: bool,
    /// The topic's history has finished loading (see [`history_settled`]).
    pub history_settled: bool,
}

impl Landing {
    /// Record growth at `now` and report whether the page should be
    /// re-pinned: always, until [`LANDING_MAX_MS`] after the first pin (the
    /// first call with a target starts the phase) or the reader's input.
    pub fn grow(&mut self, now: f64) -> bool {
        if self.done || self.target.is_none() {
            return false;
        }
        if self.started_at == 0.0 {
            self.started_at = now;
        }
        if now - self.started_at > LANDING_MAX_MS {
            self.done = true;
            self.final_pin_owed = !self.history_settled && !self.touched;
            return false;
        }
        true
    }

    /// Record whether the topic's history has settled, and report
    /// whether this is the moment for the one final pin owed by a ceiling
    /// that passed while it was still loading.
    pub fn note_history(&mut self, settled: bool) -> bool {
        let newly = settled && !self.history_settled;
        self.history_settled = settled;
        if newly && self.final_pin_owed && !self.touched {
            self.final_pin_owed = false;
            return true;
        }
        false
    }

    /// Whether a scheduled pin may still move the page (`final_pin`: the
    /// one owed when history settles after the ceiling).
    pub fn may_pin(&self, final_pin: bool) -> bool {
        if final_pin {
            !self.touched
        } else {
            !self.done
        }
    }

    /// The reader scrolled, tapped or pressed a key at `now`.
    pub fn reader_input(&mut self, now: f64) {
        if self.started_at > 0.0 && now - self.started_at > LANDING_INPUT_GRACE_MS {
            self.done = true;
            self.touched = true;
            self.final_pin_owed = false;
        }
    }
}

/// Whether a topic's history has finished loading: the channel's history
/// query has its authoritative receipt (`channel_settles`, see
/// `SyncReceipt::settles`) and the topic's own list (`topic`, its cursor) has
/// answered its first page and has no page in flight.
pub fn history_settled(
    channel_settles: bool,
    topic: Option<&crate::stores::channels::HistoryCursor>,
) -> bool {
    channel_settles && topic.is_some_and(|c| c.started && !c.loading)
}

/// DOM id of a rendered post, for deep-link scrolling.
pub fn post_anchor_id(event_id: &str) -> String {
    format!("post-{}", event_id.to_lowercase())
}

/// Where a freshly opened topic should land: the `focus` post when it is the
/// root or one of the replies (`true` = focused), otherwise the newest reply.
/// `None` when there is nothing below the root to scroll to.
pub fn landing_target(
    focus: Option<&str>,
    root_id: &str,
    reply_ids: &[String],
) -> Option<(String, bool)> {
    if let Some(f) = focus.map(str::trim).filter(|f| !f.is_empty()) {
        if root_id.eq_ignore_ascii_case(f) {
            return Some((root_id.to_string(), true));
        }
        if let Some(id) = reply_ids.iter().find(|id| id.eq_ignore_ascii_case(f)) {
            return Some((id.clone(), true));
        }
        // Focus target not loaded (yet): fall through to the newest reply; the
        // effect re-runs as replies arrive and will pick the focus up.
    }
    reply_ids.last().map(|id| (id.clone(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landing_prefers_focus_then_newest_reply() {
        let replies = vec!["aa".to_string(), "bb".to_string(), "cc".to_string()];
        assert_eq!(
            landing_target(None, "root", &replies),
            Some(("cc".into(), false))
        );
        assert_eq!(
            landing_target(Some("BB"), "root", &replies),
            Some(("bb".into(), true))
        );
        assert_eq!(
            landing_target(Some("root"), "root", &replies),
            Some(("root".into(), true))
        );
        assert_eq!(
            landing_target(Some("zz"), "root", &replies),
            Some(("cc".into(), false))
        );
        assert_eq!(landing_target(Some(" "), "root", &[]), None);
        assert_eq!(landing_target(None, "root", &[]), None);
    }

    fn landing_to(target: &str) -> Landing {
        Landing {
            target: Some((target.into(), false)),
            ..Landing::default()
        }
    }

    #[test]
    fn landing_waits_for_a_target() {
        let mut l = Landing::default();
        assert!(!l.grow(1_000.0));
        assert_eq!(l.started_at, 0.0);
        assert!(!l.done);
    }

    #[test]
    fn landing_repins_while_the_topic_keeps_growing() {
        let mut l = landing_to("cc");
        assert!(l.grow(1_000.0));
        // Media keeps expanding posts every couple of seconds: each growth
        // extends the window past the first settle period.
        assert!(l.grow(3_000.0));
        assert!(l.grow(5_000.0));
        assert!(l.grow(7_000.0));
        assert!(!l.done);
    }

    #[test]
    fn cold_load_batch_after_a_long_quiet_repins_immediately() {
        // Staging timeline (11k-reply encrypted topic, no reader input):
        // 27 posts render and are pinned at ~7 s; the receipts are in (the
        // history reads as settled) while keys are still opening posts; at
        // 22.5 s 71 more posts render. They must re-pin at once.
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(7_000.0), "first batch pins");
        l.note_history(true);
        assert!(l.grow(22_500.0), "the late batch was not pinned");
        // ...and so does any later growth before the ceiling.
        assert!(l.grow(30_000.0));
        assert!(!l.done);
    }

    #[test]
    fn cold_load_batch_while_loading_repins_immediately() {
        // The same sequence with the load still in flight throughout.
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(7_000.0));
        assert!(l.grow(22_500.0));
        assert!(!l.done);
    }

    #[test]
    fn ceiling_counts_from_the_first_pin() {
        let mut l = landing_to("cc");
        l.note_history(true);
        assert!(l.grow(5_000.0));
        assert!(l.grow(5_000.0 + LANDING_MAX_MS - 1.0));
        assert!(!l.grow(5_000.0 + LANDING_MAX_MS + 1.0));
        assert!(l.done);
        // History already settled at the ceiling: nothing is owed.
        assert!(!l.note_history(true));
    }

    #[test]
    fn history_settling_after_the_ceiling_earns_one_final_pin() {
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(1_000.0));
        assert!(!l.grow(1_000.0 + LANDING_MAX_MS + 1.0));
        assert!(l.done);
        assert!(l.may_pin(true), "final pin allowed after the ceiling");
        assert!(!l.may_pin(false), "ordinary growth no longer pins");
        assert!(l.note_history(true), "one final pin");
        assert!(!l.note_history(true), "only one");
        assert!(!l.note_history(false));
        assert!(!l.note_history(true));
    }

    #[test]
    fn reader_input_cancels_the_final_pin() {
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(1_000.0));
        assert!(!l.grow(1_000.0 + LANDING_MAX_MS + 1.0));
        l.reader_input(40_000.0);
        assert!(!l.may_pin(true));
        assert!(!l.note_history(true));
    }

    #[test]
    fn landing_does_not_settle_while_history_is_loading() {
        // Cold load: 19 replies render, then nothing for 8 s while the rest
        // of the topic is still on its way.
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(1_000.0));
        assert!(l.grow(9_000.0), "a quiet spell mid-load ended the landing");
        assert!(!l.done);
    }

    #[test]
    fn reader_input_ends_landing_while_history_is_loading() {
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(1_000.0));
        l.reader_input(1_000.0 + LANDING_INPUT_GRACE_MS + 1.0);
        assert!(l.done);
        assert!(!l.grow(2_000.0));
    }

    #[test]
    fn unsettled_history_still_has_a_ceiling() {
        let mut l = landing_to("cc");
        l.note_history(false);
        assert!(l.grow(1_000.0));
        assert!(l.grow(1_000.0 + LANDING_MAX_MS - 1.0));
        assert!(!l.grow(1_000.0 + LANDING_MAX_MS + 1.0));
        assert!(l.done);
    }

    // The ceiling must outlast a cold load of a long topic.
    const _: () = assert!(LANDING_MAX_MS >= 30_000.0);

    #[test]
    fn history_settles_on_both_receipts() {
        use crate::stores::channels::HistoryCursor;
        let started = HistoryCursor {
            started: true,
            ..HistoryCursor::default()
        };
        let in_flight = HistoryCursor {
            started: true,
            loading: true,
            ..HistoryCursor::default()
        };
        let first_page_pending = HistoryCursor {
            loading: true,
            ..HistoryCursor::default()
        };
        assert!(history_settled(true, Some(&started)));
        assert!(!history_settled(false, Some(&started)));
        assert!(!history_settled(true, Some(&in_flight)));
        assert!(!history_settled(true, Some(&first_page_pending)));
        assert!(!history_settled(true, Some(&HistoryCursor::default())));
        assert!(!history_settled(true, None));
    }

    #[test]
    fn landing_has_a_hard_ceiling() {
        let mut l = landing_to("cc");
        let mut now = 1_000.0;
        assert!(l.grow(now));
        while now <= 1_000.0 + LANDING_MAX_MS {
            now += 1_000.0;
            l.grow(now);
        }
        assert!(l.done);
    }

    #[test]
    fn reader_input_ends_landing_after_the_grace() {
        let mut l = landing_to("cc");
        l.reader_input(500.0); // before start: ignored
        assert!(l.grow(1_000.0));
        l.reader_input(1_000.0 + LANDING_INPUT_GRACE_MS - 1.0); // momentum
        assert!(!l.done);
        l.reader_input(1_000.0 + LANDING_INPUT_GRACE_MS + 1.0);
        assert!(l.done);
        assert!(!l.grow(1_100.0 + LANDING_INPUT_GRACE_MS));
    }

    #[test]
    fn post_anchor_is_lowercase_and_prefixed() {
        assert_eq!(post_anchor_id("ABC"), "post-abc");
    }
}
