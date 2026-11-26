//! Alerts for the operator: what the house cannot fix by itself, said where
//! someone is watching.
//!
//! The table raises [`Effect::Alert`] for a halted payout debt or a producer
//! that keeps refusing a payout. The runner always prints it to stderr. When
//! the operator has configured an `alert_pubkey`, an [`Alerter`] also turns
//! it into one [`Effect::Dm`], a NIP-17 direct message the runner gift-wraps
//! (NIP-59) and publishes on the forum relay.
//!
//! Two limits keep an operator's inbox usable. An alert is said once per
//! debt and cause within a window ([`DEFAULT_WINDOW_SECS`]), however often
//! the table raises it, and at most [`DEFAULT_MAX_PER_WINDOW`] alerts leave
//! in one window at all. A suppressed alert still reaches stderr.

use std::collections::HashMap;

use crate::table::Effect;

/// How long an alert for one debt and cause is not repeated, seconds.
pub const DEFAULT_WINDOW_SECS: u64 = 6 * 60 * 60;

/// The most alerts sent in one window, over every debt and cause.
pub const DEFAULT_MAX_PER_WINDOW: usize = 20;

/// Why the house is alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertCause {
    /// A payout debt is halted: no payout is signed until an operator pays
    /// the member on-chain.
    Halted,
    /// The producer keeps refusing a payout.
    Refused,
    /// The startup summary of the debts that are halted.
    Summary,
}

impl AlertCause {
    /// The cause as a short word.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertCause::Halted => "halted",
            AlertCause::Refused => "refused",
            AlertCause::Summary => "summary",
        }
    }
}

/// Something an operator must look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The hand root of the debt it is about; empty for a summary.
    pub debt: String,
    /// Why it was raised.
    pub cause: AlertCause,
    /// What to tell the operator.
    pub text: String,
}

impl Alert {
    /// An alert about the debt for hand `debt`.
    pub fn new(debt: impl Into<String>, cause: AlertCause, text: impl Into<String>) -> Self {
        Alert {
            debt: debt.into(),
            cause,
            text: text.into(),
        }
    }

    /// The startup summary of `halted` debts (hand root and why), or `None`
    /// when none is halted.
    ///
    /// ```
    /// use nostr_bbs_poker_citizen::alert::Alert;
    /// assert!(Alert::summary(&[]).is_none());
    /// let a = Alert::summary(&[("ab".repeat(32), "rejected twice".into())]).unwrap();
    /// assert!(a.text.contains("1 halted"));
    /// ```
    pub fn summary(halted: &[(String, String)]) -> Option<Alert> {
        if halted.is_empty() {
            return None;
        }
        let mut text = format!(
            "{} halted payout debt(s) at startup; each holds back its amount from new buy-ins until you pay the member on-chain with the memo hand:<root>.",
            halted.len()
        );
        for (root, why) in halted {
            text.push_str(&format!("\n- hand {}…: {why}", &root[..root.len().min(12)]));
        }
        Some(Alert::new("", AlertCause::Summary, text))
    }
}

/// Decides which alerts become a direct message.
#[derive(Debug, Clone)]
pub struct Alerter {
    to: Option<String>,
    window_secs: u64,
    max_per_window: usize,
    /// When each debt and cause was last sent.
    sent: HashMap<(String, AlertCause), u64>,
}

impl Alerter {
    /// An alerter that sends to `to` (a 64-hex pubkey), or only to stderr
    /// when there is none, with the default limits.
    pub fn new(to: Option<String>) -> Self {
        Self::with_limits(to, DEFAULT_WINDOW_SECS, DEFAULT_MAX_PER_WINDOW)
    }

    /// [`Alerter::new`] with the window and the cap chosen.
    pub fn with_limits(to: Option<String>, window_secs: u64, max_per_window: usize) -> Self {
        Alerter {
            to,
            window_secs,
            max_per_window,
            sent: HashMap::new(),
        }
    }

    /// Whether alerts are sent anywhere beyond stderr.
    pub fn is_configured(&self) -> bool {
        self.to.is_some()
    }

    /// The direct message for `alert`, if one is due at `now`: none without
    /// a configured key, none when the same debt and cause went out within
    /// the window, none once the window's cap is spent.
    ///
    /// ```
    /// use nostr_bbs_poker_citizen::alert::{Alert, AlertCause, Alerter};
    /// let a = Alert::new("r1", AlertCause::Halted, "halted");
    /// let mut on = Alerter::new(Some("ab".repeat(32)));
    /// assert!(on.route(&a, 100).is_some());
    /// assert!(on.route(&a, 101).is_none(), "once per debt and cause");
    /// let mut off = Alerter::new(None);
    /// assert!(off.route(&a, 100).is_none(), "no key: stderr only");
    /// ```
    pub fn route(&mut self, alert: &Alert, now: u64) -> Option<Effect> {
        let to = self.to.clone()?;
        self.sent
            .retain(|_, at| now.saturating_sub(*at) < self.window_secs);
        let key = (alert.debt.clone(), alert.cause);
        if self.sent.contains_key(&key) || self.sent.len() >= self.max_per_window {
            return None;
        }
        self.sent.insert(key, now);
        Some(Effect::Dm {
            to,
            text: format!("[poker-citizen {}] {}", alert.cause.as_str(), alert.text),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: &str = "ab";

    fn op() -> String {
        OP.repeat(32)
    }

    fn halted(root: &str) -> Alert {
        Alert::new(root, AlertCause::Halted, format!("HALTED hand {root}"))
    }

    fn dms(e: &[Option<Effect>]) -> usize {
        e.iter()
            .filter(|e| matches!(e, Some(Effect::Dm { .. })))
            .count()
    }

    #[test]
    fn one_dm_per_debt_and_cause_within_the_window() {
        let mut a = Alerter::new(Some(op()));
        let first = a.route(&halted("r1"), 1_000);
        match &first {
            Some(Effect::Dm { to, text }) => {
                assert_eq!(*to, op());
                assert!(text.contains("HALTED hand r1") && text.contains("halted"));
            }
            other => panic!("expected a DM, got {other:?}"),
        }
        let repeats: Vec<_> = (1..50)
            .map(|i| a.route(&halted("r1"), 1_000 + i * 60))
            .collect();
        assert_eq!(dms(&repeats), 0, "the same debt and cause is said once");
        // another debt, and another cause for the same debt, are separate
        assert!(a.route(&halted("r2"), 1_001).is_some());
        let refused = Alert::new("r1", AlertCause::Refused, "refused 5 times");
        assert!(a.route(&refused, 1_002).is_some());
        assert!(a.route(&refused, 1_003).is_none());
    }

    #[test]
    fn the_same_alert_is_said_again_after_the_window() {
        let mut a = Alerter::with_limits(Some(op()), 600, 10);
        assert!(a.route(&halted("r1"), 0).is_some());
        assert!(a.route(&halted("r1"), 599).is_none());
        assert!(a.route(&halted("r1"), 600).is_some());
    }

    #[test]
    fn no_alert_key_means_stderr_only() {
        let mut a = Alerter::new(None);
        assert!(!a.is_configured());
        for i in 0..5 {
            assert!(a.route(&halted("r1"), i).is_none());
        }
    }

    #[test]
    fn a_flood_of_distinct_debts_is_capped_and_recovers() {
        let mut a = Alerter::with_limits(Some(op()), 100, 3);
        let sent: Vec<_> = (0..10)
            .map(|i| a.route(&halted(&format!("r{i}")), 10))
            .collect();
        assert_eq!(dms(&sent), 3);
        assert!(a.route(&halted("r99"), 111).is_some(), "the window passed");
    }

    #[test]
    fn the_startup_summary_names_each_halted_debt_once() {
        assert!(Alert::summary(&[]).is_none());
        let s = Alert::summary(&[
            ("a".repeat(64), "rejected twice".into()),
            ("b".repeat(64), "replaced too often".into()),
        ])
        .unwrap();
        assert_eq!(s.cause, AlertCause::Summary);
        assert!(s.text.contains("2 halted") && s.text.contains("rejected twice"));
        assert!(s.text.contains("hand:<root>"));
        let mut a = Alerter::new(Some(op()));
        assert!(a.route(&s, 5).is_some());
        assert!(a.route(&s, 6).is_none());
    }
}
