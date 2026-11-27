//! Where each copy of a sent DM goes, and what the user is told about it
//! (ADR-2027 decision 1; nostr.chat profile section 3.3).
//!
//! Pure functions: the plan for a recipient, and the fold from per-relay
//! acknowledgements to the single outcome shown on the message. The publishing
//! itself lives in [`super`]; keeping the decisions here makes them testable
//! without a socket.

use nostr::RelayUrl;

use super::routing::Route;

/// What a send achieved, as shown on the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Every relay the recipient's copy was addressed to acknowledged it, and
    /// so did our own copy.
    Sent,
    /// At least one relay acknowledged the recipient's copy and at least one
    /// attempt failed.
    Partial,
    /// No relay acknowledged the recipient's copy: the message did not reach
    /// them, however it looks on our screen.
    Failed,
}

/// One relay's answer to one publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The relay's URL, for the log and the tooltip.
    pub relay: String,
    /// The relay's `OK` flag; `false` also stands for "never answered".
    pub accepted: bool,
    /// The relay's message, or `"timeout"`.
    pub reason: String,
}

impl Attempt {
    /// An acknowledged publish.
    pub fn ok(relay: &str) -> Self {
        Self {
            relay: relay.to_string(),
            accepted: true,
            reason: String::new(),
        }
    }

    /// A refused or unanswered publish.
    pub fn failed(relay: &str, reason: &str) -> Self {
        Self {
            relay: relay.to_string(),
            accepted: false,
            reason: reason.to_string(),
        }
    }
}

/// Where the recipient's copy is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Whether our own relay gets the recipient's copy.
    pub to_ours: bool,
    /// The recipient's foreign relays that do.
    pub foreign: Vec<RelayUrl>,
}

impl Plan {
    /// Nothing to publish to: the recipient cannot be reached from here.
    pub fn is_empty(&self) -> bool {
        !self.to_ours && self.foreign.is_empty()
    }
}

/// Plan the recipient's copy.
///
/// Our relay takes it only for a member: its gift-wrap gate refuses a wrap whose
/// recipient is not whitelisted, so sending one is a guaranteed refusal. The
/// foreign relays are always used, and never consult the whitelist.
pub fn plan(route: &Route, recipient_is_member: bool) -> Plan {
    Plan {
        to_ours: recipient_is_member,
        foreign: route.foreign.clone(),
    }
}

/// Which of the two wraps a publish carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Copy {
    /// The sender's own copy, the only one they can read back after a reload.
    Own,
    /// The copy addressed to the recipient.
    Recipient,
}

/// Where a publish goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Our own relay.
    Ours,
    /// A relay the recipient named.
    Foreign(RelayUrl),
}

/// One publish: a copy, to a target.
pub type Step = (Copy, Target);

/// The order of publishes for the extended send. The sender's own copy on our
/// relay is ALWAYS first, so a sent message is recoverable after a reload even
/// when every later publish fails; then the recipient's copy to our relay (a
/// member only) and to each foreign relay.
pub fn send_order(plan: &Plan) -> Vec<Step> {
    let mut steps = vec![(Copy::Own, Target::Ours)];
    if plan.to_ours {
        steps.push((Copy::Recipient, Target::Ours));
    }
    steps.extend(
        plan.foreign
            .iter()
            .map(|u| (Copy::Recipient, Target::Foreign(u.clone()))),
    );
    steps
}

/// The order of publishes for the plain single-relay send: own copy first.
pub fn plain_order() -> [Copy; 2] {
    [Copy::Own, Copy::Recipient]
}

/// Whether a relay's refusal text is the recipient gate saying "not a member".
///
/// That is an expected answer for an outsider, not a failure to report.
/// Matched on the relay's fixed phrase (`blocked: gift-wrap recipient not
/// whitelisted`), case-insensitively.
pub fn is_non_member_refusal(reason: &str) -> bool {
    reason.to_ascii_lowercase().contains("not whitelisted")
}

/// The reason shown when a plan has no recipient target at all.
pub const NO_ROUTE: &str = "no route to recipient";

/// Fold the acknowledgements into the outcome shown on the message.
///
/// `to_recipient` holds the attempts at the recipient's copy, `own_copy` the
/// attempts at the sender's self-copy. A refusal of the recipient's copy by our
/// own relay for being a non-member ([`is_non_member_refusal`]) is dropped
/// first: it was an expected skip.
///
/// * No accepted self-copy, including no attempt at all, is [`Delivery::Failed`]:
///   without a recoverable backup the message is not "sent" however far the
///   recipient's copy got.
/// * No accepted recipient copy, including no attempts at all, is
///   [`Delivery::Failed`]. An empty slice never counts as "all acknowledged".
/// * Every remaining attempt accepted, both copies, is [`Delivery::Sent`].
/// * Anything between is [`Delivery::Partial`].
pub fn fold(to_recipient: &[Attempt], own_copy: &[Attempt]) -> Delivery {
    if !own_copy.iter().any(|a| a.accepted) {
        return Delivery::Failed;
    }
    let counted: Vec<&Attempt> = to_recipient
        .iter()
        .filter(|a| a.accepted || !is_non_member_refusal(&a.reason))
        .collect();
    if !counted.iter().any(|a| a.accepted) {
        return Delivery::Failed;
    }
    if counted.iter().all(|a| a.accepted) && own_copy.iter().all(|a| a.accepted) {
        Delivery::Sent
    } else {
        Delivery::Partial
    }
}

/// Whether the send may continue past the own copy: only when our relay
/// acknowledged it. Otherwise nothing is sent to the recipient, because a
/// message that reaches them but cannot be recovered by its author is worse
/// than one that visibly failed.
pub fn own_copy_stored(own: &Attempt) -> bool {
    own.accepted
}

/// The text of the one-time confirmation before the first foreign publish.
pub const CONSENT_TEXT: &str = "Replying connects directly to relays chosen by this person. \
Their operators can see your IP address and connection time. \
Message contents remain encrypted.";

/// Whether the member must confirm before foreign sockets open: the recipient
/// is not a member (so the relays are a stranger's choice), there is at least
/// one foreign relay, and they have not accepted for this recipient before.
pub fn consent_needed(recipient_is_member: bool, foreign: &[RelayUrl], accepted: bool) -> bool {
    !recipient_is_member && !foreign.is_empty() && !accepted
}

/// The steps that may run now. When consent is needed and not given, every
/// foreign step is withheld, so no foreign socket can open.
pub fn release_steps(order: &[Step], consent_required: bool, consent_given: bool) -> Vec<Step> {
    order
        .iter()
        .filter(|(_, t)| !(matches!(t, Target::Foreign(_)) && consent_required && !consent_given))
        .cloned()
        .collect()
}

/// Host names of the foreign relays, for the confirmation text.
pub fn hosts(foreign: &[RelayUrl]) -> Vec<String> {
    foreign
        .iter()
        .filter_map(|u| u.host().map(|h| h.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::routing::{resolve, KIND_DM_RELAYS};
    use super::*;

    use crate::dm::routing::{signed, test_pubkey};

    const BOB: u8 = 7;

    fn route_with(relays: &[&str]) -> Route {
        let ev = signed(
            KIND_DM_RELAYS,
            BOB,
            1,
            relays
                .iter()
                .map(|r| vec!["relay".to_string(), r.to_string()])
                .collect(),
        );
        resolve("wss://ours.example.com", &test_pubkey(BOB), &[ev])
    }

    #[test]
    fn a_member_recipient_copy_goes_to_our_relay_and_theirs() {
        let p = plan(&route_with(&["wss://theirs.example.com"]), true);
        assert!(p.to_ours);
        assert_eq!(p.foreign.len(), 1);
    }

    #[test]
    fn a_non_member_recipient_copy_skips_our_relay() {
        let p = plan(&route_with(&["wss://theirs.example.com"]), false);
        assert!(!p.to_ours);
        assert_eq!(p.foreign.len(), 1);
        assert!(!p.is_empty());
    }

    #[test]
    fn a_non_member_with_no_inbox_list_has_nowhere_to_go() {
        let p = plan(&route_with(&[]), false);
        assert!(p.is_empty());
        assert_eq!(fold(&[], &[Attempt::ok("ours")]), Delivery::Failed);
        // A plan with no recipient target at all is the same case.
        assert!(send_order(&p).len() == 1 && NO_ROUTE == "no route to recipient");
    }

    #[test]
    fn an_empty_own_copy_slice_is_not_vacuously_sent() {
        assert_eq!(fold(&[Attempt::ok("theirs")], &[]), Delivery::Failed);
    }

    #[test]
    fn a_refused_own_copy_is_failed_even_if_the_recipient_copy_landed() {
        let own = Attempt::failed("ours", "timeout");
        assert!(!own_copy_stored(&own));
        assert!(own_copy_stored(&Attempt::ok("ours")));
        assert_eq!(fold(&[Attempt::ok("theirs")], &[own]), Delivery::Failed);
    }

    #[test]
    fn consent_is_needed_only_for_a_non_member_with_foreign_relays_not_yet_accepted() {
        let r = route_with(&["wss://a.example.com"]);
        assert!(consent_needed(false, &r.foreign, false));
        assert!(!consent_needed(false, &r.foreign, true));
        assert!(!consent_needed(true, &r.foreign, false));
        assert!(!consent_needed(false, &[], false));
        assert_eq!(hosts(&r.foreign), ["a.example.com"]);
        assert!(CONSENT_TEXT.starts_with(
            "Replying connects directly to relays chosen by this person. Their operators"
        ));
        assert!(CONSENT_TEXT.ends_with("Message contents remain encrypted."));
    }

    #[test]
    fn no_foreign_step_is_released_before_consent() {
        let p = plan(
            &route_with(&["wss://a.example.com", "wss://b.example.com"]),
            false,
        );
        let order = send_order(&p);
        let before = release_steps(&order, true, false);
        assert!(before.iter().all(|(_, t)| !matches!(t, Target::Foreign(_))));
        assert_eq!(before[0], (Copy::Own, Target::Ours));
        let after = release_steps(&order, true, true);
        assert_eq!(after.len(), 3);
        // No consent needed (a member): everything is released.
        assert_eq!(release_steps(&order, false, false).len(), 3);
    }

    #[test]
    fn the_own_copy_is_published_before_any_recipient_copy() {
        let plan = plan(
            &route_with(&["wss://a.example.com", "wss://b.example.com"]),
            true,
        );
        let order = send_order(&plan);
        assert_eq!(order[0], (Copy::Own, Target::Ours));
        assert_eq!(order.len(), 4);
        assert!(order[1..].iter().all(|(c, _)| *c == Copy::Recipient));
        // Even with nowhere to send the recipient's copy, ours still goes.
        let none = super::plan(&route_with(&[]), false);
        assert_eq!(send_order(&none), vec![(Copy::Own, Target::Ours)]);
        assert_eq!(plain_order()[0], Copy::Own);
    }

    #[test]
    fn all_acknowledged_is_sent() {
        let r = [Attempt::ok("ours"), Attempt::ok("theirs")];
        assert_eq!(fold(&r, &[Attempt::ok("ours")]), Delivery::Sent);
    }

    #[test]
    fn one_of_two_relays_failing_is_partial() {
        let r = [Attempt::ok("ours"), Attempt::failed("theirs", "timeout")];
        assert_eq!(fold(&r, &[Attempt::ok("ours")]), Delivery::Partial);
    }

    #[test]
    fn zero_acknowledgements_is_failed_never_sent() {
        let r = [
            Attempt::failed("ours", "error: boom"),
            Attempt::failed("theirs", "timeout"),
        ];
        assert_eq!(fold(&r, &[Attempt::ok("ours")]), Delivery::Failed);
        assert_eq!(fold(&[], &[]), Delivery::Failed);
    }

    #[test]
    fn the_non_member_refusal_is_an_expected_skip_not_a_failure() {
        let refusal = Attempt::failed("ours", "blocked: gift-wrap recipient not whitelisted");
        assert_eq!(
            fold(
                &[refusal.clone(), Attempt::ok("theirs")],
                &[Attempt::ok("ours")]
            ),
            Delivery::Sent
        );
        // Refused by the gate and nowhere else to go: still a failure.
        assert_eq!(fold(&[refusal], &[Attempt::ok("ours")]), Delivery::Failed);
    }

    #[test]
    fn a_lost_self_copy_is_failed_not_partial() {
        let r = [Attempt::ok("theirs")];
        assert_eq!(
            fold(&r, &[Attempt::failed("ours", "timeout")]),
            Delivery::Failed
        );
    }
}
