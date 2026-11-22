//! Found, still loading, or genuinely absent: the decision every deep-linked
//! forum page (zone, section, topic) makes before it may say "not found".
//!
//! The pages used to say "not found" as soon as `ChannelStore::loading`
//! cleared. That flag clears on the channel list's first EOSE (or a six-second
//! timer, or immediately when a channel cache exists), which says nothing about
//! whether the kind-42 history that holds a topic has been requested yet, let
//! alone delivered. A cold deep link therefore showed "Topic Not Found" for as
//! long as the message sync took.
//!
//! The rule here is the one [`super::bootstrap`] applies to the flat channel
//! view: absence is only reported on a *receipt* — the relay's EOSE for the
//! subscription that would have carried the thing — or once a bounded deadline
//! has passed. A thing that turns up after either still wins.
//!
//! One wrinkle is NIP-42. The relay answers a REQ from a socket that has not
//! yet authenticated with only what an anonymous reader may see, then the
//! client replays every subscription once AUTH completes. For a members-only
//! zone the first EOSE is therefore an anonymous answer, and an empty one is
//! not evidence of absence. [`SyncReceipt`] records whether an EOSE arrived on
//! an authenticated socket so [`SyncReceipt::settles`] can tell the two apart.
//!
//! Pure apart from [`arm_deadline`], so the decision unit-tests natively.

use leptos::prelude::*;

use crate::stores::zones::{resolve_zone_param, Zone, ZoneVisibility};

/// How long a deep-linked page waits for a receipt before it gives up and
/// reports the thing as unavailable. Generous because a NIP-07 extension can
/// take several seconds to sign the AUTH challenge, and gated-zone history
/// only arrives after that.
pub const LOOKUP_DEADLINE_MS: i32 = 15_000;

/// The relay's EOSE receipts for one subscription.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReceipt {
    /// At least one EOSE arrived.
    pub any: bool,
    /// At least one EOSE arrived while the socket was NIP-42 authenticated.
    pub authed: bool,
}

impl SyncReceipt {
    /// Record an EOSE that arrived while the socket's NIP-42 state was
    /// `authed`. Receipts only accumulate: a reconnect that drops AUTH does
    /// not un-deliver history the store already holds.
    pub fn record(&mut self, authed: bool) {
        self.any = true;
        self.authed |= authed;
    }

    /// Whether this receipt is evidence that the relay has sent everything
    /// the viewer may read. For a public zone any EOSE is; for a gated zone
    /// only one that arrived after AUTH, because the pre-AUTH answer omits
    /// members-only events by design.
    pub fn settles(self, zone_gated: bool) -> bool {
        if zone_gated {
            self.authed
        } else {
            self.any
        }
    }
}

/// What a deep-linked page should render for the thing its URL names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Not here yet and the relay has not finished answering: show the
    /// loading state.
    Loading,
    /// Present in the store.
    Found,
    /// The relay finished answering and it is not there.
    NotFound,
    /// No receipt arrived before [`LOOKUP_DEADLINE_MS`]. Reported separately
    /// from [`Lookup::NotFound`] so the page does not claim an absence it has
    /// not observed.
    TimedOut,
}

impl Lookup {
    /// Decide from what the page has observed. Presence beats everything, a
    /// receipt beats the clock, and only then does the deadline count — so a
    /// late arrival still resolves to [`Lookup::Found`].
    pub fn decide(found: bool, synced: bool, deadline_passed: bool) -> Self {
        if found {
            Lookup::Found
        } else if synced {
            Lookup::NotFound
        } else if deadline_passed {
            Lookup::TimedOut
        } else {
            Lookup::Loading
        }
    }

    /// Chain a nested lookup: the child (a topic) is only looked up once its
    /// parent (the section) has been found; any other parent state is the
    /// child's state too, since a topic cannot be found in a missing section.
    pub fn then(self, child: impl FnOnce() -> Lookup) -> Self {
        match self {
            Lookup::Found => child(),
            other => other,
        }
    }

    /// Whether the loading state is the honest thing to show.
    pub fn is_loading(self) -> bool {
        self == Lookup::Loading
    }
}

/// Whether the zone a `:category` URL param names withholds content from
/// anonymous readers. An unknown zone is treated as public: no section routes
/// to it, so waiting for an authenticated receipt would only delay a genuine
/// "not found".
pub fn zone_is_gated(category_param: &str, zones: &[Zone]) -> bool {
    resolve_zone_param(category_param, zones)
        .map(|z| z.visibility != ZoneVisibility::Public)
        .unwrap_or(false)
}

/// Start the page's [`LOOKUP_DEADLINE_MS`] clock and return the signal it
/// flips. `try_set` because the page may have unmounted (and disposed the
/// signal) by the time the timer fires.
pub fn arm_deadline() -> RwSignal<bool> {
    let passed = RwSignal::new(false);
    super::set_timeout_once(
        move || {
            let _ = passed.try_set(true);
        },
        LOOKUP_DEADLINE_MS,
    );
    passed
}

#[cfg(test)]
mod tests {
    use super::Lookup::*;
    use super::*;

    fn zone(id: &str, visibility: &str) -> Zone {
        serde_json::from_value(serde_json::json!({ "id": id, "visibility": visibility }))
            .expect("minimal zone parses")
    }

    #[test]
    fn absent_before_any_receipt_is_loading() {
        assert_eq!(Lookup::decide(false, false, false), Loading);
    }

    #[test]
    fn absent_after_receipt_is_not_found() {
        assert_eq!(Lookup::decide(false, true, false), NotFound);
    }

    #[test]
    fn absent_after_deadline_without_receipt_is_timed_out() {
        assert_eq!(Lookup::decide(false, false, true), TimedOut);
    }

    #[test]
    fn receipt_beats_the_deadline() {
        assert_eq!(Lookup::decide(false, true, true), NotFound);
    }

    #[test]
    fn presence_beats_receipt_and_deadline() {
        assert_eq!(Lookup::decide(true, false, false), Found);
        assert_eq!(Lookup::decide(true, true, false), Found);
        assert_eq!(Lookup::decide(true, false, true), Found);
        assert_eq!(Lookup::decide(true, true, true), Found);
    }

    #[test]
    fn nested_lookup_waits_for_its_parent() {
        let child_called = std::cell::Cell::new(false);
        let child = || {
            child_called.set(true);
            NotFound
        };
        assert_eq!(Loading.then(child), Loading);
        assert!(!child_called.get(), "child must not be judged early");
        assert_eq!(TimedOut.then(|| Found), TimedOut);
        assert_eq!(NotFound.then(|| Found), NotFound);
        assert_eq!(Found.then(|| Loading), Loading);
        assert_eq!(Found.then(|| NotFound), NotFound);
    }

    /// The reported bug: the section resolved, its topic history had not
    /// arrived, and the page said "not found" anyway.
    #[test]
    fn cold_topic_link_shows_loading_until_history_receipt() {
        let section = Lookup::decide(true, true, false);
        let topic = section.then(|| Lookup::decide(false, false, false));
        assert_eq!(topic, Loading);
        // History arrives with the topic in it.
        let topic = section.then(|| Lookup::decide(true, false, false));
        assert_eq!(topic, Found);
    }

    #[test]
    fn empty_receipt_records_nothing() {
        let r = SyncReceipt::default();
        assert!(!r.settles(false));
        assert!(!r.settles(true));
    }

    #[test]
    fn pre_auth_receipt_settles_public_but_not_gated() {
        let mut r = SyncReceipt::default();
        r.record(false);
        assert!(r.settles(false));
        assert!(
            !r.settles(true),
            "an anonymous EOSE omits members-only events"
        );
    }

    #[test]
    fn post_auth_receipt_settles_gated() {
        let mut r = SyncReceipt::default();
        r.record(false);
        r.record(true);
        assert!(r.settles(true));
        assert!(r.settles(false));
    }

    #[test]
    fn receipts_survive_a_later_unauthenticated_eose() {
        let mut r = SyncReceipt::default();
        r.record(true);
        r.record(false);
        assert!(r.settles(true));
    }

    #[test]
    fn zone_gating_follows_visibility() {
        let zones = vec![
            zone("welcome", "public"),
            zone("family", "locked"),
            zone("inner", "hidden"),
        ];
        assert!(!zone_is_gated("welcome", &zones));
        assert!(zone_is_gated("family", &zones));
        assert!(zone_is_gated("inner", &zones));
        assert!(!zone_is_gated("no-such-zone", &zones));
    }
}
