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
//! not evidence of absence. [`SyncReceipt`] records whether an EOSE was an
//! authenticated answer — decided by the relay layer's per-subscription REQ
//! ledger (`relay::receipt`), not by the socket's state when the EOSE lands —
//! so [`SyncReceipt::settles`] can tell the two apart.
//!
//! Pure apart from [`deadline_for`], which only drives the pure
//! [`DeadlineClock`] from a timer, so the decision unit-tests
//! natively.

use leptos::prelude::*;

use crate::stores::zones::{resolve_zone_param, Zone, ZoneVisibility};
use crate::zone_crypto::grant_backlog::KeyPhase;

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
    /// At least one EOSE was an authenticated answer: every REQ sent for the
    /// subscription had been answered and the latest went out after the
    /// relay accepted our NIP-42 AUTH.
    pub authed: bool,
}

impl SyncReceipt {
    /// Record an EOSE; `authed` is the relay ledger's verdict on it. Receipts only accumulate: a reconnect that drops AUTH does
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
    /// The relay has answered, but in an encrypted zone the member's zone
    /// keys are still arriving (the grant backlog is moving), so the thing
    /// may yet appear when a key opens it. Shown as loading, with copy that
    /// says keys are on their way rather than blaming the connection.
    KeysLoading,
    /// The relay answered but the member's zone keys stopped arriving (no
    /// progress within the stall window, or the overall cap). Distinct from
    /// [`Lookup::TimedOut`], which means no relay answer arrived at all.
    KeysTimedOut,
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
        matches!(self, Lookup::Loading | Lookup::KeysLoading)
    }

    /// Decide for a channel whose posts may need zone keys to recognise.
    /// Identical to [`Lookup::decide`] while the relay has not answered (the
    /// no-answer path keeps its deadline and connection copy) and in a zone
    /// that needs no keys; otherwise "absent" waits on the keys:
    /// still arriving reads as [`Lookup::KeysLoading`], stopped as
    /// [`Lookup::KeysTimedOut`], settled as [`Lookup::NotFound`].
    pub fn decide_with_keys(
        found: bool,
        relay_answered: bool,
        keys: KeyState,
        deadline_passed: bool,
    ) -> Self {
        if found {
            return Lookup::Found;
        }
        if !relay_answered {
            return Lookup::decide(false, false, deadline_passed);
        }
        match keys {
            KeyState::NotNeeded | KeyState::Settled => Lookup::NotFound,
            KeyState::Pending | KeyState::Progressing { .. } => Lookup::KeysLoading,
            KeyState::Stalled => Lookup::KeysTimedOut,
        }
    }
}

/// Where the signed-in member's zone keys stand, as far as a page in this
/// zone cares.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyState {
    /// The zone is not encrypted (or nothing here can decrypt): keys do not
    /// bear on whether something is absent.
    NotNeeded,
    /// Every key this member will get has arrived. A member who holds no key
    /// for the zone settles too, and sees the locked posts.
    Settled,
    /// The grant sync has not started yet (stored keys loading, relay AUTH
    /// in progress). Bounded by the page's ordinary deadline.
    Pending,
    /// The grant backlog is moving; look again at `until` (epoch ms).
    Progressing {
        /// When the stall window or cap next needs checking.
        until: f64,
    },
    /// The grant backlog stopped moving, hit its cap, or never started
    /// before the page deadline.
    Stalled,
}

/// Fold the zone-key store's view into a [`KeyState`]. `phase` is `None`
/// until the grant sync has started for the member.
pub fn key_state(encrypted: bool, phase: Option<KeyPhase>, deadline_passed: bool) -> KeyState {
    if !encrypted {
        return KeyState::NotNeeded;
    }
    match phase {
        Some(KeyPhase::Settled) => KeyState::Settled,
        Some(KeyPhase::Progressing { until }) => KeyState::Progressing { until },
        Some(KeyPhase::Stalled) => KeyState::Stalled,
        None if deadline_passed => KeyState::Stalled,
        None => KeyState::Pending,
    }
}

/// A [`KeyState`] memo that re-evaluates itself when a moving backlog's
/// stall window or cap comes due, since nothing else changes at that moment.
/// `phase` reads the zone-key store at the given time (epoch ms).
pub fn key_state_memo(
    encrypted: impl Fn() -> bool + Send + Sync + 'static,
    phase: impl Fn(f64) -> Option<KeyPhase> + Send + Sync + 'static,
    deadline: Signal<bool>,
) -> Memo<KeyState> {
    let tick = RwSignal::new(0u64);
    let pending = StoredValue::new(false);
    let keys = Memo::new(move |_| {
        tick.track();
        key_state(encrypted(), phase(js_sys::Date::now()), deadline.get())
    });
    Effect::new(move |_| {
        // Tracks the tick too, so a timer that fired early (the backlog moved
        // on meanwhile) re-arms for the new `until` even when the state reads
        // the same as before.
        tick.track();
        let KeyState::Progressing { until } = keys.get() else {
            return;
        };
        if pending.try_get_value().unwrap_or(true) {
            return;
        }
        pending.set_value(true);
        let delay = (until - js_sys::Date::now()).max(0.0) as i32 + 50;
        super::set_timeout_once(
            move || {
                let _ = pending.try_set_value(false);
                let _ = tick.try_update(|t| *t = t.wrapping_add(1));
            },
            delay,
        );
    });
    keys
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

/// Whether the zone a `:category` URL param names is encrypted for reading:
/// the deployment's encryption gate (`gate_on`) and the zone's own flag. An
/// unknown zone is not.
pub fn zone_is_encrypted(category_param: &str, zones: &[Zone], gate_on: bool) -> bool {
    resolve_zone_param(category_param, zones)
        .map(|z| crate::zone_crypto::zone_is_encrypted(gate_on, z.encrypted))
        .unwrap_or(false)
}

/// Whether the channel list is complete enough to build the broad message
/// sync's per-zone filters from. Starting on the first channel to arrive
/// would scope those filters to that one channel's zone.
///
/// Only an authenticated answer counts: the anonymous one omits Hidden-zone
/// channels. There is no anonymous case to settle for, because the client
/// only connects to the relay while signed in (`App`'s connect effect), so a
/// logged-out visitor produces no receipts at all — and the forum routes
/// that read this list are auth-gated and send them to sign-in instead. The
/// deadline covers a relay that never challenges, or an AUTH that is refused
/// or stalls.
pub fn channel_list_settled(receipt: SyncReceipt, deadline_passed: bool) -> bool {
    receipt.authed || deadline_passed
}

/// Whether an authenticated channel-list answer proves the relay holds no
/// channels (and so no message history) this viewer may read.
///
/// The broad message sync never starts on an empty list, so its EOSE, which
/// readiness checks such as the zone-key mint plan wait for, would never
/// arrive on a fresh database. An empty list is only evidence of an empty
/// relay once the answer is authenticated: the deadline passing with no answer,
/// or an anonymous answer (which omits Hidden-zone channels), proves nothing.
pub fn history_known_empty(receipt: SyncReceipt, channel_count: usize) -> bool {
    receipt.authed && channel_count == 0
}

/// The failure clock for whichever target (zone, section, topic) a page is
/// currently looking up. Leptos reuses a route component when only its params
/// change, so one clock per mount would let the previous target's expiry
/// apply to the next one at once. Each retarget starts a new generation, and
/// a timer only expires the generation it was started for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadlineClock<K> {
    target: Option<K>,
    generation: u64,
}

impl<K> Default for DeadlineClock<K> {
    fn default() -> Self {
        Self {
            target: None,
            generation: 0,
        }
    }
}

impl<K: PartialEq + Clone> DeadlineClock<K> {
    /// Point the clock at `target`. Returns the generation to start a timer
    /// for when the target changed, `None` when it is the same target.
    pub fn retarget(&mut self, target: K) -> Option<u64> {
        if self.target.as_ref() == Some(&target) {
            return None;
        }
        self.target = Some(target);
        self.generation += 1;
        Some(self.generation)
    }

    /// A timer started for `generation` fired. Returns the target it expires,
    /// or `None` if the page has moved on since (a stale timer).
    pub fn fire(&self, generation: u64) -> Option<K> {
        if generation == self.generation {
            self.target.clone()
        } else {
            None
        }
    }
}

/// A [`LOOKUP_DEADLINE_MS`] deadline that follows `target`: `true` once the
/// clock has expired for the target the page is showing *now*. Derived from
/// the expired target rather than a bare flag, so a param change reads
/// `false` immediately instead of waiting for the re-arming effect to run.
pub fn deadline_for<K>(target: impl Fn() -> K + Send + Sync + 'static) -> Signal<bool>
where
    K: PartialEq + Clone + Send + Sync + 'static,
{
    let target = Signal::derive(target);
    let clock = StoredValue::new(DeadlineClock::<K>::default());
    let expired_for = RwSignal::new(Option::<K>::None);
    Effect::new(move |_| {
        let current = target.get();
        let Some(generation) = clock.try_update_value(|c| c.retarget(current)).flatten() else {
            return;
        };
        // Returning to a target that expired earlier must not read as
        // expired before its new timer runs.
        let _ = expired_for.try_set(None);
        super::set_timeout_once(
            move || {
                // `try_*`: the page may have unmounted before the timer fired.
                if let Some(expired) = clock.try_with_value(|c| c.fire(generation)).flatten() {
                    let _ = expired_for.try_set(Some(expired));
                }
            },
            LOOKUP_DEADLINE_MS,
        );
    });
    Signal::derive(move || expired_for.with(|e| e.as_ref() == Some(&target.get())))
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
    fn channel_list_settles_only_on_an_authenticated_answer() {
        let mut r = SyncReceipt::default();
        assert!(!channel_list_settled(r, false));
        r.record(false);
        assert!(
            !channel_list_settled(r, false),
            "anonymous answer is not the whole list for a member"
        );
        r.record(true);
        assert!(channel_list_settled(r, false));
    }

    #[test]
    fn empty_history_needs_an_authenticated_empty_list() {
        let none = SyncReceipt::default();
        assert!(!history_known_empty(none, 0), "no answer at all");
        let mut anon = SyncReceipt::default();
        anon.record(false);
        assert!(
            !history_known_empty(anon, 0),
            "anonymous answer hides channels"
        );
        let mut authed = SyncReceipt::default();
        authed.record(true);
        assert!(history_known_empty(authed, 0));
        assert!(!history_known_empty(authed, 3), "channels exist: sync them");
    }

    #[test]
    fn channel_list_deadline_ends_the_wait() {
        let mut r = SyncReceipt::default();
        assert!(channel_list_settled(r, true), "no answer at all");
        r.record(false);
        assert!(channel_list_settled(r, true), "AUTH refused or stalled");
    }

    #[test]
    fn deadline_clock_starts_one_generation_per_target() {
        let mut c = DeadlineClock::default();
        assert_eq!(c.retarget("a"), Some(1));
        assert_eq!(c.retarget("a"), None, "same target keeps its timer");
        assert_eq!(c.retarget("b"), Some(2));
    }

    #[test]
    fn stale_timer_cannot_expire_the_next_target() {
        let mut c = DeadlineClock::default();
        let first = c.retarget("topic-1").unwrap();
        let second = c.retarget("topic-2").unwrap();
        assert_eq!(c.fire(first), None, "topic-1's timer is stale");
        assert_eq!(c.fire(second), Some("topic-2"));
    }

    #[test]
    fn returning_to_a_target_rearms_it() {
        let mut c = DeadlineClock::default();
        let a1 = c.retarget("a").unwrap();
        c.retarget("b");
        let a2 = c.retarget("a").unwrap();
        assert_ne!(a1, a2);
        assert_eq!(c.fire(a1), None);
        assert_eq!(c.fire(a2), Some("a"));
    }

    // -- Encrypted zones: wait for the member's keys -------------------------

    fn progressing() -> KeyState {
        KeyState::Progressing { until: 1e12 }
    }

    /// The live cold-device case: the authenticated history answer has
    /// arrived, the topic root is a sealed original still under its envelope
    /// id, and the grants carrying the key are still being opened.
    #[test]
    fn keys_progressing_is_keys_loading() {
        assert_eq!(
            Lookup::decide_with_keys(false, true, progressing(), false),
            KeysLoading
        );
        assert!(KeysLoading.is_loading());
    }

    /// Past the page's 15 s deadline the backlog is still moving: keep saying
    /// the keys are on their way, not "check your connection".
    #[test]
    fn keys_progressing_outlives_the_page_deadline() {
        assert_eq!(
            Lookup::decide_with_keys(false, true, progressing(), true),
            KeysLoading
        );
    }

    #[test]
    fn keys_stalled_is_keys_timed_out() {
        assert_eq!(
            Lookup::decide_with_keys(false, true, KeyState::Stalled, false),
            KeysTimedOut
        );
        assert!(!KeysTimedOut.is_loading());
    }

    #[test]
    fn keys_settled_and_root_absent_is_not_found() {
        assert_eq!(
            Lookup::decide_with_keys(false, true, KeyState::Settled, false),
            NotFound
        );
    }

    #[test]
    fn keys_settled_and_root_present_is_found() {
        assert_eq!(
            Lookup::decide_with_keys(true, true, KeyState::Settled, false),
            Found
        );
    }

    #[test]
    fn root_restored_after_a_keys_timeout_still_wins() {
        assert_eq!(
            Lookup::decide_with_keys(true, true, KeyState::Stalled, true),
            Found
        );
    }

    /// No relay answer at all keeps the existing path and copy: loading,
    /// then the connection timeout at the deadline, whatever the keys do.
    #[test]
    fn no_relay_answer_path_is_unchanged() {
        for keys in [KeyState::NotNeeded, progressing(), KeyState::Stalled] {
            assert_eq!(Lookup::decide_with_keys(false, false, keys, false), Loading);
            assert_eq!(Lookup::decide_with_keys(false, false, keys, true), TimedOut);
        }
    }

    #[test]
    fn unencrypted_zone_is_unaffected() {
        for phase in [
            None,
            Some(KeyPhase::Stalled),
            Some(KeyPhase::Progressing { until: 1.0 }),
        ] {
            let keys = key_state(false, phase, false);
            assert_eq!(keys, KeyState::NotNeeded);
            for (found, answered, deadline) in [
                (false, true, false),
                (true, true, false),
                (false, false, false),
                (false, false, true),
            ] {
                assert_eq!(
                    Lookup::decide_with_keys(found, answered, keys, deadline),
                    Lookup::decide(found, answered, deadline)
                );
            }
        }
    }

    /// A member holding no key for the zone: the backlog settles at EOSE with
    /// nothing in it, so the page settles too (locked posts show as before)
    /// rather than spinning.
    #[test]
    fn keyless_member_settles() {
        let mut b = crate::zone_crypto::grant_backlog::GrantBacklog::new(false, 0.0);
        b.scope_delivered(
            crate::zone_crypto::grant_paging::GrantScope::Identity,
            true,
            500.0,
        );
        let keys = key_state(true, Some(b.phase(600.0)), false);
        assert_eq!(keys, KeyState::Settled);
        assert_eq!(Lookup::decide_with_keys(false, true, keys, false), NotFound);
        assert_eq!(Lookup::decide_with_keys(true, true, keys, false), Found);
    }

    /// The zone's only grant ended in a retryable failure (an unanswered
    /// admin check, a refused NIP-07 prompt): the page must say the keys are
    /// late, never "not found", which is what this page fix exists for.
    #[test]
    fn a_grant_left_to_retry_never_reads_as_not_found() {
        use crate::zone_crypto::grant_backlog::{GrantBacklog, WrapOutcome, KEYS_STALL_MS};
        use crate::zone_crypto::grant_paging::GrantScope;
        for outcome in [WrapOutcome::Retry, WrapOutcome::Refused] {
            let mut b = GrantBacklog::new(false, 0.0);
            b.wrap_started();
            b.scope_delivered(GrantScope::Identity, true, 500.0);
            b.wrap_done(800.0, "grant", 1, outcome);
            let early = key_state(true, Some(b.phase(900.0)), false);
            assert_ne!(
                Lookup::decide_with_keys(false, true, early, false),
                NotFound,
                "{outcome:?}"
            );
            let late = key_state(true, Some(b.phase(800.0 + KEYS_STALL_MS)), false);
            assert_eq!(late, KeyState::Stalled, "{outcome:?}");
            assert_ne!(
                Lookup::decide_with_keys(false, true, late, false),
                NotFound,
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn grant_sync_not_started_waits_only_until_the_deadline() {
        assert_eq!(key_state(true, None, false), KeyState::Pending);
        assert_eq!(key_state(true, None, true), KeyState::Stalled);
        assert_eq!(
            Lookup::decide_with_keys(false, true, KeyState::Pending, false),
            KeysLoading
        );
    }

    #[test]
    fn zone_encryption_needs_the_gate_and_the_flag() {
        let zones: Vec<Zone> = serde_json::from_value(serde_json::json!([
            { "id": "family", "visibility": "locked", "encrypted": true },
            { "id": "friends", "visibility": "locked" }
        ]))
        .expect("zones parse");
        assert!(zone_is_encrypted("family", &zones, true));
        assert!(!zone_is_encrypted("family", &zones, false), "gate off");
        assert!(!zone_is_encrypted("friends", &zones, true));
        assert!(!zone_is_encrypted("no-such-zone", &zones, true));
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
