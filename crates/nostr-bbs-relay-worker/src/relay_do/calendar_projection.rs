//! Phase C: tiered calendar visibility projection (access-tier data projection).
//!
//! This module is the COMPLETE access decision for calendar event kinds. There
//! is no upstream zone read-gate for calendar kinds: a live probe proved that a
//! gate-then-project ordering omitted any event in a zone the viewer was not a
//! member of, so the FreeBusy / cross-zone-Full tiers never executed. The
//! projector answers the whole question — for every (viewer, event) pair: serve
//! full, reduce to a free/busy block, or omit entirely (viewer must remain
//! unaware the event exists). It is deny-by-default for unknown zones.
//!
//! It implements the operator-approved matrix
//! (`dreamlab-ai-website/docs/architecture/forum-org-redesign.md` §4):
//!
//! | Viewer ↓ / Event zone → | family   | business | friends | public | unknown |
//! |-------------------------|----------|----------|---------|--------|---------|
//! | admin / owner           | full     | full     | full    | full   | full    |
//! | family                  | full     | full     | full    | full   | full    |
//! | friends                 | f/b*     | f/b*     | full    | full   | OMIT    |
//! | business                | OMIT     | full     | OMIT    | full   | OMIT    |
//! | no cohort / anon        | OMIT     | OMIT     | OMIT    | full   | OMIT    |
//!
//! (*) friends see family/business as free/busy ONLY at a recognised shared
//! venue (fairfield/dreamlab); off-site events are omitted.
//!
//! Free/busy keeps start/end + venue + a busy flag (see
//! [`nostr_bbs_core::to_free_busy`]); for a `friends` viewer, a family/business
//! event that is NOT at a recognised venue (fairfield/dreamlab) is OMITTED
//! rather than shown as free/busy — friends only see venue blocking, never
//! private off-site time.
//!
//! "own" is decided by the caller comparing `event.pubkey` to the viewer's
//! authenticated pubkey; an owner always gets full detail.

use nostr_bbs_core::event::NostrEvent;
use nostr_bbs_core::{is_known_venue, read_venue_tag, read_zone_tag, to_free_busy};

/// Cohort names used in the matrix. These are the same string slugs stored in
/// `whitelist.cohorts` and used as `Zone.required_cohorts` — no new vocabulary.
pub const COHORT_ADMIN: &str = "admin";
pub const COHORT_FAMILY: &str = "family";
pub const COHORT_FRIENDS: &str = "friends";
pub const COHORT_BUSINESS: &str = "business";

/// Zone slugs that own calendar events.
pub const ZONE_FAMILY: &str = "family";
pub const ZONE_BUSINESS: &str = "business";
pub const ZONE_FRIENDS: &str = "friends";
/// The public zone slug — readable by every tier at full detail.
pub const ZONE_PUBLIC: &str = "public";

/// The outcome of projecting one calendar event for one viewer tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projection {
    /// Serve the event unchanged.
    Full,
    /// Serve a redacted free/busy block (start/end/venue/busy only).
    FreeBusy,
    /// Omit the event entirely — the viewer must remain unaware it exists.
    Omit,
}

/// Decide the projection tier for a calendar event, given the viewer's cohorts,
/// the event's owning zone, and the (optional) venue.
///
/// This is the pure decision core — no event mutation, no I/O — so the matrix is
/// directly unit-testable. The caller applies the result: [`Projection::Full`]
/// serves the event as-is, [`Projection::FreeBusy`] serves
/// [`nostr_bbs_core::to_free_busy`], [`Projection::Omit`] drops it.
///
/// `is_owner` short-circuits to [`Projection::Full`]: an author always sees their
/// own events in full, regardless of zone.
pub fn project_tier(
    viewer_cohorts: &[String],
    event_zone: &str,
    venue: Option<&str>,
    is_owner: bool,
    is_admin: bool,
) -> Projection {
    // Owners and admins always get full detail.
    if is_owner || is_admin {
        return Projection::Full;
    }

    let has = |c: &str| viewer_cohorts.iter().any(|v| v == c);

    // admin cohort tag (belt-and-braces with the is_admin flag).
    if has(COHORT_ADMIN) {
        return Projection::Full;
    }

    let venue_is_shared = venue.map(is_known_venue).unwrap_or(false);

    // family viewer: full detail on every zone.
    if has(COHORT_FAMILY) {
        return Projection::Full;
    }

    // friends viewer.
    if has(COHORT_FRIENDS) {
        return match event_zone {
            // Own circle: full.
            ZONE_FRIENDS => Projection::Full,
            // family / business: free/busy IF at a shared venue, else omit.
            ZONE_FAMILY | ZONE_BUSINESS => {
                if venue_is_shared {
                    Projection::FreeBusy
                } else {
                    Projection::Omit
                }
            }
            // Public is not zone-private: full detail.
            ZONE_PUBLIC => Projection::Full,
            // Any unrecognised zone: deny by default — the projector is now the
            // complete access decision (no upstream read-gate), so an unknown
            // zone must not be served.
            _ => Projection::Omit,
        };
    }

    // business viewer.
    if has(COHORT_BUSINESS) {
        return match event_zone {
            ZONE_BUSINESS => Projection::Full,
            // family / friends: business must remain unaware.
            ZONE_FAMILY | ZONE_FRIENDS => Projection::Omit,
            // Public is not zone-private: full detail.
            ZONE_PUBLIC => Projection::Full,
            // Unrecognised zone: deny by default.
            _ => Projection::Omit,
        };
    }

    // No relevant cohort (includes anon/unauthenticated and whitelisted but
    // uncohorted viewers). The projector is the complete access decision: public
    // zone events are served full, EVERYTHING else is omitted. Deny by default.
    match event_zone {
        ZONE_PUBLIC => Projection::Full,
        _ => Projection::Omit,
    }
}

/// Apply the projection to an event, returning the event to serve, or `None`
/// when it must be omitted. Convenience wrapper used by the REQ seam.
pub fn project_calendar_event(
    viewer_cohorts: &[String],
    event: &NostrEvent,
    is_owner: bool,
    is_admin: bool,
) -> Option<NostrEvent> {
    // An event with no zone-binding tag is unscoped: serve it as-is (it carries
    // no zone-private detail — the same posture Phase A used for untagged
    // calendar kinds).
    let Some(zone) = read_zone_tag(event) else {
        return Some(event.clone());
    };
    let venue = read_venue_tag(event);

    match project_tier(viewer_cohorts, zone, venue, is_owner, is_admin) {
        Projection::Full => Some(event.clone()),
        Projection::FreeBusy => Some(to_free_busy(event)),
        Projection::Omit => None,
    }
}

/// Whether a kind is a calendar kind subject to tiered projection.
///
/// 31922 date-based, 31923 time-based events, and 31925 RSVP (which can leak the
/// existence of and detail about an event via its `e`/`a` reference) are all
/// projected. RSVPs to an omitted event are omitted; RSVPs that survive are
/// served as-is (they carry only a status, no private detail of their own).
pub fn is_projected_calendar_kind(kind: u64) -> bool {
    matches!(
        kind,
        nostr_bbs_core::KIND_CALENDAR_DATE_EVENT
            | nostr_bbs_core::KIND_CALENDAR_EVENT
            | nostr_bbs_core::KIND_CALENDAR_RSVP
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cohorts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // ---- The four high-risk cells called out in the design doc -------------

    #[test]
    fn friends_sees_family_venue_event_as_free_busy() {
        let p = project_tier(
            &cohorts(&[COHORT_FRIENDS]),
            ZONE_FAMILY,
            Some("fairfield"),
            false,
            false,
        );
        assert_eq!(p, Projection::FreeBusy);
    }

    #[test]
    fn friends_sees_family_offsite_event_as_omitted() {
        // No venue → off-site → friends must not even see free/busy.
        let p = project_tier(&cohorts(&[COHORT_FRIENDS]), ZONE_FAMILY, None, false, false);
        assert_eq!(p, Projection::Omit);
        // An unrecognised venue is equally off-site.
        let p2 = project_tier(
            &cohorts(&[COHORT_FRIENDS]),
            ZONE_FAMILY,
            Some("someones-house"),
            false,
            false,
        );
        assert_eq!(p2, Projection::Omit);
    }

    #[test]
    fn business_sees_family_event_as_omitted() {
        let p = project_tier(
            &cohorts(&[COHORT_BUSINESS]),
            ZONE_FAMILY,
            Some("dreamlab"),
            false,
            false,
        );
        assert_eq!(p, Projection::Omit);
    }

    #[test]
    fn family_sees_business_event_as_full() {
        let p = project_tier(
            &cohorts(&[COHORT_FAMILY]),
            ZONE_BUSINESS,
            None,
            false,
            false,
        );
        assert_eq!(p, Projection::Full);
    }

    // ---- Remaining matrix cells --------------------------------------------

    #[test]
    fn admin_sees_everything_full() {
        for zone in [ZONE_FAMILY, ZONE_BUSINESS, ZONE_FRIENDS] {
            assert_eq!(
                project_tier(&[], zone, None, false, true),
                Projection::Full,
                "admin flag, zone {zone}"
            );
            assert_eq!(
                project_tier(&cohorts(&[COHORT_ADMIN]), zone, None, false, false),
                Projection::Full,
                "admin cohort, zone {zone}"
            );
        }
    }

    #[test]
    fn owner_always_full_even_other_tier() {
        // A business user viewing their OWN family-zone event still gets full.
        let p = project_tier(&cohorts(&[COHORT_BUSINESS]), ZONE_FAMILY, None, true, false);
        assert_eq!(p, Projection::Full);
    }

    #[test]
    fn family_sees_all_zones_full() {
        for zone in [ZONE_FAMILY, ZONE_BUSINESS, ZONE_FRIENDS] {
            assert_eq!(
                project_tier(&cohorts(&[COHORT_FAMILY]), zone, None, false, false),
                Projection::Full,
                "family viewer, zone {zone}"
            );
        }
    }

    #[test]
    fn friends_sees_own_friends_zone_full() {
        let p = project_tier(
            &cohorts(&[COHORT_FRIENDS]),
            ZONE_FRIENDS,
            None,
            false,
            false,
        );
        assert_eq!(p, Projection::Full);
    }

    #[test]
    fn friends_sees_business_venue_event_as_free_busy() {
        let p = project_tier(
            &cohorts(&[COHORT_FRIENDS]),
            ZONE_BUSINESS,
            Some("dreamlab"),
            false,
            false,
        );
        assert_eq!(p, Projection::FreeBusy);
    }

    #[test]
    fn business_sees_friends_event_as_omitted() {
        let p = project_tier(
            &cohorts(&[COHORT_BUSINESS]),
            ZONE_FRIENDS,
            Some("fairfield"),
            false,
            false,
        );
        assert_eq!(p, Projection::Omit);
    }

    #[test]
    fn business_sees_own_business_zone_full() {
        let p = project_tier(
            &cohorts(&[COHORT_BUSINESS]),
            ZONE_BUSINESS,
            None,
            false,
            false,
        );
        assert_eq!(p, Projection::Full);
    }

    // ---- Deny-by-default / no-cohort / unknown-zone cells ------------------

    #[test]
    fn no_cohort_viewer_full_on_public_omitted_elsewhere() {
        // Empty cohorts (anon / unauthenticated / whitelisted-but-uncohorted).
        assert_eq!(
            project_tier(&[], ZONE_PUBLIC, None, false, false),
            Projection::Full,
            "no cohort, public"
        );
        for zone in [ZONE_FAMILY, ZONE_BUSINESS, ZONE_FRIENDS, "mystery"] {
            assert_eq!(
                project_tier(&[], zone, Some("fairfield"), false, false),
                Projection::Omit,
                "no cohort, zone {zone} omitted"
            );
        }
    }

    #[test]
    fn friends_unknown_zone_omitted_public_full() {
        assert_eq!(
            project_tier(&cohorts(&[COHORT_FRIENDS]), "mystery", None, false, false),
            Projection::Omit,
            "friends, unknown zone deny-by-default"
        );
        assert_eq!(
            project_tier(&cohorts(&[COHORT_FRIENDS]), ZONE_PUBLIC, None, false, false),
            Projection::Full,
            "friends, public zone full"
        );
    }

    #[test]
    fn business_unknown_zone_omitted_public_full() {
        assert_eq!(
            project_tier(&cohorts(&[COHORT_BUSINESS]), "mystery", None, false, false),
            Projection::Omit,
            "business, unknown zone deny-by-default"
        );
        assert_eq!(
            project_tier(&cohorts(&[COHORT_BUSINESS]), ZONE_PUBLIC, None, false, false),
            Projection::Full,
            "business, public zone full"
        );
    }

    #[test]
    fn family_sees_business_full_explicit() {
        // The probe persona: family-dave must see business@dreamlab full.
        assert_eq!(
            project_tier(
                &cohorts(&[COHORT_FAMILY]),
                ZONE_BUSINESS,
                Some("dreamlab"),
                false,
                false,
            ),
            Projection::Full,
        );
        // ...and friends events full too.
        assert_eq!(
            project_tier(&cohorts(&[COHORT_FAMILY]), ZONE_FRIENDS, None, false, false),
            Projection::Full,
        );
    }

    #[test]
    fn friends_sees_family_fairfield_free_busy_not_omit() {
        // The probe persona: friends-carol must get free/busy (not absent) for
        // family@fairfield and business@dreamlab.
        assert_eq!(
            project_tier(
                &cohorts(&[COHORT_FRIENDS]),
                ZONE_FAMILY,
                Some("fairfield"),
                false,
                false,
            ),
            Projection::FreeBusy,
        );
        assert_eq!(
            project_tier(
                &cohorts(&[COHORT_FRIENDS]),
                ZONE_BUSINESS,
                Some("dreamlab"),
                false,
                false,
            ),
            Projection::FreeBusy,
        );
    }

    #[test]
    fn dual_cohort_family_friends_takes_family_tier() {
        // A relative who also visits (family,friends) gets the more permissive
        // family tier: full detail on a family event, not free/busy.
        let p = project_tier(
            &cohorts(&[COHORT_FAMILY, COHORT_FRIENDS]),
            ZONE_FAMILY,
            None,
            false,
            false,
        );
        assert_eq!(p, Projection::Full);
    }

    // ---- project_calendar_event wrapper (event mutation) -------------------

    fn build_event(zone: &str, venue: Option<&str>) -> NostrEvent {
        let key = [0x07u8; 32];
        let ev = nostr_bbs_core::create_calendar_event(
            &key,
            "Private detail",
            1_700_000_000,
            Some(1_700_003_600),
            Some("Secret location"),
            Some("notes"),
            None,
        )
        .unwrap();
        let ev = nostr_bbs_core::set_zone_tag(ev, zone);
        match venue {
            Some(v) => nostr_bbs_core::set_venue_tag(ev, v),
            None => ev,
        }
    }

    #[test]
    fn wrapper_friends_family_venue_returns_redacted() {
        let ev = build_event(ZONE_FAMILY, Some("fairfield"));
        let out = project_calendar_event(&cohorts(&[COHORT_FRIENDS]), &ev, false, false).unwrap();
        // Redacted: no title, no content.
        assert!(out.content.is_empty());
        assert!(!out.tags.iter().any(|t| t[0] == "title"));
        assert!(out.tags.iter().any(|t| t[0] == "busy"));
        assert_eq!(read_venue_tag(&out), Some("fairfield"));
    }

    #[test]
    fn wrapper_business_family_returns_none() {
        let ev = build_event(ZONE_FAMILY, Some("dreamlab"));
        let out = project_calendar_event(&cohorts(&[COHORT_BUSINESS]), &ev, false, false);
        assert!(out.is_none());
    }

    #[test]
    fn wrapper_no_cohort_public_full_unknown_omit() {
        // No-cohort viewer on a public zone event: full (title preserved).
        let pub_ev = build_event(ZONE_PUBLIC, None);
        let out = project_calendar_event(&[], &pub_ev, false, false).unwrap();
        assert!(out.tags.iter().any(|t| t[0] == "title"));
        // No-cohort viewer on an unknown zone: omitted entirely.
        let unk_ev = build_event("mystery", Some("fairfield"));
        assert!(project_calendar_event(&[], &unk_ev, false, false).is_none());
    }

    #[test]
    fn wrapper_friends_unknown_zone_omitted() {
        let ev = build_event("mystery", Some("dreamlab"));
        assert!(project_calendar_event(&cohorts(&[COHORT_FRIENDS]), &ev, false, false).is_none());
    }

    #[test]
    fn wrapper_untagged_event_served_as_is() {
        let key = [0x09u8; 32];
        let ev = nostr_bbs_core::create_calendar_event(
            &key,
            "Open",
            1_700_000_000,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let out = project_calendar_event(&cohorts(&[COHORT_BUSINESS]), &ev, false, false).unwrap();
        // No zone tag → unscoped → unchanged (title preserved).
        assert!(out.tags.iter().any(|t| t[0] == "title"));
    }

    // ---- RSVP tier gating contract (the nip_handlers RSVP rule) ------------
    //
    // The RSVP handler serves an RSVP ONLY when the viewer's tier for the TARGET
    // event is Full; FreeBusy/Omit ⇒ withhold (an RSVP leaks participants). These
    // assert the tier inputs that drive that branch. The D1 target lookup itself
    // is exercised by integration tests; here we pin the decision boundary.

    #[test]
    fn rsvp_served_only_when_target_tier_full() {
        // friends viewing a friends-zone target → Full → RSVP served.
        assert_eq!(
            project_tier(&cohorts(&[COHORT_FRIENDS]), ZONE_FRIENDS, None, false, false),
            Projection::Full,
        );
        // friends viewing a family@fairfield target → FreeBusy → RSVP withheld.
        assert_eq!(
            project_tier(
                &cohorts(&[COHORT_FRIENDS]),
                ZONE_FAMILY,
                Some("fairfield"),
                false,
                false,
            ),
            Projection::FreeBusy,
        );
        // business viewing a family-zone target → Omit → RSVP withheld.
        assert_eq!(
            project_tier(&cohorts(&[COHORT_BUSINESS]), ZONE_FAMILY, None, false, false),
            Projection::Omit,
        );
    }

    #[test]
    fn rsvp_spoofed_mirror_zone_does_not_grant_full() {
        // SECURITY: even if an attacker mirrors zone=public on the RSVP, the
        // handler resolves the TARGET's real zone (family) from D1 and feeds THAT
        // here. A no-cohort/lower-tier viewer therefore gets Omit, not Full — the
        // spoofed public tag never reaches this function.
        assert_eq!(
            project_tier(&[], ZONE_FAMILY, None, false, false),
            Projection::Omit,
        );
        // Contrast: had the spoof won (public fed in), it would have been Full —
        // which is exactly the leak the target-resolution prevents.
        assert_eq!(
            project_tier(&[], ZONE_PUBLIC, None, false, false),
            Projection::Full,
        );
    }

    #[test]
    fn projected_kinds() {
        assert!(is_projected_calendar_kind(31922));
        assert!(is_projected_calendar_kind(31923));
        assert!(is_projected_calendar_kind(31925));
        assert!(!is_projected_calendar_kind(42));
        assert!(!is_projected_calendar_kind(40));
    }
}
