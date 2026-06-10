//! Phase C: tiered calendar visibility projection (access-tier data projection).
//!
//! This module sits *on top of* the Phase A zone read-gate. The zone gate
//! (`trust::has_zone_access`) answers "may this viewer see this zone at all?".
//! The calendar projector answers the finer question: even among calendar events
//! a viewer is allowed to know about, which ones must be reduced to a free/busy
//! block, and which must be omitted entirely because the viewer is not even
//! supposed to be *aware* they exist.
//!
//! It implements the operator-approved matrix
//! (`dreamlab-ai-website/docs/architecture/forum-org-redesign.md` §4):
//!
//! | Viewer ↓ / Event zone → | family   | business | friends | own  |
//! |-------------------------|----------|----------|---------|------|
//! | admin                   | full     | full     | full    | full |
//! | family                  | full     | full     | full    | full |
//! | friends                 | free/busy| free/busy| full    | full |
//! | business                | OMIT     | full     | OMIT    | full |
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
            // Any other (e.g. public) zone: free/busy is the safe floor for a
            // non-owning friend; but public calendar events are not zone-private,
            // so default to full for unknown/public zones the friend can already
            // read via the zone gate.
            _ => Projection::Full,
        };
    }

    // business viewer.
    if has(COHORT_BUSINESS) {
        return match event_zone {
            ZONE_BUSINESS => Projection::Full,
            // family / friends: business must remain unaware.
            ZONE_FAMILY | ZONE_FRIENDS => Projection::Omit,
            _ => Projection::Full,
        };
    }

    // No relevant cohort: the Phase A zone read-gate already denied non-members
    // of locked/hidden zones before reaching here, so anything that arrives is a
    // zone the viewer may read (e.g. public). Serve full — the gate, not the
    // projector, is the membership boundary.
    Projection::Full
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

    #[test]
    fn projected_kinds() {
        assert!(is_projected_calendar_kind(31922));
        assert!(is_projected_calendar_kind(31923));
        assert!(is_projected_calendar_kind(31925));
        assert!(!is_projected_calendar_kind(42));
        assert!(!is_projected_calendar_kind(40));
    }
}
