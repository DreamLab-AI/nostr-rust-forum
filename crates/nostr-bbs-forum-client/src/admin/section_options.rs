//! Section choices for the admin "Create Channel" form.
//!
//! The client routes a channel to a zone through its `section` tag
//! ([`crate::stores::zones::section_to_zone`]): the section must equal a
//! configured zone id or start with `<zone-id>-`. The choices offered here are
//! therefore derived from the deployment's zone config, so every option routes
//! to the zone it is listed under. A deployment with no zone config keeps the
//! historic hardcoded list.
//!
//! Everything in this module is pure (no DOM, no globals) so it is unit tested
//! natively.

use crate::stores::zones::{zone_id_for_section, Zone};

/// Longest section id the form will produce. Matches the form's 64-character
/// name limit and keeps tags comfortably small.
pub const MAX_SECTION_LEN: usize = 64;

/// The generic kit's legacy sections, offered only when no zone config exists.
/// Format: (section_id, display_label).
pub const LEGACY_SECTIONS: &[(&str, &str)] = &[
    // Home
    ("home-lobby", "Home Lobby"),
    // Members
    ("members-training", "Members Training"),
    ("members-projects", "Members Projects"),
    ("members-bookings", "Members Bookings"),
    ("ai-general", "AI General"),
    ("ai-claude-flow", "AI Claude Flow"),
    ("ai-visionflow", "AI VisionFlow"),
    // Minimoonoir
    ("private-welcome", "Minimoonoir Welcome"),
    ("private-events", "Minimoonoir Events"),
    ("private-booking", "Minimoonoir Booking"),
];

/// One selectable section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionOption {
    /// The `section` tag value.
    pub id: String,
    /// Label shown in the dropdown.
    pub label: String,
}

/// The sections offered for one configured zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSections {
    /// Zone id (`zone2`): the prefix of every section id below and the value
    /// bound on the relay.
    pub zone_id: String,
    /// Zone display name.
    pub zone_label: String,
    /// The zone's own `section_order` entries that route back to it.
    pub sections: Vec<SectionOption>,
}

/// Dropdown value that means "a new section: type its slug".
pub const NEW_SECTION: &str = "__new__";

/// Derive the per-zone choices from the zone config.
///
/// Each zone contributes its `section_order` entries, except any that do not
/// route back to that zone (an entry like `minimoonoir-rants` under zone
/// `zone2` would silently land in the first zone's tile, so it is not
/// offered). A zone with no usable entries still appears, so the admin can add
/// a new section under it.
pub fn zone_sections(zones: &[Zone]) -> Vec<ZoneSections> {
    zones
        .iter()
        .map(|z| {
            let mut sections: Vec<SectionOption> = Vec::new();
            for sid in &z.section_order {
                let routes_here = zone_id_for_section(sid, zones)
                    .is_some_and(|zid| zid.eq_ignore_ascii_case(&z.id));
                if routes_here && !sections.iter().any(|o| o.id == *sid) {
                    sections.push(SectionOption {
                        id: sid.clone(),
                        label: sid.clone(),
                    });
                }
            }
            ZoneSections {
                zone_id: z.id.clone(),
                zone_label: z.label(),
                sections,
            }
        })
        .collect()
}

/// Validate a new-section slug: lowercase `a-z`, `0-9` and single hyphens,
/// not starting or ending with a hyphen. Returns the slug, or a message fit
/// to show the admin.
pub fn validate_slug(slug: &str) -> Result<&str, &'static str> {
    if slug.is_empty() {
        return Err("Enter a section name.");
    }
    if slug.starts_with('-') || slug.ends_with('-') || slug.contains("--") {
        return Err("Use single hyphens between words, none at the start or end.");
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("Use lowercase letters, digits and hyphens only.");
    }
    Ok(slug)
}

/// Build the section id for a new slug under a zone: `<zone-id>-<slug>`.
///
/// Fails when the slug is invalid or the result would exceed
/// [`MAX_SECTION_LEN`].
pub fn compose_section(zone_id: &str, slug: &str) -> Result<String, &'static str> {
    let slug = validate_slug(slug)?;
    let id = format!("{zone_id}-{slug}");
    if id.len() > MAX_SECTION_LEN {
        return Err("That section name is too long.");
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(id: &str, order: &[&str]) -> Zone {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "display_name": id,
            "section_order": order,
        }))
        .unwrap()
    }

    #[test]
    fn options_come_from_each_zones_section_order() {
        let zones = vec![zone("zone1", &[]), zone("zone2", &["zone2-rants"])];
        let out = zone_sections(&zones);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].zone_id, "zone1");
        assert!(out[0].sections.is_empty(), "still offers a new section");
        assert_eq!(out[1].sections.len(), 1);
        assert_eq!(out[1].sections[0].id, "zone2-rants");
    }

    #[test]
    fn section_order_entries_that_do_not_route_back_are_dropped() {
        let zones = vec![
            zone("zone1", &[]),
            zone(
                "zone2",
                &["minimoonoir-rants", "zone2-rants", "zone2-rants"],
            ),
        ];
        let out = zone_sections(&zones);
        let ids: Vec<_> = out[1].sections.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, vec!["zone2-rants"], "dedups and drops the stray one");
    }

    #[test]
    fn every_offered_section_routes_to_its_own_zone() {
        let zones = vec![zone("a", &["a-x", "a"]), zone("b", &["b-y", "a-z"])];
        for zs in zone_sections(&zones) {
            for o in zs.sections {
                assert_eq!(
                    crate::stores::zones::section_to_zone(&o.id, &zones).as_deref(),
                    Some(zs.zone_id.as_str())
                );
            }
        }
    }

    #[test]
    fn slug_accepts_lowercase_digits_and_inner_hyphens() {
        for ok in ["rants", "q3-2024", "a", "a1-b2-c3"] {
            assert_eq!(validate_slug(ok), Ok(ok));
        }
    }

    #[test]
    fn slug_rejects_everything_else() {
        for bad in [
            "",
            "Rants",
            "has space",
            "under_score",
            "-lead",
            "trail-",
            "dou--ble",
            "é",
            "a/b",
            "a.b",
        ] {
            assert!(validate_slug(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn compose_prefixes_the_zone_and_caps_the_length() {
        assert_eq!(compose_section("zone2", "rants").unwrap(), "zone2-rants");
        let long = "a".repeat(MAX_SECTION_LEN);
        assert!(compose_section("zone2", &long).is_err());
        assert!(compose_section("zone2", "Bad").is_err());
        let fits = "a".repeat(MAX_SECTION_LEN - "zone2-".len());
        assert_eq!(
            compose_section("zone2", &fits).unwrap().len(),
            MAX_SECTION_LEN
        );
    }

    #[test]
    fn legacy_list_is_unchanged() {
        assert_eq!(LEGACY_SECTIONS.len(), 10);
        assert_eq!(LEGACY_SECTIONS[0].0, "home-lobby");
    }
}
