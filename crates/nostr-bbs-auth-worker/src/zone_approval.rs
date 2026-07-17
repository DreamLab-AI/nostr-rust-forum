//! Per-zone auto-approval of new joiners.
//!
//! A brand-new user is auto-whitelisted at username-claim time (the deliberate
//! join signal, see [`crate::username::claim`]). Historically they were granted
//! a hardcoded `["members"]` cohort. This module makes the granted cohorts
//! config-driven: each zone in `ZONE_CONFIG` may carry an `auto_approve` flag,
//! and an opted-in zone's `required_cohorts` are additively granted to every new
//! joiner — so they land straight in that zone without an admin approving them.
//!
//! Opt-in per zone, deny-by-default: with no `auto_approve` zone (or an absent /
//! malformed `ZONE_CONFIG`) the result is exactly `["members"]`, preserving the
//! historic behaviour. The relay enforces the same model at its own admission
//! points; this keeps the auth-worker's grant in lockstep with operator config.

use serde::Deserialize;

/// Minimal projection of a `ZONE_CONFIG` entry — only the fields auto-approval
/// needs. Extra fields in the JSON are ignored.
#[derive(Debug, Deserialize)]
struct ApprovalZone {
    #[serde(default)]
    required_cohorts: Vec<String>,
    #[serde(default)]
    auto_approve: bool,
}

/// The JSON cohort array a new joiner is granted: the base `members` cohort plus
/// the de-duplicated `required_cohorts` of every `auto_approve` zone in the given
/// `ZONE_CONFIG` string. An absent/empty/malformed config yields `["members"]`.
pub(crate) fn new_joiner_cohorts_json(zone_config: Option<&str>) -> String {
    let mut cohorts = vec!["members".to_string()];
    if let Some(raw) = zone_config {
        if let Ok(zones) = serde_json::from_str::<Vec<ApprovalZone>>(raw.trim()) {
            for z in zones {
                if z.auto_approve {
                    for c in z.required_cohorts {
                        if !cohorts.contains(&c) {
                            cohorts.push(c);
                        }
                    }
                }
            }
        }
    }
    serde_json::to_string(&cohorts).unwrap_or_else(|_| r#"["members"]"#.to_string())
}

#[cfg(test)]
mod tests {
    use super::new_joiner_cohorts_json;

    #[test]
    fn absent_config_is_members_only() {
        assert_eq!(new_joiner_cohorts_json(None), r#"["members"]"#);
    }

    #[test]
    fn malformed_config_is_members_only() {
        assert_eq!(new_joiner_cohorts_json(Some("not json")), r#"["members"]"#);
    }

    #[test]
    fn no_auto_approve_zone_is_members_only() {
        let z = r#"[{"id":"public","required_cohorts":[]},
                    {"id":"minimoonoir","required_cohorts":["friends"]}]"#;
        assert_eq!(new_joiner_cohorts_json(Some(z)), r#"["members"]"#);
    }

    #[test]
    fn auto_approve_zone_grants_its_cohort_additively() {
        let z = r#"[{"id":"public","required_cohorts":[]},
                    {"id":"minimoonoir","required_cohorts":["friends"],"auto_approve":true},
                    {"id":"family","required_cohorts":["family"]},
                    {"id":"business","required_cohorts":["business"]}]"#;
        // members base + minimoonoir's friends; family/business NOT auto-granted.
        assert_eq!(new_joiner_cohorts_json(Some(z)), r#"["members","friends"]"#);
    }

    #[test]
    fn multiple_auto_approve_zones_union_no_dupes() {
        let z = r#"[{"id":"a","required_cohorts":["friends"],"auto_approve":true},
                    {"id":"b","required_cohorts":["friends","extra"],"auto_approve":true}]"#;
        assert_eq!(
            new_joiner_cohorts_json(Some(z)),
            r#"["members","friends","extra"]"#
        );
    }
}
