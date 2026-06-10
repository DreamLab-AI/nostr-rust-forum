//! Config-driven zone definitions for the relay worker.
//!
//! Zones (forum sections) are entirely data-driven: the operator declares them
//! in `forum.toml` under `[[zones]]`, and the deployment pipeline serialises the
//! `zones` array to JSON and exposes it to this worker as the `ZONE_CONFIG`
//! environment variable (a `wrangler` `[vars]` entry or secret). The shape is the
//! serde representation of `nostr_bbs_config::schema::Zone`, so config authored in
//! TOML round-trips through JSON without a second schema.
//!
//! Nothing here is hardcoded: if `ZONE_CONFIG` is absent or unparseable the
//! lookups fall back to a deny-by-default posture (no zone matched), and the
//! caller's admin bypass still applies. The relay never invents zone names.
//!
//! Access model (matches the operator-approved org redesign §3):
//! - read  gate: `required_cohorts` — empty + `visibility = public` ⇒ unauth read.
//! - write gate: `write_cohorts ?? required_cohorts`.
//! - admins bypass both, unconditionally (enforced at the call sites).

use serde::Deserialize;
use worker::Env;

/// Visibility policy for non-members. Mirrors
/// `nostr_bbs_config::schema::ZoneVisibility`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneVisibility {
    /// Listed + readable without auth/cohort.
    Public,
    /// Listed as a content-gated tile (default for non-members).
    #[default]
    Locked,
    /// Omitted entirely for non-members.
    Hidden,
}

/// A single zone definition. Mirrors the serde representation of
/// `nostr_bbs_config::schema::Zone` so `forum.toml` `[[zones]]` entries
/// serialise straight into `ZONE_CONFIG` JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    /// Slug identifier (`"public"`, `"friends"`, `"family"`, `"business"`, ...).
    pub id: String,
    /// Display name (surfaced on the tile).
    #[serde(default)]
    pub display_name: String,
    /// Cohorts required to READ. Empty + `Public` ⇒ unauthenticated read.
    #[serde(default)]
    pub required_cohorts: Vec<String>,
    /// Cohorts required to WRITE; falls back to `required_cohorts` when absent.
    #[serde(default)]
    pub write_cohorts: Option<Vec<String>>,
    /// Banner image rendered on the (possibly locked) tile.
    #[serde(default)]
    pub banner_image_url: Option<String>,
    /// Visibility policy for non-members.
    #[serde(default)]
    pub visibility: ZoneVisibility,
    /// Client-side NIP-44 encryption flag (relay only records it).
    #[serde(default)]
    pub encrypted: bool,
}

impl Zone {
    /// Effective write cohorts: explicit `write_cohorts`, else `required_cohorts`.
    pub fn effective_write_cohorts(&self) -> &[String] {
        match &self.write_cohorts {
            Some(w) => w.as_slice(),
            None => self.required_cohorts.as_slice(),
        }
    }
}

/// The full set of zone definitions parsed from `ZONE_CONFIG`.
#[derive(Debug, Clone, Default)]
pub struct ZoneConfig {
    zones: Vec<Zone>,
}

impl ZoneConfig {
    /// Load zone definitions from the `ZONE_CONFIG` env var (JSON array). An
    /// absent or malformed value yields an empty config (deny-by-default for
    /// non-admins). This is the single source of zone truth in the worker.
    pub fn load(env: &Env) -> Self {
        let raw = match env.var("ZONE_CONFIG") {
            Ok(v) => v.to_string(),
            Err(_) => return Self::default(),
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::default();
        }
        match serde_json::from_str::<Vec<Zone>>(trimmed) {
            Ok(zones) => Self { zones },
            Err(_) => Self::default(),
        }
    }

    /// Look up a zone definition by id.
    pub fn get(&self, id: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.id == id)
    }

    /// Whether a zone with this id exists in config.
    pub fn is_known(&self, id: &str) -> bool {
        self.get(id).is_some()
    }

    /// Whether the zone is readable with no auth and no cohort membership.
    /// True only for `Public` zones with no required read cohorts.
    pub fn is_public_read(&self, id: &str) -> bool {
        self.get(id)
            .map(|z| z.visibility == ZoneVisibility::Public && z.required_cohorts.is_empty())
            .unwrap_or(false)
    }

    /// Whether the channel definitions (kind-40) for this zone should be served
    /// to a non-member. `Public` and `Locked` zones expose their tile (defs);
    /// `Hidden` zones are omitted entirely. Admins/members are gated elsewhere.
    pub fn defs_visible_to_nonmember(&self, id: &str) -> bool {
        self.get(id)
            .map(|z| z.visibility != ZoneVisibility::Hidden)
            .unwrap_or(false)
    }

    /// Decide read access for a member given their cohort list. Membership in
    /// any `required_cohorts` entry grants read; an empty requirement grants
    /// read only when the zone is `Public`. Admin bypass is the caller's job.
    pub fn cohorts_can_read(&self, id: &str, cohorts: &[String]) -> bool {
        match self.get(id) {
            None => false,
            Some(z) => {
                if z.required_cohorts.is_empty() {
                    z.visibility == ZoneVisibility::Public
                } else {
                    cohorts.iter().any(|c| z.required_cohorts.contains(c))
                }
            }
        }
    }

    /// Decide write access for a member given their cohort list, using the
    /// effective write cohorts (write_cohorts ?? required_cohorts). An empty
    /// effective set denies all non-admins (writes are never anonymous).
    pub fn cohorts_can_write(&self, id: &str, cohorts: &[String]) -> bool {
        match self.get(id) {
            None => false,
            Some(z) => {
                let req = z.effective_write_cohorts();
                if req.is_empty() {
                    false
                } else {
                    cohorts.iter().any(|c| req.contains(&c.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ZoneConfig {
        let json = r#"[
            {"id":"public","display_name":"Public","required_cohorts":[],"write_cohorts":["friends"],"visibility":"public"},
            {"id":"friends","display_name":"Friends","required_cohorts":["friends"],"visibility":"locked"},
            {"id":"family","display_name":"Family","required_cohorts":["family"],"visibility":"locked","encrypted":true},
            {"id":"business","display_name":"Business","required_cohorts":["business"],"visibility":"hidden"}
        ]"#;
        ZoneConfig {
            zones: serde_json::from_str(json).unwrap(),
        }
    }

    #[test]
    fn public_zone_is_unauth_readable_but_not_unauth_writable() {
        let c = cfg();
        assert!(c.is_public_read("public"));
        // empty cohorts => read ok (public), but write requires "friends"
        assert!(c.cohorts_can_read("public", &[]));
        assert!(!c.cohorts_can_write("public", &[]));
        assert!(c.cohorts_can_write("public", &["friends".to_string()]));
    }

    #[test]
    fn locked_zone_gates_content_but_shows_tile() {
        let c = cfg();
        assert!(!c.is_public_read("friends"));
        assert!(c.defs_visible_to_nonmember("friends")); // tile shown
        assert!(!c.cohorts_can_read("friends", &[])); // content withheld
        assert!(c.cohorts_can_read("friends", &["friends".to_string()]));
    }

    #[test]
    fn hidden_zone_omits_tile_for_nonmembers() {
        let c = cfg();
        assert!(!c.defs_visible_to_nonmember("business"));
        assert!(!c.cohorts_can_read("business", &[]));
        assert!(c.cohorts_can_read("business", &["business".to_string()]));
    }

    #[test]
    fn write_falls_back_to_required_when_unset() {
        let c = cfg();
        // friends zone has no write_cohorts => falls back to required_cohorts
        assert!(c.cohorts_can_write("friends", &["friends".to_string()]));
        assert!(!c.cohorts_can_write("friends", &["family".to_string()]));
    }

    #[test]
    fn unknown_zone_denies_all() {
        let c = cfg();
        assert!(!c.cohorts_can_read("nope", &["friends".to_string()]));
        assert!(!c.cohorts_can_write("nope", &["friends".to_string()]));
        assert!(!c.is_public_read("nope"));
        assert!(!c.defs_visible_to_nonmember("nope"));
    }
}
