//! Config-driven zone definitions for the client.
//!
//! Phase A made zones config-driven server-side: the relay reads a `ZONE_CONFIG`
//! JSON array (the serde shape of `nostr_bbs_config::schema::Zone`) and enforces
//! real access. This module is the *client-side mirror* of that config, used
//! purely for UX — deciding which section tiles to render and which to grey out.
//! The relay remains the security boundary (ADR-022); a locked tile the client
//! shows but cannot open is fine.
//!
//! ## Delivery
//!
//! The same `ZONE_CONFIG` JSON the deploy hands the relay is also surfaced to the
//! client through the already-injected `window.__ENV__` global, under the key
//! `ZONE_CONFIG`. The client reads it once at module load. No new relay route,
//! no extra fetch. If the key is absent or unparseable, we fall back to the
//! legacy hardcoded 3-zone list so existing deployments do not regress.
//!
//! ### Expected `window.__ENV__.ZONE_CONFIG` shape
//!
//! A JSON **string** (so it survives env-var injection) whose parsed value is an
//! array of zone objects matching the relay's serde shape:
//!
//! ```jsonc
//! [
//!   {
//!     "id": "public",
//!     "display_name": "MiniMooNoir",
//!     "required_cohorts": [],
//!     "write_cohorts": ["friends"],
//!     "banner_image_url": "/images/heroes/minimoonoir-hero.webp",
//!     "visibility": "public",
//!     "encrypted": false
//!   },
//!   { "id": "friends",  "display_name": "Friends",  "required_cohorts": ["friends"],
//!     "banner_image_url": "/images/heroes/minimoonoir-hero.webp", "visibility": "locked" },
//!   { "id": "family",   "display_name": "Family",   "required_cohorts": ["family"],
//!     "banner_image_url": "/images/heroes/family-hero.webp",      "visibility": "locked", "encrypted": true },
//!   { "id": "business", "display_name": "Business", "required_cohorts": ["business"],
//!     "banner_image_url": "/images/heroes/dreamlab-hero.webp",    "visibility": "locked" }
//! ]
//! ```
//!
//! `ZONE_CONFIG` may also be supplied already-parsed (a JS array) rather than a
//! string; both are accepted.

use serde::Deserialize;

/// Visibility policy for non-members. Mirrors
/// `nostr_bbs_config::schema::ZoneVisibility` (lowercase serde).
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
/// `nostr_bbs_config::schema::Zone`.
#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    /// Slug identifier (`"public"`, `"friends"`, `"family"`, `"business"`).
    pub id: String,
    /// Display name surfaced on the tile (also used as banner `alt`).
    #[serde(default)]
    pub display_name: String,
    /// Cohorts required to READ. Empty + `Public` ⇒ unauthenticated read.
    #[serde(default)]
    pub required_cohorts: Vec<String>,
    /// Cohorts required to WRITE; falls back to `required_cohorts` when absent.
    #[serde(default)]
    #[allow(dead_code)]
    pub write_cohorts: Option<Vec<String>>,
    /// Banner image rendered on the (possibly locked) tile.
    #[serde(default)]
    pub banner_image_url: Option<String>,
    /// Visibility policy for non-members.
    #[serde(default)]
    pub visibility: ZoneVisibility,
    /// Client-side NIP-44 encryption flag (UX hint only).
    #[serde(default)]
    #[allow(dead_code)]
    pub encrypted: bool,
}

impl Zone {
    /// Whether a user holding `user_cohorts` is a member of this zone.
    ///
    /// A zone with empty `required_cohorts` requires no cohort (membership is
    /// driven by visibility/auth elsewhere); admins are handled by the caller.
    pub fn is_member(&self, user_cohorts: &[String]) -> bool {
        if self.required_cohorts.is_empty() {
            return true;
        }
        self.required_cohorts
            .iter()
            .any(|req| user_cohorts.iter().any(|c| c == req))
    }

    /// Best-effort display name: explicit `display_name`, else humanised `id`.
    pub fn label(&self) -> String {
        if self.display_name.trim().is_empty() {
            humanize(&self.id)
        } else {
            self.display_name.clone()
        }
    }
}

/// Read and parse the zone config from `window.__ENV__.ZONE_CONFIG`.
///
/// Accepts either a JSON string or an already-parsed JS array. Returns the
/// legacy fallback list when the key is absent or unparseable so navigation
/// never regresses.
pub fn load_zones() -> Vec<Zone> {
    match read_zone_config_json() {
        Some(json) => match serde_json::from_str::<Vec<Zone>>(&json) {
            Ok(zones) if !zones.is_empty() => zones,
            Ok(_) => fallback_zones(),
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[zones] ZONE_CONFIG parse failed ({e}); using fallback").into(),
                );
                fallback_zones()
            }
        },
        None => fallback_zones(),
    }
}

/// Extract `window.__ENV__.ZONE_CONFIG` as a JSON string.
///
/// `ZONE_CONFIG` is typically injected as a JSON string (env vars are strings).
/// If a deploy injects an already-parsed array/object, we re-stringify it.
fn read_zone_config_json() -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let val = js_sys::Reflect::get(&env, &"ZONE_CONFIG".into()).ok()?;
    if val.is_undefined() || val.is_null() {
        return None;
    }
    if let Some(s) = val.as_string() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(s);
    }
    // Already-parsed JS value: re-stringify it back to JSON.
    js_sys::JSON::stringify(&val)
        .ok()
        .and_then(|s| s.as_string())
}

/// Humanise a zone slug: `"public"` → `"Public"`, `"ai-agents"` → `"Ai Agents"`.
fn humanize(id: &str) -> String {
    id.split(['-', '_'])
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Legacy fallback zones, used when `ZONE_CONFIG` is unavailable. Mirrors the
/// previous hardcoded `home`/`members`/`private` list, expressed in the new
/// config shape so the renderer has a single code path.
fn fallback_zones() -> Vec<Zone> {
    vec![
        Zone {
            id: "home".to_string(),
            display_name: "Home".to_string(),
            required_cohorts: vec![],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/members-hero.webp".to_string()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
        },
        Zone {
            id: "members".to_string(),
            display_name: "Members".to_string(),
            required_cohorts: vec!["members".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/ai-commander-week.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: false,
        },
        Zone {
            id: "private".to_string(),
            display_name: "Minimoonoir".to_string(),
            required_cohorts: vec!["private".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/corporate-immersive.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: false,
        },
    ]
}
