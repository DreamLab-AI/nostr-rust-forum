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
//!     "display_name": "Public",
//!     "required_cohorts": [],
//!     "write_cohorts": ["friends"],
//!     "banner_image_url": "/images/heroes/public-hero.webp",
//!     "visibility": "public",
//!     "encrypted": false,
//!     "accent_hex": "#22c55e"
//!   },
//!   { "id": "friends",  "display_name": "Friends",  "required_cohorts": ["friends"],
//!     "banner_image_url": "/images/heroes/friends-hero.webp",     "visibility": "locked" },
//!   { "id": "family",   "display_name": "Family",   "required_cohorts": ["family"],
//!     "banner_image_url": "/images/heroes/family-hero.webp",      "visibility": "locked", "encrypted": true },
//!   { "id": "business", "display_name": "Business", "required_cohorts": ["business"],
//!     "banner_image_url": "/images/heroes/business-hero.webp",    "visibility": "locked" }
//! ]
//! ```
//!
//! `accent_hex` (issue #34) is optional per-zone; when present it overrides
//! the built-in colour for that zone via
//! [`crate::utils::zone_theme::zone_accent_style_cfg`]. Omitted zones keep the
//! built-in [`crate::utils::zone_theme::zone_theme`] default.
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
    /// Stable internal identifier (`"public"`, `"friends"`, `"family"`,
    /// `"business"`). Sections (`section` tag) and cohort rules resolve against
    /// this — it never changes once deployed. The URL segment prefers
    /// [`slug`](Self::slug) when set.
    pub id: String,
    /// Optional URL slug (issue #45). When present the client addresses this
    /// zone as `/<slug>` instead of `/forums/<id>`; [`id`](Self::id) remains the
    /// resolution key. `ZONE_CONFIG` may omit it. Mirrors
    /// `nostr_bbs_config::schema::Zone::slug`.
    #[serde(default)]
    pub slug: Option<String>,
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
    /// Operator-configured accent colour override (issue #34), e.g. `"#22c55e"`.
    /// Validated upstream as a CSS hex colour by `nostr_bbs_config::validate`.
    /// When absent, rendering falls back to the built-in
    /// [`crate::utils::zone_theme::zone_theme`] palette for this zone id.
    #[serde(default)]
    pub accent_hex: Option<String>,
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

/// URL slug for a zone: its explicit `slug` when set and non-empty, else its
/// `id` (issue #45).
///
/// This is the segment the client puts in the address bar (`/<slug>`). The `id`
/// remains the stable key for section/cohort resolution — only the URL uses the
/// slug — so this is a pure display-of-URL concern.
pub fn zone_path_for_id(zone_id: &str) -> String {
    let zones = load_zones();
    zones
        .iter()
        .find(|z| z.id == zone_id)
        .map(|z| zone_slug(z).to_string())
        .unwrap_or_else(|| zone_id.to_string())
}

pub fn zone_slug(z: &Zone) -> &str {
    match z.slug.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => &z.id,
    }
}

/// Resolve a URL path segment (the `:category` param) to a zone by slug OR id,
/// case-insensitively, with slug taking precedence (issue #45).
///
/// New `/<slug>` links pass the slug; legacy `/forums/<id>` links pass the id;
/// both resolve here so navigation never regresses during the rename. Slug is
/// tried first so it wins any (config-invalid but defensively-handled) overlap
/// with another zone's id. Sections/cohorts continue to key on [`Zone::id`].
pub fn resolve_zone_param<'a>(param: &str, zones: &'a [Zone]) -> Option<&'a Zone> {
    let needle = param.to_lowercase();
    zones
        .iter()
        .find(|z| {
            z.slug
                .as_deref()
                .is_some_and(|s| s.to_lowercase() == needle)
        })
        .or_else(|| zones.iter().find(|z| z.id.to_lowercase() == needle))
}

/// Resolve a channel's `section` tag to the id of the owning config zone.
///
/// Channels carry a free-form `section` tag (e.g. `"family-events"`). With
/// config-driven zones the relationship is by prefix/exact match against the
/// live zone ids: a section belongs to the zone whose id it equals or is
/// prefixed by (`"<zone>-..."`). Falls back to the first zone so channels never
/// silently disappear from the index.
///
/// This is the single canonical resolver — previously copied verbatim into
/// `forums.rs`, `section.rs`, `category.rs` and `channel.rs` (audit M1), and
/// the inverse predicate [`section_routes_to_zone`] is derived from it.
pub fn section_to_zone(section: &str, zones: &[Zone]) -> Option<String> {
    let sec = section.to_lowercase();
    // Exact id match.
    if let Some(z) = zones.iter().find(|z| z.id.to_lowercase() == sec) {
        return Some(z.id.clone());
    }
    // Prefix match: "<zone-id>-suffix".
    if let Some(z) = zones
        .iter()
        .find(|z| sec.starts_with(&format!("{}-", z.id.to_lowercase())))
    {
        return Some(z.id.clone());
    }
    // Catch-all: first zone so unrouted channels remain visible.
    zones.first().map(|z| z.id.clone())
}

/// Whether a channel's `section` tag routes to the given zone URL param.
///
/// Derived from [`section_to_zone`]: a section routes to `category_slug` when
/// the canonical resolver maps it to that zone (case-insensitively). The param
/// may be the zone's URL slug (short URLs, issue #45) or its legacy id — it is
/// canonicalised to the zone ID before comparison, since `section_to_zone`
/// always yields ids. An empty `category_slug` matches everything (the
/// un-scoped/legacy lookup contract).
pub fn section_routes_to_zone(section: &str, category_slug: &str, zones: &[Zone]) -> bool {
    if category_slug.is_empty() {
        return true;
    }
    let cat = resolve_zone_param(category_slug, zones)
        .map(|z| z.id.to_lowercase())
        .unwrap_or_else(|| category_slug.to_lowercase());
    section_to_zone(section, zones)
        .map(|z| z.to_lowercase() == cat)
        .unwrap_or(false)
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
            slug: None,
            display_name: "Home".to_string(),
            required_cohorts: vec![],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/members-hero.webp".to_string()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
            accent_hex: None,
        },
        Zone {
            id: "members".to_string(),
            slug: None,
            display_name: "Members".to_string(),
            required_cohorts: vec!["members".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/ai-commander-week.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: false,
            accent_hex: None,
        },
        Zone {
            id: "private".to_string(),
            slug: None,
            display_name: "Private".to_string(),
            required_cohorts: vec!["private".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/corporate-immersive.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: false,
            accent_hex: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(id: &str) -> Zone {
        Zone {
            id: id.to_string(),
            slug: None,
            display_name: String::new(),
            required_cohorts: vec![],
            write_cohorts: None,
            banner_image_url: None,
            visibility: ZoneVisibility::Public,
            encrypted: false,
            accent_hex: None,
        }
    }

    fn zone_with_slug(id: &str, slug: Option<&str>) -> Zone {
        Zone {
            slug: slug.map(str::to_string),
            ..zone(id)
        }
    }

    fn sample_zones() -> Vec<Zone> {
        vec![
            zone("public"),
            zone("friends"),
            zone("family"),
            zone("business"),
        ]
    }

    #[test]
    fn section_to_zone_exact_match() {
        let zones = sample_zones();
        assert_eq!(
            section_to_zone("family", &zones),
            Some("family".to_string())
        );
    }

    #[test]
    fn section_to_zone_prefix_match() {
        let zones = sample_zones();
        assert_eq!(
            section_to_zone("family-events", &zones),
            Some("family".to_string())
        );
        assert_eq!(
            section_to_zone("BUSINESS-Deals", &zones),
            Some("business".to_string())
        );
    }

    #[test]
    fn section_to_zone_falls_back_to_first() {
        let zones = sample_zones();
        assert_eq!(
            section_to_zone("totally-unknown", &zones),
            Some("public".to_string())
        );
        assert_eq!(section_to_zone("anything", &[]), None);
    }

    #[test]
    fn routes_to_zone_is_derived_from_resolver() {
        let zones = sample_zones();
        // For any (section, category) the predicate must agree with the
        // resolver (case-insensitively) — the derivation invariant.
        for section in ["family", "family-events", "business-deals", "stray"] {
            for cat in ["public", "friends", "family", "business"] {
                let expected = section_to_zone(section, &zones)
                    .map(|z| z.eq_ignore_ascii_case(cat))
                    .unwrap_or(false);
                assert_eq!(
                    section_routes_to_zone(section, cat, &zones),
                    expected,
                    "section={section} cat={cat}"
                );
            }
        }
    }

    #[test]
    fn routes_to_zone_empty_category_matches_everything() {
        let zones = sample_zones();
        assert!(section_routes_to_zone("family-events", "", &zones));
        assert!(section_routes_to_zone("anything", "", &zones));
    }

    #[test]
    fn accent_hex_deserializes_when_present() {
        // r##"…"##: the inner `"accent_hex":"#…"` contains `"#`, which would
        // otherwise close an r#"…"# raw string early.
        let json = r##"[{"id":"public","display_name":"Landing","accent_hex":"#22c55e"}]"##;
        let zones: Vec<Zone> = serde_json::from_str(json).unwrap();
        assert_eq!(zones[0].accent_hex.as_deref(), Some("#22c55e"));
    }

    #[test]
    fn accent_hex_defaults_to_none_when_absent() {
        let json = r#"[{"id":"friends","display_name":"Friends"}]"#;
        let zones: Vec<Zone> = serde_json::from_str(json).unwrap();
        assert_eq!(zones[0].accent_hex, None);
    }

    // -- Zone URL slugs (issue #45) -----------------------------------------

    #[test]
    fn zone_slug_uses_slug_when_present() {
        let z = zone_with_slug("business", Some("dreamlab"));
        assert_eq!(zone_slug(&z), "dreamlab");
    }

    #[test]
    fn zone_slug_falls_back_to_id() {
        assert_eq!(zone_slug(&zone_with_slug("family", None)), "family");
        // An empty slug also falls back to the id.
        assert_eq!(zone_slug(&zone_with_slug("family", Some(""))), "family");
    }

    #[test]
    fn resolve_zone_param_matches_slug() {
        let zones = vec![
            zone_with_slug("business", Some("dreamlab")),
            zone_with_slug("family", None),
        ];
        assert_eq!(
            resolve_zone_param("dreamlab", &zones).map(|z| z.id.as_str()),
            Some("business")
        );
    }

    #[test]
    fn resolve_zone_param_matches_id_for_legacy_links() {
        let zones = vec![
            zone_with_slug("business", Some("dreamlab")),
            zone_with_slug("family", None),
        ];
        // Old /forums/<id> links still resolve by id.
        assert_eq!(
            resolve_zone_param("business", &zones).map(|z| z.id.as_str()),
            Some("business")
        );
        assert_eq!(
            resolve_zone_param("family", &zones).map(|z| z.id.as_str()),
            Some("family")
        );
    }

    #[test]
    fn resolve_zone_param_is_case_insensitive() {
        let zones = vec![zone_with_slug("business", Some("dreamlab"))];
        assert_eq!(
            resolve_zone_param("DreamLab", &zones).map(|z| z.id.as_str()),
            Some("business")
        );
        assert_eq!(
            resolve_zone_param("BUSINESS", &zones).map(|z| z.id.as_str()),
            Some("business")
        );
    }

    #[test]
    fn resolve_zone_param_slug_takes_precedence_over_id() {
        // param equals zone A's id AND zone B's slug — slug wins (defensive; the
        // config validator forbids this overlap, but the resolver stays
        // deterministic regardless).
        let zones = vec![
            zone_with_slug("welcome", None),           // id "welcome"
            zone_with_slug("public", Some("welcome")), // slug "welcome"
        ];
        assert_eq!(
            resolve_zone_param("welcome", &zones).map(|z| z.id.as_str()),
            Some("public")
        );
    }

    #[test]
    fn resolve_zone_param_unknown_is_none() {
        let zones = vec![zone_with_slug("business", Some("dreamlab"))];
        assert!(resolve_zone_param("nope", &zones).is_none());
    }

    #[test]
    fn section_routes_to_zone_accepts_slug_param() {
        // Regression (issue #45 rollout): "public-intros" routes to zone id
        // "public"; the URL param may be the slug "welcome" and must still
        // match after canonicalisation. Legacy id and unknown params keep
        // their old behaviour.
        let zones = vec![zone_with_slug("public", Some("welcome")), zone("friends")];
        assert!(section_routes_to_zone("public-intros", "welcome", &zones));
        assert!(section_routes_to_zone("public-intros", "public", &zones));
        assert!(!section_routes_to_zone("friends-music", "welcome", &zones));
        assert!(section_routes_to_zone("anything", "", &zones));
        assert!(!section_routes_to_zone("public-intros", "nope", &zones));
    }
}
