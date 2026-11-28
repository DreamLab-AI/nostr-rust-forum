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
//! generic 4-zone list (`public`/`friends`/`family`/`business`, matching the
//! example below) so a vanilla/dev deployment still renders sensibly.
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
    /// End-to-end encrypt this zone's messages (ADR-2016). Effective only when
    /// the deployment gate `ENCRYPTION_ENABLED` is `"true"`; see
    /// [`crate::zone_crypto::encryption_enabled`].
    #[serde(default)]
    pub encrypted: bool,
    /// Whether `agent`-cohort members may be granted this zone's key
    /// (ADR-2016). Default `false`.
    #[serde(default)]
    pub agent_keys: bool,
    /// Oldest epoch of this zone's key that grants may still hand out as
    /// history. Keys held for earlier epochs (for example a previous
    /// deployment's keys still in an admin's browser) are never sent. The
    /// newest held key is always grantable. Absent: no floor.
    #[serde(default)]
    pub history_from_epoch: Option<u32>,
    /// Operator-configured accent colour override (issue #34), e.g. `"#22c55e"`.
    /// Validated upstream as a CSS hex colour by `nostr_bbs_config::validate`.
    /// When absent, rendering falls back to the built-in
    /// [`crate::utils::zone_theme::zone_theme`] palette for this zone id.
    #[serde(default)]
    pub accent_hex: Option<String>,
    /// Operator-configured priority order for this zone's section tiles, by
    /// full `section` id (e.g. `"zone2-rants"`). Sections listed here render
    /// FIRST, in this order (so an operator can pin a primary section to the top
    /// of the zone tile); any section not listed falls to alphabetical order
    /// after them. Empty (default) ⇒ the historic all-alphabetical order.
    /// Read from `ZONE_CONFIG`; ignored by the relay/auth workers (a pure
    /// client rendering concern).
    #[serde(default)]
    pub section_order: Vec<String>,
    /// Whether this zone offers the collaborative kanban task board
    /// (`[[zones]] kanban = true`). Pure UX flag — the relay gates the board
    /// kinds by zone tag regardless.
    #[serde(default)]
    pub kanban: bool,
    /// Search mode (`"off" | "server" | "sealed"`), projected from
    /// `nostr_bbs_config::schema::Zone::search`. Absent ⇒ derived by
    /// [`Zone::effective_search`] exactly as the config does.
    #[serde(default)]
    pub search: Option<String>,
    /// Kind-40 channel ids pinned to this zone (ADR-2037), projected from
    /// `nostr_bbs_config::schema::Zone::channels`. A pinned channel belongs to
    /// this zone whatever its signed `section` tag says; see
    /// [`pinned_zone_for`] and [`effective_section`]. Empty (default): no pins.
    /// A value of the wrong type reads as no pins rather than failing the
    /// whole `ZONE_CONFIG` (which would drop the client to the fallback zone
    /// list); the relay fails such pins closed.
    #[serde(default, deserialize_with = "lenient_channels")]
    pub channels: Vec<String>,
}

/// `channels` as an array of strings; any other shape (a bare string, an
/// array holding non-strings, `null`) yields no pins.
fn lenient_channels<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(match v {
        serde_json::Value::Array(a) if a.iter().all(serde_json::Value::is_string) => a
            .into_iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    })
}

impl Zone {
    /// The search mode in force: configured, else encrypted → `sealed`,
    /// public → `off`, otherwise `server` (mirrors
    /// `nostr_bbs_config::schema::Zone::effective_search`). An unknown value
    /// reads as `off`.
    pub fn effective_search(&self) -> &'static str {
        match self.search.as_deref() {
            Some("sealed") if self.encrypted => "sealed",
            Some("server") if !self.encrypted => "server",
            Some(_) => "off",
            None if self.encrypted => "sealed",
            None if self.visibility == ZoneVisibility::Public => "off",
            None => "server",
        }
    }
}

impl Zone {
    /// Whether a user holding `user_cohorts` is a member of this zone.
    ///
    /// Mirrors the relay's read rule (`ZoneConfig::cohorts_can_read`): holding
    /// any of `required_cohorts` makes a member, and a zone with no required
    /// cohorts has members only when it is `Public` (an empty list on a
    /// `Locked` or `Hidden` zone means admins only). Admins are handled by the
    /// caller.
    pub fn is_member(&self, user_cohorts: &[String]) -> bool {
        if self.required_cohorts.is_empty() {
            return self.visibility == ZoneVisibility::Public;
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
    configured_zones().unwrap_or_else(fallback_zones)
}

/// The zones the deployment actually configured, or `None` when
/// `ZONE_CONFIG` is absent, empty or unparseable (the generic kit default,
/// where [`load_zones`] substitutes the built-in fallback list).
///
/// Admin tooling that must tell "this deployment declares its own zones" from
/// "no config, using placeholders" reads this rather than [`load_zones`].
pub fn configured_zones() -> Option<Vec<Zone>> {
    match read_zone_config_json() {
        Some(json) => match serde_json::from_str::<Vec<Zone>>(&json) {
            Ok(zones) if !zones.is_empty() => Some(zones),
            Ok(_) => None,
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[zones] ZONE_CONFIG parse failed ({e}); using fallback").into(),
                );
                None
            }
        },
        None => None,
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

/// The zone that pins `channel_id` through its `channels` list (ADR-2037),
/// or `None` when no zone does.
///
/// Ids compare case-insensitively and entries that are not 64 hex digits are
/// skipped, as the relay does. Config validation refuses a channel pinned by
/// two zones; should a config do it anyway, the first such zone in config
/// order is returned here, while the relay refuses every read and write of
/// the channel, so the result is still never more open than the relay.
pub fn pinned_zone_for<'a>(channel_id: &str, zones: &'a [Zone]) -> Option<&'a Zone> {
    zones.iter().find(|z| {
        z.channels.iter().map(|c| c.trim()).any(|c| {
            c.len() == 64
                && c.bytes().all(|b| b.is_ascii_hexdigit())
                && c.eq_ignore_ascii_case(channel_id)
        })
    })
}

/// The section a channel is routed by: the raw signed `section` tag, unless a
/// zone pins the channel (ADR-2037) and the tag does not already name that
/// zone, in which case the pinning zone's id.
///
/// Every resolver ([`section_to_zone`], [`zone_id_for_section`],
/// [`media_target_for_section`], the forum index, search and the BBS views)
/// reads `ChannelMeta::section`, which holds this value, so they all follow a
/// pin with no change of their own. The pinned zone's id is used verbatim so
/// it resolves by exact match, never by a prefix that another zone might
/// share. With no pins this is `section_tag` unchanged.
pub fn effective_section(channel_id: &str, section_tag: &str, zones: &[Zone]) -> String {
    match pinned_zone_for(channel_id, zones) {
        Some(z) if zone_id_for_section(section_tag, zones).as_deref() != Some(z.id.as_str()) => {
            z.id.clone()
        }
        _ => section_tag.to_string(),
    }
}

/// The zone the admin "Bind to zone" action (and bind-on-create) would write
/// to the relay's `channel_zones` for a channel, or `None` when there is
/// nothing to bind.
///
/// A pinned channel (ADR-2037) is never bound: the pin already decides its
/// zone on the relay, and a `channel_zones` row written now would outlive the
/// pin, so removing the pin later would not hand the channel back to the zone
/// its tag names. An unpinned channel binds to the zone its signed `section`
/// tag names strictly ([`zone_id_for_section`]).
pub fn bind_zone_for(channel_id: &str, section_tag: &str, zones: &[Zone]) -> Option<String> {
    if pinned_zone_for(channel_id, zones).is_some() {
        return None;
    }
    zone_id_for_section(section_tag, zones)
}

/// Pod container for images attached in a channel with this `section`: the
/// strict zone ([`zone_id_for_section`]) when the deployment declares zones,
/// `Unzoned` (upload refused) when it declares zones but the section names
/// none, and `Public` when it declares no zones at all.
pub fn media_target_for_section(
    section: Option<&str>,
) -> crate::utils::restricted_media::MediaTarget {
    let ids: Option<Vec<String>> =
        configured_zones().map(|zs| zs.into_iter().map(|z| z.id).collect());
    crate::utils::restricted_media::media_target_for(section, ids.as_deref())
}

/// Strict counterpart of [`section_to_zone`]: the id of the configured zone a
/// section id belongs to by exact match or `<zone-id>-` prefix, and `None`
/// otherwise.
///
/// [`section_to_zone`] falls back to the first zone so a stray channel never
/// vanishes from the index. That is right for display and wrong for anything
/// that writes: binding a channel on the relay (`channel_zones`) changes who may
/// read and write it, so only a section that names its zone may be bound.
pub fn zone_id_for_section(section: &str, zones: &[Zone]) -> Option<String> {
    let sec = section.to_lowercase();
    zones
        .iter()
        .find(|z| {
            let id = z.id.to_lowercase();
            sec == id || sec.starts_with(&format!("{id}-"))
        })
        .map(|z| z.id.clone())
}

/// Compare two section ids for zone-tile ordering. An operator-pinned section
/// (present in `section_order`, e.g. a zone's `[[zones]].section_order`) sorts
/// before an unpinned one; two pinned sections keep their configured order; two
/// unpinned sections sort alphabetically. This is the primary-section-first
/// rule the zone tile uses so an operator can float a section (e.g.
/// `"zone2-rants"`) to the top rather than accept pure alphabetical order.
pub fn section_cmp(a: &str, b: &str, section_order: &[String]) -> std::cmp::Ordering {
    let rank = |sid: &str| section_order.iter().position(|s| s == sid);
    match (rank(a), rank(b)) {
        (Some(ra), Some(rb)) => ra.cmp(&rb),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.cmp(b),
    }
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
/// generic 4-zone model documented in the module-level `ZONE_CONFIG` example
/// above (`public`/`friends`/`family`/`business`), expressed in the new config
/// shape so the renderer has a single code path. These ids are the same ones
/// exercised by `zone_theme`/`zone_hero`'s `"public"` matchers and by this
/// module's own tests (`sample_zones()`), so a vanilla/dev deployment with no
/// `ZONE_CONFIG` still behaves consistently with the rest of the client.
fn fallback_zones() -> Vec<Zone> {
    vec![
        Zone {
            id: "public".to_string(),
            slug: None,
            display_name: "Public".to_string(),
            required_cohorts: vec![],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/public-hero.webp".to_string()),
            visibility: ZoneVisibility::Public,
            encrypted: false,
            agent_keys: false,
            history_from_epoch: None,
            accent_hex: None,
            section_order: Vec::new(),
            kanban: false,
            search: None,
            channels: Vec::new(),
        },
        Zone {
            id: "friends".to_string(),
            slug: None,
            display_name: "Friends".to_string(),
            required_cohorts: vec!["friends".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/friends-hero.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: false,
            agent_keys: false,
            history_from_epoch: None,
            accent_hex: None,
            section_order: Vec::new(),
            kanban: false,
            search: None,
            channels: Vec::new(),
        },
        Zone {
            id: "family".to_string(),
            slug: None,
            display_name: "Family".to_string(),
            required_cohorts: vec!["family".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/family-hero.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: true,
            agent_keys: false,
            history_from_epoch: None,
            accent_hex: None,
            section_order: Vec::new(),
            kanban: false,
            search: None,
            channels: Vec::new(),
        },
        Zone {
            id: "business".to_string(),
            slug: None,
            display_name: "Business".to_string(),
            required_cohorts: vec!["business".to_string()],
            write_cohorts: None,
            banner_image_url: Some("/images/heroes/business-hero.webp".to_string()),
            visibility: ZoneVisibility::Locked,
            encrypted: false,
            agent_keys: false,
            history_from_epoch: None,
            accent_hex: None,
            section_order: Vec::new(),
            kanban: false,
            search: None,
            channels: Vec::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_cmp_pins_configured_first_then_alphabetical() {
        // The Minimoonoir case: pin rants first; the rest fall alphabetical.
        let order = vec!["zone2-rants".to_string()];
        let mut v = vec![
            "zone2-photos",
            "zone2-music",
            "zone2-rants",
            "zone2-fairfield-events",
        ];
        v.sort_by(|a, b| section_cmp(a, b, &order));
        assert_eq!(
            v,
            vec![
                "zone2-rants",
                "zone2-fairfield-events",
                "zone2-music",
                "zone2-photos"
            ]
        );

        // Empty order ⇒ pure alphabetical (historic behaviour, unchanged).
        let none: Vec<String> = vec![];
        let mut w = vec!["b", "a", "c"];
        w.sort_by(|a, b| section_cmp(a, b, &none));
        assert_eq!(w, vec!["a", "b", "c"]);

        // Several pinned sections keep their CONFIGURED order, not alphabetical.
        let order2 = vec!["z-two".to_string(), "a-one".to_string()];
        let mut x = vec!["a-one", "m-mid", "z-two"];
        x.sort_by(|a, b| section_cmp(a, b, &order2));
        assert_eq!(x, vec!["z-two", "a-one", "m-mid"]);
    }

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
            agent_keys: false,
            history_from_epoch: None,
            accent_hex: None,
            section_order: Vec::new(),
            kanban: false,
            search: None,
            channels: Vec::new(),
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
    fn zone_id_for_section_is_strict_where_section_to_zone_falls_back() {
        let zones = sample_zones();
        assert_eq!(
            zone_id_for_section("family-events", &zones),
            Some("family".to_string())
        );
        assert_eq!(
            zone_id_for_section("Family", &zones),
            Some("family".to_string())
        );
        // A legacy section names no configured zone: no binding.
        assert_eq!(zone_id_for_section("home-lobby", &zones), None);
        assert_eq!(zone_id_for_section("familyevents", &zones), None);
        // The display resolver still catches it, by design.
        assert_eq!(
            section_to_zone("home-lobby", &zones),
            Some("public".to_string())
        );
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

    // -- ADR-2037 channel pins and the empty-cohort rule --------------------

    const PIN: &str = "9999999999999999999999999999999999999999999999999999999999999999";
    const LOOSE: &str = "8888888888888888888888888888888888888888888888888888888888888888";

    /// "open" is the zone the channel's tag names; "staff" pins it.
    fn pinned_zones() -> Vec<Zone> {
        vec![
            Zone {
                required_cohorts: vec!["members".into()],
                visibility: ZoneVisibility::Locked,
                encrypted: true,
                ..zone("open")
            },
            Zone {
                visibility: ZoneVisibility::Hidden,
                encrypted: true,
                channels: vec![PIN.to_string()],
                ..zone("staff")
            },
        ]
    }

    #[test]
    fn channels_deserialise_and_default_to_empty() {
        let zones: Vec<Zone> = serde_json::from_str(&format!(
            r#"[{{"id":"open"}},{{"id":"staff","channels":["{PIN}"]}}]"#
        ))
        .unwrap();
        assert!(zones[0].channels.is_empty());
        assert_eq!(zones[1].channels, vec![PIN.to_string()]);
    }

    #[test]
    fn pinned_zone_for_matches_like_the_relay() {
        let zones = pinned_zones();
        assert_eq!(
            pinned_zone_for(PIN, &zones).map(|z| z.id.as_str()),
            Some("staff")
        );
        assert_eq!(
            pinned_zone_for(&PIN.to_uppercase(), &zones).map(|z| z.id.as_str()),
            Some("staff")
        );
        assert!(pinned_zone_for(LOOSE, &zones).is_none());
        let junk = vec![Zone {
            channels: vec!["abc".into(), "zz".repeat(32)],
            ..zone("x")
        }];
        assert!(pinned_zone_for("abc", &junk).is_none());
        assert!(pinned_zone_for(&"zz".repeat(32), &junk).is_none());
        // A (validation-refused) double pin: the first zone in config order.
        let doubled = vec![
            Zone {
                channels: vec![PIN.into()],
                ..zone("a")
            },
            Zone {
                channels: vec![PIN.into()],
                ..zone("b")
            },
        ];
        assert_eq!(
            pinned_zone_for(PIN, &doubled).map(|z| z.id.as_str()),
            Some("a")
        );
    }

    #[test]
    fn effective_section_is_the_pinned_zone_for_a_pinned_channel() {
        let zones = pinned_zones();
        assert_eq!(effective_section(PIN, "open-agents", &zones), "staff");
        assert_eq!(effective_section(PIN, "", &zones), "staff");
        assert_eq!(effective_section(PIN, "legacy-lobby", &zones), "staff");
        // A tag that already names the pinned zone is kept as it is.
        assert_eq!(effective_section(PIN, "staff-notes", &zones), "staff-notes");
        // An unpinned channel keeps its tag.
        assert_eq!(
            effective_section(LOOSE, "open-agents", &zones),
            "open-agents"
        );
        // Every resolver then lands on the pinned zone.
        let routed = effective_section(PIN, "open-agents", &zones);
        assert_eq!(section_to_zone(&routed, &zones).as_deref(), Some("staff"));
        assert_eq!(
            zone_id_for_section(&routed, &zones).as_deref(),
            Some("staff")
        );
        assert!(section_routes_to_zone(&routed, "staff", &zones));
        assert!(!section_routes_to_zone(&routed, "open", &zones));
    }

    #[test]
    fn with_no_pins_effective_section_is_the_tag() {
        let zones = sample_zones();
        for tag in ["family-events", "", "Family", "stray", "BUSINESS-Deals"] {
            assert_eq!(effective_section(PIN, tag, &zones), tag);
        }
        assert_eq!(
            effective_section(PIN, "family-events", &[]),
            "family-events"
        );
    }

    #[test]
    fn bind_never_targets_a_pinned_channel() {
        let zones = pinned_zones();
        // The pinned channel's tag names "open"; binding it there would undo
        // the pin's effect once the pin is removed, so nothing is bound.
        assert_eq!(bind_zone_for(PIN, "open-agents", &zones), None);
        assert_eq!(
            bind_zone_for(LOOSE, "open-agents", &zones).as_deref(),
            Some("open")
        );
        assert_eq!(bind_zone_for(LOOSE, "legacy-lobby", &zones), None);
        // No pins: exactly the strict resolver, as before.
        let plain = sample_zones();
        for tag in ["family-events", "home-lobby", "Business"] {
            assert_eq!(
                bind_zone_for(PIN, tag, &plain),
                zone_id_for_section(tag, &plain)
            );
        }
    }

    #[test]
    fn the_key_for_a_pinned_channel_is_the_pinned_zone_key() {
        let zones = pinned_zones();
        let routed = effective_section(PIN, "open-agents", &zones);
        let zone = crate::zone_crypto::store::zone_for_channel_section(&routed, &zones).unwrap();
        assert_eq!(zone.id, "staff");
        assert!(zone.encrypted);
        // Without the pin the same channel uses the zone its tag names.
        let unpinned: Vec<Zone> = pinned_zones()
            .into_iter()
            .map(|z| Zone {
                channels: Vec::new(),
                ..z
            })
            .collect();
        let routed = effective_section(PIN, "open-agents", &unpinned);
        let zone = crate::zone_crypto::store::zone_for_channel_section(&routed, &unpinned).unwrap();
        assert_eq!(zone.id, "open");
    }

    #[test]
    fn empty_cohorts_mean_open_only_on_a_public_zone() {
        let none: Vec<String> = vec![];
        let some = vec!["members".to_string()];
        // A public zone with no cohorts (a welcome zone) stays open to all.
        let public = zone("welcome");
        assert!(public.is_member(&none));
        assert!(public.is_member(&some));
        // Locked or hidden with no cohorts: admins only, as on the relay.
        for vis in [ZoneVisibility::Locked, ZoneVisibility::Hidden] {
            let z = Zone {
                visibility: vis,
                ..zone("staff")
            };
            assert!(!z.is_member(&none), "{vis:?}");
            assert!(!z.is_member(&some), "{vis:?}");
        }
        // Zones with cohorts are unchanged, whatever their visibility.
        for vis in [
            ZoneVisibility::Public,
            ZoneVisibility::Locked,
            ZoneVisibility::Hidden,
        ] {
            let z = Zone {
                visibility: vis,
                required_cohorts: vec!["members".into()],
                ..zone("open")
            };
            assert!(z.is_member(&some));
            assert!(!z.is_member(&none));
        }
        // The built-in fallback list keeps its open public zone.
        let fallback = fallback_zones();
        assert!(fallback[0].is_member(&none));
    }

    #[test]
    fn a_wrong_typed_channels_field_does_not_break_the_zone_list() {
        let zones: Vec<Zone> = serde_json::from_str(&format!(
            r#"[{{"id":"open"}},{{"id":"staff","channels":"{PIN}"}},{{"id":"odd","channels":[1,2]}}]"#
        ))
        .unwrap();
        assert_eq!(zones.len(), 3);
        assert!(zones.iter().all(|z| z.channels.is_empty()));
    }
}
