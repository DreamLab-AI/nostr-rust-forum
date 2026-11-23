//! Zone-restricted media containers: `/media/zones/<zone-id>/<name>`.
//!
//! An image posted in a forum zone is readable exactly when that zone's
//! messages are readable. The decision is made per request from the relay's
//! live `whitelist` row (bound to this worker as `RELAY_DB`) and the zone's
//! `required_cohorts` from `ZONE_CONFIG`; nothing about readers is stored with
//! the object, so adding or removing a member takes effect on the next request,
//! old images included.
//!
//! The decision here is AUTHORITATIVE for every path under [`ZONE_MEDIA_ROOT`]:
//! the caller skips the WAC walk for these paths, so an `.acl` sidecar can
//! neither open nor close a zone container, and it runs before any R2 read, so
//! a refused requester learns nothing about which objects exist.
//!
//! Rules (mirroring the relay where the relay has a rule):
//! - Writes (`PUT`/`DELETE`; `POST`/`PATCH` are refused by the caller): the pod
//!   owner's raw key only, and only while the owner may post in the zone: an
//!   active whitelist row and either admin or the zone's effective write
//!   cohorts (`write_cohorts ?? required_cohorts`, the relay's
//!   `cohorts_can_write`; empty denies non-admins).
//! - Container reads (listing): the pod owner only.
//! - Object reads: the owner; a static `ADMIN_PUBKEYS` key; a raw key whose
//!   own active whitelist row has `is_admin = 1`; or an active whitelisted
//!   principal whose cohorts meet the zone rule.
//! - Active row: `expires_at` unset or in the future (the relay's admission
//!   filter) and `suspended_until` unset or past (the relay's suspension test).
//! - Device keys (`DEVICE_KEYS_ENABLED`): cohorts and expiry come from the
//!   device's owner; suspension of the device key OR its owner denies; admin
//!   status is never inherited from the owner (relay ADR-099 semantics).
//! - Zone rule: non-empty `required_cohorts` needs an intersecting cohort, as
//!   the relay's `cohorts_can_read`. Empty `required_cohorts` with
//!   `visibility = "public"` (zone1/Welcome) needs any active whitelisted
//!   member. This deliberately deviates from message visibility, where such a
//!   zone is anonymous-read: no zone image sits in a public folder. Empty
//!   `required_cohorts` with any other visibility (default `locked`) reads as
//!   admin-only, exactly as the relay's `cohorts_can_read`.
//! - Unknown zone, or `ZONE_CONFIG` missing or malformed: owner and admins only.

use serde::Deserialize;

/// Path prefix of the zone media containers inside a pod.
pub const ZONE_MEDIA_ROOT: &str = "/media/zones";

/// Raster image types accepted into, and served from, zone containers. SVG is
/// deliberately absent: it is an active document type.
pub const ALLOWED_IMAGE_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/avif",
];

/// `Cache-Control` for every response on a zone path, errors included.
pub const ZONE_CACHE_CONTROL: &str = "private, no-store";

/// `Vary` for every response on a zone path.
pub const ZONE_VARY: &str = "Origin, Authorization, Accept";

/// Classification of a pod resource path under [`ZONE_MEDIA_ROOT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneMediaPath<'a> {
    /// `/media/zones` or `/media/zones/`: the container of all zone containers.
    Root,
    /// `/media/zones/<zone>/`: one zone's container.
    Container { zone: &'a str },
    /// `/media/zones/<zone>/<name>`: an object.
    Object { zone: &'a str, name: &'a str },
    /// Under the prefix but not one of the shapes above (deeper nesting, a
    /// sidecar, a bad zone id or object name, a missing trailing slash).
    Invalid,
}

/// Classify `resource_path` (the part after `/pods/<pk>`). `None` when the path
/// is not under [`ZONE_MEDIA_ROOT`] at all, so the ordinary WAC path applies.
pub fn classify(resource_path: &str) -> Option<ZoneMediaPath<'_>> {
    let rest = resource_path.strip_prefix(ZONE_MEDIA_ROOT)?;
    if rest.is_empty() || rest == "/" {
        return Some(ZoneMediaPath::Root);
    }
    // `/media/zonesX` is a different resource, not ours.
    let rest = rest.strip_prefix('/')?;
    let mut parts = rest.splitn(2, '/');
    let zone = parts.next().unwrap_or("");
    let Some(tail) = parts.next() else {
        // `/media/zones/<zone>` without the trailing slash.
        return Some(ZoneMediaPath::Invalid);
    };
    if !is_valid_zone_id(zone) {
        return Some(ZoneMediaPath::Invalid);
    }
    if tail.is_empty() {
        return Some(ZoneMediaPath::Container { zone });
    }
    if !is_valid_object_name(tail) {
        return Some(ZoneMediaPath::Invalid);
    }
    Some(ZoneMediaPath::Object { zone, name: tail })
}

/// Zone ids as path segments: `[a-z0-9][a-z0-9_-]{0,63}`.
pub fn is_valid_zone_id(zone: &str) -> bool {
    let b = zone.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Object names: one segment of `[A-Za-z0-9._-]`, 1..=160 bytes, not starting
/// with `.` (no `.acl`, `.meta` or other dot-files), not ending in `.acl` or
/// `.meta`.
pub fn is_valid_object_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 160
        && b[0] != b'.'
        && !name.ends_with(".acl")
        && !name.ends_with(".meta")
        && b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The two request classes a zone path distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `GET` / `HEAD`.
    Read,
    /// `PUT` / `POST` / `PATCH` / `DELETE`.
    Write,
}

/// Map an HTTP method name. Anything that is not a read is treated as a write,
/// so an unexpected verb gets the strictest (owner-only) rule.
pub fn access_for_method(method: &str) -> Access {
    match method {
        "GET" | "HEAD" => Access::Read,
        _ => Access::Write,
    }
}

/// One zone's access rule as parsed from `ZONE_CONFIG`. Unknown fields of the
/// full zone schema are ignored.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ZoneRule {
    /// Zone id (`"zone2"`).
    pub id: String,
    /// Cohorts that may read the zone.
    #[serde(default)]
    pub required_cohorts: Vec<String>,
    /// Cohorts that may post; falls back to `required_cohorts`.
    #[serde(default)]
    pub write_cohorts: Option<Vec<String>>,
    /// `"public"`, `"locked"` (the default) or `"hidden"`.
    #[serde(default)]
    pub visibility: Option<String>,
}

impl ZoneRule {
    fn is_public(&self) -> bool {
        self.visibility
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("public"))
    }

    /// Read rule for an ACTIVE, non-admin member with `cohorts`.
    pub fn member_can_read(&self, cohorts: &[String]) -> bool {
        if self.required_cohorts.is_empty() {
            // Relay: empty requirement reads only when Public. Here Public
            // still needs an active member (no anonymous zone images).
            self.is_public()
        } else {
            cohorts.iter().any(|c| self.required_cohorts.contains(c))
        }
    }

    /// Write rule for an ACTIVE, non-admin member (relay `cohorts_can_write`).
    pub fn member_can_write(&self, cohorts: &[String]) -> bool {
        let req = self
            .write_cohorts
            .as_deref()
            .unwrap_or(&self.required_cohorts);
        !req.is_empty() && cohorts.iter().any(|c| req.contains(c))
    }
}

/// Parse `ZONE_CONFIG`. `None` for absent, blank or malformed input, which the
/// decision treats as "owner and admins only".
pub fn parse_zone_config(raw: Option<&str>) -> Option<Vec<ZoneRule>> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    serde_json::from_str::<Vec<ZoneRule>>(raw).ok()
}

/// The relay `whitelist` columns the decision needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WhitelistRow {
    /// Parsed `cohorts` JSON array.
    pub cohorts: Vec<String>,
    /// `is_admin = 1`.
    pub is_admin: bool,
    /// `suspended_until` (unix seconds).
    pub suspended_until: Option<i64>,
    /// `expires_at` (unix seconds).
    pub expires_at: Option<i64>,
}

impl WhitelistRow {
    /// Not expired (relay admission filter).
    pub fn is_unexpired(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }

    /// Not suspended (relay `check_suspension`: suspended while `until > now`).
    pub fn is_unsuspended(&self, now: i64) -> bool {
        self.suspended_until.is_none_or(|t| t <= now)
    }

    /// Both of the above.
    pub fn is_active(&self, now: i64) -> bool {
        self.is_unexpired(now) && self.is_unsuspended(now)
    }
}

/// Everything the decision depends on. Rows are looked up by the caller.
#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    /// Read or write.
    pub access: Access,
    /// Pod owner (64 hex).
    pub owner: &'a str,
    /// NIP-98-verified raw signing key, if any.
    pub requester: Option<&'a str>,
    /// Requester is in the static `ADMIN_PUBKEYS` list.
    pub static_admin: bool,
    /// Requester's own whitelist row.
    pub requester_row: Option<&'a WhitelistRow>,
    /// When the requester is a registered, unrevoked device key and device keys
    /// are enabled: the owner's whitelist row (`Some(None)` = device of an owner
    /// with no row). `None` = not a device.
    pub device_owner_row: Option<Option<&'a WhitelistRow>>,
    /// Parsed `ZONE_CONFIG` (`None` = missing/malformed).
    pub zones: Option<&'a [ZoneRule]>,
    /// Unix seconds.
    pub now: i64,
}

/// Outcome of [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Serve / perform the request.
    Allow,
    /// 401: no valid NIP-98.
    Unauthenticated,
    /// 403.
    Forbidden,
    /// 404: an invalid shape under the prefix (nothing can live there).
    NotFound,
}

/// Whether the decision needs whitelist rows at all (the caller skips the D1
/// read for owners, static admins, anonymous requests and non-object paths).
pub fn needs_whitelist(path: &ZoneMediaPath<'_>, req: &AccessRequest<'_>) -> bool {
    let ZoneMediaPath::Object { .. } = path else {
        return false;
    };
    if req.static_admin {
        return false;
    }
    match req.access {
        Access::Read => req.requester.is_some_and(|r| r != req.owner),
        Access::Write => req.requester == Some(req.owner),
    }
}

/// Decide a request on a zone path.
pub fn decide(path: &ZoneMediaPath<'_>, req: &AccessRequest<'_>) -> Decision {
    if *path == ZoneMediaPath::Invalid {
        return Decision::NotFound;
    }
    let Some(requester) = req.requester else {
        return Decision::Unauthenticated;
    };
    let is_owner = requester == req.owner;

    // Writes and listings: the owner's raw key, nobody else.
    let ZoneMediaPath::Object { zone, .. } = path else {
        return if is_owner && req.access == Access::Read {
            Decision::Allow
        } else if is_owner {
            // No write targets a container.
            Decision::NotFound
        } else {
            Decision::Forbidden
        };
    };
    if req.access == Access::Write {
        if !is_owner {
            return Decision::Forbidden;
        }
        if req.static_admin {
            return Decision::Allow;
        }
        // The owner writes only while they may post in this zone.
        let Some(row) = req.requester_row.filter(|r| r.is_active(req.now)) else {
            return Decision::Forbidden;
        };
        if row.is_admin {
            return Decision::Allow;
        }
        let rule = req.zones.and_then(|zs| zs.iter().find(|z| z.id == *zone));
        return match rule {
            Some(rule) if rule.member_can_write(&row.cohorts) => Decision::Allow,
            _ => Decision::Forbidden,
        };
    }

    if is_owner || req.static_admin {
        return Decision::Allow;
    }

    let now = req.now;
    // The raw key's own sanctions always apply (a suspended device key is
    // denied even when its owner is in good standing).
    if req.requester_row.is_some_and(|r| !r.is_unsuspended(now)) {
        return Decision::Forbidden;
    }
    // Admin is the raw signing key's own flag, never a device owner's.
    if req.requester_row.is_some_and(|r| r.is_admin && r.is_active(now)) {
        return Decision::Allow;
    }

    // Effective principal for cohorts and expiry.
    let principal_row = match req.device_owner_row {
        Some(owner_row) => owner_row,
        None => req.requester_row,
    };
    let Some(row) = principal_row.filter(|r| r.is_active(now)) else {
        return Decision::Forbidden;
    };

    let Some(rule) = req.zones.and_then(|zs| zs.iter().find(|z| z.id == *zone)) else {
        return Decision::Forbidden;
    };
    if rule.member_can_read(&row.cohorts) {
        Decision::Allow
    } else {
        Decision::Forbidden
    }
}

/// Media type of a `Content-Type` value: lower-cased, parameters dropped.
fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Whether a `PUT` body's `Content-Type` may be stored in a zone container.
pub fn is_allowed_upload_type(content_type: &str) -> bool {
    ALLOWED_IMAGE_TYPES.contains(&media_type(content_type).as_str())
}

/// Raster type implied by an object name's extension (for legacy
/// `application/octet-stream` objects). Never SVG.
fn raster_type_for_name(name: &str) -> Option<&'static str> {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "webp" => Some("image/webp"),
        "gif" => Some("image/gif"),
        "avif" => Some("image/avif"),
        _ => None,
    }
}

/// The `Content-Type` to serve for a stored zone object, and whether it must be
/// served as a download (`Content-Disposition: attachment`). Only allow-listed
/// raster types are served as themselves; everything else, SVG included, is
/// `application/octet-stream` as an attachment.
pub fn served_content_type(stored: &str, name: &str) -> (String, bool) {
    let media = media_type(stored);
    if ALLOWED_IMAGE_TYPES.contains(&media.as_str()) {
        return (media, false);
    }
    if media.is_empty() || media == "application/octet-stream" {
        if let Some(t) = raster_type_for_name(name) {
            return (t.to_string(), false);
        }
    }
    ("application/octet-stream".to_string(), true)
}

/// Allowed browser origins for zone responses: `ALLOWED_ORIGINS`
/// (comma-separated), falling back to `EXPECTED_ORIGIN`. A `*` entry is dropped:
/// zone responses never use a wildcard.
pub fn allowed_origins(allowed_var: Option<&str>, expected_origin: Option<&str>) -> Vec<String> {
    let source = allowed_var
        .filter(|v| !v.trim().is_empty())
        .or(expected_origin)
        .unwrap_or("");
    source
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty() && s != "*")
        .collect()
}

/// The `Access-Control-Allow-Origin` for a zone response: the request's own
/// origin when it is allowed, else none (the browser then blocks the read).
pub fn select_origin(allowed: &[String], request_origin: Option<&str>) -> Option<String> {
    let origin = request_origin?.trim();
    allowed.iter().find(|o| *o == origin).cloned()
}

/// Whether `pubkey` is in the static `ADMIN_PUBKEYS` list, parsed exactly as
/// the relay parses it (hex or npub, via `nostr_bbs_core`).
pub fn is_static_admin(admin_pubkeys: Option<&str>, pubkey: &str) -> bool {
    admin_pubkeys.is_some_and(|raw| nostr_bbs_core::admin_shared::is_static_admin(pubkey, raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NOW: i64 = 1_800_000_000;

    fn zones() -> Vec<ZoneRule> {
        parse_zone_config(Some(
            r#"[{"id":"zone1","required_cohorts":[],"write_cohorts":["members"],"visibility":"public"},
                {"id":"zone2","required_cohorts":["zone2","minimoonoir"],"encrypted":true},
                {"id":"zone5","required_cohorts":[],"visibility":"locked"},
                {"id":"zone6","required_cohorts":[]}]"#,
        ))
        .unwrap()
    }

    fn row(cohorts: &[&str]) -> WhitelistRow {
        WhitelistRow {
            cohorts: cohorts.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn read<'a>(
        requester: Option<&'a str>,
        row: Option<&'a WhitelistRow>,
        zones: &'a [ZoneRule],
    ) -> AccessRequest<'a> {
        AccessRequest {
            access: Access::Read,
            owner: OWNER,
            requester,
            static_admin: false,
            requester_row: row,
            device_owner_row: None,
            zones: Some(zones),
            now: NOW,
        }
    }

    const Z2: ZoneMediaPath<'static> = ZoneMediaPath::Object {
        zone: "zone2",
        name: "x.webp",
    };
    const Z1: ZoneMediaPath<'static> = ZoneMediaPath::Object {
        zone: "zone1",
        name: "x.webp",
    };

    #[test]
    fn classify_shapes() {
        assert_eq!(classify("/media/public/x.png"), None);
        assert_eq!(classify("/media/zonesx/a"), None);
        assert_eq!(classify("/media/zones"), Some(ZoneMediaPath::Root));
        assert_eq!(classify("/media/zones/"), Some(ZoneMediaPath::Root));
        assert_eq!(
            classify("/media/zones/zone2/"),
            Some(ZoneMediaPath::Container { zone: "zone2" })
        );
        assert_eq!(classify("/media/zones/zone2/a.webp"), Some(Z2_A));
        for bad in [
            "/media/zones/zone2",
            "/media/zones/zone2/a/b.png",
            "/media/zones/zone2/.acl",
            "/media/zones/zone2/a.png.acl",
            "/media/zones/zone2/a.meta",
            "/media/zones/zone2//a.png",
            "/media/zones/Zone2/a.png",
            "/media/zones//a.png",
            "/media/zones/zone2/a%20b.png",
            "/media/zones/-z/a.png",
        ] {
            assert_eq!(classify(bad), Some(ZoneMediaPath::Invalid), "{bad}");
        }
    }

    const Z2_A: ZoneMediaPath<'static> = ZoneMediaPath::Object {
        zone: "zone2",
        name: "a.webp",
    };

    #[test]
    fn anonymous_is_unauthenticated_everywhere_valid() {
        let z = zones();
        assert_eq!(decide(&Z2, &read(None, None, &z)), Decision::Unauthenticated);
        assert_eq!(
            decide(&ZoneMediaPath::Root, &read(None, None, &z)),
            Decision::Unauthenticated
        );
        assert_eq!(
            decide(&ZoneMediaPath::Invalid, &read(None, None, &z)),
            Decision::NotFound
        );
    }

    #[test]
    fn member_reads_and_non_member_is_refused() {
        let z = zones();
        let member = row(&["members", "minimoonoir"]);
        let outsider = row(&["members"]);
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&member), &z)), Decision::Allow);
        assert_eq!(
            decide(&Z2, &read(Some(OTHER), Some(&outsider), &z)),
            Decision::Forbidden
        );
        // A valid Nostr key with no whitelist row at all.
        assert_eq!(decide(&Z2, &read(Some(OTHER), None, &z)), Decision::Forbidden);
    }

    #[test]
    fn zone1_with_no_cohorts_needs_an_active_member_not_anyone() {
        let z = zones();
        assert_eq!(
            decide(&Z1, &read(Some(OTHER), Some(&row(&["members"])), &z)),
            Decision::Allow
        );
        assert_eq!(decide(&Z1, &read(Some(OTHER), None, &z)), Decision::Forbidden);
        assert_eq!(decide(&Z1, &read(None, None, &z)), Decision::Unauthenticated);
    }

    #[test]
    fn empty_cohorts_without_public_visibility_is_admin_only() {
        let z = zones();
        let member = row(&["members", "zone2"]);
        for zone in ["zone5", "zone6"] {
            let p = ZoneMediaPath::Object {
                zone,
                name: "a.png",
            };
            assert_eq!(
                decide(&p, &read(Some(OTHER), Some(&member), &z)),
                Decision::Forbidden,
                "{zone}"
            );
            let mut admin = row(&[]);
            admin.is_admin = true;
            assert_eq!(decide(&p, &read(Some(OTHER), Some(&admin), &z)), Decision::Allow);
        }
    }

    #[test]
    fn owner_writes_only_while_they_may_post_in_the_zone() {
        let z = zones();
        let poster = row(&["members", "zone2"]);
        let mut w = read(Some(OWNER), Some(&poster), &z);
        w.access = Access::Write;
        assert!(needs_whitelist(&Z2, &w));
        assert_eq!(decide(&Z2, &w), Decision::Allow);
        assert_eq!(decide(&Z1, &w), Decision::Allow, "zone1 write_cohorts = members");

        let outsider = row(&["members"]);
        w.requester_row = Some(&outsider);
        assert_eq!(decide(&Z2, &w), Decision::Forbidden);

        let mut suspended = row(&["zone2"]);
        suspended.suspended_until = Some(NOW + 1);
        w.requester_row = Some(&suspended);
        assert_eq!(decide(&Z2, &w), Decision::Forbidden);

        w.requester_row = None;
        assert_eq!(decide(&Z2, &w), Decision::Forbidden, "no whitelist row");

        let locked_empty = ZoneMediaPath::Object {
            zone: "zone5",
            name: "a.png",
        };
        w.requester_row = Some(&poster);
        assert_eq!(decide(&locked_empty, &w), Decision::Forbidden);

        let mut admin = row(&[]);
        admin.is_admin = true;
        w.requester_row = Some(&admin);
        assert_eq!(decide(&locked_empty, &w), Decision::Allow);

        w.requester_row = None;
        w.static_admin = true;
        assert!(!needs_whitelist(&Z2, &w));
        assert_eq!(decide(&Z2, &w), Decision::Allow);
    }

    #[test]
    fn suspended_and_expired_members_are_refused() {
        let z = zones();
        let mut suspended = row(&["zone2"]);
        suspended.suspended_until = Some(NOW + 60);
        let mut lifted = row(&["zone2"]);
        lifted.suspended_until = Some(NOW);
        let mut expired = row(&["zone2"]);
        expired.expires_at = Some(NOW);
        let mut future = row(&["zone2"]);
        future.expires_at = Some(NOW + 1);
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&suspended), &z)), Decision::Forbidden);
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&lifted), &z)), Decision::Allow);
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&expired), &z)), Decision::Forbidden);
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&future), &z)), Decision::Allow);
    }

    #[test]
    fn admins_read_everything_but_a_suspended_db_admin_does_not() {
        let z = zones();
        let mut admin = row(&[]);
        admin.is_admin = true;
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&admin), &z)), Decision::Allow);
        admin.suspended_until = Some(NOW + 10);
        assert_eq!(decide(&Z2, &read(Some(OTHER), Some(&admin), &z)), Decision::Forbidden);
        let mut static_admin = read(Some(OTHER), None, &z);
        static_admin.static_admin = true;
        assert_eq!(decide(&Z2, &static_admin), Decision::Allow);
        // Static admins also read zones the pod does not know.
        let unknown = ZoneMediaPath::Object {
            zone: "zone9",
            name: "a.png",
        };
        assert_eq!(decide(&unknown, &static_admin), Decision::Allow);
    }

    #[test]
    fn owner_always_reads_own_and_alone_writes_and_lists() {
        let z = zones();
        let poster = row(&["zone2"]);
        let mut owner = read(Some(OWNER), Some(&poster), &z);
        assert_eq!(decide(&Z2, &owner), Decision::Allow);
        assert_eq!(decide(&ZoneMediaPath::Root, &owner), Decision::Allow);
        assert_eq!(
            decide(&ZoneMediaPath::Container { zone: "zone2" }, &owner),
            Decision::Allow
        );
        owner.access = Access::Write;
        assert_eq!(decide(&Z2, &owner), Decision::Allow);
        assert_eq!(
            decide(&ZoneMediaPath::Container { zone: "zone2" }, &owner),
            Decision::NotFound
        );

        let mut admin = row(&["zone2"]);
        admin.is_admin = true;
        let mut other = read(Some(OTHER), Some(&admin), &z);
        other.static_admin = true;
        // Admins and members neither list nor write.
        assert_eq!(
            decide(&ZoneMediaPath::Container { zone: "zone2" }, &other),
            Decision::Forbidden
        );
        assert_eq!(decide(&ZoneMediaPath::Root, &other), Decision::Forbidden);
        other.access = Access::Write;
        assert_eq!(decide(&Z2, &other), Decision::Forbidden);
    }

    #[test]
    fn unknown_zone_or_missing_config_is_owner_and_admin_only() {
        let z = zones();
        let member = row(&["zone2", "zone9"]);
        let unknown = ZoneMediaPath::Object {
            zone: "zone9",
            name: "a.png",
        };
        assert_eq!(decide(&unknown, &read(Some(OTHER), Some(&member), &z)), Decision::Forbidden);
        let mut no_cfg = read(Some(OTHER), Some(&member), &z);
        no_cfg.zones = None;
        assert_eq!(decide(&Z2, &no_cfg), Decision::Forbidden);
        no_cfg.requester = Some(OWNER);
        assert_eq!(decide(&Z2, &no_cfg), Decision::Allow);
        assert_eq!(parse_zone_config(None), None);
        assert_eq!(parse_zone_config(Some("  ")), None);
        assert_eq!(parse_zone_config(Some("{not json")), None);
    }

    #[test]
    fn device_keys_read_as_their_owner_and_never_inherit_admin() {
        let z = zones();
        let owner_member = row(&["zone2"]);
        let mut owner_admin = row(&[]);
        owner_admin.is_admin = true;
        let mut req = read(Some(OTHER), None, &z);

        req.device_owner_row = Some(Some(&owner_member));
        assert_eq!(decide(&Z2, &req), Decision::Allow);

        req.device_owner_row = Some(Some(&owner_admin));
        assert_eq!(decide(&Z2, &req), Decision::Forbidden, "admin is not inherited");

        req.device_owner_row = Some(None);
        assert_eq!(decide(&Z2, &req), Decision::Forbidden);

        let mut owner_suspended = row(&["zone2"]);
        owner_suspended.suspended_until = Some(NOW + 5);
        req.device_owner_row = Some(Some(&owner_suspended));
        assert_eq!(decide(&Z2, &req), Decision::Forbidden);

        // The device key's own suspension denies even with a good owner.
        let mut device_row = row(&[]);
        device_row.suspended_until = Some(NOW + 5);
        req.requester_row = Some(&device_row);
        req.device_owner_row = Some(Some(&owner_member));
        assert_eq!(decide(&Z2, &req), Decision::Forbidden);
    }

    #[test]
    fn whitelist_is_only_needed_for_non_owner_object_reads() {
        let z = zones();
        assert!(needs_whitelist(&Z2, &read(Some(OTHER), None, &z)));
        assert!(!needs_whitelist(&Z2, &read(Some(OWNER), None, &z)));
        assert!(!needs_whitelist(&Z2, &read(None, None, &z)));
        assert!(!needs_whitelist(&ZoneMediaPath::Root, &read(Some(OTHER), None, &z)));
        let mut s = read(Some(OTHER), None, &z);
        s.static_admin = true;
        assert!(!needs_whitelist(&Z2, &s));
        s.static_admin = false;
        s.access = Access::Write;
        assert!(!needs_whitelist(&Z2, &s), "a non-owner write is refused without a lookup");
    }

    #[test]
    fn methods_other_than_get_and_head_are_writes() {
        assert_eq!(access_for_method("GET"), Access::Read);
        assert_eq!(access_for_method("HEAD"), Access::Read);
        for m in ["PUT", "POST", "PATCH", "DELETE", "OPTIONS", "TRACE"] {
            assert_eq!(access_for_method(m), Access::Write, "{m}");
        }
    }

    #[test]
    fn upload_types_are_rasters_only() {
        for ok in ["image/webp", "IMAGE/PNG", "image/jpeg; q=1", "image/gif", "image/avif"] {
            assert!(is_allowed_upload_type(ok), "{ok}");
        }
        for bad in ["image/svg+xml", "text/html", "application/octet-stream", "", "image/bmp"] {
            assert!(!is_allowed_upload_type(bad), "{bad}");
        }
    }

    #[test]
    fn served_type_never_upgrades_to_svg_and_attaches_the_rest() {
        assert_eq!(served_content_type("image/png", "a.png"), ("image/png".into(), false));
        assert_eq!(
            served_content_type("application/octet-stream", "a.JPG"),
            ("image/jpeg".into(), false)
        );
        assert_eq!(
            served_content_type("application/octet-stream", "a.svg"),
            ("application/octet-stream".into(), true)
        );
        assert_eq!(
            served_content_type("image/svg+xml", "a.png"),
            ("application/octet-stream".into(), true)
        );
        assert_eq!(
            served_content_type("text/html", "a.webp"),
            ("application/octet-stream".into(), true)
        );
    }

    #[test]
    fn origins_are_reflected_only_when_allowed_and_never_wildcard() {
        let allowed = allowed_origins(Some("https://a.example, https://b.example/"), None);
        assert_eq!(allowed, vec!["https://a.example", "https://b.example"]);
        assert_eq!(
            select_origin(&allowed, Some("https://b.example")),
            Some("https://b.example".into())
        );
        assert_eq!(select_origin(&allowed, Some("https://evil.example")), None);
        assert_eq!(select_origin(&allowed, None), None);
        assert_eq!(
            allowed_origins(None, Some("http://172.20.0.10:4180")),
            vec!["http://172.20.0.10:4180"]
        );
        assert!(allowed_origins(Some(""), Some("*")).is_empty());
        assert!(allowed_origins(Some("*"), None).is_empty());
    }

    #[test]
    fn static_admin_list_matches_exact_keys() {
        let list = format!("{OWNER}, {}", "c".repeat(64));
        assert!(is_static_admin(Some(&list), OWNER));
        assert!(!is_static_admin(Some(&list), OTHER));
        assert!(!is_static_admin(None, OWNER));
        assert!(!is_static_admin(Some(""), OWNER));
    }
}
