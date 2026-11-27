//! "Continue where you left off": the last zone, section or topic a member
//! viewed, per signed-in identity and per device.
//!
//! Only the route path and its display labels are stored, never content. The
//! zone label comes from public config and the section label from the
//! section's public kind-40 metadata. A topic title is stored only for an
//! unencrypted zone: for an encrypted zone the route and the zone/section
//! labels are stored, and the Forums index shows the topic title only if the
//! channel store already holds it decrypted in memory.
//!
//! The entry lives in `localStorage` under `nostrbbs:resume:<pubkey>` (the
//! same namespacing as the per-account notification list) and is removed on
//! sign-out. The decisions are pure and unit-tested; the storage helpers are
//! thin.

use serde::{Deserialize, Serialize};

use crate::stores::zones::{resolve_zone_param, zone_slug, Zone};
use crate::utils::back_nav::ForumRoute;

/// The stored place: a canonical, base-relative forum route and the labels to
/// show for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumePoint {
    /// Base-relative route (`/welcome/s0123456789ab/t0123456789abcdef`).
    pub path: String,
    /// The zone's display name.
    pub zone: String,
    /// The section's display name, for section and topic routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// The topic's title, for topic routes in unencrypted zones only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

/// Separator between the labels, matching the breadcrumb's chevron.
const SEP: &str = " \u{203A} ";

/// Longest label kept, in characters; a topic's first line can be long.
const MAX_LABEL: usize = 90;

impl ResumePoint {
    /// The link text after "Continue: ": `Zone › Section › Topic`, with
    /// whichever parts are known. `topic` (a title held in memory) wins over
    /// the stored one.
    pub fn label(&self, topic: Option<&str>) -> String {
        let mut out = self.zone.clone();
        for part in [self.section.as_deref(), topic.or(self.topic.as_deref())]
            .into_iter()
            .flatten()
            .filter(|p| !p.trim().is_empty())
        {
            out.push_str(SEP);
            out.push_str(part);
        }
        out
    }

    /// Serialise for storage.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse a stored value. Anything that is not a well-formed entry for a
    /// zone, section or topic route is ignored, so a stale or tampered value
    /// can never become a link elsewhere.
    pub fn decode(raw: &str) -> Option<Self> {
        let point: Self = serde_json::from_str(raw).ok()?;
        (is_resumable_route(&point.path) && !point.zone.trim().is_empty()).then_some(point)
    }
}

/// Whether `path` is a route the Continue link may point at: a zone, section
/// or topic, written as a plain base-relative path.
pub fn is_resumable_route(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['\\', '?', '#'])
        && !path.chars().any(char::is_control)
        && matches!(
            ForumRoute::parse(path),
            ForumRoute::Zone { .. } | ForumRoute::Section { .. } | ForumRoute::Topic { .. }
        )
}

/// Whether the Continue link is shown: there is a stored point, it is not the
/// page the member is on, and its zone is still one they can reach.
pub fn should_show(point: Option<&ResumePoint>, current_path: &str, zone_reachable: bool) -> bool {
    match point {
        Some(p) => zone_reachable && trim_slash(&p.path) != trim_slash(current_path),
        None => false,
    }
}

fn trim_slash(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        "/"
    } else {
        t
    }
}

/// Clip a display label to [`MAX_LABEL`] characters.
pub fn clip_label(label: &str) -> String {
    let label = label.trim();
    if label.chars().count() > MAX_LABEL {
        let clipped: String = label.chars().take(MAX_LABEL).collect();
        format!("{}\u{2026}", clipped.trim_end())
    } else {
        label.to_string()
    }
}

/// The topic title for storage, or `None` when it must not be stored: the
/// zone is configured as encrypted (whatever the deployment gate), the root
/// event is a zone-encrypted message, or its content is not a usable title.
pub fn storable_topic_title(
    zone_encrypted: bool,
    root_is_zone_message: bool,
    title: Option<&str>,
) -> Option<String> {
    if zone_encrypted || root_is_zone_message {
        return None;
    }
    title
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(clip_label)
}

/// A topic as the thread page knows it, for [`point_for`].
#[derive(Clone, Copy, Debug)]
pub struct TopicVisit<'a> {
    /// The topic's URL slug.
    pub slug: &'a str,
    /// The topic's first line, when its root is known.
    pub title: Option<&'a str>,
    /// Whether the root is a zone-encrypted message (or its placeholder).
    pub is_zone_message: bool,
}

/// The resume point for a page in the zone named by `category_param` (slug or
/// id), with its section (`(url slug, display name)`) and topic when the page
/// is that deep. `None` when the zone is not in the config. The path is the
/// canonical slug form, and a topic title is dropped for an encrypted zone.
pub fn point_for(
    zones: &[Zone],
    category_param: &str,
    section: Option<(&str, &str)>,
    topic: Option<TopicVisit<'_>>,
) -> Option<ResumePoint> {
    let zone = resolve_zone_param(category_param, zones)?;
    let mut path = format!("/{}", zone_slug(zone));
    let mut section_label = None;
    let mut topic_label = None;
    if let Some((slug, label)) = section {
        path.push('/');
        path.push_str(slug);
        section_label = Some(clip_label(label)).filter(|l| !l.is_empty());
        if let Some(t) = topic {
            path.push('/');
            path.push_str(t.slug);
            topic_label = storable_topic_title(zone.encrypted, t.is_zone_message, t.title);
        }
    }
    let point = ResumePoint {
        path,
        zone: clip_label(&zone.label()),
        section: section_label,
        topic: topic_label,
    };
    is_resumable_route(&point.path).then_some(point)
}

/// The localStorage key of `pubkey`'s resume point.
pub fn storage_key(pubkey: &str) -> String {
    format!("nostrbbs:resume:{pubkey}")
}

// -- Storage (browser only) ---------------------------------------------------

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

/// The resume point stored for `pubkey` on this device.
pub fn load(pubkey: &str) -> Option<ResumePoint> {
    let raw = local_storage()?.get_item(&storage_key(pubkey)).ok()??;
    ResumePoint::decode(&raw)
}

/// Remember `point` for `pubkey`. A no-op when the same value is stored, so
/// page effects that re-run on every store change do not rewrite storage.
pub fn remember(pubkey: &str, point: &ResumePoint) {
    if !is_resumable_route(&point.path) {
        return;
    }
    let Some(storage) = local_storage() else {
        return;
    };
    let key = storage_key(pubkey);
    let value = point.encode();
    if storage.get_item(&key).ok().flatten().as_deref() != Some(value.as_str()) {
        let _ = storage.set_item(&key, &value);
    }
}

/// Forget the signed-out account's resume point (sign-out clears per-identity
/// state).
pub fn clear_for_logout(pubkey: Option<&str>) {
    if let (Some(pk), Some(storage)) = (pubkey, local_storage()) {
        let _ = storage.remove_item(&storage_key(pk));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(path: &str, section: Option<&str>, topic: Option<&str>) -> ResumePoint {
        ResumePoint {
            path: path.into(),
            zone: "Welcome".into(),
            section: section.map(Into::into),
            topic: topic.map(Into::into),
        }
    }

    #[test]
    fn label_joins_the_known_parts() {
        assert_eq!(point("/welcome", None, None).label(None), "Welcome");
        assert_eq!(
            point("/welcome/s0123456789ab", Some("Lobby"), None).label(None),
            "Welcome \u{203A} Lobby"
        );
        let t = point(
            "/welcome/s0123456789ab/t0123456789abcdef",
            Some("Lobby"),
            Some("Hi"),
        );
        assert_eq!(t.label(None), "Welcome \u{203A} Lobby \u{203A} Hi");
        // A title held in memory wins over the stored one.
        assert_eq!(
            t.label(Some("Decrypted")),
            "Welcome \u{203A} Lobby \u{203A} Decrypted"
        );
        // Blank parts are skipped.
        assert_eq!(
            point("/welcome/s0123456789ab", Some("  "), None).label(Some("")),
            "Welcome"
        );
    }

    #[test]
    fn round_trips_and_omits_absent_labels() {
        let p = point("/welcome/s0123456789ab", Some("Lobby"), None);
        let raw = p.encode();
        assert!(!raw.contains("topic"), "{raw}");
        assert_eq!(ResumePoint::decode(&raw), Some(p));
    }

    #[test]
    fn decode_rejects_anything_but_a_forum_place() {
        for raw in [
            "",
            "not json",
            r#"{"path":"/settings","zone":"Z"}"#,
            r#"{"path":"/forums","zone":"Z"}"#,
            r#"{"path":"/","zone":"Z"}"#,
            r#"{"path":"//evil.example/x","zone":"Z"}"#,
            r#"{"path":"https://evil.example/welcome","zone":"Z"}"#,
            r#"{"path":"/welcome?x=1","zone":"Z"}"#,
            r#"{"path":"/dm/abc","zone":"Z"}"#,
            r#"{"path":"/welcome","zone":"  "}"#,
        ] {
            assert_eq!(ResumePoint::decode(raw), None, "{raw}");
        }
        assert!(ResumePoint::decode(r#"{"path":"/forums/zone1/s1","zone":"Z"}"#).is_some());
    }

    #[test]
    fn shown_only_when_stored_elsewhere_and_reachable() {
        let p = point("/welcome/s0123456789ab", Some("Lobby"), None);
        assert!(should_show(Some(&p), "/forums", true));
        assert!(!should_show(None, "/forums", true));
        assert!(!should_show(Some(&p), "/forums", false));
        assert!(!should_show(Some(&p), "/welcome/s0123456789ab", true));
        assert!(!should_show(Some(&p), "/welcome/s0123456789ab/", true));
    }

    #[test]
    fn encrypted_topic_titles_are_never_stored() {
        assert_eq!(storable_topic_title(true, false, Some("Secret")), None);
        assert_eq!(storable_topic_title(false, true, Some("Secret")), None);
        assert_eq!(storable_topic_title(true, true, Some("Secret")), None);
        assert_eq!(storable_topic_title(false, false, Some("  ")), None);
        assert_eq!(storable_topic_title(false, false, None), None);
        assert_eq!(
            storable_topic_title(false, false, Some(" Hello ")),
            Some("Hello".into())
        );
    }

    #[test]
    fn long_labels_are_clipped() {
        let long = "x".repeat(200);
        let c = clip_label(&long);
        assert_eq!(c.chars().count(), MAX_LABEL + 1);
        assert!(c.ends_with('\u{2026}'));
    }

    fn zones() -> Vec<Zone> {
        serde_json::from_str(
            r#"[
                {"id":"zone1","slug":"welcome","display_name":"Welcome"},
                {"id":"zone2","display_name":"Vault","encrypted":true,"required_cohorts":["x"]}
            ]"#,
        )
        .unwrap()
    }

    #[test]
    fn point_for_builds_the_canonical_slug_path() {
        let zs = zones();
        // The legacy id resolves, but the stored path uses the slug.
        let p = point_for(&zs, "zone1", None, None).unwrap();
        assert_eq!(p.path, "/welcome");
        assert_eq!(p.zone, "Welcome");
        let p = point_for(&zs, "welcome", Some(("s0123456789ab", "Lobby")), None).unwrap();
        assert_eq!(p.path, "/welcome/s0123456789ab");
        assert_eq!(p.section.as_deref(), Some("Lobby"));
        let t = TopicVisit {
            slug: "t0123456789abcdef",
            title: Some("Hello there"),
            is_zone_message: false,
        };
        let p = point_for(&zs, "welcome", Some(("s0123456789ab", "Lobby")), Some(t)).unwrap();
        assert_eq!(p.path, "/welcome/s0123456789ab/t0123456789abcdef");
        assert_eq!(p.topic.as_deref(), Some("Hello there"));
        assert!(point_for(&zs, "nope", None, None).is_none());
    }

    #[test]
    fn point_for_an_encrypted_zone_keeps_route_and_names_only() {
        let zs = zones();
        let t = TopicVisit {
            slug: "t0123456789abcdef",
            title: Some("Decrypted secret title"),
            is_zone_message: false,
        };
        let p = point_for(&zs, "zone2", Some(("s0123456789ab", "Plans")), Some(t)).unwrap();
        assert_eq!(p.path, "/zone2/s0123456789ab/t0123456789abcdef");
        assert_eq!(p.zone, "Vault");
        assert_eq!(p.section.as_deref(), Some("Plans"));
        assert_eq!(p.topic, None);
        assert!(!p.encode().contains("secret"));
        // A zone-encrypted root in an unflagged zone is not stored either.
        let t = TopicVisit {
            slug: "t0123456789abcdef",
            title: Some("secret"),
            is_zone_message: true,
        };
        let p = point_for(&zs, "welcome", Some(("s0123456789ab", "Lobby")), Some(t)).unwrap();
        assert_eq!(p.topic, None);
    }

    #[test]
    fn keys_are_per_identity() {
        assert_eq!(storage_key("abc"), "nostrbbs:resume:abc");
        assert_ne!(storage_key("abc"), storage_key("def"));
    }
}
