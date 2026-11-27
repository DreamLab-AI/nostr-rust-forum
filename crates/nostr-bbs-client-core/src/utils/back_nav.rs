//! Where the header's Back control goes.
//!
//! The installed phone app has no browser back button, so the header carries
//! one. It goes back in history when the previous history entry is a page of
//! this forum, and otherwise goes UP one level of the forum hierarchy
//! (topic → section → zone → Forums), so it never leaves the app or does
//! nothing. Everything here is pure (no DOM), so the decisions are unit-tested
//! natively; the browser glue lives in `components::back_button`.
//!
//! [`ForumRoute::parse`] mirrors the route table in `app.rs`: a static route
//! (`/dm/:pubkey`, `/go/:event_id`, `/forums/:category`, …) out-scores the
//! dynamic zone-slug aliases (`/:category/:section/:topic`) of the same depth,
//! exactly as `FlatRoutes` ranks them, so `/dm/abc` is a DM conversation and
//! never zone `dm`, section `abc`.

/// One route of the forum, as far as the Back control needs to know it.
///
/// `legacy` is true for the `/forums/…` form of a zone route; going up keeps
/// whichever form the member is on, so `/forums/zone1/s1` goes to
/// `/forums/zone1` and `/welcome/s1` goes to `/welcome`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForumRoute<'a> {
    /// `/`: the landing, which sends a signed-in member on to `/forums`.
    Root,
    /// `/forums`: the Forums index of every zone.
    Forums,
    /// A zone's list of sections (`/:category`, `/forums/:category`).
    Zone {
        /// Under the `/forums/` prefix.
        legacy: bool,
        /// The zone URL segment (slug or id).
        zone: &'a str,
    },
    /// A zone's task board (`/:category/board`, `/forums/:category/board`).
    Board {
        /// Under the `/forums/` prefix.
        legacy: bool,
        /// The zone URL segment.
        zone: &'a str,
    },
    /// A section's list of topics.
    Section {
        /// Under the `/forums/` prefix.
        legacy: bool,
        /// The zone URL segment.
        zone: &'a str,
        /// The section URL segment (normally a hashed slug).
        section: &'a str,
    },
    /// One topic.
    Topic {
        /// Under the `/forums/` prefix.
        legacy: bool,
        /// The zone URL segment.
        zone: &'a str,
        /// The section URL segment.
        section: &'a str,
        /// The topic URL segment.
        topic: &'a str,
    },
    /// Any other page (DMs, settings, admin, events, profile, legacy chat, …).
    Other,
}

/// First segments of every static route in `app.rs`. A path whose first
/// segment is one of these never resolves to a zone alias at the depths
/// [`static_depths`] lists for it.
const STATIC_ROUTES: &[(&str, &[usize])] = &[
    ("about", &[1]),
    ("login", &[1]),
    ("connect", &[1]),
    ("signup", &[1]),
    ("glossary", &[1]),
    ("view", &[2]),
    ("go", &[2]),
    ("join", &[2]),
    ("setup", &[1]),
    ("knowledge", &[1]),
    ("chat", &[1, 2]),
    ("dm", &[1, 2]),
    ("events", &[1]),
    ("profile", &[2]),
    ("settings", &[1]),
    ("admin", &[1]),
    ("governance", &[1]),
    ("pod", &[1]),
    ("wallet", &[1]),
    ("table", &[1]),
];

/// The depths (segment counts) at which `first` names a static route.
fn static_depths(first: &str) -> &'static [usize] {
    STATIC_ROUTES
        .iter()
        .find(|(name, _)| *name == first)
        .map(|(_, depths)| *depths)
        .unwrap_or(&[])
}

/// The path part of an app path: query and fragment dropped.
fn path_only(path: &str) -> &str {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    &path[..end]
}

impl<'a> ForumRoute<'a> {
    /// Classify a base-relative app path (`/welcome/s1a2b3c4d5e6`). Query,
    /// fragment, empty segments and trailing slashes are ignored.
    pub fn parse(path: &'a str) -> Self {
        let segs: Vec<&'a str> = path_only(path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let Some(&first) = segs.first() else {
            return ForumRoute::Root;
        };
        if first == "forums" {
            return match segs[1..] {
                [] => ForumRoute::Forums,
                [zone] => ForumRoute::Zone { legacy: true, zone },
                [zone, "board"] => ForumRoute::Board { legacy: true, zone },
                [zone, section] => ForumRoute::Section {
                    legacy: true,
                    zone,
                    section,
                },
                [zone, section, topic] => ForumRoute::Topic {
                    legacy: true,
                    zone,
                    section,
                    topic,
                },
                _ => ForumRoute::Other,
            };
        }
        // `/governance/admin` is the one static two-segment route whose first
        // segment is also a one-segment static route.
        if segs == ["governance", "admin"] || static_depths(first).contains(&segs.len()) {
            return ForumRoute::Other;
        }
        match segs[..] {
            [zone] => ForumRoute::Zone {
                legacy: false,
                zone,
            },
            [zone, "board"] => ForumRoute::Board {
                legacy: false,
                zone,
            },
            [zone, section] => ForumRoute::Section {
                legacy: false,
                zone,
                section,
            },
            [zone, section, topic] => ForumRoute::Topic {
                legacy: false,
                zone,
                section,
                topic,
            },
            _ => ForumRoute::Other,
        }
    }

    /// Whether this is the forum's front page, where Back is not shown.
    /// (A single-zone member's home zone is their front page too; that needs
    /// the zone config, so the component checks it.)
    pub fn is_front(&self) -> bool {
        matches!(self, ForumRoute::Root | ForumRoute::Forums)
    }

    /// The zone URL segment, for zone-scoped routes.
    pub fn zone(&self) -> Option<&'a str> {
        match *self {
            ForumRoute::Zone { zone, .. }
            | ForumRoute::Board { zone, .. }
            | ForumRoute::Section { zone, .. }
            | ForumRoute::Topic { zone, .. } => Some(zone),
            _ => None,
        }
    }

    /// One level up: topic → its section, section or board → its zone, zone
    /// → Forums, anything else → Forums. `None` on the front page.
    pub fn up_target(&self) -> Option<String> {
        let zone_path = |legacy: bool, zone: &str| {
            if legacy {
                format!("/forums/{zone}")
            } else {
                format!("/{zone}")
            }
        };
        match *self {
            ForumRoute::Root | ForumRoute::Forums => None,
            ForumRoute::Zone { .. } | ForumRoute::Other => Some(FORUMS.to_string()),
            ForumRoute::Board { legacy, zone } | ForumRoute::Section { legacy, zone, .. } => {
                Some(zone_path(legacy, zone))
            }
            ForumRoute::Topic {
                legacy,
                zone,
                section,
                ..
            } => Some(format!("{}/{section}", zone_path(legacy, zone))),
        }
    }
}

/// The Forums index route.
pub const FORUMS: &str = "/forums";

/// Routes that send the reader straight on elsewhere, or that a signed-in
/// member has no reason to return to: going back to one would bounce forward
/// again (`/` pushes `/forums`, `/go/…` forwards to the topic) or land on an
/// auth page. A previous history entry on one of these is not "in-app
/// history" for Back.
fn is_bounce_route(app_path: &str) -> bool {
    let segs: Vec<&str> = path_only(app_path)
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    matches!(
        segs[..],
        [] | ["chat"] | ["connect"] | ["login"] | ["signup"] | ["setup"] | ["join", _] | ["go", _]
    )
}

/// Whether the previous history entry's absolute URL is a page of this forum
/// that Back may return to: same origin, inside the forum's base path (`base`
/// is `""` when the forum is mounted at the root), and not a bounce route.
pub fn is_in_app_entry(prev_url: &str, origin: &str, base: &str) -> bool {
    let Some(rest) = prev_url.strip_prefix(origin) else {
        return false;
    };
    // `https://host.example.evil` must not pass for origin `https://host.example`.
    if !(rest.is_empty() || rest.starts_with(['/', '?', '#'])) {
        return false;
    }
    let path = path_only(rest);
    let app = if base.is_empty() {
        path
    } else if path == base {
        "/"
    } else {
        match path.strip_prefix(base) {
            Some(p) if p.starts_with('/') => p,
            _ => return false,
        }
    };
    !is_bounce_route(app)
}

/// Whether scroll position should be restored when returning to `app_path`.
/// A topic manages its own landing (it opens on the newest post or a focused
/// one), so it is left alone; every list page is restored.
pub fn restores_scroll(app_path: &str) -> bool {
    !matches!(ForumRoute::parse(app_path), ForumRoute::Topic { .. })
}

/// Whether a link from `current` to `target` (both base-relative paths) goes
/// one level up, to [`ForumRoute::up_target`]: following it returns to that
/// page, so its saved scroll position applies, as for Back.
pub fn is_up_link(current: &str, target: &str) -> bool {
    ForumRoute::parse(current).up_target().as_deref() == Some(path_only(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(path: &str) -> Option<String> {
        ForumRoute::parse(path).up_target()
    }

    #[test]
    fn front_pages_have_no_up_target() {
        for p in ["/", "", "/forums", "/forums/", "/?pwa=1"] {
            assert!(ForumRoute::parse(p).is_front(), "{p}");
            assert_eq!(up(p), None, "{p}");
        }
    }

    #[test]
    fn topic_goes_to_its_section() {
        assert_eq!(
            up("/welcome/s0123456789ab/t0123456789abcdef"),
            Some("/welcome/s0123456789ab".into())
        );
        assert_eq!(
            up("/welcome/s0123456789ab/t0123456789abcdef?focus=abc#p"),
            Some("/welcome/s0123456789ab".into())
        );
        assert_eq!(
            up("/forums/zone1/s0123456789ab/t0123456789abcdef"),
            Some("/forums/zone1/s0123456789ab".into())
        );
    }

    #[test]
    fn a_breadcrumb_to_the_parent_is_an_up_link() {
        let topic = "/minimoonoir/s00405652f2bf/teddb1228c6efe63d";
        assert!(is_up_link(topic, "/minimoonoir/s00405652f2bf"));
        assert!(is_up_link("/minimoonoir/s00405652f2bf", "/minimoonoir"));
        // The section-tag hash names the same section but is not its URL.
        assert!(!is_up_link(topic, "/minimoonoir/s6d38b5f106d8"));
        // Neither a sibling nor a page two levels up.
        assert!(!is_up_link(topic, "/minimoonoir/s2e0e14f07842"));
        assert!(!is_up_link(topic, "/minimoonoir"));
    }

    #[test]
    fn up_from_a_canonical_topic_is_the_canonical_section() {
        use crate::utils::section_url::{section_path, topic_path};
        // Rants in Minimoonoir: the canonical topic URL (channel-id hash)
        // goes up to the canonical section URL, never to the section-tag
        // hash (`s6d38b5f106d8`) the Forums index used to link.
        let cid = "62e1c0f409f0e35bacefb701e49ba85a8b6168ee48cc4a55eb70df8b8638e1bd";
        let root = "eddb1228c6efe63d00112233445566778899aabbccddeeff0011223344556677";
        let section = section_path("minimoonoir", cid);
        assert_eq!(section, "/minimoonoir/s00405652f2bf");
        assert_eq!(up(&topic_path("minimoonoir", cid, root)), Some(section));
    }

    #[test]
    fn section_and_board_go_to_their_zone() {
        assert_eq!(up("/welcome/s0123456789ab"), Some("/welcome".into()));
        assert_eq!(up("/welcome/s0123456789ab/"), Some("/welcome".into()));
        assert_eq!(up("/forums/zone1/lobby"), Some("/forums/zone1".into()));
        assert_eq!(up("/welcome/board"), Some("/welcome".into()));
        assert_eq!(up("/forums/zone1/board"), Some("/forums/zone1".into()));
        assert!(matches!(
            ForumRoute::parse("/welcome/board"),
            ForumRoute::Board { .. }
        ));
    }

    #[test]
    fn zone_goes_to_forums() {
        assert_eq!(up("/welcome"), Some("/forums".into()));
        assert_eq!(up("/forums/zone1"), Some("/forums".into()));
        // An unknown single segment is routed to the zone page ("Zone Not
        // Found"), so it is a zone here too.
        assert_eq!(up("/nope"), Some("/forums".into()));
        assert_eq!(ForumRoute::parse("/nope").zone(), Some("nope"));
    }

    #[test]
    fn static_routes_are_never_zones_and_go_to_forums() {
        for p in [
            "/go/abcdef",
            "/dm",
            "/dm/abcdef0123",
            "/settings",
            "/admin",
            "/chat",
            "/chat/abcdef",
            "/events",
            "/profile/abcdef",
            "/governance",
            "/governance/admin",
            "/pod",
            "/wallet",
            "/table",
            "/about",
            "/glossary",
            "/knowledge",
            "/view/note1xyz",
            "/join/CODE",
            "/login",
            "/signup",
            "/setup",
            "/connect",
        ] {
            assert_eq!(ForumRoute::parse(p), ForumRoute::Other, "{p}");
            assert_eq!(up(p), Some("/forums".into()), "{p}");
            assert_eq!(ForumRoute::parse(p).zone(), None, "{p}");
        }
    }

    #[test]
    fn static_first_segment_at_another_depth_is_a_zone_alias() {
        // No static route has this shape, so FlatRoutes falls through to the
        // dynamic alias, and so does the parser.
        assert_eq!(
            ForumRoute::parse("/about/board"),
            ForumRoute::Board {
                legacy: false,
                zone: "about"
            }
        );
        assert!(matches!(
            ForumRoute::parse("/dm/a/b"),
            ForumRoute::Topic { zone: "dm", .. }
        ));
    }

    #[test]
    fn too_deep_is_other() {
        assert_eq!(ForumRoute::parse("/a/b/c/d"), ForumRoute::Other);
        assert_eq!(ForumRoute::parse("/forums/a/b/c/d"), ForumRoute::Other);
    }

    const ORIGIN: &str = "https://forum.example";

    #[test]
    fn previous_entry_inside_the_base_is_in_app() {
        let base = "/community";
        assert!(is_in_app_entry(
            "https://forum.example/community/welcome/s0123456789ab",
            ORIGIN,
            base
        ));
        assert!(is_in_app_entry(
            "https://forum.example/community/forums?x=1",
            ORIGIN,
            base
        ));
        assert!(is_in_app_entry(
            "https://forum.example/community/dm/abc",
            ORIGIN,
            base
        ));
    }

    #[test]
    fn previous_entry_outside_the_app_is_not() {
        let base = "/community";
        // The host site, a sibling path, another origin, a look-alike host.
        assert!(!is_in_app_entry("https://forum.example/", ORIGIN, base));
        assert!(!is_in_app_entry(
            "https://forum.example/communityfoo/x",
            ORIGIN,
            base
        ));
        assert!(!is_in_app_entry(
            "https://other.example/community/forums",
            ORIGIN,
            base
        ));
        assert!(!is_in_app_entry(
            "https://forum.example.evil/community/forums",
            ORIGIN,
            base
        ));
    }

    #[test]
    fn previous_bounce_routes_are_not_history_to_return_to() {
        let base = "/community";
        for p in [
            "/community",
            "/community/",
            "/community/?pwa=1",
            "/community/chat",
            "/community/connect",
            "/community/login?returnTo=%2Fforums",
            "/community/signup",
            "/community/setup",
            "/community/join/CODE",
            "/community/go/abcdef",
        ] {
            let url = format!("{ORIGIN}{p}");
            assert!(!is_in_app_entry(&url, ORIGIN, base), "{p}");
        }
        // But a legacy chat channel is a real page.
        assert!(is_in_app_entry(
            &format!("{ORIGIN}/community/chat/abc"),
            ORIGIN,
            base
        ));
    }

    #[test]
    fn root_mounted_forum() {
        assert!(is_in_app_entry("https://forum.example/welcome", ORIGIN, ""));
        assert!(!is_in_app_entry("https://forum.example/", ORIGIN, ""));
        assert!(!is_in_app_entry("https://forum.example", ORIGIN, ""));
    }

    #[test]
    fn scroll_is_restored_on_lists_not_topics() {
        assert!(restores_scroll("/forums"));
        assert!(restores_scroll("/welcome"));
        assert!(restores_scroll("/welcome/s0123456789ab"));
        assert!(restores_scroll("/dm"));
        assert!(!restores_scroll("/welcome/s0123456789ab/t0123456789abcdef"));
    }
}
