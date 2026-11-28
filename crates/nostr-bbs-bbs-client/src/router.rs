//! Hash-based URL router for the retro BBS workspace.
//!
//! Using `#/...` hash routing works cleanly under any sub-path deployment
//! (such as `/community/bbs/`) with zero reverse-proxy SPA fallback rules,
//! supports browser Back/Forward, reload persistence, and shareable deep links,
//! while keeping `?pwa=1` query parameters intact for ADR-109 zone-bound boot.

use leptos::prelude::*;
use nostr_bbs_client_core::base_href;
use nostr_bbs_client_core::stores::channels::{ChannelMeta, ChannelStore};
use nostr_bbs_client_core::stores::zones::{load_zones, resolve_zone_param, zone_slug, Zone};
use nostr_bbs_client_core::utils::post_link::jump_link;
use nostr_bbs_client_core::utils::section_url::{canonical_section_path, section_path};
use nostr_bbs_client_core::utils::slug_hash::topic_slug;

/// Every navigable location in the re-imagined BBS workspace.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Route {
    /// Logged-out welcome / onboarding screen.
    Landing,
    /// Transient iOS PWA first-launch identity rebind (ADR-109).
    Rebind,
    /// Top-level Zones directory (home dashboard).
    #[default]
    Zones,
    /// One zone's overview: boards list + Kanban shortcut + zone banner.
    Zone { slug: String },
    /// A board's topic list (kind-40 channel).
    Board { zone: String, channel_id: String },
    /// A thread view (root kind-42 + kind-42/1111 replies), opened at its
    /// newest post, or at post `focus` when set (a notification, a search
    /// hit, a bookmark).
    Thread {
        zone: String,
        channel_id: String,
        root_id: String,
        focus: Option<String>,
    },
    /// A link to one post (`event_id`, optionally its channel), resolved to
    /// the topic that holds it and replaced by that [`Route::Thread`]. The
    /// BBS form of the forum's `/go/<id>?c=<channel>`.
    Go {
        event_id: String,
        channel: Option<String>,
    },
    /// Per-zone Kanban board (kind-30301 / kind-30302).
    Kanban { zone: String },
    /// Live cross-channel activity feed.
    LiveFeed,
    /// Direct messages inbox + NIP-17 Requests lane.
    DmList,
    /// One encrypted 1:1 DM conversation.
    DmChat { pubkey: String },
    /// Agent governance control plane (kinds 31400–31405).
    Agents,
    /// Calendar & community events (NIP-52 kinds 31923 / 31925).
    Events,
    /// Shared-agent-learning Colloquy knowledge board (ADR-2085/2086).
    Knowledge,
    /// Door Games arcade hub (UA 571-C Sentry Gun + Heads-Up Poker).
    Games,
    /// Terminal Heads-Up Limit Hold'em Poker table (practice or chain asset).
    Poker { chain: Option<String> },
    /// Multi-chain Sidestr Wallet (DREAM / BLAKES7).
    Wallet,
    /// Authenticated Solid Pod browser + Git panel.
    Pod { path: String },
    /// Member directory (kind-0 / did:nostr).
    Members,
    /// Single member profile (bio, did:nostr, WebID, NIP-58 badges, activity).
    Profile { pubkey: String },
    /// Notifications center (mentions, replies, DMs).
    Notifications,
    /// Saved bookmarks (per-identity).
    Bookmarks,
    /// Settings: theme, CRT effects, a11y, profile edit, identity, PWA, backup.
    Settings,
    /// Interactive help & keyboard reference.
    Help,
}

impl Route {
    /// Canonical hash fragment (starting with `#/`).
    pub fn to_hash(&self) -> String {
        match self {
            Route::Landing => "#/welcome".into(),
            Route::Rebind => "#/rebind".into(),
            Route::Zones => "#/zones".into(),
            Route::Zone { slug } => format!("#/z/{slug}"),
            Route::Board { zone, channel_id } => format!("#/z/{zone}/b/{channel_id}"),
            Route::Thread {
                zone,
                channel_id,
                root_id,
                focus: None,
            } => format!("#/z/{zone}/b/{channel_id}/t/{root_id}"),
            Route::Thread {
                zone,
                channel_id,
                root_id,
                focus: Some(f),
            } => format!("#/z/{zone}/b/{channel_id}/t/{root_id}/p/{f}"),
            Route::Go {
                event_id,
                channel: None,
            } => format!("#/go/{event_id}"),
            Route::Go {
                event_id,
                channel: Some(c),
            } => format!("#/go/{event_id}/c/{c}"),
            Route::Kanban { zone } => format!("#/z/{zone}/kanban"),
            Route::LiveFeed => "#/live".into(),
            Route::DmList => "#/dm".into(),
            Route::DmChat { pubkey } => format!("#/dm/{pubkey}"),
            Route::Agents => "#/agents".into(),
            Route::Events => "#/events".into(),
            Route::Knowledge => "#/knowledge".into(),
            Route::Games => "#/games".into(),
            Route::Poker { chain: None } => "#/games/poker".into(),
            Route::Poker { chain: Some(c) } => format!("#/games/poker/{c}"),
            Route::Wallet => "#/wallet".into(),
            Route::Pod { path } if path.is_empty() => "#/pod".into(),
            Route::Pod { path } => format!("#/pod/{}", path.trim_start_matches('/')),
            Route::Members => "#/members".into(),
            Route::Profile { pubkey } => format!("#/profile/{pubkey}"),
            Route::Notifications => "#/notifications".into(),
            Route::Bookmarks => "#/bookmarks".into(),
            Route::Settings => "#/settings".into(),
            Route::Help => "#/help".into(),
        }
    }

    /// Parse a `location.hash` string into a [`Route`].
    pub fn from_hash(raw: &str) -> Self {
        let path = raw.trim().trim_start_matches('#');
        // A forum-style query (`#/go/<id>?c=<channel>`) is accepted too.
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let param = |k: &str| {
            query
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .find(|(key, v)| *key == k && !v.is_empty())
                .map(|(_, v)| v.to_string())
        };
        let path = path.trim_matches('/');
        if path.is_empty() {
            return Route::Zones;
        }
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match segs.as_slice() {
            ["welcome"] | ["landing"] => Route::Landing,
            ["rebind"] => Route::Rebind,
            ["zones"] | ["boards"] | ["home"] => Route::Zones,
            ["z", slug] => Route::Zone {
                slug: (*slug).to_string(),
            },
            ["z", zone, "kanban"] | ["z", zone, "board"] => Route::Kanban {
                zone: (*zone).to_string(),
            },
            ["z", zone, "b", channel_id] => Route::Board {
                zone: (*zone).to_string(),
                channel_id: (*channel_id).to_string(),
            },
            ["z", zone, "b", channel_id, "t", root_id] => Route::Thread {
                zone: (*zone).to_string(),
                channel_id: (*channel_id).to_string(),
                root_id: (*root_id).to_string(),
                focus: param("focus"),
            },
            ["z", zone, "b", channel_id, "t", root_id, "p", focus] => Route::Thread {
                zone: (*zone).to_string(),
                channel_id: (*channel_id).to_string(),
                root_id: (*root_id).to_string(),
                focus: Some((*focus).to_string()),
            },
            ["go", event_id] => Route::Go {
                event_id: (*event_id).to_string(),
                channel: param("c"),
            },
            ["go", event_id, "c", channel] => Route::Go {
                event_id: (*event_id).to_string(),
                channel: Some((*channel).to_string()),
            },
            ["live"] | ["chat"] => Route::LiveFeed,
            ["dm"] | ["dms"] | ["inbox"] => Route::DmList,
            ["dm", pubkey] => Route::DmChat {
                pubkey: (*pubkey).to_string(),
            },
            ["agents"] | ["governance"] | ["gov"] => Route::Agents,
            ["events"] | ["calendar"] => Route::Events,
            ["knowledge"] | ["colloquy"] => Route::Knowledge,
            ["games"] | ["doors"] => Route::Games,
            ["games", "poker"] | ["poker"] => Route::Poker { chain: None },
            ["games", "poker", chain] | ["poker", chain] => Route::Poker {
                chain: Some((*chain).to_string()),
            },
            ["wallet"] => Route::Wallet,
            ["pod"] => Route::Pod {
                path: String::new(),
            },
            ["pod", rest @ ..] => Route::Pod {
                path: rest.join("/"),
            },
            ["members"] | ["users"] => Route::Members,
            ["profile", pubkey] => Route::Profile {
                pubkey: (*pubkey).to_string(),
            },
            ["notifications"] | ["alerts"] => Route::Notifications,
            ["bookmarks"] => Route::Bookmarks,
            ["settings"] | ["config"] => Route::Settings,
            ["help"] | ["about"] => Route::Help,
            _ => Route::Zones,
        }
    }

    /// Short title displayed in the topbar & page header.
    pub fn title(&self) -> &'static str {
        match self {
            Route::Landing => "Welcome",
            Route::Rebind => "Re-link Device",
            Route::Zones => "Zones",
            Route::Zone { .. } => "Zone",
            Route::Board { .. } => "Board",
            Route::Thread { .. } => "Thread",
            Route::Go { .. } => "Opening Post",
            Route::Kanban { .. } => "Kanban",
            Route::LiveFeed => "Live Feed",
            Route::DmList | Route::DmChat { .. } => "Direct Messages",
            Route::Agents => "Agents & Governance",
            Route::Events => "Events & Calendar",
            Route::Knowledge => "Knowledge Board",
            Route::Games => "Door Games",
            Route::Poker { .. } => "Poker Table",
            Route::Wallet => "Sidestr Wallet",
            Route::Pod { .. } => "Solid Pod",
            Route::Members => "Members",
            Route::Profile { .. } => "Profile",
            Route::Notifications => "Notifications",
            Route::Bookmarks => "Bookmarks",
            Route::Settings => "Settings",
            Route::Help => "Help & Keys",
        }
    }

    /// Parent route for the ESC / back affordance.
    pub fn parent(&self, pinned_zone: Option<&str>) -> Route {
        match self {
            Route::Thread {
                zone, channel_id, ..
            } => Route::Board {
                zone: zone.clone(),
                channel_id: channel_id.clone(),
            },
            Route::Board { zone, .. } | Route::Kanban { zone } => {
                Route::Zone { slug: zone.clone() }
            }
            Route::Zone { .. } => match pinned_zone {
                Some(z) => Route::Zone {
                    slug: z.to_string(),
                },
                None => Route::Zones,
            },
            Route::DmChat { .. } => Route::DmList,
            Route::Poker { .. } => Route::Games,
            Route::Profile { .. } => Route::Members,
            Route::Pod { path } if !path.is_empty() => {
                let trimmed = path.trim_end_matches('/');
                let parent_path = match trimmed.rfind('/') {
                    Some(i) => format!("{}/", &trimmed[..i]),
                    None => String::new(),
                };
                Route::Pod { path: parent_path }
            }
            _ => match pinned_zone {
                Some(z) => Route::Zone {
                    slug: z.to_string(),
                },
                None => Route::Zones,
            },
        }
    }
}

impl Route {
    /// The equivalent page of the modern forum, as an app-relative path
    /// (prefix it with `base_href`): a board opens its section page, a thread
    /// its topic page (at the focused post when there is one), a post link
    /// the forum's own resolver, and the other views their forum
    /// counterparts. The forum's front page where there is none.
    ///
    /// Section and topic paths are the forum's canonical ones
    /// (client-core `utils::section_url`): `/<zone-slug>/<channel-id hash>`
    /// and `…/<topic hash>`. The zone comes from the channel's own section
    /// tag when `channels` holds its metadata, exactly as the forum derives
    /// it, so the forum never has to replace the address; otherwise from
    /// the route's zone.
    pub fn forum_path(&self, zones: &[Zone], channels: &[ChannelMeta]) -> String {
        // The forum accepts a zone's slug or id; links carry the slug.
        let zone_path = |z: &str| {
            resolve_zone_param(z, zones)
                .map(|z| zone_slug(z).to_string())
                .unwrap_or_else(|| z.to_string())
        };
        let section = |zone: &str, channel_id: &str| {
            channels
                .iter()
                .find(|c| c.id == channel_id)
                .and_then(|c| canonical_section_path(c, zones))
                .unwrap_or_else(|| section_path(&zone_path(zone), channel_id))
        };
        match self {
            Route::Zone { slug } => format!("/{}", zone_path(slug)),
            Route::Board { zone, channel_id } => section(zone, channel_id),
            Route::Thread {
                zone,
                channel_id,
                root_id,
                focus,
            } => {
                let topic = format!("{}/{}", section(zone, channel_id), topic_slug(root_id));
                match focus {
                    Some(f) => format!("{topic}?focus={f}"),
                    None => topic,
                }
            }
            Route::Go { event_id, channel } => jump_link(event_id, channel.as_deref()),
            Route::Kanban { zone } => format!("/{}/board", zone_path(zone)),
            Route::Zones | Route::LiveFeed => "/forums".into(),
            Route::DmList => "/dm".into(),
            Route::DmChat { pubkey } => format!("/dm/{pubkey}"),
            Route::Agents => "/governance".into(),
            Route::Events => "/events".into(),
            Route::Knowledge => "/knowledge".into(),
            Route::Wallet => "/wallet".into(),
            Route::Pod { .. } => "/pod".into(),
            Route::Profile { pubkey } => format!("/profile/{pubkey}"),
            Route::Settings => "/settings".into(),
            Route::Poker { .. } => "/table".into(),
            Route::Landing
            | Route::Rebind
            | Route::Games
            | Route::Members
            | Route::Notifications
            | Route::Bookmarks
            | Route::Help => "/".into(),
        }
    }
}

/// The href of `route`'s equivalent page in the modern forum
/// ([`Route::forum_path`] under the forum's base path), with the channel
/// metadata `channels` holds. Tracks the channel list when read reactively.
pub fn forum_href(route: &Route, channels: ChannelStore) -> String {
    let zones = load_zones();
    channels
        .channels
        .with(|cs| base_href(&route.forum_path(&zones, cs)))
}

/// Parse a `/command` string into a [`CommandAction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAction {
    Navigate(Route),
    Search(Option<String>),
    CycleTheme,
    ToggleCrt,
    ToggleSidebar,
    LaunchSentry,
    OpenForum,
    Back,
    Unknown(String),
}

/// Parse text typed into the `/` command bar.
pub fn parse_slash_command(raw: &str) -> CommandAction {
    let trimmed = raw.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return CommandAction::Unknown(String::new());
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let head = parts.next().unwrap_or("").to_ascii_lowercase();
    let arg = parts.next().map(str::trim).filter(|s| !s.is_empty());

    match head.as_str() {
        "search" | "find" | "s" => CommandAction::Search(arg.map(str::to_string)),
        "theme" | "t" | "color" | "colour" => CommandAction::CycleTheme,
        "crt" | "scanlines" => CommandAction::ToggleCrt,
        "sidebar" | "nav" => CommandAction::ToggleSidebar,
        "sentry" | "aliens" => CommandAction::LaunchSentry,
        "forum" | "web" | "exit" | "quit" | "bye" => CommandAction::OpenForum,
        "back" | "b" => CommandAction::Back,
        "zones" | "boards" | "home" | "1" => CommandAction::Navigate(Route::Zones),
        "live" | "feed" | "chat" | "2" => CommandAction::Navigate(Route::LiveFeed),
        "dm" | "dms" | "inbox" | "3" => match arg {
            Some(pk) => CommandAction::Navigate(Route::DmChat {
                pubkey: pk.to_string(),
            }),
            None => CommandAction::Navigate(Route::DmList),
        },
        "agents" | "gov" | "governance" | "4" => CommandAction::Navigate(Route::Agents),
        "events" | "calendar" | "cal" | "5" => CommandAction::Navigate(Route::Events),
        "knowledge" | "colloquy" | "kb" | "6" => CommandAction::Navigate(Route::Knowledge),
        "games" | "doors" | "arcade" | "7" => CommandAction::Navigate(Route::Games),
        "poker" | "table" => CommandAction::Navigate(Route::Poker {
            chain: arg.map(str::to_string),
        }),
        "wallet" | "dream" | "8" => CommandAction::Navigate(Route::Wallet),
        "pod" | "files" | "git" | "9" => CommandAction::Navigate(Route::Pod {
            path: arg.unwrap_or("").to_string(),
        }),
        "members" | "users" | "who" => CommandAction::Navigate(Route::Members),
        "bookmarks" | "saved" => CommandAction::Navigate(Route::Bookmarks),
        "notifications" | "alerts" | "notifs" => CommandAction::Navigate(Route::Notifications),
        "settings" | "prefs" | "config" => CommandAction::Navigate(Route::Settings),
        "help" | "about" | "?" | "0" => CommandAction::Navigate(Route::Help),
        "z" | "zone" => match arg {
            Some(slug) => CommandAction::Navigate(Route::Zone {
                slug: slug.to_string(),
            }),
            None => CommandAction::Navigate(Route::Zones),
        },
        "kanban" | "tasks" => match arg {
            Some(slug) => CommandAction::Navigate(Route::Kanban {
                zone: slug.to_string(),
            }),
            None => CommandAction::Navigate(Route::Zones),
        },
        _ => CommandAction::Unknown(trimmed.to_string()),
    }
}

/// Reactive router state provided at the BBS root.
#[derive(Clone, Copy)]
pub struct Router {
    pub route: RwSignal<Route>,
    /// ADR-109 zone-bound PWA mode (hides multi-zone switcher when active).
    pub pwa_mode: RwSignal<bool>,
    /// Pinned zone id when in ADR-109 PWA mode.
    pub pinned_zone: RwSignal<Option<String>>,
}

impl Router {
    /// Create a router initialized to `initial`.
    pub fn new(initial: Route, pwa_mode: bool, pinned_zone: Option<String>) -> Self {
        Self {
            route: RwSignal::new(initial),
            pwa_mode: RwSignal::new(pwa_mode),
            pinned_zone: RwSignal::new(pinned_zone),
        }
    }

    /// Navigate to `target`, honoring ADR-109 zone pinning and updating `location.hash`.
    pub fn go(&self, target: Route) {
        let effective = self.enforce_pin(target);
        let hash = effective.to_hash();
        self.route.set(effective);
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(win) = web_sys::window() {
                let loc = win.location();
                if loc.hash().ok().as_deref() != Some(hash.as_str()) {
                    let _ = loc.set_hash(&hash);
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = hash;
    }

    /// Navigate to `target` in place of the current history entry (a
    /// resolver route such as [`Route::Go`] handing over to its result, so
    /// Back does not return to the resolver).
    pub fn replace(&self, target: Route) {
        let effective = self.enforce_pin(target);
        let hash = effective.to_hash();
        self.route.set(effective);
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(win) = web_sys::window() {
                let loc = win.location();
                if loc.hash().ok().as_deref() != Some(hash.as_str()) {
                    let _ = loc.replace(&hash);
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = hash;
    }

    /// Navigate up one level in the route hierarchy.
    pub fn back(&self) {
        let pinned = self.pinned_zone.get_untracked();
        let next = self.route.get_untracked().parent(pinned.as_deref());
        self.go(next);
    }

    /// Enter ADR-109 zone-pinned PWA mode.
    pub fn enter_pwa(&self, zone_id: String) {
        self.pwa_mode.set(true);
        self.pinned_zone.set(Some(zone_id.clone()));
        self.go(Route::Zone { slug: zone_id });
    }

    fn enforce_pin(&self, target: Route) -> Route {
        if self.pwa_mode.get_untracked() {
            if let Some(pin) = self.pinned_zone.get_untracked() {
                if matches!(target, Route::Zones | Route::Landing) {
                    return Route::Zone { slug: pin };
                }
            }
        }
        target
    }

    /// Attach a `hashchange` listener so browser Back/Forward stays in sync.
    #[cfg(target_arch = "wasm32")]
    pub fn install_hash_listener(&self) {
        use wasm_bindgen::prelude::*;
        let router = *self;
        let cb = Closure::<dyn FnMut()>::new(move || {
            if let Some(hash) = web_sys::window().and_then(|w| w.location().hash().ok()) {
                let parsed = router.enforce_pin(Route::from_hash(&hash));
                if router.route.get_untracked() != parsed {
                    router.route.set(parsed);
                }
            }
        });
        if let Some(win) = web_sys::window() {
            let _ = win.add_event_listener_with_callback("hashchange", cb.as_ref().unchecked_ref());
        }
        cb.forget();
    }
}

/// Read the initial hash route from `window.location.hash` (wasm).
#[cfg(target_arch = "wasm32")]
pub fn current_hash_route() -> Option<Route> {
    let hash = web_sys::window()?.location().hash().ok()?;
    let trimmed = hash.trim().trim_start_matches('#').trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(Route::from_hash(&hash))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn current_hash_route() -> Option<Route> {
    None
}

/// Provide the router in Leptos context.
pub fn provide_router(router: Router) {
    provide_context(router);
}

/// Retrieve the router from Leptos context.
pub fn use_router() -> Router {
    expect_context::<Router>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_hash_round_trips() {
        let cases = vec![
            Route::Landing,
            Route::Rebind,
            Route::Zones,
            Route::Zone {
                slug: "public".into(),
            },
            Route::Board {
                zone: "public".into(),
                channel_id: "abc123".into(),
            },
            Route::Thread {
                zone: "public".into(),
                channel_id: "abc123".into(),
                root_id: "def456".into(),
                focus: None,
            },
            Route::Thread {
                zone: "public".into(),
                channel_id: "abc123".into(),
                root_id: "def456".into(),
                focus: Some("fff999".into()),
            },
            Route::Go {
                event_id: "e1".into(),
                channel: None,
            },
            Route::Go {
                event_id: "e1".into(),
                channel: Some("c1".into()),
            },
            Route::Kanban {
                zone: "friends".into(),
            },
            Route::LiveFeed,
            Route::DmList,
            Route::DmChat {
                pubkey: "deadbeef".into(),
            },
            Route::Agents,
            Route::Events,
            Route::Knowledge,
            Route::Games,
            Route::Poker { chain: None },
            Route::Poker {
                chain: Some("sidestr-dreamlab".into()),
            },
            Route::Wallet,
            Route::Pod {
                path: String::new(),
            },
            Route::Pod {
                path: "media/public".into(),
            },
            Route::Members,
            Route::Profile {
                pubkey: "cafe".into(),
            },
            Route::Notifications,
            Route::Bookmarks,
            Route::Settings,
            Route::Help,
        ];
        for r in cases {
            let h = r.to_hash();
            assert_eq!(Route::from_hash(&h), r, "round-trip failed for {h}");
        }
    }

    #[test]
    fn slash_command_parsing() {
        assert_eq!(
            parse_slash_command("search hello world"),
            CommandAction::Search(Some("hello world".into()))
        );
        assert_eq!(
            parse_slash_command("/poker dream"),
            CommandAction::Navigate(Route::Poker {
                chain: Some("dream".into())
            })
        );
        assert_eq!(parse_slash_command("sentry"), CommandAction::LaunchSentry);
        assert_eq!(parse_slash_command("crt"), CommandAction::ToggleCrt);
        assert_eq!(parse_slash_command("theme"), CommandAction::CycleTheme);
        assert_eq!(
            parse_slash_command("z friends"),
            CommandAction::Navigate(Route::Zone {
                slug: "friends".into()
            })
        );
        assert_eq!(
            parse_slash_command("kanban friends"),
            CommandAction::Navigate(Route::Kanban {
                zone: "friends".into()
            })
        );
    }

    #[test]
    fn parent_navigation_respects_pin() {
        let t = Route::Thread {
            zone: "fam".into(),
            channel_id: "c1".into(),
            root_id: "r1".into(),
            focus: Some("p1".into()),
        };
        assert_eq!(
            t.parent(None),
            Route::Board {
                zone: "fam".into(),
                channel_id: "c1".into()
            }
        );
        assert_eq!(
            Route::Zone { slug: "fam".into() }.parent(Some("fam")),
            Route::Zone { slug: "fam".into() }
        );
        assert_eq!(
            Route::Zone { slug: "fam".into() }.parent(None),
            Route::Zones
        );
    }

    #[test]
    fn forum_style_queries_parse() {
        assert_eq!(
            Route::from_hash("#/go/abc?c=chan"),
            Route::Go {
                event_id: "abc".into(),
                channel: Some("chan".into())
            }
        );
        assert_eq!(
            Route::from_hash("#/go/abc"),
            Route::Go {
                event_id: "abc".into(),
                channel: None
            }
        );
        assert_eq!(
            Route::from_hash("#/z/z1/b/c1/t/r1?focus=p1"),
            Route::Thread {
                zone: "z1".into(),
                channel_id: "c1".into(),
                root_id: "r1".into(),
                focus: Some("p1".into())
            },
            "a query never ends up inside the root id"
        );
    }

    #[test]
    fn forum_path_opens_the_equivalent_page() {
        use nostr_bbs_client_core::utils::slug_hash::section_slug;
        let cid = "a".repeat(64);
        let root = "b".repeat(64);
        let board = Route::Board {
            zone: "zone-x".into(),
            channel_id: cid.clone(),
        };
        assert_eq!(
            board.forum_path(&[], &[]),
            format!("/zone-x/{}", section_slug(&cid))
        );
        let thread = Route::Thread {
            zone: "zone-x".into(),
            channel_id: cid.clone(),
            root_id: root.clone(),
            focus: None,
        };
        assert_eq!(
            thread.forum_path(&[], &[]),
            format!("/zone-x/{}/{}", section_slug(&cid), topic_slug(&root))
        );
        let focused = Route::Thread {
            zone: "zone-x".into(),
            channel_id: cid.clone(),
            root_id: root.clone(),
            focus: Some("p1".into()),
        };
        assert!(focused.forum_path(&[], &[]).ends_with("?focus=p1"));
        assert_eq!(
            Route::Go {
                event_id: "e1".into(),
                channel: Some("chan".into())
            }
            .forum_path(&[], &[]),
            "/go/e1?c=chan"
        );
        assert_eq!(
            Route::Zone {
                slug: "zone-x".into()
            }
            .forum_path(&[], &[]),
            "/zone-x"
        );
        assert_eq!(Route::Zones.forum_path(&[], &[]), "/forums");
        assert_eq!(Route::Help.forum_path(&[], &[]), "/");
    }

    /// The live Rants section: the forum's canonical URL for it (and its
    /// topics) is what the BBS links to, whichever form of the zone the BBS
    /// route carries and even when the route names another zone.
    #[test]
    fn forum_path_is_the_forums_canonical_section_url() {
        use nostr_bbs_client_core::utils::section_url::canonical_topic_path;
        let zones: Vec<Zone> = serde_json::from_str(
            r#"[
                {"id":"zone1","slug":"welcome","display_name":"Welcome"},
                {"id":"zone2","slug":"minimoonoir","display_name":"Minimoonoir"}
            ]"#,
        )
        .expect("zone config parses");
        let rants = ChannelMeta {
            id: "62e1c0f409f0e35bacefb701e49ba85a8b6168ee48cc4a55eb70df8b8638e1bd".into(),
            name: "Rants".into(),
            description: String::new(),
            section: "zone2-rants".into(),
            section_tag: "zone2-rants".into(),
            picture: String::new(),
            created_at: 0,
        };
        let channels = vec![rants.clone()];
        let canonical = canonical_section_path(&rants, &zones).expect("canonical");
        assert_eq!(canonical, "/minimoonoir/s00405652f2bf");
        for zone in ["zone2", "minimoonoir", "zone1"] {
            let board = Route::Board {
                zone: zone.into(),
                channel_id: rants.id.clone(),
            };
            assert_eq!(board.forum_path(&zones, &channels), canonical, "{zone}");
        }
        let root = "c".repeat(64);
        let thread = Route::Thread {
            zone: "zone2".into(),
            channel_id: rants.id.clone(),
            root_id: root.clone(),
            focus: None,
        };
        assert_eq!(
            Some(thread.forum_path(&zones, &channels)),
            canonical_topic_path(&rants, "", Some(&root), &zones)
        );
        // Without the channel's metadata: the route's zone, as its slug.
        let board = Route::Board {
            zone: "zone2".into(),
            channel_id: rants.id.clone(),
        };
        assert_eq!(board.forum_path(&zones, &[]), canonical);
    }
}
