//! BBS navigation model: the ten screens, the main-menu layout, and the
//! command-line / keyboard parsing. All pure so it can be unit-tested natively;
//! the Leptos views in `screens` and `chrome` render on top of it.
//!
//! Each screen maps to a REAL kit capability rather than being cosmetic:
//! Boards → config zones + kind-40/42 channels, Pod → the Solid pod browser,
//! Network → relays + federation mesh, Members → did:nostr WebID profiles,
//! Agents → the agent-governance control-panel plane (human-in-the-loop), Status
//! → DID/relay/pod status, etc. Agents leads the menu: it is the highest-value
//! feature and must not be buried behind wildcat-BBS jargon.

/// One of the ten BBS screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// Logged-out onboarding landing — what this is + how to get in. Shown before
    /// the numbered menu when signed out and the viewer hasn't chosen to look
    /// around. Not a numbered menu item; reached only as the signed-out entry.
    Landing,
    /// Encrypted 1:1 direct messages (NIP-44 sealed, NIP-59 gift-wrapped). Reached
    /// from the bottom-nav "DMs" tab / `/dm`; not a numbered main-menu item.
    Dm,
    /// The numbered main menu (home screen once past onboarding).
    #[default]
    MainMenu,
    /// Agent control panels — approve, reject, act (human-in-the-loop).
    Agents,
    /// Zones & boards — kind-40/42 channels, zone-gated.
    Boards,
    /// Live channel & encrypted DMs (NIP-44 / NIP-59).
    Chat,
    /// Members — did:nostr WebID profiles.
    Members,
    /// Solid pod browser — WebID-owned storage.
    Pod,
    /// Shared snippets & pod files.
    Code,
    /// Relays & federation mesh peers.
    Network,
    /// Node / relay / pod / identity status.
    Status,
    /// Theme + identity + node settings.
    Settings,
    /// Help / about.
    Help,
}

impl Screen {
    /// The ten selectable screens, in main-menu order.
    pub fn menu_order() -> [Screen; 10] {
        [
            Screen::Agents,
            Screen::Boards,
            Screen::Chat,
            Screen::Members,
            Screen::Pod,
            Screen::Code,
            Screen::Network,
            Screen::Status,
            Screen::Settings,
            Screen::Help,
        ]
    }

    /// The number key (`'1'`..='9'`, `'0'` for the tenth) that selects this
    /// screen from the main menu, or `None` for the main menu itself.
    pub fn menu_key(self) -> Option<char> {
        Screen::menu_order()
            .iter()
            .position(|s| *s == self)
            .map(|i| {
                if i == 9 {
                    '0'
                } else {
                    (b'1' + i as u8) as char
                }
            })
    }

    /// Resolve a main-menu number key to its screen.
    pub fn from_menu_key(key: char) -> Option<Screen> {
        let order = Screen::menu_order();
        let idx = match key {
            '0' => 9,
            '1'..='9' => (key as u8 - b'1') as usize,
            _ => return None,
        };
        order.get(idx).copied()
    }

    /// Short title (shown in the menu and the screen header).
    pub fn title(self) -> &'static str {
        match self {
            Screen::Landing => "Welcome",
            Screen::Dm => "Direct Messages",
            Screen::MainMenu => "Main Menu",
            Screen::Agents => "Agents",
            Screen::Boards => "Boards",
            Screen::Chat => "Chat",
            Screen::Members => "Members",
            Screen::Pod => "Pod",
            Screen::Code => "Code",
            Screen::Network => "Network",
            Screen::Status => "Status",
            Screen::Settings => "Settings",
            Screen::Help => "Help",
        }
    }

    /// One-line description of the real kit feature behind the screen.
    pub fn subtitle(self) -> &'static str {
        match self {
            Screen::Landing => "What this is, and how to get in",
            Screen::Dm => "Encrypted 1:1 — NIP-44 sealed, NIP-59 gift-wrapped",
            Screen::MainMenu => "Select a board by number, or type / for a command",
            Screen::Agents => "Agent control panels — approve, reject, act (human-in-the-loop)",
            Screen::Boards => "Zones & boards — kind-40/42 channels, zone-gated",
            Screen::Chat => "Live channel & encrypted DMs (NIP-44/59)",
            Screen::Members => "Members — did:nostr WebID profiles",
            Screen::Pod => "Your Solid pod — WebID-owned storage",
            Screen::Code => "Shared snippets & pod files",
            Screen::Network => "Relays & federation mesh peers",
            Screen::Status => "Node / relay / pod / identity status",
            Screen::Settings => "Theme, identity & node settings",
            Screen::Help => "About the BBS, zones, agents & pods",
        }
    }

    /// Command-line aliases that jump to this screen (typed after `/`).
    pub fn aliases(self) -> &'static [&'static str] {
        match self {
            Screen::Landing => &["welcome", "start", "landing"],
            Screen::Dm => &["dm", "dms", "inbox"],
            Screen::MainMenu => &["menu", "main", "home"],
            Screen::Agents => &["agents", "gov", "door", "doors", "admin", "d", "agent"],
            Screen::Boards => &["msg", "messages", "boards", "m", "board"],
            Screen::Chat => &["chat", "c"],
            Screen::Members => &["users", "members", "who", "u", "member"],
            Screen::Pod => &["files", "file", "pod", "f", "pods"],
            Screen::Code => &["code", "snippets", "x", "snippet"],
            Screen::Network => &["nodes", "relays", "net", "n", "node"],
            Screen::Status => &["sys", "system", "info", "status", "s"],
            Screen::Settings => &["settings", "set", "config"],
            Screen::Help => &["help", "about", "?"],
        }
    }
}

/// A parsed command-line action (input typed after the `/` prompt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Navigate to a screen.
    Go(Screen),
    /// Return to the previous screen (or main menu).
    Back,
    /// Cycle the colour theme.
    Theme,
    /// Quit back to the host site.
    Quit,
    /// Launch the UA 571-C sentry-gun door game (Easter egg, off the main path).
    Sentry,
    /// Open the global-search overlay (F11). A bare `search` / `find` maps here;
    /// `search <q>` with a query is intercepted earlier by the command line so
    /// the query text survives (this enum is `Copy` and carries no `String`).
    Search,
    /// Unrecognised command.
    Unknown,
}

/// Parse a command-line string (without the leading `/`).
///
/// Accepts a bare menu number (`"3"`), a screen alias (`"files"`), or a control
/// word (`"back"`, `"theme"`, `"quit"`, `"sentry"`). Leading/trailing whitespace
/// and case are ignored.
pub fn parse_command(raw: &str) -> Command {
    let cmd = raw.trim().to_ascii_lowercase();
    if cmd.is_empty() {
        return Command::Unknown;
    }
    match cmd.as_str() {
        "back" | "b" | "esc" => return Command::Back,
        "theme" | "t" | "color" | "colour" => return Command::Theme,
        "quit" | "q" | "exit" | "logoff" | "bye" => return Command::Quit,
        "sentry" | "game" => return Command::Sentry,
        "search" | "find" => return Command::Search,
        _ => {}
    }
    if let Some(ch) = cmd.chars().next() {
        if cmd.len() == 1 {
            if let Some(s) = Screen::from_menu_key(ch) {
                return Command::Go(s);
            }
        }
    }
    for screen in [Screen::Landing, Screen::MainMenu, Screen::Dm]
        .into_iter()
        .chain(Screen::menu_order())
    {
        if screen.aliases().contains(&cmd.as_str()) {
            return Command::Go(screen);
        }
    }
    Command::Unknown
}

/// Move a selection index by `delta`, wrapping within `[0, len)`.
///
/// Used by the vertical list navigation on every screen (↑/↓ or k/j).
pub fn wrap_index(current: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let len_i = len as i32;
    (((current as i32 + delta) % len_i + len_i) % len_i) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_keys_are_one_through_zero_and_round_trip() {
        assert_eq!(Screen::Agents.menu_key(), Some('1'));
        assert_eq!(Screen::Help.menu_key(), Some('0'));
        assert_eq!(Screen::MainMenu.menu_key(), None);
        for s in Screen::menu_order() {
            let key = s.menu_key().unwrap();
            assert_eq!(Screen::from_menu_key(key), Some(s));
        }
    }

    #[test]
    fn from_menu_key_rejects_non_digits() {
        assert_eq!(Screen::from_menu_key('a'), None);
    }

    #[test]
    fn parse_bare_number_navigates() {
        assert_eq!(parse_command("1"), Command::Go(Screen::Agents));
        assert_eq!(parse_command(" 6 "), Command::Go(Screen::Code));
        assert_eq!(parse_command("0"), Command::Go(Screen::Help));
    }

    #[test]
    fn parse_alias_navigates_case_insensitively() {
        assert_eq!(parse_command("FILES"), Command::Go(Screen::Pod));
        assert_eq!(parse_command("agents"), Command::Go(Screen::Agents));
        assert_eq!(parse_command("relays"), Command::Go(Screen::Network));
    }

    #[test]
    fn parse_control_words() {
        assert_eq!(parse_command("back"), Command::Back);
        assert_eq!(parse_command("theme"), Command::Theme);
        assert_eq!(parse_command("quit"), Command::Quit);
    }

    #[test]
    fn parse_sentry_command() {
        assert_eq!(parse_command("sentry"), Command::Sentry);
        assert_eq!(parse_command("game"), Command::Sentry);
        assert_eq!(parse_command("SENTRY"), Command::Sentry);
    }

    #[test]
    fn parse_search_command_word() {
        assert_eq!(parse_command("search"), Command::Search);
        assert_eq!(parse_command("FIND"), Command::Search);
    }

    #[test]
    fn parse_dm_alias_navigates() {
        assert_eq!(parse_command("dm"), Command::Go(Screen::Dm));
        assert_eq!(parse_command("inbox"), Command::Go(Screen::Dm));
    }

    #[test]
    fn parse_unknown() {
        assert_eq!(parse_command(""), Command::Unknown);
        assert_eq!(parse_command("xyzzy"), Command::Unknown);
    }

    #[test]
    fn wrap_index_wraps_both_directions() {
        assert_eq!(wrap_index(0, -1, 4), 3);
        assert_eq!(wrap_index(3, 1, 4), 0);
        assert_eq!(wrap_index(1, 1, 4), 2);
        assert_eq!(wrap_index(0, 0, 0), 0);
    }
}
