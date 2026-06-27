//! BBS navigation model: the ten screens, the main-menu layout, and the
//! command-line / keyboard parsing. All pure so it can be unit-tested natively;
//! the Leptos views in `screens` and `chrome` render on top of it.
//!
//! Each screen maps to a REAL kit capability rather than being cosmetic:
//! Message Base → config zones + kind-40/42 channels, File Base → the Solid pod
//! browser, Node List → relays + federation mesh, User List → did:nostr WebID
//! profiles, Door Games → the agent-governance control-panel plane, System Info
//! → DID/relay/pod status, etc.

/// One of the ten BBS screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// The numbered main menu (landing screen).
    #[default]
    MainMenu,
    /// Zones & boards — kind-40/42 channels, zone-gated reads.
    MessageBase,
    /// Solid pod browser — WebID-owned storage.
    FileBase,
    /// Relays & federation mesh peers.
    NodeList,
    /// Members — did:nostr WebID profiles.
    UserList,
    /// Live channel & encrypted DMs (NIP-44 / NIP-59).
    Chat,
    /// Agent control panels — human-in-the-loop governance.
    DoorGames,
    /// Shared snippets & pod files.
    CodeExchange,
    /// Node / relay / pod / identity status.
    SystemInfo,
    /// Theme + identity + node settings.
    Settings,
    /// Help / about.
    Help,
}

impl Screen {
    /// The ten selectable screens, in main-menu order.
    pub fn menu_order() -> [Screen; 10] {
        [
            Screen::MessageBase,
            Screen::FileBase,
            Screen::NodeList,
            Screen::UserList,
            Screen::Chat,
            Screen::DoorGames,
            Screen::CodeExchange,
            Screen::SystemInfo,
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
            Screen::MainMenu => "Main Menu",
            Screen::MessageBase => "Message Base",
            Screen::FileBase => "File Base",
            Screen::NodeList => "Node List",
            Screen::UserList => "User List",
            Screen::Chat => "Chat",
            Screen::DoorGames => "Door Games",
            Screen::CodeExchange => "Code Exchange",
            Screen::SystemInfo => "System Info",
            Screen::Settings => "Settings",
            Screen::Help => "Help",
        }
    }

    /// One-line description of the real kit feature behind the screen.
    pub fn subtitle(self) -> &'static str {
        match self {
            Screen::MainMenu => "Select a board by number, or type / for a command",
            Screen::MessageBase => "Zones & boards — kind-40/42 channels, zone-gated",
            Screen::FileBase => "Solid pod browser — your WebID-owned storage",
            Screen::NodeList => "Relays & federation mesh peers",
            Screen::UserList => "Members — did:nostr WebID profiles",
            Screen::Chat => "Live channel & encrypted DMs (NIP-44/59)",
            Screen::DoorGames => "Agent control panels — human-in-the-loop governance",
            Screen::CodeExchange => "Shared snippets & pod files",
            Screen::SystemInfo => "Node / relay / pod / identity status",
            Screen::Settings => "Theme, identity & node settings",
            Screen::Help => "About the BBS, zones, agents & pods",
        }
    }

    /// Command-line aliases that jump to this screen (typed after `/`).
    pub fn aliases(self) -> &'static [&'static str] {
        match self {
            Screen::MainMenu => &["menu", "main", "home"],
            Screen::MessageBase => &["msg", "messages", "boards", "m"],
            Screen::FileBase => &["files", "file", "pod", "f"],
            Screen::NodeList => &["nodes", "relays", "n"],
            Screen::UserList => &["users", "members", "who", "u"],
            Screen::Chat => &["chat", "dm", "c"],
            Screen::DoorGames => &["doors", "door", "agents", "agent", "gov", "d"],
            Screen::CodeExchange => &["code", "snippets", "x"],
            Screen::SystemInfo => &["sys", "system", "info", "s"],
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
    /// Unrecognised command.
    Unknown,
}

/// Parse a command-line string (without the leading `/`).
///
/// Accepts a bare menu number (`"3"`), a screen alias (`"files"`), or a control
/// word (`"back"`, `"theme"`, `"quit"`). Leading/trailing whitespace and case
/// are ignored.
pub fn parse_command(raw: &str) -> Command {
    let cmd = raw.trim().to_ascii_lowercase();
    if cmd.is_empty() {
        return Command::Unknown;
    }
    match cmd.as_str() {
        "back" | "b" | "esc" => return Command::Back,
        "theme" | "t" | "color" | "colour" => return Command::Theme,
        "quit" | "q" | "exit" | "logoff" | "bye" => return Command::Quit,
        _ => {}
    }
    if let Some(ch) = cmd.chars().next() {
        if cmd.len() == 1 {
            if let Some(s) = Screen::from_menu_key(ch) {
                return Command::Go(s);
            }
        }
    }
    for screen in [Screen::MainMenu].into_iter().chain(Screen::menu_order()) {
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
        assert_eq!(Screen::MessageBase.menu_key(), Some('1'));
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
        assert_eq!(parse_command("1"), Command::Go(Screen::MessageBase));
        assert_eq!(parse_command(" 6 "), Command::Go(Screen::DoorGames));
        assert_eq!(parse_command("0"), Command::Go(Screen::Help));
    }

    #[test]
    fn parse_alias_navigates_case_insensitively() {
        assert_eq!(parse_command("FILES"), Command::Go(Screen::FileBase));
        assert_eq!(parse_command("agents"), Command::Go(Screen::DoorGames));
        assert_eq!(parse_command("relays"), Command::Go(Screen::NodeList));
    }

    #[test]
    fn parse_control_words() {
        assert_eq!(parse_command("back"), Command::Back);
        assert_eq!(parse_command("theme"), Command::Theme);
        assert_eq!(parse_command("quit"), Command::Quit);
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
