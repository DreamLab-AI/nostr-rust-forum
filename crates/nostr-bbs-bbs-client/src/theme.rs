//! BBS colour themes.
//!
//! The `[branding].theme` TOML key (projected to `window.__ENV__.THEME`) selects
//! one of four retro palettes. The actual colour values live in `assets/bbs.css`
//! under `.theme-*` classes; this module only maps a theme name to its class and
//! is intentionally pure so it can be unit-tested on the native target.

/// A BBS colour theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    /// Classic amber phosphor (default).
    #[default]
    Amber,
    /// Green phosphor.
    Green,
    /// Purple.
    Purple,
    /// Sky blue.
    Sky,
}

impl Theme {
    /// Parse a theme name (case-insensitive). Unknown names fall back to
    /// [`Theme::Amber`] so a misconfigured `theme` never blanks the UI.
    pub fn parse(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "green" => Theme::Green,
            "purple" | "violet" => Theme::Purple,
            "sky" | "blue" | "cyan" => Theme::Sky,
            _ => Theme::Amber,
        }
    }

    /// The CSS class applied to the root element for this theme.
    pub fn css_class(self) -> &'static str {
        match self {
            Theme::Amber => "theme-amber",
            Theme::Green => "theme-green",
            Theme::Purple => "theme-purple",
            Theme::Sky => "theme-sky",
        }
    }

    /// Human-readable label (shown in the Settings screen).
    pub fn label(self) -> &'static str {
        match self {
            Theme::Amber => "amber",
            Theme::Green => "green",
            Theme::Purple => "purple",
            Theme::Sky => "sky",
        }
    }

    /// All themes, in cycle order (used by the Settings screen toggle).
    pub fn all() -> [Theme; 4] {
        [Theme::Amber, Theme::Green, Theme::Purple, Theme::Sky]
    }

    /// The next theme in cycle order (wraps).
    pub fn next(self) -> Theme {
        let all = Theme::all();
        let idx = all.iter().position(|t| *t == self).unwrap_or(0);
        all[(idx + 1) % all.len()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_themes_case_insensitive() {
        assert_eq!(Theme::parse("amber"), Theme::Amber);
        assert_eq!(Theme::parse("GREEN"), Theme::Green);
        assert_eq!(Theme::parse(" Purple "), Theme::Purple);
        assert_eq!(Theme::parse("violet"), Theme::Purple);
        assert_eq!(Theme::parse("sky"), Theme::Sky);
        assert_eq!(Theme::parse("blue"), Theme::Sky);
    }

    #[test]
    fn parse_unknown_falls_back_to_amber() {
        assert_eq!(Theme::parse(""), Theme::Amber);
        assert_eq!(Theme::parse("chartreuse"), Theme::Amber);
    }

    #[test]
    fn css_class_matches_stylesheet() {
        assert_eq!(Theme::Green.css_class(), "theme-green");
        assert_eq!(Theme::Sky.css_class(), "theme-sky");
    }

    #[test]
    fn next_cycles_and_wraps() {
        assert_eq!(Theme::Amber.next(), Theme::Green);
        assert_eq!(Theme::Sky.next(), Theme::Amber);
    }
}
