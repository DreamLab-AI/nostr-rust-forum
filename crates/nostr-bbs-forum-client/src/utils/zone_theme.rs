//! Zone → colour-palette mapping (issue #29).
//!
//! Each operator-configured zone gets a coherent, distinctive Tailwind palette:
//! a background **gradient** (used behind the [`crate::components::zone_hero`]
//! header), an **accent** colour (the zone's signature hue, surfaced as a
//! `--zone-accent` CSS custom property and an accent text class), and a matching
//! **border** colour. Centralising the mapping here means the zone hero, the
//! category page and the section page all derive the same look from one source.
//!
//! ## Real zone ids (operator config, `forum-config/dreamlab.toml`)
//!
//! | id            | display     | colour family                |
//! |---------------|-------------|------------------------------|
//! | `public`      | Landing     | amber / dawn (warm, open)    |
//! | `minimoonoir` | Minimoonoir | rose / fuchsia (the social)  |
//! | `family`      | Family      | emerald / teal (warm, safe)  |
//! | `business`    | DreamLab    | **purple** (the brand, #29)  |
//!
//! Unknown / legacy ids (`home`, `members`, `private`, seeded test zones) fall
//! back to a neutral slate palette so navigation never renders un-themed.
//!
//! The accent is a literal hex so it can flow into a CSS custom property
//! (`style="--zone-accent: #..."`) on page-root containers we own — chat/thread
//! pages can pick it up via that variable without us editing their internals.

/// A coherent colour palette for a single zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneTheme {
    /// Tailwind `bg-gradient-to-*` colour-stop classes (no `bg-gradient-*`
    /// prefix), e.g. `"from-amber-500/20 via-orange-500/10 to-yellow-500/10"`.
    pub gradient: &'static str,
    /// Tailwind border-colour class, e.g. `"border-amber-500/20"`.
    pub border: &'static str,
    /// Tailwind text-colour class for the accent (chips, links), e.g.
    /// `"text-amber-400"`.
    pub accent_text: &'static str,
    /// Literal accent hex (no `#`-less variants) for the `--zone-accent` CSS
    /// custom property, e.g. `"#a855f7"`. This is the value that carries the
    /// zone identity into pages we don't own (chat/thread) via the variable.
    pub accent_hex: &'static str,
}

/// Resolve the palette for a zone id. Matches the real operator zone ids and
/// keeps legacy aliases working; everything else gets the neutral slate theme.
pub fn zone_theme(zone_id: &str) -> ZoneTheme {
    match zone_id {
        // public / Landing — warm amber dawn, mirrors the lake-district-dawn banner.
        "public" | "home" | "landing" => ZoneTheme {
            gradient: "from-amber-500/20 via-orange-500/10 to-yellow-500/10",
            border: "border-amber-500/25",
            accent_text: "text-amber-400",
            accent_hex: "#f59e0b",
        },
        // minimoonoir — the social zone: rose → fuchsia.
        "minimoonoir" | "friends" => ZoneTheme {
            gradient: "from-rose-500/20 via-pink-500/10 to-fuchsia-500/10",
            border: "border-rose-500/25",
            accent_text: "text-rose-400",
            accent_hex: "#fb7185",
        },
        // family — warm, safe emerald / teal.
        "family" => ZoneTheme {
            gradient: "from-emerald-500/20 via-teal-500/10 to-green-500/10",
            border: "border-emerald-500/25",
            accent_text: "text-emerald-400",
            accent_hex: "#34d399",
        },
        // business / DreamLab — PURPLE (issue #29: the DreamLab zone is purple).
        "business" | "dreamlab" => ZoneTheme {
            gradient: "from-purple-500/25 via-violet-500/12 to-indigo-500/10",
            border: "border-purple-500/30",
            accent_text: "text-purple-400",
            accent_hex: "#a855f7",
        },
        // Legacy `members` / `private` aliases + any unknown / seeded zone.
        "members" => ZoneTheme {
            gradient: "from-rose-500/20 via-pink-500/10 to-fuchsia-500/10",
            border: "border-rose-500/25",
            accent_text: "text-rose-400",
            accent_hex: "#fb7185",
        },
        "private" => ZoneTheme {
            gradient: "from-purple-500/25 via-violet-500/12 to-indigo-500/10",
            border: "border-purple-500/30",
            accent_text: "text-purple-400",
            accent_hex: "#a855f7",
        },
        _ => ZoneTheme {
            gradient: "from-slate-500/20 via-slate-500/10 to-slate-500/5",
            border: "border-slate-500/25",
            accent_text: "text-slate-300",
            accent_hex: "#94a3b8",
        },
    }
}

/// Convenience: the `--zone-accent: <hex>;` inline-style fragment for a zone, so
/// page-root containers can expose the accent to descendants (including the
/// chat/thread pages we don't own) as a CSS custom property.
pub fn zone_accent_style(zone_id: &str) -> String {
    format!("--zone-accent: {};", zone_theme(zone_id).accent_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_zone_is_purple() {
        let t = zone_theme("business");
        assert_eq!(t.accent_hex, "#a855f7");
        assert!(t.gradient.contains("purple"));
        assert!(t.accent_text.contains("purple"));
        assert!(t.border.contains("purple"));
    }

    #[test]
    fn each_real_zone_has_a_distinct_accent() {
        let public = zone_theme("public").accent_hex;
        let mini = zone_theme("minimoonoir").accent_hex;
        let family = zone_theme("family").accent_hex;
        let business = zone_theme("business").accent_hex;
        let all = [public, mini, family, business];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "zone accents must be distinct");
            }
        }
    }

    #[test]
    fn unknown_zone_falls_back_to_neutral_slate() {
        let t = zone_theme("some-seeded-test-zone");
        assert!(t.gradient.contains("slate"));
        assert_eq!(t.accent_hex, "#94a3b8");
    }

    #[test]
    fn accent_style_emits_custom_property() {
        assert_eq!(zone_accent_style("business"), "--zone-accent: #a855f7;");
    }
}
