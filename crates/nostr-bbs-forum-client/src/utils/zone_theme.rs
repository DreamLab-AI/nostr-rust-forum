//! Zone → colour-palette mapping (issue #29).
//!
//! Each operator-configured zone gets a coherent, distinctive Tailwind palette:
//! a background **gradient** (used behind the [`crate::components::zone_hero`]
//! header), an **accent** colour (the zone's signature hue, surfaced as a
//! `--zone-accent` CSS custom property and an accent text class), and a matching
//! **border** colour. Centralising the mapping here means the zone hero, the
//! category page and the section page all derive the same look from one source.
//!
//! ## Generic zone ids (operator config, `forum.toml` overlay)
//!
//! | id            | display     | colour family                |
//! |---------------|-------------|------------------------------|
//! | `public`      | Public      | amber / dawn (warm, open)    |
//! | `friends`     | Friends     | rose / fuchsia (the social)  |
//! | `minimoonoir` | Minimoonoir | blue / sky (cool, distinct)  |
//! | `family`      | Family      | emerald / teal (warm, safe)  |
//! | `business`    | Business    | purple (the brand accent)    |
//!
//! Display labels above are defaults; the operator overrides them via the
//! `forum.toml` overlay. Unknown / legacy ids (`home`, `members`, `private`,
//! seeded test zones) fall back to a neutral slate palette so navigation never
//! renders un-themed.
//!
//! The accent is a literal hex so it can flow into a CSS custom property
//! (`style="--zone-accent: #..."`) on page-root containers we own — chat/thread
//! pages can pick it up via that variable without us editing their internals.
//!
//! ## Operator-configured accents (issue #34)
//!
//! The built-in palette above is a per-deployment *default*; an operator can
//! override the accent hex per zone via `[[zones]] accent_hex = "#rrrrrr"` in
//! the `forum.toml` overlay (validated in `nostr_bbs_config::validate`; parsed
//! client-side into [`crate::stores::zones::Zone::accent_hex`]). Callers that
//! have a resolved [`crate::stores::zones::Zone`] in scope should use
//! [`zone_accent_style_cfg`], which prefers the configured hex and falls back
//! to the built-in [`zone_theme`] accent when absent — the *other* styling
//! (gradient, border, accent text class) stays driven by the built-in palette
//! regardless of config, since only the accent hex is operator-tunable today.

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

/// Resolve the palette for a zone id. Matches the generic zone ids and keeps
/// legacy aliases working; everything else gets the neutral slate theme.
pub fn zone_theme(zone_id: &str) -> ZoneTheme {
    match zone_id {
        // public / Landing — warm amber dawn, mirrors the lake-district-dawn banner.
        "public" | "home" | "landing" => ZoneTheme {
            gradient: "from-amber-500/20 via-orange-500/10 to-yellow-500/10",
            border: "border-amber-500/25",
            accent_text: "text-amber-400",
            accent_hex: "#f59e0b",
        },
        // friends — the social zone: rose → fuchsia.
        "friends" => ZoneTheme {
            gradient: "from-rose-500/20 via-pink-500/10 to-fuchsia-500/10",
            border: "border-rose-500/25",
            accent_text: "text-rose-400",
            accent_hex: "#fb7185",
        },
        // minimoonoir — cool, distinct blue / sky.
        "minimoonoir" => ZoneTheme {
            gradient: "from-blue-500/20 via-sky-500/10 to-cyan-500/10",
            border: "border-blue-500/25",
            accent_text: "text-blue-400",
            accent_hex: "#3b82f6",
        },
        // family — warm, safe emerald / teal.
        "family" => ZoneTheme {
            gradient: "from-emerald-500/20 via-teal-500/10 to-green-500/10",
            border: "border-emerald-500/25",
            accent_text: "text-emerald-400",
            accent_hex: "#34d399",
        },
        // business — purple, the brand accent zone.
        "business" => ZoneTheme {
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
///
/// Uses the built-in palette only. Prefer [`zone_accent_style_cfg`] wherever
/// the caller has a resolved config [`crate::stores::zones::Zone`] in scope,
/// so an operator-configured `accent_hex` (issue #34) takes precedence.
pub fn zone_accent_style(zone_id: &str) -> String {
    format!("--zone-accent: {};", zone_theme(zone_id).accent_hex)
}

/// Config-aware variant of [`zone_accent_style`]: prefers `cfg_accent` (the
/// operator's `[[zones]] accent_hex` for this zone, if configured and
/// non-empty) and falls back to the built-in [`zone_theme`] accent otherwise.
///
/// This is how operator colour overrides (issue #34) reach the
/// `--zone-accent` CSS custom property without disturbing deployments that
/// leave `accent_hex` unset — they keep the existing built-in palette.
pub fn zone_accent_style_cfg(zone_id: &str, cfg_accent: Option<&str>) -> String {
    let hex = cfg_accent
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| zone_theme(zone_id).accent_hex);
    format!("--zone-accent: {};", hex)
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
    fn each_generic_zone_has_a_distinct_accent() {
        let public = zone_theme("public").accent_hex;
        let friends = zone_theme("friends").accent_hex;
        let minimoonoir = zone_theme("minimoonoir").accent_hex;
        let family = zone_theme("family").accent_hex;
        let business = zone_theme("business").accent_hex;
        let all = [public, friends, minimoonoir, family, business];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "zone accents must be distinct");
            }
        }
    }

    #[test]
    fn minimoonoir_zone_is_blue() {
        let t = zone_theme("minimoonoir");
        assert_eq!(t.accent_hex, "#3b82f6");
        assert!(t.gradient.contains("blue"));
        assert!(t.accent_text.contains("blue"));
        assert!(t.border.contains("blue"));
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

    #[test]
    fn accent_style_cfg_prefers_configured_hex() {
        // Operator override (e.g. `[[zones]] id = "public" accent_hex = "#22c55e"`)
        // wins over the built-in amber default for `public`.
        assert_eq!(
            zone_accent_style_cfg("public", Some("#22c55e")),
            "--zone-accent: #22c55e;"
        );
    }

    #[test]
    fn accent_style_cfg_falls_back_to_built_in_when_absent() {
        assert_eq!(
            zone_accent_style_cfg("business", None),
            "--zone-accent: #a855f7;"
        );
    }

    #[test]
    fn accent_style_cfg_falls_back_to_built_in_when_empty() {
        // A blank/whitespace-only accent_hex must not leak into the style
        // string; treat it as absent.
        assert_eq!(
            zone_accent_style_cfg("business", Some("   ")),
            "--zone-accent: #a855f7;"
        );
    }
}
