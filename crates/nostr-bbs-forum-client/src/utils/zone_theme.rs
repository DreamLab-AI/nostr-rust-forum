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
//! to the built-in [`zone_theme`] accent when absent.
//!
//! ## Configured accent drives the whole tile (issue #43)
//!
//! The forum *index* used to colour its zone tiles from a local hash of the
//! zone id (an arbitrary Tailwind palette name), which ignored the configured
//! accent entirely and could disagree with the drill-down pages. The index now
//! resolves one accent hex per zone via [`resolved_accent_hex`] (configured
//! hex first, built-in [`zone_theme`] fallback) and paints the tile border,
//! background gradient, accent edge, heading and every category card from that
//! single hex via the inline-style builders below ([`hex_rgba`],
//! [`zone_tile_style`]). Because the gradient/border are now emitted as
//! `rgba()` derived from the resolved hex — not fixed Tailwind classes — a
//! green-configured zone can no longer render an amber gradient. The built-in
//! [`ZoneTheme`] struct stays as the fallback *source* of `accent_hex`.

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

/// Format an alpha channel for `rgba()`: clamped to `[0, 1]`, up to three
/// decimal places, trailing zeros trimmed (`0.25 -> "0.25"`, `1.0 -> "1"`).
/// Keeping it deterministic avoids f32 Display drift (`0.16000001`) in styles.
fn fmt_alpha(alpha: f32) -> String {
    let s = format!("{:.3}", alpha.clamp(0.0, 1.0));
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Parse a `#rrggbb` hex colour into a CSS `rgba(r,g,b,a)` string at `alpha`.
///
/// Returns `None` for anything that is not a leading-`#`, six-hex-digit colour
/// (missing `#`, short/long, non-hex garbage), so callers can fall back to the
/// built-in palette rather than emitting broken CSS. This is the single parser
/// every configured-accent inline style is built from (issue #43).
pub fn hex_rgba(hex: &str, alpha: f32) -> Option<String> {
    let body = hex.strip_prefix('#')?;
    if body.len() != 6 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let r = u8::from_str_radix(&body[0..2], 16).ok()?;
    let g = u8::from_str_radix(&body[2..4], 16).ok()?;
    let b = u8::from_str_radix(&body[4..6], 16).ok()?;
    Some(format!("rgba({},{},{},{})", r, g, b, fmt_alpha(alpha)))
}

/// Resolve the single accent hex for a zone: the operator-configured
/// `cfg_accent` when it is present and a parseable `#rrggbb`, otherwise the
/// built-in [`zone_theme`] accent for `zone_id`.
///
/// This is the config-first source of truth the forum index paints every tile
/// and card from (issue #43) — a malformed or blank configured value never
/// leaks into the style, it degrades to the built-in palette instead.
pub fn resolved_accent_hex(zone_id: &str, cfg_accent: Option<&str>) -> String {
    cfg_accent
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .filter(|h| hex_rgba(h, 1.0).is_some())
        .map(str::to_string)
        .unwrap_or_else(|| zone_theme(zone_id).accent_hex.to_string())
}

/// Inline style for an index zone tile, driven entirely by a resolved accent
/// hex (see [`resolved_accent_hex`]): a subtle accent border, a diagonal accent
/// gradient tuned to match the weight of the old Tailwind `from-*/20 via-*/10`
/// stops, and the `--zone-accent` custom property so descendants can theme off
/// it. Falls back to neutral slate rgba only if `accent_hex` is unparseable.
pub fn zone_tile_style(accent_hex: &str) -> String {
    let border = hex_rgba(accent_hex, 0.25).unwrap_or_else(|| "rgba(148,163,184,0.25)".to_string());
    let strong = hex_rgba(accent_hex, 0.16).unwrap_or_else(|| "rgba(148,163,184,0.16)".to_string());
    let mid = hex_rgba(accent_hex, 0.06).unwrap_or_else(|| "rgba(148,163,184,0.06)".to_string());
    format!(
        "border-color: {border}; \
         background: linear-gradient(135deg, {strong}, {mid} 55%, transparent); \
         --zone-accent: {accent_hex};"
    )
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

    // -- hex_rgba (issue #43) --------------------------------------------------

    #[test]
    fn hex_rgba_parses_valid_colour() {
        // Operator green #22c55e -> 34,197,94.
        assert_eq!(
            hex_rgba("#22c55e", 0.25).as_deref(),
            Some("rgba(34,197,94,0.25)")
        );
    }

    #[test]
    fn hex_rgba_rejects_missing_hash() {
        assert_eq!(hex_rgba("22c55e", 0.25), None);
    }

    #[test]
    fn hex_rgba_rejects_short_hex() {
        // Three-digit shorthand is not accepted; only full #rrggbb.
        assert_eq!(hex_rgba("#abc", 1.0), None);
        assert_eq!(hex_rgba("#22c55", 1.0), None);
    }

    #[test]
    fn hex_rgba_rejects_garbage() {
        assert_eq!(hex_rgba("#gggggg", 0.5), None);
        assert_eq!(hex_rgba("not-a-colour", 0.5), None);
        assert_eq!(hex_rgba("", 0.5), None);
    }

    #[test]
    fn hex_rgba_formats_alpha_without_trailing_zeros() {
        // 1.0 collapses to "1", a mid value keeps its significant digits, and
        // 0 collapses to "0" — no "1.000"/"0.500"/"0.000" noise in the style.
        assert_eq!(hex_rgba("#000000", 1.0).as_deref(), Some("rgba(0,0,0,1)"));
        assert_eq!(
            hex_rgba("#ffffff", 0.5).as_deref(),
            Some("rgba(255,255,255,0.5)")
        );
        assert_eq!(
            hex_rgba("#ffffff", 0.0).as_deref(),
            Some("rgba(255,255,255,0)")
        );
        // Out-of-range alpha is clamped, not emitted verbatim.
        assert_eq!(hex_rgba("#000000", 2.0).as_deref(), Some("rgba(0,0,0,1)"));
    }

    // -- resolved_accent_hex (issue #43) --------------------------------------

    #[test]
    fn resolved_accent_prefers_configured_hex() {
        // Operator green wins over the built-in amber default for `public`.
        assert_eq!(resolved_accent_hex("public", Some("#22c55e")), "#22c55e");
    }

    #[test]
    fn resolved_accent_falls_back_when_absent_or_invalid() {
        // Absent -> built-in; malformed/blank config never leaks, also -> built-in.
        assert_eq!(resolved_accent_hex("minimoonoir", None), "#3b82f6");
        assert_eq!(resolved_accent_hex("business", Some("nope")), "#a855f7");
        assert_eq!(resolved_accent_hex("business", Some("   ")), "#a855f7");
    }

    // -- zone_tile_style (issue #43) ------------------------------------------

    #[test]
    fn zone_tile_style_derives_every_channel_from_the_hex() {
        let style = zone_tile_style("#22c55e");
        assert!(style.contains("border-color: rgba(34,197,94,0.25)"));
        assert!(style.contains("linear-gradient(135deg, rgba(34,197,94,0.16)"));
        assert!(style.contains("--zone-accent: #22c55e;"));
    }
}
