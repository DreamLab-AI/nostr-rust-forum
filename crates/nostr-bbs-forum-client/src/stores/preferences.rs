//! User preferences store backed by localStorage.
//!
//! Persists theme, notification level, link preview, reduced motion, font
//! size, and density preferences across sessions. Provided via Leptos
//! context.
//!
//! Appearance preferences (theme, font size, density, reduced motion) are
//! *applied* to the document via [`apply_preferences`], which toggles the
//! Tailwind `dark` class (the kit configures `darkMode: 'class'`) plus a set
//! of `data-*` attributes on `<html>` and injects a managed `<style>` element
//! so the choices take real visual effect. They are applied on app load (via
//! [`provide_preferences`]) and re-applied on every save.

use leptos::prelude::*;

const PREFS_KEY: &str = "nostrbbs:preferences";

/// `id` of the managed `<style>` element injected into `<head>` to back the
/// appearance preferences (light theme overrides, font scale, density).
const PREFS_STYLE_ID: &str = "nostrbbs-prefs-style";

/// Complete light-theme palette, scoped under `[data-theme="light"]` and
/// injected into the managed `<style>` when a Light theme is active.
///
/// The kit is dark-first: `style.css`/`design-tokens.css` set a dark body, dark
/// `--dl-card-*` surface vars, and components hardcode dark Tailwind utilities.
/// Toggling Light only flips `body`, leaving most surfaces dark-on-light and
/// near-unreadable. Rather than rewriting hundreds of component call-sites, we
/// override the *actual* classes those components use, at the theme layer:
///
/// - Surfaces (`.glass-card`, `.glass`, `.section-list-card`,
///   `.category-hero-card`, `.event-card`, `.link-preview-card`, modals,
///   toasts, and the `bg-gray-50…900`/`bg-white|black/N` utilities) →
///   light surface + subtle dark-tinted border.
/// - Muted/secondary text (`text-gray-300…600`, `text-white/N`) →
///   readable dark-grey (#374151/#4b5563 ≈ 7–9:1 on #f9fafb).
/// - `text-white` → near-black so emphasised copy stays the *strongest* text.
/// - Chips/badges (amber "N posts", emerald "new", gray stat chips) →
///   light chip fills with darker accent text.
/// - Inputs/textareas/selects → light field + dark text + visible border +
///   readable placeholder.
/// - Borders/dividers (`border-gray-*`, `border-white/N`, `divide-*`) and the
///   breadcrumb keep adequate contrast.
///
/// `color-scheme: light` (set on `<html>` in `apply_preferences`) already drives
/// native scrollbars/form chrome; this covers the styled layer on top.
const LIGHT_THEME_CSS: &str = concat!(
    // -- Canvas + base text ------------------------------------------------
    "body{background-color:#f9fafb !important;color:#111827 !important;}",
    // The animated dark mesh hero washes out on a light page — give it a light
    // gradient bed so candy-gradient/text sits on a legible field.
    "[data-theme=\"light\"] .mesh-bg{background:",
    "radial-gradient(ellipse at 20% 50%,rgba(245,158,11,0.10) 0%,transparent 55%),",
    "radial-gradient(ellipse at 80% 20%,rgba(96,165,250,0.10) 0%,transparent 55%),",
    "radial-gradient(ellipse at 60% 80%,rgba(168,85,247,0.08) 0%,transparent 55%),",
    "#eef1f6 !important;}",
    // -- Glass / card / panel surfaces -------------------------------------
    "[data-theme=\"light\"] .glass-card,",
    "[data-theme=\"light\"] .glass-card-interactive,",
    "[data-theme=\"light\"] .glass,",
    "[data-theme=\"light\"] .section-list-card,",
    "[data-theme=\"light\"] .category-hero-card,",
    "[data-theme=\"light\"] .event-card,",
    "[data-theme=\"light\"] .link-preview-card{",
    "background:rgba(255,255,255,0.92) !important;",
    "border-color:rgba(17,24,39,0.12) !important;color:#1f2937 !important;",
    "box-shadow:0 1px 3px rgba(17,24,39,0.06),0 1px 2px rgba(17,24,39,0.04) !important;}",
    // Interactive surface hover: keep the amber-tinted lift, just on light.
    "[data-theme=\"light\"] .section-list-card:hover,",
    "[data-theme=\"light\"] .event-card:hover,",
    "[data-theme=\"light\"] .glass-card-interactive:hover{",
    "background:rgba(255,255,255,0.98) !important;",
    "border-color:rgba(245,158,11,0.45) !important;",
    "box-shadow:0 4px 14px rgba(17,24,39,0.10) !important;}",
    // Modal/search/toast surfaces: opaque white so overlaid content reads.
    "[data-theme=\"light\"] .modal-panel,",
    "[data-theme=\"light\"] .search-panel,",
    "[data-theme=\"light\"] .toast-item{",
    "background:rgba(255,255,255,0.98) !important;color:#1f2937 !important;",
    "border-color:rgba(17,24,39,0.12) !important;",
    "box-shadow:0 10px 40px rgba(17,24,39,0.18) !important;}",
    // -- Dark surface utilities → light fills ------------------------------
    "[data-theme=\"light\"] .bg-gray-900,",
    "[data-theme=\"light\"] .bg-gray-850{background-color:#eef1f6 !important;}",
    "[data-theme=\"light\"] .bg-gray-800,",
    "[data-theme=\"light\"] .bg-gray-750{background-color:#f1f3f7 !important;}",
    "[data-theme=\"light\"] .bg-gray-700{background-color:#e5e7eb !important;}",
    "[data-theme=\"light\"] .bg-gray-600{background-color:#d1d5db !important;}",
    "[data-theme=\"light\"] .bg-gray-500{background-color:#cbd0d8 !important;}",
    // Translucent gray utilities used for chips/inputs (e.g. bg-gray-800/60).
    "[data-theme=\"light\"] [class*=\"bg-gray-900/\"],",
    "[data-theme=\"light\"] [class*=\"bg-gray-800/\"],",
    "[data-theme=\"light\"] [class*=\"bg-gray-750/\"],",
    "[data-theme=\"light\"] [class*=\"bg-gray-700/\"]{",
    "background-color:rgba(243,244,246,0.85) !important;}",
    // white/black alpha surfaces (subtle dark hover/overlay tints).
    "[data-theme=\"light\"] [class*=\"bg-white/\"]{background-color:rgba(17,24,39,0.05) !important;}",
    "[data-theme=\"light\"] [class*=\"bg-black/\"]{background-color:rgba(17,24,39,0.35) !important;}",
    // -- Text: emphasis + muted/secondary ----------------------------------
    // `text-white`/`text-gray-100/200` are the *strongest* copy → near-black.
    "[data-theme=\"light\"] .text-white,",
    "[data-theme=\"light\"] .text-gray-100,",
    "[data-theme=\"light\"] .text-gray-200{color:#111827 !important;}",
    "[data-theme=\"light\"] [class*=\"text-white/\"]{color:#1f2937 !important;}",
    // gray-300/400 (body + muted) → readable mid-dark grey (≈7:1 on #f9fafb).
    "[data-theme=\"light\"] .text-gray-300{color:#1f2937 !important;}",
    "[data-theme=\"light\"] .text-gray-400{color:#374151 !important;}",
    // gray-500/600 (subtle meta/stat text) → still ≥4.5:1 on light surfaces.
    "[data-theme=\"light\"] .text-gray-500{color:#4b5563 !important;}",
    "[data-theme=\"light\"] .text-gray-600{color:#52606d !important;}",
    // -- Borders / dividers -------------------------------------------------
    "[data-theme=\"light\"] .border-gray-900,",
    "[data-theme=\"light\"] .border-gray-800,",
    "[data-theme=\"light\"] .border-gray-700,",
    "[data-theme=\"light\"] .border-gray-600,",
    "[data-theme=\"light\"] .border-gray-500{border-color:rgba(17,24,39,0.14) !important;}",
    "[data-theme=\"light\"] [class*=\"border-gray-700/\"],",
    "[data-theme=\"light\"] [class*=\"border-gray-800/\"],",
    "[data-theme=\"light\"] [class*=\"border-white/\"]{border-color:rgba(17,24,39,0.12) !important;}",
    "[data-theme=\"light\"] [class*=\"divide-gray-\"]>*+*{border-color:rgba(17,24,39,0.10) !important;}",
    // -- Chips / badges -----------------------------------------------------
    // Amber chips ("N posts", links) — darken text so the fill still reads.
    "[data-theme=\"light\"] .text-amber-400{color:#b45309 !important;}",
    "[data-theme=\"light\"] .text-amber-300{color:#92400e !important;}",
    "[data-theme=\"light\"] [class*=\"bg-amber-500/\"],",
    "[data-theme=\"light\"] [class*=\"bg-amber-400/\"]{background-color:rgba(245,158,11,0.18) !important;}",
    // Emerald "new" badge.
    "[data-theme=\"light\"] .text-emerald-400{color:#047857 !important;}",
    "[data-theme=\"light\"] [class*=\"bg-emerald-500/\"]{background-color:rgba(16,185,129,0.16) !important;}",
    "[data-theme=\"light\"] [class*=\"border-emerald-500/\"]{border-color:rgba(16,185,129,0.35) !important;}",
    // -- Inputs / textareas / selects --------------------------------------
    "[data-theme=\"light\"] input,",
    "[data-theme=\"light\"] textarea,",
    "[data-theme=\"light\"] select{",
    "background-color:#ffffff !important;color:#111827 !important;",
    "border-color:rgba(17,24,39,0.20) !important;}",
    "[data-theme=\"light\"] input::placeholder,",
    "[data-theme=\"light\"] textarea::placeholder,",
    "[data-theme=\"light\"] [class*=\"placeholder-gray-\"]::placeholder{color:#6b7280 !important;}",
    // -- Breadcrumb ---------------------------------------------------------
    "[data-theme=\"light\"] .breadcrumb-nav,",
    "[data-theme=\"light\"] .breadcrumb-nav a{color:#4b5563 !important;}",
    "[data-theme=\"light\"] .breadcrumb-nav a:hover{color:#b45309 !important;}",
    "[data-theme=\"light\"] .breadcrumb-separator{color:#9ca3af !important;}",
);

/// User-configurable preferences.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Preferences {
    pub theme: Theme,
    pub notification_level: NotificationLevel,
    pub show_link_previews: bool,
    pub reduced_motion: bool,
    /// When true, show Nostr protocol names (NIP-07, nsec, pubkey hex, relay URLs).
    /// When false (default), use friendly labels.
    #[serde(default)]
    pub show_technical_details: bool,
    /// Base text size for the whole app (scales the root font size).
    #[serde(default)]
    pub font_size: FontSize,
    /// Whitespace density for lists, cards, and message rows.
    #[serde(default)]
    pub density: Density,
}

/// Visual theme selection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Theme {
    Dark,
    Light,
    System,
}

impl Theme {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dark => "Dark",
            Self::Light => "Light",
            Self::System => "System",
        }
    }

    /// Resolve `System` to a concrete dark/light choice using the OS
    /// `prefers-color-scheme` media query. Returns `true` for dark.
    fn resolves_dark(&self) -> bool {
        match self {
            Self::Dark => true,
            Self::Light => false,
            Self::System => prefers_dark_scheme(),
        }
    }
}

/// Base text-size selection (applied as a root font-size scale).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FontSize {
    Small,
    #[default]
    Medium,
    Large,
}

impl FontSize {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Small => "Small",
            Self::Medium => "Medium",
            Self::Large => "Large",
        }
    }

    /// Stable token written to `data-font-size` on `<html>` and matched by the
    /// injected stylesheet.
    fn token(&self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    /// Root font-size in px backing each scale (browser default is 16px).
    fn root_px(&self) -> u8 {
        match self {
            Self::Small => 14,
            Self::Medium => 16,
            Self::Large => 18,
        }
    }

    pub fn all_variants() -> &'static [FontSize] {
        &[Self::Small, Self::Medium, Self::Large]
    }
}

/// Whitespace density selection.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Density {
    #[default]
    Comfortable,
    Compact,
}

impl Density {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Comfortable => "Comfortable",
            Self::Compact => "Compact",
        }
    }

    fn token(&self) -> &'static str {
        match self {
            Self::Comfortable => "comfortable",
            Self::Compact => "compact",
        }
    }

    pub fn all_variants() -> &'static [Density] {
        &[Self::Comfortable, Self::Compact]
    }
}

/// Notification verbosity level.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NotificationLevel {
    All,
    MentionsOnly,
    None,
}

impl NotificationLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::MentionsOnly => "Mentions Only",
            Self::None => "None",
        }
    }

    pub fn all_variants() -> &'static [NotificationLevel] {
        &[Self::All, Self::MentionsOnly, Self::None]
    }
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            notification_level: NotificationLevel::All,
            show_link_previews: true,
            reduced_motion: false,
            show_technical_details: false,
            font_size: FontSize::Medium,
            density: Density::Comfortable,
        }
    }
}

/// Provide the preferences store into Leptos context. Call once near the app
/// root. Applies the persisted appearance preferences to the document so the
/// user's saved theme/font-size/density/reduced-motion choices take effect on
/// load — not just after they re-toggle a control.
pub fn provide_preferences() {
    let initial = load_preferences();
    apply_preferences(&initial);
    let prefs = RwSignal::new(initial);
    provide_context(prefs);
    // Cross-tab sync: reload + re-apply appearance when a sibling tab saves prefs,
    // so a theme/font/density change in one tab is not reverted by a stale sibling
    // persisting its whole Preferences snapshot. See stores/notifications.rs.
    crate::utils::on_cross_tab_storage_write(PREFS_KEY, move || {
        let fresh = load_preferences();
        apply_preferences(&fresh);
        prefs.set(fresh);
    });
}

/// Retrieve the preferences signal from context.
pub fn use_preferences() -> RwSignal<Preferences> {
    expect_context()
}

fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
}

fn load_preferences() -> Preferences {
    get_local_storage()
        .and_then(|s| s.get_item(PREFS_KEY).ok())
        .flatten()
        .and_then(|json| serde_json::from_str::<Preferences>(&json).ok())
        .unwrap_or_default()
}

/// Persist preferences to localStorage and apply the appearance ones to the
/// document immediately, so toggling a control takes visible effect without a
/// reload.
pub fn save_preferences(prefs: &Preferences) {
    if let Some(storage) = get_local_storage() {
        if let Ok(json) = serde_json::to_string(prefs) {
            let _ = storage.set_item(PREFS_KEY, &json);
        }
    }
    apply_preferences(prefs);
}

/// Read the persisted `reduced_motion` preference directly from localStorage,
/// without going through the Leptos context.
///
/// The fx renderers ([`crate::components::fx`], [`ParticleCanvas`]) need this
/// at points where the preferences *context* may not be provided yet (e.g.
/// `provide_render_tier()` runs before `provide_preferences()` at app start),
/// so they read storage directly rather than `use_preferences()`. Defaults to
/// `false` when unset or unparseable.
///
/// [`ParticleCanvas`]: crate::components::particle_canvas::ParticleCanvas
pub fn reduced_motion_pref() -> bool {
    load_preferences().reduced_motion
}

/// Read the persisted `notification_level` directly from localStorage, without
/// going through the Leptos context.
///
/// The notification store gates which events surface as notifications on this
/// value, and does so from relay-driven effects/callbacks where reading
/// storage directly is simpler and free of context-ordering concerns. Defaults
/// to [`NotificationLevel::All`] when unset.
pub fn notification_level_pref() -> NotificationLevel {
    load_preferences().notification_level
}

/// Read the OS `prefers-color-scheme: dark` media query. Defaults to dark when
/// the query is unavailable (matches the kit's dark-first design).
fn prefers_dark_scheme() -> bool {
    web_sys::window()
        .and_then(|w| w.match_media("(prefers-color-scheme: dark)").ok().flatten())
        .map(|mq| mq.matches())
        .unwrap_or(true)
}

/// Apply the appearance preferences to the live document.
///
/// - Toggles the Tailwind `dark` class on `<html>` (the kit sets
///   `darkMode: 'class'`), resolving `System` against the OS query.
/// - Writes `data-theme`, `data-font-size`, `data-density`, and
///   `data-reduced-motion` attributes on `<html>` for CSS hooks.
/// - Injects/refreshes a managed `<style>` element that backs light-theme
///   overrides, the root font-size scale, the compact-density spacing, and a
///   user-driven reduced-motion rule.
///
/// No-op outside the browser (native test builds have no `document`).
pub fn apply_preferences(prefs: &Preferences) {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let Some(root) = document.document_element() else {
        return;
    };

    let dark = prefs.theme.resolves_dark();

    // Tailwind class-based dark mode lives on the root element.
    let class_list = root.class_list();
    if dark {
        let _ = class_list.add_1("dark");
        let _ = class_list.remove_1("light");
    } else {
        let _ = class_list.remove_1("dark");
        let _ = class_list.add_1("light");
    }

    let theme_token = if dark { "dark" } else { "light" };
    let _ = root.set_attribute("data-theme", theme_token);
    let _ = root.set_attribute("data-font-size", prefs.font_size.token());
    let _ = root.set_attribute("data-density", prefs.density.token());
    let _ = root.set_attribute(
        "data-reduced-motion",
        if prefs.reduced_motion {
            "true"
        } else {
            "false"
        },
    );
    // Drive the browser's own form-control / scrollbar rendering.
    let _ = root.set_attribute("style", &format!("color-scheme: {theme_token};"));

    inject_prefs_style(&document, prefs, dark);
}

/// Build and (re)install the managed `<style>` element that backs the
/// appearance preferences. Replacing the textContent of a single, stable
/// element keeps this idempotent across re-applies.
fn inject_prefs_style(document: &web_sys::Document, prefs: &Preferences, dark: bool) {
    let mut css = String::new();

    // Root font-size scale. `rem`-based Tailwind sizing scales with this.
    css.push_str(&format!(
        ":root{{font-size:{}px;}}",
        prefs.font_size.root_px()
    ));

    // Light theme: the kit is dark-first — `style.css` hardcodes a dark body
    // and components lean on dark Tailwind utilities (`bg-gray-900`,
    // `text-gray-300/400`, `border-gray-700`, `border-white/10`, …) and on the
    // dark `--dl-card-*` surface vars, with no light counterpart. Rewriting
    // every component is not viable, so we complete the palette here at the
    // theme layer: a single scoped block under `[data-theme="light"]` that
    // re-points the real surfaces, borders, muted text, chips/badges, and
    // inputs to an accessible light palette (dark text ≥ ~4.5:1 on light
    // surfaces). This `<style>` is the one place that already scopes Light
    // rules, so it stays the chokepoint.
    if !dark {
        css.push_str(LIGHT_THEME_CSS);
    }

    // Compact density: tighten the standard card/section padding so lists fit
    // more rows. Scoped to the density attribute so Comfortable is untouched.
    if prefs.density == Density::Compact {
        css.push_str(
            "[data-density=\"compact\"] .glass-card{padding:0.875rem !important;}\
             [data-density=\"compact\"] .space-y-6>*+*{margin-top:0.75rem !important;}\
             [data-density=\"compact\"] .space-y-4>*+*{margin-top:0.5rem !important;}\
             [data-density=\"compact\"] .py-3{padding-top:0.375rem !important;padding-bottom:0.375rem !important;}",
        );
    }

    // User-driven reduced motion: the kit only honours the OS media query, so
    // this lets a user opt in regardless of OS setting by neutralising
    // animations/transitions under the attribute.
    if prefs.reduced_motion {
        css.push_str(
            "[data-reduced-motion=\"true\"] *,\
             [data-reduced-motion=\"true\"] *::before,\
             [data-reduced-motion=\"true\"] *::after{\
             animation-duration:0.001ms !important;animation-iteration-count:1 !important;\
             transition-duration:0.001ms !important;scroll-behavior:auto !important;}",
        );
    }

    // Find or create the managed style element, then set its content.
    let existing = document.get_element_by_id(PREFS_STYLE_ID);
    let style_el: web_sys::Element = match existing {
        Some(el) => el,
        None => {
            let Ok(el) = document.create_element("style") else {
                return;
            };
            let _ = el.set_attribute("id", PREFS_STYLE_ID);
            if let Some(head) = document.head() {
                let _ = head.append_child(&el);
            }
            el
        }
    };
    style_el.set_text_content(Some(&css));
}
