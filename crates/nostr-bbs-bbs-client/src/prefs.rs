//! Persisted BBS display & accessibility preferences.
//!
//! Covers active phosphor [`Theme`], CRT scanline/bloom toggle, larger text
//! size, reduced motion, and desktop sidebar collapse state. All persisted to
//! `localStorage` under `bbs_pref_*` keys so they survive reloads cleanly.

use leptos::prelude::*;

use crate::theme::Theme;

/// Reactive BBS UI preferences, provided at the app root.
#[derive(Clone, Copy)]
pub struct BbsPrefs {
    pub theme: RwSignal<Theme>,
    pub crt_effects: RwSignal<bool>,
    pub text_large: RwSignal<bool>,
    pub reduced_motion: RwSignal<bool>,
    pub sidebar_collapsed: RwSignal<bool>,
    /// Mobile slide-over navigation drawer open state (ephemeral).
    pub mobile_drawer_open: RwSignal<bool>,
    /// `/` command bar open state (ephemeral).
    pub cmd_open: RwSignal<bool>,
}

impl BbsPrefs {
    /// Load persisted preferences (falling back to `default_theme` and OS
    /// `prefers-reduced-motion`).
    pub fn load(default_theme: Theme) -> Self {
        let (theme, crt, text_large, reduced_motion, sidebar_collapsed) =
            read_stored(default_theme);
        Self {
            theme: RwSignal::new(theme),
            crt_effects: RwSignal::new(crt),
            text_large: RwSignal::new(text_large),
            reduced_motion: RwSignal::new(reduced_motion),
            sidebar_collapsed: RwSignal::new(sidebar_collapsed),
            mobile_drawer_open: RwSignal::new(false),
            cmd_open: RwSignal::new(false),
        }
    }

    /// Cycle through the 4 phosphor themes.
    pub fn cycle_theme(&self) {
        self.theme.update(|t| *t = t.next());
    }

    /// Toggle CRT scanlines & vignette.
    pub fn toggle_crt(&self) {
        self.crt_effects.update(|v| *v = !*v);
    }

    /// Toggle desktop sidebar collapse.
    pub fn toggle_sidebar(&self) {
        self.sidebar_collapsed.update(|v| *v = !*v);
    }

    /// Install a reactive effect that persists preferences and syncs `<html>` classes.
    pub fn install_sync(&self) {
        let prefs = *self;
        Effect::new(move |_| {
            let theme = prefs.theme.get();
            let crt = prefs.crt_effects.get();
            let large = prefs.text_large.get();
            let reduced = prefs.reduced_motion.get();
            let collapsed = prefs.sidebar_collapsed.get();
            apply_and_persist(theme, crt, large, reduced, collapsed);
        });
    }
}

pub fn provide_bbs_prefs(prefs: BbsPrefs) {
    provide_context(prefs);
}

pub fn use_bbs_prefs() -> BbsPrefs {
    expect_context::<BbsPrefs>()
}

#[cfg(target_arch = "wasm32")]
fn read_stored(default_theme: Theme) -> (Theme, bool, bool, bool, bool) {
    let storage = web_sys::window().and_then(|w| w.local_storage().ok().flatten());
    let get = |k: &str| storage.as_ref().and_then(|s| s.get_item(k).ok().flatten());
    let theme = get("bbs_pref_theme")
        .map(|s| Theme::parse(&s))
        .unwrap_or(default_theme);
    let crt = get("bbs_pref_crt").as_deref() != Some("0");
    let text_large = get("bbs_text_size").as_deref() == Some("large");
    let reduced_motion = match get("bbs_reduced_motion").as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => web_sys::window()
            .and_then(|w| {
                w.match_media("(prefers-reduced-motion: reduce)")
                    .ok()
                    .flatten()
            })
            .map(|m| m.matches())
            .unwrap_or(false),
    };
    let collapsed = get("bbs_pref_sidebar").as_deref() == Some("collapsed");
    (theme, crt, text_large, reduced_motion, collapsed)
}

#[cfg(not(target_arch = "wasm32"))]
fn read_stored(default_theme: Theme) -> (Theme, bool, bool, bool, bool) {
    (default_theme, true, false, false, false)
}

#[cfg(target_arch = "wasm32")]
fn apply_and_persist(
    theme: Theme,
    crt: bool,
    text_large: bool,
    reduced_motion: bool,
    sidebar_collapsed: bool,
) {
    if let Some(html) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
    {
        let cl = html.class_list();
        let _ = cl.toggle_with_force("bbs-text-large", text_large);
        let _ = cl.toggle_with_force("bbs-reduced-motion", reduced_motion);
        let _ = cl.toggle_with_force("bbs-crt-off", !crt);
    }
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item("bbs_pref_theme", theme.label());
        let _ = storage.set_item("bbs_pref_crt", if crt { "1" } else { "0" });
        let _ = storage.set_item("bbs_text_size", if text_large { "large" } else { "normal" });
        let _ = storage.set_item("bbs_reduced_motion", if reduced_motion { "1" } else { "0" });
        let _ = storage.set_item(
            "bbs_pref_sidebar",
            if sidebar_collapsed {
                "collapsed"
            } else {
                "open"
            },
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_and_persist(
    _theme: Theme,
    _crt: bool,
    _text_large: bool,
    _reduced_motion: bool,
    _sidebar_collapsed: bool,
) {
}
