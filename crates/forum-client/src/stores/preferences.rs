//! User preferences store backed by localStorage.
//!
//! Persists theme, notification level, link preview, compact mode, and
//! reduced motion preferences across sessions. Provided via Leptos context.

use leptos::prelude::*;

const PREFS_KEY: &str = "bbs:preferences";

/// User-configurable preferences.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Preferences {
    pub theme: Theme,
    pub notification_level: NotificationLevel,
    pub show_link_previews: bool,
    pub compact_messages: bool,
    pub reduced_motion: bool,
    /// When true, show Nostr protocol names (NIP-07, nsec, pubkey hex, relay URLs).
    /// When false (default), use friendly labels.
    #[serde(default)]
    pub show_technical_details: bool,
}

/// Visual theme selection.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
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
            compact_messages: false,
            reduced_motion: false,
            show_technical_details: false,
        }
    }
}

/// Provide the preferences store into Leptos context. Call once near the app root.
pub fn provide_preferences() {
    let prefs = RwSignal::new(load_preferences());
    provide_context(prefs);
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

/// Persist preferences to localStorage.
pub fn save_preferences(prefs: &Preferences) {
    if let Some(storage) = get_local_storage() {
        if let Ok(json) = serde_json::to_string(prefs) {
            let _ = storage.set_item(PREFS_KEY, &json);
        }
    }
}
