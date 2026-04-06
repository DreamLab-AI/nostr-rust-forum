//! Muted users and channels store, persisted to localStorage.
//!
//! Provides `provide_mute_store()` / `use_mute_store()` context pair.

use gloo::storage::Storage as _;
use leptos::prelude::*;

const STORAGE_KEY: &str = "bbs:mutes";

/// Serializable mute list for users and channels.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MuteData {
    pub muted_users: Vec<String>,
    pub muted_channels: Vec<String>,
}

/// Reactive wrapper providing mute operations via Leptos context.
#[derive(Clone, Copy)]
pub struct MuteStore {
    inner: RwSignal<MuteData>,
}

impl MuteStore {
    fn new() -> Self {
        let loaded = load_from_storage().unwrap_or_default();
        Self {
            inner: RwSignal::new(loaded),
        }
    }

    // -- Channel mute ---------------------------------------------------------

    /// Toggle mute state for a channel. Returns `true` if now muted.
    pub fn toggle_mute_channel(&self, channel_id: &str) -> bool {
        let mut now_muted = false;
        self.inner.update(|d| {
            if let Some(pos) = d.muted_channels.iter().position(|c| c == channel_id) {
                d.muted_channels.remove(pos);
            } else {
                d.muted_channels.push(channel_id.to_string());
                now_muted = true;
            }
        });
        self.persist();
        now_muted
    }

    /// Check if a channel is muted.
    pub fn is_channel_muted(&self, channel_id: &str) -> bool {
        self.inner
            .get()
            .muted_channels
            .iter()
            .any(|c| c == channel_id)
    }

    /// Reactive signal for whether a specific channel is muted.
    #[allow(dead_code)]
    pub fn channel_muted_signal(&self, channel_id: String) -> Memo<bool> {
        let inner = self.inner;
        Memo::new(move |_| {
            inner
                .get()
                .muted_channels
                .iter()
                .any(|c| c == &channel_id)
        })
    }

    // -- User mute ------------------------------------------------------------

    /// Toggle mute state for a user. Returns `true` if now muted.
    pub fn toggle_mute_user(&self, pubkey: &str) -> bool {
        let mut now_muted = false;
        self.inner.update(|d| {
            if let Some(pos) = d.muted_users.iter().position(|p| p == pubkey) {
                d.muted_users.remove(pos);
            } else {
                d.muted_users.push(pubkey.to_string());
                now_muted = true;
            }
        });
        self.persist();
        now_muted
    }

    /// Check if a user is muted.
    pub fn is_user_muted(&self, pubkey: &str) -> bool {
        self.inner.get().muted_users.iter().any(|p| p == pubkey)
    }

    /// Get list of muted channel IDs (reactive).
    #[allow(dead_code)]
    pub fn muted_channel_ids(&self) -> Vec<String> {
        self.inner.get().muted_channels.clone()
    }

    fn persist(&self) {
        let data = self.inner.get_untracked();
        if let Ok(json) = serde_json::to_string(&data) {
            let _ = gloo::storage::LocalStorage::set(STORAGE_KEY, json);
        }
    }
}

fn load_from_storage() -> Option<MuteData> {
    let raw: String = gloo::storage::LocalStorage::get(STORAGE_KEY).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Provide the mute store in Leptos context. Call once at app root.
pub fn provide_mute_store() {
    provide_context(MuteStore::new());
}

/// Retrieve the mute store from context.
pub fn use_mute_store() -> MuteStore {
    expect_context::<MuteStore>()
}
