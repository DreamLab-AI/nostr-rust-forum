//! Read-position tracking per channel, persisted to localStorage.
//!
//! Provides `provide_read_positions()` / `use_read_positions()` context pair.
//! Components call `mark_read()` when the user has viewed the latest messages.
//! The canonical unread model is TIMESTAMP-based: a channel message is unread
//! when its `created_at` is newer than the channel's last-read `timestamp`
//! (see [`ReadPositionStore::read_timestamps`] /
//! [`ReadPositionStore::last_read_timestamp`]). Consumers (forum index, channel
//! cards) compute the count themselves against the live message set so the
//! badge always reflects what is actually on the relay.

use gloo::storage::Storage as _;
use leptos::prelude::*;
use std::collections::HashMap;

const STORAGE_KEY: &str = "nostrbbs:read_positions";

/// Persisted per-channel read position.
///
/// Legacy caches may carry an extra `unread_count` field from the old
/// (never-wired) counter model; `serde_json` ignores unknown fields on
/// deserialize, so older data still loads cleanly.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReadPosition {
    pub last_event_id: String,
    pub timestamp: u64,
}

/// Map of channel_id -> ReadPosition, serialized as JSON in localStorage.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ReadPositions {
    pub positions: HashMap<String, ReadPosition>,
}

/// Reactive wrapper around `ReadPositions` stored in Leptos context.
#[derive(Clone, Copy)]
pub struct ReadPositionStore {
    inner: RwSignal<ReadPositions>,
}

impl ReadPositionStore {
    fn new() -> Self {
        let loaded = load_from_storage().unwrap_or_default();
        Self {
            inner: RwSignal::new(loaded),
        }
    }

    /// Mark a channel as read up to the given event.
    pub fn mark_read(&self, channel_id: &str, event_id: &str, timestamp: u64) {
        self.inner.update(|rp| {
            rp.positions.insert(
                channel_id.to_string(),
                ReadPosition {
                    last_event_id: event_id.to_string(),
                    timestamp,
                },
            );
        });
        self.persist();
    }

    /// Return the last-read event ID for a channel (empty string if never read).
    pub fn last_read_event_id(&self, channel_id: &str) -> String {
        self.inner
            .get()
            .positions
            .get(channel_id)
            .map(|p| p.last_event_id.clone())
            .unwrap_or_default()
    }

    /// Reactively read the whole `channel_id -> last-read timestamp` map.
    ///
    /// Used by the forum index to compute per-section unread counts: a message
    /// is unread when its `created_at` is newer than the last-read timestamp for
    /// its channel (or the channel has no read position at all). Subscribing to
    /// this signal makes the unread badges update the moment a channel is marked
    /// read (e.g. on returning from a channel view).
    pub fn read_timestamps(&self) -> HashMap<String, u64> {
        self.inner.with(|rp| {
            rp.positions
                .iter()
                .map(|(cid, pos)| (cid.clone(), pos.timestamp))
                .collect()
        })
    }

    /// Reactive last-read timestamp for a single channel (0 if never opened).
    ///
    /// This is the canonical TIMESTAMP read model (the same one
    /// [`read_timestamps`](Self::read_timestamps) and the forum index use):
    /// unread = messages whose `created_at` is strictly newer than this value.
    /// Subscribing to this signal makes a card's "N new" chip clear the instant
    /// the channel is marked read.
    pub fn last_read_timestamp(&self, channel_id: String) -> Memo<u64> {
        let inner = self.inner;
        Memo::new(move |_| {
            inner
                .get()
                .positions
                .get(&channel_id)
                .map(|p| p.timestamp)
                .unwrap_or(0)
        })
    }

    fn persist(&self) {
        let data = self.inner.get_untracked();
        if let Ok(json) = serde_json::to_string(&data) {
            let _ = gloo::storage::LocalStorage::set(STORAGE_KEY, json);
        }
    }
}

fn load_from_storage() -> Option<ReadPositions> {
    let raw: String = gloo::storage::LocalStorage::get(STORAGE_KEY).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Provide the read-position store in Leptos context. Call once at app root.
pub fn provide_read_positions() {
    let store = ReadPositionStore::new();
    provide_context(store);
    // Cross-tab sync: without it, reading channel X in one tab is reverted when a
    // stale sibling tab (same account under remember-me / passkey) later marks
    // channel Y read and persists its whole map — the "N new" chip on X reappears.
    // Reload the map load-only from any sibling's write. See notifications.rs.
    let inner = store.inner;
    crate::utils::on_cross_tab_storage_write(STORAGE_KEY, move || {
        if let Some(rp) = load_from_storage() {
            inner.set(rp);
        }
    });
}

/// Retrieve the read-position store from context.
pub fn use_read_positions() -> ReadPositionStore {
    expect_context::<ReadPositionStore>()
}
