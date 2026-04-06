//! Read-position tracking per channel, persisted to localStorage.
//!
//! Provides `provide_read_positions()` / `use_read_positions()` context pair.
//! Components call `mark_read()` when the user has viewed the latest messages
//! and `get_unread_count()` to display badge counts.

use gloo::storage::Storage as _;
use leptos::prelude::*;
use std::collections::HashMap;

const STORAGE_KEY: &str = "bbs:read_positions";

/// Persisted per-channel read position.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReadPosition {
    pub last_event_id: String,
    pub timestamp: u64,
    pub unread_count: u32,
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
                    unread_count: 0,
                },
            );
        });
        self.persist();
    }

    /// Increment the unread counter for a channel (call when a new message arrives
    /// while the user is NOT viewing that channel).
    #[allow(dead_code)]
    pub fn increment_unread(&self, channel_id: &str) {
        self.inner.update(|rp| {
            if let Some(pos) = rp.positions.get_mut(channel_id) {
                pos.unread_count += 1;
            } else {
                rp.positions.insert(
                    channel_id.to_string(),
                    ReadPosition {
                        last_event_id: String::new(),
                        timestamp: 0,
                        unread_count: 1,
                    },
                );
            }
        });
        self.persist();
    }

    /// Return the current unread count for a channel.
    #[allow(dead_code)]
    pub fn get_unread_count(&self, channel_id: &str) -> u32 {
        self.inner
            .get()
            .positions
            .get(channel_id)
            .map(|p| p.unread_count)
            .unwrap_or(0)
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

    /// Return a reactive signal of the unread count for a specific channel.
    pub fn unread_count_signal(&self, channel_id: String) -> Memo<u32> {
        let inner = self.inner;
        Memo::new(move |_| {
            inner
                .get()
                .positions
                .get(&channel_id)
                .map(|p| p.unread_count)
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
    provide_context(ReadPositionStore::new());
}

/// Retrieve the read-position store from context.
pub fn use_read_positions() -> ReadPositionStore {
    expect_context::<ReadPositionStore>()
}
