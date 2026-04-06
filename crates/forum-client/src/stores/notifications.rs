//! Notification store backed by localStorage with 7-day eviction.
//!
//! Provides `NotificationStore` via Leptos context. Any component can push
//! notifications which persist across page reloads and auto-evict after 7 days.

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

const STORAGE_KEY: &str = "bbs:notifications";
const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

// -- Types --------------------------------------------------------------------

/// Category of notification for icon display and routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationKind {
    Message,
    Mention,
    DM,
    JoinRequest,
    JoinApproved,
    EventRSVP,
    System,
}

/// A single notification entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    pub timestamp: u64,
    pub read: bool,
    pub link: Option<String>,
}

/// Serializable store persisted to localStorage.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedNotifications {
    items: Vec<Notification>,
}

// -- Reactive store -----------------------------------------------------------

/// Reactive notification store, provided via context.
#[derive(Clone, Copy)]
pub struct NotificationStoreV2 {
    pub items: RwSignal<Vec<Notification>>,
}

impl NotificationStoreV2 {
    fn new() -> Self {
        let loaded = load_from_storage();
        Self {
            items: RwSignal::new(loaded),
        }
    }

    /// Number of unread notifications.
    pub fn unread_count(&self) -> Memo<usize> {
        let items = self.items;
        Memo::new(move |_| items.get().iter().filter(|n| !n.read).count())
    }

    /// Mark a single notification as read.
    pub fn mark_read(&self, id: &str) {
        let id = id.to_string();
        self.items.update(|list| {
            if let Some(n) = list.iter_mut().find(|n| n.id == id) {
                n.read = true;
            }
        });
        self.persist();
    }

    /// Mark all notifications as read.
    pub fn mark_all_read(&self) {
        self.items.update(|list| {
            for n in list.iter_mut() {
                n.read = true;
            }
        });
        self.persist();
    }

    /// Push a new notification.
    #[allow(dead_code)]
    pub fn add(
        &self,
        kind: NotificationKind,
        title: &str,
        body: &str,
        link: Option<&str>,
    ) {
        let now = now_secs();
        // Generate a random ID using js_sys (WASM-safe, no getrandom crate needed)
        let id = {
            let mut bytes = [0u8; 8];
            for b in bytes.iter_mut() {
                *b = (js_sys::Math::random() * 256.0) as u8;
            }
            hex::encode(bytes)
        };

        let notification = Notification {
            id,
            kind,
            title: title.to_string(),
            body: body.to_string(),
            timestamp: now,
            read: false,
            link: link.map(|s| s.to_string()),
        };

        self.items.update(|list| {
            list.insert(0, notification);
            // Cap at 100 notifications
            if list.len() > 100 {
                list.truncate(100);
            }
        });
        self.persist();
    }

    /// Clear all notifications.
    pub fn clear_all(&self) {
        self.items.set(Vec::new());
        self.persist();
    }

    fn persist(&self) {
        let data = PersistedNotifications {
            items: self.items.get_untracked(),
        };
        let _ = LocalStorage::set(STORAGE_KEY, data);
    }
}

// -- Context providers --------------------------------------------------------

/// Provide the notification store context. Call once near the app root.
pub fn provide_notification_store() {
    let store = NotificationStoreV2::new();
    provide_context(store);
}

/// Read the notification store from context.
pub fn use_notification_store() -> NotificationStoreV2 {
    use_context::<NotificationStoreV2>().unwrap_or_else(|| {
        let store = NotificationStoreV2::new();
        provide_context(store);
        store
    })
}

// -- Helpers ------------------------------------------------------------------

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Load notifications from localStorage, evicting entries older than 7 days.
fn load_from_storage() -> Vec<Notification> {
    let data: PersistedNotifications = LocalStorage::get(STORAGE_KEY).unwrap_or_default();
    let now = now_secs();
    let items: Vec<Notification> = data
        .items
        .into_iter()
        .filter(|n| now.saturating_sub(n.timestamp) < MAX_AGE_SECS)
        .collect();
    // Persist the evicted list back
    let _ = LocalStorage::set(
        STORAGE_KEY,
        PersistedNotifications {
            items: items.clone(),
        },
    );
    items
}
