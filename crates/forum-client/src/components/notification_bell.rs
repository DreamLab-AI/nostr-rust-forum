//! Notification bell icon with dropdown panel.
//!
//! Displays an SVG bell with an unread-count badge (`.notification-badge` +
//! `.neon-pulse` CSS), and toggles the NotificationCenter slide-out panel.
//! Also maintains the legacy NotificationStore for backward compatibility.

use leptos::prelude::*;

use crate::components::notification_center::NotificationCenter;
use crate::stores::notifications::use_notification_store;

/// A single notification entry (legacy).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Notification {
    pub id: String,
    pub message: String,
    /// UNIX timestamp.
    pub timestamp: u64,
    pub read: bool,
}

/// Legacy reactive notification store, provided via context.
#[derive(Clone, Copy)]
pub struct NotificationStore {
    pub items: RwSignal<Vec<Notification>>,
}

impl NotificationStore {
    fn new() -> Self {
        Self {
            items: RwSignal::new(Vec::new()),
        }
    }

    /// Number of unread notifications.
    pub fn unread_count(&self) -> Memo<usize> {
        let items = self.items;
        Memo::new(move |_| items.get().iter().filter(|n| !n.read).count())
    }

    /// Mark all notifications as read.
    #[allow(dead_code)]
    pub fn mark_all_read(&self) {
        self.items.update(|list| {
            for n in list.iter_mut() {
                n.read = true;
            }
        });
    }

    /// Clear all notifications.
    #[allow(dead_code)]
    pub fn clear_all(&self) {
        self.items.set(Vec::new());
    }

    /// Push a new notification.
    #[allow(dead_code)]
    pub fn push(&self, notification: Notification) {
        self.items.update(|list| list.insert(0, notification));
    }
}

/// Provide the notification store context. Call once near the app root.
pub fn provide_notifications() -> NotificationStore {
    let store = NotificationStore::new();
    provide_context(store);
    store
}

/// Read the notification store from context.
pub fn use_notifications() -> NotificationStore {
    use_context::<NotificationStore>().unwrap_or_else(|| {
        let store = NotificationStore::new();
        provide_context(store);
        store
    })
}

/// Bell icon button with badge. Toggles the NotificationCenter panel.
#[component]
pub(crate) fn NotificationBell() -> impl IntoView {
    let v2_store = use_notification_store();
    let legacy_store = use_notifications();
    let panel_open = RwSignal::new(false);

    // Combined unread count from both stores
    let legacy_unread = legacy_store.unread_count();
    let v2_unread = v2_store.unread_count();
    let total_unread = Memo::new(move |_| legacy_unread.get() + v2_unread.get());

    let toggle = move |_| panel_open.update(|v| *v = !*v);

    view! {
        <div class="relative" data-notification-bell="">
            // Bell button
            <button
                class="relative p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800 transition-colors"
                on:click=toggle
                aria-label=move || {
                    let count = total_unread.get();
                    if count == 0 {
                        "Notifications".to_string()
                    } else {
                        format!("Notifications, {} unread", count)
                    }
                }
                aria-expanded=move || panel_open.get().to_string()
                aria-haspopup="true"
            >
                <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"
                        stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M13.73 21a2 2 0 01-3.46 0"
                        stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                {move || {
                    let count = total_unread.get();
                    (count > 0).then(|| {
                        let label = if count > 99 { "99+".to_string() } else { count.to_string() };
                        view! {
                            <span class="notification-badge neon-pulse">{label}</span>
                        }
                    })
                }}
            </button>

            // Notification Center panel
            <NotificationCenter is_open=panel_open />
        </div>
    }
}
