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
    #[allow(dead_code)] // legacy shim, kept alongside sibling methods below
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
#[allow(dead_code)] // legacy shim, no current callers — see `provide_notifications`
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
    // #31: attach the live relay→notification effects. The bell mounts inside
    // the Layout, after every app-root context (channel store, read positions,
    // auth) is provided, so this is the safe point to start syncing. Idempotent.
    v2_store.init_sync();
    let panel_open = RwSignal::new(false);

    // ADR-2023 Tier 0: DMs notify from anywhere in the app. The per-page DM
    // store only subscribes while a DM screen is open, so the layout watches
    // gift wraps itself once the relay session is authenticated, and re-arms
    // after a reconnect or an account switch.
    if let Some(relay) = use_context::<crate::relay::RelayConnection>() {
        let conn = relay.connection_state();
        let relay_authed = relay.authenticated();
        let me = crate::auth::use_auth().pubkey();
        let auth_for_dm = crate::auth::use_auth();
        let watching: StoredValue<Option<(String, String)>> = StoredValue::new(None);
        // The signer is not a reactive value, so it can be absent at the moment
        // the session turns ready. Re-run a few times rather than never arming.
        let retry = RwSignal::new(0u32);
        Effect::new(move |_| {
            let attempt = retry.get();
            let ready =
                conn.get() == crate::relay::ConnectionState::Connected && relay_authed.get();
            let pk = me.get();
            let current = watching.get_value();
            let wanted = if ready { pk } else { None };
            if current.as_ref().map(|(_, p)| p) == wanted.as_ref() {
                return;
            }
            if let Some((sid, _)) = current {
                relay.unsubscribe(&sid);
                watching.set_value(None);
            }
            let Some(pk) = wanted else {
                return;
            };
            let Some(signer) = auth_for_dm.get_signer() else {
                if attempt < 10 {
                    crate::utils::set_timeout_once(move || retry.update(|n| *n += 1), 1_000);
                }
                return;
            };
            let sid = crate::dm::start_incoming_watcher(&relay, signer, &pk);
            watching.set_value(Some((sid, pk)));
        });
    }

    // ADR-2023: once signed in, keep this device's push registration fresh (at
    // most daily; a no-op unless the member already turned alerts on here).
    let push_auth = crate::auth::use_auth();
    let push_authed = push_auth.is_authenticated();
    let push_refreshed = std::cell::Cell::new(false);
    Effect::new(move |_| {
        // Tracked: re-runs when sign-in completes (the signer itself is not reactive).
        if !push_authed.get() || push_refreshed.get() {
            return;
        }
        if let Some(signer) = push_auth.get_signer() {
            push_refreshed.set(true);
            leptos::task::spawn_local(crate::utils::push::refresh_if_due(
                signer,
                crate::utils::push::brand_label(),
            ));
        }
    });

    // Bug #18: route open-state through the shared PopoverCoord so opening
    // this popover automatically closes any sibling popover (Bookmarks etc.)
    // Two-way sync — see app.rs::Layout for the parallel bookmarks block.
    let coord = crate::components::popover_coord::use_popover_coord();
    const KEY: &str = "notifications";
    Effect::new(move |_| {
        panel_open.set(coord.is_active(KEY));
    });
    Effect::new(move |_| {
        if !panel_open.get() {
            coord.close(KEY);
        }
    });

    // Badge count: read ONLY from the V2 store — the exact same `items` signal
    // the NotificationCenter renders. Previously the badge summed a second,
    // legacy `NotificationStore` that nothing populates and that the center
    // never renders; any divergence there produced the "bell shows a count but
    // the expanded list is empty" bug. Counting one source guarantees the badge
    // and the list never disagree.
    let total_unread = v2_store.unread_count();

    let toggle = move |_| coord.toggle(KEY);

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
